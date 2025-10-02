import asyncio
import struct
import logging
import uuid
import threading  # ✅ TAMBAHKAN IMPORT
from server.smpp_common import (
    PDU, CommandId, CommandStatus, HEADER_LEN, HEADER_FMT,
    build_bind_transceiver, build_enquire_link, build_enquire_link_resp,
    parse_deliver_sm, CLIENT_SESSIONS, dict_lock, build_submit_sm_pdu, build_deliver_sm_dlr,
    SUPPLIER_TO_CLIENT_MSGID, CLIENT_MSGID_MAP
)

COMMAND_STATUS_DESCRIPTIONS = {
    0x00000000: "OK",
    0x00000001: "Invalid message length",
    0x00000002: "Invalid command length", 
    0x00000003: "Invalid command ID",
    0x00000008: "System error",
    0x0000000E: "Invalid password",
    0x0000000F: "Invalid system ID",
    0x000000FF: "Message queue full",
}

class SmppClient:
    def __init__(self, host, port, system_id, password):
        self.host = host
        self.port = port
        self.system_id = system_id
        self.password = password
        self.sequence = 0
        self.reader = None
        self.writer = None
        self.logger = logging.getLogger("smpp.client")
        self._pending = {}
        # ✅ PERBAIKAN: GUNAKAN threading.Lock UNTUK SYNCHRONOUS OPERATIONS
        self._seq_lock = threading.Lock()
        self._pending_lock = asyncio.Lock()
        self._write_lock = asyncio.Lock()

    # ✅ METHOD Thread-safe sequence - FIXED
    def next_seq(self):
        with self._seq_lock:
            self.sequence += 1
            return self.sequence

    # ✅ METHOD Thread-safe pending management  
    async def add_pending(self, seq, future):
        async with self._pending_lock:
            self._pending[seq] = future

    async def get_and_remove_pending(self, seq):
        async with self._pending_lock:
            return self._pending.pop(seq, None)

    # ✅ METHOD Thread-safe write
    async def safe_write(self, data):
        async with self._write_lock:
            if self.writer and not self.writer.is_closing():
                self.writer.write(data)
                await self.writer.drain()

    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        self.logger.info("Connected to %s:%s", self.host, self.port)

    async def bind_transceiver(self):
        # ✅ SEKARANG AMAN - next_seq() menggunakan threading.Lock
        seq = self.next_seq()
        pdu = build_bind_transceiver(self.system_id, self.password, "", sequence=seq)

        future = asyncio.get_event_loop().create_future()
        await self.add_pending(seq, future)

        await self.safe_write(pdu)

        # Jalankan loop pembaca permanen dan keepalive
        asyncio.create_task(self._receiver_loop())
        asyncio.create_task(self._keepalive())

        resp = await asyncio.wait_for(future, timeout=10)
        if resp.command_status != CommandStatus.ESME_ROK:
            raise RuntimeError("Bind failed")
        self.logger.info("Bind successful")

    async def submit_sm(self, src, dst, text):
        """
        Kirim SMS ke supplier, simpan mapping client_msgid → supplier_msgid
        """
        self.logger.info(f"submit_sm: from={src}, to={dst}, text={text}")
        start_seq = self.next_seq()
        pdus = build_submit_sm_pdu(src, dst, text, start_sequence=start_seq)
        responses = []

        for pdu in pdus:
            client_msgid = str(uuid.uuid4())
            pdu.client_msgid = client_msgid

            seq = pdu.sequence
            future = asyncio.get_event_loop().create_future()
            await self.add_pending(seq, future)

            await self.safe_write(pdu.pack())

            try:
                resp = await asyncio.wait_for(future, timeout=10)
                supplier_msgid = resp.body.decode() if resp.body else ""
                
                async with dict_lock:
                    if supplier_msgid:
                        SUPPLIER_TO_CLIENT_MSGID[supplier_msgid] = client_msgid
                        CLIENT_MSGID_MAP[client_msgid] = {
                            "system_id": self.system_id,
                            "source_addr": src,
                            "dest_addr": dst
                        }

                desc = COMMAND_STATUS_DESCRIPTIONS.get(resp.command_status, "Unknown error")
                self.logger.info(f"submit_sm_resp: seq={seq}, status=0x{resp.command_status:02X} ({desc})")
                responses.append(resp)
            except asyncio.TimeoutError:
                self.logger.error(f"⏰ Timeout menunggu submit_sm_resp untuk seq={seq}")

        return responses

    async def _read_pdu(self):
        header = await self.reader.readexactly(16)
        if len(header) < 16:
            raise ConnectionError("Header PDU terlalu pendek")

        command_length, command_id, command_status, sequence = struct.unpack(">IIII", header)
        body_length = command_length - 16
        body = await self.reader.readexactly(body_length)

        return PDU(
            command_id=command_id,
            command_status=command_status,
            sequence=sequence,
            body=body
        )

    async def _receiver_loop(self):
        while True:
            try:
                pdu = await self._read_pdu()
            except Exception as e:
                logging.error(f"❌ Error reading PDU: {e}")
                break

            logging.debug(f"⬅️ Received PDU: cmd_id=0x{pdu.command_id:08X}, seq={pdu.sequence}")

            # Response PDU
            if pdu.command_id & 0x80000000:
                seq = pdu.sequence
                future = await self.get_and_remove_pending(seq)
                if future and not future.done():
                    future.set_result(pdu)
                else:
                    logging.warning(f"⚠️ Unmatched response PDU: cmd_id=0x{pdu.command_id:08X}, seq={seq}")
                continue

            # deliver_sm (DLR atau inbound)
            if pdu.command_id == CommandId.deliver_sm:
                msg = parse_deliver_sm(pdu.body)
                asyncio.create_task(self._handle_deliver_sm(pdu, msg))
                continue

            # enquire_link
            if pdu.command_id == CommandId.enquire_link:
                resp = build_enquire_link_resp(pdu.sequence)
                await self.safe_write(resp)
                continue

            logging.warning(f"⚠️ Unknown PDU type: cmd_id=0x{pdu.command_id:08X}, seq={pdu.sequence}")

    async def _handle_deliver_sm(self, pdu, msg):
        text_bytes = msg.get("text", b"")
        if isinstance(text_bytes, bytes):
            text_bytes = text_bytes.rstrip(b'\x00')
        text = text_bytes.decode("utf-8", errors="ignore") if isinstance(text_bytes, bytes) else str(text_bytes)
        logging.info(f"📩 deliver_sm received from supplier: {text}")

        # Kirim deliver_sm_resp ke supplier
        resp = PDU(
            command_id=CommandId.deliver_sm_resp,
            command_status=CommandStatus.ESME_ROK,
            sequence=pdu.sequence,
            body=b""
        ).pack()
        await self.safe_write(resp)
        self.logger.info("✅ deliver_sm_resp sent to supplier")

        # ========== IMPROVED DLR PARSING ==========
        text = text.replace('\x00', '').strip()
        
        logging.info(f"🔍 Raw DLR text for parsing: '{text}'")
        
        supplier_msgid = None
        stat = "UNKNOWN"
        
        try:
            fields = {}
            for item in text.split():
                if ':' in item:
                    key, value = item.split(':', 1)
                    fields[key.lower()] = value.strip()
            
            supplier_msgid = (fields.get('id') or fields.get('d') or 
                            fields.get('messageid') or fields.get('msgid') or '')
            
            stat = (fields.get('stat') or fields.get('status') or 
                fields.get('state') or fields.get('s') or 'UNKNOWN')
            
            if stat == "UNKNOWN":
                import re
                stat_match = re.search(r'stat:([^\s]+)', text)
                if stat_match:
                    stat = stat_match.group(1)
            
            supplier_msgid = supplier_msgid.split('\x00')[0].strip()
            stat = stat.upper().strip()
            
            valid_statuses = ["DELIVRD", "EXPIRED", "UNDELIV", "REJECTD", "UNKNOWN", "ACCEPTD", "DELETED"]
            if stat not in valid_statuses:
                logging.warning(f"⚠️ Invalid status '{stat}', falling back to UNKNOWN")
                stat = "UNKNOWN"
            
        except Exception as e:
            logging.error(f"❌ Error parsing supplier DLR: {e}")
            return

        if not supplier_msgid:
            logging.warning(f"❗ Tidak dapat extract supplier_msgid dari DLR: {text}")
            return

        logging.info(f"🆔 Supplier DLR - Message ID: '{supplier_msgid}', Status: {stat}")

        # ========== DEBUG: Log semua available mappings ==========
        async with dict_lock:
            available_keys = list(SUPPLIER_TO_CLIENT_MSGID.keys())
        logging.info(f"🔍 Available mappings: {available_keys}")
        logging.info(f"🔍 Looking for: '{supplier_msgid}'")

        # Mapping ke client
        client_msgid = None
        info = None
        client_session = None
        
        for attempt in range(5):
            async with dict_lock:
                client_msgid = SUPPLIER_TO_CLIENT_MSGID.get(supplier_msgid)
                if client_msgid:
                    info = CLIENT_MSGID_MAP.get(client_msgid)
                    if info and info.get("system_id"):
                        client_session = CLIENT_SESSIONS.get(info["system_id"])
                        logging.info(f"✅ Mapping found: '{supplier_msgid}' -> {client_msgid}")

            if client_session and client_session.bound:
                break
            await asyncio.sleep(0.3)

        if not client_session or not info:
            logging.warning(f"❗ Session client untuk supplier_msgid '{supplier_msgid}' tidak ditemukan setelah retry")
            async with dict_lock:
                logging.info(f"🔍 SUPPLIER_TO_CLIENT_MSGID: {SUPPLIER_TO_CLIENT_MSGID}")
                logging.info(f"🔍 CLIENT_MSGID_MAP: {CLIENT_MSGID_MAP}")
                logging.info(f"🔍 CLIENT_SESSIONS: {list(CLIENT_SESSIONS.keys())}")
            return

        # ✅ PERBAIKAN: Thread-safe sequence handling untuk client session
        try:
            if hasattr(client_session, 'next_seq'):
                sequence = await client_session.next_seq()
            elif hasattr(client_session, 'sequence'):
                if hasattr(client_session, '_write_lock'):
                    async with client_session._write_lock:
                        client_session.sequence += 1
                        sequence = client_session.sequence
                else:
                    client_session.sequence += 1
                    sequence = client_session.sequence
            else:
                sequence = 1

            dlr_pdu = build_deliver_sm_dlr(
                msg_id=client_msgid,
                source_addr=info["dest_addr"],
                dest_addr=info["source_addr"],
                stat=stat,
                sequence=sequence
            )

            if hasattr(client_session, 'safe_write'):
                await client_session.safe_write(dlr_pdu)
            else:
                client_session.transport.write(dlr_pdu)

            logging.info(f"✅ DLR diteruskan ke client {info['system_id']}: msgid={client_msgid}, status={stat}")
            
            async with dict_lock:
                SUPPLIER_TO_CLIENT_MSGID.pop(supplier_msgid, None)
                CLIENT_MSGID_MAP.pop(client_msgid, None)
                
        except Exception as e:
            logging.error(f"❌ Gagal kirim DLR ke client {info['system_id']}: {e}")

    async def _keepalive(self):
        while True:
            await asyncio.sleep(60)
            seq = self.next_seq()
            pdu = build_enquire_link(seq)
            future = asyncio.get_event_loop().create_future()
            await self.add_pending(seq, future)

            await self.safe_write(pdu)
            self.logger.debug(f"sent enquire_link with seq={seq}")

            try:
                resp = await asyncio.wait_for(future, timeout=10)
                self.logger.debug(f"received enquire_link_resp for seq={seq}")
            except asyncio.TimeoutError:
                self.logger.warning(f"time out waiting for enquire_link_resp seq={seq}")
                await self.get_and_remove_pending(seq)

    async def close(self):
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()