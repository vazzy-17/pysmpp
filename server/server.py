from __future__ import annotations
from server.db import DB
from dotenv import load_dotenv
import hashlib
import os
import asyncio
import logging
import uuid
import struct
from server.credential_watcher import GLOBAL_CREDENTIALS, load_credentials, apply_new_credentials

# Di level global
dict_lock = asyncio.Lock()

# buat handler untuk log
logging.getLogger("watchdog.observers.inotify_buffer").setLevel(logging.WARNING)

from server.smpp_common import (
    PDU, CommandId, CommandStatus, Ton, Npi, DLR_STATUS_MAP,
    build_bind_transceiver_resp, parse_bind_transceiver_body,
    build_enquire_link_resp, build_submit_sm, parse_submit_sm_body,
    strip_udh_and_decode, build_deliver_sm_dlr, parse_deliver_sm, clean_smpp_string,
    SUPPLIER_CLIENT, CLIENT_SESSIONS, SUPPLIER_TO_CLIENT_MSGID, CLIENT_MSGID_MAP
)

load_dotenv()
db = DB(os.getenv("DATABASE_URL2"))

def apply_new_credentials(new_creds: dict):
    GLOBAL_CREDENTIALS.clear()
    GLOBAL_CREDENTIALS.update(new_creds)

class SmppServerProtocol(asyncio.Protocol):
    def __init__(self, min_version: int = 0x33, max_version: int = 0x34):
        self.transport = None
        self.bound = False
        self.sequence = 0
        self.peer = "?"
        self.expected_system_id = None
        self.min_version = min_version
        self.max_version = max_version
        self.logger = logging.getLogger("smpp.server")
        self._write_lock = asyncio.Lock()

    async def safe_write(self, data):
        async with self._write_lock:
            if self.transport and not self.transport.is_closing():
                self.transport.write(data)

    async def next_seq(self):
        async with self._write_lock:
            self.sequence += 1
            return self.sequence  # ✅ RETURN DALAM LOCK SCOPE

    def connection_made(self, transport: asyncio.Transport):
        self.transport = transport
        self.peer = str(transport.get_extra_info("peername"))
        self.logger.info(f"Client connected: {self.peer}")

    def data_received(self, data: bytes):
        asyncio.create_task(self._handle(data))

    def connection_lost(self, exc):
        if self.bound and self.expected_system_id:
            asyncio.create_task(self.remove_client_session())
        self.logger.info(f"Connection lost: {self.peer}")

    async def remove_client_session(self):
        """Thread-safe way to remove client session"""
        async with dict_lock:
            if self.expected_system_id in CLIENT_SESSIONS:
                del CLIENT_SESSIONS[self.expected_system_id]
                self.logger.info(f"Removed client session: {self.expected_system_id}")

    # ----------------------------
    # Helper: Kirim DLR nanti
    # ----------------------------
    async def send_dlr_later(self, msg_id, source, dest, delay=2.0, status_code=0):
        await asyncio.sleep(delay)
        if self.transport and self.bound:
            sequence = await self.next_seq()
            dlr_pdu = build_deliver_sm_dlr(
                msg_id, source, dest, DLR_STATUS_MAP.get(status_code, "UNKNOWN"), sequence
            )
            await self.safe_write(dlr_pdu)

    # ----------------------------
    # Parser PDU
    # ----------------------------
    async def _handle(self, data: bytes):
        offset = 0
        while offset + 4 <= len(data):
            length = struct.unpack(">I", data[offset:offset + 4])[0]
            if offset + length > len(data):
                self.logger.error("Incomplete PDU received")
                break

            try:
                pdu = PDU.unpack(data[offset:offset + length])
            except Exception as e:
                self.logger.exception("Failed to unpack PDU: %s", e)
                nack = PDU(CommandId.generic_nack, CommandStatus.ESME_RINVCMDLEN, 0, b"")
                await self.safe_write(nack.pack())
                return

            await self._process_pdu(pdu)
            offset += length

    # ----------------------------
    # Process masing-masing PDU
    # ----------------------------
    async def _process_pdu(self, pdu: PDU):
        # ----------------------------
        # Bind transceiver
        # ----------------------------
        if pdu.command_id == CommandId.bind_transceiver:
            params = parse_bind_transceiver_body(pdu.body)
            self.logger.info(f"📥 Bind request from {params['system_id']}")

            ver = params["interface_version"]
            if not (self.min_version <= ver <= self.max_version):
                status = CommandStatus.ESME_RINVVER
            elif params["system_id"] not in GLOBAL_CREDENTIALS:
                status = CommandStatus.ESME_RINVSYSID
            elif GLOBAL_CREDENTIALS[params["system_id"]] != hashlib.sha256(params["password"].encode()).digest():
                status = CommandStatus.ESME_RINVPASWD
            elif self.bound:
                status = CommandStatus.ESME_RALYBND
            else:
                status = CommandStatus.ESME_ROK
                self.bound = True
                self.system_id = params["system_id"]
                self.expected_system_id = self.system_id

                async with dict_lock:
                    CLIENT_SESSIONS[self.system_id] = self

                self.logger.info(f"✅ Client bound and registered: {self.system_id}")

            resp = build_bind_transceiver_resp(params["system_id"], status, pdu.sequence)
            await self.safe_write(resp)
            return

        # ----------------------------
        # Enquire link
        # ----------------------------
        if pdu.command_id == CommandId.enquire_link:
            resp = build_enquire_link_resp(pdu.sequence)
            await self.safe_write(resp)
            return

        # ----------------------------
        # Submit SM
        # ----------------------------
        if pdu.command_id == CommandId.submit_sm:
            msg = parse_submit_sm_body(pdu.body)
            decoded_text = strip_udh_and_decode(msg["short_message"], msg["data_coding"])

            # Ambil IP client
            peer = self.transport.get_extra_info("peername")
            peer_ip = peer[0] if peer else "unknown"
            try:
                account_ip_id = await db.get_account_ip_id(peer_ip)
            except ValueError as e:
                self.logger.error(f"❌ {e}")
                status = CommandStatus.ESME_RSYSERR
                resp = PDU(CommandId.submit_sm_resp, status, pdu.sequence, b"\x00").pack()
                await self.safe_write(resp)
                return

            # Simpan log
            raw_msg_id = await db.insert_log(
                source=msg["source_addr"],
                msisdn=msg["dest_addr"],
                message=decoded_text,
                account_ip=account_ip_id,
                gtw_id=int(os.getenv("GTW_ID", 4)),
                telco_id=7
            )

            # Simpan mapping client msg
            async with dict_lock:
                CLIENT_MSGID_MAP[raw_msg_id] = {
                    "source_addr": msg["source_addr"],
                    "dest_addr": msg["dest_addr"],
                    "system_id": self.expected_system_id
                }

            # Kirim ke supplier
            status = CommandStatus.ESME_RSYSERR
            if SUPPLIER_CLIENT:
                responses = await SUPPLIER_CLIENT.submit_sm(msg["source_addr"], msg["dest_addr"], decoded_text)
                if responses and responses[0].body:
                    raw_bytes = responses[0].body
                    # self.logger.info(f"🔍 RAW supplier_msgid bytes: {raw_bytes}")
                    # self.logger.info(f"🔍 RAW supplier_msgid hex: {raw_bytes.hex()}")
                    
                    supplier_msgid = raw_bytes.decode("ascii", errors="ignore")
                    supplier_msgid = supplier_msgid.replace('\x00', '').strip()
                    
                    # self.logger.info(f"🔍 FINAL supplier_msgid: '{supplier_msgid}'")
                    # self.logger.info(f"🔍 FINAL length: {len(supplier_msgid)}")
                    # self.logger.info(f"🔍 FINAL repr: {repr(supplier_msgid)}")
                    
                    async with dict_lock:
                        SUPPLIER_TO_CLIENT_MSGID[supplier_msgid] = raw_msg_id
                        
                    # self.logger.info(f"✅ Mapping saved: '{supplier_msgid}' -> {raw_msg_id}")
                    
                    current_keys = list(SUPPLIER_TO_CLIENT_MSGID.keys())
                    # self.logger.info(f"📋 All current mappings: {current_keys}")
                    
                    status = responses[0].command_status

            # Kirim submit_sm_resp
            msg_id_bytes = raw_msg_id.encode("ascii") + b"\x00"
            resp = PDU(CommandId.submit_sm_resp, status, pdu.sequence, msg_id_bytes).pack()
            await self.safe_write(resp)
            return

        # ----------------------------
        # Deliver SM (DLR)
        # ----------------------------
        if pdu.command_id == CommandId.deliver_sm:
            self.logger.info("📩 Received deliver_sm (likely DLR)")
            msg = parse_deliver_sm(pdu.body)
            text_bytes = msg.get("text", b"")
            text = text_bytes.decode("ascii", errors="replace")
            self.logger.info(f"📨 Decoded DLR text: {text}")

            # Parse supplier DLR dengan handling yang lebih robust
            supplier_msgid = None
            status = "UNKNOWN"
            
            try:
                fields = {}
                for item in text.split():
                    if ":" in item:
                        key, value = item.split(":", 1)
                        fields[key.lower()] = value.strip()
                
                supplier_msgid = fields.get("id") or fields.get("messageid") or fields.get("msgid") or ""
                status = fields.get("stat") or fields.get("status") or fields.get("state") or "UNKNOWN"
                
                supplier_msgid = supplier_msgid.split('\x00')[0].strip()
                status = status.upper().strip()
                
                self.logger.info(f"🆔 Parsed DLR - Message ID: {supplier_msgid}, Status: {status}")
                
            except Exception as e:
                self.logger.error(f"❌ Failed to parse DLR: {text} | Error: {e}")
                return

            if not supplier_msgid:
                self.logger.warning("❗ Supplier DLR missing msgid")
                return

            # ✅ PERBAIKAN: Safe dictionary access dengan error handling
            client_msgid = None
            info = None
            client_session = None
            
            async with dict_lock:
                client_msgid = SUPPLIER_TO_CLIENT_MSGID.get(supplier_msgid)
                if client_msgid:
                    info = CLIENT_MSGID_MAP.get(client_msgid)
                    if info and info.get("system_id"):
                        client_session = CLIENT_SESSIONS.get(info["system_id"])

            if not info or not client_session or not client_session.bound:
                self.logger.warning(f"❗ Client session untuk msg_id {supplier_msgid} tidak ditemukan. DLR dropped.")
                self.logger.info(f"   Available mappings: {list(SUPPLIER_TO_CLIENT_MSGID.keys())}")
                return

            # ✅ PERBAIKAN: Thread-safe sequence handling
            try:
                if hasattr(client_session, 'next_seq'):
                    sequence = await client_session.next_seq()
                else:
                    # Fallback dengan lock manual
                    if hasattr(client_session, '_write_lock'):
                        async with client_session._write_lock:
                            client_session.sequence += 1
                            sequence = client_session.sequence
                    else:
                        # Last resort
                        client_session.sequence += 1
                        sequence = client_session.sequence

                dlr_pdu = build_deliver_sm_dlr(
                    msg_id=client_msgid,
                    source_addr=info["source_addr"],
                    dest_addr=info["dest_addr"],
                    stat=status,
                    sequence=sequence
                )

                if hasattr(client_session, 'safe_write'):
                    await client_session.safe_write(dlr_pdu)
                else:
                    client_session.transport.write(dlr_pdu)
                    
                self.logger.info(f"✅ Forwarded DLR to client: {info['system_id']}, msgid={client_msgid}, status={status}")
                
                # ✅ PERBAIKAN: Hapus mapping dengan pop() yang lebih safe
                async with dict_lock:
                    SUPPLIER_TO_CLIENT_MSGID.pop(supplier_msgid, None)
                    CLIENT_MSGID_MAP.pop(client_msgid, None)
                        
            except Exception as e:
                self.logger.error(f"❌ Failed to forward DLR to client {info['system_id']}: {e}")
            return

        # ----------------------------
        # deliver_sm_resp
        # ----------------------------
        if pdu.command_id == CommandId.deliver_sm_resp:
            self.logger.debug("Received deliver_sm_resp (DLR ack)")
            return

        # ----------------------------
        # Generic NACK
        # ----------------------------
        nack = PDU(CommandId.generic_nack, CommandStatus.ESME_RINVCMDID, pdu.sequence, b"").pack()
        await self.safe_write(nack)

async def cleanup_existing_mappings():
    """Bersihkan existing mappings dari null characters"""
    async with dict_lock:
        cleaned = {}
        for key, value in SUPPLIER_TO_CLIENT_MSGID.items():
            clean_key = key.replace('\x00', '').strip() if isinstance(key, str) else key
            cleaned[clean_key] = value
        SUPPLIER_TO_CLIENT_MSGID.clear()
        SUPPLIER_TO_CLIENT_MSGID.update(cleaned)
        logging.info(f"🧹 Cleaned existing mappings: {list(SUPPLIER_TO_CLIENT_MSGID.keys())}")

# ----------------------------------------
# Main server entry
# ----------------------------------------
async def run_server():
    file_handler = logging.FileHandler('pysmpp.log')
    formatter = logging.Formatter("%(asctime)s | %(levelname)-8s | %(name)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    file_handler.setFormatter(formatter)
    logging.basicConfig(level='DEBUG', handlers=[file_handler])

    import os
    current_dir = os.path.dirname(__file__)

    await db.connect()
    creds = await load_credentials(db)
    apply_new_credentials(creds)

    from client.client_01 import SmppClient

    global SUPPLIER_CLIENT
    # SUPPLIER_CLIENT = SmppClient("103.65.237.145", 37001, "ptest001", "Pasming")
    SUPPLIER_CLIENT = SmppClient("127.0.0.1", 2025, "aggregator", "aggregatorpass")
    # SUPPLIER_CLIENT = SmppClient("sms-gw.redision.com", 37002, "dwi_test", "123456")
    await SUPPLIER_CLIENT.connect()
    await SUPPLIER_CLIENT.bind_transceiver()

    loop = asyncio.get_running_loop()
    server = await loop.create_server(lambda: SmppServerProtocol(), "0.0.0.0", 37002)
    logging.info("Server started on port 37002")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(run_server())