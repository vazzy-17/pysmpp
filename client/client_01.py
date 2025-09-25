# client.py
import asyncio
import struct
import logging
import smpplib.consts
from server.smpp_common import (
    PDU, CommandId, CommandStatus, HEADER_LEN, HEADER_FMT,
    build_bind_transceiver, build_enquire_link,build_enquire_link_resp, read_cstring,
    parse_deliver_sm, CLIENT_SESSIONS, build_submit_sm_pdu
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
                # self.pending_responses = {}  # seq → Future

    def next_seq(self):
        self.sequence += 1
        return self.sequence

    async def bind_transceiver(self):
        seq = self.next_seq()
        pdu = build_bind_transceiver(self.system_id, self.password, "", sequence=seq)

        # Simpan future sebelum kirim
        future = asyncio.get_event_loop().create_future()
        self._pending[seq] = future

        self.writer.write(pdu)
        await self.writer.drain()

        # Jalankan loop pembaca permanen
        asyncio.create_task(self._receiver_loop())
        asyncio.create_task(self._keepalive())

        # Tunggu hasil bind
        resp = await asyncio.wait_for(future, timeout=10)
        if resp.command_status != CommandStatus.ESME_ROK:
            raise RuntimeError("Bind failed")
        self.logger.info("Bind successful")

    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        self.logger.info("Connected to %s:%s", self.host, self.port)

    async def _receiver_loop(self):
        """
        Loop utama untuk membaca semua PDU dari supplier.
        Semua PDU masuk ditangani sesuai tipe:
        - response PDU (submit_sm_resp, bind_resp)
        - deliver_sm (DLR atau pesan masuk)
        - enquire_link
        """
        while True:
            try:
                pdu = await self._read_pdu()  # baca PDU dari supplier
            except Exception as e:
                logging.error(f"❌ Error reading PDU: {e}")
                break

            logging.debug(f"⬅️ Received PDU: cmd_id=0x{pdu.command_id:08X}, seq={pdu.sequence}, body={pdu.short_message}")

            # Response PDU (bit 0x80000000 = 1)
            if pdu.command_id & 0x80000000:
                seq = pdu.sequence
                if seq in self._pending:
                    logging.info(f"✅ Matched response PDU: seq={seq}")
                    self._pending[seq].set_result(pdu)
                    del self._pending[seq]
                else:
                    logging.warning(f"⚠️ Unmatched response PDU: cmd_id=0x{pdu.command_id:08X}, seq={seq}")
                continue

            # deliver_sm (DLR atau inbound message)
            if pdu.command_id == CommandId.deliver_sm:
                logging.info(f"📩 deliver_sm received: from={pdu.source_addr}, to={pdu.destination_addr}, msg={pdu.short_message}")
                asyncio.create_task(self._handle_deliver_sm(pdu))
                continue

            # enquire_link
            if pdu.command_id == CommandId.enquire_link:
                logging.info("🔄 enquire_link received, sending response")
                await build_enquire_link(pdu.sequence)
                continue

            

            # unhandled PDU
            logging.warning(f"⚠️ Unknown PDU type: cmd_id=0x{pdu.command_id:08X}, seq={pdu.sequence}")

    async def _handle_deliver_sm(self, pdu):
        """
        Menangani deliver_sm dari supplier:
        - Bisa berupa DLR (status DELIVRD, FAILED, dsb.)
        - Bisa berupa pesan masuk
        """
        # parse message_state jika DLR (TLV)
        msg_state = pdu.params.get('message_state')
        
        logging.info(f"DLR/Inbound msg: from={pdu.source_addr}, to={pdu.destination_addr}, state={msg_state}, msg={pdu.short_message}")

        # forward ke client
        # await self.forward_to_client(pdu)

    async def send_submit_sm(self, pdu):
        """
        Kirim submit_sm ke supplier dan tunggu submit_sm_resp
        """
        seq = self._next_sequence()
        future = asyncio.get_event_loop().create_future()
        self._pending[seq] = future

        pdu.sequence = seq
        self.writer.write(pdu.pack())
        await self._writer.drain()
        logging.info(f"➡️ submit_sm sent: seq={seq}, to={pdu.destination_addr}, msg={pdu.short_message}")

        # tunggu submit_sm_resp
        resp = await asyncio.wait_for(future, timeout=10)
        logging.info(f"✅ submit_sm_resp received: seq={seq}, status={resp.status}")
        return resp

    async def _read_pdu(self):
        """
        Membaca PDU dari supplier.
        """
        # baca 4 byte pertama untuk command_length
        header = await self.reader.readexactly(16)  # header SMPP = 16 byte
        if len(header) < 16:
            raise ConnectionError("Header PDU terlalu pendek")

        # unpack header
        command_length, command_id, command_status, sequence = struct.unpack(">IIII", header)
        body_length = command_length - 16
        body = await self.reader.readexactly(body_length)

        # parse body menjadi PDU object
        pdu = PDU(
            command_id=command_id,
            command_status=command_status,
            sequence=sequence,
            body=body
        )
        return pdu

    async def _keepalive(self):
        while True:
            await asyncio.sleep(60)

            seq = self.next_seq()
            pdu = build_enquire_link(seq)

            future = asyncio.get_event_loop().create_future()
            self._pending[seq] = future

            self.writer.write(pdu)
            await self.writer.drain()
            self.logger.debug(f"sent enquire_link with seq={seq}")

            try:
                resp = await asyncio.wait_for(future, timeout=10)
                self.logger.debug(f"received enquire_link_resp for seq={seq}")
            except asyncio.TimeoutError:
                self.logger.warning(f"time out waiting for enquire_link_resp seq={seq}")
                del self._pending[seq]

            # self.writer.write(build_enquire_link(self.next_seq()))
            # await self.writer.drain()

    async def submit_sm(self, src, dst, text):
        self.logger.info(f"📤 Mengirim submit_sm: from={src}, to={dst}, text={text}")
        from server.smpp_common import build_submit_sm

        # pdus = build_submit_sm(src, dst, text, sequence=self.next_seq())
        pdus = build_submit_sm_pdu(src, dst, text, start_sequence=self.next_seq())
        responses = []

        for pdu in pdus:
            seq = pdu.sequence
            future = asyncio.get_event_loop().create_future()
            self._pending[seq] = future

            self.writer.write(pdu.pack())
            await self.writer.drain()

            try:
                resp = await asyncio.wait_for(future, timeout=10)
                desc = COMMAND_STATUS_DESCRIPTIONS.get(resp.command_status, "Unknown error")
                self.logger.warning(f"📥 Respon submit_sm dari supplier: status=0x{resp.command_status:02X} ({desc})")

                responses.append(resp)
            except asyncio.TimeoutError:
                self.logger.error(f"⏰ Timeout menunggu submit_sm_resp untuk seq={seq}")

        return responses

    async def close(self):
        self.writer.close()
        await self.writer.wait_closed()
