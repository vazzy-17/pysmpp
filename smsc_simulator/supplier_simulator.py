# supplier_simulator_standalone.py

import asyncio
import struct
import uuid
import logging
import random
from time import strftime
from dataclasses import dataclass
from enum import IntEnum

# SMPP Constants (standalone)
HEADER_FMT = ">IIII"
HEADER_LEN = 16

class CommandId(IntEnum):
    bind_transceiver = 0x00000009
    bind_transceiver_resp = 0x80000009
    submit_sm = 0x00000004
    submit_sm_resp = 0x80000004
    deliver_sm = 0x00000005
    deliver_sm_resp = 0x80000005
    enquire_link = 0x00000015
    enquire_link_resp = 0x80000015

class CommandStatus(IntEnum):
    ESME_ROK = 0x00000000

class Ton(IntEnum):
    INTERNATIONAL = 1

class Npi(IntEnum):
    ISDN = 1

@dataclass
class PDU:
    command_id: int
    command_status: int
    sequence: int
    body: bytes

    def pack(self) -> bytes:
        total_len = HEADER_LEN + len(self.body)
        header = struct.pack(HEADER_FMT, total_len, self.command_id, self.command_status, self.sequence)
        return header + self.body
    
    @staticmethod
    def unpack(data: bytes) -> "PDU":
        length, cmd_id, status, seq = struct.unpack(HEADER_FMT, data[:HEADER_LEN])
        return PDU(cmd_id, status, seq, data[HEADER_LEN:])

# Utility functions
def cstring(s: str) -> bytes:
    return s.encode("ascii", errors="ignore") + b"\x00"

def read_cstring(buf: memoryview, offset: int):
    for i in range(offset, len(buf)):
        if buf[i] == 0:
            val = bytes(buf[offset:i]).decode("ascii", errors="ignore")
            return val, i + 1
    raise ValueError("c-Octet string terminator not found")

def parse_bind_transceiver_body(body: bytes):
    mv = memoryview(body)
    off = 0
    system_id, off = read_cstring(mv, off)
    password, off = read_cstring(mv, off)
    system_type, off = read_cstring(mv, off)
    interface_version = mv[off]; off += 1
    addr_ton = mv[off]; off += 1
    addr_npi = mv[off]; off += 1
    address_range, off = read_cstring(mv, off)
    return {
        "system_id": system_id,
        "password": password,
        "system_type": system_type,
        "interface_version": interface_version,
        "addr_ton": addr_ton,
        "addr_npi": addr_npi,
        "address_range": address_range,
    }

def build_bind_transceiver_resp(system_id: str, status: int, sequence: int) -> bytes:
    body = cstring(system_id)
    p = PDU(CommandId.bind_transceiver_resp, status, sequence, body)
    return p.pack()

def parse_submit_sm_body(body: bytes):
    mv = memoryview(body)
    off = 0
    service_type, off = read_cstring(mv, off)
    source_addr_ton = mv[off]; off += 1
    source_addr_npi = mv[off]; off += 1
    source_addr, off = read_cstring(mv, off)
    dest_addr_ton = mv[off]; off += 1
    dest_addr_npi = mv[off]; off += 1
    dest_addr, off = read_cstring(mv, off)
    esm_class = mv[off]; off += 1
    protocol_id = mv[off]; off += 1
    priority_flag = mv[off]; off += 1
    schedule_delivery_time, off = read_cstring(mv, off)
    validity_period, off = read_cstring(mv, off)
    registered_delivery = mv[off]; off += 1
    replace_if_present_flag = mv[off]; off += 1
    data_coding = mv[off]; off += 1
    sm_default_msg_id = mv[off]; off += 1
    sm_length = mv[off]; off += 1
    short_message = bytes(mv[off:off + sm_length])

    return {
        "service_type": service_type,
        "source_addr": source_addr,
        "dest_addr": dest_addr,
        "data_coding": data_coding,
        "short_message": short_message,
    }

def strip_udh_and_decode(short_message: bytes, data_coding: int) -> str:
    if len(short_message) >= 6 and short_message.startswith(b"\x05\x00\x03"):
        payload = short_message[6:]
    else:
        payload = short_message

    if data_coding == 8:
        return payload.decode("utf-16-be", errors="replace")
    else:
        return payload.decode("ascii", errors="replace")

def build_deliver_sm_dlr(msg_id: str, source_addr: str, dest_addr: str, stat: str = "DELIVRD", sequence: int = 1) -> bytes:
    """Build DLR dengan status yang di-hardcode"""
    now = strftime("%y%m%d%H%M")
    
    # ⚠️ PERBAIKAN: Tambahkan field stat: dalam DLR text
    dlr_text = (f"id:{msg_id} sub:001 dlvrd:001 submit date:{now} done date:{now} stat:{stat} err:000 text:DLR").encode("ascii")
    
    # DEBUG: Log DLR text yang akan dikirim
    print(f"🔍 DLR Text to send: {dlr_text.decode('ascii')}")
    
    body = b"".join([
        cstring(""),
        struct.pack(">B", Ton.INTERNATIONAL),
        struct.pack(">B", Npi.ISDN),
        cstring(source_addr),
        struct.pack(">B", Ton.INTERNATIONAL),
        struct.pack(">B", Npi.ISDN),
        cstring(dest_addr),
        struct.pack(">B", 0x04),  # esm_class: delivery receipt
        struct.pack(">B", 0),     # protocol_id
        struct.pack(">B", 0),     # priority_flag
        cstring(""),              # schedule_delivery_time
        cstring(""),              # validity_period
        struct.pack(">B", 0),     # registered_delivery
        struct.pack(">B", 0),     # replace_if_present_flag
        struct.pack(">B", 0),     # data_coding
        struct.pack(">B", 0),     # sm_default_msg_id
        struct.pack(">B", len(dlr_text)),
        dlr_text
    ])
    return PDU(CommandId.deliver_sm, 0, sequence, body).pack()

class SupplierSimulator(asyncio.Protocol):
    def __init__(self, fixed_status=None):
        self.transport = None
        self.logger = logging.getLogger("supplier")
        self.sequence = 1
        self.bound = False
        self.message_counter = 0
        
        # Daftar status DLR
        self.dlr_statuses = [
            "DELIVRD",    # Message delivered
            "EXPIRED",    # Message expired
            "UNDELIV",    # Message undeliverable  
            "REJECTD",    # Message rejected
            "UNKNOWN",    # Unknown status
        ]
        
        self.fixed_status = fixed_status

    def _get_dlr_status(self):
        """Pilih status DLR"""
        if self.fixed_status:
            return self.fixed_status
        # Random status
        return random.choice(self.dlr_statuses)

    def connection_made(self, transport):
        self.transport = transport
        peer = transport.get_extra_info("peername")
        self.logger.info(f"🔗 Aggregator connected: {peer}")
        if self.fixed_status:
            self.logger.info(f"📊 DLR Status: FIXED to {self.fixed_status}")
        else:
            self.logger.info(f"📊 DLR Status: RANDOM from {self.dlr_statuses}")

    def data_received(self, data: bytes):
        asyncio.create_task(self._handle(data))

    async def _handle(self, data: bytes):
        offset = 0
        while offset + 4 <= len(data):
            length = struct.unpack(">I", data[offset:offset + 4])[0]
            if offset + length > len(data):
                self.logger.warning("Incomplete PDU received")
                break
            pdu_data = data[offset:offset + length]
            offset += length

            try:
                pdu = PDU.unpack(pdu_data)
            except Exception as e:
                self.logger.error(f"Invalid PDU: {e}")
                continue

            await self._process_pdu(pdu)

    async def _process_pdu(self, pdu: PDU):
        if pdu.command_id == CommandId.bind_transceiver:
            params = parse_bind_transceiver_body(pdu.body)
            self.logger.info(f"📥 Received BIND from {params['system_id']}")
            resp = build_bind_transceiver_resp(
                system_id=params['system_id'],
                status=CommandStatus.ESME_ROK,
                sequence=pdu.sequence
            )
            self.transport.write(resp)
            self.bound = True
            return
            
        if pdu.command_id == CommandId.submit_sm:
            msg = parse_submit_sm_body(pdu.body)
            msg_id = str(uuid.uuid4())
            decoded = strip_udh_and_decode(msg["short_message"], msg["data_coding"])
            self.logger.info(f"📨 Received SMS: from={msg['source_addr']} to={msg['dest_addr']} text='{decoded}'")

            # Kirim submit_sm_resp
            body = cstring(msg_id)
            resp = PDU(CommandId.submit_sm_resp, CommandStatus.ESME_ROK, pdu.sequence, body).pack()
            self.transport.write(resp)

            # Dapatkan status DLR
            dlr_status = self._get_dlr_status()
            self.message_counter += 1
            
            self.logger.info(f"⏳ Will send DLR in 2 seconds with status: {dlr_status}")

            # Kirim DLR dalam 2 detik
            await asyncio.sleep(2)
            self.sequence += 1
            
            # ⚠️ PERBAIKAN: Definisikan dlr_text sebelum digunakan
            now = strftime("%y%m%d%H%M")
            dlr_text_content = f"id:{msg_id} sub:001 dlvrd:001 submit date:{now} done date:{now} stat:{dlr_status} err:000 text:DLR"
            
            # DEBUG: Log DLR content
            self.logger.info(f"🔍 DLR Content: {dlr_text_content}")
            
            dlr_pdu = build_deliver_sm_dlr(
                msg_id=msg_id,
                source_addr=msg["dest_addr"],
                dest_addr=msg["source_addr"],
                stat=dlr_status,
                sequence=self.sequence
            )
            self.transport.write(dlr_pdu)
            self.logger.info(f"✅ DLR sent with status: {dlr_status}")

        if pdu.command_id == CommandId.enquire_link:
            resp = PDU(CommandId.enquire_link_resp, 0, pdu.sequence, b"").pack()
            self.transport.write(resp)

        if pdu.command_id == CommandId.deliver_sm_resp:
            self.logger.debug("📩 ACK received for DLR")

    def connection_lost(self, exc):
        self.logger.warning("🔌 Aggregator disconnected")

async def run_supplier_simulator(host="127.0.0.1", port=2025, fixed_status=None):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%H:%M:%S"
    )
    
    loop = asyncio.get_running_loop()
    server = await loop.create_server(lambda: SupplierSimulator(fixed_status=fixed_status), host, port)
    
    print("=" * 60)
    print("🚀 SUPPLIER SIMULATOR STARTED")
    print(f"📍 Listening on {host}:{port}")
    if fixed_status:
        print(f"📊 DLR Status: FIXED to {fixed_status}")
    else:
        print("📊 DLR Status: RANDOM (DELIVRD, EXPIRED, UNDELIV, etc.)")
    print("=" * 60)
    
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    # Pilih mode:
    # - None untuk random status
    # - "DELIVRD", "UNDELIV", "EXPIRED", dll untuk fixed status
    
    # fixed_status = None  # Random
    fixed_status = "DELIVRD"  # Fixed status
    
    asyncio.run(run_supplier_simulator(fixed_status=fixed_status))