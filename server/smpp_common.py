# smpp_common.py
import struct
import uuid
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional, Tuple
from server.credential_watcher import  GLOBAL_CREDENTIALS
from time import strftime
from typing import Optional, TYPE_CHECKING
import asyncio

if TYPE_CHECKING:
    from server.server import SmppServerProtocol
    from client.client_01 import SmppClient

dict_lock = asyncio.Lock()
SUPPLIER_CLIENT: Optional["SmppClient"] = None
CLIENT_SESSIONS: dict[str, "SmppServerProtocol"] = {}
SUPPLIER_TO_CLIENT_MSGID = {}  # supplier_msgid -> client_msgid
CLIENT_MSGID_MAP = {}          # client_msgid -> {system_id, source_addr, dest_addr}
# -----------------------------
# SMPP Constants
# -----------------------------
# pdu header: 16 byte: length,cmd_id,status,seq
HEADER_FMT = ">IIII"
HEADER_LEN = 16

class CommandId(IntEnum):
    bind_receiver       = 0x00000001
    bind_transmitter    = 0x00000002
    bind_transceiver    = 0x00000009
    outbind             = 0x0000000B
    unbind              = 0x00000006
    unbind_resp         = 0x80000006
    submit_sm           = 0x00000004
    submit_sm_resp      = 0x80000004
    deliver_sm          = 0x00000005
    deliver_sm_resp     = 0x80000005
    enquire_link        = 0x00000015
    enquire_link_resp   = 0x80000015
    generic_nack        = 0x80000000
    bind_receiver_resp  = 0x80000001
    bind_transmitter_resp   = 0x80000002
    bind_transceiver_resp   = 0x80000009

class CommandStatus(IntEnum):
    ESME_ROK                = 0x00000000
    ESME_RINVMSGLEN         = 0x00000001
    ESME_RINVCMDLEN         = 0x00000002
    ESME_RINVCMDID          = 0x00000003
    ESME_RINVBNDSTS         = 0x00000004
    ESME_RALYBND            = 0x00000005
    ESME_RINVPRTFLG         = 0x00000006
    ESME_RINVREGDLV         = 0x00000007
    ESME_RSYSERR            = 0x00000008
    ESME_RBINDFAIL          = 0x0000000D
    ESME_RINVPASWD          = 0x0000000E
    ESME_RINVSYSID          = 0x0000000F
    ESME_RINVVER            = 0x0000000A

class Ton(IntEnum):
    UNKNOWN = 0
    INTERNATIONAL = 1
    NATIONAL = 2
    ALPHANUMERIC = 5
class Npi(IntEnum):
    UNKNOWN = 0
    ISDN = 1
DLR_STATUS_MAP = {
    "DELIVRD": "Delivered",
    "EXPIRED": "Expired", 
    "DELETED": "Deleted",
    "UNDELIV": "Undeliverable",
    "ACCEPTD": "Accepted",
    "UNKNOWN": "Unknown",
    "REJECTD": "Rejected",

    # Extended status
    "ENROUTE": "Enroute",
    "ACCEPTED": "Accepted",
    "FAILED": "Failed",
    "DELIVERED": "Delivered",
    "UNDELIVERABLE": "Undeliverable",

    # Numeric status codes
    "0": "DELIVRD",
    "1": "EXPIRED", 
    "2": "DELETED",
    "3": "UNDELIV",
    "4": "ACCEPTD",
    "5": "UNKNOWN",
    "6": "REJECTD"
}

# -----------------------------
# Credential store (dynamic)
# -----------------------------
def apply_new_credentials(new_creds: dict):
    GLOBAL_CREDENTIALS.clear()
    GLOBAL_CREDENTIALS.update(new_creds)

# -----------------------------
# Utils
# -----------------------------
def cstring(s: str) -> bytes:
    return s.encode("ascii", errors="ignore") + b"\x00"
def read_cstring(buf: memoryview, offset: int) -> Tuple[str, int]:
    for i in range(offset, len(buf)):
        if buf[i] == 0:
            val = bytes(buf[offset:i]).decode("ascii", errors="ignore")
            return val, i + 1
    raise ValueError("c-Octet string terminator not found")

# -----------------------------
# PDU
# -----------------------------
@dataclass
class PDU:
    command_id: int
    command_status: int
    sequence: int
    body: bytes

    def __init__(self, command_id, command_status, sequence, body: bytes):
        self.command_id = command_id
        self.command_status = command_status
        self.sequence = sequence
        self.body = body

        # default, nanti bisa diisi setelah parsing submit_sm/deliver_sm
        self.source_addr = ""
        self.destination_addr = ""
        self.params = {}  # TLV, message_state, dsb.

    def pack(self) -> bytes:
        total_len = HEADER_LEN + len(self.body)
        header = struct.pack(HEADER_FMT, total_len, self.command_id, self.command_status, self.sequence)
        return header + self.body
    
    @staticmethod
    def unpack(data: bytes) -> "PDU":
        if len(data) < HEADER_LEN:
            raise ValueError("data too short")
        length,cmd_id, status, seq = struct.unpack(HEADER_FMT, data[:HEADER_LEN])
        if length != len(data):
            raise ValueError(f"length mismatch: header={length} actual={len(data)}")
        return PDU(cmd_id, status, seq, data[HEADER_LEN:])
    
    def short_message(self):
        """
        Ambil short_message dari body. 
        Default coba decode UTF-8, bisa ganti jika body UCS2 atau GSM 7-bit.
        """
        try:
            return self.body.decode('utf-8')
        except Exception:
            return self.body
    
# -----------------------------
# PDU Builders & Parsers
# -----------------------------
def build_bind_transceiver(system_id: str, password:str, system_type: str,
                               interface_version: int = 0x34,
                               addr_ton: int = Ton.INTERNATIONAL,
                               addr_npi: int = Npi.ISDN,
                               address_range: str = "",
                               sequence: int = 1) -> bytes:
        body = b"".join([cstring(system_id),cstring(password),cstring(system_type),
                         struct.pack(">B", interface_version),
                         struct.pack(">B", addr_ton),
                         struct.pack(">B", addr_npi),
                         cstring(address_range),
                         ])
        p = PDU(CommandId.bind_transceiver, 0, sequence, body)
        return p.pack()
def build_bind_transceiver_resp(system_id: str, status: int, sequence:int) -> bytes:
        body = cstring(system_id)
        p = PDU(CommandId.bind_transceiver_resp, status, sequence, body)
        return p.pack()
def parse_bind_transceiver_body(body: bytes):
        mv = memoryview(body)
        off = 0
        system_id, off = read_cstring(mv, off)
        password, off = read_cstring(mv, off)
        system_type, off = read_cstring(mv, off)
        interface_version = mv[off]
        off += 1
        addr_ton = mv[off]
        off += 1
        addr_npi = mv[off]
        off += 1
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
def build_enquire_link(sequence: int) -> bytes:
        return PDU(CommandId.enquire_link, 0, sequence, b"").pack()
def build_enquire_link_resp(sequence: int) -> bytes:
        return PDU(CommandId.enquire_link_resp, 0, sequence, b"").pack()
def build_submit_sm(source_addr: str, dest_addr: str, short_message: str,
                        source_ton: int = Ton.INTERNATIONAL,
                        source_npi: int = Npi.ISDN,
                        dest_ton: int = Ton.INTERNATIONAL,
                        dest_npi: int = Npi.ISDN,
                        data_coding: int= 0,
                        sequence: int = 1) -> bytes:
        
        if data_coding == 8:
            max_len = 67
            encode_fn = lambda s: s.encode("utf-16-be")
        else:
            max_len = 153
            encode_fn = lambda s: s.encode("ascii", errors="replace")
        
        encode_full = encode_fn(short_message)
        segment_size = max_len
        segments = [encode_full[i:i + segment_size]for i in range(0, len(encode_full), segment_size)]
        total_segments = len(segments)
        ref_num = uuid.uuid4().int & 0xFF
        pdus = []
        seq = sequence

        for idx, segment in enumerate(segments, start=1):
            if total_segments > 1:
                udh = bytes([0x05, 0x00, 0x03, ref_num, total_segments, idx])
                msg_bytes = udh + segment
                esm_class = 0x40
            else:
                msg_bytes = segment
                esm_class = 0x00

            body = b"".join([
                cstring(""),    # service_type
                struct.pack(">B", source_ton),
                struct.pack(">B", source_npi),
                cstring(source_addr),
                struct.pack(">B", dest_ton),
                struct.pack(">B", dest_npi),
                cstring(dest_addr),
                struct.pack(">B", esm_class), # esm_class
                struct.pack(">B", 0), # protocol_id
                struct.pack(">B", 0), #priority_flag
                cstring(""), # schedule_delivery_time
                cstring(""), # validity_period
                struct.pack(">B", 1), # registered_delivery
                struct.pack(">B", 0), # replace_if_present_flag
                struct.pack(">B", data_coding),
                struct.pack(">B", 0), # sm_default_msg_id
                struct.pack(">B", len(msg_bytes)),
                msg_bytes,
            ])
            pdus.append(PDU(CommandId.submit_sm, 0, seq, body).pack())
            seq += 1
        return pdus
def build_submit_sm_pdu(source_addr: str, dest_addr: str, short_message: str,
                        source_ton: int = Ton.INTERNATIONAL,
                        source_npi: int = Npi.ISDN,
                        dest_ton: int = Ton.INTERNATIONAL,
                        dest_npi: int = Npi.ISDN,
                        data_coding: int = 0,
                        start_sequence: int = 1) -> list[PDU]:
    """
    Return list of PDU object, bukan bytes
    """
    if data_coding == 8:
        max_len = 67
        encode_fn = lambda s: s.encode("utf-16-be")
    else:
        max_len = 153
        encode_fn = lambda s: s.encode("ascii", errors="replace")

    encoded = encode_fn(short_message)
    segments = [encoded[i:i + max_len] for i in range(0, len(encoded), max_len)]
    total = len(segments)
    ref_num = uuid.uuid4().int & 0xFF
    pdus = []

    for idx, seg in enumerate(segments, start=1):
        if total > 1:
            udh = bytes([0x05, 0x00, 0x03, ref_num, total, idx])
            msg = udh + seg
            esm_class = 0x40
        else:
            msg = seg
            esm_class = 0x00

        body = b"".join([
            cstring(""),  # service_type
            struct.pack(">B", source_ton),
            struct.pack(">B", source_npi),
            cstring(source_addr),
            struct.pack(">B", dest_ton),
            struct.pack(">B", dest_npi),
            cstring(dest_addr),
            struct.pack(">B", esm_class),
            struct.pack(">B", 0),  # protocol_id
            struct.pack(">B", 0),  # priority_flag
            cstring(""),  # schedule_delivery_time
            cstring(""),  # validity_period
            struct.pack(">B", 1),  # registered_delivery
            struct.pack(">B", 0),  # replace_if_present_flag
            struct.pack(">B", data_coding),
            struct.pack(">B", 0),  # sm_default_msg_id
            struct.pack(">B", len(msg)),
            msg
        ])
        pdus.append(PDU(CommandId.submit_sm, 0, start_sequence, body))
        start_sequence += 1

    return pdus
def parse_submit_sm_body(body: bytes):
    mv = memoryview(body)
    off = 0
    service_type, off =read_cstring(mv, off)
    source_addr_ton = mv[off]
    off += 1
    source_addr_npi = mv[off]
    off += 1
    source_addr, off = read_cstring(mv, off)
    dest_addr_ton = mv[off]
    off += 1
    dest_addr_npi = mv[off]
    off += 1
    dest_addr, off = read_cstring(mv, off)
    esm_class = mv[off]
    off += 1
    protocol_id = mv[off]
    off += 1
    priority_flag = mv[off]
    off += 1
    schedule_delivery_time, off =read_cstring(mv, off)
    validity_period, off = read_cstring(mv, off)
    registered_delivery = mv[off]
    off += 1
    replace_if_present_flag = mv[off]
    off += 1
    data_coding = mv[off]
    off += 1
    sm_default_msg_id = mv[off]
    off += 1
    sm_length = mv[off]
    off += 1
    short_message = bytes(mv[off:off + sm_length])

    return{
        "service_type": service_type,
        "source_addr_ton": source_addr_ton,
        "source_addr_npi": source_addr_npi,
        "source_addr": source_addr,
        "dest_addr_ton": dest_addr_ton,
        "dest_addr_npi": dest_addr_npi,
        "dest_addr": dest_addr,
        "esm_class": esm_class,
        "protocol_id": protocol_id,
        "priority_flag": priority_flag,
        "schedule_delivery_time": schedule_delivery_time,
        "validity_period": validity_period,
        "registered_delivery": registered_delivery,
        "replace_if_present_flag": replace_if_present_flag,
        "data_coding": data_coding,
        "sm_default_msg_id": sm_default_msg_id,
        "sm_length": sm_length,
        "short_message": short_message,
    }
def parse_deliver_sm(body: bytes) -> dict:
    """
    Parse deliver_sm PDU dengan approach yang lebih robust.
    Handle berbagai format dan edge cases.
    """
    try:
        offset = 0
        fields = {}
        
        # Helper function untuk read cstring
        def read_cstring_safe():
            nonlocal offset
            if offset >= len(body):
                return ""
            start = offset
            while offset < len(body) and body[offset] != 0:
                offset += 1
            result = body[start:offset].decode('ascii', errors='ignore')
            if offset < len(body):
                offset += 1  # skip null terminator
            return result
        
        # Parse mandatory fields
        try:
            # service_type
            fields['service_type'] = read_cstring_safe()
            
            # source_addr_ton, source_addr_npi
            if offset + 2 <= len(body):
                fields['source_addr_ton'] = body[offset]
                offset += 1
                fields['source_addr_npi'] = body[offset]
                offset += 1
            
            # source_addr
            fields['source_addr'] = read_cstring_safe()
            
            # dest_addr_ton, dest_addr_npi
            if offset + 2 <= len(body):
                fields['dest_addr_ton'] = body[offset]
                offset += 1
                fields['dest_addr_npi'] = body[offset]
                offset += 1
            
            # destination_addr
            fields['dest_addr'] = read_cstring_safe()
            
            # esm_class, protocol_id, priority_flag
            if offset + 3 <= len(body):
                fields['esm_class'] = body[offset]
                offset += 1
                fields['protocol_id'] = body[offset]
                offset += 1
                fields['priority_flag'] = body[offset]
                offset += 1
            
            # schedule_delivery_time
            fields['schedule_delivery_time'] = read_cstring_safe()
            
            # validity_period
            fields['validity_period'] = read_cstring_safe()
            
            # registered_delivery, replace_if_present_flag, data_coding, sm_default_msg_id
            if offset + 4 <= len(body):
                fields['registered_delivery'] = body[offset]
                offset += 1
                fields['replace_if_present_flag'] = body[offset]
                offset += 1
                fields['data_coding'] = body[offset]
                offset += 1
                fields['sm_default_msg_id'] = body[offset]
                offset += 1
            
            # sm_length
            if offset < len(body):
                sm_length = body[offset]
                offset += 1
                
                # short_message
                if offset + sm_length <= len(body):
                    fields['short_message'] = body[offset:offset + sm_length]
                else:
                    # Jika sm_length terlalu besar, ambil sampai akhir body
                    fields['short_message'] = body[offset:]
            else:
                fields['short_message'] = b''
                
        except Exception as e:
            print(f"⚠️ Warning in parse_deliver_sm: {e}")
            # Fallback: return empty but don't crash
        
        # DEBUG: Log parsed fields
        print(f"🔍 parse_deliver_sm - Parsed fields: {list(fields.keys())}")
        if 'short_message' in fields:
            print(f"🔍 parse_deliver_sm - short_message: {fields['short_message']}")
            print(f"🔍 parse_deliver_sm - short_message text: {fields['short_message'].decode('ascii', errors='ignore')}")
        
        return {
            "source_addr": fields.get('source_addr', ''),
            "dest_addr": fields.get('dest_addr', ''),
            "text": fields.get('short_message', b'')
        }
        
    except Exception as e:
        print(f"❌ Critical error in parse_deliver_sm: {e}")
        # Return the raw body for manual parsing
        return {
            "source_addr": "",
            "dest_addr": "", 
            "text": body  # Return full body as fallback
        }
def build_deliver_sm_dlr(msg_id: str, source_addr: str, dest_addr: str, stat: str = "", sequence: int = 1) -> bytes:
    """
    Build deliver_sm PDU for DLR with proper status handling.
    If stat is empty, default to UNKNOWN instead of DELIVRD.
    """
    # Validate and normalize status
    normalized_stat = normalize_dlr_status(stat) if stat else "UNKNOWN"
    
    # Validate it's a known status
    if normalized_stat not in DLR_STATUS_MAP and normalized_stat not in ["0", "1", "2", "3", "4", "5", "6"]:
        normalized_stat = "UNKNOWN"
    
    now = strftime("%y%m%d%H%M")
    dlr_text = (f"id:{msg_id} sub:001 dlvrd:001 submit date:{now} done date:{now} stat:{normalized_stat} err:000 text:DLR").encode("ascii")
    
    body = b"".join([
        cstring(""),        # service_type
        struct.pack(">B", Ton.INTERNATIONAL),
        struct.pack(">B", Npi.ISDN),
        cstring(source_addr),
        struct.pack(">B", Ton.INTERNATIONAL),
        struct.pack(">B", Npi.ISDN),
        cstring(dest_addr),
        struct.pack(">B", 0x04),    # esm_class: delivery receipt
        struct.pack(">B", 0),       # protocol_id
        struct.pack(">B", 0),       # priority_flag
        cstring(""),                # schedule_delivery_time
        cstring(""),                # validity_period
        struct.pack(">B", 0),       # registered_delivery
        struct.pack(">B", 0),       # replace_if_present_flag
        struct.pack(">B", 0),       # data_coding
        struct.pack(">B", 0),       # sm_default_msg_id
        struct.pack(">B", len(dlr_text)),
        dlr_text
    ])
    return PDU(CommandId.deliver_sm, 0, sequence, body).pack()
def strip_udh_and_decode(short_message: bytes, data_coding: int) -> str:
    if len(short_message) >= 6 and short_message.startswith(b"\x05\x00\x03"):
        payload = short_message[6:]
    else:
        payload = short_message

    if data_coding == 8:
        return payload.decode("utf-16-be", errors="replace")
    else:
        return payload.decode("ascii", errors="replace")
    
def clean_smpp_string(s: str) -> str:
    """Bersihkan string dari null characters dan whitespace tidak diinginkan"""
    if not s:
        return s
    # Hapus null characters dan split pada null terminator pertama
    cleaned = s.split('\x00')[0]
    # Hapus karakter kontrol lainnya jika ada
    cleaned = ''.join(char for char in cleaned if ord(char) >= 32 or char in '\t\n\r')
    return cleaned.strip()

def normalize_dlr_status(status: str) -> str:
    """Normalize DLR status to standard SMPP status codes."""
    if not status:
        return "UNKNOWN"
    
    status_upper = status.upper().strip()

    # Handle numeric status codes
    if status_upper in ["0", "1", "2", "3", "4", "5", "6"]:
        return DLR_STATUS_MAP.get(status_upper, "UNKNOWN")
    
    # Handle common status variations
    status_mapping = {
        "DELIVERED": "DELIVRD",
        "ACCEPTED": "ACCEPTD", 
        "UNDELIVERABLE": "UNDELIV",
        "FAILED": "UNDELIV",
        "ENROUTE": "ACCEPTD",
        "REJECTED": "REJECTD"
    }
    
    # Return mapped status or original if no mapping found
    return status_mapping.get(status_upper, status_upper)
    
def get_dlr_status_description(status: str) -> str:
    """Get human readable description for DLR status"""
    status = normalize_dlr_status(status)
    return DLR_STATUS_MAP.get(status, f"Unknown status: {status}")