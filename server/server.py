# server.py
from __future__ import annotations
import asyncio
import logging
import uuid
import struct
from server.credential_watcher import start_credential_watcher, GLOBAL_CREDENTIALS, load_credentials
# Di level global
dict_lock = asyncio.Lock()

# buat handler untuk log
logging.getLogger("watchdog.observers.inotify_buffer").setLevel(logging.WARNING)

from server.smpp_common import (
    PDU, CommandId, CommandStatus, Ton, Npi, DLR_STATUS_MAP,
    build_bind_transceiver_resp, parse_bind_transceiver_body,
    build_enquire_link_resp, build_submit_sm, parse_submit_sm_body,
    strip_udh_and_decode, build_deliver_sm_dlr, read_cstring,
    SUPPLIER_CLIENT, CLIENT_SESSIONS
)
# # -----------------------------
# # Credential store (dynamic)
# # -----------------------------
SUPPLIER_TO_CLIENT_MSGID = {}
CLIENT_MSGID_MAP = {}

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

    def connection_made(self, transport: asyncio.Transport):
        self.transport = transport
        self.peer = str(transport.get_extra_info("peername"))
        self.logger.info(f"Client connected: {self.peer}")

    def data_received(self, data: bytes):
        asyncio.create_task(self._handle(data))

    def connection_lost(self, exc):
        if self.bound and self.expected_system_id in CLIENT_SESSIONS:
            del CLIENT_SESSIONS[self.expected_system_id]
        self.logger.info(f"Connection lost: {self.peer}")
    
    

    async def send_dlr_later(self, msg_id, source, dest, delay=2.0, status_code=0):
        await asyncio.sleep(delay)
        if self.transport and self.bound:
            self.sequence += 1
            dlr_pdu = build_deliver_sm_dlr(msg_id, source, dest, DLR_STATUS_MAP.get(status_code, "UNKNOWN"), self.sequence)
            self.transport.write(dlr_pdu)

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
                self.transport.write(nack.pack())
                return

            await self._process_pdu(pdu)
            offset += length

    async def _process_pdu(self, pdu: PDU):
        if pdu.command_id == CommandId.bind_transceiver:
            params = parse_bind_transceiver_body(pdu.body)
            self.logger.info(f"Bind from {params['system_id']}")

            ver = params["interface_version"]
            if not (self.min_version <= ver <= self.max_version):
                status = CommandStatus.ESME_RINVVER
            elif params["system_id"] not in GLOBAL_CREDENTIALS:
                status = CommandStatus.ESME_RINVSYSID
            elif GLOBAL_CREDENTIALS[params["system_id"]] != params["password"]:
                status = CommandStatus.ESME_RINVPASWD
            elif self.bound:
                status = CommandStatus.ESME_RALYBND
            else:
                status = CommandStatus.ESME_ROK
                self.bound = True
                self.expected_system_id = params["system_id"]

                async with dict_lock:
                    CLIENT_SESSIONS[params["system_id"]] = self

            resp = build_bind_transceiver_resp(params["system_id"], status, pdu.sequence)
            self.transport.write(resp)
            return

        if pdu.command_id == CommandId.enquire_link:
            self.transport.write(build_enquire_link_resp(pdu.sequence))
            return

        if pdu.command_id == CommandId.submit_sm:
            msg = parse_submit_sm_body(pdu.body)
            async with dict_lock:
                CLIENT_SESSIONS[msg["source_addr"]] = self
            decoded_text = strip_udh_and_decode(msg["short_message"], msg["data_coding"])
            
            raw_msg_id = str(uuid.uuid4())

            async with dict_lock:
                CLIENT_MSGID_MAP[raw_msg_id] = {
                    "source_addr": msg["source_addr"],
                    "dest_addr": msg["dest_addr"]
                }

            if SUPPLIER_CLIENT:
                responses = await SUPPLIER_CLIENT.submit_sm(msg["source_addr"], msg["dest_addr"], decoded_text)
                status = responses[0].command_status if responses else CommandStatus.ESME_RSYSERR

                if responses and responses[0].body:
                    msgid_supplier = responses[0].body.rstrip(b"\x00").decode("ascii", errors="ignore")
                    SUPPLIER_TO_CLIENT_MSGID[msgid_supplier] = raw_msg_id
            else:
                status = CommandStatus.ESME_RSYSERR

            # Gunakan status yang sudah dicek
            msg_id = raw_msg_id.encode("ascii") + b"\x00"
            resp = PDU(CommandId.submit_sm_resp, status, pdu.sequence, msg_id).pack()
            self.transport.write(resp)

            await self.send_dlr_later(raw_msg_id,msg["source_addr"], msg["dest_addr"])
            return

        if pdu.command_id == CommandId.deliver_sm_resp:
            self.logger.debug("Received deliver_sm_resp (DLR ack)")
            return

        self.transport.write(PDU(CommandId.generic_nack, CommandStatus.ESME_RINVCMDID, pdu.sequence, b"").pack())

# ----------------------------------------
# Main server entry
# ----------------------------------------
async def run_server():
    # logging.basicConfig(level=logging.DEBUG)

    file_handler = logging.FileHandler('pysmpp.log')
    fromatter = logging.Formatter("%(asctime)s | %(levelname)-8s | %(name)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    file_handler.setFormatter(fromatter)
    logging.basicConfig(level='DEBUG', handlers=[file_handler])

    # creds = load_credentials("credentials.txt")
    import os
    current_dir = os.path.dirname(__file__)
    creds = load_credentials(os.path.join(current_dir, "credentials.txt"))
    GLOBAL_CREDENTIALS.update(creds)
    start_credential_watcher("credentials.txt", apply_new_credentials)

    from client.client_01 import SmppClient  # import here to avoid circular import

    global SUPPLIER_CLIENT
    SUPPLIER_CLIENT = SmppClient("103.65.237.145", 37001, "ptest001", "Pasming")
    # SUPPLIER_CLIENT = SmppClient("127.0.0.1", 2025, "aggregator", "aggregatorpass")
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