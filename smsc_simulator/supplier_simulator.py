import asyncio
import struct
import uuid
import logging
from time import strftime
from server.smpp_common import (
    PDU, HEADER_FMT, HEADER_LEN, CommandId, CommandStatus,
    parse_bind_transceiver_body, build_bind_transceiver_resp,
    parse_submit_sm_body, strip_udh_and_decode,
    build_deliver_sm_dlr, cstring
)

class SupplierSimulator(asyncio.Protocol):
    def __init__(self):
        self.transport = None
        self.logger = logging.getLogger("supplier")
        self.sequence = 1
        self.bound = False
    def connection_made(self, transport):
        self.transport = transport
        peer = transport.get_extra_info("peername")
        self.logger.info(f"Aggregator connected: {peer}")
    def data_received(self, data: bytes):
        asyncio.create_task(self._handle(data))
    async def _handle(self, data:bytes):
        offset = 0
        while offset + 4 <= len(data):
            length = struct.unpack(">I", data[offset:offset + 4])[0]
            if offset + length > len(data):
                self.logger.warning("incomplete pdu received")
                break
            pdu_data = data[offset:offset + length]
            offset += length

            try:
                pdu = PDU.unpack(pdu_data)
            except Exception as e:
                self.logger.error("invalid pdu: %s", e)
                continue

            await self._process_pdu(pdu)

    async def _process_pdu(self, pdu:PDU):
        if pdu.command_id == CommandId.bind_transceiver:
            params = parse_bind_transceiver_body(pdu.body)
            self.logger.info(f"Received BIND from {params['system_id']}")
            resp = build_bind_transceiver_resp(system_id=params['system_id'],status=CommandStatus.ESME_ROK,sequence=pdu.sequence)
            self.transport.write(resp)
            self.bound = True
            return
        if pdu.command_id == CommandId.submit_sm:
            msg = parse_submit_sm_body(pdu.body)
            msg_id = str(uuid.uuid4())
            decoded = strip_udh_and_decode(msg["short_message"], msg["data_coding"])
            self.logger.info(f"Received sms from aggregator: from={msg['source_addr']} to={msg['dest_addr']} text={decoded}")

            # kirim submit sm resp
            body = cstring(msg_id)
            resp = PDU(CommandId.submit_sm_resp, CommandStatus.ESME_ROK, pdu.sequence, body).pack()
            self.transport.write(resp)

            # kirim dlr dalam 2 detik
            await asyncio.sleep(2)
            self.sequence += 1
            dlr_pdu = build_deliver_sm_dlr(
                msg_id = msg_id,
                source_addr = msg["dest_addr"],
                dest_addr=msg["source_addr"],
                sequence=self.sequence
            )
            self.transport.write(dlr_pdu)
            self.logger.info("DLR sent")

        if pdu.command_id == CommandId.enquire_link:
            resp = PDU(CommandId.enquire_link_resp, 0, pdu.sequence, b"").pack()
            self.transport.write(resp)

        if pdu.command_id == CommandId.deliver_sm_resp:
            self.logger.debug("ack from aggregator for dlr")

    def connection_lost(self, exc):
        self.logger.warning("aggregator disconnected")

async def run_supplier_simulator(host="127.0.0.1", port=2025):
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s")
    loop = asyncio.get_running_loop()
    server = await loop.create_server(lambda: SupplierSimulator(), host, port)
    async with server:
        await server.serve_forever()
if __name__ == "__main__":
    asyncio.run(run_supplier_simulator())