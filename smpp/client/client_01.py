# smpp_client.py
import asyncio
import struct
import logging
from others.smpp_common import (
    PDU, CommandId, CommandStatus, HEADER_LEN, HEADER_FMT,
    build_bind_transceiver, build_enquire_link, read_cstring,
    parse_deliver_sm, CLIENT_SESSIONS
)

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

    def next_seq(self):
        self.sequence += 1
        return self.sequence

    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        self.logger.info("Connected to %s:%s", self.host, self.port)

    async def bind_transceiver(self):
        pdu = build_bind_transceiver(self.system_id, self.password, "", sequence=self.next_seq())
        self.writer.write(pdu)
        await self.writer.drain()

        header = await self.reader.readexactly(HEADER_LEN)
        length, cmd_id, status, seq = struct.unpack(HEADER_FMT, header)
        body = await self.reader.readexactly(length - HEADER_LEN)
        if status != CommandStatus.ESME_ROK:
            raise RuntimeError("Bind failed")
        self.logger.info("Bind successful")

        asyncio.create_task(self._receiver_loop())
        asyncio.create_task(self._keepalive())

    async def _receiver_loop(self):
        try:
            while True:
                header = await self.reader.readexactly(HEADER_LEN)
                length, cmd_id, status, seq = struct.unpack(HEADER_FMT, header)
                body = await self.reader.readexactly(length - HEADER_LEN)

                if cmd_id == CommandId.deliver_sm:
                    dlr = parse_deliver_sm(body)
                    source = dlr["source_addr"]
                    dest = dlr["dest_addr"]
                    self.logger.info("DLR received from %s to %s", source, dest)

                    if dest in CLIENT_SESSIONS:
                        session = CLIENT_SESSIONS[dest]
                        session.transport.write(PDU(CommandId.deliver_sm, 0, self.next_seq(), body).pack())

                    ack = PDU(CommandId.deliver_sm_resp, 0, seq, b"").pack()
                    self.writer.write(ack)
                    await self.writer.drain()

        except asyncio.IncompleteReadError:
            self.logger.warning("Connection lost")

    async def _keepalive(self):
        while True:
            await asyncio.sleep(60)
            self.writer.write(build_enquire_link(self.next_seq()))
            await self.writer.drain()

    async def submit_sm(self, src, dst, text):
        from smpp_common import build_submit_sm
        pdus = build_submit_sm(src, dst, text, sequence=self.next_seq())
        for pdu in pdus:
            self.writer.write(pdu)
        await self.writer.drain()

    async def close(self):
        self.writer.close()
        await self.writer.wait_closed()

if __name__ == "__main__":
    async def run():
        logging.basicConfig(level=logging.DEBUG)
        c = SmppClient("127.0.0.1", 2775, "test1", "password1")
        await c.connect()
        await c.bind_transceiver()
        await c.submit_sm("Oppa", "6289630489151", "Hello dunia SMPP!")
        await asyncio.sleep(5)
        await c.close()
    asyncio.run(run())
