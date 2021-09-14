
import asyncio
import logging
import random

from bncs.packets import *


class RemoteClient:
    def __init__(self, ident, reader, writer):
        self.log = logging.getLogger(f"Client{ident}")

        self.ident = ident
        self.connected = True
        self.reader = reader
        self.writer = writer
        self.closed = asyncio.get_running_loop().create_future()
        self.handlers = {}

        self.username = None
        self.product = None
        self.stats = None

    async def receive(self):
        protocol = (await self.reader.readexactly(1))[0]
        if protocol != 1:
            return self.disconnect(f"Unsupported protocol: 0x{protocol:2X}")

        while self.connected:
            packet = await BncsReader.read_from(self.reader)
            if packet is None:
                return self.disconnect("Client closed the connection")
            elif packet is False:
                return self.disconnect("Client sent invalid data")

            self.log.debug(f"Received {str(packet)}")

            if packet.packet_id in self.handlers:
                await self.handlers[packet.packet_id](self, packet)

    async def send(self, packet):
        self.writer.write(packet.get_data())
        self.log.debug(f"Sent {str(packet)}")
        await self.writer.drain()

    def disconnect(self, msg=None):
        msg = msg or "Client connection closed"

        if self.connected:
            self.connected = False
            self.writer.close()

        if not self.closed.done():
            self.closed.set_result(msg)

    async def wait_closed(self):
        msg = await self.closed
        await self.writer.wait_closed()
        return msg


class BncsServerCore:
    def __init__(self):
        self.log = logging.getLogger("BNCS")
        self.socket = None

        self.clients = []
        self.handlers = {}
        self.running = False
        self.closed = asyncio.get_running_loop().create_future()

    async def start(self):
        self.socket = await asyncio.start_server(self._handle_client, port=6112)
        self.log.info("Server started on port 6112.")
        self.running = True

    def close(self):
        for client in self.clients:
            client.disconnect()

        if not self.running:
            self.running = False
            self.socket.close()

        if not self.closed.done():
            self.closed.set_result(True)

    async def wait_closed(self):
        await self.closed
        await asyncio.wait(c.wait_closed for c in self.clients)
        await self.socket.wait_closed()

    async def _handle_client(self, reader, writer):
        ident = len(self.clients) + 1
        client = RemoteClient(ident, reader, writer)
        self.log.info(f"Client accepted as #{ident}")

        client.handlers = self.handlers
        self.clients.append(client)
        await client.receive()

        msg = await client.wait_closed()
        self.clients.remove(client)
        self.log.info(f"Client disconnected: {msg}")


async def handle_client_id(client, packet):
    await client.send(BncsPacket.prefill(SID_CLIENTID, b'\x00' * 16))

    pak = BncsPacket(SID_LOGONCHALLENGEEX)
    pak.insert_dword(random.getrandbits(32))    # UPD value
    pak.insert_dword(random.getrandbits(32))    # server token
    await client.send(pak)


async def handle_start_versioning(client, packet):
    assert isinstance(packet, BncsReader)
    packet.position += 4
    client.product = packet.get_dword(True)

    pak = BncsPacket(SID_PING)
    pak.insert_dword(random.getrandbits(32))
    await client.send(pak)

    # Static versioning challenge (filetime [0] + archive + seed)
    challenge = (b'\x00' * 8) + \
        b'lockdown-IX86-07.mpq\x00' + \
        b'\x2E\x27\xBE\x54\x25\x55\x4B\xD3\x4C\xF4\xFA\xBF\xAD\x1A\xB2\x46\x00'
    await client.send(BncsPacket.prefill(SID_STARTVERSIONING, challenge))


async def handle_report_version(client, packet):
    client.disconnect("Client info received. Fake IP ban time!")
    # client.send(BncsPacket.prefill(SID_REPORTVERSION, b'\x02\x00\x00\x00\x00\x00'))


async def handle_logon_response(client, packet):
    assert isinstance(packet, BncsReader)
    packet.position += 28    # skip first 28 bytes (tokens + password)
    client.username = packet.get_string()

    reply = BncsPacket(packet.packet_id)
    reply.insert_dword(1 if reply.packet_id == SID_LOGONRESPONSE else 0)
    await client.send(reply)


async def handle_enter_chat(client, packet):
    assert isinstance(packet, BncsReader)
    packet.get_string()     # username

    client.stats = packet.get_string()
    if len(client.stats) == 0 or client.stats[0] == ',':
        client.stats = client.product[::-1]

    reply = BncsPacket(SID_ENTERCHAT)
    reply.insert_string(client.username)
    reply.insert_string(client.stats)
    reply.insert_string(client.username)
    await client.send(reply)


async def handle_join_channel(client, packet):
    assert isinstance(packet, BncsReader)
    packet.get_dword()
    channel = packet.get_string()

    reply = BncsPacket.prefill(SID_CHATEVENT, b'\x07\x00\x00\x00' + (b'\x00' * 20))
    reply.insert_string(client.username)
    reply.insert_string(channel)
    await client.send(reply)


async def main():
    logging.basicConfig(level=logging.DEBUG)

    server = BncsServerCore()
    server.handlers = {
        0x06: handle_start_versioning,
        0x07: handle_report_version,
        0x0A: handle_enter_chat,
        0x0C: handle_join_channel,
        0x1E: handle_client_id,
        0x3A: handle_logon_response
    }
    await server.start()
    await server.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
