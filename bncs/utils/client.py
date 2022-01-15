
import abc
import asyncio
import logging
import socket

from .packet import PacketReader, InvalidPacketException


class InvalidOperationError(Exception):
    pass


class AsyncClientBase(abc.ABC):
    def __init__(self, packet_reader_class, *, logger=None):
        if not issubclass(packet_reader_class, PacketReader):
            raise TypeError("packet_reader_class must inherit from bncs.utils.PacketReader")

        self.debug_packets = False                          # Prints received packets to the log
        self.log = logger or logging.getLogger("Client")
        self.packet_handlers = {}                           # Static packet handling methods f(packet obj)
        self.state = {}                                     # Serializable values tied to client's current state

        self._connected = False                             # bool if client is connected
        self._packet_reader = packet_reader_class           # Class used for reading data
        self._reader = self._writer = None                  # asyncio StreamReader, StreamWriter
        self._receiver = self._keep_alive = None            # tasks for receiving data and sending keep-alive messages
        self._waiters = []                                  # asyncio Futures waiting for specific packets

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        if self.connected:
            self.disconnect("exception occurred" if exc_type else "context exit")

    @property
    def connected(self):
        return self._connected

    async def connect(self, host, port):
        """Opens a connection to the remote server."""
        if not isinstance(host, str) or not isinstance(port, int):
            self.log.error("Connection failed - invalid endpoint")
            return False

        # Open the connection
        self.log.info(f"Connecting to '{host}' on port {port}...")
        self._reader, self._writer = \
            await asyncio.open_connection(host, port, family=socket.AF_INET)      # IPv4 only
        self.state["remote_ip"] = self._writer.get_extra_info('peername')[0]
        self.state["local_ip"] = self._writer.get_extra_info('sockname')[0]

        self.log.info(f"Connected to {self.state['remote_ip']}")
        self._connected = True
        self._waiters = []

        # Setup tasks for receiving and keep-alive messages
        loop = asyncio.get_event_loop()
        self._receiver = loop.create_task(self.receive(), name=f"{type(self).__name__} packet receiver")
        self._keep_alive = loop.create_task(self.keep_alive(), name=f"{type(self).__name__} keep-alive")
        return self._connected

    def disconnect(self, reason=None):
        """Closes the connection"""

        # Close the socket
        if self.connected:
            self._connected = False
            self._writer.close()
            self.log.info(f"Disconnected: {reason or 'Client disconnected'}")

        # Cancel receive and keep alive loops
        self._receiver.cancel()
        self._keep_alive.cancel()

        # Cancel outstanding waiters
        for (pid, matcher, future) in self._waiters:
            if future and not future.done():
                future.cancel()

    async def wait_closed(self):
        """Waits until the connection is closed and waiters have completed"""
        await asyncio.gather(self._receiver, self._keep_alive, *[w[2] for w in self._waiters], return_exceptions=True)
        await self._writer.wait_closed()

    async def wait_for_packet(self, pid, matcher=None, timeout=5):
        """Returns an asyncio Future that will return the next packet received with the given ID."""
        future = asyncio.get_event_loop().create_future()
        self._waiters.append((pid, matcher, future))

        if self.debug_packets:
            self.log.debug(f"Registered waiter for packet 0x{pid:02X} "
                           f"with {'no ' if matcher is None else ''}matcher and {timeout}s timeout")

        return await asyncio.wait_for(future, timeout)

    async def receive(self):
        """Receives and handles packets while the connection is open."""
        invalid_packet_counter = 0
        while self.connected:
            try:
                # Receive the next packet
                packet = await self._packet_reader.read_from(self._reader)
                invalid_packet_counter = 0

            except asyncio.IncompleteReadError as ire:
                self.disconnect("Server closed the connection")
                if len(ire.partial) > 0:
                    self.log.debug(f"Partial data received ({len(ire.partial)}/{ire.expected}): {ire.partial}")
                return

            except InvalidPacketException as ipe:
                self.log.error(f"Invalid packet received: {ipe}")
                invalid_packet_counter += 1
                if invalid_packet_counter < 5:
                    continue
                else:
                    self.disconnect("Too many invalid packets received")
                    return

            if self.debug_packets:
                self.log.debug(f"Received {str(packet)}")
                self.log.debug(repr(packet))

            # Send to the static handler, if one exists
            found = False
            if packet.packet_id in self.packet_handlers:
                await self.packet_handlers[packet.packet_id](packet)
                found = True

            # Pass it to the result of waiting futures
            for waiter in self._waiters:
                pid, matcher, future = waiter

                if pid == packet.packet_id:
                    packet.reset()                  # Reset for the matcher
                    if matcher is None or matcher(packet):
                        future.set_result(packet)
                        if self.debug_packets:
                            self.log.debug(f"Packet matched for ID 0x{pid:02X}")
                        self._waiters.remove(waiter)

                        found = True
                        packet.reset()
                        break

            if not found:
                self.log.warning(f"{str(packet)} was not handled")

            await asyncio.sleep(0)

    async def send(self, packet):
        """Sends a packet to the server."""
        if not self.connected or self._writer is None:
            raise InvalidOperationError("socket not connected")

        self._writer.write(packet.get_data())
        if self.debug_packets:
            self.log.debug(f"Sent {str(packet)}")
            self.log.debug(repr(packet))

        await self._writer.drain()

    @abc.abstractmethod
    async def keep_alive(self):
        """Sends keep-alive messages to the server."""
        pass
