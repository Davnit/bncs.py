
import asyncio
from binascii import crc32
from datetime import datetime
import logging
import socket

from .packets import *
from .products import BnlsProduct, PRODUCT_CODES

from bncs.crev import CheckRevisionResults


class BnlsClient:
    def __init__(self, *, loop=None, **config):
        self.loop = loop or asyncio.get_running_loop()

        self.config = {
            "server": "jbls.davnit.net",
            "port": 9367,
            "debug_packets": False
        }
        self.config.update(config)

        self.log = logging.getLogger("BNLS")

        self.reader, self.writer = None, None

        self.products = {code: BnlsProduct(code) for code in PRODUCT_CODES}

        self._waiters = []
        self._external_ip = None
        self._version_requests = []
        self._cookies = []

        self._connected = False
        self._disconnected_fut = None

    @property
    def connected(self):
        return self._connected

    def disconnect(self, msg=None):
        msg = msg or "Client disconnected"

        if self.connected:
            self._connected = False

            self.writer.close()
            self.log.info(f"Disconnected: {msg}")

        if not self._disconnected_fut.done():
            self._disconnected_fut.set_result(True)

        # Cancel any outstanding waiters
        for (pid, matcher, fut) in self._waiters:
            if not fut.done():
                fut.cancel()

    async def wait_for_disconnect(self):
        await self.writer.wait_closed()

    async def send(self, packet):
        if not self.connected:
            self.log.debug("Send() failed due to not connected")
            return False

        self.writer.write(packet.get_data())

        self.log.debug(f"Sent BNLS packet 0x{packet.packet_id:02X} ({packet.length} bytes)")
        if self.config["debug_packets"]:
            self.log.debug(repr(packet))

        await self.writer.drain()
        return True

    async def send_and_wait(self, packet, matcher=None):
        if self.connected:
            fut = self.loop.create_future()
            self._waiters.append((packet.packet_id, matcher, fut))

            if await self.send(packet):
                return await fut

    async def receive(self):
        while self.connected:
            packet = await BnlsReader.read_from(self.reader)
            if packet is None:
                return self.disconnect("Server closed the connection")

            self.log.debug(f"Received BNLS packet 0x{packet.packet_id:02X} ({packet.length} bytes)")
            if self.config["debug_packets"]:
                self.log.debug(repr(packet))

            for (pid, matcher, fut) in self._waiters:
                if pid == packet.packet_id:
                    if matcher is None or matcher(packet):
                        fut.set_result(packet)
                        self._waiters.remove((pid, matcher, fut))
                        break

    async def connect(self):
        self.reader, self.writer = \
            await asyncio.open_connection(self.config["server"], self.config["port"], family=socket.AF_INET)

        self._connected = True
        self._waiters = []

        self._disconnected_fut = self.loop.create_future()
        self.loop.create_task(self.receive(), name="BNLS packet receiver")

    def _get_cookie(self):
        """Returns the next available cookie value.."""
        cookie = 1
        while cookie in self._cookies:
            cookie += 1
        self._cookies.append(cookie)
        return cookie

    def _release_cookie(self, cookie):
        """Marks a cookie value as available."""
        self._cookies.remove(cookie)

    async def authorize(self, bot_id, password):
        """ Logs in to the BNLS server.

        bot_id: your bot's identifier for the BNLS system (this is not the same as your Battle.net username!)
        password: your bot's password for the BNLS system (this is not the same as your Battle.net password!)

        Returns True if authorized, False if unauthorized.

            - This is not required on all servers, and is usually only used for stats tracking.
            - If this is used, it must be sent first before any other requests.
            - If unauthorized, you may still continue (logged in anonymously)

            Uses the following packets:
                - https://bnetdocs.org/packet/413/bnls-authorize
                - https://bnetdocs.org/packet/396/bnls-authorize
                - https://bnetdocs.org/packet/185/bnls-authorizeproof
                - https://bnetdocs.org/packet/196/bnls-authorizeproof
        """
        # Send the initial authorization request
        pak = BnlsPacket(BNLS_AUTHORIZE)
        pak.insert_string(bot_id)
        reply = await self.send_and_wait(pak)

        # Calculate the BNLS checksum (https://bnetdocs.org/document/23/bnls-checksum-algorithm)
        code = reply.get_dword()
        checksum = crc32((password + code.hex().upper()).encode('ascii'))

        # Send the challenge response
        pak = BnlsPacket(BNLS_AUTHORIZEPROOF)
        pak.insert_dword(checksum)
        reply = await self.send_and_wait(pak)

        status = reply.get_dword()
        if reply.position < reply.length:
            # Not all servers will return this field
            self._external_ip = reply.get_ipv4()
        return status == 0

    async def request_version_byte(self, product_code):
        """ Requests the version byte for a product.

        product_code: the 4-character product code (ex: SEXP)

        Returns the version byte of the requested product.

            Uses the following packets:
                - https://bnetdocs.org/packet/181/bnls-requestversionbyte
                - https://bnetdocs.org/packet/134/bnls-requestversionbyte
        """
        product = self.products.get(product_code)
        self._version_requests.append(product.code)

        # Make the request.
        pak = BnlsPacket(BNLS_REQUESTVERSIONBYTE)
        pak.insert_dword(product.bnls_id)

        # BNLS returns a 0 for the product on failure, so there's no way to match that response to the request
        #   if there are multiple requests pending.
        def find_verbyte_response(p):
            prod = p.get_dword(peek=True)
            return (prod == 0 and len(self._version_requests) == 1) or (prod == product.bnls_id)

        # Wait for a response with this product.
        reply = await self.send_and_wait(pak, find_verbyte_response)
        self._version_requests.remove(product.code)
        if reply.get_dword() == 0:
            return False     # Explicit failure response
        else:
            product.verbyte = reply.get_dword()
            return product.verbyte

    async def check_version(self, product_code, timestamp, archive, formula, flags=0):
        """ Requests a version check for a product.

        product_code: the 4-character product code (ex: SEXP)
        timestamp: the filetime of the version check archive, as provided by the server
        archive: the filename of the version check archive
        formula: the checksum formula/value string
        flags: value sent to the server, none are currently defined (default 0)

        Returns a BnlsProduct object containing the returned values.

            Uses the following packets:
                - https://bnetdocs.org/packet/260/bnls-versioncheckex2
                - https://bnetdocs.org/packet/125/bnls-versioncheckex2
        """
        product = self.products.get(product_code)
        cookie = self._get_cookie()

        # Send the request
        pak = BnlsPacket(BNLS_VERSIONCHECKEX2)
        pak.insert_dword(product.bnls_id)
        pak.insert_dword(flags)
        pak.insert_dword(cookie)
        pak.insert_filetime(timestamp) if isinstance(timestamp, datetime) else pak.insert_long(timestamp)
        pak.insert_string(archive)
        pak.insert_raw(formula)
        pak.insert_byte(0)

        # Function to extract and match the cookie from a response packet.
        def find_crev_response(p):
            start_pos = p.position
            match = False

            if p.get_dword() == 1:
                p.get_raw(8)
                p.get_string(encoding=None)
                if p.get_dword() == cookie:
                    match = True
            elif p.get_dword() == cookie:
                match = True

            p.position = start_pos
            return match

        # Receive the response and fill out the product object
        reply = await self.send_and_wait(pak, find_crev_response)
        self._release_cookie(cookie)
        if reply and reply.get_dword() == 1:
            results = CheckRevisionResults(product.code)
            results.version = reply.get_dword()
            results.checksum = reply.get_dword()
            results.info = reply.get_string(encoding=None)
            reply.get_dword()                                   # cookie, was checked in the matcher

            product.verbyte = reply.get_dword()
            product.check = results
            return product
        else:
            # Server returned failure code or didn't return at all
            return None

    async def hash_data(self, data, flags=4, **kwargs):
        """Requests the Broken-SHA1 (XSha) hash of some data.

        data: a byte array containing the data to be hashed
        flags: sent to the server to control the type of hash (default 4: cookie hash)

        keyword arguments:
         - 'client_key': value used with flag 2 (required if flag is set)
         - 'server_key': value used with flag 2 (required if flag is set)
         - 'cookie': value used with flag 4 (one will be generated if not set)

        Returns the 20-byte hash of the data.

            Uses the following packets:
                - https://bnetdocs.org/packet/293/bnls-hashdata
                - https://bnetdocs.org/packet/383/bnls-hashdata
        """
        pak = BnlsPacket(BNLS_HASHDATA)
        pak.insert_dword(len(data))
        pak.insert_raw(data)

        cookie = None

        if flags & 2 == 2:
            # Double hash (for OLS passwords - this should never be used in practice for security reasons)
            pak.insert_dword(kwargs["client_key"])
            pak.insert_dword(kwargs["server_key"])

        if flags & 4 == 4:
            cookie = kwargs.get("cookie", self._get_cookie())
            pak.insert_dword(cookie)

        # Function to match the response packet
        def find_hash_data_response(p):
            if cookie is None:
                return True

            p.position += 20
            match = p.get_dword(peek=True) == cookie
            p.position -= 20
            return match

        # Receive the response
        reply = await self.send_and_wait(pak, find_hash_data_response)
        return reply.get_raw(20)

    async def verify_server(self, server_ip, signature):
        """Verifies a WarCraft 3 server signature.

        server_ip: the packed int version of the server's IP address, or a str of the same in dot-notation (IPv4 only!)
        signature: the 128-byte signature provided by the server

        Returns True if the signature is valid, or False if otherwise.

            Uses the following packets:
                - https://bnetdocs.org/packet/251/bnls-verifyserver
                - https://bnetdocs.org/packet/238/bnls-verifyserver
        """
        if isinstance(server_ip, str):
            server_ip = int(socket.inet_aton(server_ip).decode('hex'), 16)

        # Send the request
        pak = BnlsPacket(BNLS_VERIFYSERVER)
        pak.insert_dword(server_ip)
        pak.insert_raw(signature)

        # Receive the response
        reply = await self.send_and_wait(pak)
        return reply.get_dword() == 1
