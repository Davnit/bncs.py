
import asyncio
from binascii import crc32
from datetime import datetime
import logging
import socket

from .packets import *
from .products import BnlsProduct

from bncs.crev import CheckRevisionResults
from bncs.utils import AsyncClientBase


class BnlsClient(AsyncClientBase):
    def __init__(self, *, logger=None, config=None):
        logger = logger or logging.getLogger("BNLS")
        AsyncClientBase.__init__(self, BnlsReader, logger=logger)

        self.config = {
            "server": "jbls.davnit.net",
            "port": 9367,
            "keep_alive_interval": 45
        }
        if config:
            self.config.update(config)

        self.products = {pid: BnlsProduct(pid) for pid in BnlsProduct.product_ids()}

        self._authorized = None
        self._cookies = []
        self._external_ip = None

        # Some packets don't have cookies or reliable ways to match their responses, so block on them.
        self._no_cookie_locks = {}

    @property
    def authorized(self):
        return self._authorized is True

    @property
    def external_ip(self):
        return self._external_ip

    def get_product_data(self, product):
        if data := self.products.get(product):
            return data

        code_lookup = {v.code: v for v in self.products.values()}
        return code_lookup.get(product)

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

    def _get_packet_lock(self, pid):
        if pid not in self._no_cookie_locks:
            self._no_cookie_locks[pid] = asyncio.Lock()
        return self._no_cookie_locks[pid]

    def connect(self, host=None, port=None):
        host = host or self.config["server"]
        port = port or self.config["port"]
        return super().connect(host, port)

    async def keep_alive(self):
        while self.connected:
            await asyncio.sleep(self.config["keep_alive_interval"])
            await self.send(BnlsPacket(BNLS_NULL))

    async def authorize(self, bot_id, password, timeout=1):
        """ Logs in to the BNLS server.

        bot_id: your bot's identifier for the BNLS system (this is not your Battle.net username!)
        password: your bot's password for the BNLS system (this is not your Battle.net password!)

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
        if self._authorized is not None:
            return self.authorized

        # Send the initial authorization request
        x0e = BnlsPacket(BNLS_AUTHORIZE)
        x0e.insert_string(bot_id)
        self.log.debug(f"Authenticating as '{bot_id}'")
        await self.send(x0e)

        # Calculate the BNLS checksum (https://bnetdocs.org/document/23/bnls-checksum-algorithm)
        challenge = await self.wait_for_packet(BNLS_AUTHORIZE, timeout=timeout)
        code = challenge.get_dword()
        checksum = crc32((password + code.hex().upper()).encode('ascii'))

        # Send the challenge response
        x0f = BnlsPacket(BNLS_AUTHORIZEPROOF)
        x0f.insert_dword(checksum)
        await self.send(x0f)

        # Parse the final result
        result = await self.wait_for_packet(BNLS_AUTHORIZEPROOF, timeout=timeout)
        status = result.get_dword()
        if result.position < result.length:
            # Not all servers will return this field
            self._external_ip = result.get_ipv4()
            self.log.debug(f"Server reports your external IP as {self._external_ip}")

        self._authorized = (status == 0)
        return self.authorized

    async def request_version_byte(self, product, timeout=5):
        """ Requests the version byte for a product.

        product: the 4-character product code (ex: SEXP)

        Returns the version byte of the requested product.

            Uses the following packets:
                - https://bnetdocs.org/packet/181/bnls-requestversionbyte
                - https://bnetdocs.org/packet/134/bnls-requestversionbyte
        """
        if (data := self.get_product_data(product)) is None and not isinstance(product, int):
            raise ValueError(f"Unrecognized BNLS product: {product}")
        elif data is None:
            data = BnlsProduct(product)

        x10 = BnlsPacket(BNLS_REQUESTVERSIONBYTE)
        x10.insert_dword(data.bnls_id)

        async with self._get_packet_lock(x10.packet_id):
            await self.send(x10)
            reply = await self.wait_for_packet(BNLS_REQUESTVERSIONBYTE, timeout=timeout)

        if reply.get_dword() == 0:
            # Server returned failure response. Some servers will just ignore the request.
            self.log.error(f"BNLS server did not recognize product 0x{data.bnls_id:02X}")
            return None
        else:
            data.verbyte = reply.get_dword()
            self.log.debug(f"BNLS returned version byte 0x{data.verbyte:02X} for product 0x{data.bnls_id}")
            if data.bnls_id not in self.products:
                self.products[data.bnls_id] = data
                if not data.code:
                    data.code = data.bnls_id
            return data.verbyte

    async def check_version(self, product, archive, formula, timestamp=0, flags=0, timeout=30):
        """ Requests a version check for a product.

        product: the 4-character product code (ex: SEXP)
        archive: the filename of the version check archive
        formula: the checksum formula/value string
        timestamp: the filetime of the version check archive, as provided by the server
        flags: value sent to the server, none are currently defined (default 0)

        Returns a BnlsProduct object containing the returned values.

            Uses the following packets:
                - https://bnetdocs.org/packet/260/bnls-versioncheckex2
                - https://bnetdocs.org/packet/125/bnls-versioncheckex2
        """
        if (data := self.get_product_data(product)) is None and not isinstance(product, int):
            raise ValueError(f"Unrecognized BNLS product: {product}")
        elif data is None:
            data = BnlsProduct(product)

        self.log.debug(f"Requesting version check for '{data.code}' with '{archive}'")

        # Send the request
        x1a = BnlsPacket(BNLS_VERSIONCHECKEX2)
        x1a.insert_dword(data.bnls_id)
        x1a.insert_dword(flags)
        x1a.insert_dword(cookie := self._get_cookie())
        x1a.insert_filetime(timestamp) if isinstance(timestamp, datetime) else x1a.insert_long(timestamp)
        x1a.insert_string(archive)
        x1a.insert_raw(formula)
        x1a.insert_byte(0)
        await self.send(x1a)

        # Function to extract and match the cookie from a response packet.
        def matcher(p):
            if p.get_dword() == 1:
                p.get_raw(8)
                p.get_string(encoding=None)
            return p.get_dword() == cookie

        try:
            reply = await self.wait_for_packet(BNLS_VERSIONCHECKEX2, matcher, timeout=timeout)
        finally:
            self._release_cookie(cookie)

        if reply.get_dword() == 1:
            # Status: success
            results = CheckRevisionResults(data.code)
            results.version = reply.get_dword()
            results.checksum = reply.get_dword()
            results.info = reply.get_string(encoding=None)
            reply.get_dword()                                   # cookie, was checked in the matcher

            data.verbyte = reply.get_dword()
            data.check = results

            if data.bnls_id not in self.products:
                self.products[data.bnls_id] = data
            return data
        else:
            # Server returned failure code or didn't return at all
            return None

    async def hash_data(self, data, client_token=None, server_token=None, flags=4, timeout=1):
        """Requests the Broken-SHA1 (XSha) hash of some data.

        data: a byte array containing the data to be hashed
        flags: sent to the server to control the type of hash (default 4: cookie hash)

        Optional arguments:
         - client_token: value used with flag 2 (required if flag is set)
         - server_token: value used with flag 2 (required if flag is set)

        If the cookie flag is not set, the request will block.

        Returns the 20-byte hash of the data.

            Uses the following packets:
                - https://bnetdocs.org/packet/293/bnls-hashdata
                - https://bnetdocs.org/packet/383/bnls-hashdata
        """
        x0b = BnlsPacket(BNLS_HASHDATA)
        x0b.insert_dword(len(data))
        x0b.insert_raw(data)

        if flags & 2 == 2:
            # Double hash (for OLS passwords - this should never be used in practice for security reasons)
            #  Use bncs.hashing.double_hash_password() instead.
            if None in [client_token, server_token]:
                raise ValueError("client_token and server_token are required for hash with flag 0x2")

            x0b.insert_dword(client_token)
            x0b.insert_dword(server_token)

        cookie = None
        matcher = None
        lock = None

        if flags & 4 == 4:
            x0b.insert_dword(cookie := self._get_cookie())

            def matcher(p):
                p.position += 20
                return (p.eob() is False) and (p.get_dword() == cookie)
        else:
            # If no cookie used, block for this packet.
            lock = self._get_packet_lock(x0b.packet_id)
            await lock.acquire()

        try:
            await self.send(x0b)
            reply = await self.wait_for_packet(BNLS_HASHDATA, matcher, timeout=timeout)
        finally:
            if cookie is None:
                lock.release()
            else:
                self._release_cookie(cookie)

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
        x11 = BnlsPacket(BNLS_VERIFYSERVER)
        x11.insert_dword(server_ip)
        x11.insert_raw(signature)

        async with self._get_packet_lock(x11.packet_id):
            await self.send(x11)
            reply = await self.wait_for_packet(BNLS_VERIFYSERVER)

        return reply.get_dword() == 1

    async def _handle_ipban(self, packet):
        # https://bnetdocs.org/packet/470/bnls-ipban
        self.log.warning(f"Server sent IP ban message: {packet.get_string()}")
