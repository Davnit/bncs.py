
import asyncio
from binascii import crc32
from datetime import datetime
import logging
import socket

from .packets import *
from .products import BnlsProduct, PRODUCT_CODES

from bncs.crev import CheckRevisionResults


class BnlsClient:
    """Client for interacting with a BNLS server."""
    def __init__(self):
        self.endpoint = None
        self.products = {code: BnlsProduct(code) for code in PRODUCT_CODES}
        self.logger = logging.getLogger("BNLS")

        self._connected = False
        self._reader = None
        self._writer = None
        self._external_ip = None
        self._version_requests = []
        self._received = []
        self._cookies = []
        self._reading = False

    @property
    def external_ip(self):
        """Client's external IP address.

        This field is only set after authorization with the BNLS server.
        """
        return self._external_ip

    @property
    def connected(self):
        return self._connected

    async def connect(self, host, port=9367):
        """Connects to the BNLS server.

        host: IP address (IPv4 only) or hostname of the remote server
        port: port number that the BNLS server is running on (default 9367)
        """
        self.endpoint = (host, port)
        self._reader, self._writer = await asyncio.open_connection(host, port, family=socket.AF_INET)
        self._connected = True

        self._cookies.clear()
        self._received.clear()
        self._version_requests.clear()

    async def disconnect(self):
        """Disconnects from the BNLS server."""
        if self._writer:
            self._writer.close()
            await self._writer.wait_closed()
        self._connected = False

    async def send_packet(self, pak):
        """Sends a BNLS packet.

        pak: the BnlsPacket object containing the data to be sent
        """
        self._writer.write(pak.get_data())
        await self._writer.drain()
        self.logger.debug("Sent BNLS packet 0x%0.2X (length: %i)", pak.id, len(pak))

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

    async def wait_for_packet(self, pid, match=None):
        """Waits until a specific packet is received and then returns it.

        pid: the packet ID for the expected packet
        match: a function taking a packet reader object as an argument and returns True if the packet matches
        """
        try:
            while self.connected:
                # Check if we've already received the packet we want
                for pak in self._received:
                    if pak.id == pid and (match is None or match(pak)):
                        self._received.remove(pak)
                        return pak

                if not self._reading:
                    self._reading = True        # Sets a flag so that only one thread will try to read at a time.

                    # Nothing found - read the next packet
                    pak = BnlsReader(await self._reader.readexactly(3))
                    self.logger.debug("Received BNLS packet 0x%0.2X (length: %i)", pak.id, len(pak))
                    pak.append(await self._reader.readexactly(len(pak) - 3))

                    self._reading = False

                    # Add the packet to the receive buffer
                    self._received.append(pak)
                else:
                    # If we can't yield to receive data, just sleep.
                    await asyncio.sleep(0.01)

        except asyncio.IncompleteReadError:
            self._connected = False
            self._reading = False
            self.logger.error("The BNLS server closed the connection.")

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
        await self.send_packet(pak)

        # Receive response and calculate the BNLS checksum (https://bnetdocs.org/document/23/bnls-checksum-algorithm)
        pak = await self.wait_for_packet(BNLS_AUTHORIZE)
        if pak is None:
            return None
        code = pak.get_dword()
        checksum = crc32((password + code.hex().upper()).encode('ascii'))

        # Send the challenge response
        pak = BnlsPacket(BNLS_AUTHORIZEPROOF)
        pak.insert_dword(checksum)
        await self.send_packet(pak)

        # Receive authorization status
        pak = await self.wait_for_packet(BNLS_AUTHORIZEPROOF)
        if pak is None:
            return None
        status = pak.get_dword()
        self._external_ip = pak.get_ipv4()
        return status == 0

    async def request_version_byte(self, product_code):
        """ Requests the version byte for a product.

        product_code: the 4-character product code (ex: SEXP)

        Returns the version byte of the requested product.

            Uses the following packets:
                - https://bnetdocs.org/packet/181/bnls-requestversionbyte
                - https://bnetdocs.org/packet/134/bnls-requestversionbyte
        """
        product = self.products.get(product_code.upper())
        self._version_requests.append(product.code)

        # Make the request.
        pak = BnlsPacket(BNLS_REQUESTVERSIONBYTE)
        pak.insert_dword(product.bnls_id)
        await self.send_packet(pak)

        # BNLS returns a 0 for the product on failure, so there's no way to match that response to the request
        #   if there are multiple requests pending.
        def find_verbyte_response(p):
            prod = p.get_dword(peek=True)
            return (prod == 0 and len(self._version_requests) == 1) or (prod == product)

        # Wait for a response with this product.
        pak = await self.wait_for_packet(BNLS_REQUESTVERSIONBYTE, find_verbyte_response)
        if pak is None:
            return None
        self._version_requests.remove(product.code)
        if pak.get_dword() == 0:
            return False     # Explicit failure response
        else:
            product.verbyte = pak.get_dword()
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
        product = self.products.get(product_code.upper())
        cookie = self._get_cookie()

        # Send the request
        pak = BnlsPacket(BNLS_VERSIONCHECKEX2)
        pak.insert_dword(product.bnls_id)
        pak.insert_dword(flags)
        pak.insert_dword(cookie)
        pak.insert_filetime(timestamp) if isinstance(timestamp, datetime) else pak.insert_long(timestamp)
        pak.insert_string(archive)
        pak.insert_string(formula)
        await self.send_packet(pak)

        # Function to extract and match the cookie from a response packet.
        def find_crev_response(p):
            start_pos = p.position
            match = False

            if p.get_dword() == 1:
                p.get_raw(8)
                p.get_string()
                if p.get_dword() == cookie:
                    match = True
            elif p.get_dword() == cookie:
                match = True

            p.position = start_pos
            return match

        # Receive the response and fill out the product object
        pak = await self.wait_for_packet(BNLS_VERSIONCHECKEX2, find_crev_response)
        self._release_cookie(cookie)
        if pak and pak.get_dword() == 1:
            results = CheckRevisionResults(product.code)
            results.version = pak.get_dword()
            results.checksum = pak.get_dword()
            results.info = pak.get_string()
            pak.get_dword()

            product.verbyte = pak.get_dword()
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

        await self.send_packet(pak)

        # Function to match the response packet
        def find_hash_data_response(p):
            if cookie is None:
                return True

            p.position += 20
            match = p.get_dword(peek=True) == cookie
            p.position -= 20
            return match

        # Receive the response
        pak = await self.wait_for_packet(BNLS_HASHDATA, find_hash_data_response)
        return pak.get_raw(20) if pak else None

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
        await self.send_packet(pak)

        # Receive the response
        pak = await self.wait_for_packet(BNLS_VERIFYSERVER)
        return pak.get_dword() == 1 if pak else None
