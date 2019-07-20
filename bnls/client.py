
import asyncio
from binascii import crc32
import logging
import socket
from struct import unpack
import threading

from .packets import *
from .products import *


log = logging.getLogger(__name__)


class BnlsClient:
    def __init__(self):
        self.cookies = []
        self.connected = False
        self.host = None
        self.products = {}
        self.received = []
        self.socket = None

        self.thread = None
        self._external_ip = None
        self._lock = threading.Lock()
        self._version_requests = []

    def connect(self, host, port=9367):
        self.host = host
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Must be IPv4
        self.socket.connect((host, port))
        self.connected = True

        self.cookies.clear()
        self.received.clear()
        self._version_requests.clear()

        self.thread = threading.Thread(target=self._run)
        self.thread.setDaemon(True)
        self.thread.start()

    def close(self):
        self.socket.close()
        self.connected = False

    def send_packet(self, pak):
        self.socket.sendall(pak.get_data())
        log.debug("Sent BNLS packet 0x%0.2X (length: %i)", pak.id, len(pak))

    def _run(self):
        # Packet receive loop
        while self.connected:
            # Receive the header
            data = self.socket.recv(3)
            if len(data) < 3:
                self.connected = False
                log.error("Disconnected from the server.")
                break

            # Build the packet
            pak = BnlsReader(data)
            log.debug("Received BNLS packet 0x%0.2X (length: %i)", pak.id, len(pak))

            # Receive the rest of the data
            pak.append(self.socket.recv(len(pak) - 3))

            if not pak.is_full_packet():
                self.connected = False
                log.error("Disconnected from the server (mid-packet).")
                break

            with self._lock:
                self.received.append(pak)

    def _get_cookie(self):
        cookie = 1
        with self._lock:
            while cookie in self.cookies:
                cookie += 1
            self.cookies.append(cookie)
        return cookie

    def _release_cookie(self, cookie):
        with self._lock:
            self.cookies.remove(cookie)

    async def get_packet(self, pid, match=None):
        while True:
            with self._lock:
                for pak in self.received:
                    if pak.id == pid and (not match or match(pak)):
                        self.received.remove(pak)
                        return pak

            # Wait for some new packets
            await asyncio.sleep(0.1)

    async def authorize(self, bot_id, password):
        """ Logs in to the BNLS server.

            - This is not required on all servers, and is usually only used for stats tracking.
            - If this is used, it must be sent first before any other requests.
            - Returns TRUE if authorized, FALSE if unauthorized, NONE if failed.
            - If unauthorized, you may still continue (logged in anonymously)

            Uses the following packets:
                - https://bnetdocs.org/packet/413/bnls-authorize
                - https://bnetdocs.org/packet/396/bnls-authorize
                - https://bnetdocs.org/packet/185/bnls-authorizeproof
                - https://bnetdocs.org/packet/196/bnls-authorizeproof
        """
        pak = BnlsPacket(BNLS_AUTHORIZE)
        pak.insert_string(bot_id)
        self.send_packet(pak)

        try:
            pak = await asyncio.wait_for(self.get_packet(BNLS_AUTHORIZE), timeout=1000)
        except asyncio.TimeoutError:
            log.warning("BNLS authentication timed out.")
            return None

        # Calculate the BNLS checksum (https://bnetdocs.org/document/23/bnls-checksum-algorithm)
        code = pak.get_dword()
        checksum = crc32((password + code.hex().upper()).encode('ascii'))

        pak = BnlsPacket(BNLS_AUTHORIZEPROOF)
        pak.insert_dword(checksum)
        self.send_packet(pak)

        try:
            pak = await asyncio.wait_for(self.get_packet(BNLS_AUTHORIZEPROOF), timeout=1000)
        except asyncio.TimeoutError:
            log.error("BNLS authentication failed.")
            return None

        status = pak.get_dword()
        self._external_ip = pak.get_ipv4()
        return status == 0

    async def request_version_byte(self, product, timeout=1000):
        """ Requests the version byte for a product.

            - Product can be either the BNLS ID or 4-character product code (ex: SEXP)
            - Returns NONE if the product is not supported or the server did not respond in a timely fashion.

            Uses the following packets:
                - https://bnetdocs.org/packet/181/bnls-requestversionbyte
                - https://bnetdocs.org/packet/134/bnls-requestversionbyte
        """
        product = get_bnls_code(product)
        self._version_requests.append(product)

        # Make the request.
        pak = BnlsPacket(BNLS_REQUESTVERSIONBYTE)
        pak.insert_dword(product)
        self.send_packet(pak)

        # BNLS returns a 0 for the product on failure, so there's no way to match that response to the request
        #   if there are multiple requests pending.
        def find_verbyte_response(p):
            prod = p.get_dword(peek=True)
            return (prod == 0 and len(self._version_requests) == 1) or (prod == product)

        # Wait for a response with this product.
        try:
            pak = await asyncio.wait_for(
                self.get_packet(BNLS_REQUESTVERSIONBYTE, find_verbyte_response), timeout)
        except asyncio.TimeoutError:
            log.warning("Version byte request for '%s' timed out.", PRODUCT_CODES.get(product, product))
            return None

        self._version_requests.remove(product)
        if pak.get_dword() == 0:
            return False     # Explicit failure response
        else:
            return pak.get_dword()

    async def check_version(self, product, timestamp, archive, formula, flags=0, timeout=10000):
        """ Requests a version check for a product.

            - product can be either the BNLS ID or 4-character product code (ex: SEXP)
            - timestamp, archive, and formula are values provided by the BNCS server
            - no flags are currently defined in the protocol

            Uses the following packets:
                - https://bnetdocs.org/packet/260/bnls-versioncheckex2
                - https://bnetdocs.org/packet/125/bnls-versioncheckex2
        """
        product = get_bnls_code(product)
        cookie = self._get_cookie()

        # Send the request
        pak = BnlsPacket(BNLS_VERSIONCHECKEX2)
        pak.insert_dword(product)
        pak.insert_dword(flags)
        pak.insert_dword(cookie)
        pak.insert_filetime(timestamp)
        pak.insert_string(archive)
        pak.insert_string(formula)
        self.send_packet(pak)

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

        try:
            pak = await asyncio.wait_for(
                self.get_packet(BNLS_VERSIONCHECKEX2, find_crev_response), timeout)
        except asyncio.TimeoutError:
            log.warning("Version check request for '%s' timed out.", PRODUCT_CODES.get(product, product))
            return None

        if pak.get_dword() == 1:
            version = pak.get_dword()
            checksum = pak.get_dword()
            info = pak.get_string()
            self._release_cookie(pak.get_dword())
            vcode = pak.get_dword()

            return version, checksum, info, vcode
        else:
            self._release_cookie(pak.get_dword())
            return False
