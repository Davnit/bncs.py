
from bncs.common.buffer import DataReader, DataBuffer
from bncs.common.products import get_product, BncsProduct
from bnls.packets import *

from socket import socket, AF_INET, SOCK_STREAM, inet_ntoa, inet_aton
from binascii import crc32
from struct import unpack


class BnlsClient(object):
    def __init__(self):
        self.socket = socket(AF_INET, SOCK_STREAM)
        self.host = None
        self.port = None

        self.external_ip = None
        self._authorized = False
        self._connected = False

    def connected(self):
        """Returns True if the client is connected to a server."""
        return self._connected

    def authorized(self):
        """Returns True if the client has authenticated with the server."""
        return self._authorized

    def connect(self, host, port=9367):
        """Initiates a connection."""
        self.host = host
        self.port = port

        self.socket.connect((host, port))
        self._connected = True

    def disconnect(self):
        """Closes the connection."""
        if self._connected:
            self.socket.close()
            self._connected = False

        self._authorized = False

    def send_packet(self, packet_id, payload=None):
        """Sends a packet with the specified ID and contents.

        - 'payload' can be either a bytes object or DataBuffer.
        - If no payload is given, an empty packet will be sent."""
        payload = payload or b''

        pak = DataBuffer()
        pak.insert_format('<HB', len(payload) + 3, packet_id)
        pak.insert_raw(payload)

        self.socket.sendall(pak.data)

    def receive_packet(self):
        """Receives the next packet from the data stream.

        - Returns both the ID of the received packet and a DataReader containing the packet (starting post-header)."""
        if not self._connected:
            return None, None

        pak = DataReader(self.socket.recv(3))
        if len(pak) == 0:
            self.disconnect()
            return None, pak

        length, pid = pak.get_format('<HB')
        if length > 3:
            pak.data += self.socket.recv(length - 3)
        return pid, pak

    def authorize(self, bot_id, password):
        """Logs into the BNLS server with the given bot ID and password.

        - This is not required on all servers."""
        pak = DataBuffer(bot_id)
        self.send_packet(BNLS_AUTHORIZE, pak)

        pid, pak = self.receive_packet()
        if pid != BNLS_AUTHORIZE:
            return False

        # Calculate the BNLS checksum
        server_code = pak.get_raw(4)
        check = (password + server_code.hex().upper()).encode('ascii')
        pak = DataBuffer(crc32(check))
        self.send_packet(BNLS_AUTHORIZEPROOF, pak)

        pid, pak = self.receive_packet()
        if pid != BNLS_AUTHORIZEPROOF:
            return False

        self._authorized = (pak.get_dword() == 0)

        # Only some servers support this
        if not pak.eop():
            self.external_ip = inet_ntoa(pak.get_raw(4))

        return self._authorized

    def request_version_byte(self, product):
        """Requests the current version byte for the specified product.

        - Product should be the 4-length code used by BNCS (can be int or string, ex: "STAR").
        - Returns -1 if the product is not supported by the server."""
        product = product if isinstance(product, BncsProduct) else get_product(product)

        pak = DataBuffer(product.bnls_id)
        self.send_packet(BNLS_REQUESTVERSIONBYTE, pak)

        pid, pak = self.receive_packet()
        if pid != BNLS_REQUESTVERSIONBYTE:
            return False

        product2 = pak.get_dword()
        if product2 == 0:
            # Product not supported by the server
            return -1

        return pak.get_dword() if product2 == product.bnls_id else False

    def hash_data(self, data, flags=0, client=None, server=None, cookie=0):
        """Returns the 20-byte XSha1() hash of the specified data.

        - If the 0x02 flag is set, a double hash including the specified server and client codes will be performed."""
        data = data.encode() if hasattr(data, 'encode') else data

        pak = DataBuffer()
        pak.insert_dword(len(data))
        pak.insert_dword(flags)
        pak.insert_raw(data)

        # Double hash with client and server tokens
        if (flags & 0x02) == 0x02:
            pak.insert_dword(client or 0)
            pak.insert_dword(server or 0)

        # Include cookie
        if (flags & 0x04) == 0x04:
            pak.insert_dword(cookie)

        self.send_packet(BNLS_HASHDATA, pak)
        pid, pak = self.receive_packet()
        if pid != BNLS_HASHDATA:
            return False

        key_hash = pak.get_raw(20)

        # Verify the cookie
        if (flags & 0x04) == 0x04:
            if pak.get_dword() != cookie:
                return False

        return key_hash

    def encrypt_key_basic(self, key, server_token):
        """Encrypts the specified CD key with the given server token and returns its components.

        - Returns success and a tuple containing the following values:
            client token, key length, product value, public value, unknown value (0), and 20-byte hash"""
        pak = DataBuffer()
        pak.insert_dword(server_token)
        pak.insert_string(key)

        self.send_packet(BNLS_CDKEY, pak)
        pid, pak = self.receive_packet()
        if pid != BNLS_CDKEY:
            return False, None

        if pak.get_dword() == 1:
            return True, pak.get_format('<5L20s')
        else:
            return False, None

    def set_nls_version(self, version):
        """Instructs the server to use the specified NLS version.

        - This almost always needs to be sent before doing any NLS operations (account logon, etc)
        - Returns True if the version was accepted.
        - There are 2 versions:
            1: WarCraft 3 Demo (default)
            2: Everything else"""
        pak = DataBuffer(version)

        self.send_packet(BNLS_CHOOSENLSREVISION, pak)
        pid, pak = self.receive_packet()
        if pid != BNLS_CHOOSENLSREVISION:
            return False

        return pak.get_dword() == 1

    def verify_server_signature(self, ip, signature):
        """Verifies the WarCraft 3 server signature returned by the BNCS server after version check."""
        if isinstance(ip, str):
            ip = unpack('!I', inet_aton(ip))[0]

        if not signature or len(signature) != 128:
            return False

        pak = DataBuffer()
        pak.insert_dword(ip)
        pak.insert_raw(signature)

        self.send_packet(BNLS_VERIFYSERVER, pak)
        pid, pak = self.receive_packet()
        if pid != BNLS_VERIFYSERVER:
            return False

        return pak.get_dword() == 1

    def check_version(self, product, timestamp, archive, formula, cookie=0, flags=0):
        """Performs a version check for the specified product with the given components.

        - Returns success, a tuple containing the results, and the latest version byte.
        - The tuple contains: version, checksum, and info"""
        product = product if isinstance(product, BncsProduct) else get_product(product)

        pak = DataBuffer()
        pak.insert_dword(product.bnls_id)
        pak.insert_dword(flags)
        pak.insert_dword(cookie)
        pak.insert_long(timestamp)
        pak.insert_string(archive)
        pak.insert_string(formula, 'latin-1')

        self.send_packet(BNLS_VERSIONCHECKEX2, pak)
        pid, pak = self.receive_packet()
        if pid != BNLS_VERSIONCHECKEX2:
            return False, None, None

        # Default return values
        success = pak.get_dword()
        data = None
        vcode = None

        if success == 1:
            version = pak.get_dword()
            checksum = pak.get_dword()
            info = pak.get_string('latin-1')
            cookie2 = pak.get_dword()
            vcode = pak.get_dword()

            data = (version, checksum, info)
            if cookie2 != cookie:
                return False, data, vcode

        return success == 1, data, vcode

    def get_logon_challenge(self, username, password):
        """Initializes the NLS/SRP system and returns the client key used in SID_AUTH_ACCOUNTLOGON (0x53)."""
        pak = DataBuffer()
        pak.insert_string(username)
        pak.insert_string(password)

        self.send_packet(BNLS_LOGONCHALLENGE, pak)
        pid, pak = self.receive_packet()
        if pid != BNLS_LOGONCHALLENGE:
            return None

        return pak.get_raw(32)

    def get_logon_proof(self, bytes_s, bytes_B):
        """Processes the logon challenge and returns the client proof used in SID_AUTH_ACCOUNTLOGONPROOF (0x54)."""
        if len(bytes_s) != 32:
            raise TypeError("Salt (s) expected to be 32 bytes, got %i" % len(bytes_s))

        if len(bytes_B) != 32:
            raise TypeError("Server key (B) expected to be 32 bytes, got %i" % len(bytes_B))

        pak = DataBuffer()
        pak.insert_raw(bytes_s)
        pak.insert_raw(bytes_B)

        self.send_packet(BNLS_LOGONPROOF, pak)
        pid, pak = self.receive_packet()
        if pid != BNLS_LOGONPROOF:
            return None

        return pak.get_raw(20)

    def get_create_account(self, username, password):
        """Initializes the NLS/SRP system and returns a salt and the verifier used in SID_AUTH_ACCOUNTCREATE (0x52)."""
        pak = DataBuffer()
        pak.insert_string(username)
        pak.insert_string(password)

        self.send_packet(BNLS_CREATEACCOUNT, pak)
        pid, pak = self.receive_packet()
        if pid != BNLS_CREATEACCOUNT:
            return None, None

        return pak.get_raw(32), pak.get_raw(32)
