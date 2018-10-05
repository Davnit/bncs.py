
from bncs.common.buffer import DataReader, DataBuffer
from bncs.common.products import *
from bncs.common.packets import *
from bncs.common.chat import *
from bncs.hashing.sigverify import check_signature
from bncs.hashing.cdkeys import KeyDecoder
from bncs.hashing.nls import NLS_Client, get_sv
from bncs.hashing.xsha import hash_password, double_hash_password
from bnls.client import BnlsClient

from socket import socket, AF_INET, SOCK_STREAM, inet_aton, inet_ntoa
from struct import pack
from datetime import datetime
from threading import Thread
import random
import time
import locale


def parse_chat_event(packet):
    if isinstance(packet, (bytes, bytearray)):
        packet = DataReader(packet)
    elif isinstance(packet, DataBuffer):
        packet = DataReader(packet.data)

    if not isinstance(packet, DataReader):
        raise TypeError("Packet must be a DataReader, DataBuffer, or bytes object.")

    # Try and make sure we're at the right spot in the array.
    packet.position = 0
    if packet.peek() == 0xFF:
        packet.get_raw(4)

    events_with_stats = [EID_SHOWUSER, EID_JOIN, EID_LEAVE, EID_USERFLAGS]

    eid, flags, ping = packet.get_format('<3L')
    packet.get_raw(12)
    user = packet.get_string()
    text = packet.get_string('latin-1' if (eid in events_with_stats) else 'utf-8')

    return eid, user, text, flags, ping


class BncsClient(Thread):
    def __init__(self):
        super().__init__()
        random.seed()

        self.socket = None
        self.host = None
        self.port = None

        # Set state variables
        self._connected = False
        self._verified = False
        self._authenticated = False
        self._logged_on = False
        self._in_chat = False
        self._product = None
        self._logon_type = None
        self._client_token = None
        self._server_token = None
        self._username = None

        # Initialize default packet handlers
        self.packet_handlers = {
            0x25: self._handle_ping
        }

        # Receive buffer
        self.received = []

    def connected(self):
        """Returns True if the client is connected to a server."""
        return self._connected

    def verified(self):
        """Returns True if the remote server has been verified as an official Battle.net server."""
        return self._verified

    def authenticated(self):
        """Returns True if the client has passed authentication (version checking)."""
        return self._authenticated

    def logged_on(self):
        """Returns True if the client has logged into an account."""
        return self._logged_on

    def in_chat(self):
        """Returns True if the client has entered the chat environment."""
        return self._in_chat

    def get_username(self):
        """Returns the username that the client is identified as."""
        return self._username

    def connect(self, host, port=6112):
        """Initiates a connection."""
        self.host = host
        self.port = port

        self.socket = socket(AF_INET, SOCK_STREAM)
        self.socket.connect((host, port))
        self._connected = True

        # Send the protocol selection byte (GAME)
        self.socket.sendall(b'\x01')

        # Generate a client token
        self._client_token = random.getrandbits(32)

        # Start receiving data
        self.start()

    def disconnect(self):
        """Closes the connection."""
        if self._connected:
            self.socket.close()
            self._connected = False

        # Reset state variables
        self._verified = False
        self._authenticated = False
        self._logged_on = False
        self._in_chat = False
        self._product = None
        self._logon_type = None
        self._client_token = None
        self._server_token = None
        self._username = None

    def send_packet(self, packet_id, payload=None):
        """Sends a packet with the specified ID and contents.

        - 'payload' can be either a bytes object or DataBuffer.
        - If no payload is given, an empty packet will be sent."""
        payload = payload or b''

        pak = DataBuffer()
        pak.insert_format('<BBH', 0xFF, packet_id, len(payload) + 4)
        pak.insert_raw(payload)

        self.socket.sendall(pak.data)

    def _receive_packet(self):
        """Receives the next packet from the data stream.

        - Returns both the received packet ID a DataReader containing the packet (starting post-header).
        - If no packet was received, None will be returned."""
        if not self._connected:
            return None, None

        pak = DataReader(self.socket.recv(4))
        if len(pak) == 0:
            self.disconnect()
            return None, pak

        head, pid, length = pak.get_format('<BBH')
        if head != 0xFF:
            raise Exception("Received invalid packet header byte.")

        if length > 4:
            pak.data += self.socket.recv(length - 4)
        return pid, pak

    def wait_for_packet(self, packet_id, timeout=5):
        """Blocks until a packet with the specified ID is received.

        - If a handler is defined for the packet ID, this will timeout.
        - If the timeout period is exceeded (default 5 seconds), None will be returned.
        - The returned packet will be removed from the receive buffer.
        - Returns the DataReader containing the packet contents (starting post-header)."""
        interval = 0.01
        elapsed = 0.0

        while self._connected:
            for i in range(len(self.received)):
                pid, pak = self.received[i]
                if pid == packet_id:
                    del self.received[i]
                    return pak

            time.sleep(interval)
            elapsed += interval

            if elapsed > timeout:
                break

        return None

    def run(self):
        while self._connected:
            pid, pak = self._receive_packet()
            if pid is not None:
                if pid in self.packet_handlers:
                    self.packet_handlers.get(pid)(pid, pak)
                else:
                    self.received.append((pid, pak))

    def authenticate(self, product, keys=None, owner=None, bnls_server='jbls.davnit.net'):
        """Authenticates to the server as the specified product using the provided keys and owner name.

        - Authentication uses BNLS for up-to-date versioning.
        - Keys and owner are optional, though keys may be required depending on the product."""
        self._product = product = product if isinstance(product, BncsProduct) else get_product(product)

        # Use BNLS for version checking
        bnls = BnlsClient()
        bnls.connect(bnls_server)
        bnls.authorize('bncs.py', 'avadakedavra')
        version_byte = bnls.request_version_byte(product)
        if version_byte is False or version_byte == -1:
            self.disconnect()
            return False, ("Unable to retrieve version information from BNLS. (%i)" % version_byte)

        # SID_AUTH_INFO (0x50)
        pak = DataBuffer()
        pak.insert_dword(0)
        pak.insert_dword('IX86')
        pak.insert_dword(product.code)
        pak.insert_dword(version_byte)
        pak.insert_dword((locale.getdefaultlocale()[0] or 'en_US').replace('_', ''))
        pak.insert_raw(inet_aton(self.socket.getsockname()[0]))
        pak.insert_dword(int((datetime.utcnow() - datetime.now()).total_seconds() / 60))
        pak.insert_dword(1033)
        pak.insert_dword(1033)
        pak.insert_string('USA')
        pak.insert_string('United States')
        self.send_packet(SID_AUTH_INFO, pak)

        pak = self.wait_for_packet(SID_AUTH_INFO)
        if pak is None:
            return False, "No auth response."

        self._logon_type = pak.get_dword()
        self._server_token = pak.get_dword()
        pak.get_dword()     # UDP value (ignored)
        ftime = pak.get_long()
        fname = pak.get_string()
        value = pak.get_string('latin-1')

        if not pak.eop():
            self._verified = check_signature(pak.get_raw(128), self.socket.getpeername()[0])

        success, results, version_byte = bnls.check_version(product, ftime, fname, value)
        bnls.disconnect()

        # SID_AUTH_CHECK (0x51)
        pak = DataBuffer()
        pak.insert_dword(self._client_token)
        pak.insert_dword(results[0])
        pak.insert_dword(results[1])
        pak.insert_dword(len(keys))
        pak.insert_dword(0)     # Spawn = false

        for i in range(len(keys)):
            key = KeyDecoder.get(keys[i])
            if not key.decode():
                self.disconnect()
                raise ValueError("Key #%i was unable to be decoded, it is likely invalid." % i)

            pak.insert_dword(len(key))
            pak.insert_dword(key.product)
            pak.insert_dword(key.public)
            pak.insert_dword(0)
            pak.insert_raw(key.get_hash(self._client_token, self._server_token))

        pak.insert_string(results[2])
        pak.insert_string(owner or 'bncs.py')
        self.send_packet(SID_AUTH_CHECK, pak)

        results = {
            0x000: "Authenticated as %s v%s" % (product.name, inet_ntoa(pack('<L', results[0]))),
            0x100: "Old game version (%s)",
            0x101: "Invalid version",
            0x102: "Game version must be downgraded (%s)",
            0x200: "Invalid CD key",
            0x201: "CD key in use by %s",
            0x202: "Banned key",
            0x203: "Wrong product",
            0x210: "Invalid expansion CD key",
            0x211: "Expansion CD key in use by %s",
            0x212: "Banned expansion key",
            0x213: "Wrong expansion key product"
        }
        pak = self.wait_for_packet(SID_AUTH_CHECK)
        if pak is None:
            return False, "No client check response."

        result = pak.get_dword()
        msg = results.get(result, "Invalid version code")
        if "%s" in msg:
            msg = msg % pak.get_string()

        self._authenticated = (result == 0x000)
        return self._authenticated, msg

    def login(self, username, password):
        """Logs into a classic Battle.net account."""
        self._username = username

        if self._logon_type == 0x00:
            # SID_LOGONRESPONSE2 (0x3A)
            pak = DataBuffer()
            pak.insert_dword(self._client_token)
            pak.insert_dword(self._server_token)
            pak.insert_raw(double_hash_password(password, self._client_token, self._server_token))
            pak.insert_string(username)
            self.send_packet(SID_LOGONRESPONSE2, pak)

            results = {
                0x00: "Logon successful",
                0x01: "Account does not exist.",
                0x02: "Invalid password",
                0x06: "Account closed: %s"
            }
            pak = self.wait_for_packet(SID_LOGONRESPONSE2)
            status = pak.get_dword()
            msg = results.get(status, "Unknown logon error: " + hex(status))
            if "%s" in msg:
                msg = msg % pak.get_string()

            self._logged_on = (status == 0x00)
            return self._logged_on, msg

        elif self._logon_type in [0x01, 0x02]:
            nls = NLS_Client(username, password, self._logon_type)

            # SID_AUTH_ACCOUNTLOGON (0x53)
            pak = DataBuffer()
            pak.insert_raw(nls.get_client_key())
            pak.insert_string(username)
            self.send_packet(SID_AUTH_ACCOUNTLOGON, pak)

            results = {
                0x00: "Logon accepted",
                0x01: "Account does not exist.",
                0x05: "Account requires upgrade"
            }
            pak = self.wait_for_packet(SID_AUTH_ACCOUNTLOGON)
            result = pak.get_dword()
            if result != 0:
                # Early failure
                return False, results.get(result, "Logon failed")

            salt = pak.get_raw(32)
            B = pak.get_raw(32)
            proof = nls.process_challenge(salt, B)

            # SID_AUTH_ACCOUNTLOGONPROOF (0x54)
            pak = DataBuffer(proof)
            self.send_packet(SID_AUTH_ACCOUNTLOGONPROOF, pak)

            results = {
                0x00: "Logon successful",
                0x02: "Incorrect password",
                0x06: "Account closed",
                0x0E: "Logon successful, no email registered",
                0x0F: "Logon error: %s"
            }
            success = [0x00, 0x0E]
            pak = self.wait_for_packet(SID_AUTH_ACCOUNTLOGONPROOF)
            status = pak.get_dword()
            nls.verify(pak.get_raw(20))
            msg = results.get(status, "Unknown logon response code: " + hex(status))
            if "%s" in msg:
                msg = msg % pak.get_string()

            if (status in success) and not nls.authenticated():
                msg += ", incorrect server proof"

            self._logged_on = (status in success)
            return self._logged_on and nls.authenticated(), msg

    def create_account(self, username, password):
        """Creates an account"""

        if self._logon_type == 0x00:
            # SID_CREATEACCOUNT2 (0x3D)
            pak = DataBuffer()
            pak.insert_raw(hash_password(password))
            pak.insert_string(username)
            self.send_packet(SID_CREATEACCOUNT2, pak)

            results = {
                0x00: "Account created",
                0x01: "Name is too short",
                0x02: "Name contains invalid characters",
                0x03: "Name contained a banned word",
                0x04: "Account already exists",
                0x05: "Account is still being created",
                0x06: "Name did not contain enough alphanumeric characters",
                0x07: "Name contained adjacent punctuation characters",
                0x08: "Name contained too many punctuation characters"
            }
            pak = self.wait_for_packet(SID_CREATEACCOUNT2)
            result = pak.get_dword()
            return result == 0x00, results.get(result, "Unknown account create response code: " + hex(result))

        elif self._logon_type in [0x01, 0x02]:
            salt, verifier = get_sv(username, password, self._logon_type)

            # SID_AUTH_ACCOUNTCREATE (0x52)
            pak = DataBuffer()
            pak.insert_raw(salt)
            pak.insert_raw(verifier)
            pak.insert_string(username)
            self.send_packet(SID_AUTH_ACCOUNTCREATE, pak)

            results = {
                0x00: "Account created",
                0x04: "Name already exists",
                0x07: "Name is too short",
                0x08: "Name contains an illegal character",
                0x09: "Name contains an illegal word",
                0x0A: "Name contains too few alphanumeric characters",
                0x0B: "Name contains adjacent punctuation characters.",
                0x0C: "Name containts too many punctuation characters."
            }
            pak = self.wait_for_packet(SID_AUTH_ACCOUNTCREATE)
            status = pak.get_dword()
            return status == 0x00, results.get(status, "Account already exists")

    def enter_chat(self):
        """Enters the chat environment and joins the default channel."""

        # SID_ENTERCHAT (0x0A)
        pak = DataBuffer()
        pak.insert_string(self._username)
        pak.insert_string('')
        self.send_packet(SID_ENTERCHAT, pak)

        # SID_JOINCHANNEL (0x0C)
        pak = DataBuffer()
        pak.insert_dword(0x05 if self._product.code in [PRODUCT_D2DV, PRODUCT_D2XP] else 0x01)
        pak.insert_string(self._product.home_channel)
        self.send_packet(SID_JOINCHANNEL, pak)

        pak = self.wait_for_packet(SID_ENTERCHAT)
        self._username = pak.get_string()
        self._in_chat = True

    def leave_chat(self):
        """Leaves the chat environment."""

        self.send_packet(SID_LEAVECHAT)
        self._in_chat = False

    def chat_command(self, text):
        """Sends a chat command or message."""

        # SID_CHATCOMMAND (0x0E)
        pak = DataBuffer(text)
        self.send_packet(SID_CHATCOMMAND, pak)

    def _handle_ping(self, packet_id, payload):
        response = DataBuffer()
        response.insert_dword(payload.get_dword())
        self.send_packet(SID_PING, response)
