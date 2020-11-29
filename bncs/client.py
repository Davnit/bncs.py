
import asyncio
from datetime import datetime
import enum
import logging
import random
import socket
import struct

from .chat import ChatEventType, ChannelFlags, UserFlags
from .hashing import KeyDecoder, hash_password, double_hash_password, NLSClient, get_verifier, xsha1, check_signature
from .packets import *
from .products import BncsProduct, LogonMechanism
from .utils import DataReader


class VersioningResult(enum.Enum):
    NoResult, Passed, PatchNeeded, InvalidVersion, \
        InvalidKey, KeyInUse, KeyBanned, KeyWrongProduct, SpawnDenied = range(9)


class LoginResult(enum.Enum):
    NoResult, LoggedIn, NoAccount, UpgradeRequired, WrongPassword, AccountClosed, NoEmail, \
        UnknownError, ServerProofInvalid = range(9)


class AccountCreationResult(enum.Enum):
    NoResult, AccountCreated, AccountExists, TooShort, CharInvalid, BadWord, TooFewAlphanumeric, \
        AdjacentPunctuation, TooManyPunctuation, UnknownError = range(10)


def _get_fut_result(fut):
    return fut.result() if fut and fut.done() else None


class ChatEvent:
    def __init__(self, packet):
        self.eid = ChatEventType(packet.get_dword())
        flag_type = ChannelFlags if self.eid == ChatEventType.JoinChannel else UserFlags

        self.flags = flag_type(packet.get_dword())
        self.ping = packet.get_dword()
        self.ip = packet.get_ipv4()
        self.account = packet.get_dword()
        self.authority = packet.get_dword()
        self.username = packet.get_string()

        self.text = packet.get_string(encoding=None)     # Text field can have mixed encodings, get it as a byte array
        if self.eid not in [1, 2, 3, 9]:            # Keep raw bytes for events with a statstring
            try:
                self.text = self.text.decode("utf-8")
            except UnicodeDecodeError:
                self.text = self.text.decode("latin-1", errors='ignore')

    def __repr__(self):
        s = f"<BncsChatEvent eid={self.eid.name}, flags={self.flags.name}, ping={self.ping}"

        # Defunct values, only show if they are different from expected.
        if self.ip != "0.0.0.0":
            s += f", ip={self.ip}"
        if self.account != 0xbaadf00d:
            s += f", account={self.account}"
        if self.authority != 0xbaadf00d:
            s += f", authority={self.authority}",

        s += f", username='{self.username}', text='{self.text[:20]}"
        s += ("..." if len(self.text) > 20 else "") + "'>"
        return s


class _UdpTestProtocol(asyncio.DatagramProtocol):
    def __init__(self, bnet_client):
        self.bnet_client = bnet_client
        self.transport = None
        self.completed = False

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if len(data) >= 4 and addr == self.bnet_client.writer.get_extra_info('peername'):
            reader = DataReader(data)
            pid = reader.get_dword()

            self.bnet_client.log.debug(f"Received {len(data)} bytes on UDP socket - ID 0x{pid:08X}")
            if self.bnet_client.config["debug_packets"]:
                self.bnet_client.log.debug(repr(reader))

            if pid == 0x05:
                # PKT_SERVERPING: https://bnetdocs.org/packet/165/pkt-serverping
                code = reader.get_dword()
                if self.completed and (code == self.bnet_client.state["udp_code"]):
                    return

                # https://bnetdocs.org/packet/406/sid-udppingresponse
                x14 = BncsPacket(SID_UDPPINGRESPONSE)
                x14.insert_dword(code)
                self.bnet_client.loop.create_task(self.bnet_client.send(x14))
                self.bnet_client.state["udp_code"] = code

                self.completed = True
            else:
                self.bnet_client.log.warning(f"Received unknown UDP packet: 0x{pid:02X} with {len(data)} bytes of data")
        else:
            self.bnet_client.log.warning(f"Received {len(data)} bytes of unknown UDP data from {addr}")

    def error_received(self, exc):
        self.bnet_client.log.error(f"UDP Error: {exc}")


class BnetClient:
    def __init__(self, *, loop=None, chat_cb=None, recv_cb=None, send_cb=None, **config):
        self.loop = loop or asyncio.get_running_loop()

        self.config = {
            "server": "useast.battle.net",
            "port": 6112,
            "bnls": "jbls.davnit.net",
            "debug_packets": False,

            "language": ["ENU", "enUS"],
            "country": ["USA", "United States", "1"],

            "platform": "IX86",             # Intel x86
            "locale": 1033,                 # English US
            "udp_code": "bnet"              # Fallback UDP code
        }
        self.config.update(config)
        self.state = {}

        # Save callback functions
        self.chat_cb = chat_cb
        self.recv_cb = recv_cb
        self.send_cb = send_cb

        self.log = logging.getLogger("BNCS")

        self.reader, self.writer = None, None
        self.udp = None

        self.packet_handlers = {
            SID_NULL: self._handle_null,
            SID_CLIENTID: self._handle_null,
            SID_STARTVERSIONING: self._handle_auth_challenge,
            SID_REPORTVERSION: self._handle_auth_result,
            SID_ENTERCHAT: self._handle_enter_chat,
            SID_CHATEVENT: self._handle_chat_event,
            SID_FLOODDETECTED: self._handle_flood_detected,
            SID_MESSAGEBOX: self._handle_message_box,
            SID_LOGONCHALLENGEEX: self._handle_logon_challenge_ex,
            SID_PING: self._handle_ping,
            SID_LOGONRESPONSE: self._handle_logon_result,
            SID_CDKEY: self._handle_auth_result,
            SID_CDKEY2: self._handle_auth_result,
            SID_LOGONRESPONSE2: self._handle_logon_result,
            SID_CREATEACCOUNT2: self._handle_account_create_result,
            SID_AUTH_INFO: self._handle_auth_challenge,
            SID_AUTH_CHECK: self._handle_auth_result,
            SID_AUTH_ACCOUNTCREATE: self._handle_account_create_result,
            SID_AUTH_ACCOUNTLOGON: self._handle_logon_challenge,
            SID_AUTH_ACCOUNTLOGONPROOF: self._handle_logon_result,
            SID_SETEMAIL: self._handle_set_email
        }

        self.bnls = None
        self._waiters = []

        self._connected = False

        # Futures for different stages of the connection
        self._authenticated = None           # Completed version check / auth
        self._logged_on = None               # Logged into an account
        self._account_created = None         # Account was created
        self._account_changed = None         # Password was changed or account was upgraded
        self._entered_chat = None            # Entered the chat environment
        self._disconnected = None            # Disconnected

    async def _run_udp_test(self, server_token, udp_token):
        if self.state["product"].uses_udp:
            tx, proto = await self.loop.create_datagram_endpoint(
                lambda: _UdpTestProtocol(self), remote_addr=self.state["endpoint"], family=socket.AF_INET)

            # UDP header consists of only the packet ID
            # https://bnetdocs.org/packet/199/pkt-conntest2
            x09 = DataBuffer()
            x09.insert_dword(0x09)  # Packet ID
            x09.insert_dword(server_token)
            x09.insert_dword(udp_token)

            tx.sendto(x09.data)
            self.log.debug(f"Sent {len(x09.data)} bytes on UDP socket - ID 0x{0x09:08X}")
            if self.config["debug_packets"]:
                self.log.debug(repr(x09))

    async def _send_keep_alives(self):
        while self.connected:
            await asyncio.sleep(480)
            await self.send(BncsPacket(SID_NULL))

    def register_waiter(self, pid, matcher=None):
        fut = self.loop.create_future()
        self._waiters.append((pid, matcher, fut))
        return fut

    def _get_account_login_mechanism(self, options):
        mechanism = options.get("logon_method", self.state["logon_method"])
        if mechanism == LogonMechanism.New and "logon_type" in self.state:
            # NLS login sequence allows the account type (and associated packets) to be overridden
            logon_type = self.state["logon_type"]
            mechanism = LogonMechanism.Old if logon_type == 0 else \
                LogonMechanism.New if logon_type in [1, 2] else \
                mechanism
        return mechanism

    @property
    def connected(self):
        return self._connected

    async def connect(self, **options):
        """
            Opens a connection to the Battle.net server.

            Optional parameters:
                - server: hostname or URL of the Battle.net server
                - port: TCP port number the server is listening on
        """
        if self.connected:
            return True

        self.state = {}     # Reset state
        self.state["endpoint"] = endpoint = \
            options.get("server", self.config["server"]), options.get("port", self.config["port"])

        self.log.info(f"Connecting to {endpoint}...")

        # TCP connection (main transport)
        self.reader, self.writer = \
            await asyncio.open_connection(endpoint[0], endpoint[1], family=socket.AF_INET)      # IPv4 ONLY

        self.writer.write(b'\x01')      # Protocol selection byte
        await self.writer.drain()

        self._connected = True
        self.log.info("Connected. Protocol 0x01 selected.")

        # Start receiving data
        self.loop.create_task(self.receive(), name="BNCS packet receiver")
        self.loop.create_task(self._send_keep_alives(), name="BNCS keep-alive sender")
        self._waiters = []

        self._disconnected = self.loop.create_future()
        return self.connected

    def disconnect(self, msg=None):
        msg = msg or "Client disconnected"

        # Cancel any remaining waiters
        for (pid, matcher, fut) in self._waiters:
            if not fut.done():
                fut.cancel()

        # Cancel uncompleted state futures
        hard_states = {
            self._authenticated: VersioningResult.NoResult,
            self._logged_on: LoginResult.NoResult,
            self._account_created: AccountCreationResult.NoResult,
            self._account_changed: False,
            self._entered_chat: False
        }
        for fut, result in hard_states.items():
            if fut and not fut.done():
                fut.set_result(result)

        if self.connected:
            self._connected = False

            self.writer.close()
            self.log.info(f"Disconnected: {msg}")

        # Close BNLS connection if we're hosting it
        if self.state.get("bnls_host", False):
            # We're not using a pool'd BNLS connection, so we can clean it up now.
            self.bnls.disconnect()

        if not self._disconnected.done():
            self._disconnected.set_result(msg)

    async def wait_for_disconnect(self):
        await self._disconnected
        await self.writer.wait_closed()

        if self.state.get("bnls_host", False):
            await self.bnls.wait_for_disconnect()

    async def send(self, packet):
        if not self.connected:
            self.log.error("Send attempted on closed socket")
            return False

        if self.send_cb and (await self.send_cb(self, packet.packet_id, packet) is True):
            # If the callback function returns TRUE then do not send this packet
            self.log.debug(f"Packet 0x{packet.packet_id:02X} SEND veto'd by callback")
            return False

        self.writer.write(packet.get_data())

        self.log.debug(f"Sent packet 0x{packet.packet_id:02X} ({packet.length} bytes)")
        if self.config["debug_packets"]:
            self.log.debug(repr(packet))

        await self.writer.drain()
        return True

    async def receive(self):
        while self.connected:
            packet = await BncsReader.read_from(self.reader)
            if packet is None:
                return self.disconnect("Server closed the connection")
            elif packet is False:
                return self.disconnect("Invalid packet data received")

            self.log.debug(f"Received packet 0x{packet.packet_id:02X} ({packet.length} bytes)")
            if self.config["debug_packets"]:
                self.log.debug(repr(packet))

            # First pass the packet to any listening callback (gives a chance to veto it)
            if self.recv_cb and (await self.recv_cb(self, packet.packet_id, packet) is True):
                # If the callback functions returns TRUE then do not parse this packet
                self.log.debug(f"Packet 0x{packet.packet_id:02X} RECV veto'd by callback")
                continue

            # Now send the packet to the standard handler, if one exists.
            found = False
            packet.position = 4             # Reset the position
            if packet.packet_id in self.packet_handlers:
                await self.packet_handlers[packet.packet_id](packet)
                found = True

            # Finally pass it to the result of any waiting futures
            for waiter in self._waiters:
                pid, matcher, fut = waiter

                if fut.cancelled():
                    # No longer waiting for this
                    self._waiters.remove(waiter)

                elif pid == packet.packet_id:
                    packet.position = 4         # Reset the position, again

                    if not matcher or matcher(packet):
                        packet.position = 4     # One last time on the reset
                        fut.set_result(packet)
                        self._waiters.remove(waiter)
                        found = True
                        break

            if not found:
                self.log.debug(f"Packet 0x{packet.packet_id:02X} was not handled")
                if not self.config["debug_packets"]:
                    # Only print the packet data again if we didn't before.
                    self.log.debug(repr(packet))

    async def authenticate(self, product=None, keys=None, timeout=5, **options):
        """
            Authenticates the client to Battle.net and returns the status of the operation.

            Required parameters: (can be set in config)
                - product: 4-digit str product code identifying the emulated client (ex: D2DV)
                - keys: list[str] of product/CD keys the client should register

            Supported options:
                - bnls: the hostname or IP of a BNLS server used to assist the connection (default: jbls.davnit.net)
                - platform: the 4-digit platform code for the emulated game (ex: IX86)
                - verbyte: int value quickly identifying this product's version (uses BNLS if not set)
                - logon_method: a bncs.LogonMechanism identifying the process used for authentication
                - language: a str identifying the product's language (default: US English)
                - locale: int representing the client's locale (default 1033 [English US])
                - country: a list[str] values representing the client's country (abbreviation, name, numeric code)
                - tz_bias: int seconds between UTC and client's local time
                - spawn: bool indicating if the client should be spawned
                - key_owner: name to register to the product key(s)
                - udp_check: bool indicating if the client should verify UDP to the server

            Notes:
                - Official Battle.net servers will timeout this operation when a client is IP banned from connecting.
                - Optional parameters will default to the default behavior for the specified product.
                - client state values for 'key_owner' and 'patch_file' will be set for their respective error codes
        """
        err_header = "Client authentication failed"
        if not self.connected:
            self.log.error(f"{err_header} - client not connected")
            return VersioningResult.NoResult

        # Client cannot already be authenticated
        if _get_fut_result(self._authenticated) == VersioningResult.Passed:
            self.log.error(f"{err_header} - client already authenticated")
            return VersioningResult.NoResult

        # Valid product must be selected
        product = self.state["product"] = BncsProduct.get(self.config["product"] if product is None else product)
        if product is None:
            self.log.error(f"{err_header} - no product configured")
            return VersioningResult.NoResult

        # If the product requires CD keys, make sure we have them and they are valid.
        keys_needed = len(product.required_keys)
        if keys_needed > 0:
            product_keys = self.config.get("keys", []) if keys is None else keys

            if keys_needed > len(product_keys):
                self.log.error(f"{err_header} - missing {keys_needed - len(product_keys)} required product keys")
                return VersioningResult.NoResult

            # Validate the keys we do have
            self.state["product_keys"] = []
            for k_idx in range(len(product_keys)):
                try:
                    key = KeyDecoder.get(product_keys[k_idx])
                    if not key.decode():
                        raise ValueError()
                    self.state["product_keys"].append(key)
                except ValueError:
                    self.log.error(f"{err_header} - key #{k_idx + 1} is invalid (decode failed)")
                    self.state["crev_errored_key_index"] = k_idx
                    return VersioningResult.InvalidKey

        # Prepare for the version check
        if not self.bnls:
            from bnls import BnlsClient

            bnls_server = options.get("bnls", self.config["bnls"])
            self.bnls = BnlsClient(server=bnls_server, debug_packets=self.config["debug_packets"])
            self.state["bnls_host"] = True   # Mark that we created the BNLS client, so we can clean it up later.

        # We just need a version byte to request a challenge
        verbyte = self.state["verbyte"] = options.get("verbyte", self.config.get("verbyte"))
        if verbyte is None:
            if not self.bnls.connected:
                await self.bnls.connect()

            self.state["verbyte"] = await self.bnls.request_version_byte(product.code)
            self.log.debug(f"Received version byte for '{product.code}' from BNLS: 0x{self.state['verbyte']:02X}")

        # Determine which packet sequence to use
        mechanism = options.get("logon_method", self.config.get("logon_method", product.logon_mechanism))
        self._authenticated = self.loop.create_future()
        self.log.info("Authenticating client...")

        # Save some options for later
        self.state["platform"] = options.get("platform", self.config["platform"])
        self.state["check_udp"] = options.get("udp_check", self.config.get("udp_check", product.uses_udp))
        self.state["key_owner"] = options.get("key_owner", self.config.get("key_owner", "bncs.py client"))
        self.state["use_spawn"] = options.get("spawn", self.config.get("spawn", False))
        self.state["client_token"] = random.getrandbits(32)
        self.state["logon_method"] = mechanism

        # Build some values
        s_time, l_time = datetime.utcnow(), datetime.now()
        tz_bias = int((s_time - l_time).total_seconds() / 60)
        country_info = options.get("country", self.config["country"])
        language = options.get("language", self.config["language"])
        locale = options.get("locale", self.config["locale"])

        # Initialize versioning
        packet_ids = {
            LogonMechanism.Legacy: SID_CLIENTID,
            LogonMechanism.Old: SID_CLIENTID2,
            LogonMechanism.New: SID_AUTH_INFO
        }
        pak = BncsPacket(packet_ids.get(mechanism, SID_AUTH_INFO))
        if pak.packet_id == SID_AUTH_INFO:
            # Modern authentication - officially supported (but not used) by all binary products
            # https://bnetdocs.org/packet/279/sid-auth-info
            pak.insert_dword(0)
            pak.insert_dword(self.state["platform"])
            pak.insert_dword(self.state["product"].code)
            pak.insert_dword(self.state["verbyte"])
            pak.insert_dword(language[1] if isinstance(language, list) else language)
            pak.insert_ipv4(self.writer.get_extra_info('sockname')[0])
            pak.insert_dword(options.get("tz_bias", tz_bias))
            pak.insert_dword(locale)
            pak.insert_dword(locale)
            pak.insert_string(country_info[0])
            pak.insert_string(country_info[1])
            await self.send(pak)

        else:
            # Legacy authentication - used with older games (W2, D1, etc)
            # SID_CLIENTID: https://bnetdocs.org/packet/244/sid-clientid
            # SID_CLIENTID2: https://bnetdocs.org/packet/381/sid-clientid2
            if pak.packet_id == SID_CLIENTID2:
                pak.insert_dword(1)     # One extra DWORD for this one

            pak.insert_raw(b"\x00" * 18)    # 4 DWORD's + 2 empty strings (all defunct)
            await self.send(pak)

            # https://bnetdocs.org/packet/287/sid-localeinfo
            x12 = BncsPacket(SID_LOCALEINFO)
            x12.insert_filetime(s_time)
            x12.insert_filetime(l_time)
            x12.insert_dword(options.get("tz_bias", tz_bias))
            x12.insert_dword(locale)
            x12.insert_dword(locale)
            x12.insert_dword(locale)
            x12.insert_string(language[0] if isinstance(language, list) else language)
            x12.insert_string(country_info[2] if len(country_info) > 2 else "1")
            x12.insert_string(country_info[0])
            x12.insert_string(country_info[1])
            await self.send(x12)

            # https://bnetdocs.org/packet/372/sid-startversioning
            x06 = BncsPacket(SID_STARTVERSIONING)
            x06.insert_dword(options.get("platform", self.config["platform"]))
            x06.insert_dword(self.state["product"].code)
            x06.insert_dword(self.state["verbyte"])
            x06.insert_dword(0)  # Unknown
            await self.send(x06)

        try:
            return await asyncio.wait_for(self._authenticated, timeout)
        except asyncio.TimeoutError:
            self.log.error(f"{err_header} - timed out after {timeout} seconds")

    async def login(self, username=None, password=None, timeout=5, **options):
        """
            Logs into a classic Battle.net account and returns the status of the operation.

            Required parameters: (can be set in config)
                - username: name of the account to login to
                - password: password for the account

            Supported options:
                - logon_method: a bncs.LogonMechanism identifying the process used for login
                    (defaults to the product's default method, or the server's specified one if available)
                - ignore_proof: a bool indicating if the client should ignore the server's password proof (NLS only)
                - email: an email address to register to the account
                - nls_version: overrides the version of NLS used (logon_method must also be NLS)
        """
        err_header = "Account login failed"

        # Client must be authenticated to login
        if _get_fut_result(self._authenticated) != VersioningResult.Passed:
            self.log.error(f"{err_header} - client not authenticated")
            return LoginResult.NoResult

        # Client cannot already be logged in
        if _get_fut_result(self._logged_on) == LoginResult.LoggedIn:
            self.log.error(f"{err_header} - client already logged in")
            return LoginResult.NoResult

        username = self.state["account_name"] = \
            self.config.get("username", self.state.get("account_name")) if username is None else username
        if username is None:
            self.log.error(f"{err_header} - no username specified")
            return LoginResult.NoResult

        password = self.config.get("password") if password is None else password
        if password is None:
            self.log.error(f"{err_header} - no password specified")
            return LoginResult.NoResult

        # Save some options
        self.state["register_email"] = \
            self.state.get("register_email", options.get("email", self.config.get("register_email")))

        self._logged_on = self.loop.create_future()
        self.log.info(f"Logging into account '{username}'...")

        mechanism = self._get_account_login_mechanism(options)
        if mechanism in [LogonMechanism.Legacy, LogonMechanism.Old]:
            c_token, s_token = self.state["client_token"], self.state["server_token"]

            # The format for both of these packets is the same, the only difference is the response.
            # https://bnetdocs.org/packet/262/sid-logonresponse
            # https://bnetdocs.org/packet/225/sid-logonresponse2
            pak = BncsPacket(SID_LOGONRESPONSE if mechanism == LogonMechanism.Legacy else SID_LOGONRESPONSE2)
            pak.insert_dword(c_token)
            pak.insert_dword(s_token)
            pak.insert_raw(double_hash_password(password, c_token, s_token))
            pak.insert_string(username)
            await self.send(pak)

        elif mechanism == LogonMechanism.New:
            # Server specifies the required version in the response to SID_AUTH_INFO
            # If we did not receive this, default to version 2, which is the most common.
            nls = NLSClient(username, password, options.get("nls_version", self.state.get("logon_type", 2)))
            self.state["nls_client"] = nls
            self.state["ignore_nls_proof"] = options.get("ignore_proof", self.config.get("ignore_nls_proof", False))

            # https://bnetdocs.org/packet/323/sid-auth-accountlogon
            x53 = BncsPacket(SID_AUTH_ACCOUNTLOGON)
            x53.insert_raw(nls.get_client_key())
            x53.insert_string(username)
            await self.send(x53)

        else:
            self.log.error(f"{err_header} - login mechanism not supported: {mechanism}")
            return LoginResult.NoResult

        # This will timeout if you have failed too many login attempts (account temporarily locked)
        try:
            return await asyncio.wait_for(self._logged_on, timeout)
        except asyncio.TimeoutError:
            self.log.error(f"{err_header} - timed out after {timeout} seconds")

    async def create_account(self, username=None, password=None, timeout=5, **options):
        """
            Registers a classic Battle.net account and returns success.

            Required parameters: (can be set in config)
                - username: name of the account to register
                - password: password for the account

            Supported options:
                - logon_method: a bncs.LogonMechanism identifying the process used for creating
                - nls_version: overrides the version of NLS used (logon_method must also be NLS)
        """
        err_header = "Account creation failed"

        # Client must be authenticated to login
        if _get_fut_result(self._authenticated) != VersioningResult.Passed:
            self.log.error(f"{err_header} - client not authenticated")
            return LoginResult.NoResult

        # Client cannot already be logged in
        if _get_fut_result(self._logged_on) == LoginResult.LoggedIn:
            self.log.error(f"{err_header} - client already logged in")
            return LoginResult.NoResult

        username = self.state["account_name"] = \
            self.config.get("username", self.state.get("account_name")) if username is None else username
        if username is None:
            self.log.error(f"{err_header} - no username specified")
            return LoginResult.NoResult

        password = self.config.get("password") if password is None else password
        if password is None:
            self.log.error(f"{err_header} - no password specified")
            return LoginResult.NoResult

        self.log.info(f"Creating account '{username}'...")
        self._account_created = self.loop.create_future()

        mechanism = self._get_account_login_mechanism(options)
        if mechanism in [LogonMechanism.Legacy, LogonMechanism.Old]:
            # The format for both of these packets is the same, the only difference is the response.
            # https://bnetdocs.org/packet/305/sid-createaccount
            # https://bnetdocs.org/packet/226/sid-createaccount2
            pak = BncsPacket(SID_CREATEACCOUNT if mechanism == LogonMechanism.Legacy else SID_CREATEACCOUNT2)
            pak.insert_raw(hash_password(password))
            pak.insert_string(username)
            await self.send(pak)

        elif mechanism == LogonMechanism.New:
            salt, verifier = get_verifier(username, password,
                                          options.get("nls_version", self.state.get("logon_type", 2)))

            # https://bnetdocs.org/packet/274/sid-auth-accountcreate
            x52 = BncsPacket(SID_AUTH_ACCOUNTCREATE)
            x52.insert_raw(salt)
            x52.insert_raw(verifier)
            x52.insert_string(username)
            await self.send(x52)

        else:
            self.log.error(f"{err_header} - account creation mechanism not supported: {mechanism}")
            return LoginResult.NoResult

        try:
            return await asyncio.wait_for(self._account_created, timeout)
        except asyncio.TimeoutError:
            self.log.error(f"{err_header} - timed out after {timeout} seconds")

    async def register_email(self, email=None):
        err_header = "Email registration failed"

        # Client must be logged in
        if not self._logged_on or (self._logged_on.done() and not self._logged_on.result()):
            self.log.error(f"{err_header} - not logged on")
            return False

        email = self.state.get("register_email", self.config.get("email")) if email is None else email
        if email is None:
            self.log.error(f"{err_header} - no email specified")
            return False

        x59 = BncsPacket(SID_SETEMAIL)
        x59.insert_string(email)
        await self.send(x59)

        # There is no real confirmation that this succeeds, so just return if it was sent.
        return True

    async def enter_chat(self, timeout=5, **options):
        """
            Enters chat and joins the client's home channel.

            Optional parameters:
                - username: username to send with SID_ENTERCHAT (doesn't usually do anything)
                - statstring: a custom statstring (may not work for all products)
                - product: overrides the product used when requesting channel list and joining home
                    (may not always work or do anything different)
                - home_channel: a custom channel to join instead of the client's product home
        """
        err_header = "Unable to enter chat"

        # Client must be logged in to an account
        if _get_fut_result(self._logged_on) != LoginResult.LoggedIn:
            self.log.error(f"{err_header} - not logged in")
            return False

        # Client must not already be in chat
        if _get_fut_result(self._entered_chat):
            self.log.error(f"{err_header} - already in chat")
            return False

        product_code = options.get("product", self.state["product"].code)
        product = BncsProduct.get(product_code) or self.state["product"]
        home_channel = options.get("home_channel", self.config.get("home_channel", product.home_channel))

        self._entered_chat = self.loop.create_future()

        # https://bnetdocs.org/packet/145/sid-enterchat
        x0a = BncsPacket(SID_ENTERCHAT)
        x0a.insert_string(options.get("username", self.state["account_name"]))
        x0a.insert_string(options.get("statstring", self.state.get("statstring", self.config.get("statstring", ""))))
        await self.send(x0a)

        # https://bnetdocs.org/packet/374/sid-getchannellist
        await self.request_channel_list(product_code)

        # https://bnetdocs.org/packet/227/sid-joinchannel
        await self.join_channel(home_channel, product.home_flags if home_channel == product.home_channel else 0x02)

        try:
            return await asyncio.wait_for(self._entered_chat, timeout)
        except asyncio.TimeoutError:
            self.log.error(f"{err_header} - timed out after {timeout} seconds")

    async def request_channel_list(self, product=None):
        product = self.state["product"].code if product is None else product

        # https://bnetdocs.org/packet/374/sid-getchannellist
        x0b = BncsPacket(SID_GETCHANNELLIST)
        x0b.insert_dword(product)

        reply = self.register_waiter(SID_GETCHANNELLIST)
        await self.send(x0b)

        # https://bnetdocs.org/packet/363/sid-getchannellist
        pak = await reply
        channels = []
        while len(channel := pak.get_string()) > 0:
            channels.append(channel)
        return channels

    async def join_channel(self, channel, flags=0):
        # https://bnetdocs.org/packet/227/sid-joinchannel
        x0c = BncsPacket(SID_JOINCHANNEL)
        x0c.insert_dword(flags)
        x0c.insert_string(channel)
        await self.send(x0c)

    async def send_command(self, command):
        # https://bnetdocs.org/packet/360/sid-chatcommand
        x0e = BncsPacket(SID_CHATCOMMAND)
        x0e.insert_string(command)
        return await self.send(x0e)

    async def full_login(self, username=None, password=None, product=None, keys=None, **options):
        if await self.connect(**options):
            if await self.authenticate(product, keys, **options) == VersioningResult.Passed:
                login_status = await self.login(username, password, **options)

                if login_status == LoginResult.NoAccount:
                    if await self.create_account(username, password, **options) == AccountCreationResult.AccountCreated:
                        login_status = await self.login(username, password, **options)

                if login_status == LoginResult.LoggedIn:
                    return await self.enter_chat(**options)

        return False

    async def get_icon_data(self):
        err_header = "Unable to retrieve icon data"

        # Client must be authenticated
        if _get_fut_result(self._authenticated) != VersioningResult.Passed:
            self.log.error(f"{err_header} - client not authenticated")
            return None, None

        # Client cannot already be in chat
        if _get_fut_result(self._entered_chat):
            self.log.error(f"{err_header} - already in chat")
            return None, None

        fut = self.register_waiter(SID_GETICONDATA)

        # https://bnetdocs.org/packet/121/sid-geticondata
        await self.send(BncsPacket(SID_GETICONDATA))

        # https://bnetdocs.org/packet/120/sid-geticondata
        reply = await fut
        ft = reply.get_filetime()
        name = reply.get_string()
        self.log.debug(f"Icon file: {name} ({ft})")
        return name, ft

    async def get_filetime(self, file, req_id=None):
        # Client must be authenticated
        if _get_fut_result(self._authenticated) != VersioningResult.Passed:
            self.log.error(f"Unable to request metadata for '{file}' - client not authenticated")
            return None

        known_req_ids = {
            "tos_usa.txt": 0x01,
            "bnserver-WAR3.ini": 0x03,
            "tos_USA.txt": 0x1A,
            "bnserver.ini": 0x1B,
            "icons_STAR.bni": 0x1D,
            "bnserver-D2DV.ini": 0x80000004,
            "IX86ExtraWork.mpq": 0x80000005
        }
        req_id = known_req_ids.get(file, 0) if req_id is None else req_id

        def matcher(p):
            if p.get_dword() == req_id:
                p.get_raw(12)       # skip unknown and filetime
                return p.get_string() == file
            return False

        fut = self.register_waiter(SID_GETFILETIME, matcher)

        # https://bnetdocs.org/packet/382/sid-getfiletime
        x33 = BncsPacket(SID_GETFILETIME)
        x33.insert_dword(req_id)
        x33.insert_dword(0)
        x33.insert_string(file)
        await self.send(x33)

        # https://bnetdocs.org/packet/195/sid-getfiletime
        reply = await fut
        reply.get_raw(8)    # Skip request ID and null unknown (req already verified in matcher)
        return reply.get_filetime()

    async def get_user_data(self, accounts, keys, ignore_limits=False):
        # Client must be authenticated
        if _get_fut_result(self._authenticated) != VersioningResult.Passed:
            self.log.error(f"Unable to request user data - client not authenticated")
            return None

        accounts = [accounts] if not isinstance(accounts, list) else accounts
        keys = [keys] if not isinstance(keys, list) else keys

        if not ignore_limits:
            blocked_header = "User data request blocked"

            if len(accounts) > 1:
                self.log.warning(f"{blocked_header} - only 1 account can be requested at a time")
                return {}
            elif len(keys) >= 32:
                self.log.warning(f"{blocked_header} - cannot request 32 or more keys at a time")
                return {}

        # Find an available request ID
        requests = self.state.get("user_data_requests", {})
        req_id = 1
        while req_id in requests:
            req_id += 1
        requests[req_id] = (accounts, keys)
        self.state["user_data_requests"] = requests

        # Build a response matcher
        def matcher(p):
            p.get_raw(8)    # Skip numbers
            return p.get_dword() == req_id

        fut = self.register_waiter(SID_READUSERDATA, matcher)

        # https://bnetdocs.org/packet/358/sid-readuserdata
        x26 = BncsPacket(SID_READUSERDATA)
        x26.insert_dword(len(accounts))
        x26.insert_dword(len(keys))
        x26.insert_dword(req_id)
        for account in accounts:
            x26.insert_string(account)
        for key in keys:
            x26.insert_string(key)
        await self.send(x26)

        # https://bnetdocs.org/packet/112/sid-readuserdata
        reply = await fut
        num_accounts = reply.get_dword()
        num_keys = reply.get_dword()

        # Verify the response is sensical
        if num_accounts != len(accounts) or num_keys != len(keys):
            self.log.warning("User data request failed - server returned mismatched response")
            return {}

        reply.get_dword()       # Skip request ID verified in matcher

        data = {}
        for account in accounts:
            data[account] = {}
            for key in keys:
                data[account][key] = reply.get_string()

        return data

    async def set_user_data(self, accounts, keys, values, ignore_limits=False):
        # Client must be logged in
        if _get_fut_result(self._logged_on) != LoginResult.LoggedIn:
            self.log.error(f"Unable to set user data - client not logged in")
            return None

        accounts = [accounts] if not isinstance(accounts, list) else accounts
        keys = [keys] if not isinstance(keys, list) else keys

        if not ignore_limits:
            blocked_header = "User data request blocked"

            if len(accounts) > 1 or accounts[0].lower() != self.state["account_name"].lower():
                self.log.warning(f"{blocked_header} - you can only modify your own account")
                return {}
            elif len(keys) >= 32:
                self.log.warning(f"{blocked_header} - cannot set 32 or more keys at a time")
                return {}

        # https://bnetdocs.org/packet/122/sid-writeuserdata
        x27 = BncsPacket(SID_WRITEUSERDATA)
        x27.insert_dword(len(accounts))
        x27.insert_dword(len(keys))
        for account in accounts:
            x27.insert_string(account)
        for key in keys:
            x27.insert_string(key)
        for account in accounts:
            data = values[account]
            for key in keys:
                x27.insert_string(data[key])
        await self.send(x27)

    async def leave_chat(self):
        # Client must be in chat
        if not _get_fut_result(self._entered_chat):
            self.log.error("Unable to leave chat - client not in chat")
            return False

        # https://bnetdocs.org/packet/339/sid-leavechat
        await self.send(BncsPacket(SID_LEAVECHAT))
        return True

    async def _handle_null(self, packet):
        pass

    async def _handle_ping(self, packet):
        # S->C https://bnetdocs.org/packet/164/sid-ping
        # C->S https://bnetdocs.org/packet/268/sid-ping
        x25 = BncsPacket(SID_PING)
        x25.insert_dword(packet.get_dword())        # Echo the value back
        await self.send(x25)

    async def _handle_logon_challenge_ex(self, packet):
        # https://bnetdocs.org/packet/286/sid-logonchallengeex
        self.state["udp_token"] = udp_token = packet.get_dword()
        self.state["server_token"] = server_token = packet.get_dword()
        await self._run_udp_test(server_token, udp_token)

    async def _handle_auth_challenge(self, packet):
        if packet.packet_id == SID_STARTVERSIONING:
            # https://bnetdocs.org/packet/127/sid-startversioning
            filetime = packet.get_filetime()
            archive = packet.get_string()
            formula = packet.get_string(encoding=None)      # Some formulas can contain raw data

        elif packet.packet_id == SID_AUTH_INFO:
            # https://bnetdocs.org/packet/146/sid-auth-info
            self.state["logon_type"] = logon_type = packet.get_dword()
            logon_types = {
                0: "XSha1 (OLS)",
                1: "NLSv1",
                2: "NLSv2"
            }
            type_name = logon_types.get(logon_type, f"Unknown (0x{logon_type:08X})")
            self.log.info(f"Server suggests {type_name} account login.")

            self.state["server_token"] = s_token = packet.get_dword()
            self.state["udp_token"] = u_token = packet.get_dword()
            await self._run_udp_test(s_token, u_token)

            filetime = packet.get_filetime()
            archive = packet.get_string()
            formula = packet.get_string(encoding=None)

            # Check for a server signature
            if not packet.eob():
                server_ip = self.writer.get_extra_info('peername')[0]
                signature = packet.get_raw(128)
                if check_signature(signature, server_ip):
                    self.log.info("Server signature verified!")
                else:
                    self.log.warning("Server signature verification failed - this may not be an official server")
        else:
            self.log.error(f"Unsupported packet sent to handle_auth_challenge: 0x{packet.packet_id:02X}")
            return

        err_header = "Client authentication failed"
        if self.bnls:
            if not self.bnls.connected:
                await self.bnls.connect()

            results = self.state["crev_results"] = \
                await self.bnls.check_version(self.state["product"].code, filetime, archive, formula)

            if not results:
                self.log.error(f"{err_header} - BNLS failed version check")
                self._authenticated.set_result(False)
            else:
                results = results.check
        else:
            # Local hashing still not supported
            results = None

        if not results:
            # We have no way to continue
            return self.disconnect("Check revision failed (client)")

        if packet.packet_id == SID_STARTVERSIONING:
            # Send SID_REPORTVERSION: https://bnetdocs.org/packet/347/sid-reportversion
            x07 = BncsPacket(SID_REPORTVERSION)
            x07.insert_dword(self.state["platform"])
            x07.insert_dword(self.state["product"].code)
            x07.insert_dword(self.state["verbyte"])
            x07.insert_dword(results.version)
            x07.insert_dword(results.checksum)
            x07.insert_raw(results.info + b'\0')
            await self.send(x07)

        elif packet.packet_id == SID_AUTH_INFO:
            keys = self.state.get("product_keys", [])

            # Send SID_AUTH_CHECK: https://bnetdocs.org/packet/408/sid-auth-check
            x51 = BncsPacket(SID_AUTH_CHECK)
            x51.insert_dword(self.state["client_token"])
            x51.insert_dword(results.version)
            x51.insert_dword(results.checksum)
            x51.insert_dword(len(keys))
            x51.insert_dword(1 if self.state["use_spawn"] else 0)

            for k_idx in range(len(keys)):
                key = keys[k_idx]
                self.log.debug(f"Product key #{k_idx + 1}: {key.get_product_name()}")

                x51.insert_dword(len(key))
                x51.insert_dword(key.product)
                x51.insert_dword(key.public)
                x51.insert_dword(0)
                x51.insert_raw(key.get_hash(self.state["client_token"], self.state["server_token"]))

            x51.insert_raw(results.info + b'\0')
            x51.insert_string(self.state["key_owner"])
            await self.send(x51)

    async def _handle_auth_result(self, packet):
        err_header = "Client authentication failed"

        if packet.packet_id == SID_REPORTVERSION:
            # https://bnetdocs.org/packet/412/sid-reportversion
            result = packet.get_dword()
            result_lookup = {
                0x00: VersioningResult.InvalidVersion,
                0x01: VersioningResult.PatchNeeded,
                0x02: VersioningResult.Passed,
                0x03: VersioningResult.PatchNeeded
            }
            result = result_lookup.get(result, result)

            if result == VersioningResult.Passed:
                keys = self.state.get("product_keys", [])
                if len(keys) == 1:
                    # Register and validate product keys
                    if self.state["logon_method"] == LogonMechanism.Legacy:
                        # https://bnetdocs.org/packet/170/sid-cdkey
                        x30 = BncsPacket(SID_CDKEY)
                        x30.insert_dword(1 if self.state["use_spawn"] else 0)
                        x30.insert_string(keys[0].key)
                        x30.insert_string(self.state["key_owner"])
                        await self.send(x30)

                    else:
                        # https://bnetdocs.org/packet/359/sid-cdkey2
                        x36 = BncsPacket(SID_CDKEY2)
                        x36.insert_dword(1 if self.state["use_spawn"] else 0)
                        x36.insert_dword(len(keys[0]))
                        x36.insert_dword(keys[0].product)
                        x36.insert_dword(keys[0].public)
                        x36.insert_dword(self.state["server_token"])
                        x36.insert_dword(self.state["client_token"])

                        key_buff = struct.pack('<5L', self.state["client_token"], self.state["server_token"],
                                               keys[0].product, keys[0].public, keys[0].private)
                        x36.insert_raw(xsha1(key_buff).digest())
                        x36.insert_string(self.state["key_owner"])
                        await self.send(x36)

                    # We're not done with auth until these CD key checks also pass
                    # When these packets are returned it will be handled elsewhere in this function.
                    return

                elif len(keys) > 1:
                    # Too many keys, can't continue with this method (or can we?)
                    # TODO: Find out if we can use SID_CDKEY2 or SID_CDKEY3 for multi-key auth
                    self.log.error(f"{err_header} - multi-key product used with single-key auth method")
                    self._authenticated.set_result(False)
                    return

        elif packet.packet_id == SID_AUTH_CHECK:
            # https://bnetdocs.org/packet/106/sid-auth-check
            result = packet.get_dword()
            if result == 0:
                result = VersioningResult.Passed

            elif result & 0x0FF == result:
                # Invalid version code
                result = VersioningResult.InvalidVersion

            elif result & 0x100 == 0x100:
                # Result is a versioning error
                result_lookup = {
                    0x100: VersioningResult.PatchNeeded,
                    0x101: VersioningResult.InvalidVersion,
                    0x102: VersioningResult.PatchNeeded
                }
                result = result_lookup.get(result, result)

            elif result & 0x200 == 0x200:
                # Result is a key registration error
                result_lookup = {
                    0x200: VersioningResult.InvalidKey,
                    0x201: VersioningResult.KeyInUse,
                    0x202: VersioningResult.KeyBanned,
                    0x203: VersioningResult.KeyWrongProduct
                }
                self.state["crev_errored_key_index"] = (result & 0x0F0) // 16
                result = result_lookup.get(result & ~0x0F0, result)

        elif packet.packet_id in [SID_CDKEY, SID_CDKEY2]:
            # Response is the same for both SID_CDKEY and SID_CDKEY2
            # SID_CDKEY: https://bnetdocs.org/packet/188/sid-cdkey
            # SID_CDKEY2: https://bnetdocs.org/packet/184/sid-cdkey2
            result = packet.get_dword()
            result_lookup = {
                0x01: VersioningResult.Passed,
                0x02: VersioningResult.InvalidKey,
                0x03: VersioningResult.KeyWrongProduct,
                0x04: VersioningResult.KeyBanned,
                0x05: VersioningResult.KeyInUse
            }
            result = result_lookup.get(result, result)
            self.state["crev_errored_key_index"] = 0
        else:
            self.log.error(f"Unsupported packet sent to handle_auth_result: 0x{packet.packet_id:02X}")
            return

        if result != VersioningResult.Passed:
            if result == VersioningResult.KeyInUse:
                owner = self.state["key_owner"] = packet.get_string()
                if self.state["use_spawm"] and owner in ["TOO MANY SPAWNS", "NO SPAWNING"]:
                    result = VersioningResult.SpawnDenied
            elif result == VersioningResult.PatchNeeded:
                self.state["patch_file"] = packet.get_string()

            key_number = self.state.get("crev_errored_key_index", -1) + 1
            error_lookup = {
                VersioningResult.PatchNeeded: f"patch required ({self.state.get('patch_file', 'no patch')})",
                VersioningResult.InvalidVersion: "invalid game version",
                VersioningResult.InvalidKey: f"product key #{key_number} invalid",
                VersioningResult.KeyInUse: f"product key #{key_number} in use by '{self.state['key_owner']}'",
                VersioningResult.KeyBanned: f"product key #{key_number} is banned",
                VersioningResult.KeyWrongProduct: f"product key #{key_number} is for another game",
                VersioningResult.SpawnDenied: f"product key #{key_number} denied spawn ({self.state['key_owner']})"
            }
            self.log.error(f"{err_header} - {error_lookup.get(result, 'Unknown error')}")
        else:
            self.log.info(f"Authenticated as {self.state['product'].name}")

        self._authenticated.set_result(result)

    def _display_logon_error(self, result, header):
        if result in [LoginResult.NoResult, LoginResult.LoggedIn]:
            return

        error_lookup = {
            LoginResult.NoAccount: "Account does not exist",
            LoginResult.UpgradeRequired: "Account must be upgraded",
            LoginResult.WrongPassword: "Incorrect password",
            LoginResult.AccountClosed: "Account is closed (%0)",
            LoginResult.NoEmail: "An email address should be registered to this account.",
            LoginResult.UnknownError: "An unknown error occurred: %0",
            LoginResult.ServerProofInvalid: "The server failed to prove it knows your password"
        }
        error = error_lookup.get(result, LoginResult.UnknownError)
        if result in [LoginResult.AccountClosed, LoginResult.UnknownError]:
            error = error.replace("%0", self.state.get("logon_error_code"))

        if result == LoginResult.NoEmail:
            self.log.info(error)
        else:
            self.log.error(f"{header} - {error}")

    async def _handle_logon_challenge(self, packet):
        err_header = "Account login failed"
        result = LoginResult.NoResult

        if packet.packet_id == SID_AUTH_ACCOUNTLOGON:
            # https://bnetdocs.org/packet/210/sid-auth-accountlogon
            status = packet.get_dword()
            if status == 0x00:      # Accepted, requires proof
                salt = packet.get_raw(32)
                server_key = packet.get_raw(32)

                nls = self.state["nls_client"]
                proof = nls.process_challenge(salt, server_key)
                if not proof:
                    self.log.error(f"{err_header} - SRP client proof calculation failed")
                    result = LoginResult.UnknownError
                else:
                    # https://bnetdocs.org/packet/378/sid-auth-accountlogonproof
                    x54 = BncsPacket(SID_AUTH_ACCOUNTLOGONPROOF)
                    x54.insert_raw(proof)
                    await self.send(x54)
            else:
                status_lookup = {
                    0x01: LoginResult.NoAccount,
                    0x05: LoginResult.UpgradeRequired
                }
                result = status_lookup.get(status, LoginResult.UnknownError)

            if result == LoginResult.UnknownError:
                self.state["logon_error_code"] = status

        else:
            self.log.error(f"Unsupported packet sent to handle_logon_challenge: 0x{packet.packet_id:02X}")
            return

        if result != LoginResult.NoResult:
            self._display_logon_error(result, err_header)
            self._logged_on.set_result(result)

    async def _handle_logon_result(self, packet):
        err_header = "Account login failed"

        if packet.packet_id == SID_AUTH_ACCOUNTLOGONPROOF:
            # https://bnetdocs.org/packet/330/sid-auth-accountlogonproof
            status = packet.get_dword()
            status_lookup = {
                0x00: LoginResult.LoggedIn,
                0x02: LoginResult.WrongPassword,
                0x06: LoginResult.AccountClosed,
                0x0E: LoginResult.NoEmail,
                0x0F: LoginResult.UnknownError,
                0x48: LoginResult.UnknownError
            }
            result = status_lookup.get(status, LoginResult.UnknownError)

            proof = packet.get_raw(20)      # Read even if we know if failed (error comes after)

            if result in [LoginResult.LoggedIn, LoginResult.NoEmail]:
                # Login was accepted, make sure the server knows whats up.
                nls = self.state["nls_client"]
                if not nls.verify(proof):
                    ignore_proof = self.state["ignore_nls_proof"]
                    (self.log.warning if ignore_proof else self.log.error)(f"{err_header} - SRP server proof invalid")
                    if not ignore_proof:
                        result = LoginResult.ServerProofInvalid

                if result == LoginResult.NoEmail and "register_email" in self.state:
                    await self.register_email(self.state["register_email"])

            elif result in [LoginResult.AccountClosed, LoginResult.UnknownError]:
                self.state["logon_error_code"] = \
                    packet.get_string() if status in [0x06, 0x0F] else \
                    "Account has no salt" if status == 0x48 else \
                    status

        elif packet.packet_id == SID_LOGONRESPONSE:
            # https://bnetdocs.org/packet/314/sid-logonresponse
            # This is a simple yes/no result, no more details available.
            result = LoginResult.LoggedIn if packet.get_dword() == 1 else LoginResult.UnknownError

        elif packet.packet_id == SID_LOGONRESPONSE2:
            # https://bnetdocs.org/packet/377/sid-logonresponse2
            status = packet.get_dword()
            status_lookup = {
                0x00: LoginResult.LoggedIn,
                0x01: LoginResult.NoAccount,
                0x02: LoginResult.WrongPassword,
                0x06: LoginResult.AccountClosed
            }
            result = status_lookup.get(status, LoginResult.UnknownError)

            if result == LoginResult.UnknownError:
                self.state["logon_error_code"] = status
            elif result == LoginResult.AccountClosed:
                self.state["logon_error_code"] = packet.get_string()

        else:
            self.log.error(f"Unsupported packet sent to handle_logon_result: 0x{packet.packet_id:02X}")
            return

        if result == LoginResult.LoggedIn:
            self.log.info("Login accepted.")
        else:
            self._display_logon_error(result, err_header)

        self._logged_on.set_result(result)

    async def _handle_account_create_result(self, packet):
        err_header = "Account creation failed"

        if packet.packet_id == SID_AUTH_ACCOUNTCREATE:
            # https://bnetdocs.org/packet/138/sid-auth-accountcreate
            status = packet.get_dword()
            status_lookup = {
                0x00: AccountCreationResult.AccountCreated,
                0x04: AccountCreationResult.AccountExists,
                0x07: AccountCreationResult.TooShort,
                0x08: AccountCreationResult.CharInvalid,
                0x09: AccountCreationResult.BadWord,
                0x0A: AccountCreationResult.TooFewAlphanumeric,
                0x0B: AccountCreationResult.AdjacentPunctuation,
                0x0C: AccountCreationResult.TooManyPunctuation
            }
            result = status_lookup.get(status, AccountCreationResult.AccountExists)

            if result == AccountCreationResult.AccountExists:
                self.state["account_create_error_code"] = status

        elif packet.packet_id == SID_CREATEACCOUNT:
            # https://bnetdocs.org/packet/228/sid-createaccount
            # This a simple yes/no result, no more details available.
            result = AccountCreationResult.AccountCreated if packet.get_dword() == 1 else \
                AccountCreationResult.UnknownError

        elif packet.packet_id == SID_CREATEACCOUNT2:
            # https://bnetdocs.org/packet/255/sid-createaccount2
            status = packet.get_dword()
            status_lookup = {
                0x00: AccountCreationResult.AccountCreated,
                0x01: AccountCreationResult.TooShort,
                0x02: AccountCreationResult.CharInvalid,
                0x03: AccountCreationResult.BadWord,
                0x04: AccountCreationResult.AccountExists,
                0x05: AccountCreationResult.UnknownError,
                0x06: AccountCreationResult.TooFewAlphanumeric,
                0x07: AccountCreationResult.AdjacentPunctuation,
                0x08: AccountCreationResult.TooManyPunctuation
            }
            result = status_lookup.get(status, AccountCreationResult.UnknownError)

            if result == AccountCreationResult.UnknownError:
                self.state["account_create_error_code"] = status

            if result != AccountCreationResult.AccountCreated:
                self.state["account_create_error_msg"] = packet.get_string()

        else:
            self.log.error(f"Unsupported packet sent to handle_account_create_result: 0x{packet.packet_id:02X}")
            return

        if result not in [AccountCreationResult.NoResult, AccountCreationResult.AccountCreated]:
            error_lookup = {
                AccountCreationResult.AccountExists: "Account already exists",
                AccountCreationResult.TooShort: "Name is too short",
                AccountCreationResult.CharInvalid: "Name contains invalid characters",
                AccountCreationResult.BadWord: "Name contains a banned word",
                AccountCreationResult.TooFewAlphanumeric: "Name contains too few alphanumeric characters",
                AccountCreationResult.AdjacentPunctuation: "Name contains adjacent punctuation characters",
                AccountCreationResult.TooManyPunctuation: "Name contains too many adjacent punctuation characters",
                AccountCreationResult.UnknownError: "An unknown error occurred: %0"
            }
            error = error_lookup.get(result, AccountCreationResult.UnknownError)
            if result == AccountCreationResult.UnknownError:
                error = error.replace("%0", self.state.get("account_create_error_code"))

            self.log.error(f"{err_header} - {error}")

            server_err_msg = self.state.get("account_create_error_msg")
            if server_err_msg:
                self.log.error(f"{err_header} - Additional info: {server_err_msg}")

        elif result == AccountCreationResult.AccountCreated:
            self.log.info(f"Account created: {self.state['account_name']}")

        self._account_created.set_result(result)

    async def _handle_set_email(self, packet):
        # https://bnetdocs.org/packet/223/sid-setemail
        self.log.info("An email address should be registered to this account.")
        if email := self.state.get("register_email", self.config.get("email")):
            await self.register_email(email)

    async def _handle_enter_chat(self, packet):
        # https://bnetdocs.org/packet/186/sid-enterchat
        self.state["username"] = packet.get_string()
        self.state["statstring"] = packet.get_string()
        self.state["account_name"] = packet.get_string()

        # Connection is effectively completed.
        self._entered_chat.set_result(True)
        self.log.info(f"Entered chat as '{self.state['username']}'")

        if self.state.get("bnls_host", False):
            # We're not using a pool'd BNLS connection, so we can clean it up now.
            self.bnls.disconnect()

    async def _handle_chat_event(self, packet):
        # https://bnetdocs.org/packet/307/sid-chatevent
        event = ChatEvent(packet)
        if self.chat_cb and (await self.chat_cb(self, event) is True):
            # If the callback returns TRUE then do not process the event
            self.log.debug(f"Chat event 0x{event.eid:08X} veto'd by callback")
            return

    async def _handle_flood_detected(self, packet):
        # https://bnetdocs.org/packet/242/sid-flooddetected
        self.state["flood_detected"] = True
        self.log.error("You have been disconnected for flooding.")

    async def _handle_message_box(self, packet):
        # https://bnetdocs.org/packet/346/sid-messagebox
        style = packet.get_dword()
        text = packet.get_string()
        caption = packet.get_string()

        printers = {
            0x10: self.log.error,
            0x30: self.log.warning,
            0x40: self.log.info
        }
        for flag, printer in printers.items():
            if style & flag == flag:
                printer(f"{caption} - {text}")
                return

        # Couldn't find a suitable printer, so just use info
        self.log.info(f"{caption} - {text}")
