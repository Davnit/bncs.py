
import asyncio
from datetime import datetime, timedelta
import enum
import logging
import random
import socket
import struct

from .chat import ChatEvent, ChatUser, ChatEventType
from .crev import format_crev_formula
from .hashing import KeyDecoder, hash_password, double_hash_password, NLSClient, get_verifier, xsha1, check_signature
from .packets import *
from .products import BncsProduct, LogonMechanism
from .utils import DataReader, AsyncClientBase, InvalidOperationError


TIMEOUT = 5         # Default timeout for packet operations (in seconds)


class ClientStatus(enum.IntEnum):
    Offline = 0
    Connected = 1
    Authenticated = 2       # Client authentication passed
    LoggedIn = 3            # Logged into an account
    Chatting = 4            # In the chat environment


class ClientAuthResult(enum.Enum):
    NoResult = 0
    Passed = 1
    PatchRequired = 2           # Version does not match the server
    InvalidVersion = 3          # Version not recognized by the server
    InvalidKey = 4              # CD key is invalid
    KeyInUse = 5                # Another client is using your CD key
    KeyBanned = 6               # CD key is banned from the server
    KeyWrongProduct = 7         # CD key is for a different game
    SpawnDenied = 8             # Client is not permitted to SPAWN
    CheckFailed = 9
    UnknownError = -1

    def __bool__(self):
        return self.value == 1


class AccountLoginResult(enum.Enum):
    NoResult = 0
    Success = 1
    NoAccount = 2               # Account does not exist
    UpgradeRequired = 3         # Account requires upgrade (defunct)
    WrongPassword = 4           # Password is incorrect
    AccountClosed = 5           # Account has been closed (banned) by the server
    NoEmail = 6                 # Success, but no email is registered to the account
    ServerProofInvalid = 7      # Login accepted, but the server failed SRP validation
    UnknownError = -1           # Something happened.

    def __bool__(self):
        return self.value in [1, 6]


class AccountCreateResult(enum.Enum):
    NoResult = 0
    Success = 1
    AccountAlreadyExists = 2
    TooShort = 3
    InvalidCharacter = 4
    BannedWord = 5
    TooFewAlphanumeric = 6
    AdjacentPunctuation = 7
    TooMuchPunctuation = 8
    UnknownError = -1

    def __bool__(self):
        return self.value == 1


class LadderDataSorting(enum.IntEnum):
    Rating = 0,
    Climbers = 1,
    Wins = 2,
    Games = 3


class FriendStatus(enum.IntFlag):
    Mutual = 1,
    DoNotDisturb = 2,
    Away = 4


class FriendLocation(enum.IntEnum):
    Offline = 0,
    Online = 1,
    Chatting = 2,
    PublicGame = 3,
    PrivateGame = 4
    PrivateGameMutual = 5


def convert_filetime_string(fts):
    """Converts a filetime string from a user data key to a datetime object"""
    buff = DataBuffer()
    [buff.insert_dword(int(i)) for i in reversed(fts.split(' '))]
    read = DataReader(buff.data)
    return read.get_filetime()


class _UdpTestProtocol(asyncio.DatagramProtocol):
    def __init__(self, bnet_client, server_token, udp_token):
        self.client = bnet_client
        self.tokens = (server_token, udp_token)
        self.transport = None
        self.completed = False

    def connection_made(self, tx):
        self.transport = tx
        self.client.log.debug(f"Opened UDP test socket from {tx.get_extra_info('sockname')} "
                              f"to {tx.get_extra_info('peername')}")

        # UDP header consists of only the packet ID
        # https://bnetdocs.org/packet/199/pkt-conntest2
        x09 = DataBuffer()
        x09.insert_dword(0x09)
        x09.insert_dword(self.tokens[0])
        x09.insert_dword(self.tokens[1])
        tx.sendto(x09.data)

        if self.client.debug_packets:
            self.client.log.debug(f"Sent {len(x09.data)} bytes on UDP socket - ID 0x{0x09:08X}")
            self.client.log.debug(repr(x09))

    def connection_lost(self, exc):
        self.client.log.debug("UDP test socket closed")

    def datagram_received(self, data, addr):
        if len(data) >= 4:
            reader = DataReader(data)
            pid = reader.get_dword()

            if self.client.debug_packets:
                self.client.log.debug(f"Received {len(data)} bytes on UDP socket - ID 0x{pid:08X}")
                self.client.log.debug(repr(reader))

            if pid == 0x05:
                # PKT_SERVERPING: https://bnetdocs.org/packet/165/pkt-serverping
                self.client.state["udp_code"] = code = reader.get_dword()
                if self.completed:
                    return

                self.client.log.info(f"UDP check OK - code: {code}")

                # https://bnetdocs.org/packet/406/sid-udppingresponse
                x14 = BncsPacket(SID_UDPPINGRESPONSE)
                x14.insert_dword(code)
                asyncio.create_task(self.client.send(x14))

                self.completed = True
                self.transport.close()
            else:
                self.client.log.warning(f"Received unknown UDP packet: 0x{pid:02X} with {len(data)} bytes of data")
        else:
            self.client.log.warning(f"Received {len(data)} bytes of unknown UDP data from {addr}")

    def error_received(self, exc):
        self.client.log.error(f"UDP Error: {exc}")


class BnetClient(AsyncClientBase):
    def __init__(self, *, bnls_client=None, logger=None, config=None):
        logger = logger or logging.getLogger("BNCS")
        AsyncClientBase.__init__(self, BncsReader, logger=logger)

        self.config = {
            "server": "useast.battle.net",
            "port": 6112,

            "language": ["ENU", "enUS"],
            "country": ["USA", "United States", "1"],
            "locale": 1033,                     # English US

            "platform": "IX86",                 # Intel x86
            "product": "DRTL",                  # Diablo 1 Retail
            "udp_code": "bnet",                 # Spoofed UDP code
            "keep_alive_interval": 480          # Time between keep-alive messages (seconds)
        }
        if config:
            self.config.update(config)

        self.bnls = bnls_client

        self.packet_handlers.update({
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
            SID_CREATEACCOUNT: self._handle_account_create_result,
            SID_CDKEY: self._handle_auth_result,
            SID_CHANGEPASSWORD: self._handle_logon_result,
            SID_CDKEY2: self._handle_auth_result,
            SID_LOGONRESPONSE2: self._handle_logon_result,
            SID_CREATEACCOUNT2: self._handle_account_create_result,
            SID_OPTIONALWORK: self._handle_extra_work,
            SID_REQUIREDWORK: self._handle_extra_work,
            SID_AUTH_INFO: self._handle_auth_challenge,
            SID_AUTH_CHECK: self._handle_auth_result,
            SID_AUTH_ACCOUNTCREATE: self._handle_account_create_result,
            SID_AUTH_ACCOUNTLOGON: self._handle_logon_challenge,
            SID_AUTH_ACCOUNTLOGONPROOF: self._handle_logon_result,
            SID_AUTH_ACCOUNTCHANGE: self._handle_logon_challenge,
            SID_AUTH_ACCOUNTCHANGEPROOF: self._handle_logon_result,
            SID_SETEMAIL: self._handle_set_email,
            SID_WARDEN: self._handle_warden,
            SID_FRIENDSUPDATE: self._handle_friend_update,
            SID_FRIENDSADD: self._handle_friend_update,
            SID_FRIENDSREMOVE: self._handle_friend_update,
            SID_FRIENDSPOSITION: self._handle_friend_update
        })

        # Futures for multi-packet processes
        self._client_auth_fut = None
        self._account_login_fut = None
        self._account_create_fut = None
        self._account_change_fut = None
        self._enter_chat_fut = None

        self.state = {
            "cookies": [],
            "status": ClientStatus.Offline
        }

    @property
    def channel(self):
        return self.state.get("channel")

    @property
    def channels(self):
        return self.state.get("channels", [])

    @property
    def cookies(self):
        return self.state["cookies"]

    @property
    def friends(self):
        return self.state.get("friends", [])

    @property
    def status(self):
        return self.state["status"]

    @property
    def username(self):
        return self.state.get("username")

    @property
    def users(self):
        return self.state.get("users", [])

    async def _run_udp_test(self, server_token, udp_token):
        if self.state.get("check_udp", True):
            self.log.debug("Performing UDP test...")

            loop = asyncio.get_event_loop()
            endpoint = self._writer.get_extra_info('peername')
            coro = loop.create_datagram_endpoint(lambda: _UdpTestProtocol(self, server_token, udp_token),
                                                 remote_addr=endpoint, family=socket.AF_INET)
            try:
                await asyncio.wait_for(coro, timeout=1)
                return True
            except asyncio.TimeoutError:
                self.log.debug("UDP test connection timed out")
                return False
        else:
            self.log.debug("UDP test skipped")

    def _get_login_mechanism(self, override=None):
        if override is not None:
            return override

        if (mechanism := self.state["logon_method"]) == LogonMechanism.New:
            logon_type = self.state.get("logon_type", 2)
            return LogonMechanism.New if logon_type in [1, 2] else LogonMechanism.Old
        return mechanism

    def get_cookie(self):
        i = 1
        while i in self.cookies:
            i += 1
        self.cookies.append(i)
        return i

    def get_user(self, username):
        for user in self.users:
            if user.name.lower() == username.lower():
                return user

    def check_config(self, key, override=None, default=None, require=True):
        value = self.config.get(key, default) if override is None else override
        if value is None and require:
            raise ValueError(f"missing required config paramter: {key}")
        return value

    async def connect(self, host=None, port=None):
        host = host or self.config["server"]
        port = port or self.config["port"]
        if await super().connect(host, port):
            self.state["status"] = ClientStatus.Connected

            # Send the protocol selection byte (0x1 - BNCS)
            self._writer.write(b'\x01')

    def disconnect(self, reason=None):
        hard_futures = [self._client_auth_fut, self._account_login_fut, self._account_create_fut,
                        self._account_change_fut, self._enter_chat_fut]

        for future in hard_futures:
            if future and not future.done():
                future.cancel()

        super().disconnect(reason)

    async def wait_closed(self):
        hard_futures = [self._client_auth_fut, self._account_login_fut, self._account_create_fut,
                        self._account_change_fut, self._enter_chat_fut]
        await asyncio.gather(*filter(None, hard_futures), return_exceptions=True)
        await super().wait_closed()

    async def keep_alive(self):
        while self.connected:
            await asyncio.sleep(self.config["keep_alive_interval"])
            await self.send(BncsPacket(SID_NULL))

    async def authenticate(self, product=None, keys=None, timeout=TIMEOUT, **options):
        """
            Authenticates the client to Battle.net and returns the status of the operation.

            Required parameters: (can be set in config)
                - product: 4-digit str product code identifying the emulated client (ex: 'D2DV')
                - keys: list[str] of product/CD keys the client should register

            Supported options:
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
        if self.status != ClientStatus.Connected:
            msg = 'not connected' if self.status < ClientStatus.Connected else 'already authenticated'
            raise InvalidOperationError(f"{err_header} - client {msg}")

        # Valid product must be selected
        product = self.state["product"] = BncsProduct.get(product or self.config.get("product"))
        if product is None:
            raise InvalidOperationError(f"{err_header} - missing required config parameter: product")

        # If the product requires CD keys, make sure we have them and they are valid.
        self.state["product_keys"] = []
        self.state.pop("crev_errored_key_index", 1)
        keys_needed = len(product.required_keys)
        if keys_needed > 0:
            product_keys = keys or self.config.get("keys", [])

            if len(product_keys) < keys_needed:
                raise InvalidOperationError(f"{err_header} - "
                                            f"missing {keys_needed - len(product_keys)} required product keys")

            # Validate the keys we do have
            for k_idx in range(len(product_keys)):
                try:
                    key = KeyDecoder.get(product_keys[k_idx])
                    if not key.decode():
                        raise ValueError()
                    self.state["product_keys"].append(key)
                except ValueError:
                    self.log.error(f"{err_header} - key #{k_idx + 1} is invalid (decode failed)")
                    self.state["crev_errored_key_index"] = k_idx
                    return ClientAuthResult.InvalidKey

        # We just need a version byte to request a challenge
        verbyte = self.state["verbyte"] = options.get("verbyte", self.config.get("verbyte"))
        if verbyte is None:
            if not self.bnls:
                raise InvalidOperationError(f"{err_header} - missing verbyte and no BNLS client")

            self.state["verbyte"] = verbyte = await self.bnls.request_version_byte(product.code)

        # Determine which packet sequence to use
        mechanism = options.get("logon_method", self.config.get("logon_method", product.logon_mechanism))

        # Save some options for later
        self.state["platform"] = options.get("platform", self.config["platform"])
        self.state["check_udp"] = options.get("udp_check", self.config.get("udp_check", product.uses_udp))
        self.state["key_owner"] = options.get("key_owner", self.config.get("key_owner", "bncs.py client"))
        self.state["use_spawn"] = options.get("spawn", self.config.get("spawn", False))
        self.state["client_token"] = random.getrandbits(32)
        self.state["logon_method"] = mechanism
        self.state.pop("logon_type", 1)
        self.state.pop("patch_file", 1)

        self._client_auth_fut = asyncio.get_event_loop().create_future()
        self.log.info(f"Authenticating as '{self.state['platform']}/{product.code}' client "
                      f"using '{mechanism.name.lower()}' auth system")

        # Build some values
        s_time, l_time = datetime.utcnow(), datetime.now()
        tz_bias = options.get("tz_bias", int((s_time - l_time).total_seconds() / 60))
        country_info = options.get("country", self.config["country"])
        language = options.get("language", self.config["language"])
        locale = options.get("locale", self.config["locale"])

        self.log.debug(f"Client auth additional params - verbyte: 0x{verbyte:02X}, tz: {tz_bias}s, "
                       f"ip: {self.state['local_ip']}, locale: 0x{locale:02X}, lang: {language}, ci: {country_info}")

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
            pak.insert_dword(0)                         # Protocol ID, has only ever been 0
            pak.insert_dword(self.state["platform"])
            pak.insert_dword(self.state["product"].code)
            pak.insert_dword(self.state["verbyte"])
            pak.insert_dword(language[1] if isinstance(language, list) else language)
            pak.insert_ipv4(self.state["local_ip"])
            pak.insert_dword(tz_bias)
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
            x12.insert_dword(tz_bias)
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

        result = await asyncio.wait_for(self._client_auth_fut, timeout)
        if result == ClientAuthResult.Passed:
            self.state["status"] = ClientStatus.Authenticated
        return result

    async def login(self, username=None, password=None, timeout=TIMEOUT, **options):
        """
            Logs into a classic Battle.net account and returns the status of the operation.
            This operation will timeout if your account is locked due to failed login attempts.

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
        if self.status != ClientStatus.Authenticated:
            msg = "not authenticated" if self.status < ClientStatus.Authenticated else "already logged in"
            raise InvalidOperationError(f"{err_header} - client {msg}")

        try:
            username = self.check_config("username", username or self.state.get("account_name"))
            password = self.check_config("password", password)
        except ValueError as ve:
            raise InvalidOperationError(f"{err_header} - {ve}")

        # Save some options
        self.state["account_name"] = username
        self.state["register_email"] = options.get("email", self.config.get("email"))
        self.state.pop("logon_error_code", 1)
        self.state.pop("logon_error_msg", 1)

        self._account_login_fut = asyncio.get_event_loop().create_future()
        mechanism = self._get_login_mechanism(options.get("logon_method"))
        logon_type = f"NLSv{self.state['logon_type']}" if mechanism == LogonMechanism.New else "OLS"
        self.log.info(f"Logging into account '{username}' using {logon_type}...")

        if mechanism in [LogonMechanism.Legacy, LogonMechanism.Old]:
            # The format for both of these packets is the same, the only difference is the response.
            # https://bnetdocs.org/packet/262/sid-logonresponse
            # https://bnetdocs.org/packet/225/sid-logonresponse2
            pak = BncsPacket(SID_LOGONRESPONSE if mechanism == LogonMechanism.Legacy else SID_LOGONRESPONSE2)
            pak.insert_dword(c_token := self.state["client_token"])
            pak.insert_dword(s_token := self.state["server_token"])
            pak.insert_raw(double_hash_password(password, c_token, s_token))
            pak.insert_string(username)
            await self.send(pak)

        elif mechanism == LogonMechanism.New:
            # Server specifies the required version in the response to SID_AUTH_INFO
            nls_version = options.get("nls_version", self.state.get("logon_type"))
            if nls_version not in [1, 2]:
                self.log.error(f"{err_header} - unsupported NLS version: {nls_version}")
                return AccountLoginResult.NoResult

            nls = self.state["nls_client"] = NLSClient(username, password, nls_version)
            self.state["ignore_nls_proof"] = options.get("ignore_proof", self.config.get("ignore_nls_proof", False))

            # https://bnetdocs.org/packet/323/sid-auth-accountlogon
            x53 = BncsPacket(SID_AUTH_ACCOUNTLOGON)
            x53.insert_raw(nls.get_client_key())
            x53.insert_string(username)
            await self.send(x53)

        else:
            raise InvalidOperationError(f"login mechanism not supported: {mechanism}")

        try:
            result = await asyncio.wait_for(self._account_login_fut, timeout)
            if result in [AccountLoginResult.Success, AccountLoginResult.NoEmail,
                          AccountLoginResult.ServerProofInvalid]:
                self.state["status"] = ClientStatus.LoggedIn
                self.state.pop("nls_client", 1)
            return result
        except asyncio.TimeoutError:
            self.log.error(f"{err_header} - timed out, your account may be temporarily locked")
            self.state["logon_error_code"] = -1
            self.state["logon_error_msg"] = "Request timed out"
            return AccountLoginResult.UnknownError

    async def create_account(self, username=None, password=None, timeout=TIMEOUT, **options):
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
        if self.status != ClientStatus.Authenticated:
            msg = "not authenticated" if self.status < ClientStatus.Authenticated else "already logged in"
            raise InvalidOperationError(f"{err_header} - client {msg}")

        try:
            username = self.check_config("username", username or self.state.get("account_name"))
            password = self.check_config("password", password)
        except ValueError as ve:
            raise InvalidOperationError(f"{err_header} - {ve}")

        self._account_create_fut = asyncio.get_event_loop().create_future()
        mechanism = self._get_login_mechanism(options.get("logon_method"))
        logon_type = f"NLSv{self.state['logon_type']}" if mechanism == LogonMechanism.New else "OLS"
        self.state["account_name"] = username
        self.log.info(f"Creating account '{username}' using {logon_type}...")

        if mechanism in [LogonMechanism.Legacy, LogonMechanism.Old]:
            # The format for both of these packets is the same, the only difference is the response.
            # https://bnetdocs.org/packet/305/sid-createaccount
            # https://bnetdocs.org/packet/226/sid-createaccount2
            pak = BncsPacket(SID_CREATEACCOUNT if mechanism == LogonMechanism.Legacy else SID_CREATEACCOUNT2)
            pak.insert_raw(hash_password(password))
            pak.insert_string(username)
            await self.send(pak)

        elif mechanism == LogonMechanism.New:
            nls_version = options.get("nls_version", self.state.get("logon_type"))
            if nls_version not in [1, 2]:
                raise InvalidOperationError(f"{err_header} - unsupported NLS version: {nls_version}")

            salt, verifier = get_verifier(username, password, nls_version)

            # https://bnetdocs.org/packet/274/sid-auth-accountcreate
            x52 = BncsPacket(SID_AUTH_ACCOUNTCREATE)
            x52.insert_raw(salt)
            x52.insert_raw(verifier)
            x52.insert_string(username)
            await self.send(x52)

        else:
            raise InvalidOperationError(f"{err_header} - account creation mechanism not supported: {mechanism}")

        return await asyncio.wait_for(self._account_create_fut, timeout)

    async def change_password(self, new_password, old_password=None, account=None, timeout=TIMEOUT, **options):
        err_header = "Password change failed"
        if self.status != ClientStatus.Authenticated:
            msg = "not authenticated" if self.status < ClientStatus.Authenticated else "already logged in"
            raise InvalidOperationError(f"{err_header} - client {msg}")

        try:
            account = self.check_config("username", account or self.state.get("account_name"))
            old_password = self.check_config("password", old_password)
            c_token = self.state["client_token"]
            s_token = self.state["server_token"]
        except ValueError as ve:
            raise InvalidOperationError(f"{err_header} - {ve}")
        except KeyError:
            raise InvalidOperationError(f"{err_header} - missing needed client/server tokens")

        self._account_change_fut = asyncio.get_event_loop().create_future()
        mechanism = self._get_login_mechanism(options.get("logon_method"))
        logon_type = f"NLSv{self.state['logon_type']}" if mechanism == LogonMechanism.New else "OLS"
        self.state["account_name"] = account
        self.log.info(f"Changing password for account '{account}' using {logon_type}...")

        if mechanism in [LogonMechanism.Legacy, LogonMechanism.Old]:
            # Both LLS and OLS use the same packets
            # https://bnetdocs.org/packet/338/sid-changepassword
            x31 = BncsPacket(SID_CHANGEPASSWORD)
            x31.insert_dword(c_token)
            x31.insert_dword(s_token)
            x31.insert_raw(double_hash_password(old_password, c_token, s_token))
            x31.insert_raw(hash_password(new_password))
            x31.insert_string(account)
            await self.send(x31)

        elif mechanism == LogonMechanism.New:
            nls_version = options.get("nls_version", self.state.get("logon_type"))
            if nls_version not in [1, 2]:
                raise InvalidOperationError(f"{err_header} - unsupported NLS version: {nls_version}")

            nls = self.state["nls_client"] = NLSClient(account, old_password, nls_version)
            self.state["ignore_nls_proof"] = options.get("ignore_proof", self.config.get("ignore_nls_proof", False))

            # https://bnetdocs.org/packet/108/sid-auth-accountchange
            x55 = BncsPacket(SID_AUTH_ACCOUNTCHANGE)
            x55.insert_raw(nls.get_client_key())
            x55.insert_string(account)
            if await self.send(x55):
                self.state["nls_change_params"] = get_verifier(account, new_password, nls_version)

        else:
            raise InvalidOperationError(f"{err_header} - password change mechanism not supported: {mechanism}")

        try:
            return await asyncio.wait_for(self._account_change_fut, timeout)
        finally:
            if "nls_change_params" in self.state:
                del self.state["nls_change_params"]

    async def register_email(self, email=None):
        err_header = "Email registration failed"
        if self.status < ClientStatus.LoggedIn:
            raise InvalidOperationError(f"{err_header} - client not logged in")

        email = email or self.config.get("email")
        if email is None:
            raise InvalidOperationError(f"{err_header} - missing required config parameter: email")

        x59 = BncsPacket(SID_SETEMAIL)
        x59.insert_string(email)
        await self.send(x59)

    async def reset_password(self, email=None, account=None):
        err_header = "Unable to reset password"
        if self.status != ClientStatus.Authenticated:
            msg = "not authenticated" if self.status < ClientStatus.Authenticated else "already logged in"
            raise InvalidOperationError(f"{err_header} - client {msg}")

        try:
            account = self.check_config("username", account or self.state.get("account_name"))
            email = self.check_config("email", email)
        except ValueError as ve:
            raise InvalidOperationError(f"{err_header} - {ve}")

        # https://bnetdocs.org/packet/405/sid-resetpassword
        x5a = BncsPacket(SID_RESETPASSWORD)
        x5a.insert_string(account)
        x5a.insert_string(email)
        await self.send(x5a)

    async def change_email(self, new_email, old_email=None, account=None):
        err_header = "Unable to change email"
        if self.status != ClientStatus.Authenticated:
            msg = "not authenticated" if self.status < ClientStatus.Authenticated else "already logged in"
            raise InvalidOperationError(f"{err_header} - client {msg}")

        try:
            account = self.check_config("username", account or self.state.get("account_name"))
            old_email = self.check_config("email", old_email)
        except ValueError as ve:
            raise InvalidOperationError(f"{err_header} - {ve}")

        # https://bnetdocs.org/packet/105/sid-changeemail
        x5b = BncsPacket(SID_CHANGEEMAIL)
        x5b.insert_string(account)
        x5b.insert_string(old_email)
        x5b.insert_string(new_email)
        await self.send(x5b)

    async def enter_chat(self, timeout=TIMEOUT, **options):
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
        if self.status != ClientStatus.LoggedIn:
            msg = "not logged in" if self.status < ClientStatus.LoggedIn else "already in chat"
            raise InvalidOperationError(f"{err_header} - client {msg}")

        product = BncsProduct.get(options.get("product")) if "product" in options else self.state["product"]
        home_channel = options.get("home_channel", self.config.get("home_channel", product.home_channel))

        # Uses 'force join' flag if a home channel is explicitly set, otherwise 'first join'
        home_join_flags = 0x02 if ("home_channel" in options or "home_channel" in self.config) else product.home_flags

        self._enter_chat_fut = asyncio.get_event_loop().create_future()

        # https://bnetdocs.org/packet/145/sid-enterchat
        x0a = BncsPacket(SID_ENTERCHAT)
        x0a.insert_string(options.get("username", self.state["account_name"]))
        x0a.insert_string(options.get("statstring", self.state.get("statstring", self.config.get("statstring", ""))))
        await self.send(x0a)

        self.state.update({
            "channel": None, "users": [], "friends": [], "channels": []
        })
        self.state["channels"] = await self.request_channel_list(product.code)
        await self.join_channel(home_channel, home_join_flags)

        return await asyncio.wait_for(self._enter_chat_fut, timeout)

    async def send_ping(self, cookie=0):
        # C->S https://bnetdocs.org/packet/268/sid-ping
        x25 = BncsPacket(SID_PING)
        x25.insert_dword(cookie)
        await self.send(x25)

    async def request_channel_list(self, product=None, timeout=TIMEOUT):
        product = product or self.state["product"]
        if isinstance(product, BncsProduct):
            product = product.code

        # https://bnetdocs.org/packet/374/sid-getchannellist
        x0b = BncsPacket(SID_GETCHANNELLIST)
        x0b.insert_dword(product)
        await self.send(x0b)

        # https://bnetdocs.org/packet/363/sid-getchannellist
        channels = []
        reply = await self.wait_for_packet(SID_GETCHANNELLIST, timeout=timeout)
        while len(channel := reply.get_string()) > 0:
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
        await self.send(x0e)

    async def get_icon_data(self, timeout=TIMEOUT):
        err_header = "Unable to retrieve icon data"
        if self.status not in [ClientStatus.Authenticated, ClientStatus.LoggedIn]:
            msg = "not authenticated" if self.status < ClientStatus.Authenticated else "already in chat"
            raise InvalidOperationError(f"{err_header} - client {msg}")

        # https://bnetdocs.org/packet/121/sid-geticondata
        await self.send(BncsPacket(SID_GETICONDATA))

        # https://bnetdocs.org/packet/120/sid-geticondata
        reply = await self.wait_for_packet(SID_GETICONDATA, timeout=timeout)
        ft = reply.get_filetime()
        name = reply.get_string()
        self.log.debug(f"Icon file: {name} ({ft})")
        return name, ft

    async def get_filetime(self, file, timeout=TIMEOUT):
        # https://bnetdocs.org/packet/382/sid-getfiletime
        x33 = BncsPacket(SID_GETFILETIME)
        x33.insert_dword(cookie := self.get_cookie())
        x33.insert_dword(0)
        x33.insert_string(file)
        await self.send(x33)

        def matcher(p):
            if p.get_dword() == cookie:
                p.get_raw(12)       # skip unknown and filetime
                return p.get_string() == file
            return False

        try:
            # https://bnetdocs.org/packet/195/sid-getfiletime
            reply = await self.wait_for_packet(SID_GETFILETIME, matcher, timeout)
            reply.get_raw(8)    # Skip request ID and null unknown (req already verified in matcher)
            return reply.get_filetime()
        finally:
            self.cookies.remove(cookie)

    def _validate_user_data_request(self, accounts, keys, ignore, req_type):
        err_header = "User data request failed"
        if self.status < ClientStatus.Authenticated:
            raise InvalidOperationError(f"{err_header} - client not authenticated")

        accounts = [accounts] if not isinstance(accounts, list) else accounts
        keys = [keys] if not isinstance(keys, list) else keys

        if not ignore:
            # These limits are imposed by official servers
            blocked_header = "User data request blocked"

            if len(accounts) > 1:
                raise InvalidOperationError(f"{blocked_header} - only 1 account can be {req_type} at a time")
            elif len(keys) >= 32:
                raise InvalidOperationError(f"{blocked_header} - cannot {req_type} 32 or more keys at a time")
            elif req_type == 'set' and accounts[0].lower() != self.state.get("account_name", "").lower():
                raise InvalidOperationError(f"{blocked_header} - you can only modify your own account")

        return accounts, keys

    async def get_user_data(self, accounts, keys, ignore_limits=False, timeout=TIMEOUT):
        accounts, keys = self._validate_user_data_request(accounts, keys, ignore_limits, 'request')
        cookie = self.get_cookie()
        self.log.debug(f"Requesting {len(keys)} user data keys for {len(accounts)} accounts (cookie: {cookie})")

        # https://bnetdocs.org/packet/358/sid-readuserdata
        x26 = BncsPacket(SID_READUSERDATA)
        x26.insert_dword(len(accounts))
        x26.insert_dword(len(keys))
        x26.insert_dword(cookie)
        for account in accounts:
            x26.insert_string(account)
        for key in keys:
            x26.insert_string(key)
        await self.send(x26)

        def matcher(p):
            p.position += 8    # Skip numbers
            return p.get_dword() == cookie

        try:
            reply = await self.wait_for_packet(SID_READUSERDATA, matcher, timeout)
        finally:
            self.cookies.remove(cookie)

        # https://bnetdocs.org/packet/112/sid-readuserdata
        num_accounts = reply.get_dword()
        num_keys = reply.get_dword()

        # Verify the response is sensical
        if num_accounts != len(accounts) or num_keys != len(keys):
            self.log.warning(f"User data request failed - server returned mismatched response")
            return {}

        reply.get_dword()       # Skip request ID verified in matcher

        data = {}
        for account in accounts:
            data[account] = {}
            for key in keys:
                data[account][key] = reply.get_string()

        return data

    async def set_user_data(self, accounts, keys, values, ignore_limits=False):
        accounts, keys = self._validate_user_data_request(accounts, keys, ignore_limits, 'set')
        self.log.debug(f"Requesting change of {len(keys)} user keys for {len(accounts)} accounts...")

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

    async def request_profile(self, account=None, timeout=TIMEOUT):
        account = account or self.state["account_name"]
        keys = ["Profile\\Age", "Profile\\Sex", "Profile\\Location", "Profile\\Description"]
        data = (await self.get_user_data(account, keys, timeout=timeout)).get(account)
        return {k.split('\\')[1]: v for k, v in data.items()}

    async def set_profile(self, location=None, description=None, sex=None, age=None):
        data = {
            "Profile\\Location": location,
            "Profile\\Description": description,
            "Profile\\Sex": sex,
            "Profile\\Age": age
        }

        # Only send fields that have new values. None = no change
        keys, values = [], []
        for key, value in data.items():
            if value is not None:
                keys.append(key)
                values.append(value)

        return await self.set_user_data(self.state["account_name"], keys, values)

    async def request_account_keys(self, timeout=TIMEOUT):
        account = self.state["account_name"]
        keys = ["System\\Account Created", "System\\Last Logon", "System\\Last Logoff", "System\\Time Logged"]
        data = (await self.get_user_data(account, keys, timeout=timeout)).get(account)
        data = {k.split('\\')[1]: v for k, v in data.items() if v}
        return {k: convert_filetime_string(v) if ' ' in v else timedelta(seconds=int(v)) for k, v in data.items()}

    async def leave_chat(self):
        # Client must be in chat
        if self.status < ClientStatus.Chatting:
            raise InvalidOperationError("Unable to leave chat - client not in chat")

        # https://bnetdocs.org/packet/339/sid-leavechat
        await self.send(BncsPacket(SID_LEAVECHAT))

    async def check_ad(self, last_ad=None, platform=None, product=None, time=None, timeout=TIMEOUT):
        platform = platform or self.state.get("platform", "IX86")
        product = BncsProduct.get(product or self.state.get("product", self.config["product"]))
        last_ad = self.state.get("ad_banner", {}).get("id", 0) if last_ad is None else last_ad

        # https://bnetdocs.org/packet/250/sid-checkad
        x15 = BncsPacket(SID_CHECKAD)
        x15.insert_dword(platform)
        x15.insert_dword(product.code)
        x15.insert_dword(last_ad)
        x15.insert_dword(int(datetime.now().timestamp()) if time is None else time)
        await self.send(x15)

        self.log.debug(f"Requesting banner ad data for '{platform}/{product.code}' (last: {last_ad})")

        try:
            # https://bnetdocs.org/packet/272/sid-checkad
            reply = await self.wait_for_packet(SID_CHECKAD, timeout=timeout)
            ad_info = {
                "id": reply.get_dword(),
                "extension": reply.get_dword(as_str=True),
                "filetime": reply.get_filetime(),
                "filename": reply.get_string(),
                "link_url": reply.get_string()
            }
            return ad_info, True
        except asyncio.TimeoutError:
            # A timeout is actually expected with this request when no new ads are available
            self.log.debug(f"Banner ad request for '{platform}/{product.code}' timed out")
            return self.state.get("ad_banner"), False

    async def get_news_info(self, start=None, assume_order=True, timeout=TIMEOUT):
        """Requests news from the server starting from the specified `start` time.

            Returns a tuple containing a list of news entries and the motd (news, motd). Each news
                item is itself a tuple of (timestamp, content). If `assume_order` is True then this
                function will return after the MotD is received, otherwise it will wait until timeout.
        """
        if timeout is None and assume_order is False:
            raise ValueError("News timeout cannot be None when assume_order is False")

        if start is None:
            start = self.state.get("last_news_timestamp", 0)
        elif isinstance(start, datetime):
            start = start.timestamp()

        self.log.debug(f"Requesting news entries since {datetime.utcfromtimestamp(start).isoformat()}")
        entries = []
        motd = []

        async def handle_news_packet(packet):
            # https://bnetdocs.org/packet/101/sid-news-info
            count = packet.get_byte()
            packet.position += 12       # Skip 3 DWORDs
            for _ in range(count):
                timestamp = packet.get_dword()
                content = packet.get_string()
                if timestamp == 0:
                    motd.append(content)
                else:
                    entries.append((timestamp, content))

        async def run_news_request():
            # https://bnetdocs.org/packet/247/sid-news-info
            x46 = BncsPacket(SID_NEWS_INFO)
            x46.insert_dword(start)
            await self.send(x46)

            while assume_order is False or len(motd) == 0:
                await asyncio.sleep(0)

        try:
            self.packet_handlers[SID_NEWS_INFO] = handle_news_packet
            await asyncio.wait_for(run_news_request(), timeout)
        finally:
            del self.packet_handlers[SID_NEWS_INFO]

        latest = max(entries, key=lambda e: e[0])
        if latest > self.state.get("last_news_timestamp", 0):
            self.state["last_news_timestamp"] = latest

        self.log.debug(f"Received {len(entries)} news entries and {len(motd)} MotD")
        return sorted(entries, key=lambda e: e[0]), motd

    async def get_ladder_data(self, sorting=None, start=0, count=20, league=1, product=None, timeout=TIMEOUT):
        product = self.state["product"] if product is None else BncsProduct.get(product)

        # https://bnetdocs.org/packet/298/sid-getladderdata
        x2e = BncsPacket(SID_GETLADDERDATA)
        x2e.insert_dword(product.code)
        x2e.insert_dword(league)
        x2e.insert_dword(sorting)
        x2e.insert_dword(start)
        x2e.insert_dword(count)
        await self.send(x2e)

        def matcher(p):
            return p.data[4:20] == x2e.data[0:16]

        self.log.debug(f"Requesting ladder data for '{product.code}' "
                       f"(league: {league}, sorting: {sorting}, start: {start}, count: {count})")

        # https://bnetdocs.org/packet/254/sid-getladderdata
        reply = await self.wait_for_packet(SID_GETLADDERDATA, matcher, timeout)
        reply.get_raw(16)
        returned = reply.get_dword()
        ladder = []
        for _ in range(returned):
            ladder.append({
                "wins": reply.get_dword(), "losses": reply.get_dword(), "disconnects": reply.get_dword(),
                "rating": reply.get_dword(), "rank": reply.get_dword(), "official_wins": reply.get_dword(),
                "official_losses": reply.get_dword(), "official_disconnects": reply.get_dword(),
                "official_rating": reply.get_dword(), "unknown1": reply.get_dword(), "official_rank": reply.get_dword(),
                "unknown2": reply.get_dword(), "unknown3": reply.get_dword(), "highest_rating": reply.get_dword(),
                "unknown4": reply.get_dword(), "season": reply.get_dword(), "last_game_time": reply.get_filetime(),
                "official_last_game_time": reply.get_filetime(), "name": reply.get_string()
            })

        return {
            "product": product.code, "league": league, "sorting": sorting, "start": start,
            "count": count, "results": ladder
        }

    async def update_friends_list(self, timeout=TIMEOUT):
        # https://bnetdocs.org/packet/191/sid-friendslist
        await self.send(BncsPacket(SID_FRIENDSLIST))

        # https://bnetdocs.org/packet/153/sid-friendslist
        reply = await self.wait_for_packet(SID_FRIENDSLIST, timeout=timeout)

        friends = []
        count = reply.get_byte()
        for _ in range(count):
            friends.append({
                "account": reply.get_string(),
                "status": FriendStatus(reply.get_byte()),
                "location": FriendLocation(reply.get_byte()),
                "product": BncsProduct.get(reply.get_dword()),
                "location_name": reply.get_string()
            })
        self.log.debug(f"Received friends list update with {count} entries")
        self.state["friends"] = friends
        return friends

    async def _handle_null(self, packet):
        pass

    async def _handle_ping(self, packet):
        # S->C https://bnetdocs.org/packet/164/sid-ping
        await self.send_ping(packet.get_dword())

    async def _handle_logon_challenge_ex(self, packet):
        # https://bnetdocs.org/packet/286/sid-logonchallengeex
        self.state["udp_token"] = udp_token = packet.get_dword()
        self.state["server_token"] = server_token = packet.get_dword()
        self.log.debug(f"Server OLS auth challenge - token: {server_token}, udp: {udp_token}")
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
            logon_types = {0: "XSha1", 1: "NLSv1", 2: "NLSv2"}
            type_name = logon_types.get(logon_type, f"Unknown (0x{logon_type:08X})")

            self.state["server_token"] = s_token = packet.get_dword()
            self.state["udp_token"] = u_token = packet.get_dword()
            self.log.debug(f"Server NLS auth challenge - login: {type_name}, token: {s_token}, udp: {u_token}")
            await self._run_udp_test(s_token, u_token)

            filetime = packet.get_filetime()
            archive = packet.get_string()
            formula = packet.get_string(encoding=None)

            # Check for a server signature
            if not packet.eob():
                server_ip = self.state["remote_ip"]
                signature = packet.get_raw(128)
                if check_signature(signature, server_ip):
                    self.log.info(f"Server signature verified! (IP: {server_ip})")
                else:
                    self.log.warning(f"Server signature verification failed (IP: {server_ip})"
                                     f" - this may not be an official server")
        else:
            raise InvalidOperationError(f"Unsupported packet sent to handle_auth_challenge: 0x{packet.packet_id:02X}")

        self.log.debug(f"Versioning challenge - archive: {archive}, seed: {format_crev_formula(formula)}")
        self.state["crev_challenge"] = {
            "archive": archive,
            "timestamp": filetime,
            "formula": formula
        }

        err_header = "Client authentication failed"
        results = None
        if self.bnls:
            results = self.state["crev_results"] = \
                await self.bnls.check_version(self.state["product"].code, archive, formula, filetime)

            if not results:
                self.log.error(f"{err_header} - BNLS failed version check")
        else:
            # Local hashing still not supported
            self.log.error(f"{err_header} - local hashing is not supported.")

        if results is None or not results.check.success:
            # We have no way to continue
            self._client_auth_fut.set_result(ClientAuthResult.CheckFailed)
            self.disconnect("Check revision failed (client)")
        else:
            results = results.check
            self.log.debug(results)

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

            if self.state["use_spawn"]:
                self.log.debug("Attempting to use SPAWN")

            for k_idx in range(len(keys)):
                key = keys[k_idx]
                self.log.debug(f"Product key #{k_idx + 1}: {key.get_product_name()} "
                               f"(length: {len(key)}, public: 0x{key.public:08X})")

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
        result = ClientAuthResult.UnknownError

        if packet.packet_id == SID_REPORTVERSION:
            # https://bnetdocs.org/packet/412/sid-reportversion
            status = packet.get_dword()
            result_lookup = {
                0x00: ClientAuthResult.InvalidVersion,
                0x01: ClientAuthResult.PatchRequired,
                0x02: ClientAuthResult.Passed,
                0x03: ClientAuthResult.PatchRequired
            }
            result = result_lookup.get(status, result)

            if result == ClientAuthResult.Passed:
                keys = self.state.get("product_keys", [])
                if len(keys) == 1:
                    self.log.debug(f"Product key: {keys[0].get_product_name()} "
                                   f"(length: {len(keys[0])}, public: 0x{keys[0].public:08X})")
                    if self.state["use_spawn"]:
                        self.log.debug("Attempting to use SPAWN")

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

                elif len(keys) > 1:
                    # Too many keys, can't continue with this method (or can we?)
                    # TODO: Find out if we can use SID_CDKEY2 or SID_CDKEY3 for multi-key auth
                    raise InvalidOperationError(f"{err_header} - multi-key product used with single-key auth method")

        elif packet.packet_id == SID_AUTH_CHECK:
            # https://bnetdocs.org/packet/106/sid-auth-check
            status = packet.get_dword()
            if status == 0:
                result = ClientAuthResult.Passed

            elif status & 0x0FF == status:
                # Invalid version code
                result = ClientAuthResult.InvalidVersion

            elif status & 0x100 == 0x100:
                # Result is a versioning error
                result_lookup = {
                    0x100: ClientAuthResult.PatchRequired,
                    0x101: ClientAuthResult.InvalidVersion,
                    0x102: ClientAuthResult.PatchRequired
                }
                result = result_lookup.get(status, result)

            elif status & 0x200 == 0x200:
                # Result is a key registration error
                result_lookup = {
                    0x200: ClientAuthResult.InvalidKey,
                    0x201: ClientAuthResult.KeyInUse,
                    0x202: ClientAuthResult.KeyBanned,
                    0x203: ClientAuthResult.KeyWrongProduct
                }
                self.state["crev_errored_key_index"] = (status & 0x0F0) // 16
                result = result_lookup.get(status & ~0x0F0, result)

        elif packet.packet_id in [SID_CDKEY, SID_CDKEY2]:
            # Response is the same for both SID_CDKEY and SID_CDKEY2
            # SID_CDKEY: https://bnetdocs.org/packet/188/sid-cdkey
            # SID_CDKEY2: https://bnetdocs.org/packet/184/sid-cdkey2
            status = packet.get_dword()
            result_lookup = {
                0x01: ClientAuthResult.Passed,
                0x02: ClientAuthResult.InvalidKey,
                0x03: ClientAuthResult.KeyWrongProduct,
                0x04: ClientAuthResult.KeyBanned,
                0x05: ClientAuthResult.KeyInUse
            }
            result = result_lookup.get(status, result)
            if result != ClientAuthResult.Passed:
                self.state["crev_errored_key_index"] = 0
        else:
            raise InvalidOperationError(f"Unsupported packet sent to handle_auth_result: 0x{packet.packet_id:02X}")

        if result != ClientAuthResult.Passed:
            if result == ClientAuthResult.KeyInUse:
                owner = self.state["key_owner"] = packet.get_string()
                if self.state["use_spawm"] and owner in ["TOO MANY SPAWNS", "NO SPAWNING"]:
                    result = ClientAuthResult.SpawnDenied
            elif result == ClientAuthResult.PatchNeeded:
                self.state["patch_file"] = packet.get_string()

            key_number = self.state.get("crev_errored_key_index", -1) + 1
            error_lookup = {
                ClientAuthResult.PatchRequired: f"patch required ({self.state.get('patch_file', 'no patch')})",
                ClientAuthResult.InvalidVersion: "invalid game version",
                ClientAuthResult.InvalidKey: f"product key #{key_number} invalid",
                ClientAuthResult.KeyInUse: f"product key #{key_number} in use by '{self.state['key_owner']}'",
                ClientAuthResult.KeyBanned: f"product key #{key_number} is banned",
                ClientAuthResult.KeyWrongProduct: f"product key #{key_number} is for another game",
                ClientAuthResult.SpawnDenied: f"product key #{key_number} denied spawn ({self.state['key_owner']})"
            }
            self.log.error(f"{err_header} - {error_lookup.get(result, 'Unknown error')}")
        else:
            self.log.info(f"Client completed identification as {self.state['product'].name}")

        self._client_auth_fut.set_result(result)
        return result

    def _display_logon_error(self, result, header):
        if result in [AccountLoginResult.NoResult, AccountLoginResult.Success]:
            return

        error_lookup = {
            AccountLoginResult.NoAccount: "Account does not exist",
            AccountLoginResult.UpgradeRequired: "Account must be upgraded",
            AccountLoginResult.WrongPassword: "Incorrect password",
            AccountLoginResult.AccountClosed: "Account is closed (%0)",
            AccountLoginResult.NoEmail: "Server suggests email registration for your account",
            AccountLoginResult.UnknownError: "An unknown error occurred: %0",
            AccountLoginResult.ServerProofInvalid: "The server failed to prove it knows your password"
        }
        error = error_lookup.get(result, AccountLoginResult.UnknownError)
        if result in [AccountLoginResult.AccountClosed, AccountLoginResult.UnknownError]:
            error = error.replace("%0", str(self.state.get("logon_error_msg")))

        if result == AccountLoginResult.NoEmail:
            self.log.info(error)
        else:
            self.log.error(f"{header} - {error}")

    async def _handle_logon_challenge(self, packet):
        result = AccountLoginResult.NoResult

        if packet.packet_id in [SID_AUTH_ACCOUNTLOGON, SID_AUTH_ACCOUNTCHANGE]:
            # Both messages have the same format, just with different functions
            # https://bnetdocs.org/packet/210/sid-auth-accountlogon
            # https://bnetdocs.org/packet/407/sid-auth-accountchange
            status = packet.get_dword()
            reply_id = packet.packet_id + 1
            err_header = ("Account login" if packet.packet_id == SID_AUTH_ACCOUNTLOGON else "Password change")

            if status == 0x00:      # Accepted, requires proof
                salt = packet.get_raw(32)
                server_key = packet.get_raw(32)
                if salt == 0:
                    self.log.debug(f"NLS account salt returned NULL")

                nls = self.state["nls_client"]
                proof = nls.process_challenge(salt, server_key)
                if not proof:
                    self.log.error(f"{err_header} failed - SRP client proof calculation failed")
                    result = AccountLoginResult.UnknownError
                else:
                    # These packets start off the same, but the change version has some additional fields
                    # https://bnetdocs.org/packet/378/sid-auth-accountlogonproof
                    # https://bnetdocs.org/packet/270/sid-auth-accountchangeproof
                    pak = BncsPacket(reply_id)
                    pak.insert_raw(proof)

                    if reply_id == SID_AUTH_ACCOUNTCHANGEPROOF:
                        new_salt, verifier = self.state["nls_change_params"]
                        pak.insert_raw(new_salt)
                        pak.insert_raw(verifier)

                    await self.send(pak)
            else:
                status_lookup = {
                    0x01: AccountLoginResult.NoAccount,
                    0x05: AccountLoginResult.UpgradeRequired
                }
                result = status_lookup.get(status, AccountLoginResult.UnknownError)

            if result == AccountLoginResult.UnknownError:
                self.state["logon_error_code"] = status

        else:
            self.log.error(f"Unsupported packet sent to handle_logon_challenge: 0x{packet.packet_id:02X}")
            return

        if result != AccountLoginResult.NoResult:
            self._display_logon_error(result, err_header)
            self._account_login_fut.set_result(result)
        return result

    async def _handle_logon_result(self, packet):
        result = AccountLoginResult.UnknownError

        if packet.packet_id in [SID_AUTH_ACCOUNTLOGONPROOF, SID_AUTH_ACCOUNTCHANGEPROOF]:
            # These packets have the same format, just with different functions.
            # https://bnetdocs.org/packet/330/sid-auth-accountlogonproof
            # https://bnetdocs.org/packet/379/sid-auth-accountchangeproof
            status = packet.get_dword()
            status_lookup = {
                0x00: AccountLoginResult.Success,
                0x02: AccountLoginResult.WrongPassword,
                0x06: AccountLoginResult.AccountClosed,
                0x0E: AccountLoginResult.NoEmail,
                0x0F: AccountLoginResult.UnknownError,
                0x48: AccountLoginResult.UnknownError
            }
            result = status_lookup.get(status, result)

            proof = packet.get_raw(20)      # Read even if we know it failed (error comes after)

            if result in [AccountLoginResult.Success, AccountLoginResult.NoEmail]:
                nls = self.state["nls_client"]
                if not nls.verify(proof):
                    ignore_proof = self.state["ignore_nls_proof"]
                    printer = (self.log.warning if ignore_proof else self.log.error)
                    printer("Server accepted password but gave invalid NLS proof")
                    if not ignore_proof:
                        result = AccountLoginResult.ServerProofInvalid

                if result == AccountLoginResult.NoEmail and "register_email" in self.state:
                    await self.register_email(self.state["register_email"])

            elif result in [AccountLoginResult.AccountClosed, AccountLoginResult.UnknownError]:
                self.state["logon_error_code"] = status
                self.state["logon_error_msg"] = \
                    packet.get_string() if status in [0x06, 0x0F] else \
                    "Account has no salt" if status == 0x48 else None

        elif packet.packet_id == SID_LOGONRESPONSE:
            # https://bnetdocs.org/packet/314/sid-logonresponse
            # This is a simple yes/no result, no more details available.
            result = AccountLoginResult.Success if packet.get_dword() == 1 else AccountLoginResult.UnknownError

        elif packet.packet_id == SID_LOGONRESPONSE2:
            # https://bnetdocs.org/packet/377/sid-logonresponse2
            status = packet.get_dword()
            status_lookup = {
                0x00: AccountLoginResult.Success,
                0x01: AccountLoginResult.NoAccount,
                0x02: AccountLoginResult.WrongPassword,
                0x06: AccountLoginResult.AccountClosed
            }
            result = status_lookup.get(status, result)

            if result != AccountLoginResult.Success:
                self.state["logon_error_code"] = status
            if result == AccountLoginResult.AccountClosed:
                self.state["logon_error_msg"] = packet.get_string()

        elif packet.packet_id == SID_CHANGEPASSWORD:
            # https://bnetdocs.org/packet/220/sid-changepassword
            result = AccountLoginResult.Success if packet.get_dword() == 0 else AccountLoginResult.UnknownError

        else:
            raise InvalidOperationError(f"Unsupported packet sent to handle_logon_result: 0x{packet.packet_id:02X}")

        if result == AccountLoginResult.Success:
            self.log.info(f"Logged into account '{self.state['account_name']}'")
        else:
            is_pw_change = packet.packet_id in [SID_AUTH_ACCOUNTCHANGEPROOF, SID_CHANGEPASSWORD]
            self._display_logon_error(result, ("Password change" if is_pw_change else "Account login") + " failed")

        if packet.packet_id == SID_AUTH_ACCOUNTCHANGEPROOF:
            self._account_change_fut.set_result(result)
        else:
            self._account_login_fut.set_result(result)
        return result

    async def _handle_account_create_result(self, packet):
        err_header = "Account creation failed"

        if packet.packet_id == SID_AUTH_ACCOUNTCREATE:
            # https://bnetdocs.org/packet/138/sid-auth-accountcreate
            status = packet.get_dword()
            status_lookup = {
                0x00: AccountCreateResult.Success,
                0x04: AccountCreateResult.AccountAlreadyExists,
                0x07: AccountCreateResult.TooShort,
                0x08: AccountCreateResult.InvalidCharacter,
                0x09: AccountCreateResult.BannedWord,
                0x0A: AccountCreateResult.TooFewAlphanumeric,
                0x0B: AccountCreateResult.AdjacentPunctuation,
                0x0C: AccountCreateResult.TooMuchPunctuation
            }
            result = status_lookup.get(status, AccountCreateResult.AccountAlreadyExists)

            if result == AccountCreateResult.AccountAlreadyExists:
                self.state["account_create_error_code"] = status

        elif packet.packet_id == SID_CREATEACCOUNT:
            # https://bnetdocs.org/packet/228/sid-createaccount
            # This a simple yes/no result, no more details available.
            result = AccountCreateResult.Success if packet.get_dword() == 1 else \
                AccountCreateResult.UnknownError

        elif packet.packet_id == SID_CREATEACCOUNT2:
            # https://bnetdocs.org/packet/255/sid-createaccount2
            status = packet.get_dword()
            status_lookup = {
                0x00: AccountCreateResult.Success,
                0x01: AccountCreateResult.TooShort,
                0x02: AccountCreateResult.InvalidCharacter,
                0x03: AccountCreateResult.BannedWord,
                0x04: AccountCreateResult.AccountAlreadyExists,
                0x05: AccountCreateResult.UnknownError,
                0x06: AccountCreateResult.TooFewAlphanumeric,
                0x07: AccountCreateResult.AdjacentPunctuation,
                0x08: AccountCreateResult.TooManyPunctuation
            }
            result = status_lookup.get(status, AccountCreateResult.UnknownError)

            if result != AccountCreateResult.Success:
                self.state["account_create_error_code"] = status
                self.state["account_create_error_msg"] = packet.get_string()

        else:
            raise InvalidOperationError(f"Unsupported packet sent to "
                                        f"handle_account_create_result: 0x{packet.packet_id:02X}")

        if result not in [AccountCreateResult.NoResult, AccountCreateResult.Success]:
            error_lookup = {
                AccountCreateResult.AccountAlreadyExists: "Account already exists",
                AccountCreateResult.TooShort: "Name is too short",
                AccountCreateResult.InvalidCharacter: "Name contains invalid characters",
                AccountCreateResult.BannedWord: "Name contains a banned word",
                AccountCreateResult.TooFewAlphanumeric: "Name contains too few alphanumeric characters",
                AccountCreateResult.AdjacentPunctuation: "Name contains adjacent punctuation characters",
                AccountCreateResult.TooManyPunctuation: "Name contains too many adjacent punctuation characters",
                AccountCreateResult.UnknownError: "An unknown error occurred: %0"
            }
            error = error_lookup.get(result, AccountCreateResult.UnknownError)
            if result == AccountCreateResult.UnknownError:
                error = error.replace("%0", str(self.state.get("account_create_error_code")))

            self.log.error(f"{err_header} - {error}")

            server_err_msg = self.state.get("account_create_error_msg")
            if server_err_msg:
                self.log.error(f"{err_header} - Additional info: {server_err_msg}")

        elif result == AccountCreateResult.Success:
            self.log.info(f"Account created: '{self.state['account_name']}'")

        self._account_create_fut.set_result(result)
        return result

    async def _handle_set_email(self, _):
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
        self._enter_chat_fut.set_result(True)
        self.state["status"] = ClientStatus.Chatting
        self.log.info(f"Entered chat as '{self.state['username']}'")

    async def _handle_chat_event(self, packet):
        # https://bnetdocs.org/packet/307/sid-chatevent
        event = ChatEvent.parse(packet)
        self.log.debug(repr(event))

        if event.eid == ChatEventType.JoinChannel:
            self.state["users"] = []
            self.state["channel"] = event.text
            self.log.info(f"Joined channel: {event.text}")

        elif event.eid in [ChatEventType.UserJoin, ChatEventType.ShowUser, ChatEventType.FlagUpdate]:
            if user := self.get_user(event.username):
                if event.eid == ChatEventType.UserJoin:
                    # For duplicate users, the oldest copy is usually a ghost, so get rid of it
                    self.log.warning(f"Duplicate join event for user '{user}' - cleaning up ghosts")
                    self.users.remove(user)
                    self.users.append(user)
                else:
                    event.is_update = True

                user.flags = event.flags
                user.ping = event.ping
                user.statstring = event.text
            else:
                self.users.append(ChatUser(event.username, event.flags, event.ping, event.text))

        elif event.eid == ChatEventType.UserLeave:
            if user := self.get_user(event.username):
                self.users.remove(user)

        elif event.eid == ChatEventType.ServerInfo:
            self.log.info(f"Server info: {event.text}")

        elif event.eid == ChatEventType.ServerError:
            self.log.error(f"Server error: {event.text}")

        elif event.eid == ChatEventType.ServerBroadcast:
            self.log.info(f"Server broadcast ({event.username}): {event.text}")

        return event

    async def _handle_flood_detected(self, _):
        # https://bnetdocs.org/packet/242/sid-flooddetected
        self.state["flood_detected"] = True
        self.log.warning("Flood detected!")

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

        printer = self.log.info
        for flag, printer in printers.items():
            if style & flag == flag:
                break

        # Couldn't find a suitable printer, so just use info
        printer(f"{caption} - {text}")
        return text, caption, style

    async def _handle_extra_work(self, packet):
        # Both SID_OPTIONALWORK and SID_REQUIREDWORK have the same format.
        # https://bnetdocs.org/packet/102/sid-optionalwork
        # https://bnetdocs.org/packet/182/sid-requiredwork
        required = packet.packet_id == SID_REQUIREDWORK
        work_file = packet.get_string()
        self.log.debug(f"{'Required' if required else 'Optional'} work requested: {work_file}")
        return work_file, required

    async def _handle_warden(self, _):
        # https://bnetdocs.org/packet/420/sid-warden
        self.log.warning("Warden packet received!")

    async def _handle_friend_update(self, packet):
        if packet.packet_id in [SID_FRIENDSUPDATE, SID_FRIENDSADD]:
            if packet.packet_id == SID_FRIENDSUPDATE:
                # Single-friend update
                # https://bnetdocs.org/packet/384/sid-friendsupdate

                index = packet.get_byte()
            else:
                # New friend :)
                # https://bnetdocs.org/packet/118/sid-friendsadd

                index = -1
                self.friends.append({"account": packet.get_string()})

            # For both cases...
            self.friends[index].update({
                "status": FriendStatus(packet.get_byte()),
                "location": FriendLocation(packet.get_byte()),
                "product": BncsProduct.get(packet.get_dword()),
                "location_name": packet.get_string()
            })

            f = self.friends[index]
            assert isinstance(f, dict)
            if f['location'] == FriendLocation.Offline:
                self.log.debug(f"Friend #{index} updated - name: {f['account']}, location: offline")
            else:
                self.log.debug(f"Friend #{index} updated - name: {f['account']}, status: {f['status']}, "
                               f"location: {f['location']}, product: {f['product'].code}, "
                               f"place: '{f['location_name']}'")

        elif packet.packet_id == SID_FRIENDSREMOVE:
            # Bye friend :(
            # https://bnetdocs.org/packet/256/sid-friendsremove
            index = packet.get_byte()
            del self.friends[index]
            self.log.debug(f"Friend #{index} removed")

        elif packet.packet_id == SID_FRIENDSPOSITION:
            # Friend changed list position
            # https://bnetdocs.org/packet/117/sid-friendsposition
            index = packet.get_byte()
            new_index = packet.get_byte()

            friend = self.friends[index]
            del self.friends[index]
            self.friends.insert(new_index, friend)
            self.log.debug(f"Friend #{index} moved to position {new_index}")

    async def _handle_news_info(self, packet):
        count = packet.get_byte()
        packet.get_dword()
        oldest = datetime.utcfromtimestamp(packet.get_dword())
        newest = datetime.utcfromtimestamp(packet.get_dword())

        self.log.debug(f"News info - count: {count}, oldest: {oldest.isoformat()}, newest: {newest.isoformat()}")

        for _ in range(count):
            ts = datetime.utcfromtimestamp(packet.get_dword())
            content = packet.get_string()
            self.log.debug(f"News content ({ts.isoformat()}): {content}")
