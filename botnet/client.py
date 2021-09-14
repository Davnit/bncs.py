
import asyncio
import enum
import logging

from bncs.utils import AsyncClientBase, InvalidOperationError

from .exceptions import PROTOCOL_VIOLATION_ERRORS
from .packets import *
from .user import BotNetUser, AdminFlags

TIMEOUT = 5


class ChatAction(enum.IntEnum):
    Talk = 0
    Emote = 1


class ChatDistribution(enum.IntEnum):
    Broadcast = 0
    Database = 1
    Whisper = 2


class DatabaseTransferEvent(enum.IntEnum):
    FullTransfer = 0
    IncrementalTransfer = 1
    Completed = 2


class BotNetClient(AsyncClientBase):
    def __init__(self, *, config=None):
        log = logging.getLogger("BotNet")
        AsyncClientBase.__init__(self, BotNetReader, logger=log)

        self.config = {
            "server": "botnet.bnetdocs.org",
            "port": 0x5555,
            "keep_alive_interval": 150,
            "require_confirmation": True
        }
        if config:
            self.config.update(config)

        self.packet_handlers.update({
            BOTNET_LOGON: self._handle_logon,
            BOTNET_USER: self._handle_user,
            BOTNET_USER_DISC: self._handle_user_disc,
            BOTNET_PROTOCOL_VIOLATION: self._handle_protocol_violation,
            BOTNET_CLIENT_VERSION: self._handle_client_version,
            BOTNET_REVISION: self._handle_revision,
            BOTNET_CHAT: self._handle_chat,
            BOTNET_CHAT_OPTIONS: self._handle_chat_options
        })

        self._client_auth_fut = None

        self.state = {
            "server_revision": 1,
            "client_awl": 0,
            "admin_level": AdminFlags(0),
            "users": {}
        }

    @property
    def authenticated(self):
        return self.state.get("authenticated", False)

    @property
    def server_revision(self):
        return self.state["server_revision"]

    @property
    def client_awl(self):
        return self.state["client_awl"]

    @property
    def admin_level(self):
        return self.state["admin_level"]

    @property
    def users(self):
        return self.state["users"]

    @property
    def database(self):
        return self.state.get("database_name", "public")

    async def connect(self, host=None, port=None):
        host = host or self.config["server"]
        port = port or self.config["port"]
        await super().connect(host, port)

    def disconnect(self, reason=None):
        if self._client_auth_fut and not self._client_auth_fut.done():
            self._client_auth_fut.cancel()

        super().disconnect(reason)

    async def wait_closed(self):
        if self._client_auth_fut:
            await asyncio.gather(self._client_auth_fut, return_exceptions=True)
        await super().wait_closed()

    async def keep_alive(self):
        while self.connected:
            await asyncio.sleep(self.config["keep_alive_interval"])
            await self.send(BotNetPacket(BOTNET_KEEPALIVE))

    async def authenticate(self, bot_name=None, bot_password=None, timeout=TIMEOUT):
        """Authenticates the client to the BotNet server."""
        err_header = "Client authentication failed"
        if self.authenticated:
            raise InvalidOperationError(f"{err_header} - client already authenticated")

        bot_name = self.state["bot_name"] = bot_name or self.config["bot_name"]
        self._client_auth_fut = asyncio.get_event_loop().create_future()

        # https://bnetdocs.org/packet/231/botnet-logon
        x01 = BotNetPacket(BOTNET_LOGON)
        x01.insert_string(bot_name)
        x01.insert_string(bot_password or self.config["bot_password"])
        self.log.debug(f"Authenticating as bot {bot_name}...")
        await self.send(x01)

        try:
            return await asyncio.wait_for(self._client_auth_fut, timeout)
        except asyncio.TimeoutError:
            self.log.error(f"{err_header} - request timed out")
            return False

    async def set_chat_options(self, command=0, *, await_ack=True,
                               broadcast=None, database=None, whisper=None, external=None, timeout=TIMEOUT):
        err_header = "Unable to set chat options"
        if not self.authenticated:
            raise InvalidOperationError(f"{err_header} - client not authenticated")

        if self.state["server_revision"] < 4:
            self.log.error("Chat options are not supported on this server.")
            return False

        # https://bnetdocs.org/packet/335/botnet-chat-options
        x10 = BotNetPacket(BOTNET_CHAT_OPTIONS)
        x10.insert_byte(command)

        has_new_values = not all(b is None for b in (broadcast, database, whisper, external))
        chat_options = self.state.get("chat_options", {})
        option_keys = ["broadcast", "database", "whisper", "external"]
        new_values = [broadcast, database, whisper, external]

        for i in range(len(option_keys)):
            new_values[i] = (chat_options.get(option_keys[i], 0) if new_values[i] is None else new_values[i])
            if has_new_values:
                x10.insert_byte(new_values[i])

        await self.send(x10)

        if await_ack:
            def matcher(p):
                return p.get_byte() == command

            # https://bnetdocs.org/packet/197/botnet-chat-options
            await self.wait_for_packet(BOTNET_CHAT_OPTIONS, matcher, timeout=timeout)

    async def get_chat_options(self, command=0, timeout=TIMEOUT):
        await self.set_chat_options(command, timeout=timeout)
        return self.state.get("chat_options", {})

    async def update_stats(self, bnet_channel, bnet_user, bnet_ip, database=None):
        err_header = "StatsUpdate failed"
        if not self.authenticated:
            raise InvalidOperationError(f"{err_header} - client not authenticated")

        # https://bnetdocs.org/packet/171/botnet-statsupdate
        x02 = BotNetPacket(BOTNET_STATSUPDATE)
        x02.insert_string(bnet_user)
        x02.insert_string(bnet_channel or "<Not logged on>")
        x02.insert_ipv4(bnet_ip) if bnet_ip else x02.insert_dword(0)
        x02.insert_string(database or "")
        x02.insert_dword(0)
        await self.send(x02)

        # https://bnetdocs.org/packet/309/botnet-statsupdate
        reply = await self.wait_for_packet(BOTNET_STATSUPDATE)
        result = reply.get_dword()
        if not reply.eop():
            self.state["admin_level"] = reply.get_dword()
        return result == 1

    async def get_users(self, timeout=TIMEOUT):
        if not self.authenticated:
            raise InvalidOperationError("User list request failed - client not authenticated")

        # Requesting a new user list, clear the old one.
        self.users.clear()

        # https://bnetdocs.org/packet/369/botnet-user-list
        await self.send(BotNetPacket(BOTNET_USER_LIST))

        if self.server_revision >= 4 and self.client_awl >= 1:
            def matcher(p):
                return p.eop() is True

            await self.wait_for_packet(BOTNET_USER, matcher, timeout)
            return self.users

    async def send_chat(self, message, *, target=None, emote=False):
        if isinstance(target, BotNetUser):
            target = target.bot_id

        # https://bnetdocs.org/packet/312/botnet-chat
        x0b = BotNetPacket(BOTNET_CHAT)
        x0b.insert_dword(2 if target else 1)
        x0b.insert_dword(1 if emote else 0)
        x0b.insert_dword(target if target else 0)
        x0b.insert_string(message)
        await self.send(x0b)

    async def login(self, account=None, password=None, timeout=TIMEOUT):
        err_header = "Account login failed"
        self._account_op_precheck(err_header)

        try:
            account = account or self.state.get("account_name", self.config["account"])
            password = password or self.config["password"]
        except KeyError as ke:
            raise InvalidOperationError(f"{err_header} - missing required config parameter: {ke.args[0]}")

        self.state["account_name"] = account
        return await self._account_operation(0, timeout, account, password)

    async def create_account(self, account=None, password=None, timeout=TIMEOUT):
        err_header = "Account creation failed"
        self._account_op_precheck(err_header)

        try:
            account = account or self.state.get("account_name", self.config["account"])
            password = password or self.config["password"]
        except KeyError as ke:
            raise InvalidOperationError(f"{err_header} - missing required config parameter: {ke.args[0]}")

        self.state["account_name"] = account
        return await self._account_operation(2, timeout, account, password)

    async def change_password(self, new_password, old_password=None, account=None, timeout=TIMEOUT):
        err_header = "Account password change failed"
        self._account_op_precheck(err_header)

        try:
            account = account or self.state.get("account_name", self.config["account"])
            password = old_password or self.config["password"]
        except KeyError as ke:
            raise InvalidOperationError(f"{err_header} - missing required config parameter: {ke.args[0]}")

        self.state["account_name"] = account
        return await self._account_operation(1, timeout, account, password, new_password)

    async def get_database(self, age=None, timeout=TIMEOUT):
        # https://bnetdocs.org/packet/400/botnet-database
        x03 = BotNetPacket(BOTNET_DATABASE)
        x03.insert_dword(0x01)      # Request database
        if self.server_revision >= 4 and age is not None:
            x03.insert_dword(age)   # Incremental transfer period, in seconds
        await self.send(x03)

        if self.server_revision >= 4:
            def start_matcher(p):
                # Checks for matching sub-command and transfer event start
                return p.get_dword() == 1 and p.get_dword() in \
                       (DatabaseTransferEvent.FullTransfer, DatabaseTransferEvent.IncrementalTransfer)

            # https://bnetdocs.org/packet/243/botnet-database
            reply = await self.wait_for_packet(BOTNET_DATABASE, start_matcher, timeout)
            reply.position += 4
            transfer_type = DatabaseTransferEvent(reply.get_dword())
            self.log.info(f"Starting {transfer_type.name} of database '{self.database}'")

            def end_matcher(p):
                return p.get_dword() == 1 and p.get_dword() == DatabaseTransferEvent.Completed

            await self.wait_for_packet(BOTNET_DATABASE, end_matcher, timeout)
            self.log.info(f"Database transfer completed.")


    def _account_op_precheck(self, err_header):
        if not self.authenticated:
            raise InvalidOperationError(f"{err_header} - client not authenticated")

        if self.server_revision < 2:
            raise InvalidOperationError(f"{err_header} - accounts are not supported on this server")

    async def _account_operation(self, command, timeout, *params):
        # https://bnetdocs.org/packet/209/botnet-account
        x0d = BotNetPacket(BOTNET_ACCOUNT)
        x0d.insert_dword(command)
        for param in params:
            x0d.insert_string(param)
        await self.send(x0d)

        def matcher(p):
            return p.get_dword() == command

        # https://bnetdocs.org/packet/366/botnet-account
        reply = await self.wait_for_packet(BOTNET_ACCOUNT, matcher, timeout=timeout)
        reply.position += 4     # Skip sub-command, since we know it matches
        return reply.get_dword() == 1

    async def _handle_logon(self, packet):
        # https://bnetdocs.org/packet/204/botnet-logon
        self.state["authenticated"] = (packet.get_dword() == 1)
        self.log.info(f"Client authentication successful - server version: {self.server_revision}")

        if self.server_revision == 4:
            self.state["client_ip"] = packet.get_ipv4()

            # Determine our capability flags
            cap_flags = 0
            if self.config["require_confirmation"]:
                cap_flags |= 0x01

            # Inform the server of our capabilities and awareness
            # The actual name of this message is BOTNET_CLIENT_VERSION, but CS uses the ID for BOTNET_REVISION
            # https://bnetdocs.org/packet/511/botnet-client-version
            x0a = BotNetPacket(BOTNET_REVISION)
            x0a.insert_dword(0x01)
            x0a.insert_dword(cap_flags)
            await self.send(x0a)

    async def _handle_revision(self, packet):
        # https://bnetdocs.org/packet/385/botnet-revision
        self.state["server_revision"] = packet.get_dword()

    async def _handle_client_version(self, packet):
        # https://bnetdocs.org/packet/512/botnet-client-version
        self.state["client_awl"] = packet.get_dword()
        self.log.debug(f"Server acknowledged client awareness level {self.client_awl}")

    async def _handle_user(self, packet):
        # https://bnetdocs.org/packet/198/botnet-user
        if packet.eop():
            # BOTNET_USER_LIST null terminator
            return

        bot_id = packet.get_dword()
        user = self.users.get(bot_id, BotNetUser(bot_id))

        if self.server_revision >= 4 and self.client_awl >= 1:
            user.database_access = packet.get_dword()
            user.admin_access = AdminFlags(packet.get_dword())

            # IP is only sent for certain admin flags (A = super, C = connection, L = ??)
            if self.admin_level.has_any_flag("ACL") > 0:
                user.ip_address = packet.get_ipv4()

        user.username = packet.get_string()
        user.channel = packet.get_string()
        user.server = packet.get_ipv4()

        if self.server_revision >= 2:
            user.account = packet.get_string()

            if self.server_revision >= 3:
                user.database = packet.get_string()

        self.log.debug(f"User update - {user}")
        self.users[bot_id] = user
        return user

    async def _handle_user_disc(self, packet):
        # https://bnetdocs.org/packet/229/botnet-user-disc
        bot_id = packet.get_dword()
        self.log.debug(f"User disconnected: {bot_id}")
        self.users.pop(bot_id, None)
        return bot_id

    async def _handle_chat(self, packet):
        # https://bnetdocs.org/packet/207/botnet-chat
        distro = ChatDistribution(packet.get_dword())
        action = ChatAction(packet.get_dword())
        source = packet.get_dword()
        message = packet.get_string()

        self.log.debug(f"Chat message - dist: {distro}, action: {action}, source: {source}, message: '{message}'")
        return message, source, distro, action

    async def _handle_chat_options(self, packet):
        # Handling this separately instead of inline because in theory it could be received without request.
        # I am not sure if the official server implementation ever does this though.
        # https://bnetdocs.org/packet/197/botnet-chat-options
        command = packet.get_byte()
        if command == 0:
            options = {
                "broadcast": packet.get_byte(),
                "database": packet.get_byte(),
                "whisper": packet.get_byte(),
                "external": packet.get_byte()
            }
            values = ", ".join(f"{k}: {v}" for k, v in options.items())
            self.log.info(f"Chat drop options updated: {values}")
            self.state["chat_options"] = options
            return options
        else:
            self.log.warning(f"Received unrecognized chat option sub-command: 0x{command:02X}")

    async def _handle_protocol_violation(self, packet):
        # https://bnetdocs.org/packet/513/botnet-protocol-violation
        code = packet.get_dword()
        msg_id = packet.get_byte()

        err_text = PROTOCOL_VIOLATION_ERRORS.get(msg_id, {}).get(code)
        if err_text is None:
            if code == 1:
                err_text = f"Protocol violation - unrecognized message ID: 0x{msg_id:02X}"
            else:
                err_text = f"Unknown protocol violation - code: 0x{code:02X}, pid: 0x{msg_id:02X}"
        else:
            err_text = f"Protocol violation in packet 0x{msg_id:02X} - {err_text}"

        self.log.error(err_text)
