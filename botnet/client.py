
import asyncio
import logging
import socket

from .admin import AdminFlags
from .exceptions import *
from .packets import *
from .user import BotNetUser

from bncs.utils import EventDispatcher


CAP_AWAIT_DB_CONFIRM = 0x01

OPTION_ALLOW_ALL = 0x00
OPTION_DROP_ANON = 0x01
OPTION_DROP_ALL = 0x02

OPTION_ALLOW_OUTSIDE_WHISPER = 0x00
OPTION_DROP_OUTSIDE_WHISPER = 0x01

DB_READ = 1
DB_WRITE = 2
DB_RESTRICTED = 4

DISTRO_BROADCAST = 0
DISTRO_DATABASE = 1
DISTRO_WHISPER = 2

DISCONNECT_REASONS = {
    0x03: "Kicked by Administrator",
    0x05: "Kicked for protocol violation",
    0x06: "Dropped due to network error",
    0x07: "Disconnected"
}


def default_user(bot_id):
    return BotNetUser(bot_id)


class BotNetClient(EventDispatcher):
    """Client for interacting with a vL BotNet server."""
    def __init__(self):
        super().__init__()

        self.endpoint = None
        self.logger = logging.getLogger("BOTNET")
        self.handlers = {
            BOTNET_KEEPALIVE: self._handle_keepalive,
            BOTNET_REVISION: self._handle_botnet_revision,
            BOTNET_CHAT_OPTIONS: self._handle_botnet_chat_options,
            BOTNET_STATSUPDATE: self._handle_botnet_statsupdate,
            BOTNET_USER: self._handle_botnet_user,
            BOTNET_USER_DISC: self._handle_botnet_user_disc,
            BOTNET_PROTOCOL_VIOLATION: self._handle_botnet_protocol_violation,
            BOTNET_CHAT: self._handle_botnet_chat,
            BOTNET_COMMAND: self._handle_botnet_command
        }
        self.keep_alive_interval = 120      # Time between keep-alive packets, in seconds.

        self._connected = False
        self._reader = None
        self._writer = None
        self._external_ip = None
        self._receive_lock = asyncio.Lock()
        self._received = []

        self._revision = 1
        self._client_awl = 0
        self._chat_options = {
            "broadcast": OPTION_ALLOW_ALL,
            "database": OPTION_ALLOW_ALL,
            "whisper": OPTION_ALLOW_ALL,
            "external": OPTION_ALLOW_OUTSIDE_WHISPER
        }
        self._admin_flags = AdminFlags(0)
        self._users = {}
        self._my_bot_id = None
        self._waiting_for_users = False

    @property
    def external_ip(self):
        return self._external_ip

    @property
    def connected(self):
        return self._connected

    @property
    def server_revision(self):
        return self._revision

    @property
    def chat_options(self):
        return dict(self._chat_options)

    @property
    def admin_flags(self):
        return self._admin_flags

    @property
    def users(self):
        return dict(self._users)

    @property
    def myself(self):
        return self.users.get(self._my_bot_id)

    async def connect(self, host, port=0x5555):
        """Connects to the BotNet server.

        host: IP address (IPv4 only) or hostname of the remote server
        port: port number that the server is running on (default 0x5555)
        """
        self.endpoint = (host, port)
        self._reader, self._writer = await asyncio.open_connection(host, port, family=socket.AF_INET)
        self._connected = True

        # Schedule a task to receive incoming messages
        self._received.clear()
        asyncio.create_task(self._receive_packets())
        asyncio.create_task(self._run_keep_alive())

    async def disconnect(self):
        """Disconnects from the BotNet server."""
        self._connected = False
        if self._writer:
            self._writer.close()
            await self._writer.wait_closed()
            self._writer = None
            self._reader = None
            self.logger.info("Connection closed.")

    async def send_packet(self, pak):
        """Sends a BotNet packet.

        pak: the BotNetPacket object containing the data to be sent
        """
        if self.connected and not self._writer.is_closing():
            self._writer.write(pak.get_data())
            await self._writer.drain()

            self.logger.debug("SEND %s", pak)
            self.dispatch('packet_sent', pak.packet_id, len(pak), pak.data)

    async def _receive_packets(self):
        """Receives packets while the connection is open."""
        try:
            while self.connected:
                # Receive a packet
                pak = BotNetReader(await self._reader.readexactly(4))
                self.logger.debug("RECV %s", pak)
                pak.append(await self._reader.readexactly(len(pak) - 4))

                self.dispatch('packet_received', pak.packet_id, len(pak), pak.data)

                # Handle the packet immediately or queue it up for waiting functions.
                if pak.packet_id in self.handlers:
                    self.handlers[pak.packet_id](pak)
                else:
                    async with self._receive_lock:
                        self._received.append(pak)

        except asyncio.IncompleteReadError:
            if self._connected:
                # Server has disconnected us.
                self.logger.error("The BOTNET server closed the connection.")
                self._connected = False

            self._writer = None
            self._reader = None

    async def wait_for_packet(self, pid):
        """Waits for a packet to be received with the specified ID.

        pid: the ID of the packet to wait for

        If a handler is defined for the expected packet ID, it will temporarily be removed.
        """

        # Temporarily relieve the handler of its duty
        handler = self.handlers.get(pid)
        if handler:
            del self.handlers[pid]

        while self.connected:
            async with self._receive_lock:
                for pak in self._received:
                    if pak.packet_id == pid:
                        self._received.remove(pak)
                        if handler:
                            # Restore the handler
                            self.handlers[pid] = handler
                        return pak

            await asyncio.sleep(0.01)

        if handler:
            self.handlers[pid] = handler

    async def _run_keep_alive(self):
        # Create the keep-alive packet. It contains no data aside from the header.
        pak = BotNetPacket(BOTNET_KEEPALIVE)

        while self.connected:
            await asyncio.sleep(self.keep_alive_interval)
            if self.connected:      # We might not be connected anymore
                await self.send_packet(pak)

    async def authenticate(self, bot_name, bot_password):
        """Identifies the client to the BotNet server.

        bot_name: name of the bot program [max: 32]
        bot_password: password assigned to the bot program (not your account!) [max: 64]

            - Server revision 4+ closes the connection on auth failure. Older versions send a failure result.

            Uses the following packets:
             - https://bnetdocs.org/packet/231/botnet-logon
             - https://bnetdocs.org/packet/204/botnet-logon
        """
        pak = BotNetPacket(BOTNET_LOGON)
        pak.insert_string(bot_name)
        pak.insert_string(bot_password)
        await self.send_packet(pak)

        pak = await self.wait_for_packet(BOTNET_LOGON)
        if pak is None:
            return False

        result = pak.get_dword()
        self._external_ip = pak.get_ipv4()

        if self.server_revision >= 4:
            # This is actually called BOTNET_CLIENT_VERSION but the ID's are dumb
            pak = BotNetPacket(BOTNET_REVISION)
            pak.insert_dword(1)
            pak.insert_dword(CAP_AWAIT_DB_CONFIRM)
            await self.send_packet(pak)

            # Wait for response
            pak = await self.wait_for_packet(BOTNET_CLIENT_VERSION)
            if pak:
                self._client_awl = pak.get_dword()
                if self._client_awl == 0:
                    self.logger.warning("Server rejected client AWL change. Current level: %i" % self._client_awl)

        return result == 1

    async def login(self, account, password):
        """Logs into a BotNet account.

        account: name of the account [max: 16]
        password: plain-text password for the account [max: 96]

            Uses the following packets:
             - https://bnetdocs.org/packet/209/botnet-account
             - https://bnetdocs.org/packet/366/botnet-account
        """
        return await self._send_botnet_account(0, account, password)

    async def change_password(self, account, old_password, new_password):
        """Changes the password to an account.

        account: name of the account [max: 16]
        old_password: current password for the account [max: 96]
        new_password: new password for the account [max: 96]

        Uses the following packets:
             - https://bnetdocs.org/packet/209/botnet-account
             - https://bnetdocs.org/packet/366/botnet-account
        """
        return await self._send_botnet_account(1, account, old_password, new_password)

    async def create_account(self, account, password):
        """Creates an account on the BotNet server.

        account: name of the account [max: 16]
        password: plain-text password for the account [max: 96]

            Uses the following packets:
             - https://bnetdocs.org/packet/209/botnet-account
             - https://bnetdocs.org/packet/366/botnet-account
        """
        return await self._send_botnet_account(2, account, password)

    async def _send_botnet_account(self, cmd, *args):
        # Send request
        pak = BotNetPacket(BOTNET_ACCOUNT)
        pak.insert_dword(cmd)
        for a in args:
            pak.insert_string(a)
        await self.send_packet(pak)

        # Wait for response
        pak = await self.wait_for_packet(BOTNET_ACCOUNT)
        if pak is None:
            return None
        res_cmd = pak.get_dword()
        if res_cmd != cmd:
            raise BotNetError("Received wrong sub-command in response to BOTNET_ACCOUNT request." +
                              " Only one of these requests should be sent at a time (login, create, modify).")
        return pak.get_dword() == 1

    async def set_chat_options(self, cmd=0, **options):
        """Sets server-side chat options for the connection.

        cmd: the sub-command for setting options (default: 0 - chat drop options)
        options: keyword args defining options to change. If none are set, the current values will be used.

         - Only the default sub-command 0 is currently defined.
         - Available options are: broadcast, database, whisper, external
         - Values must be between 0 and 255 (0xFF)
         - Values stored locally are not updated until confirmation is returned from the server.

         Uses the following packets:
          - https://bnetdocs.org/packet/335/botnet-chat-options
          - https://bnetdocs.org/packet/197/botnet-chat-options
        """
        if self.server_revision < 4:
            raise BotNetUnsupportedRevision(self.server_revision, '4+')

        if cmd != 0:
            raise BotNetError("Unsupported chat options sub-command: %0.2X" % cmd)

        keys = ["broadcast", "database", "whisper", "external"]

        # Validate new changes
        for opt, value in options.items():
            if opt not in keys:
                raise ValueError("Invalid chat option: %s. Must be from: %s" % (opt, ', '.join(keys)))

            if not isinstance(value, int):
                raise TypeError("Chat option values must be int")
            elif value < 0 or value > 0xFF:
                raise ValueError("Chat option values must be between 0x00 and 0xFF (byte)")

        # Send change request packet
        pak = BotNetPacket(BOTNET_CHAT_OPTIONS)
        pak.insert_byte(cmd)
        for k in keys:
            pak.insert_byte(options.get(k, self._chat_options.get(k, 0)))
        await self.send_packet(pak)

        # Wait for the confirmation
        pak = await self.wait_for_packet(BOTNET_CHAT_OPTIONS)
        if pak is None:
            return False

        # Pass it off to the usual handler and compare final values to what we requested.
        self._handle_botnet_chat_options(pak)
        for key, value in options.items():
            if self._chat_options[key] != value:
                return False
        return True

    async def get_chat_options(self, cmd=0):
        """Requests an update on the client's currently set chat options.

         - Nothing is returned from this function, but the values stored on this object will be updated.

         Uses the following packets:
          - https://bnetdocs.org/packet/335/botnet-chat-options
          - https://bnetdocs.org/packet/197/botnet-chat-options
        """
        if self.server_revision < 4:
            raise BotNetUnsupportedRevision(self.server_revision, '4+')

        if cmd != 0:
            raise BotNetError("Unsupported chat options sub-command: %0.2X" % cmd)

        pak = BotNetPacket(BOTNET_CHAT_OPTIONS)
        pak.insert_dword(cmd)
        await self.send_packet(pak)

        # Wait for the response
        pak = await self.wait_for_packet(BOTNET_CHAT_OPTIONS)
        if pak is None:
            return {}

        # Pass it off to the usual handler and return values
        self._handle_botnet_chat_options(pak)
        return self.chat_options

    async def update(self, bnet_name, bnet_server=None, bnet_channel=None, db_name=None, db_pass=None, cycle=0):
        """Updates your status on the BotNet server.

        bnet_name: your unique username on the Battle.net server (or configured account name)
        bnet_channel: name of the channel you are in (use None if offline)
        bnet_server: int-form IPv4 address of the Battle.net server
        db_name: name of the BotNet database
        db_pass: password to the BotNet database
        cycle: [defunct] 0 = not cycling, 1 = cycling

         Uses the following packets:
          - https://bnetdocs.org/packet/171/botnet-statsupdate
          - https://bnetdocs.org/packet/309/botnet-statsupdate
        """
        db_str = db_name or ""
        if db_name and db_pass:
            db_str += " " + db_pass

        pak = BotNetPacket(BOTNET_STATSUPDATE)
        pak.insert_string(bnet_name)
        pak.insert_string(bnet_channel or "<Not logged on>")
        pak.insert_ipv4(bnet_server or "255.255.255.255")
        pak.insert_string(db_str)
        pak.insert_dword(cycle)
        await self.send_packet(pak)

        # Wait for confirmation
        pak = await self.wait_for_packet(BOTNET_STATSUPDATE)
        if pak is None:
            return False

        return self._handle_botnet_statsupdate(pak)

    async def refresh_users(self):
        """Requests a refresh of all online users.

         Uses the following packets:
          - https://bnetdocs.org/packet/369/botnet-user-list
          - https://bnetdocs.org/packet/198/botnet-user
        """
        self._users.clear()     # Clear current user list
        pak = BotNetPacket(BOTNET_USER_LIST)
        self._waiting_for_users = True
        await self.send_packet(pak)

        # Only awareness level 1+ clients will receive a terminated user list.
        if self._client_awl < 1:
            await asyncio.sleep(1)
            self._waiting_for_users = False
            return

        # Wait for responses...
        while self._waiting_for_users:
            pak = await self.wait_for_packet(BOTNET_USER)
            if pak is None:
                # Connection interrupted
                self._waiting_for_users = False
                return

            user = self._handle_botnet_user(pak)
            if user is None:
                # Received entire list
                self._waiting_for_users = False

    async def chat(self, message, target=None, **kwargs):
        """Sends a chat message to the BotNet.

        message: the text to send
        target: BotNetUser object or ID of user to send a message to directly
        kwargs: additional message options: broadcast [bool], emote [bool]

        By default, messages are sent to everyone on the local database.
         - If broadcast=True, and user has appropriate permissions, message will be sent to the entire BotNet.
         - If target is not None, message will be sent to a specific user.
        """
        distro = DISTRO_WHISPER if target \
            else DISTRO_BROADCAST if kwargs.get("broadcast") is True \
            else DISTRO_DATABASE

        target = target or self.myself
        target = target.bot_id if isinstance(target, BotNetUser) else target
        action = 1 if kwargs.get("emote") is True else 0

        pak = BotNetPacket(BOTNET_CHAT)
        pak.insert_dword(distro)
        pak.insert_dword(action)
        pak.insert_dword(target)
        pak.insert_string(message)
        await self.send_packet(pak)

        self.dispatch('self_chat', self.users.get(target), message, distro, action)

    async def command(self, command, target=None, **kwargs):
        """Sends a command message to the BotNet.

        command: the command to send
        target: BotNetUser object or ID of user to send a direct command
        kwargs: additional command options: broadcast [bool], sender [str]

        By default, commands are sent to everyone on the local database.
         - If broadcast=True, and user has appropriate permissions, command will be sent to the entire BotNet.
         - If target is not None, command will be sent to a specific user.
         - If sender is set, a custom name will be used. Otherwise the current user's name will be used.
        """
        pak_id = BOTNET_COMMAND_TO if target \
            else BOTNET_COMMAND_TO_ALL if kwargs.get("broadcast") is True \
            else BOTNET_COMMAND_TO_DATABASE

        target = target.bot_id if isinstance(target, BotNetUser) else target
        sender = kwargs.get("sender", self.myself.account if self.myself.has_account else self.myself.bnet_name)

        pak = BotNetPacket(pak_id)

        if pak_id == BOTNET_COMMAND_TO:
            pak.insert_dword(target)

        pak.insert_string(sender)
        pak.insert_string(command)
        await self.send_packet(pak)

        self.dispatch('sent_command', self.users.get(target), sender, command, )

    def _handle_keepalive(self, pak):
        pass

    def _handle_botnet_revision(self, pak):
        self._revision = pak.get_dword()
        self.logger.info("Server revision: %i" % self._revision)

    def _handle_botnet_chat_options(self, pak):
        cmd = pak.get_byte()
        if cmd != 1:
            raise BotNetError("Received chat options with unsupported sub-command: %0.2X" % cmd)

        keys = ["broadcast", "database", "whisper", "external"]
        for k in keys:
            self._chat_options[k] = pak.get_byte()

    def _handle_botnet_statsupdate(self, pak):
        result = (pak.get_dword() == 1)
        if not result:
            self.logger.error("Stats update failed.")

        if not pak.eop():
            self._admin_flags.value = pak.get_dword()
            self.logger.info("Admin flags updated: %s" % self.admin_flags.to_flag_string())
        return result

    def _handle_botnet_user(self, pak):
        if pak.eop():
            # Empty packet notifying end of user list has been received.
            self._waiting_for_users = False
            self.logger.debug("Received user list terminator packet.")
            return None

        bot_id = pak.get_dword()    # Bot's unique ID on the server
        if bot_id not in self._users:
            if len(self._users) == 0:
                self._my_bot_id = bot_id        # The first one should be us!

            self._users[bot_id] = BotNetUser(bot_id)

        user = self._users[bot_id]
        old_values = user.__dict__()
        self.logger.debug("Received update for user #%i" % bot_id)

        # This packet is a mess, really.
        if self.server_revision >= 4 and self._client_awl >= 1:
            user.database_access = pak.get_dword()
            user.admin_access.value = pak.get_dword()
            if self.admin_flags.has_flag('A'):
                user.ip_address = pak.get_ipv4()

        user.bnet_name = pak.get_string()
        user.bnet_channel = pak.get_string()
        user.bnet_server = pak.get_ipv4()

        if self.server_revision >= 2:
            user.account = pak.get_string()

        if self.server_revision >= 3:
            user.database = pak.get_string()

        self.dispatch('user_update', user, user.get_changes(old_values))
        return user

    def _handle_botnet_user_disc(self, pak):
        user = None
        reason = None

        bot_id = pak.get_dword()
        if bot_id in self._users:
            user = self._users[bot_id]
            del self._users[bot_id]

            if not pak.eop():
                reason = DISCONNECT_REASONS.get(pak.get_byte())
                self.logger.info("User #%i (%s) - disconnected: %s", bot_id, user.get_bnet_ident(), reason)
            else:
                self.logger.info("User #%i (%s) - disconnected.", bot_id, user.get_bnet_ident())

        self.dispatch('user_quit', user or default_user(bot_id), reason)

    def _handle_botnet_protocol_violation(self, pak):
        error_code = pak.get_dword()
        packet_id = pak.get_byte()
        packet_len = pak.get_word()
        unproc_len = pak.get_word()

        ex = BotNetProtocolViolation(error_code, packet_id, packet_len, unproc_len)
        self.logger.exception(ex)
        return ex

    def _handle_botnet_chat(self, pak):
        distro = pak.get_dword()
        action = pak.get_dword()
        bot_id = pak.get_dword()
        message = pak.get_string()

        self.dispatch('user_chat', self._users.get(bot_id, default_user(bot_id)), message, distro, action)

    def _handle_botnet_command(self, pak):
        bot_id = pak.get_dword()
        distro = pak.get_dword()
        sender = pak.get_string()
        command = pak.get_string()

        self.dispatch('bot_command', self._users.get(bot_id, default_user(bot_id)), sender, command, distro)
