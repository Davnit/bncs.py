
from .packets import BOTNET_LOGON, BOTNET_STATSUPDATE, BOTNET_DATABASE, BOTNET_COMMAND_TO_DATABASE, BOTNET_CYCLE
from .packets import BOTNET_USER_LIST, BOTNET_COMMAND_TO_ALL, BOTNET_COMMAND_TO, BOTNET_DATABASE_CHPW
from .packets import BOTNET_CLIENT_VERSION, BOTNET_CHAT, BOTNET_ADMIN, BOTNET_ACCOUNT


class BotNetError(BaseException):
    """Indicates an error of the BotNet protocol."""
    pass


class BotNetUnsupportedRevision(BotNetError):
    """Indicates that an operation was attempted that is unsupported on the current server revision."""
    def __init__(self, current, required):
        self.current = current
        self.required = required
        super().__init__("Operation not supported on server revision %i - requires: %s" % (current, required))


PROTOCOL_VIOLATION_ERRORS = {
    BOTNET_LOGON: {
        0x02: "client attempting to identify multiple times",
        0x03: "Bot name too long",
        0x04: "Bot password too long",
        0x05: "Bot name empty",
        0x06: "Bot password empty"
    },
    BOTNET_STATSUPDATE: {
        0x02: "Client not identified",
        0x03: "Message too small",
        0x04: "Battle.net username too long",
        0x05: "Battle.net channel too long",
        0x06: "Battle.net server empty",
        0x07: "Database name/pass too long",
        0x08: "Cycle status missing",
        0x09: "Battle.net username empty",
        0x0A: "Battle.net channel empty",
        0x0B: "Battle.net server invalid",
        0x0C: "Malformed Battle.net username",
        0x0D: "Malformed database name/pass"
    },
    BOTNET_DATABASE: {
        0x02: "Missing sub-command",
        0x03: "Client tried to modify database while invisible",
        0x04: "Invalid sub-command",
        0x05: "Missing usermask or message too small",
        0x06: "Missing flags or usermask",
        0x07: "Empty usermask",
        0x08: "Empty flags or malformed usermask",
        0x09: "Malformed usermask",
        0x0A: "Malformed flags"
    },
    BOTNET_COMMAND_TO_DATABASE: {
        0x02: "Client tried to issue command while invisible",
        0x03: "Missing sender name",
        0x04: "Missing command",
        0x05: "Empty sender name",
        0x06: "Empty command",
        0x07: "Malformed sender name"
    },
    BOTNET_CYCLE: {
        0x02: "Client tried to cycle while invisible",
        0x03: "Missing count",
        0x04: "Count is zero",
        0x05: "Not enough data to satisfy count value",
        0x06: "Specified more clients than are connected"
    },
    BOTNET_USER_LIST: {
        0x02: "Client tried to query user list while invisible"
    },
    BOTNET_COMMAND_TO_ALL: {
        0x02: "Client tried to issue command while invisible",
        0x03: "Missing sender name",
        0x04: "Missing command",
        0x05: "Empty sender name",
        0x06: "Empty command",
        0x07: "Malformed sender name"
    },
    BOTNET_COMMAND_TO: {
        0x02: "Client tried to issue command while invisible",
        0x03: "Missing target bot ID",
        0x04: "Missing sender name",
        0x05: "Missing command",
        0x06: "Empty sender name",
        0x07: "Empty command",
        0x08: "Invalid target bot ID",
        0x09: "Malformed sender name"
    },
    BOTNET_DATABASE_CHPW: {
        0x02: "Client tried to change password while invisible",
        0x03: "Missing password selection",
        0x04: "Missing new password",
        0x05: "Malformed new password"
    },
    BOTNET_CLIENT_VERSION: {
        0x02: "Missing client awareness level",
        0x03: "Missing client capabilities",
        0x04: "Unsupported client capabilities"
    },
    BOTNET_CHAT: {
        0x02: "Client tried to chat while invisible",
        0x03: "Missing command",
        0x04: "Missing action",
        0x05: "Missing bot ID",
        0x06: "Missing message",
        0x07: "Invalid command",
        0x08: "Invalid target"
    },
    BOTNET_ADMIN: {
        0x02: "Client invisible",
        0x03: "Missing sub-command"
    },
    BOTNET_ACCOUNT: {
        0x02: "Missing sub-command",
        0x03: "Invalid sub-command",
        0x04: "Missing account name",
        0x05: "Empty account name",
        0x06: "Missing password",
        0x07: "Empty password",
        0x08: "Missing new password",
        0x09: "Empty new password"
    }
}


class BotNetProtocolViolation(BotNetError):
    """Indicates a reported violation of the BotNet protocol."""
    def __init__(self, code, pak_id, pak_len, unproc_data_len):
        self.error_code = code
        self.packet_id = pak_id
        self.packet_length = pak_len
        self.unprocessed_data_length = unproc_data_len

        if self.error_code == 0x01:
            self.error_message = "Unrecognized message ID: %0.2X" % self.packet_id
        else:
            self.error_message = PROTOCOL_VIOLATION_ERRORS.get(pak_id, {}).get(code, "Error code %0.2X" % code)
        super().__init__(self.error_message)
