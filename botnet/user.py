
from .admin import AdminFlags


class BotNetUser:
    def __init__(self, bot_id):
        self.bot_id = bot_id
        self.database_access = None
        self.admin_access = AdminFlags(0)
        self.ip_address = None
        self.username = None
        self.channel = None
        self.server = None
        self.account = None
        self.database = None

    def __str__(self):
        return "User #%i: Account: %s, Database: %s, Battle.net identity: %s" % (
            self.bot_id, self.account if self.has_account else None, self.database, self.get_bnet_ident()
        )

    def __dict__(self):
        return {
            "bot_id": self.bot_id,
            "database_access": self.database_access,
            "admin_access": self.admin_access.to_flag_string(),
            "ip_address": self.ip_address,
            "username": self.username,
            "channel": self.channel,
            "server": self.server,
            "account": self.account,
            "database": self.database
        }

    @property
    def has_account(self):
        return self.account != "No Account"

    @property
    def is_logged_on(self):
        return self.channel != "<Not logged on>"

    @property
    def has_name(self):
        return not (self.account is None and self.username is None)

    @property
    def name(self):
        if self.account and self.account != self.username:
            return "%s [%s]" % (self.account, self.username)
        else:
            return self.username

    def get_bnet_ident(self):
        return "%s in '%s' @ %s" % (self.username, self.channel, self.server)

    def in_same_channel(self, other):
        return self.is_logged_on and self.channel == other.bnet_channel and self.server == other.bnet_server

    def get_changes(self, old_values):
        changes = {}
        new_values = self.__dict__()
        for key, old_value in old_values.items():
            if new_values[key] != old_value:
                changes[key] = new_values[key]
        return changes
