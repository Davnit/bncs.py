
from .products import BncsProduct

import enum

# Event ID constants (EID)
EID_SHOWUSER = 0x01
EID_JOIN = 0x02
EID_LEAVE = 0x03
EID_WHISPER = 0x04
EID_TALK = 0x05
EID_BROADCAST = 0x06
EID_CHANNEL = 0x07
EID_USERFLAGS = 0x09
EID_WHISPERSENT = 0x0A
EID_CHANNELFULL = 0x0D
EID_CHANNELDOESNOTEXIST = 0x0E
EID_CHANNELRESTRICTED = 0x0F
EID_INFO = 0x12
EID_ERROR = 0x13
EID_IGNORE = 0x15
EID_ACCEPT = 0x16
EID_EMOTE = 0x17

# Channel flags
CHANNEL_PUBLIC = 0x01
CHANNEL_MODERATED = 0x02
CHANNEL_RESTRICTED = 0x04
CHANNEL_SILENT = 0x08
CHANNEL_SYSTEM = 0x10
CHANNEL_PRODUCT = 0x20
CHANNEL_GLOBAL = 0x1000
CHANNEL_REDIRECT = 0x4000
CHANNEL_CHAT = 0x8000
CHANNEL_SUPPORT = 0x10000

# User flags
FLAG_BLIZZARD = 0x01
FLAG_CHANOP = 0x02
FLAG_CHANVOICE = 0x04
FLAG_BNETADMIN = 0x08
FLAG_NOUDP = 0x10
FLAG_SQUELCH = 0x20
FLAG_GUEST = 0x40


class ChatEventType(enum.IntEnum):
    ShowUser = EID_SHOWUSER
    UserJoin = EID_JOIN
    UserLeave = EID_LEAVE
    UserWhisper = EID_WHISPER
    UserTalk = EID_TALK
    ServerBroadcast = EID_BROADCAST
    JoinChannel = EID_CHANNEL
    FlagUpdate = EID_USERFLAGS
    WhisperSent = EID_WHISPERSENT
    ErrorChannelFull = EID_CHANNELFULL
    ErrorChannelDoesNotExist = EID_CHANNELDOESNOTEXIST
    ErrorChannelRestricted = EID_CHANNELRESTRICTED
    ServerInfo = EID_INFO
    ServerError = EID_ERROR
    UserIgnored = EID_IGNORE
    UserUnignored = EID_ACCEPT
    UserEmote = EID_EMOTE


class ChannelFlags(enum.IntFlag):
    Private = 0
    Public = CHANNEL_PUBLIC
    Moderated = CHANNEL_MODERATED
    Restricted = CHANNEL_RESTRICTED
    Silent = CHANNEL_SILENT
    System = CHANNEL_SYSTEM
    ProductSpecific = CHANNEL_PRODUCT
    Global = CHANNEL_GLOBAL
    Redirect = CHANNEL_REDIRECT
    Chat = CHANNEL_CHAT
    TechSupport = CHANNEL_SUPPORT


class UserFlags(enum.IntFlag):
    NoFlags = 0
    Blizzard = FLAG_BLIZZARD
    ChannelOperator = FLAG_CHANOP
    ChannelSpeaker = FLAG_CHANVOICE
    ServerAdmin = FLAG_BNETADMIN
    UdpPlug = FLAG_NOUDP
    Squelched = FLAG_SQUELCH
    Guest = FLAG_GUEST


class ChatUser:
    def __init__(self, username, flags=0, ping=0, stats=None):
        self.name = username
        self.flags = flags
        self.ping = ping
        self.stats = stats

        self.ip_address = None
        self.account_id = None
        self.registrar = None

    @property
    def product(self):
        return BncsProduct.get(self.stats[:4])


class ChatEvent:
    def __init__(self, event_id, user=None, msg=None):
        self.eid = ChatEventType(event_id)
        self.text = msg
        self.text_encoding = None
        self.is_update = False

        self.flags = user.flags if user else 0
        self.ping = user.ping if user else 0
        self.username = user.name if user else ""

        # Deprecated fields, may be supported on some private servers
        self.ip_address = user.ip_address if user else None
        self.account_id = user.account_id if user else None
        self.registrar = user.registrar if user else None

    def __repr__(self):
        s = f"<BncsChatEvent eid={self.eid.name}, " \
            f"flags={self.flags.name or hex(self.flags.value)}, ping={self.ping}ms"

        # Defunct values, only show if they are different from expected.
        if self.ip_address != "0.0.0.0":
            s += f", ip={self.ip_address}"
        if self.account_id != 0xbaadf00d:
            s += f", account={self.account_id}"
        if self.registrar != 0xbaadf00d:
            s += f", authority={self.registrar}",

        s += f", username='{self.username}', text='{self.text}'>"
        return s

    def build_packet(self, hide_private_info=True):
        """Builds a BncsPacket to represent this chat event.

            If hide_private_info is TRUE then the IpAddress, AccountId, and RegAuth fields will be obscured.
        """
        from .packets import BncsPacket, SID_CHATEVENT
        pak = BncsPacket(SID_CHATEVENT)
        pak.insert_dword(self.eid.value)
        pak.insert_dword(self.flags.value)
        pak.insert_dword(self.ping)

        hidden_value = 0xbaadf00d
        if hide_private_info:
            pak.insert_dword(0)
            pak.insert_dword(hidden_value)
            pak.insert_dword(hidden_value)
        else:
            pak.insert_ipv4(self.ip_address or 0)
            pak.insert_dword(self.account_id or hidden_value)
            pak.insert_dword(self.registrar or hidden_value)

        pak.insert_string(self.username)
        pak.insert_string(self.text, encoding=self.text_encoding)
        return pak

    @classmethod
    def parse(cls, packet):
        from .packets import BncsReader

        if not isinstance(packet, BncsReader):
            raise TypeError("ChatEvent can only be parsed from a BncsReader")

        event = cls(packet.get_dword())
        flag_type = ChannelFlags if event.eid == ChatEventType.JoinChannel else UserFlags

        event.flags = flag_type(packet.get_dword())
        event.ping = packet.get_dword()
        event.ip_address = packet.get_ipv4()
        event.account_id = packet.get_dword()
        event.registrar = packet.get_dword()
        event.username = packet.get_string()

        # If ping is max value, set it to -1
        if event.ping == 0xffffffff:
            event.ping = -1

        # The text field can have mixed encodings depending on context
        event.text = packet.get_string(encoding=None)
        if event.eid not in [ChatEventType.ShowUser, ChatEventType.UserJoin, ChatEventType.UserLeave,
                             ChatEventType.FlagUpdate]:
            try:
                event.text = event.text.decode("utf-8")
                event.text_encoding = "utf-8"
            except UnicodeDecodeError:
                event.text = event.text.decode("latin-1", errors='ignore')
                event.text_encoding = "latin-1"

        return event
