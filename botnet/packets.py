
from bncs.utils import PacketBuilder, PacketReader, DataBuffer, get_packet_name, InvalidPacketException


BOTNET_KEEPALIVE = 0x00
BOTNET_LOGON = 0x01
BOTNET_STATSUPDATE = 0x02
BOTNET_DATABASE = 0x03
BOTNET_COMMAND = 0x04
BOTNET_COMMAND_TO_DATABASE = 0x04
BOTNET_CYCLE = 0x05
BOTNET_USER = 0x06
BOTNET_USER_LIST = 0x06
BOTNET_COMMAND_TO_ALL = 0x07
BOTNET_USER_DISC = 0x07
BOTNET_COMMAND_TO = 0x08
BOTNET_PROTOCOL_VIOLATION = 0x08
BOTNET_DATABASE_CHPW = 0x09
BOTNET_CLIENT_VERSION = 0x09
BOTNET_REVISION = 0x0A
BOTNET_CHAT = 0x0B
BOTNET_ADMIN = 0x0C
BOTNET_ACCOUNT = 0x0D
BOTNET_DATABASE_CHMO = 0x0E
BOTNET_CHAT_OPTIONS = 0x10


class BotNetPacket(PacketBuilder):
    def __init__(self, packet_id):
        super().__init__(packet_id)

    def __len__(self):
        return super().__len__() + 4

    def __str__(self):
        return "BotNet " + super().__str__()

    def get_name(self):
        return get_packet_name(self, globals(), "BOTNET_")

    def get_data(self):
        pak = DataBuffer()
        pak.insert_byte(0x01)   # Protocol version (1)
        pak.insert_byte(self.packet_id)
        pak.insert_word(self.__len__())
        pak.insert_raw(self.data)
        return pak.data


class BotNetReader(PacketReader):
    HEADER_SIZE = 4

    def __init__(self, data):
        super().__init__(data)
        proto_ver = self.get_byte()
        if proto_ver != 0x01:
            raise InvalidPacketException("Invalid BotNet packet header. (Version: %i)" % proto_ver)

        self.packet_id = self.get_byte()
        self.length = self.get_word()

    def __len__(self):
        return self.length

    def __str__(self):
        return "BotNet " + super().__str__()

    def get_name(self):
        return get_packet_name(self, globals(), "BOTNET_")

    @classmethod
    async def read_from(cls, stream):
        from asyncio import IncompleteReadError
        try:
            packet = cls(await stream.readexactly(4))
        except IncompleteReadError:
            return None

        await packet.fill(stream)
        return packet
