
from ..utils import PacketBuilder, PacketReader, DataBuffer, get_packet_name

# MCP packet constants
MCP_NULL = 0x00
MCP_STARTUP = 0x01
MCP_CHARCREATE = 0x02
MCP_CREATEGAME = 0x03
MCP_JOINGAME = 0x04
MCP_GAMELIST = 0x05
MCP_GAMEINFO = 0x06
MCP_CHARLOGON = 0x07
MCP_CHARDELETE = 0x0A
MCP_REQUESTLADDERDATA = 0x11
MCP_MOTD = 0x12
MCP_CANCELGAMECREATE = 0x13
MCP_CREATEQUEUE = 0x14
MCP_CHARRANK = 0x16
MCP_CHARLIST = 0x17
MCP_CHARUPGRADE = 0x18
MCP_CHARLIST2 = 0x19


class McpPacket(PacketBuilder):
    HEADER_SIZE = 3

    def __str__(self):
        return "MCP " + super().__str__()

    def get_name(self):
        return get_packet_name(self, globals(), "MCP_")

    def get_data(self):
        buff = DataBuffer()
        buff.insert_word(self.__len__())
        buff.insert_byte(self.packet_id)
        buff.insert_raw(self.data)
        return buff.data


class McpReader(PacketReader):
    HEADER_SIZE = 3

    def __init__(self, data):
        super().__init__(data)

        self.length = self.get_word()
        self.packet_id = self.get_byte()

    def __str__(self):
        return "MCP " + super().__str__()

    def get_name(self):
        return get_packet_name(self, globals(), "MCP_")
