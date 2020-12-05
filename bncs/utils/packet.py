
from .buffer import DataBuffer, DataReader, format_buffer


def get_packet_name(packet, names, prefix=None):
    for var, value in names.items():
        if prefix is None or var.startswith(prefix):
            if value == packet.packet_id:
                return var


class PacketBuilder(DataBuffer):
    """Helper class for creating and writing packets."""
    def __init__(self, packet_id):
        """Creates a new packet with the specified ID."""
        self.packet_id = packet_id
        super().__init__()

    @property
    def length(self):
        return super().__len__()

    def __str__(self):
        if str_id := self.get_name():
            return "Packet %s (id: 0x%0.2X, length: %i)" % (str_id, self.packet_id, len(self))
        return "Packet 0x%0.2X (length: %i)" % (self.packet_id, len(self))

    def __repr__(self):
        return format_buffer(self.get_data())

    def get_name(self):
        """Returns the name of the packet."""
        pass

    def get_data(self):
        """Returns the full packet data including the header."""
        pass


class PacketReader(DataReader):
    """Helper class for receiving and reading packets."""
    def __init__(self, data=None):
        """Creates a new reader for a packet with the given data."""
        super().__init__(data)

        self.packet_id = None
        self.length = len(data)

    def __len__(self):
        return self.length

    def __str__(self):
        if self.packet_id:
            if str_id := self.get_name():
                return "Packet %s (id: 0x%0.2X, length: %i)" % (str_id, self.packet_id, len(self))
            return "Packet 0x%0.2X (length: %i)" % (self.packet_id, len(self))
        else:
            return "Unidentified packet (length: %i)" % self.length

    def __repr__(self):
        return format_buffer(self.data)

    def get_name(self):
        """Returns the name of the packet."""
        pass

    @property
    def data_len(self):
        """The actual number of bytes in the packet."""
        return super().__len__()

    @property
    def missing(self):
        """The number of additional bytes needed to complete the packet."""
        return self.length - self.data_len

    def is_full_packet(self):
        """Returns True if an entire packet has been received."""
        return self.missing == 0

    def append(self, data):
        """Adds additional raw data onto the end of the packet."""
        self.data += data
        return self.is_full_packet()

    async def fill(self, reader):
        """Reads the remaining packet data from an asyncio StreamReader instance.

            This method should only be called AFTER the packet header is read. Returns success.
        """
        from asyncio import IncompleteReadError

        if not self.is_full_packet():
            try:
                self.append(await reader.readexactly(self.missing))
            except IncompleteReadError as ire:
                self.append(ire.partial)
                return False

        return True

