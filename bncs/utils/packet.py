
from .buffer import DataBuffer, DataReader


class PacketBuilder(DataBuffer):
    """Helper class for creating and writing packets."""
    def __init__(self, packet_id):
        """Creates a new packet with the specified ID."""
        self.packet_id = packet_id
        super().__init__()

    def __str__(self):
        return "Packet 0x%0.2X (length: %i)" % (self.packet_id, len(self))

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
            return "Packet 0x%0.2X (length: %i)" % (self.packet_id, self.length)
        else:
            return "Unidentified packet (length: %i)" % self.length

    @property
    def data_len(self):
        """Returns the actual number of bytes received into the packet."""
        return super().__len__()

    def is_full_packet(self):
        """Returns True if an entire packet has been received."""
        return self.data_len >= self.length

    def append(self, data):
        """Adds additional raw data onto the end of the packet."""
        self.data += data
        return self.is_full_packet()
