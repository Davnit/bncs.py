
from struct import pack, unpack, calcsize

def make_dword(str):
    """Converts a 4-byte string into a DWORD."""
    if len(str) != 4:
        raise ValueError("DWORD string must be exactly 4 characters.")
    return unpack('>I', str.encode('ascii'))[0]


def to_hex(b, sep=''):
    """Converts bytes into a hex string."""
    if isinstance(b, int):
        return ("00" + hex(b)[2:])[-2:]
    elif isinstance(b, (bytes, bytearray)):
        s = b.hex()
        if len(s) > 2 and sep and len(sep) > 0:
            nlen = len(s) + (len(sep) * int(len(s) / 2))
            for i in range(2, nlen - len(sep), 2 + len(sep)):
                s = s[:i] + sep + s[i:]
        return s
    else:
        raise TypeError("Unable to convert type '%s' to hex string." % type(b).__name__)


def format_buffer(data):
    """Formats a data buffer as byte values and characters."""
    if len(data) == 0:
        return

    if isinstance(data, (DataBuffer, DataReader)):
        data = data.data

    data_length = len(data)
    mod = data_length % 16

    ret = ''
    # Format _most_ of the buffer.
    for i in range(0, len(data)):
        if i != 0 and i % 16 == 0:
            ret += '\t'
            # 16 bytes at a time
            for j in range(i - 16, i):
                ret += ('.' if data[j] < 0x20 or data[j] > 0x7F else chr(data[j]))
            ret += '\n'

        ret += ('00' + hex(data[i])[2:])[-2:] + ' '

    # If the buffer length isn't a multiple of 16, add padding.
    if mod != 0:
        ret = ret.ljust(len(ret) + ((16 - mod) * 3))
        j = (data_length - mod)
    else:
        j = data_length - 16

    ret += '\t'

    # Finish the line
    for j in range(j, data_length):
        ret += ('.' if data[j] < 0x20 or data[j] > 0x7F else chr(data[j]))
    return ret + '\n'


class DataBuffer(object):
    def __init__(self, data=None):
        if isinstance(data, (bytes, bytearray)):
            self.data = data
        else:
            self.data = b''
            if isinstance(data, str):
                self.insert_string(data)
            elif isinstance(data, int):
                self.insert_dword(data)
            elif data is not None:
                raise TypeError("Unsupported generic import type.")

    def __len__(self):
        """Returns the length of the data buffer in bytes."""
        return len(self.data)

    def __str__(self):
        return format_buffer(self.data)

    def insert_raw(self, data):
        """Inserts raw binary data into the buffer. Can be a string, bytes, or a DataBuffer."""
        if isinstance(data, str):
            self.data += data.encode('ascii')
        elif isinstance(data, (DataBuffer, DataReader)):
            self.data += data.data
        else:
            self.data += data

    def insert_byte(self, b):
        """Inserts a single, unsigned byte into the buffer."""
        self.insert_raw(pack('<B', b))

    def insert_word(self, w):
        """Inserts an unsigned 16-bit WORD (or short) into the buffer."""
        self.insert_raw(pack('<H', w))

    def insert_dword(self, d):
        """Inserts an unsigned 32-bit DWORD (or int) into the buffer."""
        if isinstance(d, str):
            self.insert_dword(make_dword(d))
        else:
            self.insert_raw(pack('<I', d))

    def insert_long(self, q):
        """Inserts an unsigned 64-bit QWORD/FILETIME (or long) into the buffer."""
        self.insert_raw(pack('<Q', q))

    def insert_string(self, s, encoding='utf-8'):
        """Inserts a null-terminated string into the buffer."""
        self.insert_raw(s.encode(encoding) + b'\0')

    def insert_format(self, fmt, *args):
        """Inserts multiple objects into the buffer with the specified format from struct.pack."""
        self.insert_raw(pack(fmt, *args))

    def clear(self):
        """Clears all data from the buffer."""
        self.data = b''


class DataReader(object):
    def __init__(self, data):
        self.data = data
        self.position = 0

    def __len__(self):
        """Returns the length of the data in bytes."""
        return len(self.data)

    def __str__(self):
        return format_buffer(self.data)

    def get_raw(self, length=-1):
        """Returns the specified number of bytes from the buffer (-1 to read to the end)."""
        if length == -1:
            length = (len(self.data) - self.position)

        r = self.data[self.position:(self.position + length)]
        self.position += length
        return r

    def get_byte(self):
        """Returns the next byte from the buffer."""
        return unpack('<B', self.get_raw(1))[0]

    def get_word(self):
        """Returns the next 2 bytes as an unsigned 16-bit WORD (or short)."""
        return unpack('<H', self.get_raw(2))[0]

    def get_dword(self, as_str=False):
        """Returns the next 4 bytes as an unsigned 32-bit DWORD (or int)."""
        if as_str:
            return self.get_raw(4)[::-1].decode('ascii')
        else:
            return unpack('<I', self.get_raw(4))[0]

    def get_long(self):
        """Returns the next 8 bytes as an unisnged 64-bit QWORD/FILETIME (or long)."""
        return unpack('<Q', self.get_raw(8))[0]

    def get_string(self, encoding='utf-8', term=b'\0'):
        """Returns a string starting at the current position and going until the next NULL-byte (or sequence specified by 'term')."""
        r = self.get_raw(self.data.index(term, self.position) - self.position).decode(encoding)
        self.position += len(term)
        return r

    def get_format(self, fmt):
        """Returns multiple objects from the specified format from struct.unpack."""
        x = calcsize(fmt)
        return unpack(fmt, self.get_raw(x))

    def peek(self, size=None, pos=None, fmt=None):
        """Returns a specified number of bytes starting from the specified position in the given format."""
        size = size or 1
        pos = pos or self.position
        fmt = fmt or '<B'

        value = unpack(fmt, self.data[pos : pos + size])
        return value[0] if len(value) == 1 else value

    def eop(self):
        """Returns TRUE if the buffer has been fully read."""
        return self.position >= len(self.data)