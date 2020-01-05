
from calendar import timegm
from datetime import datetime, timedelta, tzinfo
from socket import inet_ntoa, inet_aton
from struct import pack, unpack, calcsize


# Used for converting python datetime objects to and from FILETIME structures.
_EPOCH_AS_FILETIME = 116444736000000000
_HUNDREDS_OF_NANOS = 10000000
_ZERO = timedelta(0)


class _UTC(tzinfo):
    def utcoffset(self, dt):
        return _ZERO

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return _ZERO


_utc = _UTC()


def make_dword(v):
    """ Creates a DWORD from a string. """
    if isinstance(v, str) and len(v) <= 4:
        v = v.rjust(4, '\0')
        return unpack('>I', v.encode('ascii'))[0]
    else:
        raise TypeError("DWORD must be a string with at most 4 characters.")


def format_buffer(data):
    """ Formats binary data in a human-friendly manner. """
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


class DataBuffer:
    def __init__(self, data=None):
        if isinstance(data, (bytes, bytearray)):
            self.data = data
        elif data is None:
            self.data = b''
        else:
            raise TypeError("Unsupported data buffer initialization type: %s" % type(data).__name__)

    def __len__(self):
        return len(self.data)

    def __str__(self):
        return "Buffer: %i bytes" % len(self.data)

    def __repr__(self):
        return format_buffer(self.data)

    def insert_raw(self, data):
        """ Inserts raw binary data into the buffer.

            Accepts str, bytes, and DataBuffer/DataReader objects.
        """
        if isinstance(data, str):
            self.data += data.encode('ascii')
        elif isinstance(data, (DataBuffer, DataReader)):
            self.data += data.data
        else:
            self.data += data

    def insert_byte(self, b):
        """ Inserts an unsigned byte to the end of the buffer. """
        self.insert_raw(pack('<B', b))

    def insert_word(self, w):
        """ Inserts an unsigned 16-bit WORD to the end of the buffer. """
        self.insert_raw(pack('<H', w))

    def insert_dword(self, d):
        """ Inserts an unsigned 32-bit DWORD to the end of the buffer. """
        if isinstance(d, str):
            self.insert_dword(make_dword(d))
        else:
            self.insert_raw(pack('<I', d))

    def insert_long(self, q):
        """ Inserts an unsigned 64-bit QWORD/FILETIME to the end of the buffer. """
        self.insert_raw(pack('<Q', q))

    def insert_string(self, s, encoding='utf-8', term=b'\0'):
        """ Inserts a terminated string to the end of the buffer.

            If term is omitted, a null-byte will be used.
        """
        self.insert_raw(s.encode(encoding) + term)

    def insert_ipv4(self, ipv4):
        """ Inserts an IPv4 address as a 4-byte DWORD. """
        self.insert_raw(inet_aton(ipv4))

    def insert_filetime(self, dt):
        """ Inserts a python datetime object to the end of the buffer as a 64-bit FILETIME. """
        if dt.tzinfo is None or (dt.tzinfo.utcoffset(dt) is None):
            dt = dt.replace(tzinfo=_utc)
        ft = _EPOCH_AS_FILETIME + (timegm(dt.timetuple()) * _HUNDREDS_OF_NANOS)
        self.insert_long(ft + (dt.microsecond * 10))

    def insert_format(self, fmt, *args):
        """ Inserts multiple objects into the buffer with the specified format from struct.pack. """
        self.insert_raw(pack(fmt, *args))

    def clear(self):
        """ Clears all data from the buffer. """
        self.data = b''


class DataReader:
    def __init__(self, data=b''):
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Unsupported data reader initialization type: %s" % type(data).__name__)
        self.data = data
        self.position = 0

    def __len__(self):
        return len(self.data)

    def __str__(self):
        return "Reader: %i bytes, position: %i" % (len(self.data), self.position)

    def __repr__(self):
        return format_buffer(self.data)

    def get_raw(self, length=-1, peek=False):
        """ Returns raw data from the buffer.

            If length is omitted or -1, all remaining data will be returned.
        """
        if length == -1:
            length = (len(self.data) - self.position)

        r = self.data[self.position:(self.position + length)]
        if not peek:
            self.position += length
        return r

    def get_byte(self, peek=False):
        """ Returns the next byte from the buffer. """
        return unpack('<B', self.get_raw(1, peek))[0]

    def get_word(self, peek=False):
        """ Returns the next 2 bytes as an unsigned 16-bit WORD. """
        return unpack('<H', self.get_raw(2, peek))[0]

    def get_dword(self, as_str=False, peek=False):
        """ Returns the next 4 bytes as an unsigned 32-bit DWORD. """
        if as_str:
            return self.get_raw(4, peek)[::-1].decode('ascii')
        else:
            return unpack('<I', self.get_raw(4, peek))[0]

    def get_long(self, peek=False):
        """ Returns the next 8 bytes as an unsigned 64-bit QWORD/FILETIME. """
        return unpack('<Q', self.get_raw(8, peek))[0]

    def get_string(self, encoding='utf-8', term=b'\0', peek=False):
        """ Returns a string starting at the current position and going to the next occurrence of term.

            If term is omitted, a null-byte will be used.
            This is the opposite of DataBuffer.insert_string().
        """
        r = self.get_raw(self.data.index(term, self.position) - self.position, peek).decode(encoding)
        self.position += len(term)
        return r

    def get_ipv4(self, peek=False):
        """ Returns the next 4 bytes as an IPv4 address string. """
        return inet_ntoa(self.get_raw(4, peek))

    def get_filetime(self, peek=False):
        """ Returns the next 8 bytes as a python datetime object. """
        ft = self.get_long(peek)
        if ft == 0:
            return None
        (s, ns100) = divmod(ft - _EPOCH_AS_FILETIME, _HUNDREDS_OF_NANOS)
        dt = datetime.utcfromtimestamp(s)
        return dt.replace(microsecond=(ns100 // 10))

    def get_format(self, fmt, peek=False):
        """ Returns multiple objects from the specified format from struct.unpack. """
        x = calcsize(fmt)
        return unpack(fmt, self.get_raw(x, peek))

    def eop(self):
        """ Returns TRUE if the buffer has been fully read. """
        return self.position >= len(self.data)
