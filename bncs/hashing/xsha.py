
from ctypes import c_byte, c_uint32

from .nls import i2b


bitmask = {
    0: 0xFFFFFF00,
    1: 0xFFFF00FF,
    2: 0xFF00FFFF,
    3: 0x00FFFFFF
}


def hash_password(password):
    """Returns the Broken-SHA hash of the given password.

    - Password is converted to lowercase before hashing (this is the spec used on the server).
    - This is used for creating accounts, where the original hash must be known."""
    return xsha1(password.lower()).digest()


def double_hash_password(password, client_token, server_token):
    """Returns the hash of the password combined with session tokens.

    - double = H(client, server, H(password))
    - This is used for normal logins, where the server already knows the single hash."""
    hash = xsha1()
    hash.update(i2b(client_token))
    hash.update(i2b(server_token))
    hash.update(hash_password(password))

    return hash.digest()


def insert_byte(buf, loc, b):
    ti = int(loc / 4)
    tb = loc % 4

    rep = (buf[ti] & bitmask[tb]) | ((ord(b) if type(b) == str else b) << (8 * tb))
    buf[ti] = rep
    return buf


def lshift(val, shift):
    return 0 if (shift > 32 or shift < 0) else val << shift


def rshift(val, shift):
    return 0 if (shift > 32 or shift < 0) else val >> shift


def rol(num, shift):
    shift &= 0x1F
    return lshift(num, shift) | rshift(num, 32 - shift)


def swap(a, b, c, d, dw):
    return dw, a, c_uint32(rol(b, 0x1E)).value, c, d


def do_hash(buffer):
    buf = [0] * 0x50

    for i in range(0, 0x10):
        buf[i] = buffer[i + 5]

    for i in range(0x10, 0x50):
        dw = buf[i - 0x3] ^ buf[i - 0x8] ^ buf[i - 0x10] ^ buf[i - 0xE]
        dw = c_byte(dw).value
        buf[i] = rol(1, dw)

    a = c_uint32(buffer[0]).value
    b = c_uint32(buffer[1]).value
    c = c_uint32(buffer[2]).value
    d = c_uint32(buffer[3]).value
    e = c_uint32(buffer[4]).value

    p = 0
    while p < 20:
        dw = rol(a, 5) + ((~b & d) | (c & b)) + e + buf[p] + 0x5a827999
        dw = c_uint32(dw).value

        a, b, c, d, e = swap(a, b, c, d, dw)
        p += 1

    while p < 40:
        dw = (d ^ c ^ b) + e + rol(a, 5) + buf[p] + 0x6ED9EBA1
        dw = c_uint32(dw).value

        a, b, c, d, e = swap(a, b, c, d, dw)
        p += 1

    while p < 60:
        dw = ((c & b) | (d & c) | (d & b)) + e + rol(a, 5) + buf[p] - 0x70E44324
        dw = c_uint32(dw).value

        a, b, c, d, e = swap(a, b, c, d, dw)
        p += 1

    while p < 80:
        dw = rol(a, 5) + e + (d ^ c ^ b) + buf[p] - 0x359D3E2A
        dw = c_uint32(dw).value

        a, b, c, d, e = swap(a, b, c, d, dw)
        p += 1

    buffer[0] = c_uint32(buffer[0] + a).value
    buffer[1] = c_uint32(buffer[1] + b).value
    buffer[2] = c_uint32(buffer[2] + c).value
    buffer[3] = c_uint32(buffer[3] + d).value
    buffer[4] = c_uint32(buffer[4] + e).value


class xsha1(object):
    def __init__(self, data=None):
        self.digest_size = 20
        self.block_size = 4
        self.name = 'xsha1'

        self._data = data or b''
        self._digest = None

    def update(self, data):
        """Adds more data to be hashed."""
        if len(data) > 0:
            self._digest = None

        self._data += data

    def digest(self):
        """Calculates the hash of all the data."""
        if self._digest is None:
            buffer = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0] + ([0] * 0x10)

            for i in range(0, len(self._data), 0x40):
                sub = len(self._data) - i
                if sub > 0x40:
                    sub = 0x40

                for j in range(0, sub):
                    insert_byte(buffer, j + 20, self._data[j + i])

                if sub < 0x40:
                    for j in range(sub, 0x40):
                        insert_byte(buffer, j + 20, '\0')

                do_hash(buffer)

            self._digest = b''
            for i in range(0, 5):
                self._digest += buffer[i].to_bytes(4, "little", signed=False)

        return self._digest

    def hexdigest(self):
        """Returns the digest hash as a hex string."""
        return self.digest().hex()

    def copy(self):
        """Returns a new XSha instance initialized with the same data as this one."""
        return xsha1(self._data)
