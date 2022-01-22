
from .bsha import xsha1

from struct import pack, unpack
from hashlib import sha1
from abc import ABC, abstractmethod


products = {
    (0x01, 13): ("StarCraft (group 1)", "STAR"),
    (0x02, 13): ("StarCraft (group 2)", "STAR"),
    (0x04, 16): ("WarCraft 2", "W2BN"),
    (0x05, 16): ("Diablo 2 Beta", ""),
    (0x05, 26): ("StarCraft 2 Beta or WoW:WotLK Alpha", ""),
    (0x06, 16): ("Diablo 2 (group 1)", "D2DV"),
    (0x07, 16): ("Diablo 2 (group 2)", "D2DV"),
    (0x09, 16): ("Diablo 2 Stress Test", ""),
    (0x0A, 16): ("Diablo 2: Lord of Destruction (group 1)", "D2XP"),
    (0x0B, 16): ("Diablo 2: Lord of Destruction Beta", ""),
    (0x0C, 16): ("Diablo 2: Lord of Destruction (group 2)", "D2XP"),
    (0x0D, 26): ("WarCraft 3 Beta", ""),
    (0x0E, 26): ("WarCraft 3 (group 1)", "WAR3"),
    (0x0F, 26): ("WarCraft 3 (group 2)", "WAR3"),
    (0x11, 26): ("WarCraft 3: The Frozen Throne Beta", ""),
    (0x12, 26): ("WarCraft 3: The Frozen Throne", "W3XP"),
    (0x13, 26): ("WarCraft 3: The Frozen Throne (China)", ""),
    (0x15, 26): ("WoW: Burning Crusade", ""),
    (0x16, 26): ("WoW: 14-day Trial", ""),
    (0x17, 26): ("StarCraft (digital)", "STAR"),
    (0x18, 26): ("Diablo 2 (digital)", "D2DV"),
    (0x19, 26): ("Diablo 2: Lord of Destruction (digital)", "D2XP"),
    (0x1A, 26): ("WoW: WotLK", ""),
    (0x1C, 26): ("StarCraft 2", ""),
    (0x1E, 26): ("Diablo 3", ""),
    (0x24, 26): ("Heroes of the Storm", "")
}

translate = bytearray(b'\x09\x04\x07\x0F\x0D\x0A\x03\x0B\x01\x02\x0C\x08\x06\x0E\x05\x00'
                      b'\x09\x0B\x05\x04\x08\x0F\x01\x0E\x07\x00\x03\x02\x0A\x06\x0D\x0C'
                      b'\x0C\x0E\x01\x04\x09\x0F\x0A\x0B\x0D\x06\x00\x08\x07\x02\x05\x03'
                      b'\x0B\x02\x05\x0E\x0D\x03\x09\x00\x01\x0F\x07\x0C\x0A\x06\x04\x08'
                      b'\x06\x02\x04\x05\x0B\x08\x0C\x0E\x0D\x0F\x07\x01\x0A\x00\x03\x09'
                      b'\x05\x04\x0E\x0C\x07\x06\x0D\x0A\x0F\x02\x09\x01\x00\x0B\x08\x03'
                      b'\x0C\x07\x08\x0F\x0B\x00\x05\x09\x0D\x0A\x06\x0E\x02\x04\x03\x01'
                      b'\x03\x0A\x0E\x08\x01\x0B\x05\x04\x02\x0F\x0D\x0C\x06\x07\x09\x00'
                      b'\x0C\x0D\x01\x0F\x08\x0E\x05\x0B\x03\x0A\x09\x00\x07\x02\x04\x06'
                      b'\x0D\x0A\x07\x0E\x01\x06\x0B\x08\x0F\x0C\x05\x02\x03\x00\x04\x09'
                      b'\x03\x0E\x07\x05\x0B\x0F\x08\x0C\x01\x0A\x04\x0D\x00\x06\x09\x02'
                      b'\x0B\x06\x09\x04\x01\x08\x0A\x0D\x07\x0E\x00\x0C\x0F\x02\x03\x05'
                      b'\x0C\x07\x08\x0D\x03\x0B\x00\x0E\x06\x0F\x09\x04\x0A\x01\x05\x02'
                      b'\x0C\x06\x0D\x09\x0B\x00\x01\x02\x0F\x07\x03\x04\x0A\x0E\x08\x05'
                      b'\x03\x06\x01\x05\x0B\x0C\x08\x00\x0F\x0E\x09\x04\x07\x0A\x0D\x02'
                      b'\x0A\x07\x0B\x0F\x02\x08\x00\x0D\x0E\x0C\x01\x06\x09\x03\x05\x04'
                      b'\x0A\x0B\x0D\x04\x03\x08\x05\x09\x01\x00\x0F\x0C\x07\x0E\x02\x06'
                      b'\x0B\x04\x0D\x0F\x01\x06\x03\x0E\x07\x0A\x0C\x08\x09\x02\x05\x00'
                      b'\x09\x06\x07\x00\x01\x0A\x0D\x02\x03\x0E\x0F\x0C\x05\x0B\x04\x08'
                      b'\x0D\x0E\x05\x06\x01\x09\x08\x0C\x02\x0F\x03\x07\x0B\x04\x00\x0A'
                      b'\x09\x0F\x04\x00\x01\x06\x0A\x0E\x02\x03\x07\x0D\x05\x0B\x08\x0C'
                      b'\x03\x0E\x01\x0A\x02\x0C\x08\x04\x0B\x07\x0D\x00\x0F\x06\x09\x05'
                      b'\x07\x02\x0C\x06\x0A\x08\x0B\x00\x0F\x04\x03\x0E\x09\x01\x0D\x05'
                      b'\x0C\x04\x05\x09\x0A\x02\x08\x0D\x03\x0F\x01\x0E\x06\x07\x0B\x00'
                      b'\x0A\x08\x0E\x0D\x09\x0F\x03\x00\x04\x06\x01\x0C\x07\x0B\x02\x05'
                      b'\x03\x0C\x04\x0A\x02\x0F\x0D\x0E\x07\x00\x05\x08\x01\x06\x0B\x09'
                      b'\x0A\x0C\x01\x00\x09\x0E\x0D\x0B\x03\x07\x0F\x08\x05\x02\x04\x06'
                      b'\x0E\x0A\x01\x08\x07\x06\x05\x0C\x02\x0F\x00\x0D\x03\x0B\x04\x09'
                      b'\x03\x08\x0E\x00\x07\x09\x0F\x0C\x01\x06\x0D\x02\x05\x0A\x0B\x04'
                      b'\x03\x0A\x0C\x04\x0D\x0B\x09\x0E\x0F\x06\x01\x07\x02\x00\x05\x08')


def get_hex(v):
    v &= 0xF
    return chr(v + 0x30) if v < 10 else chr(v + 0x37)


class KeyDecoder(ABC):
    @classmethod
    def get(cls, key):
        """Returns the appropriate decoder for the given key.

        key: the CD key to decode
        """
        decoder = decoder_lookup.get(len(key))
        if not decoder:
            raise ValueError("Unsupported key length: %i" % len(key))
        return decoder(key)

    def __init__(self, key):
        self.key = key.upper()
        self.product = 0
        self.public = 0
        self.private = 0
        self.unknown = 0

    def __len__(self):
        return len(self.key)

    @abstractmethod
    def decode(self):
        """Decodes the key to determine its product, public, and private values.

        - Returns True if the key was successfully decoded."""
        return False

    @classmethod
    @abstractmethod
    def encode(cls, product, public, private):
        """Encodes a key from existing product, public, and private values."""
        pass

    @abstractmethod
    def get_hash(self, client_token, server_token):
        """Returns the 20-byte hash sent to the server to verify the key.

        client_token: the DWORD value generated by the client and sent to the server during authentication
        server_token: the DWORD value receive by the server during authentication
        """
        if None in [self.product, self.public, self.private]:
            if not self.decode():
                return False
        return True

    def _get_lookup_key(self):
        return self.product, len(self.key)

    def get_product_name(self):
        """Returns the full name of the product the key is associated with."""
        pk = self._get_lookup_key()
        return products[pk][0] if pk in products else 'Unknown'

    def get_product_code(self):
        """Returns the 4-digit product code the key is associated with."""
        pk = self._get_lookup_key()
        return products[pk][1] if pk in products else '????'

    def _preset(self, product, public, private):
        self.product = product
        self.public = public
        self.private = private
        return self

    @staticmethod
    def create_key(length, product, public, private):
        decoder = decoder_lookup.get(length)
        if not decoder:
            raise ValueError("Invalid key length")

        return decoder.encode(product, public, private)


class SCKeyDecoder(KeyDecoder):
    SALT = 0x13AC9741
    ALPHA = (6, 0, 2, 9, 3, 11, 1, 7, 5, 4, 10, 8)

    def __init__(self, key):
        super().__init__(key)
        if len(key) != 13:
            raise ValueError("SC key decoder only valid for 13-digit keys")

    def get_hash(self, client_token, server_token):
        if not super().get_hash(client_token, server_token):
            return None

        buf = pack('6L', client_token, server_token, self.product, self.public, self.unknown, self.private)
        return xsha1(buf).digest()

    @staticmethod
    def _get_check_digit(value):
        chk = 3
        for i in range(0, 12):
            chk += ((value[i] - 48) ^ (chk * 2))
        return str(chk % 10)

    def decode(self):
        key = [ord(v) for v in self.key]
        decoded = [0] * 12
        salt = self.SALT

        for i in range(11, -1, -1):
            c = key[self.ALPHA[i]]
            if c <= 55:
                decoded[i] = (c ^ (salt & 7))
                salt >>= 3
            else:
                decoded[i] = (c ^ i & 1)

        valid = chr(key[-1]) == self._get_check_digit(key)
        if valid:
            value = ''.join(chr(v) for v in decoded)
            self.product = int(value[0:2])
            self.public = int(value[2:9])
            self.private = int(value[9:12])

        return valid

    @classmethod
    def encode(cls, product, public, private):
        encoded = [0] * 12
        salt = cls.SALT

        key = str(product).rjust(2, '0') + str(public).rjust(7, '0') + str(private).rjust(3, '0')

        for i in range(11, -1, -1):
            c = ord(key[i])
            if c <= 55:
                encoded[cls.ALPHA[i]] = (c ^ (salt & 7))
                salt >>= 3
            else:
                encoded[cls.ALPHA[i]] = (c ^ i & 1)

        check_digit = cls._get_check_digit(encoded)
        return cls(''.join([chr(i) for i in encoded]) + check_digit)._preset(product, public, private)


class D2KeyDecoder(KeyDecoder):
    SALT = 0x13AC9741
    ALPHA = (5, 6, 0, 1, 2, 3, 4, 9, 10, 11, 12, 13, 14, 15, 7, 8)
    CHARS = "246789BCDEFGHJKMNPRTVWXZ"

    def __init__(self, key):
        super().__init__(key)
        if len(key) != 16:
            raise ValueError("D2 key decoder only valid for 16-character keys")

    def get_hash(self, client_token, server_token):
        if not super().get_hash(client_token, server_token):
            return None

        buf = pack('6L', client_token, server_token, self.product, self.public, self.unknown, self.private)
        return xsha1(buf).digest()

    def decode(self):
        key = list(self.key)
        decoded = [0] * 16
        salt = self.SALT

        for i in range(0, 15, 2):
            if key[i] not in self.CHARS or key[i + 1] not in self.CHARS:
                return False

            n = self.CHARS.index(key[i + 1]) + (self.CHARS.index(key[i]) * 24) & 0xff
            key[i] = chr((((n >> 4) & 0xf) + 0x30) if (((n >> 4) & 0xf) < 10) else (((n >> 4) & 0xf) + 0x37))
            key[i + 1] = chr(((n & 0xf) + 0x30) if ((n & 0xf) < 10) else ((n & 0xf) + 0x37))

        for i in range(15, -1, -1):
            c = ord(key[self.ALPHA[i]])
            if c <= 55:
                decoded[i] = (c ^ (salt & 7))
                salt >>= 3
            elif c < 65:
                decoded[i] = (c ^ i & 1)
            else:
                decoded[i] = c

        dec = ''.join(chr(v) for v in decoded)
        self.product = int(dec[0:2], 16)
        self.public = int(dec[2:8], 16)
        self.private = int(dec[8:16], 16)

        return True

    @classmethod
    def encode(cls, product, public, private):
        salt = cls.SALT
        encoded = [0] * 16

        key = hex(product)[2:].rjust(2, '0') + hex(public)[2:].rjust(6, '0') + hex(private)[2:].rjust(8, '0')
        key = key.upper()

        for i in range(15, -1, -1):
            c = ord(key[i])
            if c <= 55:     # '7'
                encoded[cls.ALPHA[i]] = (c ^ (salt & 7))
                salt >>= 3
            elif c < 65:    # 'A'
                encoded[cls.ALPHA[i]] = (c ^ i & 1)
            else:
                encoded[cls.ALPHA[i]] = c

        def pc(dig):
            return (dig - 0x30) if chr(dig).isdigit() else (ord(chr(dig).upper()) - 0x37)

        r = 3
        for i in range(0, 16):
            r += pc(encoded[i]) ^ (r * 2)
        r &= 0xff

        tb = 0x80
        for i in range(14, -1, -2):
            a, b = pc(encoded[i]), pc(encoded[i + 1])
            a = int(hex(a)[2:] + hex(b)[2:], 16)

            if r & tb:
                a += 0x100

            b = 0
            while a >= 0x18:
                b += 1
                a -= 0x18

            encoded[i] = ord(cls.CHARS[b])
            encoded[i + 1] = ord(cls.CHARS[a])
            tb //= 2

        return cls(''.join([chr(i) for i in encoded]))._preset(product, public, private)


class W3KeyDecoder(KeyDecoder):
    CHARS = "246789BCDEFGHJKMNPRTVWXYZ"
    ALPHA = (30, 27, 24, 21, 18, 15, 12, 9, 6, 3, 0, 49, 46, 43, 40, 37, 34, 31, 28, 25,
             22, 19, 16, 13, 10, 7, 4, 1, 50, 47, 44, 41, 38, 35, 32, 29, 26, 23, 20, 17,
             14, 11, 8, 5, 2, 51, 48, 45, 42, 39, 36, 33)
    ORDER = (8, 9, 4, 5, 6, 7, 0, 1, 2, 3)

    def __init__(self, key):
        super().__init__(key)
        if len(key) != 26:
            raise ValueError("W3 key decoder only valid for 26-character keys")
        self.private = bytes(10)

    def get_hash(self, client_token, server_token):
        if not super().get_hash(client_token, server_token):
            return None

        buf = pack('<2L2L10B', client_token, server_token, self.product, self.public, *self.private[:10])
        return sha1(buf).digest()

    def decode(self):
        key = list(self.key)
        digits_b5 = bytearray(52)       # buffer, 2x key length

        for i in range(0, 26):
            if key[i] not in self.CHARS:
                return False

            c = self.CHARS.index(key[i])
            digits_b5[self.ALPHA[i * 2]] = (c // 5) & 0xff
            digits_b5[self.ALPHA[i * 2 + 1]] = (c % 5) & 0xff

        n = 0
        for i in range(51, -1, -1):
            n = n * 5 + digits_b5[i]

        b = n.to_bytes(16, byteorder='little')
        nibbles = bytearray(30)
        for i in range(0, 15):
            for j in range(0, 2):
                nibbles[(i << 1) + j] = ((b[i] >> (j << 2)) & 0xf) & 0xff

        for r in range(29, -1, -1):
            index = r * 16
            perm = translate[index:index+16]
            c = nibbles[r]

            for r2 in range(29, -1, -1):
                if r == r2:
                    continue

                c = perm[nibbles[r2] ^ perm[c]]

            nibbles[r] = perm[c]

        length = (len(nibbles) >> 1) - 1
        tmp = bytearray(length + 1)
        for i in range(0, length + 1):
            ni = i << 1
            tmp[i] = nibbles[ni] | (nibbles[ni | 1] << 4)

        bits = [bit == '1' for bit in ''.join(format(byte, '08b')[::-1] for byte in tmp)]
        for i in range(0, 120):
            j = (i * 11) % 120
            if j <= i:
                continue

            b = bits[i]
            bits[i] = bits[j]
            bits[j] = b

        bb = bytearray(16)
        for i in range(0, 15):
            for j in range(0, 8):
                if bits[(i << 3) + j]:
                    bb[i] = bb[i] | ((1 << j) & 0xff)

        if bb[14] == 0:
            self.product = bb[13] >> 2
            self.public = unpack('<L', bytes(bb[10:14]))[0] & 0x03ffffff
            self.private = bytes(bb[self.ORDER[i]] for i in range(10))
            return True

        return False

    @classmethod
    def encode(cls, product, public, private):
        if isinstance(private, int):
            private = private.to_bytes(10, 'little')

        bb = bytearray(16)
        for i in range(0, 10):
            bb[cls.ORDER[i]] = private[i]
        bb[10:14] = pack('<L', public)
        bb[13] = bb[13] | (product << 2)

        bits = [bit == '1' for bit in ''.join(format(byte, '08b')[::-1] for byte in bb)]
        for i in range(0, 120):
            j = (i * 11) % 120
            if j <= i:
                continue

            b = bits[i]
            bits[i] = bits[j]
            bits[j] = b

        nibbles = bytearray(30)
        for i in range(0, 30):
            for j in range(3, -1, -1):
                if bits[i * 4 + j]:
                    nibbles[i] = nibbles[i] | (0x01 << j)

        for r in range(0, 30):
            index = r * 16
            perm = translate[index:index+16]
            c = perm.index(nibbles[r])

            for r2 in range(0, 30):
                if r == r2:
                    continue

                c = perm.index(nibbles[r2] ^ perm.index(c))

            nibbles[r] = c

        length = (len(nibbles) >> 1) - 1
        tmp = bytearray(length + 1)
        for i in range(0, length + 1):
            ni = i << 1
            tmp[i] = nibbles[ni] | (nibbles[ni | 1] << 4)

        n = int.from_bytes(tmp, byteorder='little')
        digits_b5 = bytearray(52)
        for i in range(0, 52):
            digits_b5[i] = n % 5
            n = (n - digits_b5[i]) // 5

        key = ""
        for i in range(0, 26):
            bc = (digits_b5[cls.ALPHA[i * 2]] * 5) + (digits_b5[cls.ALPHA[i * 2 + 1]])
            key += cls.CHARS[bc]

        return cls(key)._preset(product, public, private)


decoder_lookup = {
    13: SCKeyDecoder,
    16: D2KeyDecoder,
    26: W3KeyDecoder
}
