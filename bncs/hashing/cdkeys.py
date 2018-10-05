
from bncs.hashing.xsha import xsha1

from struct import pack, unpack
from ctypes import c_byte, c_int32, c_uint32
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

key_table = bytearray(b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'
                      b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'
                      b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'
                      b'\xFF\xFF\x00\xFF\x01\xFF\x02\x03\x04\x05\xFF\xFF\xFF\xFF\xFF\xFF'
                      b'\xFF\xFF\x06\x07\x08\x09\x0A\x0B\x0C\xFF\x0D\x0E\xFF\x0F\x10\xFF'
                      b'\x11\xFF\x12\xFF\x13\xFF\x14\x15\x16\x17\x18\xFF\xFF\xFF\xFF\xFF'
                      b'\xFF\xFF\x06\x07\x08\x09\x0A\x0B\x0C\xFF\x0D\x0E\xFF\x0F\x10\xFF'
                      b'\x11\xFF\x12\xFF\x13\xFF\x14\x15\x16\x17\x18\xFF\xFF\xFF\xFF\xFF'
                      b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'
                      b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'
                      b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'
                      b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'
                      b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'
                      b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'
                      b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'
                      b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF')

alpha_map = [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
             -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
             -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0x00,
             -1, 0x01, -1, 0x02, 0x03, 0x04, 0x05, -1, -1, -1, -1, -1, -1, -1, -1,
             0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, -1, 0x0D, 0x0E, -1, 0x0F,
             0x10, -1, 0x11, -1, 0x12, -1, 0x13, -1, 0x14, 0x15, 0x16, -1, 0x17,
             -1, -1, -1, -1, -1, -1, -1, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
             -1, 0x0D, 0x0E, -1, 0x0F, 0x10, -1, 0x11, -1, 0x12, -1, 0x13, -1,
             0x14, 0x15, 0x16, -1, 0x17, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
             -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
             -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
             -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
             -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
             -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
             -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
             -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
             -1, -1, -1, -1]


def get_hex(v):
    v &= 0xF
    return chr(v + 0x30) if v < 10 else chr(v + 0x37)


class KeyDecoder(ABC):
    @classmethod
    def get(cls, key):
        """Returns the appropriate decoder for the given key."""
        length = len(key)
        if length == 13:
            return SCKeyDecoder(key)
        elif length == 16:
            return D2KeyDecoder(key)
        elif length == 26:
            return W3KeyDecoder(key)
        else:
            raise ValueError("Unsupported key length: %i" % length)

    def __init__(self, key):
        self.key = key.upper()
        self.product = None
        self.public = None
        self.private = None

    def __len__(self):
        return len(self.key)

    @abstractmethod
    def decode(self):
        """Decodes the key to determine its product, public, and private values.

        - Returns True if the key was successfully decoded."""
        return False

    @abstractmethod
    def get_hash(self, client_token, server_token):
        """Returns the 20-byte hash sent to the server to verify the key."""
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
        return products[pk][1] if pk in products else ''


class SCKeyDecoder(KeyDecoder):
    def __init__(self, key):
        super().__init__(key)
        if len(key) != 13:
            raise ValueError("SC key decoder only valid for 13-digit keys")

    def get_hash(self, client_token, server_token):
        if not super().get_hash(client_token, server_token):
            return None

        buf = pack('6L', client_token, server_token, self.product, self.public, 0, self.private)
        return xsha1(buf).digest()

    def decode(self):
        key_list = list(self.key)
        key_str = self.key.lower()

        # Verify
        accum = 3
        for i in range(len(key_str) - 1):
            accum += (ord(key_str[i]) - 48) ^ (accum * 2)

        if (accum % 10) != (ord(key_str[12]) - 48):
            return False

        # Shuffle
        a = 0x0B
        for i in range(0xC2, 0x06, -0x11):
            b = (i % 0x0C)
            key_list[a], key_list[b] = key_list[b], key_list[a]
            a -= 1

        # Get values
        hash_key = 0x13AC9741
        key_str = ''.join(key_list)
        for i in range(len(key_str) - 2, -1, -1):
            if key_str[i] <= '7':
                key_list[i] = chr(ord(key_list[i]) ^ (hash_key & 7))
                hash_key >>= 3
            elif key_str[i] < 'A':
                key_list[i] = chr(ord(key_list[i]) ^ (i & 1))

        dec = ''.join(key_list)
        self.product = int(dec[0:2])
        self.public = int(dec[2:9])
        self.private = int(dec[9:12])

        return True


class D2KeyDecoder(KeyDecoder):
    def __init__(self, key):
        super().__init__(key)
        if len(key) != 16:
            raise ValueError("D2 key decoder only valid for 16-character keys")

    def get_hash(self, client_token, server_token):
        if not super().get_hash(client_token, server_token):
            return None

        buf = pack('6L', client_token, server_token, self.product, self.public, 0, self.private)
        return xsha1(buf).digest()

    def decode(self):
        checksum = 0
        key_list = list(self.key)

        for i in range(0, len(self.key), 2):
            r = 1
            c1 = alpha_map[ord(self.key[i])]
            n = c1 * 3
            c2 = alpha_map[ord(self.key[i + 1])]
            n = c2 + (n * 8)

            if n >= 0x100:
                n -= 0x100
                checksum |= int(2 ** (i / 2))

            n2 = n >> 4
            key_list[i] = get_hex(n2)
            key_list[i + 1] = get_hex(n)

            r <<= 1

        v = 3
        for i in range(16):
            c = key_list[i].upper()
            n = (ord(c) - 0x30) if c.isdigit() else (ord(c) - 0x37)
            n2 = v * 2
            n ^= n2
            v += n

        v &= 0xFF
        if v != checksum:
            return False

        for i in range(15, -1, -1):
            c = ord(key_list[i])
            n = (i - 9) if i > 8 else (0xF - (8 - i))
            n &= 0xF
            c2 = ord(key_list[n])

            key_list[i] = chr(c2)
            key_list[n] = chr(c)

        v2 = 0x13AC9741
        for i in range(15, -1, -1):
            c = ord(key_list[i].upper())
            key_list[i] = chr(c)

            if key_list[i] <= '7':
                v = v2
                c2 = ((c_byte(v & 0xFF).value & 7) ^ c)
                v >>= 3

                key_list[i] = chr(c2)
                v2 = v
            elif key_list[i] < 'A':
                c2 = ((c_byte(i).value & 1) ^ c)
                key_list[i] = chr(c2)

        dec = ''.join(key_list)
        self.product = int(dec[0:2], 16)
        self.public = int(dec[2:8], 16)
        self.private = int(dec[8:16], 16)

        return True


class W3KeyDecoder(KeyDecoder):
    def __init__(self, key):
        super().__init__(key)
        if len(key) != 26:
            raise ValueError("W3 key decoder only valid for 26-character keys")

    def get_hash(self, client_token, server_token):
        if not super().get_hash(client_token, server_token):
            return None

        buf = pack('<2L2L10b', client_token, server_token, self.product, self.public, *self.private[:10])
        return sha1(buf).digest()

    def decode(self):
        table = [0] * 52
        values = [0] * 4

        # Key table lookup
        b = 0x21
        for i in range(26):
            a = (b + 0x07B5) % 52
            b = (a + 0x07B5) % 52

            key = key_table[ord(self.key[i])]
            table[a] = int(key / 5)
            table[b] = int(key % 5)

        # Mult
        rounds = 4
        mulx = 5
        for i in range(52, 0, -1):
            pos_a = pos_b = rounds - 1
            byte = table[i - 1]

            for j in range(0, rounds):
                p1 = values[pos_a] & 0x00000000FFFFFFFF
                pos_a -= 1

                p2 = mulx & 0x00000000FFFFFFFF
                edxeax = p1 * p2

                values[pos_b] = c_int32(byte + c_int32(edxeax).value).value
                byte = c_int32(edxeax >> 32).value
                pos_b -= 1

        # Key Table Pass #1
        var_8 = 29
        for i in range(464, -1, -16):
            esi = (var_8 & 7) << 2
            var_4 = var_8 >> 3
            var_c = (values[3 - var_4] & (0x0F << esi)) >> esi

            if i < 464:
                for j in range(29, var_8, -1):
                    ecx = (j & 7) << 2
                    ebp = (values[0x03 - (j >> 3)] & (0x0F << ecx)) >> ecx
                    var_c = translate[ebp ^ translate[var_c + i] + i]

            var_8 -= 1
            for j in range(var_8, -1, -1):
                ecx = (j & 7) << 2
                ebp = (values[0x03 - (j >> 3)] & (0x0F << ecx)) >> ecx
                var_c = translate[ebp ^ translate[var_c + i] + i]

            index = 3 - var_4
            ebx = (translate[var_c + i] & 0x0F) << esi
            values[index] = (ebx | ~(0x0F << esi) & values[index])

        # Key Table Pass #2
        for i in range(len(values)):
            values[i] = c_int32(values[i]).value

        esi = 0
        copy = pack('<4l', *values)
        for edi in range(0, 120):
            eax = edi & 0x1F
            ecx = esi & 0x1F
            edx = 3 - (edi >> 5)

            loc = 12 - ((esi >> 5) << 2)
            ebp = unpack('<l', copy[loc:loc+4])[0]
            ebp = (ebp & (1 << ecx)) >> ecx

            values[edx] = c_int32(((ebp & 1) << eax) | (~(1 << eax) & values[edx])).value

            esi += 0x0B
            if esi > 120:
                esi -= 120

        # Get values
        self.product = values[0] >> 0x0A
        self.public = ((values[0] & 0x03FF) << 0x10) | c_int32(c_uint32(values[1]).value >> 0x10).value

        self.private = [0] * 10
        self.private[0] = c_byte((values[1] & 0x00FF) >> 0).value
        self.private[1] = c_byte((values[1] & 0xFF00) >> 8).value
        self.private[2:6] = unpack('<4b', pack('<l', values[2]))
        self.private[6:10] = unpack('<4b', pack('<l', values[3]))

        return True
