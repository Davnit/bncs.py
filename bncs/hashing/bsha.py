
import struct


def hash_password(password):
    """Returns the XSha1 hash of the given password. Used for account creation."""
    return xsha1(password.lower().encode()).digest()


def double_hash_password(password, client_token, server_token):
    """Returns the XSha1 hash of the given password and session tokens. Used for account login."""
    return xsha1(struct.pack('<2L', client_token, server_token), hash_password(password)).digest()


def xsha1(*data):
    """Returns a hashlib-compatible instance of Battle.net's XSHA-1 hashing algorithm. """
    return BnetSha1().update(*data)


def lockdown_sha1(*data):
    """Returns a hashlib-compatible instance of Battle.net's LSHA-1 hashing algorithm."""
    return BnetSha1(lockdown=True).update(*data)


def _rotl(num, shift, width=32):
    return (num << shift & (2 ** width - 1)) | (num >> width - shift)


"""
    Sample values:
        Input: The quick brown fox jumps over the lazy dog
        XSha1: a0db6e70616033a7b5fdda37cee2d43f2da10288
        LSha1: a868fb6c0d95c48d037e9f08ce6e4200fd435fa4
        
    Unlike some implementations of this hash, this one will not modify the buffer when calling digest(),
        so it is a safe operation. You can optionally pass finalize=True to the digest() call to override
        this behavior.
"""


class BnetSha1:
    digest_size = 20
    block_size = 64

    def __init__(self, lockdown=False):
        self.lockdown = lockdown
        self.name = "lockdown-sha1" if lockdown else "bnet-sha1"
        self._buffer = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
        self._block = bytearray()
        self._length = 0
        self.finalized = False

    def debug(self):
        return struct.pack('<5L', *self._buffer).hex()

    def digest(self, finalize=False):
        buffer = self._buffer

        if len(self._block) > 0:
            block = self._block

            # If there is less than a block of data, pad it.
            if self.lockdown:
                length = self._length + len(block)

                # Standard SHA-1 padding
                if len(block) > 55:
                    # Not enough room for the tail, finish this block and then do another.
                    block += b'\x80' + bytes(self.block_size - len(block) - 1)
                    buffer = self._transform(buffer, block)
                    block = block[64:]
                else:
                    block += b'\x80'

                block += bytes(self.block_size - len(block) - 8)
                block += struct.pack('<Q', length * 8)
            else:
                # xSHA padding
                block += bytes(self.block_size - len(block))

            # Transform with the padding (but do not commit!)
            buffer = self._transform(buffer, block)

        if finalize:
            self._block = bytearray()
            self._buffer = buffer
            self.finalized = True

        return struct.pack(f'<{self.digest_size // 4}L', *buffer[0:5])

    def hexdigest(self):
        return self.digest().hex()

    def update(self, *data):
        self._block += b''.join(data)

        while len(self._block) >= self.block_size:
            self._buffer[0:5] = self._transform(self._buffer, self._block)
            self._block = self._block[64:]
            self._length += 64

        return self

    def _transform(self, buffer, block):
        w = [0] * 80
        w[0:16] = struct.unpack_from('<16L', block, 0)

        for i in range(16, 80):
            value = (w[i - 16] ^ w[i - 8] ^ w[i - 14] ^ w[i - 3])
            w[i] = _rotl(value, 1) if self.lockdown else _rotl(1, value & 31)

        keys = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6]
        a, b, c, d, e = buffer[0:5]
        for i in range(0, 80):
            if i < 20:
                dw = (b & c) | (~b & d)
            elif i < 40:
                dw = b ^ c ^ d
            elif i < 60:
                dw = (b & c) | (b & d) | (c & d)
            else:
                dw = b ^ c ^ d

            dw = (_rotl(a, 5) + dw + e + w[i] + keys[i // 20]) % (2 ** 32)
            a, b, c, d, e = (dw, a, _rotl(b, 0x1e), c, d)

        finals = (a, b, c, d, e)
        return [(buffer[i] + finals[i]) & 0xffffffff for i in range(5)]
