
import array
import ctypes
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


"""
    Sample values:
        Input: The quick brown fox jumps over the lazy dog
        XSha1: a0db6e70616033a7b5fdda37cee2d43f2da10288
        LSha1: a868fb6c0d95c48d037e9f08ce6e4200fd435fa4
        
    Unlike some implementations of this hash, this one will not modify the buffer when calling digest(),
        so it is a safe operation. You can optionally pass finalize=True to the digest() call to override
        this behavior.
"""


TRANSFORM_KEYS = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6]


class BnetSha1:
    digest_size = 20
    block_size = 64

    def __init__(self, lockdown=False):
        self.lockdown = lockdown
        self.name = "lockdown-sha1" if lockdown else "bnet-sha1"

        self._state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
        self._length = 0                # Total length of all data passed into the hash

        self._buffer = memoryview(bytearray(self.block_size))       # The input buffer
        self._position = 0                                          # Position in the input buffer

    def debug(self):
        return struct.pack('<5L', *self._state).hex()

    def digest(self):
        state = array.array('L', self._state)

        if len(self._buffer) > 0:
            # There is uncommitted data, process it.
            block = bytearray(self._buffer)
            position = self._position

            # If there is less than a block of data, pad it.
            if self.lockdown:
                # Standard SHA-1 padding
                if position > 55:
                    # Not enough room for the tail, finish this block and then do another.
                    block[position] = 0x80
                    block[position+1:] = bytes(self.block_size - position - 1)
                    self._transform(state, block)
                    position = 0
                else:
                    block[position] = 0x80
                    position += 1

                # Pad the block and add the full data length at the end
                length = self._length + self._position
                block[position:] = bytes(self.block_size - position - 8) + struct.pack('<Q', length * 8)
            else:
                # xSHA padding
                block[position:] = bytes(self.block_size - position)

            # Transform with the padding
            self._transform(state, block)

        return struct.pack(f'<{self.digest_size // 4}L', *state[:5])

    def hexdigest(self):
        return self.digest().hex()

    def update(self, *data):
        for item in (data,) if not isinstance(data, tuple) else data:
            while len(item) > 0:
                # Add as much data to the input buffer as will fit
                length = min(len(item), self.block_size - self._position)
                self._buffer[self._position:self._position+length] = item[:length]
                self._position += length

                # If the input buffer is full, process it.
                if self._position == self.block_size:
                    self._transform(self._state, self._buffer.obj)
                    self._length += self.block_size
                    self._position = 0

                # If the whole item wouldn't fit, trim it for the next round
                item = item[length:]

        return self

    def copy(self):
        new = BnetSha1(self.lockdown)
        new._state = list(self._state)
        new._buffer = memoryview(bytearray(self._buffer))
        new._length = self._length
        new._position = self._position
        return new

    def _transform(self, state, buffer):
        # Copy bytes from the input buffer into ints
        w = array.array('L', buffer)
        w.extend([0] * self.block_size)

        # Xors
        for i in range(len(w) - self.block_size, len(w)):
            value = (w[i - 16] ^ w[i - 8] ^ w[i - 14] ^ w[i - 3])
            if self.lockdown:
                w[i] = (value >> 0x1f) | ctypes.c_ulong((value << 1)).value
            else:
                w[i] = 1 << (value & 31)

        a, b, c, d, e = state[:5]
        for i in range(len(w)):
            # Steps - different operations for different blocks of the transform
            if i < 20:
                dw = (b & c) | (~b & d)
            elif i < 40:
                dw = b ^ c ^ d
            elif i < 60:
                dw = (b & c) | (b & d) | (c & d)
            else:
                dw = b ^ c ^ d

            # Key and shuffle
            dw = (((a << 5) | (a >> 0x1b)) + dw + e + w[i] + TRANSFORM_KEYS[i // 20]) % (2 ** 32)
            a, b, c, d, e = (dw, a, (b >> 2) | (b << 0x1e), c, d)

        # Replace
        finals = (a, b, c, d, e)
        for i in range(5):
            state[i] = (state[i] + finals[i]) & 0xffffffff
