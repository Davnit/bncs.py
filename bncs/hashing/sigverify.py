
from bncs.hashing.nls import b2i, i2b
from bncs.common.buffer import DataBuffer

from socket import inet_aton


DEFAULT_KEY = bytearray(b'\x01\x00\x01\x00')

DEFAULT_MOD = bytearray(b'\xD5\xA3\xD6\xAB\x0F\x0D\xC5\x0F\xC3\xFA\x6E\x78\x9D\x0B\xE3\x32'
                        b'\xB0\xFA\x20\xE8\x42\x19\xB4\xA1\x3A\x3B\xCD\x0E\x8F\xB5\x56\xB5'
                        b'\xDC\xE5\xC1\xFC\x2D\xBA\x56\x35\x29\x0F\x48\x0B\x15\x5A\x39\xFC'
                        b'\x88\x07\x43\x9E\xCB\xF3\xB8\x73\xC9\xE1\x77\xD5\xA1\x06\xA6\x20'
                        b'\xD0\x82\xC5\x2D\x4D\xD3\x25\xF4\xFD\x26\xFC\xE4\xC2\x00\xDD\x98'
                        b'\x2A\xF4\x3D\x5E\x08\x8A\xD3\x20\x41\x84\x32\x69\x8E\x8A\x34\x76'
                        b'\xEA\x16\x8E\x66\x40\xD9\x32\xB0\x2D\xF5\xBD\xE7\x57\x51\x78\x96'
                        b'\xC2\xED\x40\x41\xCC\x54\x9D\xFD\xB6\x8D\xC2\xBA\x7F\x69\x8D\xCF')


def decode_signature(bytes_sig, bytes_key=None, bytes_mod=None):
    """Decodes a server's signature.

    - If 'bytes_key' or 'bytes_mod' are specified, those values will be used in decoding.
    - Returns the decoded signature as a 128-bit bytes object."""
    key = b2i(bytes_key or DEFAULT_KEY)
    mod = b2i(bytes_mod or DEFAULT_MOD)

    signature = b2i(bytes_sig)

    return i2b(pow(signature, key, mod), 128)

def check_signature(bytes_sig, server_ip, bytes_key=None, bytes_mod=None):
    """Verifies a server's signature against the specified IP address.

    - IP can be either a bytes object or string in dot-notation (eg: '192.168.1.1')
    - If 'bytes_key' or 'bytes_mod' are specified, those values will be used in decoding.
    - Returns True if the signature is valid."""
    result = decode_signature(bytes_sig, bytes_key, bytes_mod)

    # Convert the IP to bytes
    if isinstance(server_ip, str):
        server_ip = inet_aton(server_ip)
    elif not isinstance(server_ip, (bytes, bytearray)):
        raise TypeError("Server IP must be a string or bytes.")

    # Compare the results
    for i in range(0, len(server_ip)):
        if result[i] != server_ip[i]:
            return False
    return True
