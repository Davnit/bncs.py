
import base64
from hashlib import sha1
import struct

import pefile
from signify.signed_pe import SignedPEFile


def check_version(seed, exe, include_cert=False):
    pe = pefile.PE(exe)
    ver_str = pe.FileInfo[0][0].StringTable[0].entries.get(b'FileVersion').decode('ascii')

    seed = base64.b64decode(seed)[:4]
    buff = seed + b":" + ver_str.encode('ascii') + b":" + b'\x01'
    out = base64.b64encode(sha1(buff).digest())

    version = 0
    checksum = struct.unpack('<I', out[:4])[0]
    info = out[4:].decode('ascii')

    if include_cert:
        version = 6

        with open(exe, 'rb') as fh:
            file = SignedPEFile(fh)
            cert = list(file.signed_datas)[0].certificates[0]

            # signify library returns the public key as a binary (1/0) string
            public_key = hex(int(str(cert.subject_public_key), 2))

        info += b":" + base64.b64encode(sha1(public_key + seed).digest())

    return version, checksum, info
