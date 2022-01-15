
import base64
from hashlib import sha1
import struct

import pefile
from signify.authenticode import SignedPEFile

from .classic import pe_structs

public_keys = {}


def get_public_key(file):
    if key := public_keys.get(file):
        return key

    with open(file, 'rb') as fh:
        # The EXE must be digitally signed
        pe = SignedPEFile(fh)
        cert = list(pe.signed_datas)[0].certificates[0]

        # signify library returns the public key as a binary (1/0) string
        public_key = public_keys[file] = hex(int(str(cert.subject_public_key), 2))
        return public_key


def check_version(seed, exe, include_cert=False):
    """Performs the modern 'simple' version check using the exe version and optionally the certificate.

    seed: base64 encoded seed value provided by the server
    exe: path to the main game exe file
    include_cert: set to True to include the exe certificate in the hash
    """
    if (pe := pe_structs.get(exe)) is None:
        pe = pe_structs[exe] = pefile.PE(exe)

    # Ex: '2001, 5, 18, 1'
    # This is different from the EXE version used in classic CRev
    ver_str = pe.FileInfo[0][0].StringTable[0].entries.get(b'FileVersion')

    # Decode the base64 seed and combine it with the version, some colons, and the single byte value 0x01
    seed = base64.b64decode(seed)[:4]
    buff = seed + b":" + ver_str + b":" + b'\x01'

    # Hash the combined values with SHA1 and encode them as base 64
    out = base64.b64encode(sha1(buff).digest())

    version = 0                                     # Static value for CheckRevision.mpq
    checksum = struct.unpack('<I', out[:4])[0]      # First 4 bytes of encoded hash, as a DWORD
    info = out[4:]                                  # Rest of the encoded hash

    if include_cert:
        version = 6         # Static value for CheckRevisionD1.mpq
        public_key = get_public_key(exe)

        # Combine the public key with the seed and append the encoded hash to the EXE info string
        info += b":" + base64.b64encode(sha1(public_key.encode('ascii') + seed).digest())

    return version, checksum, info
