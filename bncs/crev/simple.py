
import base64
from hashlib import sha1
import struct

import pefile
from signify.signed_pe import SignedPEFile


signature_cache = {}        # EXE signature public keys


def check_version(seed, exe, include_cert=False, skip_cache=False):
    """Performs the modern 'simple' version check using the exe version and optionally the certificate.

    seed: base64 encoded seed value provided by the server
    exe: path to the main game exe file
    include_cert: set to True to include the exe certificate in the hash
    """
    global signature_cache
    from .main import get_cached_pe_data, cache_pe_data
    if (pe := get_cached_pe_data(exe, skip_cache)) is None:
        pe = pefile.PE(exe)
        cache_pe_data(exe, pe)

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

        if skip_cache or exe.lower() not in signature_cache:
            with open(exe, 'rb') as fh:
                # The EXE must be digitally signed
                file = SignedPEFile(fh)
                cert = list(file.signed_datas)[0].certificates[0]

                # signify library returns the public key as a binary (1/0) string
                public_key = hex(int(str(cert.subject_public_key), 2))
                signature_cache[exe.lower()] = public_key
        else:
            public_key = signature_cache[exe.lower()]

        # Combine the public key with the seed and append the encoded hash to the EXE info string
        info += b":" + base64.b64encode(sha1(public_key + seed).digest())

    return version, checksum, info
