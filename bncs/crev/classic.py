
from ctypes import c_int32, c_int64
from datetime import datetime
from os import path
import re
import struct

import pefile


HASH_CODES = [0xE7F4CB62, 0xF6A14FFC, 0xAA5504AF, 0x871FCDC2, 0x11BF6A18, 0xC57292E6, 0x7927D27E, 0x2FEC8733]
FAST_FORMULAS = ["A=A.S", "B=B.C", "C=C.A", "A=A.B"]


def pad_desc(data):
    data = bytearray(data)
    value = 0xFF
    while len(data) % 1024 != 0:
        data.append(value)
        value = 0xFF if value == 0 else (value - 1)
    return data


def get_hashcode(mpq):
    """Returns the hash code (seed value?) for the specified MPQ filename."""
    num = 0
    if mpq.startswith("ver"):
        num = ord(mpq[9]) - 0x30
    elif "ver" in mpq:
        num = ord(mpq[7]) - 0x30
    return HASH_CODES[num]


def check_version(formula, mpq, files):
    """Performs a fast variant of the classic version check for standard formulas.

    For unusual formulas, this function will delegate to the slow method (not yet implemented).

    formula: the formula string used to calculate the checksum
    mpq: the name of the MPQ file variant used to seed the check
    files: a list of files that should be included in the check
    """
    # Read data from EXE PE structure
    pe = pefile.PE(files[0])

    # EXE Version
    ffi = pe.VS_FIXEDFILEINFO[0]
    vb = struct.pack('>II', ffi.FileVersionMS, ffi.FileVersionLS)
    vb = bytes([vb[x] for x in range(1, len(vb), 2)])     # Only use every other byte
    ver = struct.unpack('!I', vb)[0]

    # EXE Info
    dt = datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp)
    size = path.getsize(files[0])
    info = "%s %s %i" % (path.basename(files[0]), dt.strftime("%m/%d/%y %H:%M:%S"), size)

    tokens = list(formula.split(' '))

    # Set initial values from formula
    a = b = c = c_int64(0).value
    for x in range(3):
        seed = tokens.pop(0).lower()
        k = seed[0:2]
        v = c_int64(int(seed[2:])).value
        if k == "a=":
            a = v
        elif k == "b=":
            b = v
        elif k == "c=":
            c = v

    tokens.pop(0)

    # Build list of operations
    opc = []
    while len(tokens) > 0:
        operation = tokens.pop(0)
        opc.append(operation[3])

        if not re.match(FAST_FORMULAS[len(opc) - 1], operation, re.IGNORECASE):
            raise ValueError("Formula not supported. Expected '%s', got '%s'." %
                             (FAST_FORMULAS[len(opc) - 1], operation))

    a = c_int64(a ^ c_int32(get_hashcode(mpq)).value).value

    methods = {
        '^': lambda g, h: c_int64(g ^ h).value,
        '+': lambda g, h: c_int64(g + h).value,
        '-': lambda g, h: c_int64(g - h).value,
        '*': lambda g, h: c_int64(g * h).value,
        '/': lambda g, h: c_int64(g / h).value
    }

    for file in files:
        with open(file, 'rb') as fh:
            data = (fh.read())

        # For some MPQs, pad the file to 1024-byte intervals of descending byte values.
        if mpq.startswith("ver"):
            data = pad_desc(data)

        for i in range(0, len(data), 4):
            s = c_int32(struct.unpack_from('i', data, i)[0]).value

            a = methods[opc[0]](a, s)
            b = methods[opc[1]](b, c)
            c = methods[opc[2]](c, a)
            a = methods[opc[3]](a, b)

    check = c_int32(c).value
    return ver, check, info


# TODO: Implement 'slow' method for handling unusual formula strings
