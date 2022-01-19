
from datetime import datetime
from os import path
import logging
import re
import struct

import pefile

from .exception import CheckRevisionFailedError


log = logging.getLogger(__name__)


HASH_CODES = [0xE7F4CB62, 0xF6A14FFC, 0xAA5504AF, 0x871FCDC2, 0x11BF6A18, 0xC57292E6, 0x7927D27E, 0x2FEC8733]
FAST_FORMULAS = ["A=A.S", "B=B.C", "C=C.A", "A=A.B"]

pe_structs = {}     # file path -> PE data


class InvalidFormulaError(CheckRevisionFailedError):
    """Raised when the checksum formula could not be interpreted."""
    def __init__(self, formula, *args):
        super().__init__(*args)
        self.formula = formula


def get_hashcode(mpq):
    """Returns the hash code (seed value?) for the specified MPQ filename."""
    num = 0
    if mpq.startswith("ver"):
        num = int(mpq[9])
    elif "ver" in mpq:
        num = int(mpq[7])
    return HASH_CODES[num]


def get_file_version_and_info(file):
    """Returns the version and 'exe information' values from an file."""
    key = file.lower()
    if (pe := pe_structs.get(key)) is None:
        pe = pe_structs[key] = pefile.PE(file)

    # EXE Version
    ffi = pe.VS_FIXEDFILEINFO[0]
    vb = struct.pack('!II', ffi.FileVersionMS, ffi.FileVersionLS)
    vb = bytes([vb[x] for x in range(1, len(vb), 2)])     # Only use every other byte
    ver = struct.unpack('!I', vb)[0]

    # EXE Info
    dt = datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp)
    size = path.getsize(file)
    info = "%s %s %i" % (path.basename(file), dt.strftime("%m/%d/%y %H:%M:%S"), size)

    return ver, info


def do_op(op, var1, var2):
    res = var1 ^ var2 if op == '^' else var1 + var2 if op == '+' else \
        var1 - var2 if op == '-' else var1 * var2 if op == '*' else var1 // var2
    return res & 0xffffffffffffffff


FILE_BLOCK_SIZE = 1024


def read_file_gen(handle, version=2):
    while data := handle.read(FILE_BLOCK_SIZE):
        if len(data) < FILE_BLOCK_SIZE:
            # Reached EOF and file is not aligned
            if version == 2:
                # Pad this last block to 1024 bytes with descending byte values from 0xff
                data = (data + (bytes(range(0xff, -1, -1)) * 4))[:FILE_BLOCK_SIZE]
            elif version == 1:
                # No more full blocks, stop here.
                break

        yield from iter(struct.unpack('<%iI' % (1024 // 4,), data))


def check_version(formula, mpq, files):
    """Performs a fast variant of the classic version check for standard formulas.

    For unusual formulas, this function will delegate to the slow method (not yet implemented).

    formula: the formula string used to calculate the checksum
    mpq: the name of the MPQ file variant used to seed the check
    files: a list of files that should be included in the check
    """
    if isinstance(formula, (bytes, bytearray)):
        formula = formula.decode('ascii')

    tokens = list(formula.split(' '))

    # Set initial values from formula
    a = b = c = 0
    for x in range(3):
        seed = tokens.pop(0).lower()
        k = seed[0:2]
        v = int(seed[2:])
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
        if operation[3] not in "^+-*/":
            raise InvalidFormulaError(formula, "Invalid formula operation: %s" % operation[3])

        opc.append(operation[3])

        # Check for fast-formula eligibility
        if not re.match(FAST_FORMULAS[len(opc) - 1], operation, re.IGNORECASE):
            log.debug("Strange formula detected. Reverting to slow CRev. Formula: '%s'" % formula)
            return check_version_slow(formula, mpq, files)

    a = (a ^ get_hashcode(mpq)) & 0xffffffffffffffff

    for file in files:
        with open(file, 'rb') as fh:
            # Read the file as 32-bit ints, in 1024-byte blocks, padding with either 0's or descending byte values
            # CRev v1 uses 0's, v2 uses descending bytes from 0xff to 0x00
            for s in read_file_gen(fh, 2 if mpq.startswith("ver") else 1):
                a = do_op(opc[0], a, s)
                b = do_op(opc[1], b, c)
                c = do_op(opc[2], c, a)
                a = do_op(opc[3], a, b)

    check = int(c) & 0xffffffff
    return check


def check_version_slow(formula, mpq, files):
    values = {'S': 0}     # Stores current value of each variable
    modifiers = []        # Stores tuple of operations to perform (x, y, ., z) for x=y.z
    init_var = None       # Variable name used for seeding the checksum
    key = None            # Current variable name

    tokens = list(formula.split(' '))
    for i in range(len(tokens)):
        tok = tokens.pop(0)
        if '=' in tok:
            x = tok.split('=')
            if x[1].isdigit():
                key = x[0]
                values[key] = int(x[1]) & 0xffffffffffffffff
                if init_var is None:
                    # First variable is combined with the hash code
                    init_var = key
            elif len(tok) == 5:
                if x[1][0] not in values or x[1][2] not in values:
                    raise InvalidFormulaError(formula, "CRev formula variable not set.")
                modifiers.append((x[0], x[1][0], x[1][1], x[1][2]))

    # Check that things were at least assigned
    if init_var is None:
        raise InvalidFormulaError(formula, "CRev formula did not assign variables.")

    # Apply the hash code
    values[init_var] = (values[init_var] ^ get_hashcode(mpq)) & 0xffffffffffffffff

    # Last variable is used as the checksum
    check_var = key

    for file in files:
        with open(file, 'rb') as fh:
            # Same file read method, just using the dynamic value lookup instead of fixed variables
            for s in read_file_gen(fh, 2 if mpq.startswith("ver") else 1):
                values['S'] = s

                for mod in modifiers:
                    values[mod[0]] = do_op(mod[2], mod[1], mod[3])

    check = values[check_var] & 0xffffffff
    return check
