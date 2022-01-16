
import struct

from .classic import get_file_version_and_info as get_pe_version


# Maps product codes to the 'pattern' value for scan_version_byte().
# The 2nd value is the index of the version byte within the pattern.
SCAN_PATTERNS = {
    "STAR": (b"\xc7\x46\x10\xff\xff\xff\xff\xc7\x46\x18\xff\xff\xff\xff\xc7\x46", 3),
    "SEXP": (b"\xc7\x46\x10\xff\xff\xff\xff\xc7\x46\x18\xff\xff\xff\xff\xc7\x46", 3),
    "W2BN": (b"\xc7\x46\x10\xff\xff\xff\xff\xc7\x46\x18\xff\xff\xff\xff\xc7\x46", 3),
    "DRTL": (b"\xc7\x85\x64\xff\xff\xffLTRD\xc7\x85\x68\xff\xff\xff\xff\xff\xff\xff", 16),
    "DSHR": (b"\xc7\x85\x64\xff\xff\xffRHSD\xc7\x85\x68\xff\xff\xff\xff\xff\xff\xff", 16),
    "JSTR": (b"\x8b\x4d\xf4\xc7\x41\x0cRTSJ\x8b\x55\xf4\xc7\x42\x10\xff\xff\xff\xff", 16),
    "SSHR": (b"\xc7\x46\x0cRHSS\xc7\x46\x10\xff\xff\xff\xff", 10)
}

# Maps product codes to the index of the version number used as a version byte, usually the MINOR value.
PE_VERSION_LOOKUP = {
    "D2DV": 1,
    "D2XP": 1,
    "WAR3": 1,
    "W3XP": 1
}


def find_version_byte(exe, product):
    """
        Attempts to find the version byte for the specified game from an exe file.

        exe is the path to the game EXE
        product is the 4-digit product code (used for method lookup)
    """
    if product in SCAN_PATTERNS:
        if value := scan_version_byte(exe, *SCAN_PATTERNS[product]):
            return value

    if product in PE_VERSION_LOOKUP:
        value, _ = get_pe_version(exe)
        return struct.pack('>I', value)[PE_VERSION_LOOKUP[product]]


def scan_version_byte(exe, pattern, offset):
    """
        Scans a file for a specific byte-pattern and returns the value located at the given offset.

        exe is the path to the file to search, usually the game EXE
        pattern is the byte-string to search for, with 0xFF values indicating any value
        offset is the index within the pattern of the version byte
    """
    with open(exe, 'rb') as fh:
        value = b""
        while b := fh.read(1):
            if b[0] == pattern[len(value)] or pattern[len(value)] == 0xff:
                value += b

                if len(value) == len(pattern):
                    return struct.unpack_from("<I", value, offset)[0]
            else:
                value = b""


def main():
    import os
    import sys

    def scan_dir(fp):
        if os.path.isfile(fp) and os.path.splitext(fp)[1] == ".exe":
            product = os.path.basename(os.path.dirname(fp))

            if value := find_version_byte(fp, product):
                print("%s -> 0x%02X" % (fp, value))
            else:
                print("%s -> not found" % fp)

        elif os.path.isdir(fp):
            for file in os.listdir(fp):
                scan_dir(os.path.join(fp, file))

    base_path = sys.argv[1]
    scan_dir(base_path)


if __name__ == "__main__":
    main()
