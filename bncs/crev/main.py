
from . import classic
from . import lockdown
from . import simple

from .exception import CheckRevisionFailedError
from .results import CheckRevisionResults

from os import path, listdir
import re


CREV_VERSIONS = {
    r"(\w{4})ver([0-7])\.mpq": 1,
    r"ver-(\w{4})-([0-7])\.mpq": 2,
    r"lockdown-(\w{4})-[0-1][0-9]\.mpq": 3,
    r"CheckRevision(D1)*\.mpq": 4
}


def format_crev_formula(formula):
    try:
        return f"'{formula.decode('ascii')}'"
    except UnicodeDecodeError:
        return "0x" + formula.hex()


def get_crev_version(archive):
    """Returns the version of CheckRevision used by a given MPQ archive.

    archive: the filename given by the server during client authentication
    """
    for pattern, version in CREV_VERSIONS.items():
        if obj := re.match(pattern, archive):
            return version, obj.groups()[0] if version != 4 else 'IX86'


def get_files(archive, product, base_path):
    """Returns available files used for hashing a product with the archive.

        This function will only attempt to find files that exist on disk, it doesn't
        have any awareness of which ones are actually needed by the server. It will
        return files in an order historically consistent with hashing requirements
        (exe, storm, network, screen dump, lockdown) but may not include all or any
        of these.
    """
    version, platform = get_crev_version(archive)

    files = [None, None, None, None]        # EXE, STORM, SNP, BIN
    game_dir = path.join(base_path, platform, product)
    for file in listdir(game_dir):
        name, ext = path.splitext(path.basename(file))
        if ext == ".exe":
            files[0] = file
        elif ext == ".dll" and name.lower() in ("storm", "bnclient"):
            files[1] = file
        elif ext == ".snp" or (ext == ".dll" and name.lower() in ("d2client", "game")):
            files[2] = file

    if version == 3:
        files[3] = product + '.bin'
        files.append(path.join(base_path, 'lockdown', archive.replace(".mpq", ".dll")))

    return list(filter(None, files))


def preload(archive, product, hash_path):
    version, platform = get_crev_version(archive)
    files = get_files(archive, product, hash_path)

    if len(files) == 0:
        # No files returned, nothing to load.
        return

    classic.get_file_version_and_info(files[0])     # Parses PE structure for EXE, always needed

    if version == 3:
        # Lockdown - get PE and heap data for all files except the .bin
        for file in files:
            if not file.endswith('.bin'):
                lockdown.build_heap(file)

    elif version == 4 and archive.endswith("D1.mpq"):
        # Simple - extract public key from EXE
        simple.get_public_key(files[0])


def clear_cache():
    classic.pe_structs.clear()
    lockdown.heap_data.clear()
    simple.public_keys.clear()


def check_version(archive, formula, files):
    """Runs a CheckRevision() emulation and returns the results.

    archive: the filename provided during authentication
    formula: the value string used for calculations
    files: a list of game files that should be checked (usually just the main game EXE)

    Returns a CheckRevisionResults object with the returned values.
    """
    check_ver = get_crev_version(archive)

    if check_ver in [1, 2]:
        version, info = classic.get_file_version_and_info(files[0])
        checksum = classic.check_version(formula, archive, files)
    elif check_ver == 3:
        version, _ = classic.get_file_version_and_info(files[0])
        checksum, info = lockdown.check_version(formula, files)
    elif check_ver == 4:
        version, checksum, info = simple.check_version(formula, files[0], archive.endswith("D1.mpq"))
    else:
        raise CheckRevisionFailedError(f"Unsupported check revision archive: {archive}")

    results = CheckRevisionResults()
    results.version = version
    results.checksum = checksum
    results.info = info.encode('ascii') if isinstance(info, str) else info
    return results
