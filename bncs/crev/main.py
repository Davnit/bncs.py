
from . import classic
from . import lockdown
from . import simple

from .exception import CheckRevisionFailedError
from .results import CheckRevisionResults

from os import path
import re


CREV_VERSIONS = {
    r"\w{4}ver([0-7])\.mpq": 1,
    r"ver-\w{4}-([0-7])\.mpq": 2,
    r"lockdown-\w{4}-([0-1])([0-9])\.mpq": 3,
    r"CheckRevision(D1)*\.mpq": 4
}


pe_file_cache = {}      # File path -> PE data
pe_file_times = {}      # File path -> last modified time


def cache_pe_data(filepath, pe):
    filepath = filepath.lower()
    pe_file_cache[filepath] = pe
    pe_file_times[filepath] = path.getmtime(filepath)


def clear_pe_cache():
    pe_file_cache.clear()
    pe_file_times.clear()

    # Not technically PE, but based on it.
    lockdown.file_heaps.clear()
    simple.signature_cache.clear()


def get_cached_pe_data(filepath, skip=False):
    filepath = filepath.lower()

    if not skip and path.isfile(filepath):
        if filepath in pe_file_times:
            last_modified = path.getmtime(filepath)
            if last_modified > pe_file_times[filepath]:
                # Needs update
                return None
            return pe_file_cache.get(filepath)


def get_crev_version(archive):
    """Returns the version of CheckRevision used by a given MPQ archive.

    archive: the filename given by the server during client authentication
    """
    for pattern, version in CREV_VERSIONS.items():
        if re.match(pattern, archive):
            return version


def check_version(archive, formula, files=None, platform='IX86', timestamp=None, skip_cache=False):
    """Runs a CheckRevision() emulation and returns the results.

    archive: the filename provided during authentication
    formula: the value string used for calculations
    files: a list of game files that should be checked (usually just the main game EXE)
    platform: an identifier of the system architecture (ex: IX86, XMAC, PMAC) (default 'IX86')
    timestamp: the filetime of the archive (not typically required)

    Returns a CheckRevisionResults object with the returned values.

    Officially, the game clients download the archive from BNFTP, extract the contents, and execute the code contained
        within. Since the archives are all very similar and don't typically change, we skip the downloading bits and
        just emulate the code that they would've executed.
    """
    files = files or []
    if platform != 'IX86':
        raise CheckRevisionFailedError("Unsupported platform: %s" % platform)

    check_ver = get_crev_version(archive)
    if check_ver in [1, 2]:
        version, info = classic.get_file_version_and_info(files[0])
        checksum = classic.check_version(formula, archive, files)
    elif check_ver == 3:
        version, _ = classic.get_file_version_and_info(files[0])
        checksum, info = lockdown.check_version(archive, formula, files)
    elif check_ver == 4:
        version, checksum, info = simple.check_version(formula, files[0], archive.endswith("D1.mpq"))
    else:
        raise CheckRevisionFailedError("Unsupported check revision archive: %s (%s)" % (archive, timestamp))

    results = CheckRevisionResults()
    results.version = version
    results.checksum = checksum
    results.info = info.encode('ascii') if isinstance(info, str) else info
    return results
