
from . import classic
from . import lockdown
from . import simple

from .exception import CheckRevisionFailedError
from .results import CheckRevisionResults

import re


CREV_VERSIONS = {
    r"\w{4}ver([0-7])\.mpq": 1,
    r"ver-\w{4}-([0-7])\.mpq": 2,
    r"lockdown-\w{4}-([0-1])([0-9])\.mpq": 3,
    r"CheckRevision(D1)*\.mpq": 4
}


def get_crev_version(archive):
    """Returns the version of CheckRevision used by a given MPQ archive.

    archive: the filename given by the server during client authentication
    """
    for pattern, version in CREV_VERSIONS.items():
        if re.match(pattern, archive):
            return version


def check_version(archive, formula, files=None, platform='IX86', timestamp=None):
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
        version, checksum, info = lockdown.check_version(archive, formula, files)
    elif check_ver == 4:
        version, checksum, info = simple.check_version(formula, files[0], archive.endswith("D1.mpq"))
    else:
        raise CheckRevisionFailedError("Unsupported check revision archive: %s (%s)" % (archive, timestamp))

    results = CheckRevisionResults()
    results.version = version
    results.checksum = checksum
    results.info = info
    return results
