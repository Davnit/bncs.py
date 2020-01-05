
from . import classic
from . import lockdown
from . import simple

import re
from socket import inet_ntoa


CREV_VERSIONS = {
    r"\w{4}ver([0-7])\.mpq": 1,
    r"ver-\w{4}-([0-7])\.mpq": 2,
    r"lockdown-\w{4}-([0-1])([0-9])\.mpq": 3,
    r"CheckRevision(D1)*\.mpq": 4
}


class CheckRevisionFailedException(Exception):
    """Raised if the version checking operation did not complete."""
    pass


class CheckRevisionResults:
    """Stores the results of a version checking operation."""
    def __init__(self, product):
        self.product = product
        self.version = None
        self.checksum = None
        self.info = None

    def __str__(self):
        if self.success:
            return "CRev Results: %s - version: %s, checksum: %02.x, info: '%s'" % \
                   (self.product, self.get_version_string(), self.checksum, self.info)
        else:
            return "CRev Results: %s - version check failed" % self.product

    @property
    def success(self):
        return None not in [self.version, self.checksum]

    def get_version_string(self):
        """Returns the version in human-readable format (ex: '1.7.32.9')"""
        bo = "little" if self.product in ["WAR3", "W3XP"] else "big"
        return inet_ntoa(self.version.to_bytes(4, bo))


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
        raise CheckRevisionFailedException("Unsupported platform: %s" % platform)

    check_ver = get_crev_version(archive)
    if check_ver in [1, 2]:
        version, checksum, info = classic.check_version(formula, archive, files)
    elif check_ver == 3:
        version, checksum, info = lockdown.check_version(archive, formula, files)
    elif check_ver == 4:
        version, checksum, info = simple.check_version(formula, files[0], archive.endswith("D1.mpq"))
    else:
        raise CheckRevisionFailedException("Unsupported check revision archive: %s (%s)" % (archive, timestamp))

    results = CheckRevisionResults(None)    # We don't know the product in this context.
    results.version = version
    results.checksum = checksum
    results.info = info
    return results
