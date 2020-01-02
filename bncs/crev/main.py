
from . import classic
from . import lockdown
from . import simple

import re


CREV_VERSIONS = {
    r"\w{4}ver([0-7])\.mpq": 1,
    r"ver-\w{4}-([0-7])\.mpq": 2,
    r"lockdown-\w{4}-([0-1])([0-9])\.mpq": 3,
    r"CheckRevision(D1)*\.mpq": 4
}


class CheckRevisionFailedException(Exception):
    def __init__(self, a):
        super().__init__(a)


def get_crev_version(archive):
    for pattern, version in CREV_VERSIONS.items():
        if re.match(pattern, archive):
            return version


def check_version(archive, formula, files=None, platform=None, timestamp=None):
    files = files or []

    crev_version = get_crev_version(archive)
    if crev_version in [1, 2]:
        version, checksum, info = classic.check_version(formula, archive, files)
    elif crev_version == 3:
        version, checksum, info = lockdown.check_version(archive, formula, files)
    elif crev_version == 4:
        version, checksum, info = simple.check_version(formula, files[0], archive.endswith("D1.mpq"))
    else:
        raise CheckRevisionFailedException("Unsupported check revision archive: %s (%s)" % (archive, timestamp))

    return version, checksum, info
