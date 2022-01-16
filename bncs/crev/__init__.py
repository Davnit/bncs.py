
from .exception import CheckRevisionFailedError
from .main import get_crev_version, check_version, format_crev_formula, get_files, preload, clear_cache
from .results import CheckRevisionResults

from .classic import check_version as crev_classic, check_version_slow as crev_classic_slow
from .classic import get_file_version_and_info as get_file_meta
from .lockdown import check_version as crev_lockdown
from .simple import check_version as crev_simple
from .seeds import SCAN_PATTERNS, PE_VERSION_LOOKUP, find_version_byte, scan_version_byte
