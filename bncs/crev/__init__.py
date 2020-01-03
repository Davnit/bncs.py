
from .main import CheckRevisionFailedException, CheckRevisionResults
from .main import get_crev_version, check_version

from .classic import check_version as crev_classic
from .lockdown import check_version as crev_lockdown
from .simple import check_version as crev_simple
