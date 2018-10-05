
from struct import unpack

PRODUCT_STAR = "STAR"
PRODUCT_SEXP = "SEXP"
PRODUCT_W2BN = "W2BN"
PRODUCT_D2DV = "D2DV"
PRODUCT_D2XP = "D2XP"
PRODUCT_JSTR = "JSTR"
PRODUCT_WAR3 = "WAR3"
PRODUCT_W3XP = "W3XP"
PRODUCT_DRTL = "DRTL"
PRODUCT_DSHR = "DSHR"
PRODUCT_SSHR = "SSHR"
PRODUCT_W3DM = "W3DM"
PRODUCT_CHAT = "CHAT"

LOGON_NONE = -1     # No logon system available
LOGON_LEGACY = 0    # Legacy logon system
LOGON_OLD = 1       # Old logon system
LOGON_NEW = 2       # New logon system (NLS)
LOGON_CHAT = -2     # Legacy telnet CHAT protocol


class BncsProduct(object):
    def __init__(self, code, full_name, bnls_id=None, num_keys=None, channel=None, logon_type=None):
        self.code = code
        self.name = full_name
        self.bnls_id = bnls_id
        self.num_keys = num_keys or (2 if code.endswith("XP") else 1)
        self.home_channel = channel or full_name.split(":")[0]
        self.logon_type = logon_type or LOGON_NEW

    def get_product_dword(self):
        """Returns the product code as a DWORD"""
        return unpack("<I", self.code.encode("ascii"))

    def can_logon(self):
        """Returns TRUE if the product has a known logon system."""
        return self.logon_type != -1


BNCS_PRODUCTS = {
    PRODUCT_STAR: BncsProduct(PRODUCT_STAR, "StarCraft", 0x01, 0, "StarCraft", LOGON_NONE),
    PRODUCT_SEXP: BncsProduct(PRODUCT_SEXP, "StarCraft: Brood War", 0x02, 0, "Brood War", LOGON_NONE),
    PRODUCT_W2BN: BncsProduct(PRODUCT_W2BN, "WarCraft II: Battle.net Edition", 0x03, 1, "WarCraft II", LOGON_OLD),
    PRODUCT_D2DV: BncsProduct(PRODUCT_D2DV, "Diablo II", 0x04, 1, "Diablo II", LOGON_NEW),
    PRODUCT_D2XP: BncsProduct(PRODUCT_D2XP, "Diablo II: Lord of Destruction", 0x05, 2, "Diablo II", LOGON_NEW),
    PRODUCT_WAR3: BncsProduct(PRODUCT_WAR3, "WarCraft III: Reign of Chaos", 0x07, 1, "W3", LOGON_NEW),
    PRODUCT_W3XP: BncsProduct(PRODUCT_W3XP, "WarCraft III: The Frozen Throne", 0x08, 2, "W3", LOGON_NEW),
    PRODUCT_DSHR: BncsProduct(PRODUCT_DSHR, "Diablo Shareware", 0x0A, 0, "Diablo Shareware", LOGON_OLD),
    PRODUCT_DRTL: BncsProduct(PRODUCT_DRTL, "Diablo", 0x09, 0, "Diablo Retail", LOGON_OLD),
    PRODUCT_SSHR: BncsProduct(PRODUCT_SSHR, "StarCraft Shareware", 0x0B, 0, "StarCraft", LOGON_NONE),
    PRODUCT_JSTR: BncsProduct(PRODUCT_JSTR, "Japanese StarCraft", 0x06, 0, "StarCraft", LOGON_NONE),
    PRODUCT_CHAT: BncsProduct(PRODUCT_CHAT, "Telnet Chat", None, 0, "Telnet", LOGON_CHAT)
}


def get_product(pid):
    """Returns the product identified by the ID.

    ID can be the DWORD (both string and int), the full name of the product, or the BNLS ID.
    """
    if isinstance(pid, str):
        pid = pid.upper()

        # First try the product code DWORD-string
        if len(pid) == 4:
            if pid in BNCS_PRODUCTS.keys():
                return BNCS_PRODUCTS.get(pid)

            rid = ''.join(reversed(id))
            if rid in BNCS_PRODUCTS.keys():
                return BNCS_PRODUCTS.get(rid)

        # Next try the full name of the product.
        for prod in BNCS_PRODUCTS.values():
            if prod.name.upper() == pid:
                return prod

    elif isinstance(pid, int):
        for prod in BNCS_PRODUCTS.values():
            if prod.get_product_dword() == pid or prod.bnls_id == pid:
                return prod

    return None
