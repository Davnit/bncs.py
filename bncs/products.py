
import enum
import json
import pkg_resources
import struct

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


class LogonMechanism(enum.Enum):
    NoLogin, Legacy, Old, New, Chat = range(5)


supported_products = {}


_logon_mechanism_values = {
    LogonMechanism.NoLogin: [None, "none"],
    LogonMechanism.Legacy: ["legacy", "lls"],
    LogonMechanism.Old: ["old", "ols"],
    LogonMechanism.New: ["new", "nls"],
    LogonMechanism.Chat: ["chat", "telnet"]
}


def load_product_metadata(source):
    global supported_products

    if isinstance(source, bytes):
        data = json.loads(source)
    else:
        with open(source) as fh:
            data = json.load(fh)

    products = data.get("bncs-product-definitions")
    if products is None:
        raise KeyError("Invalid product definitions file - bad root node")

    for code, meta in products.items():
        product = BncsProduct(code, meta["name"])
        product.bnls_id = meta.get("bnls_id")
        product.required_keys = meta.get("required_keys", product.required_keys)
        product.home_channel = meta.get("first_join_channel", product.home_channel)
        product.home_flags = meta.get("first_join_flags", product.home_flags)
        product.uses_udp = meta.get("udp", product.uses_udp)
        product.hashes = meta.get("hashes", product.hashes)

        logon = meta.get("logon_mechanism", LogonMechanism.NoLogin)
        for mechanism, values in _logon_mechanism_values.items():
            if logon in values or (isinstance(logon, str) and logon.lower() in values):
                product.logon_mechanism = mechanism
                break

        supported_products[code] = product


class BncsProduct:
    all_products = supported_products

    def __init__(self, code, full_name):
        self.code = code.upper()
        self.name = full_name

        self.bnls_id = None                             # ID used with BNLS
        self.required_keys = []                         # 4-char product codes of required CD keys
        self.logon_mechanism = None                     # Logon method used by the official client
        self.home_channel = full_name.split(":")[0]     # String used as channel name for first-joining chat
        self.home_flags = 1                             # Flags used when first-joining chat
        self.uses_udp = False                           # True if a UDP test should be performed
        self.hashes = {}                                # Maps platform to a list of filenames used for hashing

    def __eq__(self, other):
        return isinstance(other, BncsProduct) and other.code == self.code

    def get_product_dword(self):
        """Returns the product code as a DWORD"""
        return struct.unpack("<I", self.code.encode("ascii"))[0]

    @property
    def can_logon(self):
        """Returns TRUE if the product has a known logon system."""
        return self.logon_mechanism != LogonMechanism.NoLogin

    @staticmethod
    def get(pid):
        """Returns the product identified by the ID.

            ID can be the DWORD (both string and int), the full name of the product, or the BNLS ID.
            """
        if not supported_products:
            load_product_metadata(pkg_resources.resource_string(__name__, 'products.json'))

        if isinstance(pid, str):
            pid = pid.upper()

            # First try the product code DWORD-string
            if len(pid) == 4:
                if pid in supported_products.keys():
                    return supported_products.get(pid)

                rid = ''.join(reversed(pid))
                if rid in supported_products:
                    return supported_products[rid]

            # Next try the full name of the product.
            for prod in supported_products.values():
                if prod.name.upper() == pid:
                    return prod

        elif isinstance(pid, int):
            for prod in supported_products.values():
                if prod.get_product_dword() == pid or prod.bnls_id == pid:
                    return prod

        elif isinstance(pid, BncsProduct):
            return pid

        return None
