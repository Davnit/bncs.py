
# Product codes (https://bnetdocs.org/document/44/bnls-product-codes)
PRODUCT_STARCRAFT = 0x01
PRODUCT_BROODWAR = 0x02
PRODUCT_WARCRAFT2 = 0x03
PRODUCT_DIABLO2 = 0x04
PRODUCT_D2LOD = 0x05
PRODUCT_STARCRAFTJAPAN = 0x06
PRODUCT_WARCRAFT3 = 0x07
PRODUCT_WAR3TFT = 0x08
PRODUCT_DIABLO = 0x09
PRODUCT_DIABLOSHAREWARE = 0x0A
PRODUCT_SCSHAREWARE = 0x0B
PRODUCT_WAR3DEMO = 0x0C


# Maps BNLS product codes to BNCS ID's
PRODUCT_CODES = {
    "STAR": PRODUCT_STARCRAFT,
    "SEXP": PRODUCT_BROODWAR,
    "W2BN": PRODUCT_WARCRAFT2,
    "D2DV": PRODUCT_DIABLO2,
    "D2XP": PRODUCT_D2LOD,
    "JSTR": PRODUCT_STARCRAFTJAPAN,
    "WAR3": PRODUCT_WARCRAFT3,
    "W3XP": PRODUCT_WAR3TFT,
    "DRTL": PRODUCT_DIABLO,
    "DSHR": PRODUCT_DIABLOSHAREWARE,
    "SSHR": PRODUCT_SCSHAREWARE,
    "W3DM": PRODUCT_WAR3DEMO
}

PRODUCT_IDS = {v: k for k, v in PRODUCT_CODES.items()}


class BnlsProduct:
    def __init__(self, code):
        if isinstance(code, int):
            self.bnls_id = code
            self.code = PRODUCT_IDS.get(self.bnls_id)
        elif isinstance(code, str):
            self.code = code.upper()
            self.bnls_id = PRODUCT_CODES.get(self.code)
        else:
            raise TypeError("BNLS product code must be int or str")

        self.check = None           # bncs.crev.CheckRevisionResults object
        self.verbyte = None

    def __str__(self):
        return "BNLS Product '%s'" % self.code

    @staticmethod
    def product_codes():
        return PRODUCT_CODES

    @staticmethod
    def product_ids():
        return PRODUCT_IDS
