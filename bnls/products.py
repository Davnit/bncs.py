
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
    PRODUCT_STARCRAFT: "STAR",
    PRODUCT_BROODWAR: "SEXP",
    PRODUCT_WARCRAFT2: "W2BN",
    PRODUCT_DIABLO2: "D2DV",
    PRODUCT_D2LOD: "D2XP",
    PRODUCT_STARCRAFTJAPAN: "JSTR",
    PRODUCT_WARCRAFT3: "WAR3",
    PRODUCT_WAR3TFT: "W3XP",
    PRODUCT_DIABLO: "DRTL",
    PRODUCT_DIABLOSHAREWARE: "DSHR",
    PRODUCT_SCSHAREWARE: "SSHR",
    PRODUCT_WAR3DEMO: "W3DM"
}


def get_bnls_code(product):
    product = {value: key for key, value in PRODUCT_CODES.items()}.get(product, product)
    if not isinstance(product, int):
        raise ValueError("Unrecognized product code: %s" % product)
    return product


class BnlsProduct:
    def __init__(self, code):
        self.id = get_bnls_code(code)
        self.code = PRODUCT_CODES.get(self.id)
        self.version = None
        self.verbyte = None
