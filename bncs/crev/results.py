
from socket import inet_ntoa


class CheckRevisionResults:
    """Stores the results of a version checking operation."""
    def __init__(self, product=None):
        self.product = product
        self.version = None
        self.checksum = None
        self.info = None

    def __str__(self):
        if self.success:
            return "CRev Results:%s version: %s, checksum: %.8x, info: %s" % \
                   ((" %s -" % self.product) if self.product else "",
                    self.get_version_string(), self.checksum, self.info)
        else:
            return "CRev Results:%s version check failed" % (" %s -" % self.product) if self.product else ""

    @property
    def success(self):
        return None not in [self.version, self.checksum]

    def get_version_string(self):
        """Returns the version in human-readable format (ex: '1.7.32.9')"""
        bo = "little" if self.product in ["WAR3", "W3XP"] else "big"
        return inet_ntoa(self.version.to_bytes(4, bo))
