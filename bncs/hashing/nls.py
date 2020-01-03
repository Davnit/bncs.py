
import os
from hashlib import sha1


NLS_GENERATOR = 0x2F
NLS_MODULUS = 0xF8FF1A8B619918032186B68CA092B5557E976C78C73212D91216F6658523C787

DEFAULT_BYTE_ORDER = "little"


def b2i(b):
    """Converts a byte array to an integer."""
    return int.from_bytes(b, DEFAULT_BYTE_ORDER, signed=False)


def i2b(i, length=None):
    """Converts an integer to a byte array.

    length is the expected length of the array. If None is given, the integer's smallest size will be used.
    """
    length = length or ((i.bit_length() + 7) // 8)
    return i.to_bytes(length, DEFAULT_BYTE_ORDER, signed=False)


def flip(b):
    """Flips the byte order of a bytes object or integer."""
    if isinstance(b, (bytes, bytearray)):
        return type(b)(reversed(b))
    elif isinstance(b, int):
        return b2i(bytes(reversed(i2b(b))))
    else:
        raise TypeError("Unable to convert type '%s' to bytes." % type(b).__name__)


def get_random(length):
    """Returns a random number from the specified number of bytes."""
    return b2i(os.urandom(length))


def get_random_of_length(length):
    """Returns a random number with a fixed byte length."""
    return get_random(length) | (1 << (length * 8) - 1)


def H(*args):
    """Returns a SHA1 hash of the specified values."""
    h = sha1()
    for a in args:
        if a is not None:
            if isinstance(a, int):
                a = i2b(a)

            h.update(a.encode() if hasattr(a, "encode") else a)

    return h.digest()


def xor_bytes(a, b):
    """Returns a byte array with the values from XOR'ing each byte of the input arrays."""
    if len(a) != len(b):
        raise ValueError("Both byte arrays must be the same length.")

    res = []
    for i in range(0, len(a)):
        res.append(a[i] ^ b[i])
    return bytes(res)


def get_modulus(nls_version=2):
    """Returns the modulus (N) for the given NLS version.

    Supported versions:
        - 1 (W3 beta)
        - 2 (normal)
    """
    if nls_version == 1:
        return flip(NLS_MODULUS)
    elif nls_version == 2:
        return NLS_MODULUS
    else:
        raise ValueError("Unrecognized NLS version: %i" % nls_version)


def get_x(username, password, salt):
    """Calculates the SHA1 hash of the username, password, and salt.

    Equivalent to: SHA1(salt, SHA1(username, ':', password))
    """
    return b2i(H(salt, H(username.upper(), ':', password.upper())))


def get_sv(username, password, nls_version=2, salt=None):
    """Returns the verifier (g^x % N) and salt used in creating it."""
    if salt and len(salt) != 32:
        raise ValueError("Salt must be 32 bytes.")

    s = salt or os.urandom(32)
    v = i2b(pow(NLS_GENERATOR, get_x(username, password, s), get_modulus(nls_version)), 32)
    return s, v


def get_u(B):
    """The scrambler - first four bytes of SHA1(B)"""
    return b2i(flip(H(B)[:4]))


def get_K(S):
    """Calculates the password proof."""
    S = i2b(S, 32)

    K = []
    b1 = []
    b2 = []

    for i in range(16):
        b1.append(S[i * 2])
        b2.append(S[(i * 2) + 1])

    b1 = H(bytes(b1))
    b2 = H(bytes(b2))

    for i in range(len(b1)):
        K.append(b1[i])
        K.append(b2[i])

    return bytes(K)


def calculate_M(I, username, salt, A, B, K):
    return H(I, H(username), salt.ljust(32, b'\0'), i2b(A, 32), i2b(B, 32), K)


def calculate_AMK(A, M, K):
    return H(i2b(A, 32), M, K)


class NLS_Session:
    """Base class for NLS operations."""

    def __init__(self, username, version=2, private=None):
        self.version = version
        self.username = username.upper()

        # Set NLS constants
        self.N = get_modulus(version)
        self.g = NLS_GENERATOR
        self.I = xor_bytes(H(i2b(self.g)), H(i2b(self.N)))

        # Import/create the private key, this will be either variable 'a' (client) or 'b' (server).
        if private and not isinstance(private, (bytes, bytearray)):
            raise TypeError("Private key must be a byte array.")
        self._private_key = b2i(private) if private else get_random_of_length(32)

        # Set state variable
        self._authenticated = False

        # Set NLS variables
        self.s = None
        self.v = None
        self.A = None
        self.B = None
        self.u = None
        self.S = None
        self.K = None
        self.M = None
        self.AMK = None

    def authenticated(self):
        """Returns TRUE if NLS authentication was successful."""
        return self._authenticated

    def get_session_key(self):
        return self.K if self._authenticated else None


class NLS_Client(NLS_Session):
    """Handles client-side NLS operations."""

    def __init__(self, username, password, version=2, bytes_a=None):
        """Creates a new NLS client session.

        username: the client's username
        password: the client's plain-text password (it will be hashed!)
        version: the NLS version to use (default 2)
        bytes_a: a byte array containing the client's private key (default generates a random one)
        """
        super().__init__(username, version, bytes_a)

        self._password = password.upper()
        self.x = None

        # Calculate the client public key (A)
        self.A = pow(self.g, self._private_key, self.N)

    def process_challenge(self, bytes_s, bytes_B):
        """Processes the server challenge and returns the password proof.

        The challenge is sent in SID_AUTH_ACCOUNTLOGON (0x53) and contains both required values.

        bytes_s: a byte array containing the account's salt value
        bytes_B: a byte array containing the server's public key
        """
        self.s = bytes_s
        self.B = b2i(bytes_B)

        # Safety checks
        if (self.B % self.N) == 0:
            return None
        self.u = get_u(self.B)
        if self.u == 0:
            return None

        self.x = get_x(self.username, self._password, self.s)
        self.v = pow(self.g, self.x, self.N)
        self.S = pow((self.B - self.v), (self._private_key + self.u * self.x), self.N)
        self.K = get_K(self.S)

        self.M = calculate_M(self.I, self.username, self.s, self.A, self.B, self.K)
        self.AMK = calculate_AMK(self.A, self.M, self.K)

        return self.M

    def verify(self, host_AMK):
        """Verifies the server's password proof.

        The server proof is sent in SID_AUTH_ACCOUNTLOGONPROOF (0x54).

        host_AMK: a byte array containing the server's password proof
        """
        self._authenticated = (self.AMK == host_AMK)

    def get_client_key(self):
        """Returns the client's public key as a byte array.

        The client sends this in SID_AUTH_ACCOUNTLOGON (0x52)."""
        return i2b(self.A, 32)


class NLS_Server(NLS_Session):
    """Handles server-side NLS operations."""

    def __init__(self, username, bytes_s, bytes_v, bytes_A, version=2, bytes_b=None):
        """Creates a new NLS server session.

        username: the username of the account being logged into
        bytes_s: a byte array containing the salt value associated with the account
        bytes_v: a byte array containing the verifier value associated with the account
        bytes_A: a byte array containing the client's public key
        version: the NLS version to use (default 2)
        bytes_b: the server's private key (default generates a random one)
        """
        super().__init__(username, version, bytes_b)

        self.s = bytes_s
        self.v = b2i(bytes_v)
        self.A = b2i(bytes_A)

        self.safety_failed = self.A % self.N == 0
        if not self.safety_failed:
            self.B = (self.v + pow(self.g, self._private_key, self.N)) % self.N

            self.u = get_u(self.B)
            self.S = pow(self.A * pow(self.v, self.u, self.N), self._private_key, self.N)
            self.K = get_K(self.S)

            self.M = calculate_M(self.I, self.username, self.s, self.A, self.B, self.K)
            self.AMK = calculate_AMK(self.A, self.M, self.K)

    def get_challenge(self):
        """Returns values for the challenge that should be sent to the client.

        The challenge is sent in SID_AUTH_ACCOUNTLOGON (0x53).
        Values: salt, server public key"""
        if self.safety_failed:
            return None, None
        return self.s, i2b(self.B, 32)

    def verify(self, client_M):
        """Verifies the client's password proof and returns the server's own proof.

        client_M: a byte array containing the client's password proof value
        """
        if not self.safety_failed and client_M == self.M:
            self._authenticated = True
            return self.AMK
