
class AdminFlags:
    def __init__(self, value):
        if isinstance(value, int):
            self.value = value
        else:
            self.value = 0
            self.set_flags(value)

    def to_binary_string(self):
        """Returns flags as a string of binary digits."""
        return bin(self.value)[2:].zfill(26)

    def to_flag_string(self):
        """Returns indicators for set flags."""
        flags = ""
        b_str = self.to_binary_string()
        for i in range(26):
            if b_str[i] == "1":
                flags += chr(i + 65)        # Add alphabet character corresponding to this position
        return flags

    def has_flag(self, f):
        """Returns True if a flag is set."""
        return f in self.to_flag_string()

    def has_any_flag(self, flags=None):
        """Returns True if any given flag is set"""
        if flags:
            f_str = self.to_flag_string()
            return any(f for f in flags if f in f_str)
        else:
            return self.value > 0

    def set_flags(self, flags):
        """Overwrites all flags."""
        bits = ["0"] * 26
        for f in flags.upper():
            bits[ord(f) - 65] = "1"
        self.value = int(''.join(bits), 2)

    def set_flag(self, flag):
        """Sets a specific flag."""
        self.set_flags(self.to_flag_string() + flag)

    def unset_flag(self, flag):
        """Unsets a specific flag."""
        self.set_flags(self.to_flag_string().replace(flag, ''))

    @property
    def superuser(self):
        """Can perform any administrative action"""
        return self.has_flag("A")

    @property
    def broadcast(self):
        """Can use talk-to-all"""
        return self.has_flag("B")

    @property
    def connection(self):
        """May administer service connectivity"""
        return self.has_flag("C")

    @property
    def database(self):
        """May create and maintain databases"""
        return self.has_flag("D")

    @property
    def id_control(self):
        """May create and modify hub ID's"""
        return self.has_flag("I")

    @property
    def botnet_service(self):
        """The BotNet service"""
        return self.has_flag("S")
