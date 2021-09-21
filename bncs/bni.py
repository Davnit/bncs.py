
from struct import unpack
import sys
from tempfile import TemporaryFile

from utils import unmake_dword

from PIL import Image as ImageProc


class IconEntry:
    def __init__(self, flags, width, height, top):
        self.flags = flags
        self.x = width
        self.y = height
        self.codes = []
        self.top = top
        self.image = None

    @property
    def width(self):
        return self.x

    @property
    def height(self):
        return self.y

    @property
    def left(self):
        return 0

    @property
    def size(self):
        return self.width, self.height

    def get_name(self):
        return f"Flags_0x{self.flags:08X}" if self.flags > 0 else \
            f"Code_{self.codes[0]}" if len(self.codes) > 0 else \
            f"Unknown_{self.top}"


class BnetIconFile:
    def __init__(self, fp):
        self.path = fp
        self.version = 0
        self.count = 0
        self.offset = 0
        self.icons = []
        self.image = None

    @classmethod
    def load(cls, file_path):
        """Loads and parses a BNI file"""
        obj = cls(file_path)
        obj.parse()
        return obj

    def parse(self):
        """Parses the BNI header from the file"""
        with open(self.path, 'rb') as fh:
            header_size = unpack('<I', fh.read(4))[0]
            self.version, _, self.count, self.offset = unpack('<HHII', fh.read(header_size - 4))

            for i in range(self.count):
                top = 0 if i == 0 else (self.icons[-1].top + self.icons[-1].height)
                icon = IconEntry(*unpack('<III', fh.read(12)), top)

                if icon.flags == 0:
                    while (code := unpack('<I', fh.read(4))[0]) != 0:
                        icon.codes.append(unmake_dword(code))
                else:
                    fh.read(4)

                self.icons.append(icon)

    def open_image(self):
        """Reads the image data and crops out individual icons"""
        with TemporaryFile() as temp:
            self.extract_tga(temp)
            self.image = ImageProc.open(temp)
            for icon in self.icons:
                icon.image = self.image.crop((0, icon.top, icon.width, icon.top + icon.height))
            return self.image

    def extract_tga(self, dest):
        """Extracts the image data from the BNI file and saves it to 'dest'."""
        with open(self.path, 'rb') as reader:
            reader.seek(self.offset)

            try:
                writer = open(dest, 'wb') if isinstance(dest, str) else dest
                writer.write(reader.read(-1))
            finally:
                if dest != writer:
                    writer.close()

    def extract_icons(self, fname=None):
        """Extracts individual icons and saves them to disk.
            'fname' should be a function taking an IconEntry and returning a file name
        """
        self.open_image()
        for idx, icon in enumerate(self.icons):
            name = fname(icon) if fname else icon.get_name() + ".png"
            icon.image.save(name)
            yield icon, name


def main():
    fp = sys.argv[1]
    file = BnetIconFile.load(fp)

    print(f"BNI file - version: {file.version}, count: {file.count}, offset: {file.offset}")
    for i in range(len(file.icons)):
        icon = file.icons[i]
        print(f"\t#{i + 1:02} - flags: 0x{icon.flags:02X}, size: {icon.width}x{icon.height}, codes: {icon.codes}")

    print("Extracting TARGA image and importing into Pillow...")
    image = file.open_image()
    print("\tFormat:", image.format)
    print("\t  Size:", image.size)
    print("\t  Mode:", image.mode)

    print("Cutting out individual icons...")
    counter = 0
    for _, name in file.extract_icons():
        print(f"\tSaved icon #{counter} to '{name}'")
        counter += 1


if __name__ == "__main__":
    main()