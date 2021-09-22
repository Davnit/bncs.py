
from hashlib import sha1
from os import path
from struct import pack, unpack
import sys
from tempfile import TemporaryFile

from utils import make_dword, unmake_dword

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

    def save(self, dest=None):
        """Writes the BNI data to 'dest'. If dest is None, the current path will be used."""
        if dest is None:
            dest = self.path

        with open(dest, 'wb') as fh:
            # BNI Header
            fh.write(pack('<I', 16))
            fh.write(pack('<HHII', self.version, 0, self.count, self.offset))

            # Parameters for the final image data
            width = max(icon.width for icon in self.icons)
            height = sum(icon.height for icon in self.icons)
            image = ImageProc.new("RGB", (width, height))
            top = 0

            for icon in self.icons:
                # Icon metadata
                fh.write(pack('<III', icon.flags, icon.width, icon.height))
                if icon.flags == 0:
                    for idx, code in enumerate(icon.codes):
                        if idx > 32:
                            # 32 code entries max
                            break
                        fh.write(pack('<I', make_dword(code)))
                fh.write(pack('<I', 0))

                if icon.image:
                    # Add the icon's image data to the final image
                    image.paste(icon.image, (0, top, icon.width, top + icon.height))

                # Count the height of the icon even if we don't have image data
                top += icon.height

            # Save the Targa image data to a temporary file and then copy it onto the end of the BNI
            with TemporaryFile() as temp:
                image.save(temp, 'TGA', rle=True)
                temp.seek(0)
                fh.write(temp.read(-1))

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


def hash_file(fp):
    ctx = sha1()
    with open(fp, 'rb') as fh:
        while data := fh.read(ctx.block_size * 1024):
            ctx.update(data)
    return ctx


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

    print("Saving duplicate file...")
    fname, ext = path.splitext(fp)
    new_file = fname + "2" + ext
    file.save(new_file)

    print("Comparing hashes...")
    print("\tOriginal:", hash_file(fp).hexdigest())
    print("\t    Copy:", hash_file(new_file).hexdigest())


if __name__ == "__main__":
    main()
