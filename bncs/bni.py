
import logging
from struct import pack, unpack
from tempfile import TemporaryFile

from utils import make_dword, unmake_dword

from PIL import Image as ImageProc, UnidentifiedImageError


log = logging.getLogger("BNCS.BNI")


class IconEntry:
    def __init__(self, flags, width, height, top):
        self.flags = flags
        self.x = width
        self.y = height
        self.codes = []
        self.top = top
        self.image = None
        self.index = None

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
        return f"Flags_0x{self.flags:08X}" if self.flags != 0 else \
            f"Code_{self.codes[0]}" if len(self.codes) > 0 and self.codes[0] != 0 else \
            f"Icon_{self.index}" if self.index is not None else f"Unknown_{self.top}"


class BnetIconFile:
    def __init__(self, fp):
        self.path = fp
        self.version = 0
        self.count = 0
        self.offset = 0
        self.icons = []
        self.bad_format = False

    @classmethod
    def load(cls, file_path):
        """Loads and parses a BNI file"""
        obj = cls(file_path)
        obj.parse()
        return obj

    def parse(self, _double_term=False):
        """Parses the BNI header from the file"""
        self.icons.clear()

        with open(self.path, 'rb') as fh:
            header_size = unpack('<I', fh.read(4))[0]
            self.version, _, self.count, self.offset = unpack('<HHII', fh.read(12))

            if header_size > 16 and self.offset == 0xffffffff:
                self.bad_format = True
                self.offset = header_size + 4
                log.warning(f"BNI file has unusual header size and offset values, swapping")

            for i in range(self.count):
                top = 0 if i == 0 else (self.icons[-1].top + self.icons[-1].height)
                icon = IconEntry(*unpack('<III', fh.read(12)), top)
                icon.index = i

                if icon.flags == 0:
                    while (code := unpack('<I', fh.read(4))[0]) != 0:
                        icon.codes.append(unmake_dword(code))

                    if len(icon.codes) > 0 and "\x00" in icon.codes[0] and 0 in icon.size:
                        if self.bad_format and _double_term:
                            log.error("Unable to parse BNI format - problems in icon table")
                            return False

                        log.warning("Detected badly formatted BNI icon table - attempting workaround")
                        self.bad_format = True
                        return self.parse(_double_term=True)

                    elif len(icon.codes) == 0 and _double_term:
                        # IconCode list might be double-terminated
                        fh.read(4)
                else:
                    fh.read(4)

                self.icons.append(icon)

        return True

    def get_image_size(self):
        """Returns a tuple of (width, height) of the full BNI image."""
        width = max(icon.width for icon in self.icons)
        height = sum(icon.height for icon in self.icons)
        return width, height

    def save(self, dest=None):
        """Writes the BNI data to 'dest'.
            If dest is None, the current path will be used.
            params are passed to the image library's save function
        """
        if dest is None:
            dest = self.path

        with open(dest, 'wb') as fh:
            # BNI Header
            fh.write(pack('<I', 16))
            fh.write(pack('<HHII', self.version, 0, self.count, self.offset))

            # Parameters for the final image data

            image = ImageProc.new("RGB", self.get_image_size())
            top = 0

            for icon in self.icons:
                # Icon metadata
                fh.write(pack('<III', icon.flags, icon.width, icon.height))
                if icon.flags == 0:
                    for idx, code in enumerate(icon.codes):
                        if idx > 32:
                            # 32 code entries max
                            break
                        fh.write(pack('<I', make_dword(code) if isinstance(code, str) else code))
                fh.write(pack('<I', 0))

                if icon.data:
                    # Add the icon's image data to the final image
                    image.paste(icon.image, (0, top, icon.width, top + icon.height))

                # Count the height of the icon even if we don't have image data
                top += icon.height

            # Save the TGA image data to a temporary file and then copy it onto the end of the BNI
            with TemporaryFile() as temp:
                image.save(temp, 'TGA', rle=True)
                temp.seek(0)
                fh.write(temp.read(-1))

    def open_image(self):
        """Reads the image data from the BNI and assigns it to icon entries."""
        with TemporaryFile() as temp:
            self.extract_tga(temp)
            try:
                image = ImageProc.open(temp, formats=('TGA',))
            except UnidentifiedImageError:
                log.error(f"cannot identify image data in BNI: {self.path}")
                return None

            # Crop image data into icons and return the full image
            self.load_icons(image)
            return image

    def load_icons(self, image_data):
        """Loads image data into the individual icon entries"""
        expected_size = self.get_image_size()
        if image_data.size != expected_size:
            raise ValueError(f"Size of image data does not match expected dimensions: {expected_size}")

        for icon in self.icons:
            icon.image = image_data.crop((0, icon.top, icon.width, icon.top + icon.height))

    def extract_tga(self, dest):
        """Extracts the image data from the BNI file and saves it to 'dest'."""
        with open(self.path, 'rb') as reader:
            reader.seek(self.offset)
            if reader.tell() != self.offset:
                raise Exception("BNI image data offset not found")

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
        # Make sure the icons are loaded
        if any(icon.image is None for icon in self.icons):
            self.open_image()

        for idx, icon in enumerate(self.icons):
            name = fname(icon) if fname else icon.get_name() + ".png"
            icon.image.save(name)
            yield icon, name


def main():
    from os import path, mkdir
    import sys

    fp = sys.argv[1]
    file = BnetIconFile.load(fp)

    print(f"BNI file - version: {file.version}, count: {file.count}, offset: {file.offset}")
    for i in range(len(file.icons)):
        icon = file.icons[i]
        print(f"\t#{i + 1:02} - flags: 0x{icon.flags:02X}, size: {icon.width}x{icon.height}, codes: {icon.codes}")

    print("Extracting TARGA image and importing into Pillow...")
    if not (image := file.open_image()):
        print("Error loading image data... saving to disk")
        file.extract_tga(path.basename(path.splitext(fp)[0] + ".tga"))
        return

    print("\tFormat:", image.format, "(" + image.mode + ")")
    print("\t  Size:", image.size)
    print("\t  Info:", image.info)

    print("Cutting out individual icons...")
    if not path.isdir("icons"):
        mkdir("icons")
    counter = 0
    for _, name in file.extract_icons(lambda ic: path.join("icons", ic.get_name() + ".png")):
        print(f"\tSaved icon #{counter} to '{name}'")
        counter += 1


if __name__ == "__main__":
    main()
