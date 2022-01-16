
from os import path
import struct

from .classic import pe_structs
from ..hashing.bsha import lockdown_sha1

import pefile

SEEDS = [
    0xA1F3055A, 0x5657124C, 0x1780AB47, 0x80B3A410, 0xAF2179EA,
    0x0837B808, 0x6F2516C6, 0xE3178148, 0x0FCF90B6, 0xF2F09516,
    0x378D8D8C, 0x07F8E083, 0xB0EE9741, 0x7923C9AF, 0xCA11A05E,
    0xD723C016, 0xFD545590, 0xFB600C2E, 0x684C8785, 0x58BEDE0B
]

heap_data = {}


def build_heap(file):
    key = file.lower()
    if (pe := pe_structs.get(key)) is None:
        pe = pe_structs[key] = pefile.PE(file)

    if (heap := heap_data.get(key)) is None:
        heap = LockdownHeap()
        if pe.has_relocs():
            # noinspection PyTypeChecker
            process_reloc(pe, heap)

        # noinspection PyTypeChecker
        process_import(pe, heap)

        # Sort the heap and store it in the cache
        heap.sort()
        heap_data[key] = heap

    return heap, pe


def shuffle_seed(seed):
    pos = 0
    buff = bytearray(0x10)

    for x in range(len(seed), 0, -1):
        shifter = 0
        for i in range(pos):
            b = buff[i]
            buff[i] = ((-buff[i] + shifter) & 0xff)
            shifter = (((((b << 8) - b) + shifter) >> 8) & 0xff)

        if shifter > 0:
            if pos >= 0x10:
                return None
            buff[pos] = shifter
            pos += 1

        adder = (seed[x - 1] - 1)
        i = 0
        while (i < pos) and (adder > 0):
            buff[i] = ((buff[i] + adder) & 0xff)
            adder = 1 if (buff[i] < adder) else 0
            i += 1

        if adder > 0:
            if pos >= 0x10:
                return None
            buff[pos] = adder
            pos += 1

    while pos < 0x10:
        buff[pos] = 0
        pos += 1

    return buff


def ld_shift(word1, word2):
    s1, s2 = word2, word1

    s2 = ((((s1 >> 8) + (s1 & 0xff)) >> 8) + (((s1 >> 8) + (s1 & 0xff)) & 0xff)) & 0xffff
    s2 = ((s2 & 0xff00) | (((s2 + 1) & 0xff) - (1 if (s2 & 0xff) != 0xff else 0))) & 0xffff

    s1 = (((s1 - s2) & 0xff) | (0 if ((((s1 - s2) >> 8) & 0xff) + 1) > 0 else 0x100)) & 0xffff
    s1 = ((s1 & 0xff00) | (-s1 & 0xff)) & 0xff

    return s2, s1


def shuffle_digest(digest):
    buff = bytearray(0xff)
    digest = bytearray(digest)

    x = 0x10
    position = 0
    while x > 0:
        while x > 0 and digest[x - 1] == 0:
            x -= 1

        if x > 0:
            w1 = 0
            for y in range(x - 1, -1, -1):
                w2 = (w1 << 8) + digest[y]
                w1, w2 = ld_shift(w1, w2)
                digest[y] = w2 & 0xff

            buff[position] = (w1 + 1) & 0xff
            position += 1

    return bytes(buff[0:position])


def pad_ldsha(ctx, amount):
    while (count := 0x1000 if amount > 0x1000 else amount) > 0:
        ctx.update(bytes(count))
        amount -= count


def hash_file(ctx, file_path, library):
    heap, pe = build_heap(file_path)

    # Get the size of the PE header and hash all bytes of the file up to that
    header = pe.OPTIONAL_HEADER
    header_size = (header.SizeOfHeaders + header.FileAlignment - 1) & ~(header.FileAlignment - 1)
    ctx.update(pe.get_data(0, header_size))
    # print("PE header: " + ctx.debug())

    seed = SEEDS[int(path.basename(library).split('-')[2][:2])]

    for section in pe.sections:
        hash1(ctx, heap, pe, section, seed)
        # print("state: " + ctx.debug())


def hash1(ctx, heap, pe, section, seed):
    section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
    section_size = section.Misc_VirtualSize

    padding = ((section_size + section_alignment - 1) & ~(section_alignment - 1)) - section_size

    # print("Hash1: %s" % section.Name.strip(b'\0').decode('ascii'))
    if section.Characteristics & 0x80000000:
        pad_ldsha(ctx, padding + section_size)
        # print("Hash1: LD pad: %i" % ((padding + section_size),))
    else:
        i, index = 0, 0
        if heap.length > 0:
            while index < heap.length and heap.extract(i, 1) < section.VirtualAddress:
                i, index = i + 4, index + 1

        if section_size > 0:
            ptr_mem = section.VirtualAddress
            while (ptr_mem - section.VirtualAddress) < section.Misc_VirtualSize:
                length = section.VirtualAddress - ptr_mem + section.Misc_VirtualSize

                s = 0
                if index < heap.length:
                    s = heap.extract(index * 4, 1)

                if s > 0:
                    s -= ptr_mem
                    if s < length:
                        length = s

                if length > 0:
                    # print("Hash1: %i PE bytes @ 0x%x" % (length, ptr_mem))
                    ctx.update(section.get_data(ptr_mem, length))
                    ptr_mem += length
                else:
                    hash2(ctx, pe, heap.extract(index * 4), ptr_mem, seed)
                    ptr_mem += heap.extract(index * 4 + 1, 1)
                    index += 1

        if padding != 0:
            buff = bytearray(padding)
            i = 0
            while i < padding:
                s = 0
                if index < heap.length:
                    s = heap.extract(index * 4, 1) - section.Misc_VirtualSize - section.VirtualAddress + buff[0]

                padding += i
                if s > 0:
                    s -= struct.unpack_from('<L', buff, i)[0]
                    if s < padding:
                        padding = s

                if padding != 0:
                    # print("Hash1 (pad): %i bytes" % padding)
                    ctx.update(buff[i:i+padding])
                    i += padding
                else:
                    hash2(ctx, pe, heap.extract(index * 4), buff[i], seed)
                    index += 1
                    i += heap.extract(index * 4 + 1, 1)


def hash2(ctx, pe, memory, pointer, seed):
    if memory[2] == 0:
        if memory[3] == 0:
            pad_ldsha(ctx, memory[1])
            # print("Hash2 LD pad: %x" % memory[1])
        else:
            tmp = pe.get_data(memory[3], memory[1])
            # print("Hash2 (0): %i bytes @ %x" % (memory[1], memory[3]))
            ctx.update(tmp)

    elif memory[2] == 1:
        tmp = bytearray(0x14)
        if pointer != 0:
            tmp[:0x14] = pe.get_data(pointer, 0x14)

        # print("Hash2 (1): 20 bytes @ %x" % pointer)
        ctx.update(tmp)

    elif memory[2] == 2:
        if memory[3] == 3:
            value = 0
            if pointer != 0:
                value = pe.get_dword_at_rva(pointer) ^ seed

            tmp = struct.pack('<L', value)
            # print("Hash2 (2): %x" % value)
            ctx.update(tmp)


def process_reloc(pe, heap):
    type_lookup = {0x0a: 8, 3: 4, 2: 2}     # 64, 32, 16 bit respectively
    for reloc in pe.DIRECTORY_ENTRY_BASERELOC:
        for entry in reloc.entries:
            if entry.type > 0:
                data_size = type_lookup.get(entry.type)
                if data_size is None:
                    raise ValueError("Unknown PE relocation type: %i" % entry.type)

                heap.add(struct.pack('<4L', entry.rva, data_size, 2, entry.type))


def process_import(pe, heap):
    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        return

    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']]
    address = directory.VirtualAddress

    for module in pe.DIRECTORY_ENTRY_IMPORT:
        eax = (len(module.imports) * 4) + 4
        heap.add(struct.pack('<4L', module.struct.FirstThunk, eax, 0, module.struct.OriginalFirstThunk))
        heap.add(struct.pack('<4L', address, 0x14, 1, 0))
        address += 0x14


def check_version(seed, files):
    # We need at least 3 files to do this: exe, mem dump, library
    if len(files) < 3:
        raise ValueError("Not enough files to complete Lockdown CheckRevision")

    library = files.pop()       # files[4] == archive 'lockdown-XXXX-YY.mpq'
    memdump = files.pop()       # files[3] == bin 'ZZZZ.bin'

    if (not library.startswith("lockdown-") or not library.endswith(".mpq")) or \
            (len(memdump) != 8 or not memdump.endswith(".bin")):
        raise ValueError("Invalid files passed to Lockdown CheckRevision. Screen dump and library must come last.")

    ctx = lockdown_sha1()

    # Decode the seed value
    vs_buffer_1 = bytearray([ord('6')] * 0x40)
    vs_buffer_2 = bytearray([ord('\\')] * 0x40)
    vs_encoded = shuffle_seed(seed)
    for i in range(0x10):
        vs_buffer_1[i] ^= vs_encoded[i]
        vs_buffer_2[i] ^= vs_encoded[i]
    ctx.update(vs_buffer_1)

    # Process and hash files
    hash_file(ctx, library, library)        # Hash the lockdown library itself
    for file in files:
        hash_file(ctx, file, library)       # Hash the actual game files (exe, storm, snp)

    # Hash the game's video memory dump (not created at runtime)
    with open(memdump, 'rb') as fh:
        ctx.update(fh.read())

    ctx.update(b'\x01\x00\x00\x00')
    ctx.update(b'\x00\x00\x00\x00')
    out_buff_1 = ctx.digest()

    ctx = lockdown_sha1()
    ctx.update(vs_buffer_2)
    ctx.update(out_buff_1)
    out_buff_2 = ctx.digest()

    info = shuffle_digest(out_buff_2[4:])
    checksum = struct.unpack_from('<L', out_buff_2, 0)[0]
    return checksum, info


class LockdownHeap:
    def __init__(self):
        self.length = 0
        self.maximum = 0x1000
        self.memory = bytearray(self.maximum)

    def add(self, data):
        if len(data) % 0x10 != 0:
            raise ValueError("Heap data must have length multiple of 16 bytes")

        size = len(data)
        while (self.length + size) >= self.maximum:
            self.maximum *= 2
            self.memory.extend([0] * (self.maximum - self.length))

        position = self.length * 0x10
        self.memory[position:position + size] = data
        self.length += (size // 0x10)

    def extract(self, start=0, length=4):
        values = struct.unpack_from(f'<{length}L', self.memory, start * 4)
        return values[0] if length == 1 else values

    def hex(self):
        return self.memory[:self.length * 0x10].hex()

    def sort(self):
        values = []
        for i in range(self.length):
            values.append(struct.unpack_from('<4L', self.memory, i * 0x10))

        values = sorted(values, key=lambda v: v[0])

        for i in range(self.length):
            struct.pack_into('<4L', self.memory, i * 0x10, *values[i])
