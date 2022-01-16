
from . import classic
from . import lockdown
from . import simple

from .exception import CheckRevisionFailedError
from .results import CheckRevisionResults
from .seeds import find_version_byte

from ..products import BncsProduct

import asyncio
from concurrent.futures import ThreadPoolExecutor
import logging
from os import path, listdir
import re


CREV_CLASSIC = 1
CREV_CLASSIC_EXT = 2
CREV_LOCKDOWN = 3
CREV_SIMPLE = 4


CREV_VERSIONS = {
    r"(\w{4})ver([0-7])\.mpq": CREV_CLASSIC,
    r"ver-(\w{4})-([0-7])\.mpq": CREV_CLASSIC_EXT,
    r"lockdown-(\w{4})-[0-1][0-9]\.mpq": CREV_LOCKDOWN,
    r"CheckRevision(D1)*\.mpq": CREV_SIMPLE
}


hashing_thread_pool = ThreadPoolExecutor()


def get_crev_version(archive):
    """Returns the version of CheckRevision used by a given MPQ archive."""
    for pattern, version in CREV_VERSIONS.items():
        if obj := re.match(pattern, archive):
            return version, obj.groups()[0] if version != 4 else 'IX86'


def format_crev_seed(formula, archive=None):
    """Formats a CheckRevision seed value to be human-friendly."""
    def fmt_ascii():
        return formula.decode('ascii')

    def fmt_bin():
        return "0x" + formula.hex()

    if archive:
        version, _ = get_crev_version(archive)
        return fmt_bin() if version == CREV_LOCKDOWN else fmt_ascii()
    else:
        try:
            return fmt_ascii()
        except UnicodeDecodeError:
            return fmt_bin()


def preload_exe(exe, incl_pubkey, incl_heap):
    classic.get_file_version_and_info(exe)          # Parses PE structure for EXE, always needed
    if incl_pubkey:
        # Simple - extract public key from EXE
        simple.get_public_key(exe)
    if incl_heap:
        lockdown.build_heap(exe)


async def preload(files, version=None):
    """
        Loads the values needed to hash a list of game files with a CheckRevision MPQ archive.

        - files is a list of file paths for the files to be hashed
        - If version is an int then the files will be loaded for that version of CheckRevision.
        - If version is a str then files will be loaded for the CheckRevision version of the archive.
        - If version is None then all supported versions will be loaded.

        Note that this function will not preload the lockdown libraries themselves unless they are
            included in the list of files.
    """
    archive = None
    if isinstance(version, str):
        archive = version
        version, _ = get_crev_version(archive)
    elif version is None:
        version = CREV_LOCKDOWN

    # Remove files from the list if they don't exist
    files = [f for f in files if path.isfile(f)]

    # Build a list of tasks to complete
    loop = asyncio.get_event_loop()
    waiters = []
    count = 0
    for exe in [f for f in files if path.splitext(f)[1] == ".exe"]:
        pubkey = archive is None or (version == CREV_SIMPLE and archive.endswith("D1.mpq"))
        waiters.append(loop.run_in_executor(hashing_thread_pool, preload_exe, exe, pubkey, version == CREV_LOCKDOWN))
        count += 1

    if archive is None or version == CREV_LOCKDOWN:
        for file in [f for f in files if path.splitext(f)[1] not in [".bin", ".exe"]]:
            waiters.append(loop.run_in_executor(hashing_thread_pool, lockdown.build_heap, file))
            count += 1

    # Run the tasks
    if count > 0:
        await asyncio.gather(*waiters)

    return count       # Returns the number of files actually sent to load


def clear_file_cache():
    classic.pe_structs.clear()
    lockdown.heap_data.clear()
    simple.public_keys.clear()


class LocalHashingProvider:
    def __init__(self, file_root, files=None, *, logger=None):
        """
            Creates a new hashing provider for the given products and their files located at file_root.
            products is a dict mapping (platform, product) -> [filenames]
        """
        if files is None:
            files = {}
            for code, product in BncsProduct.all_products.items():
                for platform, f_list in product.hashes.items():
                    files[(platform, product)] = f_list

        self.root = file_root           # Path to base directory where hashing files are located
        self.files = files              # Maps (platform, product) to a list of files used in hashing
        self.cache = {
            "versions": {},             # Maps (platform, product) to version byte
            "results": {}               # Maps (product, archive, seed) to version result
        }
        self.loop = asyncio.get_event_loop()
        self.connected = False          # Set to TRUE once connect() has preloaded hashes
        self.log = logger or logging.getLogger("CREV")

    def get_files(self, product, archive=None, platform=None):
        """
            Returns a list of files needed to complete the version checking process for a given archive.
            If archive is specified, platform will be ignored in favor of the archive's platform.
        """
        if archive:
            version, platform = get_crev_version(archive)
        else:
            version = CREV_LOCKDOWN
            if platform is None:
                raise ValueError("platform is required when no archive is given")

        # Pull file list from configuration
        base_path = path.join(self.root, platform, product)
        files = []
        for file in self.files.get((platform, product), []):
            # For v4, we only need the EXE
            if version == CREV_SIMPLE and path.splitext(file)[1] != ".exe":
                continue

            files.append(path.join(base_path, file))

        # For v3, include the memory dump binary and lockdown library associated with this archive.
        if version == CREV_LOCKDOWN:
            files.append(path.join(base_path, product + '.bin'))

            if archive:
                files.append(path.join(self.root, 'Lockdown', archive.replace(".mpq", ".dll")))

        return files

    async def get_version_byte(self, product, platform=None):
        """
            Returns the version byte value for the  specified product, or None if the value cannot be determined.

            There are 3 methods of finding this value: scanning the game exe for a known pattern,
                using the minor version value from the exe's PE product version value,
                and looking the value up from a pre-generated configuration. This behavior can be controlled
                by manipulating the bncs.crev.SCAN_PATTERNS and bncs.crev.PE_VERSION_LOOKUP dictionaries, which
                map product codes to the parameters for each method.
        """
        platform = platform or 'IX86'

        # Check the cache
        if version := self.cache.get("versions", {}).get((platform, product)):
            return version

        self.log.debug(f"Attempting to determine version byte for ({platform}, {product})...")

        # Find an EXE and extract the value from it
        for file in self.get_files(product, platform=platform):
            if path.splitext(file)[1] == ".exe":
                if not path.isfile(file):
                    raise FileNotFoundError("required hashing file could not be found", file)

                value = await self.loop.run_in_executor(hashing_thread_pool, find_version_byte, file, product)
                if value:
                    if "versions" not in self.cache:
                        self.cache["versions"] = {}

                    self.cache["versions"][(platform, product)] = value
                    return value

    def check_version_blocking(self, product, archive, formula, timestamp):
        # Check the cache
        if results := self.cache.get("results", {}).get((product, archive, formula)):
            return results

        # Runs the actual CheckRevision sequence
        method, platform = get_crev_version(archive)
        files = self.get_files(product, archive)

        self.log.debug(f"Running local version check for {product} with {len(files)} hash files: "
                       f"{', '.join(path.basename(f) for f in files)} ...")

        # Verify that the files actually exist
        if not all(path.isfile(f) for f in files):
            raise FileNotFoundError("one or more required hashing files could not be found",
                                    [f for f in files if not path.isfile(f)])

        if method in [CREV_CLASSIC, CREV_CLASSIC_EXT]:
            # Classic - run formula over blocks of each file
            version, info = classic.get_file_version_and_info(files[0])
            checksum = classic.check_version(formula, archive, files)
        elif method == CREV_LOCKDOWN:
            # Lockdown - seeded hash of key parts of files + (simulated) memory
            version, _ = classic.get_file_version_and_info(files[0])
            checksum, info = lockdown.check_version(formula, files)
        elif method == CREV_SIMPLE:
            # Simple - hash of EXE's version number and (sometimes) public key
            version, checksum, info = simple.check_version(formula, files[0], archive.endswith("D1.mpq"))
        else:
            raise CheckRevisionFailedError(f"Unsupported check revision archive: {archive}")

        results = CheckRevisionResults()
        results.version = version
        results.checksum = checksum
        results.info = info.encode('ascii') if isinstance(info, str) else info

        if "results" not in self.cache:
            self.cache["results"] = {}
        self.cache["results"][(product, archive, formula)] = results
        return results

    async def check_version(self, product, archive, formula, timestamp=0):
        """
            Runs an emulation of the CheckRevision() function from the given archive and returns the results.

            product is the 4-digit product code, ex 'STAR'
            archive is the name of the version checking archive given by the Battle.net server, ex 'CheckRevision.mpq'
            formula is the seed value provided by the server to be used in the checking operation.
            timestamp is currently ignored
        """
        return await self.loop.run_in_executor(hashing_thread_pool, self.check_version_blocking,
                                               product, archive, formula, timestamp)

    async def preload(self, pairs=None, include_lockdown=False):
        """
            Preloads the hashes managed by this provider.
            If pairs is an iterable of (platform, product) tuples then only those files will be loaded.
        """
        self.log.info(f"Preloading hashes for {len(self.files) if pairs is None else len(pairs)} "
                      f"game(s). This may take a while...")

        count = 0
        for key, files in self.files.items():
            if pairs is None or key in pairs:
                base = path.join(self.root, *key)
                count += await preload([path.join(base, f) for f in files])

        if include_lockdown:
            base = path.join(self.root, "Lockdown")
            files = [f for f in listdir(base) if path.splitext(f)[1] == ".dll"]
            self.log.info(f"Preloading heaps for {len(files)} Lockdown libraries. This may also take a while...")
            count += await preload([path.join(base, f) for f in files], CREV_LOCKDOWN)

        self.log.info(f"Preload complete. {count} files loaded.")
        self.connected = (count > 0)
        return count

    async def connect(self, host=None, port=None):
        """Preloads the hashes managed by this provider. Mostly a dummy method for compatibility with BNLS clients."""
        if not self.connected:
            await self.preload()
        return self.connected

    def disconnect(self, reason=None):
        pass

    async def wait_closed(self):
        pass
