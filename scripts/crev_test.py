
import asyncio
import logging
import os.path
import time

from bncs.crev import crev_classic, crev_classic_slow, get_file_meta, CheckRevisionResults
from bnls import BnlsClient


async def main():
    logging.basicConfig(level=logging.DEBUG)

    product = "D2DV"
    mpq = "ver-IX86-1.mpq"
    formula = "A=5 B=10 C=15 4 A=A+S B=B-C C=C+A A=A-B"
    files = [r"C:\Users\David\Documents\Development\BNET\Hashes\D2DV\Game.exe"]

    version, info = get_file_meta(files[0])
    results = CheckRevisionResults(product)
    results.checksum = 1    # Fake value so the output string passes success check
    results.version = version
    results.info = info
    print("LOCAL: %s" % results)

    client = BnlsClient()
    await client.connect("jbls.davnit.net")
    data = await client.check_version(product, 0, mpq, formula)
    if data is None:
        print("NOTICE! BNLS failed version check.")
    else:
        print("BNLS: %s" % data.check)
    await client.disconnect()

    print("Running FAST version check (%s) on file(s): %s" % (mpq, ', '.join([os.path.basename(f) for f in files])))
    start = time.perf_counter()
    checksum = crev_classic(formula, mpq, files)
    end = time.perf_counter()
    print("\tChecksum: %.8x" % checksum)
    print("\tElapsed time: %.2f seconds" % (end - start))

    print("Running SLOW version check (%s) on file(s): %s" % (mpq, ', '.join([os.path.basename(f) for f in files])))
    start = time.perf_counter()
    checksum = crev_classic_slow(formula, mpq, files)
    end = time.perf_counter()
    print("\tChecksum: %.8x" % checksum)
    print("\tElapsed time: %.2f seconds" % (end - start))


if __name__ == "__main__":
    asyncio.run(main())
