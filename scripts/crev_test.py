
import argparse
import asyncio
import logging
import time

from bncs import LocalHashingProvider, BncsProduct
from bnls import BnlsClient


async def main(args):
    logging.basicConfig(level=logging.DEBUG)

    # Seed can be either an ASCII string or a hex number
    if args.seed[:2] == "0x" and ' ' not in args.seed:
        seed = int(args.seed, 16).to_bytes(16, 'little', signed=False)
    else:
        seed = args.seed.encode('ascii')

    product = BncsProduct.get(args.product)

    remote = BnlsClient()
    local = LocalHashingProvider(args.hashes)

    await asyncio.gather(
        local.preload([('IX86', product.code)], version=args.archive),
        remote.connect()
    )

    async def run_test(src, tag):
        print(f"Starting {tag} test on {product.code} with archive {args.archive}")
        start = time.perf_counter()
        result = await src.check_version(product.code, args.archive, seed)
        duration = (time.perf_counter() - start)
        print(f"{tag} {result} (time: {duration:.3f}s)")

    remote_test = asyncio.create_task(run_test(remote, "REMOTE"))
    local_test = asyncio.create_task(run_test(local, "LOCAL"))

    await asyncio.gather(remote_test, local_test)

    remote.disconnect("done")
    await remote.wait_closed()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("product", type=str, help="4 digit product code")
    parser.add_argument("archive", type=str, help="Name of the version checking archive")
    parser.add_argument("seed", type=str, help="Version checking formula or hex value of the seed")
    parser.add_argument("hashes", type=str, help="Path to root of hash file directory")

    asyncio.run(main(parser.parse_args()))
