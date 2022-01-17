
import argparse
import asyncio
import logging
import time

from bncs import LocalHashingProvider, BncsProduct
from bnls import BnlsClient


def print_result(t):
    r, d = t.result()
    print(f"Results: {r}")
    print(f"Time taken: {d} seconds")


async def main(args):
    logging.basicConfig(level=logging.DEBUG)

    # Seed can be either an ASCII string or a hex number
    if args.seed[:2] == "0x" and ' ' not in args.seed:
        seed = int(args.seed, 16).to_bytes(16, 'little', signed=False)
    else:
        seed = args.seed.encode('ascii')

    product = BncsProduct.get(args.product)
    local = LocalHashingProvider(args.hashes)
    await local.preload([('IX86', product.code)], version=args.archive)

    # remote = BnlsClient()
    # await remote.connect()

    async def run_test(src, tag):
        print(f"Starting {tag} test on {product.code} with archive {args.archive}")
        start = time.perf_counter()
        result = await src.check_version(product.code, args.archive, seed)
        duration = (time.perf_counter() - start)
        return result, duration

    task = asyncio.create_task(run_test(local, "LOCAL"))
    task.add_done_callback(print_result)
    await task

    # remote.disconnect("done")
    # await remote.wait_closed()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("product", type=str, help="4 digit product code")
    parser.add_argument("archive", type=str, help="Name of the version checking archive")
    parser.add_argument("seed", type=str, help="Version checking formula or hex value of the seed")
    parser.add_argument("hashes", type=str, help="Path to root of hash file directory")

    asyncio.run(main(parser.parse_args()))
