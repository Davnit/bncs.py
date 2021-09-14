
import argparse
import asyncio
import logging
import random

from bnls import BnlsClient


async def main(args):
    client = BnlsClient(logger=logging.getLogger("BNLS_Probe"))
    log = client.log

    log.info(f"Connecting to BNLS server at {args.server}...")
    await client.connect(args.server)
    if not client.connected:
        log.error("BNLS connection failed.")
        return

    number = random.randint(0, 7)
    archive = f"ver-IX86-{number}.mpq"
    std_formula = "A=5 B=10 C=15 4 A=A+S B=B-C C=C+A A=A-B"
    ld_seed = 0x7B45A6249337FBEDF9DA86C8D6E07F9A.to_bytes(length=16, byteorder='little')
    cd_seed = 'b1cZwQAA'

    async def check_and_print_version(p):
        try:
            if obj := await client.check_version(p, archive, std_formula, 0, timeout=args.timeout):
                log.info(f"{obj.check} (0x{obj.verbyte:02X})")
            else:
                log.info(f"{p} - not supported")
        except asyncio.TimeoutError:
            log.info(f"{p} - timed out")

    async def get_version_check_result(p2, a, f):
        try:
            obj = await client.check_version(p2, a, f, 0, timeout=args.timeout)
            return "ok" if obj and obj.check.success else "fail"
        except asyncio.TimeoutError:
            return "timeout"

    log.info(f"Running standard checks on {len(client.products)} products...")
    await asyncio.gather(*[check_and_print_version(prd.code) for prd in client.products.values()])

    if args.extended:
        # Find a product that returned a good check from the standard list
        good_products = [p.code for p in client.products.values() if p.check and p.check.success]
        if len(good_products) == 0:
            log.error("Extended checks are not available because no products completed the standard check.")
            client.disconnect()
            await client.wait_closed()
            return

        product = good_products[0]
        archives = [
            f"ver-XMAC-{number}.mpq", f"ver-PMAC-{number}.mpq", f"IX86ver{number}.mpq", f"XMACver{number}.mpq",
            f"PMACver{number}.mpq", f"ver-IX86-{number * number}.mpq"
        ]

        log.info(f"Running checks for alternate archives...")
        for archive in archives:
            log.info(f"{archive} ({product}): {await get_version_check_result(product, archive, std_formula)}")

        for product in good_products:
            log.info(f"CRevD1 ({product}): {await get_version_check_result(product, 'CheckRevisionD1.mpq', cd_seed)}")

        for product in ["SSHR", "DRTL", "W2BN"]:
            if product in good_products:
                for i in range(20):
                    archive = f"lockdown-IX86-{i:02}.mpq"
                    log.info(f"Lockdown-{i:02} ({product}): "
                             f"{await get_version_check_result(product, archive, ld_seed)}")
                break

    log.info("Checks complete. Disconnecting...")
    client.disconnect()
    await client.wait_closed()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Prints current version information from a BNLS server.")
    parser.add_argument("server", help="The server to check.")
    parser.add_argument("-t", "--timeout", help="Time in seconds to wait for a response from the server.",
                        default=5, type=int)
    parser.add_argument("-e", "--extended", help="Runs extended checks", action='store_true')

    logging.basicConfig(level=logging.INFO)

    aa = parser.parse_args()
    asyncio.run(main(aa))
