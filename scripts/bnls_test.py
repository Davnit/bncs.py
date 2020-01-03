
import argparse
import asyncio
import logging
import sys

from bnls import BnlsClient


log = logging.getLogger("BNLS_Tester")
logging.basicConfig(stream=sys.stdout, level=logging.INFO)


async def main():
    parser = argparse.ArgumentParser(description="Prints current version information from a BNLS server.")
    parser.add_argument("server", help="The server to check.")
    parser.add_argument("-t", "--timeout", help="Time in seconds to wait for a response from the server.",
                        default=5, type=int)
    args = parser.parse_args()

    archive = "ver-IX86-1.mpq"
    formula = "A=5 B=10 C=15 4 A=A+S B=B-C C=C+A A=A-B"

    client = BnlsClient()
    client.logger = log

    log.info("Connecting to BNLS server at %s..." % args.server)
    await client.connect(args.server)
    if client.connected:
        log.info("Connected!")
    else:
        log.error("Connection failed.")
        return

    async def check_and_print_version(product):
        obj = await client.check_version(product, 0, archive, formula)
        if obj:
            log.info(obj.check)
        else:
            log.info("%s - not supported", product)

    log.info("Running checks on %i products...", len(client.products))
    await asyncio.wait([check_and_print_version(p) for p in client.products], timeout=args.timeout)

    log.info("Checks complete. Disconnecting...")
    await client.disconnect()
    log.info("Disconnected")


if __name__ == "__main__":
    asyncio.run(main())
