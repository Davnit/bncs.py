
import argparse
import asyncio
import logging
from socket import inet_ntoa
import sys

from bncs import products
from bnls import BnlsClient


log = logging.getLogger(__name__)
logging.basicConfig(stream=sys.stdout, level=logging.INFO)


async def main():
    parser = argparse.ArgumentParser(description="Prints current version information from a BNLS server.")
    parser.add_argument("server", help="The server to check.")
    args = parser.parse_args()

    archive = "ver-IX86-1.mpq"
    formula = "A=5 B=10 C=15 4 A=A+S B=B-C C=C+A A=A-B"

    client = BnlsClient()
    client.connect(args.server)

    for prod in products:
        if prod == "CHAT":
            prod = "W3DM"   # Chat not a BNLS product, so switch with W3DM

        v = await client.check_version(prod, 0, archive, formula)
        # v = (version, checksum, info, verbyte)

        if v:
            bo = "little" if prod in ["WAR3", "W3XP"] else "big"
            ver_str = inet_ntoa(v[0].to_bytes(4, bo))
            log.info("%s - version: %s, info: '%s', verbyte: 0x%0.2X", prod, ver_str, v[2], v[3])
        else:
            log.info("%s - not supported", prod)

    client.close()


if __name__ == "__main__":
    asyncio.run(main())
