
import argparse
import asyncio
from datetime import datetime
import hashlib
import logging
import sys

import bnftp.client


log = logging.getLogger("BNFTP")
bnftp.client.log = log
logging.basicConfig(stream=sys.stdout, level=logging.INFO)


async def main():
    parser = argparse.ArgumentParser(description="Downloads a file from BNFTP.")
    parser.add_argument("file", help="Name of the file to download.")
    parser.add_argument("--ftime", default="0", help="Filetime of the requested file.")
    parser.add_argument("--platform", default="IX86", help="4-char system platform code.")
    parser.add_argument("--product", default="D2DV", help="4-char game product code.")
    parser.add_argument("--start", type=int, default=0, help="Offset from which to start the download.")
    parser.add_argument("--banner", nargs=2, default=[0, 0], help="Requested AD banner ID and extension.")
    parser.add_argument("--key", help="Product key used for authentication.")
    parser.add_argument("--outfile", help="Path to save the file.")
    parser.add_argument("--server", default="useast.battle.net:6112", help="Server to download from.")
    parser.add_argument("--hash", action='store_true', help="Prints the MD5 hash of the downloaded file.")

    args = parser.parse_args()

    server = args.server.split(':')
    host = server[0]
    try:
        port = int(server[1]) if len(server) > 1 else 6112
    except ValueError:
        log.error("Invalid server/port specified. Use format: <host>[:port]")
        sys.exit(1)

    client = bnftp.client.BnftpClient(host, port)

    try:
        if args.ftime.isdigit():
            ft = int(args.ftime)
        elif args.ftime.isalum():
            ft = int(args.ftime, 16)
        else:
            ft = datetime.strptime(args.ftime, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        log.error("Invalid filetime specified. Must be int, hex, or datetime in format 'Y-m-d H:M:S'.")
        sys.exit(1)

    request = {
        "timestamp": ft,
        "platform": args.platform,
        "product": args.product,
        "start": args.start,
        "banner_id": args.banner[0],
        "banner_ext": args.banner[1],
    }

    saved_to, filetime = await client.download(args.file, args.outfile, args.key, **request)
    log.info("File saved to '%s'.", saved_to)

    if args.hash:
        blocksize = 64 * 1000
        h = hashlib.md5()
        with open(saved_to, 'rb') as fh:
            buf = fh.read(blocksize)
            while len(buf) > 0:
                h.update(buf)
                buf = fh.read(blocksize)
        log.info("MD5: %s", h.hexdigest())


if __name__ == "__main__":
    asyncio.run(main())
