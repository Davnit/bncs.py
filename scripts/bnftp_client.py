
from bnftp import BnftpClient

import argparse
from datetime import datetime
import hashlib


parser = argparse.ArgumentParser(description="Downloads a file from the Battle.net FTP service.")
parser.add_argument("file", help="The name of the file to download.")
parser.add_argument("--server", default="useast.battle.net", help="The hostname or IP of the BNFTP server.")
parser.add_argument("--port", type=int, default=6112, help="The port on the server where BNFTP is listening.")
parser.add_argument("--time", help="The expected filetime of the requested file.")
parser.add_argument("--platform", default="IX86", help="The 4-character platform code identifying the system.")
parser.add_argument("--product", default="D2DV", help="The 4-character game code associated with the file.")
parser.add_argument("--banner", default=[0, 0], nargs=2, metavar=('ID', 'EXT'),
                    help="The requested banner ID and extension.")
parser.add_argument("--position", default=0, help="The position in the file to start the download.")
parser.add_argument("--protocol", default=0x100, help="The BNFTP protocol version to use.")
parser.add_argument("--hash", const="md5", nargs='?', help="Prints the hash of the completed file.")
parser.add_argument("--no-write", dest="write", action='store_false',
                    help="Keeps the file in memory and does not write it to disk.")

args = parser.parse_args()

ft = None
if args.time:
    if args.time.isdigit():
        ft = int(args.time)         # Normal int
    elif args.time[0:2] == "0x":
        ft = int(args.time, 16)     # Hex int
    else:
        ft = datetime.strptime(args.time, "%Y-%m-%d %H:%M:%S")

kw = {
    "filetime": ft,
    "position": args.position,
    "protocol": args.protocol,
    "product": args.product,
    "bannerID": args.banner[0],
    "bannerExt": args.banner[1],
    "write": args.write
}


def download_started(size, name, ftime):
    print("Received BNFTP response:")
    print("\tFile name: %s" % name)
    print("\tSize     : %i" % size)
    print("\tFiletime : %s" % ftime)


def download_complete():
    if args.hash:
        print("Hash: %s" % client.hash.hexdigest())
    print("Download complete.")


client = BnftpClient(args.server, args.port)
client.started_callback = download_started
client.completed_callback = download_complete

# If a hashing algorithm other than the default was specified, initialize it.
if args.hash and args.hash.lower() != "md5":
    client.hash = hashlib.new(args.hash)

print("Requesting file '%s' as %s-%s from BNFTP at %s..." % (args.file, args.platform, args.product, args.server))
client.request(args.file, **kw)
