
from bncs.buffer import DataBuffer, DataReader
from bncs.hashing.cdkeys import KeyDecoder

import asyncio
from datetime import datetime
import logging
import random
import socket


class BnftpClient:
    def __init__(self, host, port=6112):
        self.host = host
        self.port = port
        self.logger = logging.getLogger("BNFTP")

    async def download(self, filename, target=None, key=None, **request):
        """ Downloads a file from the BNFTP server and saves it to disk.

        filename: name of the file to download.
        target: local path to where the file should be saved
        key: optional CD key to authenticate with
        request: other named arguments used in the request.

        Returns a tuple containing the path where the file was saved and the time returned by the server.

            See: https://bnetdocs.org/document/5/file-transfer-protocol-version-1
            and: https://bnetdocs.org/document/6/file-transfer-protocol-version-2
        """
        version = 0x200 if key else 0x100
        filetime = request.get("timestamp", 0)
        product = request.get("product", "D2DV")
        start = request.get("start", 0)
        if not isinstance(filetime, (int, datetime)):
            raise TypeError("Invalid type for timestamp. Must be int or datetime, got %s." % type(filetime).__name__)

        # Locally verify the CD key if used before connecting
        if key:
            key = KeyDecoder.get(key)

            if not key.decode():
                self.logger.error("CD key is invalid.")
                return None, None

            if key.get_product_code() != product:
                self.logger.error("CD key is for a different product.")
                return None, None

        reader, writer = await asyncio.open_connection(self.host, self.port, family=socket.AF_INET)
        self.logger.debug("Connected to '%s'.", writer.get_extra_info("peername"))
        writer.write(b'\x02')           # Protocol selection (0x02 - BNFTP)

        self.logger.info("Requesting file '%s' ...", filename)
        pak = DataBuffer()
        pak.insert_word(20 if key else (33 + len(filename)))
        pak.insert_word(version)
        pak.insert_dword(request.get("platform", "IX86"))
        pak.insert_dword(product)
        pak.insert_dword(request.get("banner_id", 0))
        pak.insert_dword(request.get("banner_ext", 0))

        # This part is sent later for v2
        sub = DataBuffer()
        sub.insert_dword(start)
        if isinstance(filetime, int):
            sub.insert_long(filetime)
        else:
            sub.insert_filetime(filetime)

        if not key:
            pak.insert_raw(sub.data)
            pak.insert_string(filename)

        # Initial request
        self.logger.debug("Request: \n" + repr(pak))
        writer.write(pak.data)
        await writer.drain()

        try:
            pak = DataReader(await reader.readexactly(4 if key else 2))
        except asyncio.IncompleteReadError:
            self.logger.error("Authentication failed." if key else "File not found.")
            return None, None

        # v2 authentication
        if key:
            s_token = pak.get_dword()               # Server token
            c_token = random.getrandbits(32)        # Client token

            self.logger.info("Authenticating...")
            pak = DataBuffer()
            pak.insert_raw(sub.data)
            pak.insert_dword(c_token)
            pak.insert_dword(len(key))
            pak.insert_dword(key.product)
            pak.insert_dword(key.public)
            pak.insert_dword(0)                     # Unknown (0)
            pak.insert_raw(key.get_hash(c_token, s_token))
            pak.insert_string(filename)

            self.logger.debug("Request (pt2): \n" + repr(pak))
            writer.write(pak.data)
            await writer.drain()

            try:
                pak = DataReader(await reader.readexactly(4))
            except asyncio.IncompleteReadError:
                self.logger.error("File not found.")
                return None, None

        # Read the response header
        length = (pak.get_dword() if key else pak.get_word()) - len(pak)
        pak.data += await reader.readexactly(length)
        self.logger.debug("Response: \n" + repr(pak))

        if not key:
            pak.get_word()              # "Type" (not sure what this is)

        file_size = pak.get_dword()
        pak.get_long()                  # Ad banner info (2 DWORD's)
        filetime = pak.get_filetime()
        filename = pak.get_string()

        self.logger.info("File size: %i bytes", file_size)
        self.logger.info("File time: %s", filetime)

        # Receive and write the file to disk.
        target = target or filename
        remaining = file_size
        with open(target, 'wb' if start == 0 else 'ab') as fh:
            while remaining > 0:
                chunk_size = 1024 if remaining > 1024 else remaining
                data = await reader.readexactly(chunk_size)

                fh.write(data)
                remaining -= chunk_size

        self.logger.info("Download complete. File saved to '%s'." % target)

        return target, filetime
