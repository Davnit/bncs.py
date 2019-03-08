
from bncs.common import buffer

import datetime
import hashlib
import socket
import struct
import threading


class BnftpClient:
    def __init__(self, host=None, port=None):
        self.host = host or "useast.battle.net"
        self.port = port or 6112
        self.socket = None
        self.position = 0
        self.filename = None
        self.filetime = None
        self.size = None
        self.write_to_disk = True
        self.thread = None
        self.data = None
        self.hash = hashlib.md5()
        self.started_callback = None
        self.completed_callback = None
        self._connected = False

    def connect(self, host=None):
        # Connect to the server
        self.host = host or self.host
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
        self._connected = True

        # Send protocol selection byte (BNFTP)
        self.socket.sendall(b'\x02')

    def disconnect(self):
        self.socket.close()
        self._connected = False

    @property
    def completed(self):
        return (self.size - self.position) == 0

    def request(self, filename, **kwargs):
        if not self._connected:
            if self.host:
                self.connect()
            else:
                raise ValueError("BNFTP request must have hostname set.")

        self.filename = filename
        self.filetime = kwargs.get("filetime") or 0
        self.position = kwargs.get("position") or self.position
        self.write_to_disk = kwargs.get("write") or self.write_to_disk

        pak = buffer.DataBuffer()
        pak.insert_word(kwargs.get("protocol") or 0x100)
        pak.insert_dword(kwargs.get("platform") or "IX86")
        pak.insert_dword(kwargs.get("product") or "D2DV")
        pak.insert_dword(kwargs.get("bannerID") or 0)
        pak.insert_dword(kwargs.get("bannerExt") or 0)

        pak.insert_dword(self.position)

        if isinstance(self.filetime, datetime.datetime):
            pak.insert_filetime(self.filetime)
        else:
            pak.insert_long(self.filetime)
        pak.insert_string(filename)

        data = struct.pack('<H', len(pak) + 2) + pak.data
        self.socket.sendall(data)

        if not self.write_to_disk:
            self.data = b''

        self.thread = threading.Thread(target=self._receive)
        self.thread.start()

    def _receive(self):
        pak = buffer.DataReader(self.socket.recv(2))
        if len(pak) == 0:
            raise Exception("Received empty response from server.")

        # Get the header length
        length = pak.get_word()
        if length < 25:
            raise Exception("Server responded with invalid header (length: %i)" % length)

        # Receive the rest of the header.
        pak.data += self.socket.recv(length - 2)
        file_type, file_size, banner_id, banner_ext = pak.get_format('<HIII')
        self.filetime = pak.get_filetime()
        filename = pak.get_string()
        self.size = file_size

        # Check for different filename
        if filename.lower() != self.filename.lower():
            print("NOTICE! Server returned response for file with different name: %s" % filename)
            self.filename = filename

        # Inform any listeners that the download has started.
        if self.started_callback:
            self.started_callback(file_size, self.filename, self.filetime)

        # If writing a file, open it.
        fh = None
        if self.write_to_disk:
            fh = open(self.filename, "wb" if self.position == 0 else "ab")

        # Receive the file content
        while not self.completed:
            bytes_left = self.size - self.position
            data = self.socket.recv(bytes_left)

            # Check that receive call was OK
            if len(data) == 0:
                # Either way we're terminating so close the file if its open.
                if fh:
                    fh.close()
                    fh = None

                if bytes_left > 0:
                    raise Exception("Connection terminated before file fully received (%i bytes left)" % bytes_left)
                else:
                    break

            # Append received data
            self.position += len(data)
            if fh:
                fh.write(data)
            else:
                self.data += data

            # Update hash
            if self.hash:
                self.hash.update(data)

        if fh:
            fh.close()

        self.disconnect()
        if self.completed_callback:
            self.completed_callback()
