# bncs.py
Python library for classic Battle.net client development.

For more information on available functions and classes, refer to [the wiki](https://github.com/Davnit/bncs.py/wiki).

## Packages
* `bncs` - handles connecting to and interacting with the Battle.net Chat Service
  * `chat` - relating to the chat environment (users, channels, flags)
  * `crev` - functions and classes for handling the client version checking process - supports classic, lockdown, and simple/modern variants
    * `get_file_meta(file)` - returns the version number (DWORD) and filename, timestamp, and size of the given file, usually an EXE
    * `LocalHashingProvider(root)` - class which performs version checking operations from the local file system, partially interface compatible with `bnls.BnlsClient()`
  * `hashing` - handles CD key and password hashing
    * `KeyDecoder.get(key)` - decodes a given CD/product key and identifies it
    * `NLSClient(username, password)`, `NLSServer` - client and server implementations of the 'new login system' (NLS), an SRP-based system for verifying account logins
    * `check_signature(sig, ip)` - verifies that the signature presented by a server is valid for that server's IP address
    * `hash_password(password)`, `double_hash_password(password, c_token, s_token)`, `xsha1(data)` - hashes passwords and other data with Blizzard's custom SHA1 implementation
    * `lockdown_sha1(data)` - hashes data using another one of Blizzard's custom SHA1 implementations
  * `mcp` - handles the Diablo 2 realm service
  * `products` - contains packet ID constants and classes for reading and writing BNCS packets
  * `utils` - generic utilities (packet buffer, async TCP client)
  * `BnetClient()` - handles a complete connection to the chat service
  * `BnetProduct.get(pid)` - provides access to metadata on game clients that can connect to Battle.net
  * `BnetIconFile.load(file)` - extracts game icons from an icon file (.bni)
  * `CreditQueue()` - a system for delaying outbound chat messages to avoid rate limiting/flooding
* `bnls` - the Battle.net Logon Service (3rd party)
  * `BnlsClient()` - a client for interacting with a BNLS server
* `bnftp` - the Battle.net FTP service
  * `BnftpClient` - downloads files available through the BNFTP protocol
* `botnet` - the Valhalla Legends BotNet service (used for inter-bot communication)
  * `BotNetClient` - a client for interacting with a BotNet server
