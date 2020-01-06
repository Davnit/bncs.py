# bncs.py
Python library for classic Battle.net client development.

For more information on available functions and classes, refer to [the wiki](https://github.com/Davnit/bncs.py/wiki).

## Packages
* `bncs` - the main Battle.net Chat Service (BNCS)
  * `crev` - functions and classes for handling CheckRevision
    * `check_version(archive, formula, [files[]], [platform], [timestamp])` - performs CheckRevision() and returns results
    * `get_file_meta(file)` - returns version number and info string of a PE file
    * NOTE: Lockdown CheckRevision is not currently supported and will raise an exception if attempted.
  * `utils` - general utilities for the library and BNET ecosystem
    * `DataBuffer`, `DataReader` - binary packet buffer for writing and reading respectively
  * `hashing` - handles XSha1, NLS, and SigVerify (CD key and password hashing)
    * `KeyDecoder` - decodes CD keys and returns hashing values
    * `NLSClient`, `NLSServer` - client and server implementations of the 'new login system' (NLS)
    * `check_signature(sig, ip)` - server signature verification
    * `xsha()`, `hash_password`, `double_hash_password` - Broken SHA-1 (xsha) hashing
* `bnls` - the Battle.net Logon Service (3rd party)
  * `BnlsClient` - a client for interacting with a BNLS server
* `bnftp` - the Battle.net FTP service
  * `BnftpClient` - downloads files available through the BNFTP protocol
* `botnet` - the Valhalla Legends BotNet service (used for inter-bot communication)
  * `BotNetClient` - a client for interacting with a BotNet server
  
Packages also contain constants used with each system. (SID_AUTH_INFO, BNLS_AUTHORIZE, EID_SHOWUSER, etc).
