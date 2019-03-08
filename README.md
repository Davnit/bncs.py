# bncs.py
Python library for classic Battle.net client development.

For more information on available functions and classes, refer to [the wiki](https://github.com/Davnit/bncs.py/wiki).

## Packages
* `bncs` - contains functions related to the Battle.net Chat Service
  * `DataBuffer`, `DataReader` - binary packet buffer for writing and reading respectively
  * `KeyDecoder` - decodes CD keys and returns hashing values
  * `NLS_Client`, `NLS_Server` - client and server implementations of the 'new login system' (NLS)
  * `check_signature(sig, ip)` - server signature verification
  * `xsha()`, `hash_password`, `double_hash_password` - Broken SHA-1 (xsha) hashing
  * `BncsClient` - a lightweight BNCS client for connecting to Battle.net
* `bnls` - contains functions related to the Battle.net Logon Service (3rd party)
  * `BnlsClient` - a client for connecting to and interacting with a BNLS server
* `bnftp` - contains clients for the Battle.net FTP service
  * `BnftpClient` - downloads files available through V1 of the BNFTP protocol
  
Both packages also contain constants used with each system. (SID_AUTH_INFO, BNLS_AUTHORIZE, EID_SHOWUSER, etc).
  
## Scripts
* `bncs_client.py` - a command-line implementation of `bncs.BncsClient` providing a very basic chat experience
  * To run: `python bncs_client.py <server> <product> <key1>,[key2] <account> <password>`
    * eg: `python bncs_client.py useast.battle.net WAR3 xxx myuser mypass`
* `bnftp_client.py` - a command-line implementation of `bnftp.BnftpClient` allowing retrieval of files from the BNFTP service.
  * To run: `python bnftp_client.py <file> [--server useast.battle.net] [--product D2DV]`
    * eg: `python bnftp_client.py CheckRevision.mpq --server useast.battle.net --product D2DV`
  * More options are available, use `python bnftp_client.py -h` for full help.
