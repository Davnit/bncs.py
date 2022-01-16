
import asyncio
import enum
import logging

from ..utils import AsyncClientBase

from .packets import *

TIMEOUT = 5


class RealmClientStatus(enum.IntEnum):
    NotConnected = 0,
    Connected = 1,
    LoggedOn = 2,           # MCP_STARTUP has been exchanged successfully
    OnCharacter = 3         # A character has been selected


class McpClient(AsyncClientBase):
    def __init__(self, host, port, *, logger=None, **config):
        logger = logger or logging.getLogger("MCP")
        AsyncClientBase.__init__(self, McpReader, logger=logger)

        self.config = {
            "server": host,
            "port": port,

            "keep_alive_interval": 480
        }
        if config:
            self.config.update(config)

        self.packet_handlers.update({
            MCP_NULL: self._handle_null
        })

    @property
    def character_list(self):
        return list(self.state.get("characters", {}).keys())

    @property
    def selected_character(self):
        return self.state.get("character_name")

    @property
    def status(self):
        return self.state["status"]

    async def connect(self, host=None, port=None):
        host = host or self.config["server"]
        port = port or self.config["port"]

        if await super().connect(host, port):
            # Send the protocol selection byte (0x1)
            self._writer.write(b'\x01')
            self.state["status"] = RealmClientStatus.Connected
        else:
            self.state["status"] = RealmClientStatus.NotConnected

        self.state.pop("server_error", 1)
        return self.status == RealmClientStatus.Connected

    async def startup(self, blob, timeout=TIMEOUT):
        # C->S https://bnetdocs.org/packet/320/mcp-startup
        x01 = McpPacket(MCP_STARTUP)
        x01.insert_raw(blob)
        await self.send(x01)

        # S->C https://bnetdocs.org/packet/375/mcp-startup
        reply = await self.wait_for_packet(MCP_STARTUP, timeout=timeout)
        result = reply.get_dword()
        error_lookup = {
            0x02: "Realm unavailable",
            0x7E: "CD key is banned from the realm",
            0x7F: "IP is temporarily banned form the realm"
        }
        if result in error_lookup or result in range(0x0a, 0x0d):
            self.state["server_error"] = error_lookup.get(result, "Realm unavailable") + f"(0x{result:02X})"
            self.log.error(f"Realm login failed - {self.state['server_error']}")
            return False
        else:
            self.state["status"] = RealmClientStatus.LoggedOn
            self.log.info("Realm login successful")
            return True

    async def request_character_list(self, count=8, timeout=TIMEOUT):
        # C->S https://bnetdocs.org/packet/261/mcp-charlist2
        x19 = McpPacket(MCP_CHARLIST2)
        x19.insert_dword(count)
        await self.send(x19)

        characters = {}

        # S->C https://bnetdocs.org/packet/189/mcp-charlist2
        reply = await self.wait_for_packet(MCP_CHARLIST2, timeout=timeout)
        reply.get_word()                # number requested
        total = reply.get_dword()       # number on account
        returned = reply.get_word()     # number returned

        for _ in range(returned):
            expires = reply.get_dword()
            char_name = reply.get_string()
            stats = reply.get_string(encoding=None)

            characters[char_name] = (expires, stats)

        self.state["characters"] = characters
        self.log.debug(f"Received character list with {returned}/{total} entries")
        return characters

    async def change_character(self, char_name, timeout=TIMEOUT):
        # C->S https://bnetdocs.org/packet/154/mcp-charlogon
        x07 = McpPacket(MCP_CHARLOGON)
        x07.insert_string(char_name)
        await self.send(x07)

        # S->C https://bnetdocs.org/packet/337/mcp-charlogon
        reply = await self.wait_for_packet(MCP_CHARLOGON, timeout=timeout)
        result = reply.get_dword()
        err_lookup = {
            0x46: "Character not found",
            0x7A: "Logon failed",
            0x7B: "Character expired"
        }
        if result in err_lookup:
            self.state["server_error"] = err_lookup[result]
            self.log.error(f"Character selection failed - {self.state['server_error']}")
            return False
        else:
            self.state["character_name"] = char_name
            self.state["status"] = RealmClientStatus.OnCharacter
            return True

    async def keep_alive(self):
        while self.connected:
            await asyncio.sleep(self.config["keep_alive_interval"])
            await self.send(McpPacket(MCP_NULL))

    async def _handle_null(self, packet):
        pass
