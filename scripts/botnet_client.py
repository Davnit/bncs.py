
import argparse
import asyncio
import logging
import sys

from botnet import BotNetClient, DISTRO_BROADCAST, DISTRO_DATABASE, DISTRO_WHISPER


tags = {
    DISTRO_BROADCAST: "Broadcast",
    DISTRO_DATABASE: "Database",
    DISTRO_WHISPER: "Whisper"
}


def on_user_chat(user, message, distro, action):
    print_chat_message(user, message, distro, action, False)


def on_sent_chat(target, message, distro, action):
    print_chat_message(target, message, distro, action, True)


def on_user_quit(user, reason):
    print("QUIT - %s%s" % (user.name, (": " + reason) if reason else ""))


def on_user_update(user, changes):
    print("UPDATE - %s: %s" % (user.name, changes))


def print_chat_message(user, message, distro, action, out):
    print("CHAT - [%s%s]" % (tags.get(distro, "D: %i" % distro), "Emote" if action == 1 else "") +
          " %s: %s" % ((("To " if out else "From ") + user.name) if distro == DISTRO_WHISPER else user.name, message))


async def main():
    log = logging.getLogger("BotNet")
    logging.basicConfig(stream=sys.stdout, level=logging.INFO)

    parser = argparse.ArgumentParser()
    parser.add_argument("name", type=str, help="Battle.net account name")
    parser.add_argument("--server", type=str, help="Battle.net server")
    parser.add_argument("--channel", type=str, help="Battle.net channel")
    parser.add_argument("--account", type=str, help="BotNet account")
    parser.add_argument("--password", type=str, help="Account password")
    parser.add_argument("--host", type=str, help="BotNet server", default="botnet.bnetdocs.org")
    parser.add_argument("-p", "--port", type=int, help="Service port", default=0x5555)
    parser.add_argument("--dbname", type=str, help="Database to join")
    parser.add_argument("--dbpass", type=str, help="Password for database")
    parser.add_argument("--create", action='store_true', help="Attempts to create an account")

    args = parser.parse_args()

    client = BotNetClient()
    client.logger = log
    client.add_listener(on_user_chat)
    client.add_listener(on_sent_chat)
    client.add_listener(on_user_quit)
    client.add_listener(on_user_update)

    log.info("Connecting to %s..." % args.host)
    await client.connect(args.host, args.port)
    log.info("Authenticating as StealthBot...")
    await client.authenticate("StealthBot", "33 9c 0f 58 fe c7 2a")

    if args.account and args.password:
        if args.create:
            log.info("Creating account '%s' ..." % args.account)
            if not await client.create_account(args.account, args.password):
                log.error("ERROR: Account creation failed")
                return

        log.info("Logging in as '%s' ..." % args.account)
        if not await client.login(args.account, args.password):
            log.error("Login failed")
            return

    await client.update(args.name, args.server, args.channel, args.dbname, args.dbpass)
    await client.refresh_users()
    log.info("Logged on as %s" % client.myself)
    log.info("%i users online." % len(client.users))

    def get_user_input():
        return input()

    while client.connected:
        s = await asyncio.get_running_loop().run_in_executor(None, get_user_input)
        if s[0] == '/':
            parts = s.split(' ')
            cmd = parts[0][1:]
            if cmd == "exit":
                await client.disconnect()
                break
            else:
                log.error("Invalid command: %s" % cmd)
        else:
            await client.chat(s)


if __name__ == "__main__":
    asyncio.run(main())
