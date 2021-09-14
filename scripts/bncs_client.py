
import argparse
import asyncio
from datetime import datetime
import logging

from bncs import BnetClient, AccountLoginResult, ChatEventType, ClientStatus
from bnls import BnlsClient


class SampleBnetClient(BnetClient):
    async def do_login(self):
        if await self.authenticate(timeout=10):
            if await self.login() == AccountLoginResult.NoAccount:
                if not await self.create_account() and await self.login():
                    return
            if self.status == ClientStatus.LoggedIn:
                await self.enter_chat()

    async def _handle_chat_event(self, packet):
        event = await super()._handle_chat_event(packet)

        if event.eid == ChatEventType.UserTalk:
            print(f"<{event.username}> {event.text}")
        elif event.eid == ChatEventType.UserEmote:
            print(f"<{event.username} {event.text}>")
        elif event.eid == ChatEventType.WhisperSent:
            print(f"<To {event.username}> {event.text}")
        elif event.eid == ChatEventType.UserWhisper:
            print(f"<From {event.username}> {event.text}")


async def main(args):
    config = {
        "username": args.username,
        "password": args.password,
        "product": args.product,
        "server": args.server,
        "keys": args.keys.split(',') if args.keys else []
    }

    bnls = BnlsClient()
    client = SampleBnetClient(bnls_client=bnls, config=config)

    def get_user_input():
        return input()

    try:
        await client.connect()
        await bnls.connect()

        await client.do_login()
        bnls.disconnect("Done")

        if client.status == ClientStatus.Chatting:
            while client.connected:
                raw_input = await asyncio.get_event_loop().run_in_executor(None, get_user_input)
                is_local_cmd = True

                if raw_input[0] == '/':
                    args = raw_input[1:].split(' ')
                    cmd = args.pop(0).lower()

                    if cmd == "exit":
                        client.disconnect("Quit")
                        break

                    elif cmd == "channels":
                        product = client.state["product"].code if len(args) == 0 else args[0]
                        channels = await client.request_channel_list(product)
                        print(f"Channels available for '{product}':")
                        for i in range(0, len(channels), 3):
                            print(f"\t{', '.join(c for c in channels[i:i+3])}")

                    elif cmd == "filetime":
                        if len(args) == 0:
                            print("Command usage: /filetime <filename>")
                        else:
                            ft = await client.get_filetime(args[0])
                            print(f"Filetime for '{args[0]}': {ft}")

                    elif cmd == "profile":
                        user = None if len(args) == 0 else args[0]
                        data = await client.request_profile(user)
                        if data:
                            user = user or client.state["account_name"]
                            print(f"Profile for '{user}': {data}")
                        else:
                            print("Profile request returned no data")

                    elif cmd == "accountinfo":
                        data = await client.request_account_keys()
                        if data:
                            print(f"Account info: {data}")
                        else:
                            print("No account info returned")

                    elif cmd == "ad":
                        platform, product = args[0].split('\\') if len(args) == 1 else (None, None)
                        banner = await client.check_ad(platform=platform, product=product)
                        print(f"Current ad banner: {banner}")

                    elif cmd == "news":
                        news, motd = await client.get_news_info()
                        latest = news[-1] if len(news) > 0 else None
                        print(f"Server MotD: {motd}")
                        print(f"Latest news: {datetime.utcfromtimestamp(latest[0]).isoformat()} -> " +
                              str(latest[1].split('\n')))

                    else:
                        is_local_cmd = False

                if not is_local_cmd:
                    await client.send_command(raw_input)
    finally:
        client.disconnect("dead")
        bnls.disconnect("dead")
        await client.wait_closed()
        await bnls.wait_closed()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    parser = argparse.ArgumentParser()
    parser.add_argument("username", help="Name of the account to login as")
    parser.add_argument("password", help="Password for the account")
    parser.add_argument("--server", help="Hostname or IP of the Battle.net server", default='useast.battle.net')
    parser.add_argument("--product", help="4-digit code of the game to emulate (ex: WAR3, SEXP)", default='DRTL')
    parser.add_argument("--keys", help="Comma separated list of CD keys for the emulated product")

    aa = parser.parse_args()
    asyncio.run(main(aa))
