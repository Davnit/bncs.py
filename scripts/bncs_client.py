#!/usr/bin/env python3

from bncs import *

import sys


def _handle_chat_event(packet_id, payload):
    eid, user, text, flags, ping = parse_chat_event(payload)

    messages = {
        EID_JOIN: "%s joined the channel." % user,
        EID_LEAVE: "%s left the channel." % user,
        EID_WHISPER: "From <%s>: %s" % (user, text),
        EID_TALK: "<%s>: %s" % (user, text),
        EID_BROADCAST: "Broadcast from %s: %s" % (user, text),
        EID_CHANNEL: "Joined channel: %s" % text,
        EID_INFO: "INFO: %s" % text,
        EID_ERROR: "ERROR: %s" % text,
        EID_EMOTE: "<%s %s>" % (user, text)
    }

    if eid in messages:
        print(messages.get(eid))


def _handle_message_box(packet_id, payload):
    payload.get_dword()
    text = payload.get_string()
    caption = payload.get_string()

    print("MSG - %s: %s" % (caption, text))


# CL ARGUMENTS: <server> <product> <key1>,[key2] <account> <password>
if __name__ == '__main__':
    if len(sys.argv) < 6:
        raise Exception("Missing required command-line parameters, expected 5, got %i" % (len(sys.argv) - 1))

    sp = sys.argv[1].split(':')
    server = sp[0]
    port = int(sp[1]) if len(sp) > 1 else 6112

    product = sys.argv[2]
    keys = sys.argv[3].split(',')

    account = sys.argv[4]
    password = sys.argv[5]

    client = BncsClient()
    client.packet_handlers[SID_CHATEVENT] = _handle_chat_event
    client.packet_handlers[SID_MESSAGEBOX] = _handle_message_box

    print("Connecting to %s..." % server)
    client.connect(server)
    print("Connected!")

    print("Authenticating client...")
    auth, msg = client.authenticate(product, keys)
    if not auth:
        client.disconnect()
        print("Authentication failed: %s" % msg)
        sys.exit(2)
    else:
        print(msg)

    print("Server %s" % ("verified!" if client.verified() else "verification failed."))

    print("Logging in...")
    logged, msg = client.login(account, password)
    if not logged:
        if msg == "Account does not exist.":
            print(msg + ", creating...")
            created, msg = client.create_account(account, password)
            if not created:
                print("Account creation failed: %s" % msg)
            else:
                print(msg + ", logging in...")
                logged, msg = client.login(account, password)
                if not logged:
                    print("Login failed: %s" % msg)

    if not client.logged_on():
        client.disconnect()
        sys.exit(2)
    else:
        print(msg)

    print("Entering chat...")
    client.enter_chat()

    if client.in_chat():
        print("Logged on as %s" % client.get_username())

    while client.connected():
        command = input()
        if command.lower() == "/exit":
            client.disconnect()
            input("Connection closed. Press ENTER to close.")
        else:
            client.chat_command(command)
