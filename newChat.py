# Copyright (C) 2026  GigaPixel Entertainment
# Licensed under the GNU General Public License v3, see <https://www.gnu.org/licenses/>.

"""Script to create a new chat"""

import time
import sys

from cryptography.fernet import Fernet
import msgpack

import config

CHAT_COUNT = sum(1 for item in config.CHATS_DIR.iterdir() if item.is_file() and item.suffix == ".enc")

if not (config.CWD / "meta.key").is_file():
    print("No meta.key file found!")
    sys.exit(-1)

key = None
with open(config.CWD / "meta.key", "rb") as f:
    key = f.read()
    f.close()

fernet = Fernet(key)

chatName = input("Chat/Server name: ")

with open(config.CHATS_DIR / f"{CHAT_COUNT}.enc", "wb") as f:
    f.write(msgpack.packb({"meta": {"CID":CHAT_COUNT, "Type": "forced-gc"}, "Name": chatName, "Time": int(time.time()), "messages": [{"time": int(time.time()), "content": fernet.encrypt("Welcome to the new Chat!".encode("utf-16")), "UID": 0, "MSGID": 0}]}))
    f.close()

print("Chat created successfully!")
