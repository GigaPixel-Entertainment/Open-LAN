# Copyright (C) 2026  GigaPixel Entertainment
# Licensed under the GNU General Public License v3, see <https://www.gnu.org/licenses/>.

"""Script to convert a forced-gc chat into a regular gc"""

import sys

from cryptography.fernet import Fernet
import msgpack

import config

CID = input("CID: ")

if not (config.CHATS_DIR / f"{CID}.enc").exists():
    print(f"Invalid chat {CID}")
    sys.exit(1)

key = None
with open(config.SAVE_KEY, "rb") as f:
    key = f.read()
    f.close()

fernet = Fernet(key)

with open(config.CHATS_DIR / f"{CID}.enc", "rb+") as f:
    chatData = msgpack.unpackb(f.read())

    print(chatData)
    chatData["meta"]["Type"] = "gc"
    print(chatData)

    f.seek(0)
    f.write(msgpack.packb(chatData))
    f.truncate()

    f.close()

print("Chat edited successfully!")
