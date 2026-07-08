# Copyright (C) 2026  GigaPixel Entertainment
# Licensed under the GNU General Public License v3, see <https://www.gnu.org/licenses/>.

from cryptography.fernet import Fernet
import pathlib
import msgpack
import time
import sys

CWD = pathlib.Path(__file__).resolve().parent
CHATS_DIR = CWD / "Chats/"
CHAT_COUNT = sum(1 for item in CHATS_DIR.iterdir() if item.is_file() and item.suffix == ".enc")

if not (CWD / "meta.key").is_file():
    print("No meta.key file found!")
    sys.exit(-1)

key = None
with open(CWD / "meta.key", "rb") as f:
    key = f.read()
    f.close()

fernet = Fernet(key)

chatName = input("Chat/Server name: ")

with open(CHATS_DIR / f"{CHAT_COUNT}.enc", "wb") as f:
    f.write(msgpack.packb({"meta": {"CID":CHAT_COUNT, "Type": "forced-server"}, "Name": chatName, "messages": [{"time": int(time.time()), "content": fernet.encrypt("Welcome to the new Chat!".encode("utf-16")), "UID": 0, "MSGID": 0}]}))
    f.close()

print("Chat created successfully!")