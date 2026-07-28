# Copyright (C) 2026  GigaPixel Entertainment
# Licensed under the GNU General Public License v3, see <https://www.gnu.org/licenses/>.

"""Script to purge any unreferenced cdn"""

import traceback
import pathlib
import sys

from cryptography.fernet import Fernet
import msgpack

CWD = pathlib.Path(__file__).resolve().parent
CHATS_DIR = CWD / "Chats/"
CDN_DIR = CWD / "cdn/"

if not (CWD / "meta.key").is_file():
    print("No meta.key file found!")
    sys.exit(-1)

key = None
with open(CWD / "meta.key", "rb") as f:
    key = f.read()
    f.close()

fernet = Fernet(key)

referencedCDN = set()
for chat in CHATS_DIR.iterdir():
    if chat.is_file() and chat.suffix == ".enc":
        try:
            with open(chat, "rb") as chatFile:
                chatUnpacked = msgpack.unpackb(chatFile.read())
                messages = chatUnpacked["messages"]

                for msg in messages:
                    if not "embed" in msg:
                        continue

                    embeds = msg["embed"]

                    for embed in embeds:
                        referencedCDN.add(embed)
        except:
            traceback.print_exc()
            print(f"Failed to load chat {chat}!")
            sys.exit(-1)

unreferencedCDN = set()
for cdn in CDN_DIR.iterdir():
    cdnRel = cdn.relative_to(CWD)

    if not str(cdnRel) in referencedCDN:
        unreferencedCDN.add(cdnRel)

for cdn in unreferencedCDN:
    path: pathlib.Path = CWD / cdn
    path.unlink(True)

print("Purged successfully!")
