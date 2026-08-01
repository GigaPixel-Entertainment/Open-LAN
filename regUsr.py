# Copyright (C) 2026  GigaPixel Entertainment
# Licensed under the GNU General Public License v3, see <https://www.gnu.org/licenses/>.

"""Script to register a new user"""

import pathlib
import time

import msgpack
import bcrypt

import config

USER_COUNT = sum(1 for item in config.USERS_DIR.iterdir() if item.is_file())

username = input("Username: ")
pwd = input("Password: ")

hashed = bcrypt.hashpw(pwd.encode("utf-8"), bcrypt.gensalt(rounds=15)).decode("utf-8")

with open(config.USERS_DIR / f"{username}.usr", "wb") as f:
    f.write(msgpack.packb({"UID": USER_COUNT, "USRNAME": username,"PWD": hashed, "Chats": [0], "Friends": [], "AccCreated": time.time()}))
    f.close()

print("User registered successfully!")
