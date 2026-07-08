# Copyright (C) 2026  GigaPixel Entertainment
# Licensed under the GNU General Public License v3, see <https://www.gnu.org/licenses/>.

import pathlib
import msgpack
import bcrypt
import time

CWD = pathlib.Path(__file__).resolve().parent
USERS_DIR = CWD / "Users/"
USER_COUNT = sum(1 for item in USERS_DIR.iterdir() if item.is_file())

username = input("Username: ")
pwd = input("Password: ")

hashed = bcrypt.hashpw(pwd.encode("utf-8"), bcrypt.gensalt(rounds=15)).decode("utf-8")

with open(USERS_DIR / f"{username}.usr", "wb") as f:
    f.write(msgpack.packb({"UID": USER_COUNT, "USRNAME": username,"PWD": hashed, "Chats": [0], "Friends": [], "AccCreated": time.time()}))
    f.close()

print("User registered successfully!")