# Copyright (C) 2026  GigaPixel Entertainment
# Licensed under the GNU General Public License v3, see <https://www.gnu.org/licenses/>.

"""Script to edit a saved user"""

import sys

from cryptography.fernet import Fernet
import msgpack
import bcrypt

import config

username = input("Username: ")


if not (config.USERS_DIR / f"{username}.usr").exists():
    print(f"Invalid user {username}")
    sys.exit(1)

key = None
with open(config.SAVE_KEY, "rb") as f:
    key = f.read()
    f.close()

fernet = Fernet(key)

with open(config.USERS_DIR / f"{username}.usr", "rb+") as f:
    userData = msgpack.unpackb(fernet.decrypt(f.read()))

    print(userData)
    userData["PWD"] = bcrypt.hashpw(b"12367", bcrypt.gensalt(15)).decode("utf-8")
    print(userData)

    f.seek(0)
    f.write(fernet.encrypt(msgpack.packb(userData)))
    f.truncate()

    f.close()

print("User edited successfully!")
