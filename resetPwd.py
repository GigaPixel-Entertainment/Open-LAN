# Copyright (C) 2026  GigaPixel Entertainment
# Licensed under the GNU General Public License v3, see <https://www.gnu.org/licenses/>.

"""Script to view a user's recovery key and reset their password"""

import sys

from cryptography.fernet import Fernet
import msgpack
import orjson
import bcrypt

import config

username = input("Username: ")


if not (config.SECURITY_DIR / f"{username}.sq").exists() or not (config.USERS_DIR / f"{username}.usr").exists():
    print(f"Invalid user {username}")
    sys.exit(1)

key = None
with open(config.SAVE_KEY, "rb") as f:
    key = f.read()
    f.close()

fernet = Fernet(key)

with open(config.SECURITY_DIR / f"{username}.sq", "rb") as f:
    securityKey = orjson.loads(fernet.decrypt(f.read()))

    print(f"Name: {securityKey["name"]}")
    showKey = input("Show key? [y/n]: ").lower()

    if showKey == "y":
        print(f"Key: {securityKey["secQ"]}")
        resetPwd = input("Reset Pwd? [y/n]: ").lower()

        if resetPwd == "y":
            newPwd = input("New Pwd: ")
            hashed = bcrypt.hashpw(newPwd.encode("utf-8"), bcrypt.gensalt(config.NUM_ENCRYPT_ROUNDS)).decode("utf-8")

            with open(config.USERS_DIR / f"{username}.usr", "rb+") as uf:
                userData = msgpack.unpackb(fernet.decrypt(uf.read()))
                userData["PWD"] = hashed

                uf.seek(0)
                uf.write(fernet.encrypt(msgpack.packb(userData)))
                uf.truncate()

                uf.close()

    f.close()

print("User edited successfully!")
