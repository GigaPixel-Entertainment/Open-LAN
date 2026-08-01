# Copyright (C) 2026  GigaPixel Entertainment
# Licensed under the GNU General Public License v3, see <https://www.gnu.org/licenses/>.

"""Script to delete a saved user"""

import pathlib
import sys

from cryptography.fernet import Fernet
import msgpack

import config

username = input("Username: ")

if not (config.USERS_DIR / f"{username}.usr").exists():
    print(f"Invalid user {username}")
    sys.exit(1)

confirm = input(f"Are you sure you want to delete {username}? (y/n): ")

if confirm.lower() != "y":
    print("Deletion cancelled!")
    sys.exit(1)

key = None
with open(config.SAVE_KEY, "rb") as f:
    key = f.read()
    f.close()

fernet = Fernet(key)

with open(config.USERS_DIR / f"{username}.usr", "rb+") as f:
    userData = msgpack.unpackb(fernet.decrypt(f.read()))

    UID = userData["UID"]

    userData["Displayname"] = f"DELETED USER {UID}"
    userData["Birthday"] = None
    userData["BirthdayV"] = "PRIVATE"
    userData["Pronouns"] = ""
    userData["Bio"] = ""

    f.seek(0)
    f.write(fernet.encrypt(msgpack.packb(userData)))
    f.truncate()

    f.close()

print("User deleted successfully!")
