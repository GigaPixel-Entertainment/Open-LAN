# Copyright (C) 2026  GigaPixel Entertainment
# Licensed under the GNU General Public License v3, see <https://www.gnu.org/licenses/>.

import pathlib
import msgpack

CWD = pathlib.Path(__file__).resolve().parent
USERS_DIR = CWD / "Users/"

username = input("Username: ")

with open(USERS_DIR / f"{username}.usr", "rb+") as f:
    userData = msgpack.unpackb(f.read())

    print(userData)
    userData["USRNAME"] = ""
    print(userData)

    f.seek(0)
    f.write(msgpack.packb(userData))
    f.truncate()

    f.close()

print("User edited successfully!")