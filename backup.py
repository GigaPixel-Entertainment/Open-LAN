# Copyright (C) 2026  GigaPixel Entertainment
# Licensed under the GNU General Public License v3, see <https://www.gnu.org/licenses/>.

"""Simple backup script for Open-LAN"""

from datetime import datetime
import shutil
import time
import sys

import config

runBk = input("Run backup? [y/n]: ")

if runBk.lower() != "y":
    print("Canceled")
    sys.exit(0)

print("Running backup!")

ACTIVE_DIR = config.BACKUP_DIR / f"{datetime.fromtimestamp(time.time()).strftime("%Y-%m-%d %H-%M-%S")}/"
ACTIVE_DIR.mkdir(exist_ok=False)

shutil.copytree(config.CHATS_DIR, ACTIVE_DIR / "Chats/")
shutil.copytree(config.USERS_DIR, ACTIVE_DIR / "Users/")
shutil.copytree(config.SERVER_DIR, ACTIVE_DIR / "Servers/")
shutil.copytree(config.CDN_DIR, ACTIVE_DIR / "cdn/")
shutil.copyfile(config.SAVE_KEY, ACTIVE_DIR / "meta.key")

print("Done!")
