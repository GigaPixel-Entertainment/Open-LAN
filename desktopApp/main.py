# Open-LAN allows you to host your own messaging server on the Local Area Network.
# Copyright (C) 2026  GigaPixel Entertainment
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# GigaPixel Entertainment <the_mrjune@gigapixel.cc>

from urllib.parse import urlparse
from tkinter import simpledialog, messagebox
import datetime
import logging
import pathlib
import json
import sys
import os

import requests
import webview

BUILD = 1

CWD = pathlib.Path(__file__).resolve().parent
LOG_DIR = CWD / "LOGS/"
CONFIG = CWD / "config.json"

LOG_DIR.mkdir(exist_ok=True)

serverAddr = ""
trustSelfSignedOverride = False
config = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(filename)s] [%(levelname)s]: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_DIR / f"{datetime.datetime.now().strftime("%Y-%m-%d %H-%M-%S")}.log")
    ]
)

logging.info("Hello world!")
logging.info(f"Open-LAN Desktop Client Build {BUILD}")

if CONFIG.exists():
    logging.info("Loading config...")
    with open(CONFIG, "r") as f:
        config = json.load(f)
        f.close()

    if "addr" in config:
        serverAddr = config["addr"]

    if "trustSelfSigned":
        trustSelfSignedOverride = True

def setupErr(errMsg: str) -> None:
    global trustSelfSignedOverride
    if messagebox.askyesno("Open-LAN", f"{errMsg}; Would you like to try again?"):
        trustSelfSignedOverride = False
        setup()
    else:
        sys.exit(1)

def checkServer(address: str):
    global trustSelfSignedOverride
    try:
        urlParsed = urlparse(address)
    except:
        return False

    try:
        result = requests.head("https://" + urlParsed.path + "/api/appPing", timeout=5)
    except requests.exceptions.SSLError:
        if trustSelfSignedOverride:
            trySelfSigned = True
        else:
            trySelfSigned = messagebox.askyesno("Open-LAN", "Connection failed! Would you like to try allowing self-signed certificate? DO THIS ONLY IF YOU TRUST THE SERVER!!!")

        if not trySelfSigned:
            return False

        trustSelfSignedOverride = True
        try:
            result = requests.head("https://" + urlParsed.path + "/api/appPing", verify=False, timeout=5)
        except Exception as e:
            return False
    except Exception as e:
        return False

    if result.status_code != 200:
        return False

    if "minBuild" in result.headers:
        logging.info("Server requires build %s", result.headers["minBuild"])

        if BUILD < int(result.headers["minBuild"]):
            logging.warning("...but the app is build %i!", BUILD)
            messagebox.showerror(f"Outdated client! Please update the client to build {result.headers["minBuild"]} or later! (Currently build {BUILD})")
            return False
    else:
        logging.warning("Min Build not specified! This usually means that the server is not an Open-LAN server, but we'll try anyways.")

    return True

def setup() -> None:
    global serverAddr

    address = simpledialog.askstring("Open-LAN", "Please enter Open-LAN server ip")

    if address is None:
        setupErr("Invalid address")
        return

    if checkServer(address):
        logging.info("Server verified!")
        serverAddr = address
    else:
        setupErr("Connection failed")
        return

if serverAddr == "":
    setup()

if checkServer(serverAddr):
    if not CONFIG.exists():
        with open(CONFIG, "w") as f:
            json.dump({
                "addr": serverAddr,
                "trustSelfSigned": trustSelfSignedOverride
            }, f)

    if trustSelfSignedOverride:
        webview.settings['IGNORE_SSL_ERRORS'] = True
    webview.create_window("Open-LAN", url=f"https://{serverAddr}/", width=1200, height=700)
    webview.start()

    logging.info("Closing client!")
    sys.exit(0)
else:
    if messagebox.askyesno("Open-LAN", "Saved server address is no longer accessible! Would you like to restart the setup?"):
        CONFIG.unlink(True)
        os.execv(sys.executable, [sys.executable] + sys.argv)
        sys.exit(0)