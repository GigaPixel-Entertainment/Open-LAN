# Copyright (C) 2026  GigaPixel Entertainment
# Licensed under the GNU General Public License v3, see <https://www.gnu.org/licenses/>.

"""Configuration file for Open-LAN"""

import logging
import pathlib
import os

from dotenv import load_dotenv

DEV = False
VER = "0.0.4"
STAGE = "alpha"

CWD = pathlib.Path(__file__).resolve().parent
CA_CERT_DIR = CWD / "CA_CERT"
CDN_DIR = CWD / "cdn/"
CHATS_DIR = CWD / "Chats/"
CSS_DIR = CWD / "CSS/"
ENV_FILE = CWD / ".env"
JS_DIR = CWD / "JS/"
LOG_DIR = CWD / "logs/"
MEDIA_DIR = CWD / "Media/"
PFP_DIR = CWD / "pfps/"
RUN_LOG_DIR = CWD / "runLogs/"
SAVE_KEY = CWD / "meta.key"
SECURITY_DIR = CWD / "security"
USERS_DIR = CWD / "Users/"

PRIVATE_DIRS = [
    USERS_DIR,
    CHATS_DIR,
    CA_CERT_DIR,
    SECURITY_DIR,
    SAVE_KEY,
    LOG_DIR,
    RUN_LOG_DIR,
    ENV_FILE
]

IMPORTANT_FILES = [
    CWD / "server.py",
    CWD / "httphelper.py"
]

if ENV_FILE.exists():
    load_dotenv(CWD / ".env")

PORT = 33333
WS_PORT = 33334
WSS_PORT = 33335
DASHBOARD_PORT = 22222
SOCKET_BACKLOG_NUM = 5
MAX_RETRY_ATTEMPTS = 10
RETRY_ATTEMPTS_CLEAR_AFTER_SEC = 120
AUTOSAVE_INTERVAL_SEC = 300
ACC_CREATION_COOLDOWN_SEC = 30*60
NUM_ENCRYPT_ROUNDS = 15
LOG_LEVEL = logging.DEBUG if DEV else logging.INFO

ZSTD_COMPRESSION_LEVEL = 9 # -inf - 22
BROTLI_COMPRESSION_LEVEL = 11 # 0 - 11
GZIP_COMPRESSION_LEVEL = 3 # 0 - 9

DASHBOARD_ENABLED = True
DASHBOARD_USERNAME = os.getenv("DASHBOARD_USERNAME", "")
DASHBOARD_HASHED_PWD = os.getenv("DASHBOARD_HASHED_PWD", "")

TOKEN_EXPIRES_SEC = 60*60*24 # 1 Day
REDIRECT_TOKEN_EXPIRES_SEC = 60 # 1 Minute
