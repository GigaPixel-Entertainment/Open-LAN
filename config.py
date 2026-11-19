# Copyright (C) 2026  GigaPixel Entertainment
# Licensed under the GNU General Public License v3, see <https://www.gnu.org/licenses/>.

"""Configuration file for Open-LAN"""

import logging
import pathlib
import os

from dotenv import load_dotenv

DEV = True
VER = "0.1.2"
STAGE = "beta"

CWD = pathlib.Path(__file__).resolve().parent
WEB_DIR = CWD / "Web"
BACKUP_DIR = CWD / "Backups/"
CA_CERT_DIR = CWD / "CA_CERT/"
CDN_DIR = WEB_DIR / "cdn/"
CHATS_DIR = CWD / "Chats/"
CSS_DIR = WEB_DIR / "CSS/"
ENV_FILE = CWD / ".env"
INVITE_FILE = CWD / "invites.inv"
JS_DIR = WEB_DIR / "JS/"
LOG_DIR = CWD / "logs/"
MEDIA_DIR = WEB_DIR / "Media/"
PFP_DIR = CWD / "pfps/"
RUN_LOG_DIR = CWD / "runLogs/"
SAVE_KEY = CWD / "meta.key"
SECURITY_DIR = CWD / "security/"
SERVER_CERT_FILE = CA_CERT_DIR / "server.crt"
SERVER_DIR = CWD / "Servers/"
SERVER_KEY_FILE = CA_CERT_DIR / "server.key"
USERS_DIR = CWD / "Users/"

ERROR_PAGE = WEB_DIR / "error.html"

PRIVATE_DIRS = [
    USERS_DIR,
    CHATS_DIR,
    CA_CERT_DIR,
    SECURITY_DIR,
    SAVE_KEY,
    LOG_DIR,
    RUN_LOG_DIR,
    ENV_FILE,
    BACKUP_DIR,
    INVITE_FILE
]

if ENV_FILE.exists():
    load_dotenv(ENV_FILE)

PORT = 33333 # HTTP/HTTPS port
WS_PORT = 33334 # WS port
WSS_PORT = 33335 # WSS port
DASHBOARD_PORT = 22222 # Dashboard port
SOCKET_BACKLOG_NUM = 5 # Http request queue size
MAX_RETRY_ATTEMPTS = 10 # On error: retry x amounts of times before giving up
RETRY_ATTEMPTS_CLEAR_AFTER_SEC = 120 # When the retry counter resets
AUTOSAVE_INTERVAL_SEC = 30*60 # 30 Minutes
ACC_CREATION_COOLDOWN_SEC = 30*60 # 30 Minutes
NUM_ENCRYPT_ROUNDS = 15
LOG_LEVEL = logging.INFO if DEV else logging.WARNING

TOKEN_EXPIRES_SEC = 60*60*24 # 1 Day
REDIRECT_TOKEN_EXPIRES_SEC = 60 # 1 Minute
RESET_PWD_TOKEN_EXPIRE_SEC = 15*60 # 15 minutes
INVITE_EXPIRE_TIME = 24*60*60 # 1 day
MAX_PFP_SIZE = 10*1024*1024 # 10 MiB
MAX_ICON_SIZE = 10*1024*1024 # 10 MiB
MAX_EMBED_SIZE = 25*1024*1024 # 25 MiB
MAX_EMBED_COUNT = 10 # 10 Embeds/Msg
MAX_MSG_SIZE = 4000 # 4000 chars/Msg
MAX_WS_MSG_SIZE_MARGIN = 1024*1024 # 1MiB

AUTOJOIN_CHAT_0 = True

ZSTD_COMPRESSION_LEVEL = 22 # -inf - 22
BROTLI_COMPRESSION_LEVEL = 11 # 0 - 11
GZIP_COMPRESSION_LEVEL = 9 # 0 - 9

DASHBOARD_ENABLED = True
DASHBOARD_USERNAME = os.getenv("DASHBOARD_USERNAME", "")
DASHBOARD_HASHED_PWD = os.getenv("DASHBOARD_HASHED_PWD", "")

EMPTY_IMG = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAACXBIWXMAAC4jAAAuIwF4pT92AAAADUlEQVQI12NgYGD4DwABBAEApOCsMQAAAABJRU5ErkJggg=="
