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


print("""
####################
#                  #
#     Open-LAN     #
#                  #
####################
by GigaPixel Entertainment

Open-LAN  Copyright (C) 2026  GigaPixel Entertainment
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions; See <https://www.gnu.org/licenses/>.
""")

print("""
REQUIRED IMPORTS:
(use pip to install)
cryptography,
websockets,
concurrent,
collections,
http,
io,
pillow,
mimetypes,
zstandard,
traceback,
threading,
datetime,
logging,
secrets,
pathlib,
msgpack,
asyncio,
orjson,
brotli,
bcrypt,
psutil,
socket,
select,
base64,
gzip,
time,
json,
copy,
math,
sys,
ssl
""")

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from websockets.asyncio.server import serve, ServerConnection, Request
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidTag
from http.server import BaseHTTPRequestHandler
from concurrent.futures._base import Future
from cryptography.fernet import Fernet
from collections.abc import Iterable
from http import cookies
from io import BytesIO
from PIL import Image
import mimetypes
import zstandard
import traceback
import threading
import datetime
import logging
import secrets
import pathlib
import msgpack
import asyncio
import orjson
import brotli
import bcrypt
import psutil # type: ignore
import socket
import select
import base64
import gzip
import time
import copy
import math
import sys
import ssl

PORT = 33333
WS_PORT = 33334
WSS_PORT = 33335
SOCKET_BACKLOG_NUM = 5
MAX_RETRY_ATTEMPTS = 10
RETRY_ATTEMPTS_CLEAR_AFTER_SEC = 120
AUTOSAVE_INTERVAL_SEC = 300
ACC_CREATION_COOLDOWN_SEC = 30*60
NUM_ENCRYPT_ROUNDS = 15
LOG_LEVEL = logging.DEBUG

ZSTD_COMPRESSION_LEVEL = 9 # -inf - 22
BROTLI_COMPRESSION_LEVEL = 11 # 0 - 11
GZIP_COMPRESSION_LEVEL = 3 # 0 - 9

TOKEN_EXPIRES_SEC = 60*60*24 # 1 Day
REDIRECT_TOKEN_EXPIRES_SEC = 60 # 1 Minute

CWD = pathlib.Path(__file__).resolve().parent
CA_CERT_DIR = CWD / "CA_CERT"
CDN_DIR = CWD / "cdn/"
CHATS_DIR = CWD / "Chats/"
SAVE_KEY = CWD / "meta.key"
CSS_DIR = CWD / "CSS/"
JS_DIR = CWD / "JS/"
LOG_DIR = CWD / "logs/"
MEDIA_DIR = CWD / "Media/"
PFP_DIR = CWD / "pfps/"
SECURITY_DIR = CWD / "security"
USERS_DIR = CWD / "Users/"

PRIVATE_DIRS = [
    USERS_DIR,
    CHATS_DIR,
    CA_CERT_DIR,
    SECURITY_DIR,
    SAVE_KEY,
    LOG_DIR
]

WS_CLIENTS: set[ServerConnection] = set()
VALID_TOKENS = {}
SHORT_REDIRECT_TOKENS = {}

RATELIMITED_IPS = []

DEFAULT_PFPS: list[str] = []

class HTTPRequestParser(BaseHTTPRequestHandler):
    def __init__(self, request_bytes: bytes):
        self.rfile = BytesIO(request_bytes)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        
        self.parse_request()

    def send_error(self, code: int, message: str | None=None, explain: str | None=None):
        self.error_code = code
        self.error_message = message

def genSaveKey():
    key = Fernet.generate_key()
    with open(SAVE_KEY, "wb") as f:
        f.write(key)
        f.close()

def validateImgFile(path: pathlib.Path | BytesIO):
    try:
        with Image.open(path) as img:
            img.verify()
            return True
    except:
        return False

def loadPfps():
    logging.info("[IO] Loading default PFPs")
    for pfp in PFP_DIR.iterdir():
        if pfp.is_file() and validateImgFile(pfp):
            try:
                fileContents = None
                with open(pfp, "rb") as f:
                    fileContents = f.read()
                    f.close()
                
                base64Pfp: str = resizePfpBytes(fileContents)

                DEFAULT_PFPS.append(base64Pfp)
            except:
                traceback.print_exc()
                logging.error(f"[IO] Failed to load pfp {pfp}")
        else:
            logging.warning(f"[IO] File {pfp} is not a valid img file!")
    logging.info("[IO] Loaded default PFPs")

def loadUsers():
    logging.info("[IO] Loading users")

    if not USERS_DIR.exists():
        USERS_DIR.mkdir()
    
    if not SAVE_KEY.exists():
        logging.info("[IO] Generating new save key!")
        genSaveKey()

    for usr in USERS_DIR.iterdir():
        if usr.is_file() and usr.suffix == ".usr":
            with open(usr, "rb") as f:
                userData = msgpack.unpackb(fernet.decrypt(f.read()))

                if not "PFP" in userData:
                    userData["PFP"] = DEFAULT_PFPS[secrets.randbelow(len(DEFAULT_PFPS))]
                    
                if not "Displayname" in userData:
                    userData["Displayname"] = userData["USRNAME"]

                if not "Birthday" in userData:
                    userData["Birthday"] = None
                
                if not "BirthdayV" in userData:
                    userData["BirthdayV"] = "PRIVATE"
                
                if not "AccCreated" in userData:
                    userData["AccCreated"] = time.time()
                
                if not "Pronouns" in userData:
                    userData["Pronouns"] = ""

                if not "Bio" in userData:
                    userData["Bio"] = ""
                
                if not "FriendRequests" in userData:
                    userData["FriendRequests"] = []

                users.append(userData)
                f.close()
    
    
    logging.info("[IO] Users loaded")

def loadChats():
    logging.info("[IO] Loading chats")

    if not CHATS_DIR.exists():
        CHATS_DIR.mkdir()
    
    for chat in CHATS_DIR.iterdir():
        if chat.is_file() and chat.suffix == ".enc":
            try:
                with open(chat, "rb") as f:
                    fileContents = msgpack.unpackb(f.read())
                    metadata = fileContents["meta"]
                    name = fileContents["Name"]
                    recipients = (fileContents["Recipients"] if "Recipients" in fileContents else [])
                    messages = fileContents["messages"]

                    for msg in messages:
                        msg["content"] = fernet.decrypt(msg["content"]).decode("utf-16")

                    chats.append({"CID": metadata["CID"], "Type": metadata["Type"], "Name": name, "Recipients": recipients, "messages": messages})
                    f.close()
            except Exception:
                traceback.print_exc()
                logging.error(f"[IO] Failed to load chat! {chat.name}")
    
    logging.info("[IO] Chats loaded")

def saveUsers():
    logging.info("[IO] Saving users")

    for usr in users:
        try:
            with open(USERS_DIR / f"{usr["USRNAME"]}.usr", "wb") as f:
                packed: bytes | None = msgpack.packb(usr)

                if packed:
                    f.write(fernet.encrypt(packed))
                else:
                    logging.error(f"[IO] Failed to save user {usr["USRNAME"]}!")

                f.close()
        except:
            traceback.print_exc()
            logging.error(f"[IO] Failed to save user {usr["USRNAME"]}!")
    logging.info("[IO] Users saved")

def saveChats():
    logging.info("[IO] Saving chats")

    for chat in chats:
        try:
            chatID = chat["CID"]
            with open(CHATS_DIR / f"{chatID}.enc", "wb") as f:
                metadata = {"CID": chatID, "Type": chat["Type"]}
                messages = []

                for msg in chat["messages"]:
                    msgContents = msg["content"]
                    messageSaving = copy.deepcopy(msg)
                    messageSaving["content"] = fernet.encrypt(msgContents.encode("utf-16"))
                    messages.append(messageSaving)
                
                packed: bytes | None = msgpack.packb({"meta":metadata,"Name":chat["Name"],"Recipients": chat["Recipients"], "messages":messages})

                if packed:
                    f.write(packed)
                else:
                    logging.error(f"[IO] Failed to save chat! {chat}")

                f.close()
        except Exception:
            traceback.print_exc()
            logging.error(f"[IO] Failed to save chat! {chat}")
    
    logging.info("[IO] Chats saved")
        
def getUsernameFromAuthToken(token: str | None) -> str | None:
    for username, tk in VALID_TOKENS.items():
        if tk["TOKEN"] == token:
            return username
    
    return None

def getUserIdFromAuthToken(token: str | None) -> int | None:
    userInfo = getUserInfoFromToken(token)

    if userInfo == None:
        return None
    
    return userInfo["UID"]

def getUserInfoFromUsername(username: str) -> dict | None:
    for user in users:
        if user["USRNAME"] == username:
            return user
        
    return None

def getUserInfoFromUserId(UID: int) -> dict | None:
    for user in users:
        if user["UID"] == UID:
            return user
    return None

def getUserInfoFromToken(token: str | None) -> dict | None:
    username = getUsernameFromAuthToken(token)

    if username == None:
        return None
    
    return getUserInfoFromUsername(username)

def getChatFromCID(CID: int) -> dict | None:
    for chat in chats:
        if chat["CID"] == CID:
            return chat
    
    return None

def setUserProperty(UID: int | None, PropertyName: str, Value) -> bool:
    if UID == None:
        return False

    success = False
    for usr in users:
        if usr["UID"] == UID:
            usr[PropertyName] = Value
            success = True
            break

    return success

def tokenInChat(token: str | None, CID: int) -> bool:
    chat = getChatFromCID(CID)

    if chat == None:
        return False

    userInfo = getUserInfoFromToken(token)

    if userInfo == None:
        return False
    
    if not CID in userInfo["Chats"]:
        return False
    
    return True

def getIpAddrs():
    ip_list = []
    interfaces = psutil.net_if_addrs()
    
    for interface_name, interface_addresses in interfaces.items():
        for address in interface_addresses:
            if address.family == socket.AF_INET and not address.address.startswith("127."):
                logging.debug(f"[MAIN] Interface: {interface_name} -> IP Address: {address.address}")
                ip_list.append(address.address)
                
    return ip_list

def formatHEADResponse(filePath: pathlib.Path):
    if not filePath.is_file():
        logging.warning(f"[MAIN] Invalid fetch {filePath}!")

        return formatErrorResponse(404)
    
    mime = mimetypes.guess_file_type(filePath)[0] or "application/octet-stream"

    return (
        "HTTP/1.1 200 OK\r\n"
        f"Content-Type: {mime}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("utf-8")

def formatHttpResponse(filePath: pathlib.Path, acceptEncoding: list):
    if not filePath.is_file():
        logging.warning(f"[MAIN] Invalid fetch {filePath}!")

        return formatErrorResponse(404)
    
    fileContents = bytes()
    with open(filePath, "rb") as f:
        fileContents = f.read()
        f.close()
    
    if CDN_DIR.resolve() in filePath.resolve().parents:
        fileContents = fernet.decrypt(fileContents)
    
    mime = mimetypes.guess_file_type(filePath)[0] or "application/octet-stream"

    encoding = None

    if "text/" in mime:
        if "zstd" in acceptEncoding:
            encoding = "zstd"
        elif "br" in acceptEncoding:
            encoding = "br"
        elif "gzip" in acceptEncoding:
            encoding = "gzip"

        if encoding == "zstd":
            fileContents = zstandard.compress(fileContents, level=ZSTD_COMPRESSION_LEVEL)
        elif encoding == "br":
            fileContents = brotli.compress(fileContents, quality=BROTLI_COMPRESSION_LEVEL)
        elif encoding == "gzip":
            fileContents = gzip.compress(fileContents, compresslevel=GZIP_COMPRESSION_LEVEL)
    
    header = (f"Content-Encoding: {encoding}\r\n" if encoding != None else "")

    return (
        "HTTP/1.1 200 OK\r\n"
        f"Content-Type: {mime}\r\n"
        f"Content-Length: {len(fileContents)}\r\n"
        f"{header}"
        "Connection: close\r\n"
        "\r\n"
    ).encode("utf-8") + fileContents

def formatLoginResponse(username: str, cloudflare: bool):
    if not username:
        return formatErrorResponse(500)

    token = secrets.token_urlsafe(256)
    VALID_TOKENS[username] = {"TOKEN": token, "EXPIRES": time.time() + TOKEN_EXPIRES_SEC}
    return (
        "HTTP/1.1 308 Permanent Redirect\r\n"
        f"Set-Cookie: authToken={token}; HttpOnly; SameSite=Strict; {"Domain=gigapixel.cc;" if cloudflare else ""} Path=/\r\n"
        f"Location: /app.html\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("utf-8")

def formatErrorResponse(statusCode: int):
    if statusCode == 400:
        return "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n".encode("utf-8")
    elif statusCode == 401:
        return "HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n".encode("utf-8")
    elif statusCode == 404:
        return "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n".encode("utf-8")
    elif statusCode == 500:
        return "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n".encode("utf-8")
    
    return "HTTP/1.1 418 I'm a teapot\r\nConnection: close\r\n\r\n".encode("utf-8")

def closeSocket(sk: socket.socket):
    try:
        sk.shutdown(socket.SHUT_WR)
        sk.close()
    except:
        pass

def isSafePath(path: pathlib.Path):
    reqPath = path.resolve()

    for privDir in PRIVATE_DIRS:
        if privDir.resolve() in reqPath.parents or privDir.resolve() == reqPath:
            return False

    if CWD.resolve() in reqPath.parents:
        return True

def handleRequest(sk: socket.socket):
    request = sk.recv(4096)
    parsed = HTTPRequestParser(request)

    if parsed.error_code:
        logging.error(f"[MAIN] Failed to parse {request.decode("utf-8")}")
        closeSocket(sk)
        return
    
    method = parsed.command
    path = parsed.path
    pathSplit = path.split("?")
    page = pathSplit[0]
    uri = {}

    acceptEncoding = [s.strip() for s in parsed.headers.get("Accept-Encoding", "").split(",")]

    if len(pathSplit) > 1:
        for pair in pathSplit[1].split("&"):
            if len(pair.split("=")) > 1:
                uri[pair.split("=")[0]] = pair.split("=")[1]

    if method == "GET":
        if page == "/":
            page = "/index.html"
        
        pagePath = CWD / page.removeprefix("/")

        if page == "/api/wsurl":
            currUrl = parsed.headers.get("Domain-Url")

            if currUrl and "openlan.gigapixel.cc" in currUrl:
                # POV: Cloudflare
                sk.sendall(f"HTTP/1.1 200 OK\r\nUrl: ws://openlanws.gigapixel.cc\r\nContent-Type: text/plain\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode("utf-8"))
            else:
                sk.sendall(f"HTTP/1.1 200 OK\r\nUrl: ws://{currUrl}:{WS_PORT}\r\nContent-Type: text/plain\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode("utf-8"))
        elif page == "/api/wssurl":
            currUrl = parsed.headers.get("Domain-Url")

            if currUrl and "openlan.gigapixel.cc" in currUrl:
                # POV: Cloudflare
                sk.sendall(f"HTTP/1.1 200 OK\r\nUrl: wss://openlanws.gigapixel.cc\r\nContent-Type: text/plain\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode("utf-8"))
            else:
                sk.sendall(f"HTTP/1.1 200 OK\r\nUrl: wss://{currUrl}:{WSS_PORT}\r\nContent-Type: text/plain\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode("utf-8"))
        elif page == "/api/login":
            if "TK" in uri and "hostname" in uri:
                username = isValidRedirectToken(uri["TK"])

                if username != None:
                    sk.sendall(formatLoginResponse(username, "gigapixel.cc" in uri["hostname"]))
        elif isSafePath(pagePath):
            sk.sendall(formatHttpResponse(pagePath, acceptEncoding))
        else:
            sk.sendall(formatErrorResponse(400))
    elif method == "HEAD":
        if page == "/":
            page = "/index.html"
        
        pagePath = CWD / page.removeprefix("/")

        if isSafePath(pagePath):
            sk.sendall(formatHEADResponse(pagePath))
        else:
            sk.sendall(formatErrorResponse(400))

    closeSocket(sk)

def isValidRedirectToken(redirectToken):
    for k, v in SHORT_REDIRECT_TOKENS.items():
        if "TOKEN" in v and v["TOKEN"] == redirectToken and v["EXPIRES"] > time.time():
            SHORT_REDIRECT_TOKENS.pop(k)
            return k
    
    return None


def isValidToken(authToken: str | None, username=None):
    if authToken == None:
        return False

    if username:
        if username not in VALID_TOKENS:
            return False

        if "EXPIRES" in VALID_TOKENS[username] and VALID_TOKENS[username]["EXPIRES"] < time.time():
            VALID_TOKENS.pop(username, None)
            return False
            
        if "TOKEN" in VALID_TOKENS[username] and VALID_TOKENS[username]["TOKEN"] == authToken:
            return True
        
    else:
        for key, value in VALID_TOKENS.items():
            if "TOKEN" in value and value["TOKEN"] == authToken:
                if "EXPIRES" in value and value["EXPIRES"] < time.time():
                    VALID_TOKENS.pop(key, None)
                    return False
                else:
                    return True

    return False

def resizePfpBytes(pfpBytes: bytes):
    pfpStream = BytesIO(pfpBytes)

    if not validateImgFile(pfpStream):
        return DEFAULT_PFPS[secrets.randbelow(len(DEFAULT_PFPS))]

    img = Image.open(pfpStream)
    format = img.format if img.format else "JPEG"
    resized = img.resize((256, 256), Image.Resampling.LANCZOS)
    outputStream = BytesIO()
    resized.save(outputStream, format=format)
    resizedBytes = outputStream.getvalue()
    resizedPfp = base64.b64encode(resizedBytes).decode("utf-8")
    return f"data:image/{format.lower()};base64,{resizedPfp}"

def resizePfp(pfp: str):
    if "," in pfp:
        pfp = pfp.split(",")[1]
    pfpBytes = base64.b64decode(pfp)
    return resizePfpBytes(pfpBytes)

def validateUsername(username: str):
    return username.replace("_", "").isalnum() and username.isascii() and len(username) >= 3 and len(username) <= 30

async def getAuth(connection: ServerConnection, request: Request):
    cookie_header = request.headers.get("Cookie")
    
    if cookie_header:
        parser = cookies.SimpleCookie()
        parser.load(cookie_header)
        
        parsed_cookies = {key: morsel.value for key, morsel in parser.items()}
        
        setattr(connection, "authToken", parsed_cookies.get("authToken"))

async def wsSendEncrypted(ws: ServerConnection, data: bytes, trackerId: int | None=None):
    if trackerId != None:
        dataParsed = orjson.loads(data)
        dataParsed["trackerID"] = trackerId
        data = orjson.dumps(dataParsed)

    iv = secrets.token_bytes(12)
    encryptor = Cipher(algorithms.AES256(getattr(ws, "secretKey")), modes.GCM(iv)).encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize() + encryptor.tag

    await ws.send(orjson.dumps({"encryption":"AES","iv":iv.hex(),"body":ciphertext.hex()}), text=True)

async def wsBroadcastEncrypted(clients: Iterable[ServerConnection], data: bytes):
    for client in clients:
        try:
            await wsSendEncrypted(client, data)
        except Exception:
            traceback.print_exc()

async def checkAuthTokenEncrypted(ws: ServerConnection, authToken: str | None):
    if not isValidToken(authToken):
        await wsSendEncrypted(ws, orjson.dumps({"type":"auth_expired"}))
        await ws.close()
        return False
    return True

async def wsHandler(ws: ServerConnection):
    WS_CLIENTS.add(ws)

    try:
        authToken: str | None = getattr(ws, "authToken", None)

        if authToken:
            setattr(ws, "UID", getUserIdFromAuthToken(authToken))

        async for message in ws:
            msgDecoded = orjson.loads(message)

            if "type" in msgDecoded and msgDecoded["type"] == "encrypt-key-xch":
                clientKey = ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP256R1(),
                    bytes.fromhex(msgDecoded["publicKey"])
                )

                setattr(ws, "secretKey", PRIV_KEY.exchange(ec.ECDH(), clientKey))

                await ws.send(orjson.dumps({"type":"encrypt-key-xch", "publicKey": PUB_KEY.hex()}), text=True)
                continue
            
            if "encryption" in msgDecoded and msgDecoded["encryption"] == "AES":
                key = getattr(ws, "secretKey", None)

                if key == None:
                    logging.warning("[WS] Encrypted message sent without key!")
                    await ws.close()
                    raise ConnectionRefusedError
                
                if len(key) != 32:
                    await ws.close()
                    raise ConnectionRefusedError

                try:
                    data = bytes.fromhex(msgDecoded["body"])
                    iv = bytes.fromhex(msgDecoded["iv"])

                    if len(data) < 16:
                        raise ValueError()
                    
                    if len(iv) != 12:
                        raise ValueError()

                    ciphertext = data[:-16]
                    tag = data[-16:]

                    decryptor = Cipher(algorithms.AES256(key), modes.GCM(iv, tag)).decryptor()
                    decryptedText = decryptor.update(ciphertext) + decryptor.finalize()
                except (InvalidTag, ValueError):
                    traceback.print_exc()
                    logging.error("Failed to decrypt message!")
                    await ws.close()
                    break
                
                decryptedBody = orjson.loads(decryptedText)
                trackerId = None

                if "trackerID" in decryptedBody:
                    trackerId = decryptedBody["trackerID"]

                if not "type" in decryptedBody:
                    await wsSendEncrypted(ws, orjson.dumps({"type": "unknownRequest"}), trackerId)
                    continue

                if decryptedBody["type"] == "login":
                    if not "username" in decryptedBody or not "password" in decryptedBody:
                        await wsSendEncrypted(ws, orjson.dumps({"type": "loginFailed"}))
                        continue

                    if not validateUsername(decryptedBody["username"]):
                        await wsSendEncrypted(ws, orjson.dumps({"type": "loginFailed"}))
                        continue

                    found = False

                    usrPwd = base64.b64decode(decryptedBody["password"])
                
                    for usr in users:
                        if usr["USRNAME"] == decryptedBody["username"]:
                            if bcrypt.checkpw(usrPwd, usr["PWD"].encode("utf-8")):
                                token = secrets.token_urlsafe(32)
                                SHORT_REDIRECT_TOKENS[usr["USRNAME"]] = {"TOKEN":token,"EXPIRES": time.time() + REDIRECT_TOKEN_EXPIRES_SEC}
                                await wsSendEncrypted(ws, orjson.dumps({"type":"loginSuccess","redirect":f"/api/login?TK={token}"}))
                                found = True
                            else:
                                await wsSendEncrypted(ws, orjson.dumps({"type":"loginFailed"}))
                                found = True
                            break
                            
                    if not found:
                        bcrypt.checkpw(usrPwd, DUMMY_HASH)
                        await wsSendEncrypted(ws, data=orjson.dumps({"type":"loginFailed"}))
                
                if decryptedBody["type"] == "signup":
                    if not "realname" in decryptedBody or not "username" in decryptedBody or not "password" in decryptedBody or not "securityKey" in decryptedBody:
                        await wsSendEncrypted(ws, orjson.dumps({"type": "signupFailed", "reason": "Request error. Please contact the server owner for help."}))
                        continue

                    allowed = True

                    for ip in copy.copy(RATELIMITED_IPS):
                        if ip["ip"] == ws.remote_address[0]:
                            if ip["expire"] > time.time():
                                allowed = False
                            else:
                                RATELIMITED_IPS.remove(ip)

                    if not allowed:
                        await wsSendEncrypted(ws, orjson.dumps({"type": "signupFailed", "reason": f"You have been ratelimited. Please try again in {ACC_CREATION_COOLDOWN_SEC} minutes."}))
                        continue

                    name = decryptedBody["realname"].strip()
                    username = decryptedBody["username"].strip()
                    password = base64.b64decode(decryptedBody["password"])
                    securityKey = decryptedBody["securityKey"]

                    if not validateUsername(username):
                        await wsSendEncrypted(ws, orjson.dumps({"type": "signupFailed", "reason": "Username must only contain uppercase, lowercase, numbers, and underscores. It must also be at least 3 characters."}))
                        continue

                    allowed = True
                    for usr in users:
                        if usr["USRNAME"] == username:
                            allowed = False
                    
                    if not allowed:
                        await wsSendEncrypted(ws, orjson.dumps({"type": "signupFailed", "reason": "That username is already in use!"}))
                        continue

                    # We good :D
                    with open(SECURITY_DIR / f"{username}.sq", "wb") as f:
                        f.write(fernet.encrypt(orjson.dumps({"name": name, "username": username, "secQ": securityKey})))
                        f.close()
                    
                    users.append({"UID": len(users), "USRNAME": username, "PWD": bcrypt.hashpw(password, bcrypt.gensalt(NUM_ENCRYPT_ROUNDS)).decode("utf-8"), "Displayname": username, "Birthday": None, "BirthdayV": "PRIVATE", "AccCreated": time.time(), "Pronouns": "", "Bio": "", "PFP": DEFAULT_PFPS[secrets.randbelow(len(DEFAULT_PFPS))], "Friends": list(), "Chats": [0], "FriendRequests": list()})
                    
                    RATELIMITED_IPS.append({"ip": ws.remote_address[0], "expire": time.time() + ACC_CREATION_COOLDOWN_SEC})
                    
                    await wsSendEncrypted(ws, orjson.dumps({"type": "signupSuccess", "redirect": "/signupSuccess.html"}))
                
                if decryptedBody["type"] == "reqUser":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        userinfo = getUserInfoFromToken(authToken)

                        if userinfo == None:
                            await wsSendEncrypted(ws, orjson.dumps({"type":"reqUserFailed", "message": "User not found!"}), trackerId)
                            continue
                        
                        await wsSendEncrypted(ws, orjson.dumps({
                            "type": "reqUserSuccess",
                            "username": userinfo["USRNAME"],
                            "UID": userinfo["UID"],
                            "friends": userinfo["Friends"],
                            "chats": userinfo["Chats"],
                            "pfp": userinfo["PFP"],
                            "displayname": userinfo["Displayname"],
                            "birthday": userinfo["Birthday"],
                            "birthdayV": userinfo["BirthdayV"],
                            "accCreated": userinfo["AccCreated"],
                            "bio": userinfo["Bio"],
                            "pronouns": userinfo["Pronouns"],
                            "friendReq": userinfo["FriendRequests"]
                        }), trackerId)
                    else:
                        break
                
                if decryptedBody["type"] == "reqChatMeta":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        if not "CID" in decryptedBody:
                            await wsSendEncrypted(ws, orjson.dumps({"type": "reqChatMetaFailed", "message": "Request error. Please contact the server owner for help."}), trackerId)
                            continue

                        if not tokenInChat(authToken, decryptedBody["CID"]):
                            await wsSendEncrypted(ws, orjson.dumps({"type":"reqChatMetaFailed","message": "User not in chat!"}), trackerId)
                            continue

                        chat = getChatFromCID(decryptedBody["CID"])

                        if chat == None:
                            await wsSendEncrypted(ws, orjson.dumps({"type":"reqChatMetaFailed","message":"Chat not found!"}), trackerId)
                            continue

                        await wsSendEncrypted(ws, orjson.dumps({"type":"reqChatMetaSuccess", "chat": {
                            "CID": chat["CID"],
                            "type": chat["Type"],
                            "name": chat["Name"],
                            "recipients": chat["Recipients"]
                        }}), trackerId)
                    else:
                        break

                if decryptedBody["type"] == "reqChat":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        if not "CID" in decryptedBody or not "page" in decryptedBody:
                            await wsSendEncrypted(ws, orjson.dumps({"type": "reqChatFailed", "message": "Request error. Please contact the server owner for help."}), trackerId)
                            continue

                        if not tokenInChat(authToken, decryptedBody["CID"]):
                            await wsSendEncrypted(ws, orjson.dumps({"type":"reqChatFailed","message": "User not in chat!"}), trackerId)
                            continue

                        chat = getChatFromCID(decryptedBody["CID"])

                        if chat == None:
                            await wsSendEncrypted(ws, orjson.dumps({"type":"reqChatFailed","message":"Chat not found!"}), trackerId)
                            continue

                        pagedChat = copy.deepcopy(chat)

                        if (decryptedBody["page"] == 0):
                            pagedChat["messages"] = pagedChat["messages"][-100:]
                        else:
                            pagedChat["messages"] = pagedChat["messages"][-100 * (decryptedBody["page"] + 1):-100 * decryptedBody["page"]]

                        await wsSendEncrypted(ws, orjson.dumps({"type":"reqChatSuccess", "chat": pagedChat, "numPages": math.ceil(len(chat["messages"]) / 100 + 0.005) - 1}), trackerId)
                    else:
                        break
                
                if decryptedBody["type"] == "reqUsersList":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        if not "users" in decryptedBody:
                            await wsSendEncrypted(ws, orjson.dumps({"type": "reqUsersListFailed"}), trackerId)
                            continue

                        userInfoList = []

                        for usr in decryptedBody["users"]:
                            userinfo = getUserInfoFromUserId(usr)

                            if userinfo != None:
                                userInfoList.append({
                                    "username": userinfo["USRNAME"],
                                    "UID": userinfo["UID"],
                                    "pfp": userinfo["PFP"],
                                    "displayname": userinfo["Displayname"]
                                })
                        
                        await wsSendEncrypted(ws, orjson.dumps({"type":"reqUsersListSuccess", "users":userInfoList}), trackerId)
                    else:
                        break
                
                if decryptedBody["type"] == "sendMsg":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        if not "CID" in decryptedBody or not "msg" in decryptedBody or not "embed" in decryptedBody:
                            await wsSendEncrypted(ws, orjson.dumps({"type": "chatUpdateFailed"}))
                            continue

                        if len(decryptedBody["msg"]) > 4000:
                            await wsSendEncrypted(ws, orjson.dumps({"type": "chatUpdateFailed"}))
                            continue

                        embedFilePaths = []
                        for embed in decryptedBody["embed"]:
                            embedC = embed["contents"]
                            if "," in embed["contents"]:
                                embedC = embed["contents"].split(",")[1]
                            
                            embedBytes = base64.b64decode(embedC)
                            uuid = ""
                            fileType = mimetypes.guess_extension(embed["type"])

                            if fileType == None:
                                fileType = ".bin"

                            while True:
                                uuid = secrets.token_urlsafe(48)

                                if (CDN_DIR / f"{uuid}{fileType}").exists():
                                    continue

                                with open(CDN_DIR / f"{uuid}{fileType}", "wb") as f:
                                    f.write(fernet.encrypt(embedBytes))
                                    f.close()
                                
                                break
                            
                            embedFilePaths.append(str((CDN_DIR / f"{uuid}{fileType}").resolve().relative_to(CWD)))
                        
                        chat = getChatFromCID(decryptedBody["CID"])

                        if chat == None:
                            await wsSendEncrypted(ws, orjson.dumps({"type": "chatUpdateFailed"}))
                            continue

                        msgObj = {"time": int(time.time()), "content": decryptedBody["msg"], "embed": embedFilePaths, "UID": getUserIdFromAuthToken(authToken), "MSGID": len(chat["messages"])}
                        chat["messages"].append(msgObj)

                        broadcastClients = []
                        for client in WS_CLIENTS:
                            cAuthToken = getattr(client, "authToken")

                            if cAuthToken == None:
                                continue
                            
                            userInfo = getUserInfoFromToken(cAuthToken)

                            if userInfo == None:
                                continue
                            
                            if decryptedBody["CID"] in userInfo["Chats"]:
                                broadcastClients.append(client)
                        

                        await wsBroadcastEncrypted(broadcastClients, orjson.dumps({"type":"newMsg", "CID": chat["CID"], "message": msgObj}))
                    else:
                        break
                
                if decryptedBody["type"] == "delMsg":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        if not "CID" in decryptedBody or not "MSGID" in decryptedBody:
                            await wsSendEncrypted(ws, orjson.dumps({"type": "delMsgFailed"}))
                            continue

                        chat = None
                        for cht in chats:
                            if cht["CID"] == decryptedBody["CID"]:
                                chat = cht
                                break

                        if chat == None:
                            await wsSendEncrypted(ws, orjson.dumps({"type": "delMsgFailed"}))
                            continue
                        
                        message = None

                        for msg in chat["messages"]:
                            if msg["MSGID"] == decryptedBody["MSGID"]:
                                message = msg
                                break

                        if message == None or message["UID"] != getUserIdFromAuthToken(authToken):
                            await wsSendEncrypted(ws, orjson.dumps({"type": "delMsgFailed"}))
                            continue

                        message["content"] = "[message deleted]"
                        message["embed"] = []
                        message["deleted"] = True

                        await wsSendEncrypted(ws, orjson.dumps({"type": "delMsgSuccess"}))

                        broadcastClients = []
                        for client in WS_CLIENTS:
                            cAuthToken = getattr(client, "authToken")

                            if cAuthToken == None:
                                continue
                            
                            userInfo = getUserInfoFromToken(cAuthToken)

                            if userInfo == None:
                                continue
                            
                            if decryptedBody["CID"] in userInfo["Chats"]:
                                broadcastClients.append(client)

                        await wsBroadcastEncrypted(broadcastClients, orjson.dumps({"type":"chatUpdate", "chat": chat}))
                    else:
                        break

                if decryptedBody["type"] == "updateDisplayname":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        if not "displayname" in decryptedBody:
                            await wsSendEncrypted(ws, orjson.dumps({"type":"updateDisplaynameFailed"}), trackerId)
                            continue

                        dn = decryptedBody["displayname"].strip()

                        if (dn == ""):
                            await wsSendEncrypted(ws, orjson.dumps({"type":"updateDisplaynameFailed"}), trackerId)
                            continue

                        if (len(dn) > 30):
                            await wsSendEncrypted(ws, orjson.dumps({"type":"updateDisplaynameFailed"}), trackerId)
                            continue
                        
                        if not setUserProperty(getUserIdFromAuthToken(authToken), "Displayname", dn):
                            await wsSendEncrypted(ws, orjson.dumps({"type":"updateDisplaynameFailed"}), trackerId)
                            continue

                        await wsSendEncrypted(ws, orjson.dumps({"type":"updateDisplaynameSuccess"}), trackerId)
                        await wsBroadcastEncrypted(WS_CLIENTS, orjson.dumps({"type":"updateCachedDisplayname", "UID": getUserIdFromAuthToken(authToken), "Displayname": dn}))
                    else:
                        break
                
                if decryptedBody["type"] == "updateBirthday":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        if not "bd" in decryptedBody:
                            await wsSendEncrypted(ws, orjson.dumps({"type":"updateBirthdayFailed"}), trackerId)
                            continue

                        bDay = decryptedBody["bd"]
                        
                        if not setUserProperty(getUserIdFromAuthToken(authToken), "Birthday", bDay):
                            await wsSendEncrypted(ws, orjson.dumps({"type": "updateBirthdayFailed"}), trackerId)
                            continue

                        await wsSendEncrypted(ws, orjson.dumps({"type": "updateBirthdaySuccess"}), trackerId)
                    else:
                        break
                
                if decryptedBody["type"] == "updatePronoun":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        if not "pronoun" in decryptedBody:
                            await wsSendEncrypted(ws, orjson.dumps({"type":"updatePronounFailed"}), trackerId)
                            continue

                        pronouns = decryptedBody["pronoun"]
                        
                        if not setUserProperty(getUserIdFromAuthToken(authToken), "Pronouns", pronouns):
                            await wsSendEncrypted(ws, orjson.dumps({"type": "updatePronounFailed"}), trackerId)
                            continue

                        await wsSendEncrypted(ws, orjson.dumps({"type": "updatePronounSuccess"}), trackerId)
                    else:
                        break
                
                if decryptedBody["type"] == "updatePfp":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        if not "pfp" in decryptedBody:
                            await wsSendEncrypted(ws, orjson.dumps({"type":"updatePfpFailed"}), trackerId)
                            continue

                        pfp = decryptedBody["pfp"]
                        pfpResized = resizePfp(pfp)

                        if not setUserProperty(getUserIdFromAuthToken(authToken), "PFP", pfpResized):
                            await wsSendEncrypted(ws, orjson.dumps({"type": "updatePfpFailed"}), trackerId)
                            continue

                        await wsSendEncrypted(ws, orjson.dumps({"type": "updatePfpSuccess"}), trackerId)
                        await wsBroadcastEncrypted(WS_CLIENTS, orjson.dumps({"type": "updateCachedPfp", "UID": getUserIdFromAuthToken(authToken), "PFP": pfpResized}))
                    else:
                        break
                
                if decryptedBody["type"] == "updateBio":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        if not "bio" in decryptedBody:
                            await wsSendEncrypted(ws, orjson.dumps({"type":"updatePfpFailed"}), trackerId)
                            continue

                        bio = decryptedBody["bio"]

                        if not setUserProperty(getUserIdFromAuthToken(authToken), "Bio", bio):
                            await wsSendEncrypted(ws, orjson.dumps({"type": "updateBioFailed"}), trackerId)
                            continue

                        await wsSendEncrypted(ws, orjson.dumps({"type": "updateBioSuccess"}), trackerId)
                    else:
                        break
                
                if decryptedBody["type"] == "logout":
                    usr = getUserIdFromAuthToken(authToken)
                    
                    if usr:
                        VALID_TOKENS.pop(usr, None)

                    await wsSendEncrypted(ws, orjson.dumps({"type": "logoutSuccess"}))
                    await ws.close()
                    break

                if decryptedBody["type"] == "userSearch":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        if not "unameSearch" in decryptedBody:
                            await wsSendEncrypted(ws, orjson.dumps({"type": "userSearchFailed"}), trackerId)
                            continue

                        usernameS = decryptedBody["unameSearch"].strip()

                        if not validateUsername(usernameS):
                            await wsSendEncrypted(ws, orjson.dumps({"type": "userSearchFailed"}), trackerId)
                            continue

                        results = []
                        for usr in users:
                            if usernameS.lower() in usr["USRNAME"].lower():
                                results.append(usr)
                        
                        if len(results) == 0:
                            await wsSendEncrypted(ws, orjson.dumps({"type": "userSearchFailed"}), trackerId)
                            continue
                        
                        final = []

                        for res in results:
                            final.append({
                                "displayname": res["Displayname"],
                                "username": res["USRNAME"],
                                "pfp": res["PFP"],
                                "UID": res["UID"]
                            })

                        await wsSendEncrypted(ws, orjson.dumps({
                            "type": "userSearchSuccess",
                            "results": final
                        }), trackerId)
                    else:
                        break
                
                if decryptedBody["type"] == "friendReq":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        # TODO: Blocking users & stuff idk
                        if not "UID" in decryptedBody:
                            await wsSendEncrypted(ws, orjson.dumps({"type": "friendReqFailed"}), trackerId)
                            continue

                        targetUID = decryptedBody["UID"]
                        selfUID = getUserIdFromAuthToken(authToken)

                        targetInfo = getUserInfoFromUserId(targetUID)
                        selfInfo = getUserInfoFromToken(authToken)

                        if targetInfo is None or selfInfo is None:
                            await wsSendEncrypted(ws, orjson.dumps({"type": "friendReqFailed"}), trackerId)
                            continue

                        targetFriendReqs = targetInfo["FriendRequests"]
                        selfFriendReqs = selfInfo["FriendRequests"]
                        
                        alreadyRequested = False
                        for req in selfFriendReqs:
                            if req["UID"] == targetUID:
                                alreadyRequested = True
                                break
                        
                        if not alreadyRequested:
                            for req in targetFriendReqs:
                                if req["UID"] == targetUID:
                                    alreadyRequested = True
                                    break
                        
                        if not alreadyRequested:
                            for fri in selfInfo["Friends"]:
                                if fri["UID"] == targetUID:
                                    alreadyRequested = True
                                    break
                        
                        if not alreadyRequested:
                            for fri in targetInfo["Friends"]:
                                if fri["UID"] == selfUID:
                                    alreadyRequested = True
                                    break
                        
                        if alreadyRequested:
                            await wsSendEncrypted(ws, orjson.dumps({"type": "friendReqFailed"}), trackerId)
                            continue
                        
                        for usr in users:
                            if usr["UID"] == targetUID:
                                usr["FriendRequests"].append({"UID":selfUID, "type":"incoming"})
                                targetFriendReqs = usr["FriendRequests"]
                            
                            if usr["UID"] == selfUID:
                                usr["FriendRequests"].append({"UID":targetUID, "type":"outgoing"})
                                selfFriendReqs = usr["FriendRequests"]
                        
                        await wsSendEncrypted(ws, orjson.dumps({"type": "updateFriendReqs", "friendReqs": selfFriendReqs}), trackerId)

                        for ws2 in WS_CLIENTS:
                            wsUID = getattr(ws2, "UID", None)
                            if wsUID != None and wsUID == targetUID:
                                await wsSendEncrypted(ws2, orjson.dumps({"type": "updateFriendReqs", "friendReqs": targetFriendReqs}))
                                break
                    else:
                        break
                
                if decryptedBody["type"] == "cancelFriendReq":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        if not "UID" in decryptedBody:
                            await wsSendEncrypted(ws, orjson.dumps({"type": "cancelFriendReqFailed"}), trackerId)
                            continue

                        targetUID = decryptedBody["UID"]
                        selfUID = getUserIdFromAuthToken(authToken)

                        targetInfo = getUserInfoFromUserId(targetUID)
                        selfInfo = getUserInfoFromToken(authToken)

                        if targetInfo is None or selfInfo is None:
                            await wsSendEncrypted(ws, orjson.dumps({"type": "cancelFriendReqFailed"}), trackerId)
                            continue

                        targetFriendReqs = targetInfo["FriendRequests"]
                        selfFriendReqs = selfInfo["FriendRequests"]
                        
                        for usr in users:
                            if usr["UID"] == targetUID:
                                usr["FriendRequests"].remove({"UID":selfUID, "type":"incoming"})
                                targetFriendReqs = usr["FriendRequests"]
                            
                            if usr["UID"] == selfUID:
                                usr["FriendRequests"].remove({"UID":targetUID, "type":"outgoing"})
                                selfFriendReqs = usr["FriendRequests"]
                        
                        await wsSendEncrypted(ws, orjson.dumps({"type": "updateFriendReqs", "friendReqs": selfFriendReqs}), trackerId)

                        for ws2 in WS_CLIENTS:
                            wsUID = getattr(ws2, "UID", None)
                            if wsUID != None and wsUID == targetUID:
                                await wsSendEncrypted(ws2, orjson.dumps({"type": "updateFriendReqs", "friendReqs": targetFriendReqs}))
                                break
                    else:
                        break

                if decryptedBody["type"] == "declineFriendReq":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        if not "UID" in decryptedBody:
                            await wsSendEncrypted(ws, orjson.dumps({"type": "declineFriendReqFailed"}), trackerId)
                            continue

                        targetUID = decryptedBody["UID"]
                        selfUID = getUserIdFromAuthToken(authToken)

                        targetInfo = getUserInfoFromUserId(targetUID)
                        selfInfo = getUserInfoFromToken(authToken)

                        if targetInfo is None or selfInfo is None:
                            await wsSendEncrypted(ws, orjson.dumps({"type": "declineFriendReqFailed"}), trackerId)
                            continue

                        targetFriendReqs = targetInfo["FriendRequests"]
                        selfFriendReqs = selfInfo["FriendRequests"]
                        
                        for usr in users:
                            if usr["UID"] == targetUID:
                                usr["FriendRequests"].remove({"UID":selfUID, "type":"outgoing"})
                                targetFriendReqs = usr["FriendRequests"]
                            
                            if usr["UID"] == selfUID:
                                usr["FriendRequests"].remove({"UID":targetUID, "type":"incoming"})
                                selfFriendReqs = usr["FriendRequests"]
                        
                        await wsSendEncrypted(ws, orjson.dumps({"type": "updateFriendReqs", "friendReqs": selfFriendReqs}), trackerId)

                        for ws2 in WS_CLIENTS:
                            wsUID = getattr(ws2, "UID", None)
                            if wsUID != None and wsUID == targetUID:
                                await wsSendEncrypted(ws2, orjson.dumps({"type": "updateFriendReqs", "friendReqs": targetFriendReqs}))
                                break
                    else:
                        break

                if decryptedBody["type"] == "acceptFriendReq":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        if not "UID" in decryptedBody:
                            await wsSendEncrypted(ws, orjson.dumps({"type": "acceptFriendReqFailed"}), trackerId)
                            continue

                        targetUID = decryptedBody["UID"]
                        selfUID = getUserIdFromAuthToken(authToken)

                        targetInfo = getUserInfoFromUserId(targetUID)
                        selfInfo = getUserInfoFromToken(authToken)

                        if targetInfo is None or selfInfo is None:
                            await wsSendEncrypted(ws, orjson.dumps({"type": "acceptFriendReqFailed"}), trackerId)
                            continue

                        targetFriendReqs: list = targetInfo["FriendRequests"]
                        selfFriendReqs: list = selfInfo["FriendRequests"]

                        alreadyFriends = False
                        for fri in selfInfo["Friends"]:
                            if fri["UID"] == targetUID:
                                alreadyRequested = True
                                break
                        
                        if not alreadyFriends:
                            for fri in targetInfo["Friends"]:
                                if fri["UID"] == selfUID:
                                    alreadyRequested = True
                                    break
                        
                        if alreadyFriends:
                            await wsSendEncrypted(ws, orjson.dumps({"type": "acceptFriendReqFailed"}), trackerId)
                            continue
                        
                        if not ({"UID": targetUID, "type": "incoming"} in selfFriendReqs and {"UID": selfUID, "type": "outgoing"} in targetFriendReqs):
                            await wsSendEncrypted(ws, orjson.dumps({"type": "acceptFriendReqFailed"}), trackerId)
                            continue

                        cid = len(chats)

                        chats.append({"CID": cid, "Type": "dm", "Name": f"{targetInfo["Displayname"]} & {selfInfo["Displayname"]}", "Recipients": [selfUID, targetUID], "messages": []})
                        
                        for usr in users:
                            if usr["UID"] == targetUID:
                                usr["FriendRequests"].remove({"UID": selfUID, "type": "outgoing"})
                                usr["Friends"].append({"UID": selfUID, "CID": cid, "timestamp": time.time()})
                                usr["Chats"].append(cid)
                            
                            if usr["UID"] == selfUID:
                                usr["FriendRequests"].remove({"UID": targetUID, "type": "incoming"})
                                usr["Friends"].append({"UID": targetUID, "CID": cid, "timestamp": time.time()})
                                usr["Chats"].append(cid)
                        
                        await wsSendEncrypted(ws, orjson.dumps({"type": "updateFriends", "friendReqs": selfFriendReqs, "friends": selfInfo["Friends"], "chats": selfInfo["Chats"]}), trackerId)

                        for ws2 in WS_CLIENTS:
                            wsUID = getattr(ws2, "UID", None)
                            if wsUID != None and wsUID == targetUID:
                                await wsSendEncrypted(ws2, orjson.dumps({"type": "updateFriends", "friendReqs": targetFriendReqs, "friends": targetInfo["Friends"], "chats": targetInfo["Chats"]}))
                                break
                    else:
                        break

                continue
            

    except Exception:
        traceback.print_exc()
    finally:
        WS_CLIENTS.remove(ws)

async def shutdownWs(shutdownEvent: asyncio.Event, future: Future):
    shutdownEvent.set()
    
    await asyncio.sleep(5)

    asyncio.get_running_loop().stop()

async def wsListen(ipAddrs: list, context: ssl.SSLContext, shutdownEvent: asyncio.Event):
    servers = []

    for addr in ipAddrs:
        servers.append(serve(wsHandler, addr, WSS_PORT, max_size=(25*1024*1024 * 11), ssl=context, process_request=getAuth))
        logging.debug(f"[WS] wss://{addr}/{WSS_PORT}")
        servers.append(serve(wsHandler, addr, WS_PORT, max_size=(25*1024*1024 * 11), process_request=getAuth))
        logging.debug(f"[WS] ws://{addr}/{WS_PORT}")

    logging.info("[WS] Websockets running")
    
    await asyncio.gather(*servers, shutdownEvent.wait())
    
    logging.info("[WS] Websocket exited")

def wsBootstrap(loop: asyncio.AbstractEventLoop):
    logging.info("[WS] Websocket Bootstrap")
    asyncio.set_event_loop(loop)
    loop.run_forever()

async def autosave(shutdownEvent: asyncio.Event):
    try:
        while True:
            try:
                await asyncio.wait_for(asyncio.shield(shutdownEvent.wait()), AUTOSAVE_INTERVAL_SEC)
                break
            except asyncio.TimeoutError:
                logging.debug(f"[AS] The current time is {datetime.datetime.now().strftime("%b %d, %Y at %I:%M %p")}")
                logging.debug("[AS] Autosaving...")
                saveUsers()
                saveChats()
                logging.debug("[AS] Autosave done")
    except asyncio.CancelledError:
        pass

    logging.info("[AS] Autosave thread exited")

async def shutdownAutosave(shutdownEvent: asyncio.Event, future: Future):
    logging.info("[AS] Stopping autosaves!")
    shutdownEvent.set()

    await asyncio.sleep(5)

    asyncio.get_running_loop().stop()

def autosaveBootstrap(loop: asyncio.AbstractEventLoop):
    logging.info("[AS] Autosave Bootstrap")
    asyncio.set_event_loop(loop)
    loop.run_forever()

if __name__ == "__main__":
    print("[MAIN] Hello, world!")

    numErr = 0
    lastErr = time.time()

    print("[IO] Generating missing directories")
    CA_CERT_DIR.mkdir(exist_ok=True)
    CDN_DIR.mkdir(exist_ok=True)
    CHATS_DIR.mkdir(exist_ok=True)
    CSS_DIR.mkdir(exist_ok=True)
    JS_DIR.mkdir(exist_ok=True)
    LOG_DIR.mkdir(exist_ok=True)
    MEDIA_DIR.mkdir(exist_ok=True)
    PFP_DIR.mkdir(exist_ok=True)
    SECURITY_DIR.mkdir(exist_ok=True)
    USERS_DIR.mkdir(exist_ok=True)

    print("Starting logger")
    logging.basicConfig(
        level=LOG_LEVEL,
        format="%(asctime)s [%(levelname)s]: %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(LOG_DIR / f"{datetime.datetime.now().strftime("%Y-%m-%d %H-%M-%S")}.log")
        ]
    )

    logging.debug("[MAIN] Generating encryption key")
    PRIV_KEY = ec.generate_private_key(ec.SECP256R1())
    PUB_KEY = PRIV_KEY.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    logging.debug("[MAIN] Key generated successfully")

    logging.debug("[MAIN] Generating dummy hash")
    DUMMY_HASH = bcrypt.hashpw(b"DUMMY_PW", bcrypt.gensalt(NUM_ENCRYPT_ROUNDS))
    logging.debug("[MAIN] Dummy hash generated successfully")

    users = []

    chats = []

    logging.debug("[IO] Reading save key")
    with open(SAVE_KEY, "rb") as f:
        saveKey = f.read()
        f.close()

    fernet = Fernet(saveKey)
    logging.debug("[IO] Save key loaded")

    loadPfps()
    loadUsers()
    loadChats()
    
    ipAddrs = getIpAddrs()
    
    if len(ipAddrs) == 0:
        logging.fatal("[MAIN] No valid network interfaces found! Please connect to a network")
        sys.exit(-1)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CA_CERT_DIR / "server.crt", keyfile=CA_CERT_DIR / "server.key")
    
    socketList: list[socket.socket] = []
    for addr in ipAddrs:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((addr, PORT))
        sock.listen(SOCKET_BACKLOG_NUM)

        socketList.append(sock)
        logging.info(f"[MAIN] Listening on {addr}:{PORT}")
    
    logging.debug("[MAIN] It's time to get async")

    wsLoop = asyncio.new_event_loop()
    wsShutdownEvent = asyncio.Event()
    wsThread = threading.Thread(target=wsBootstrap, args=(wsLoop,), daemon=True)
    wsThread.start()

    wsFuture = asyncio.run_coroutine_threadsafe(wsListen(ipAddrs, context, wsShutdownEvent), wsLoop)

    autosaveLoop = asyncio.new_event_loop()
    autosaveShutdownEvent = asyncio.Event()
    autosaveThread = threading.Thread(target=autosaveBootstrap, args=(autosaveLoop,), daemon=True)
    autosaveThread.start()

    autosaveFuture = asyncio.run_coroutine_threadsafe(autosave(autosaveShutdownEvent), autosaveLoop)

    logging.debug("[MAIN] HTTP Primed and ready to go")
    logging.info("[MAIN] Connect via:")

    for addr in ipAddrs:
        logging.info(f"[MAIN] http://{addr}:{PORT}/")
        logging.info(f"[MAIN] https://{addr}:{PORT}/")
    
    while True:
        try:
            read_sockets, _, _ = select.select(socketList, [], [])
            
            for notified_socket in read_sockets:
                cSocket, ip = notified_socket.accept()
                peekBytes = cSocket.recv(3, socket.MSG_PEEK)

                if len(peekBytes) < 3:
                    closeSocket(cSocket)
                    continue

                if peekBytes[0] == 0x16:
                    try:
                        with context.wrap_socket(cSocket, server_side=True) as secureSk:
                            handleRequest(secureSk)
                    except ssl.SSLError as e:
                        logging.warning(f"[MAIN] SSL Handshake failure: {e}")
                    except Exception as e:
                        logging.error(f"[MAIN] Error handling connection: {e}")
                elif peekBytes in (b'GET', b'POS', b'PUT', b'DEL', b'HEA', b'OPT'):
                    handleRequest(cSocket)
                else:
                    logging.warning(f"[MAIN] Unknown Protocol. Bytes: {peekBytes}")
                
                closeSocket(cSocket)
        except KeyboardInterrupt:
            print("opythat!")
            break
        except Exception:
            traceback.print_exc()

            if time.time() - lastErr >= RETRY_ATTEMPTS_CLEAR_AFTER_SEC:
                numErr = 0

            if numErr < MAX_RETRY_ATTEMPTS:
                numErr += 1
                logging.warning(f"[MAIN] Attempting to recover ({numErr})")
            else:
                logging.fatal("[MAIN] Max Retry Attempts Exceeded")
                break
    
    logging.info("[MAIN] Shutting down Websocket thread (10s)")
    asyncio.run_coroutine_threadsafe(shutdownWs(wsShutdownEvent, wsFuture), loop=wsLoop)
    wsThread.join(10)

    if wsThread.is_alive():
        logging.warning("[MAIN] Forcibly shutting down Websocket thread!")
        wsLoop.close()

    logging.info("[MAIN] Shutting down autosave thread (10s)")
    asyncio.run_coroutine_threadsafe(shutdownAutosave(autosaveShutdownEvent, autosaveFuture), loop=autosaveLoop)
    autosaveThread.join(10)

    if autosaveThread.is_alive():
        logging.warning("[MAIN] Forcibly shutting down Autosave thread!")
        autosaveLoop.close()


    logging.info("[MAIN] Shutting down sockets")
    for sk in socketList:
        sk.close()

    saveUsers()
    saveChats()

    logging.info("[MAIN] Goodbye, World")
