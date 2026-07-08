# Open-LAN allows you to host your own messaging server on the Local Area Network.
# Copyright (C) 2026  Alex Gan
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
# Alex Gan <the_mrjune@gigapixel.cc>


print("""
####################
#                  #
#     Open-LAN     #
#                  #
####################
by GigaPixel Entertainment

Open-LAN  Copyright (C) 2026  Alex Gan
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions; See <https://www.gnu.org/licenses/>.
""")

print("""
REQUIRED IMPORTS:
(use pip to install)
cryptography,
websockets,
http,
io,
pillow,
traceback,
threading,
secrets,
pathlib,
msgpack,
asyncio,
bcrypt,
psutil,
socket,
select,
base64,
time,
json,
copy,
sys,
ssl,
os
""")

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from websockets.asyncio.server import serve, ServerConnection
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidTag
from http.server import BaseHTTPRequestHandler
from cryptography.fernet import Fernet
from http import cookies
from io import BytesIO
from PIL import Image
import traceback
import threading
import secrets
import pathlib
import msgpack
import asyncio
import bcrypt
import psutil # type: ignore
import socket
import select
import base64
import time
import json
import copy
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

CWD = pathlib.Path(__file__).resolve().parent
CA_CERT_DIR = CWD / "CA_CERT"
CHATS_DIR = CWD / "Chats/"
SAVE_KEY = CWD / "meta.key"
CSS_DIR = CWD / "CSS/"
MEDIA_DIR = CWD / "Media/"
PFP_DIR = CWD / "pfps/"
SECURITY_DIR = CWD / "security"
USERS_DIR = CWD / "Users/"

PRIVATE_DIRS = [
    USERS_DIR,
    CHATS_DIR,
    CA_CERT_DIR,
    SECURITY_DIR,
    SAVE_KEY
]

FILEEXT_TO_MIME = {
    ".png": "image/png",
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8"
}

WS_CLIENTS = set()
VALID_TOKENS = {}
SHORT_REDIRECT_TOKENS = {}

RATELIMITED_IPS = []

DEFAULT_PFPS = []

print("Generating encryption key")
PRIV_KEY = ec.generate_private_key(ec.SECP256R1())
PUB_KEY = PRIV_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint
)
print("Key generated successfully")

print("Generating dummy hash")
DUMMY_HASH = bcrypt.hashpw(b"DUMMY_PW", bcrypt.gensalt(15))
print("Dummy hash generated successfully")

users = []

chats = []
fernet = None

class HTTPRequestParser(BaseHTTPRequestHandler):
    def __init__(self, request_bytes):
        self.rfile = BytesIO(request_bytes)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        
        self.parse_request()

    def send_error(self, code, message=None, explain=None):
        self.error_code = code
        self.error_message = message

def genSaveKey():
    key = Fernet.generate_key()
    with open(SAVE_KEY, "wb") as f:
        f.write(key)
        f.close()

def validateImgFile(path):
    try:
        with Image.open(path) as img:
            img.verify()
            return True
    except:
        return False

def loadPfps():
    print("Loading default PFPs")
    for pfp in PFP_DIR.iterdir():
        if pfp.is_file() and validateImgFile(pfp):
            try:
                fileContents = None
                with open(pfp, "rb") as f:
                    fileContents = f.read()
                    f.close()
                
                base64Pfp = resizePfpBytes(fileContents)

                DEFAULT_PFPS.append(base64Pfp)
            except:
                traceback.print_exc()
                print(f"Failed to load pfp {pfp}")
        else:
            print(f"File {pfp} is not a valid img file!")
    print("Loaded default PFPs")

def loadUsers():
    global fernet

    print("Loading users")

    if not USERS_DIR.exists():
        USERS_DIR.mkdir()
    
    if not SAVE_KEY.exists():
        print("Generating new save key!")
        genSaveKey()

    print("Reading save key")
    with open(SAVE_KEY, "rb") as f:
        saveKey = f.read()
        f.close()

    fernet = Fernet(saveKey)

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

                users.append(userData)
                f.close()
    
    
    print("Users loaded")

def loadChats():
    global fernet

    print("Loading chats")

    if not CHATS_DIR.exists():
        CHATS_DIR.mkdir()
    
    for chat in CHATS_DIR.iterdir():
        if chat.is_file() and chat.suffix == ".enc":
            try:
                with open(chat, "rb") as f:
                    fileContents = msgpack.unpackb(f.read())
                    metadata = fileContents["meta"]
                    name = fileContents["Name"]
                    messages = fileContents["messages"]

                    for msg in messages:
                        msg["content"] = fernet.decrypt(msg["content"]).decode("utf-16")

                    chats.append({"CID": metadata["CID"], "Type": metadata["Type"], "Name": name, "messages": messages})
                    f.close()
            except Exception:
                traceback.print_exc()
                print(f"Failed to load chat! {chat.name}")
    
    print("Chats loaded")

def saveUsers():
    print("Saving users")

    for usr in users:
        try:
            with open(USERS_DIR / f"{usr["USRNAME"]}.usr", "wb") as f:
                f.write(fernet.encrypt(msgpack.packb(usr)))
                f.close()
        except:
            traceback.print_exc()
            print(f"Failed to save user {usr["USRNAME"]}!")
    print("Users saved")

def saveChats():
    print("Saving chats")

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

                f.write(msgpack.packb({"meta":metadata,"Name":chat["Name"],"messages":messages}))
                f.close()
        except Exception:
            traceback.print_exc()
            print(f"Failed to save chat! {chat}")
    
    print("Chats saved")
        
def getUsernameFromAuthToken(token):
    for username, tk in VALID_TOKENS.items():
        if tk["TOKEN"] == token:
            return username
    
    return None

def getUserIdFromAuthToken(token):
    userInfo = getUserInfoFromToken(token)

    if userInfo == None:
        return None
    
    return userInfo["UID"]

def getUserInfoFromUsername(username):
    for user in users:
        if user["USRNAME"] == username:
            return user
        
    return None

def getUserInfoFromUserId(UID):
    for user in users:
        if user["UID"] == UID:
            return user
    return None

def getUserInfoFromToken(token):
    username = getUsernameFromAuthToken(token)

    if username == None:
        return None
    
    return getUserInfoFromUsername(username)

def getChatFromCID(CID):
    for chat in chats:
        if chat["CID"] == CID:
            return chat
    
    return None

def setUserProperty(UID, PropertyName, Value):
    success = False
    for usr in users:
        if usr["UID"] == UID:
            usr[PropertyName] = Value
            success = True
            break

    return success

def tokenInChat(token, CID):
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
                print(f"Interface: {interface_name} -> IP Address: {address.address}")
                ip_list.append(address.address)
                
    return ip_list

def formatHttpResponse(filePath: pathlib.Path):
    if not filePath.is_file():
        print(f"Invalid fetch {filePath}!")

        return formatErrorResponse(404)
    
    fileContents = bytes()
    with open(filePath, "rb") as f:
        fileContents = f.read()
        f.close()

    mime = FILEEXT_TO_MIME[filePath.suffix]

    return (
        "HTTP/1.1 200 OK\r\n"
        f"Content-Type: {mime}\r\n"
        f"Content-Length: {len(fileContents)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("utf-8") + fileContents

def formatLoginResponse(username, cloudflare):
    if not username:
        return formatErrorResponse(500)

    token = secrets.token_urlsafe(256)
    VALID_TOKENS[username] = {"TOKEN": token, "EXPIRES": time.time() + (1*24*60*60)} # Expires in 1 day
    return (
        "HTTP/1.1 308 Permanent Redirect\r\n"
        f"Set-Cookie: authToken={token}; HttpOnly; SameSite=Strict; {"Domain=gigapixel.cc;" if cloudflare else ""} Path=/\r\n"
        f"Location: /app.html\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("utf-8")

def formatErrorResponse(statusCode):
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
        print(f"Failed to parse {request.decode("utf-8")}")
        closeSocket(sk)
        return
    
    method = parsed.command
    path = parsed.path
    pathSplit = path.split("?")
    page = pathSplit[0]
    uri = {}

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
            if "openlan.gigapixel.cc" in currUrl:
                # POV: Cloudflare
                sk.sendall(f"HTTP/1.1 200 OK\r\nUrl: ws://openlanws.gigapixel.cc\r\nContent-Type: text/plain\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode("utf-8"))
            else:
                sk.sendall(f"HTTP/1.1 200 OK\r\nUrl: ws://{currUrl}:{WS_PORT}\r\nContent-Type: text/plain\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode("utf-8"))
        elif page == "/api/wssurl":
            currUrl = parsed.headers.get("Domain-Url")

            if "openlan.gigapixel.cc" in currUrl:
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
            sk.sendall(formatHttpResponse(pagePath))
        else:
            sk.sendall(formatErrorResponse(400))
    elif method == "POST":
        pass

    closeSocket(sk)

def isValidRedirectToken(redirectToken):
    for k, v in SHORT_REDIRECT_TOKENS.items():
        if "TOKEN" in v and v["TOKEN"] == redirectToken and v["EXPIRES"] > time.time():
            SHORT_REDIRECT_TOKENS.pop(k)
            return k
    
    return None


def isValidToken(authToken, username=None):
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

def resizePfpBytes(pfpBytes):
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

def resizePfp(pfp):
    if "," in pfp:
        pfp = pfp.split(",")[1]
    pfpBytes = base64.b64decode(pfp)
    return resizePfpBytes(pfpBytes)

def validateUsername(username: str):
    return username.replace("_", "").isalnum() and username.isascii()

async def getAuth(connection, request):
    cookie_header = request.headers.get("Cookie")
    
    if cookie_header:
        parser = cookies.SimpleCookie()
        parser.load(cookie_header)
        
        parsed_cookies = {key: morsel.value for key, morsel in parser.items()}
        
        connection.authToken = parsed_cookies.get("authToken")

async def wsSendEncrypted(ws: ServerConnection, data: str, trackerId=None):
    if trackerId != None:
        dataParsed = json.loads(data)
        dataParsed["trackerID"] = trackerId
        data = json.dumps(dataParsed)

    iv = secrets.token_bytes(12)
    encryptor = Cipher(algorithms.AES256(getattr(ws, "secretKey")), modes.GCM(iv)).encryptor()
    ciphertext = encryptor.update(data.encode("utf-8")) + encryptor.finalize() + encryptor.tag

    await ws.send(json.dumps({"encryption":"AES","iv":iv.hex(),"body":ciphertext.hex()}))

async def wsBroadcastEncrypted(clients: list[ServerConnection], data: str):
    for client in clients:
        try:
            await wsSendEncrypted(client, data)
        except Exception:
            traceback.print_exc()

async def checkAuthTokenEncrypted(ws: ServerConnection, authToken: str):
    if not isValidToken(authToken):
        await wsSendEncrypted(ws, json.dumps({"type":"auth_expired"}))
        await ws.close()
        return False
    return True

async def wsHandler(ws: ServerConnection):
    WS_CLIENTS.add(ws)

    try:
        authToken = getattr(ws, "authToken", None)

        async for message in ws:
            msgDecoded = json.loads(message)

            if "type" in msgDecoded and msgDecoded["type"] == "encrypt-key-xch":
                clientKey = ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP256R1(),
                    bytes.fromhex(msgDecoded["publicKey"])
                )

                setattr(ws, "secretKey", PRIV_KEY.exchange(ec.ECDH(), clientKey))

                await ws.send(json.dumps({"type":"encrypt-key-xch", "publicKey": PUB_KEY.hex()}))
                continue
            
            if "encryption" in msgDecoded and msgDecoded["encryption"] == "AES":
                key = getattr(ws, "secretKey", None)

                if key == None:
                    print("Encrypted message sent without key!")
                    ws.close()
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
                    await ws.close()
                    break
                
                decryptedBody = json.loads(decryptedText.decode("utf-8"))
                trackerId = None

                if "trackerID" in decryptedBody:
                    trackerId = decryptedBody["trackerID"]

                if not "type" in decryptedBody:
                    await wsSendEncrypted(ws, json.dumps({"type": "unknownRequest"}), trackerId)
                    continue

                if decryptedBody["type"] == "login":
                    if not "username" in decryptedBody or not "password" in decryptedBody:
                        await wsSendEncrypted(ws, json.dumps({"type": "loginFailed"}))
                        continue

                    if not validateUsername(decryptedBody["username"]):
                        await wsSendEncrypted(ws, json.dumps({"type": "loginFailed"}))
                        continue

                    found = False

                    usrPwd = base64.b64decode(decryptedBody["password"])
                
                    for usr in users:
                        if usr["USRNAME"] == decryptedBody["username"]:
                            if bcrypt.checkpw(usrPwd, usr["PWD"].encode("utf-8")):
                                token = secrets.token_urlsafe(32)
                                SHORT_REDIRECT_TOKENS[usr["USRNAME"]] = {"TOKEN":token,"EXPIRES":time.time() + 60} # 1 minute
                                await wsSendEncrypted(ws, json.dumps({"type":"loginSuccess","redirect":f"/api/login?TK={token}"}))
                                found = True
                            else:
                                await wsSendEncrypted(ws, json.dumps({"type":"loginFailed"}))
                                found = True
                            break
                            
                    if not found:
                        bcrypt.checkpw(usrPwd, DUMMY_HASH)
                        await wsSendEncrypted(ws, json.dumps({"type":"loginFailed"}))
                
                if decryptedBody["type"] == "signup":
                    if not "realname" in decryptedBody or not "username" in decryptedBody or not "password" in decryptedBody or not "securityKey" in decryptedBody:
                        await wsSendEncrypted({"type": "signupFailed", "reason": "Request error. Please contact the server owner for help."})
                        continue

                    allowed = True

                    for ip in copy.copy(RATELIMITED_IPS):
                        if ip["ip"] == ws.remote_address[0]:
                            if ip["expire"] > time.time():
                                allowed = False
                            else:
                                RATELIMITED_IPS.remove(ip)

                    if not allowed:
                        await wsSendEncrypted(ws, json.dumps({"type": "signupFailed", "reason": f"You have been ratelimited. Please try again in {ACC_CREATION_COOLDOWN_SEC} minutes."}))
                        continue

                    name = decryptedBody["realname"].strip()
                    username = decryptedBody["username"].strip()
                    password = base64.b64decode(decryptedBody["password"])
                    securityKey = decryptedBody["securityKey"]

                    if not validateUsername(username):
                        await wsSendEncrypted(ws, json.dumps({"type": "signupFailed", "reason": "Username must only contain uppercase, lowercase, numbers, and underscores."}))
                        continue

                    allowed = True
                    for usr in users:
                        if usr["USRNAME"] == username:
                            allowed = False
                    
                    if not allowed:
                        await wsSendEncrypted(ws, json.dumps({"type": "signupFailed", "reason": "That username is already in use!"}))
                        continue

                    # We good :D
                    with open(SECURITY_DIR / f"{username}.sq", "wb") as f:
                        f.write(fernet.encrypt(json.dumps({"name": name, "username": username, "secQ": securityKey}).encode("utf-8")))
                        f.close()
                    
                    users.append({"UID": len(users), "USRNAME": username, "PWD": bcrypt.hashpw(password, bcrypt.gensalt(15)).decode("utf-8"), "Displayname": username, "Birthday": None, "BirthdayV": "PRIVATE", "AccCreated": time.time(), "Pronouns": "", "Bio": "", "PFP": DEFAULT_PFPS[secrets.randbelow(len(DEFAULT_PFPS))], "Friends": [], "Chats": [0]})
                    
                    RATELIMITED_IPS.append({"ip": ws.remote_address[0], "expire": time.time() + ACC_CREATION_COOLDOWN_SEC})
                    
                    await wsSendEncrypted(ws, json.dumps({"type": "signupSuccess", "redirect": "/signupSuccess.html"}))
                
                if decryptedBody["type"] == "reqUser":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        userinfo = getUserInfoFromToken(authToken)

                        if userinfo == None:
                            await wsSendEncrypted(ws, json.dumps({"type":"reqUserFailed", "message": "User not found!"}), trackerId)
                            continue
                        
                        await wsSendEncrypted(ws, json.dumps({
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
                            "pronouns": userinfo["Pronouns"]
                        }), trackerId)
                    else:
                        break

                if decryptedBody["type"] == "reqChat":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        if not "CID" in decryptedBody:
                            await wsSendEncrypted(ws, json.dumps({"type": "reqChatFailed", "message": "Request error. Please contact the server owner for help."}), trackerId)
                            continue

                        if not tokenInChat(authToken, decryptedBody["CID"]):
                            await wsSendEncrypted(ws, json.dumps({"type":"reqChatFailed","message": "User not in chat!"}), trackerId)
                            continue

                        chat = getChatFromCID(decryptedBody["CID"])

                        if chat == None:
                            await wsSendEncrypted(ws, json.dumps({"type":"reqChatFailed","message":"Chat not found!"}), trackerId)
                            continue

                        await wsSendEncrypted(ws, json.dumps({"type":"reqChatSuccess", "chat": chat}), trackerId)
                    else:
                        break
                
                if decryptedBody["type"] == "reqUsersList":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        if not "users" in decryptedBody:
                            await wsSendEncrypted(ws, json.dumps({"type": "reqUsersListFailed"}), trackerId)
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
                        
                        await wsSendEncrypted(ws, json.dumps({"type":"reqUsersListSuccess", "users":userInfoList}), trackerId)
                    else:
                        break
                
                if decryptedBody["type"] == "sendMsg":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        if not "CID" in decryptedBody or not "msg" in decryptedBody:
                            await wsSendEncrypted(ws, json.dumps({"type": "chatUpdateFailed"}))
                            continue

                        for chat in chats:
                            if chat["CID"] == decryptedBody["CID"]:
                                chat["messages"].append({"time": int(time.time()), "content": decryptedBody["msg"], "UID": getUserIdFromAuthToken(authToken), "MSGID": len(chat["messages"])})

                        newChat = getChatFromCID(decryptedBody["CID"])

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
                        

                        await wsBroadcastEncrypted(broadcastClients, json.dumps({"type":"chatUpdate", "chat": newChat}))
                    else:
                        break
                
                if decryptedBody["type"] == "delMsg":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        if not "CID" in decryptedBody or not "MSGID" in decryptedBody:
                            await wsSendEncrypted(ws, json.dumps({"type": "delMsgFailed"}))
                            continue

                        chat = None
                        for cht in chats:
                            if cht["CID"] == decryptedBody["CID"]:
                                chat = cht
                                break

                        if chat == None:
                            await wsSendEncrypted(ws, json.dumps({"type": "delMsgFailed"}))
                            continue
                        
                        message = None

                        for msg in chat["messages"]:
                            if msg["MSGID"] == decryptedBody["MSGID"]:
                                message = msg
                                break

                        if message == None or message["UID"] != getUserIdFromAuthToken(authToken):
                            await wsSendEncrypted(ws, json.dumps({"type": "delMsgFailed"}))
                            continue

                        message["content"] = "[message deleted]"
                        message["deleted"] = True

                        await wsSendEncrypted(ws, json.dumps({"type": "delMsgSuccess"}))

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

                        await wsBroadcastEncrypted(broadcastClients, json.dumps({"type":"chatUpdate", "chat": chat}))
                    else:
                        break

                if decryptedBody["type"] == "updateDisplayname":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        if not "displayname" in decryptedBody:
                            await wsSendEncrypted(ws, json.dumps({"type":"updateDisplaynameFailed"}), trackerId)
                            continue

                        dn = decryptedBody["displayname"].strip()

                        if (dn == ""):
                            await wsSendEncrypted(ws, json.dumps({"type":"updateDisplaynameFailed"}), trackerId)
                            continue

                        if (len(dn) > 30):
                            await wsSendEncrypted(ws, json.dumps({"type":"updateDisplaynameFailed"}), trackerId)
                            continue
                        
                        if not setUserProperty(getUserIdFromAuthToken(authToken), "Displayname", dn):
                            await wsSendEncrypted(ws, json.dumps({"type":"updateDisplaynameFailed"}), trackerId)
                            continue

                        await wsSendEncrypted(ws, json.dumps({"type":"updateDisplaynameSuccess"}), trackerId)
                        await wsBroadcastEncrypted(WS_CLIENTS, json.dumps({"type":"updateCachedDisplayname", "UID": getUserIdFromAuthToken(authToken), "Displayname": dn}))
                    else:
                        break
                
                if decryptedBody["type"] == "updateBirthday":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        if not "bd" in decryptedBody:
                            await wsSendEncrypted(ws, json.dumps({"type":"updateBirthdayFailed"}), trackerId)
                            continue

                        bDay = decryptedBody["bd"]
                        
                        if not setUserProperty(getUserIdFromAuthToken(authToken), "Birthday", bDay):
                            await wsSendEncrypted(ws, json.dumps({"type": "updateBirthdayFailed"}), trackerId)
                            continue

                        await wsSendEncrypted(ws, json.dumps({"type": "updateBirthdaySuccess"}), trackerId)
                    else:
                        break
                
                if decryptedBody["type"] == "updatePronoun":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        if not "pronoun" in decryptedBody:
                            await wsSendEncrypted(ws, json.dumps({"type":"updatePronounFailed"}), trackerId)
                            continue

                        pronouns = decryptedBody["pronoun"]
                        
                        if not setUserProperty(getUserIdFromAuthToken(authToken), "Pronouns", pronouns):
                            await wsSendEncrypted(ws, json.dumps({"type": "updatePronounFailed"}), trackerId)
                            continue

                        await wsSendEncrypted(ws, json.dumps({"type": "updatePronounSuccess"}), trackerId)
                    else:
                        break
                
                if decryptedBody["type"] == "updatePfp":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        if not "pfp" in decryptedBody:
                            await wsSendEncrypted(ws, json.dumps({"type":"updatePfpFailed"}), trackerId)
                            continue

                        pfp = decryptedBody["pfp"]
                        pfpResized = resizePfp(pfp)

                        if not setUserProperty(getUserIdFromAuthToken(authToken), "PFP", pfpResized):
                            await wsSendEncrypted(ws, json.dumps({"type": "updatePfpFailed"}), trackerId)
                            continue

                        await wsSendEncrypted(ws, json.dumps({"type": "updatePfpSuccess"}), trackerId)
                        await wsBroadcastEncrypted(WS_CLIENTS, json.dumps({"type": "updateCachedPfp", "UID": getUserIdFromAuthToken(authToken), "PFP": pfpResized}))
                    else:
                        break
                
                if decryptedBody["type"] == "updateBio":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        if not "bio" in decryptedBody:
                            await wsSendEncrypted(ws, json.dumps({"type":"updatePfpFailed"}), trackerId)
                            continue

                        bio = decryptedBody["bio"]

                        if not setUserProperty(getUserIdFromAuthToken(authToken), "Bio", bio):
                            await wsSendEncrypted(ws, json.dumps({"type": "updateBioFailed"}), trackerId)
                            continue

                        await wsSendEncrypted(ws, json.dumps({"type": "updateBioSuccess"}), trackerId)
                    else:
                        break
                
                if decryptedBody["type"] == "logout":
                    usr = getUserIdFromAuthToken(authToken)
                    
                    if usr:
                        VALID_TOKENS.pop(usr, None)

                    await wsSendEncrypted(ws, json.dumps({"type": "logoutSuccess"}))
                    await ws.close()
                    break

                continue
            

    except Exception:
        traceback.print_exc()
    finally:
        WS_CLIENTS.remove(ws)

async def shutdownWs(shutdownEvent):
    print("Stopping Websocket!")
    for ws in list(WS_CLIENTS):
        await ws.close()

    shutdownEvent.set()
    asyncio.get_running_loop().stop()

async def wsListen(ipAddrs, context, shutdownEvent):
    servers = []

    for addr in ipAddrs:
        servers.append(serve(wsHandler, addr, WSS_PORT, ssl=context, process_request=getAuth))
        print(f"wss://{addr}/{WSS_PORT}")
        servers.append(serve(wsHandler, addr, WS_PORT, process_request=getAuth))
        print(f"ws://{addr}/{WS_PORT}")

    print("Websockets running")
    
    await asyncio.gather(*servers, shutdownEvent.wait())

def wsBootstrap(loop: asyncio.AbstractEventLoop):
    print("Websocket Bootstrap")
    asyncio.set_event_loop(loop)
    loop.run_forever()

async def autosave(shutdownEvent: asyncio.Event):
    try:
        while True:
            try:
                await asyncio.wait_for(asyncio.shield(shutdownEvent.wait()), AUTOSAVE_INTERVAL_SEC)
                break
            except asyncio.TimeoutError:
                print("Autosaving...")
                saveUsers()
                saveChats()
                print("Autosave done!")
    except asyncio.CancelledError:
        pass

    print("Autosave thread exited")


def autosaveBootstrap(loop: asyncio.AbstractEventLoop):
    print("Autosave Bootstrap")
    asyncio.set_event_loop(loop)
    loop.run_forever()

if __name__ == "__main__":
    numErr = 0
    lastErr = time.time()

    loadPfps()
    loadUsers()
    loadChats()
    
    ipAddrs = getIpAddrs()
    
    if len(ipAddrs) == 0:
        print("No valid network interfaces found! Please connect to a network")
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
        print(f"Listening on {addr}:{PORT}")
    
    wsLoop = asyncio.new_event_loop()
    wsShutdownEvent = asyncio.Event()
    wsThread = threading.Thread(target=wsBootstrap, args=(wsLoop,), daemon=True)
    wsThread.start()

    asyncio.run_coroutine_threadsafe(wsListen(ipAddrs, context, wsShutdownEvent), wsLoop)

    autosaveLoop = asyncio.new_event_loop()
    autosaveShutdownEvent = asyncio.Event()
    autosaveThread = threading.Thread(target=autosaveBootstrap, args=(autosaveLoop,), daemon=True)
    autosaveThread.start()

    asyncio.run_coroutine_threadsafe(autosave(autosaveShutdownEvent), autosaveLoop)

    print("HTTP Primed and ready to go")
    
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
                        print(f"SSL Handshake failure: {e}")
                    except Exception as e:
                        print(f"Error handling connection: {e}")
                elif peekBytes in (b'GET', b'POS', b'PUT', b'DEL', b'HEA', b'OPT'):
                    handleRequest(cSocket)
                else:
                    print(f"Unknown Protocol. Bytes: {peekBytes}")
                
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
                print(f"Attempting to recover ({numErr})")
            else:
                print("Max Retry Attempts Exceeded")
                break
    
    print("Shutting down Websocket thread (5s)")
    asyncio.run_coroutine_threadsafe(shutdownWs(wsShutdownEvent), loop=wsLoop)
    wsThread.join(5)

    if wsThread.is_alive():
        print("Forcibly shutting down Websocket thread!")
        wsLoop.close()

    print("Shutting down sockets")
    for sk in socketList:
        sk.close()

    saveUsers()
    saveChats()
