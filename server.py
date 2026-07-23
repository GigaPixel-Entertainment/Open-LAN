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

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from websockets.asyncio.server import serve, ServerConnection, Request
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidTag
from concurrent.futures._base import Future
from cryptography.fernet import Fernet
from collections.abc import Iterable
from http import cookies
from io import BytesIO
from PIL import Image
import mimetypes
import traceback
import threading
import datetime
import logging
import secrets
import pathlib
import msgpack
import asyncio
import orjson
import bcrypt
import socket
import select
import base64
import time
import copy
import math
import sys
import ssl

from config import *
import httphelper

WS_CLIENTS: set[ServerConnection] = set()
VALID_TOKENS = {}
SHORT_REDIRECT_TOKENS = {}

RATELIMITED_IPS = []

DEFAULT_PFPS: list[str] = []

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
                logging.error("[IO] Failed to load pfp %s", pfp)
        else:
            logging.warning("[IO] File %s is not a valid img file!", pfp)
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
                    
                    if metadata["CID"] == 0:
                        recipients = [x for x in range(len(users))]

                    chats.append({"CID": metadata["CID"], "Type": metadata["Type"], "Name": name, "Recipients": recipients, "messages": messages})
                    f.close()
            except Exception:
                traceback.print_exc()
                logging.error("[IO] Failed to load chat! %s", chat.name)
    
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
                    logging.error("[IO] Failed to save user %s!", usr["USRNAME"])

                f.close()
        except:
            traceback.print_exc()
            logging.error("[IO] Failed to save user %s!", usr["USRNAME"])
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
                    messageSaving = copy.deepcopy(msg)
                    messageSaving["content"] = fernet.encrypt(messageSaving["content"].encode("utf-16"))
                    messages.append(messageSaving)
                
                packed: bytes | None = msgpack.packb({"meta":metadata,"Name":chat["Name"],"Recipients": chat["Recipients"], "messages":messages})

                if packed:
                    f.write(packed)
                else:
                    logging.error("[IO] Failed to save chat! %s", chat)

                f.close()
        except Exception:
            traceback.print_exc()
            logging.error("[IO] Failed to save chat! %s", chat)
    
    logging.info("[IO] Chats saved")
        
def getUsernameFromAuthToken(token: str | None) -> str | None:
    for username, tk in VALID_TOKENS.items():
        if tk["TOKEN"] == token:
            return username
    
    return None

def getUserIdFromAuthToken(token: str | None) -> int | None:
    userInfo = getUserInfoFromToken(token)

    if userInfo is None:
        return None
    
    return userInfo["UID"]

def getUserInfoFromUserId(UID: int) -> dict | None:
    for user in users:
        if user["UID"] == UID:
            return user
    return None

def getUserInfoFromUsername(username: str) -> dict | None:
    for user in users:
        if user["USRNAME"] == username:
            return user
        
    return None

def getUserInfoFromToken(token: str | None) -> dict | None:
    username = getUsernameFromAuthToken(token)

    if username is None:
        return None
    
    return getUserInfoFromUsername(username)

def getChatFromCID(CID: int) -> dict | None:
    for chat in chats:
        if chat["CID"] == CID:
            return chat
    
    return None

def setUserProperty(UID: int | None, PropertyName: str, Value) -> bool:
    if UID is None:
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

    if chat is None:
        return False

    userInfo = getUserInfoFromToken(token)

    if userInfo is None:
        return False
    
    if not CID in userInfo["Chats"]:
        return False
    
    return True

def formatLoginResponse(username: str, cloudflare: bool):
    if not username:
        return httphelper.formatErrorResponse(500)

    token = secrets.token_urlsafe(256)
    VALID_TOKENS[username] = {"TOKEN": token, "EXPIRES": time.time() + TOKEN_EXPIRES_SEC}

    return httphelper.formatHttpHeaderRaw(308, {
        "Set-Cookie": f"authToken={token}; HttpOnly; SameSite=Strict; {"Domain=gigapixel.cc" if cloudflare else ""} Path=/",
        "Location": "/app.html",
        "Connection": "close"
    })

def closeSocket(sk: socket.socket):
    try:
        sk.shutdown(socket.SHUT_WR)
        sk.close()
    except:
        pass

def handleRequest(sk: socket.socket):
    request = sk.recv(4096)
    parsed = httphelper.HTTPRequestParser(request)

    if parsed.error_code:
        logging.error("[MAIN] Failed to parse %s", request)
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
                sk.sendall(httphelper.formatHttpHeaderRaw(200, {
                    "Url": "ws://openlanws.gigapixel.cc",
                    "Connection": "close"
                }))
            else:
                sk.sendall(httphelper.formatHttpHeaderRaw(200, {
                    "Url": f"ws://{currUrl}:{WS_PORT}",
                    "Connection": "close"
                }))
        elif page == "/api/wssurl":
            currUrl = parsed.headers.get("Domain-Url")

            if currUrl and "openlan.gigapixel.cc" in currUrl:
                # POV: Cloudflare
                sk.sendall(httphelper.formatHttpHeaderRaw(200, {
                    "Url": "wss://openlanws.gigapixel.cc",
                    "Connection": "close"
                }))
            else:
                sk.sendall(httphelper.formatHttpHeaderRaw(200, {
                    "Url": f"wss://{currUrl}:{WSS_PORT}",
                    "Connection": "close"
                }))
        elif page == "/api/login":
            if "TK" in uri and "hostname" in uri:
                username = isValidRedirectToken(uri["TK"])

                if username is not None:
                    sk.sendall(formatLoginResponse(username, "gigapixel.cc" in uri["hostname"]))
        elif httphelper.isSafePath(pagePath):
            sk.sendall(httphelper.formatHttpResponse(pagePath, acceptEncoding, fernet))
        else:
            sk.sendall(httphelper.formatErrorResponse(404))
    elif method == "HEAD":
        if page == "/":
            page = "/index.html"
        
        pagePath = CWD / page.removeprefix("/")

        if httphelper.isSafePath(pagePath):
            sk.sendall(httphelper.formatHEADResponse(pagePath, acceptEncoding))
        else:
            sk.sendall(httphelper.formatErrorResponse(statusCode=404))

    closeSocket(sk)

def isValidRedirectToken(redirectToken):
    for k, v in SHORT_REDIRECT_TOKENS.items():
        if "TOKEN" in v and v["TOKEN"] == redirectToken and v["EXPIRES"] > time.time():
            SHORT_REDIRECT_TOKENS.pop(k)
            return k
    
    return None


def isValidToken(authToken: str | None, username=None):
    if authToken is None:
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

def checkFields(obj: dict, fields: list[str]):
    for field in fields:
        if not field in obj:
            return False
    
    return True

async def getAuth(connection: ServerConnection, request: Request):
    cookie_header = request.headers.get("Cookie")
    
    if cookie_header:
        parser = cookies.SimpleCookie()
        parser.load(cookie_header)
        
        parsed_cookies = {key: morsel.value for key, morsel in parser.items()}
        
        setattr(connection, "authToken", parsed_cookies.get("authToken"))

async def wsSendEncrypted(ws: ServerConnection, data: bytes, trackerId: int | None=None):
    if trackerId is not None:
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

async def handleEncryption(ws: ServerConnection, msgDecoded: dict):
    clientKey = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),
        bytes.fromhex(msgDecoded["publicKey"])
    )

    setattr(ws, "secretKey", PRIV_KEY.exchange(ec.ECDH(), clientKey))

    await ws.send(orjson.dumps({"type":"encrypt-key-xch", "publicKey": PUB_KEY.hex()}), text=True)

async def decrypt(ws: ServerConnection, msgDecoded: dict) -> tuple[dict, int] | tuple[None, None]:
    key = getattr(ws, "secretKey", None)

    if key is None:
        logging.warning("[WS] Encrypted message sent without key!")
        await ws.close()
        return (None, None)
    
    if len(key) != 32:
        await ws.close()
        return (None, None)

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
        decryptedBody = orjson.loads(decryptedText)

        return (decryptedBody, decryptedBody["trackerID"] if "trackerID" in decryptedBody else None)
    except (InvalidTag, ValueError):
        traceback.print_exc()
        logging.error("Failed to decrypt message!")
        await ws.close()
        return (None, None)

async def wsHandler(ws: ServerConnection):
    WS_CLIENTS.add(ws)

    try:
        authToken: str | None = getattr(ws, "authToken", None)

        if authToken:
            setattr(ws, "UID", getUserIdFromAuthToken(authToken))

        async for message in ws:
            msgDecoded = orjson.loads(message)

            if "type" in msgDecoded and msgDecoded["type"] == "encrypt-key-xch":
                await handleEncryption(ws, msgDecoded)
                continue
            
            if "encryption" in msgDecoded and msgDecoded["encryption"] == "AES":
                decryptedBody, trackerId = await decrypt(ws, msgDecoded)

                if decryptedBody is None:
                    break

                if not "type" in decryptedBody:
                    await wsSendEncrypted(ws, orjson.dumps({"type": "unknownRequest"}), trackerId)
                    continue

                if decryptedBody["type"] == "login":
                    if not checkFields(decryptedBody, ["username", "password"]):
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
                    if not checkFields(decryptedBody, ["realname", "username", "password", "securityKey"]):
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
                    
                    users.append({"UID": len(users), "USRNAME": username, "PWD": bcrypt.hashpw(password, bcrypt.gensalt(NUM_ENCRYPT_ROUNDS)).decode("utf-8"), "Displayname": username, "Birthday": None, "BirthdayV": "PRIVATE", "AccCreated": time.time(), "Pronouns": "", "Bio": "", "PFP": DEFAULT_PFPS[secrets.randbelow(len(DEFAULT_PFPS))], "Friends": [], "Chats": [0], "FriendRequests": []})
                    
                    RATELIMITED_IPS.append({"ip": ws.remote_address[0], "expire": time.time() + ACC_CREATION_COOLDOWN_SEC})
                    
                    await wsSendEncrypted(ws, orjson.dumps({"type": "signupSuccess", "redirect": "/signupSuccess.html"}))
                    
                    targetChat = None
                    for cht in chats:
                        if cht["CID"] == 0:
                            cht["Recipients"] = list(range(len(users)))
                            targetChat = cht
                    
                    if targetChat:
                        await wsBroadcastEncrypted(WS_CLIENTS, orjson.dumps({"type": "chatUpdate", "chat": targetChat}))

                
                if decryptedBody["type"] == "reqUser":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        userinfo = getUserInfoFromToken(authToken)

                        if userinfo is None:
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
                        if not checkFields(decryptedBody, ["CID"]):
                            await wsSendEncrypted(ws, orjson.dumps({"type": "reqChatMetaFailed", "message": "Request error. Please contact the server owner for help."}), trackerId)
                            continue

                        if not tokenInChat(authToken, decryptedBody["CID"]):
                            await wsSendEncrypted(ws, orjson.dumps({"type":"reqChatMetaFailed","message": "User not in chat!"}), trackerId)
                            continue

                        chat = getChatFromCID(decryptedBody["CID"])

                        if chat is None:
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
                        if not checkFields(decryptedBody, ["CID", "page"]):
                            await wsSendEncrypted(ws, orjson.dumps({"type": "reqChatFailed", "message": "Request error. Please contact the server owner for help."}), trackerId)
                            continue

                        if not tokenInChat(authToken, decryptedBody["CID"]):
                            await wsSendEncrypted(ws, orjson.dumps({"type":"reqChatFailed","message": "User not in chat!"}), trackerId)
                            continue

                        chat = getChatFromCID(decryptedBody["CID"])

                        if chat is None:
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
                
                if decryptedBody["type"] == "reqMsg":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        if not checkFields(decryptedBody, ["CID", "MSGID"]):
                            await wsSendEncrypted(ws, orjson.dumps({"type": "reqMsgFailed"}), trackerId)
                            continue

                        if not tokenInChat(authToken, decryptedBody["CID"]):
                            await wsSendEncrypted(ws, orjson.dumps({"type":"reqMsgFailed"}), trackerId)
                            continue

                        chat = getChatFromCID(decryptedBody["CID"])

                        if chat is None:
                            await wsSendEncrypted(ws, orjson.dumps({"type":"reqMsgFailed"}), trackerId)
                            continue
                        
                        targetMsg = None
                        for msg in chat["messages"]:
                            if msg["MSGID"] == decryptedBody["MSGID"]:
                                targetMsg = msg
                                break
                        
                        if targetMsg is None:
                            await wsSendEncrypted(ws, orjson.dumps({"type":"reqMsgFailed"}), trackerId)
                            continue

                        await wsSendEncrypted(ws, orjson.dumps({"type": "reqMsgSuccess", "msg": targetMsg}), trackerId)
                    else:
                        break

                if decryptedBody["type"] == "getEmbed":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        if not checkFields(decryptedBody, ["embedUrl"]):
                            await wsSendEncrypted(ws, orjson.dumps({"type": "getEmbedFailed"}), trackerId)
                            continue

                        filePath = CWD / decryptedBody["embedUrl"]

                        if not httphelper.isSafePath(filePath) or not filePath.exists():
                            await wsSendEncrypted(ws, orjson.dumps({"type": "getEmbedFailed"}), trackerId)
                            continue

                        fileType, e = mimetypes.guess_type(filePath)

                        fileContents = None
                        with open(filePath, "rb") as f:
                            fileContents = f.read()
                            f.close()

                        fileContentsDecoded = fernet.decrypt(fileContents)
                        encodedFile = base64.b64encode(fileContentsDecoded)
                        await wsSendEncrypted(ws, orjson.dumps({
                            "type": "getEmbedSuccess",
                            "embedContent": encodedFile.decode("utf-8"),
                            "embedType": fileType
                        }), trackerId)
                    else:
                        break
                
                if decryptedBody["type"] == "reqUsersList":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        if not checkFields(decryptedBody, ["users"]):
                            await wsSendEncrypted(ws, orjson.dumps({"type": "reqUsersListFailed"}), trackerId)
                            continue

                        userInfoList = []

                        for usr in decryptedBody["users"]:
                            userinfo = getUserInfoFromUserId(usr)

                            if userinfo is not None:
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
                        if not checkFields(decryptedBody, ["CID", "msg", "embed", "replyTo"]):
                            await wsSendEncrypted(ws, orjson.dumps({"type": "chatUpdateFailed"}), trackerId)
                            continue

                        if len(decryptedBody["msg"]) > 4000:
                            await wsSendEncrypted(ws, orjson.dumps({"type": "chatUpdateFailed"}), trackerId)
                            continue

                        if len(decryptedBody["embed"]) > 10:
                            await wsSendEncrypted(ws, orjson.dumps({"type": "chatUpdateFailed"}), trackerId)
                            continue

                        embedFilePaths = []
                        for embed in decryptedBody["embed"]:
                            embedC = embed["contents"]
                            embedName: str = embed["filename"].strip()

                            if len(embedName) <= 0 or len(embedName) > 128:
                                embedName = secrets.token_urlsafe(32)

                            if "," in embed["contents"]:
                                embedC = embed["contents"].split(",")[1]
                            
                            embedBytes = base64.b64decode(embedC)
                            uuid = ""
                            fNameSafe = base64.urlsafe_b64encode(embedName.encode("utf-8")).decode("utf-8")
                            fileType = mimetypes.guess_extension(embed["type"])

                            if fileType is None:
                                fileType = ".bin"

                            while True:
                                uuid = secrets.token_urlsafe(48)

                                if (CDN_DIR / f"{uuid}.{fNameSafe}{fileType}").exists():
                                    continue

                                with open(CDN_DIR / f"{uuid}.{fNameSafe}{fileType}", "wb") as f:
                                    f.write(fernet.encrypt(embedBytes))
                                    f.close()
                                
                                break
                            
                            embedFilePaths.append(str((CDN_DIR / f"{uuid}.{fNameSafe}{fileType}").resolve().relative_to(CWD)))
                        
                        chat = getChatFromCID(decryptedBody["CID"])

                        if chat is None:
                            await wsSendEncrypted(ws, orjson.dumps({"type": "chatUpdateFailed"}), trackerId)
                            continue

                        msgObj = {"time": int(time.time()), "content": decryptedBody["msg"], "embed": embedFilePaths, "replyTo": decryptedBody["replyTo"], "UID": getUserIdFromAuthToken(authToken), "MSGID": len(chat["messages"])}
                        chat["messages"].append(msgObj)

                        await wsSendEncrypted(ws, orjson.dumps({"type": "chatUpdateSuccess"}), trackerId)

                        broadcastClients = []
                        for client in WS_CLIENTS:
                            cAuthToken = getattr(client, "authToken")

                            if cAuthToken is None:
                                continue
                            
                            userInfo = getUserInfoFromToken(cAuthToken)

                            if userInfo is None:
                                continue
                            
                            if decryptedBody["CID"] in userInfo["Chats"]:
                                broadcastClients.append(client)
                        

                        await wsBroadcastEncrypted(broadcastClients, orjson.dumps({"type":"newMsg", "CID": chat["CID"], "message": msgObj}))
                    else:
                        break
                
                if decryptedBody["type"] == "delMsg":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        if not checkFields(decryptedBody, ["CID", "MSGID"]):
                            await wsSendEncrypted(ws, orjson.dumps({"type": "delMsgFailed"}), trackerId)
                            continue

                        chat = None
                        for cht in chats:
                            if cht["CID"] == decryptedBody["CID"]:
                                chat = cht
                                break

                        if chat is None or not tokenInChat(authToken, chat["CID"]):
                            await wsSendEncrypted(ws, orjson.dumps({"type": "delMsgFailed"}), trackerId)
                            continue
                        
                        message = None

                        for msg in chat["messages"]:
                            if msg["MSGID"] == decryptedBody["MSGID"]:
                                message = msg
                                break

                        if message is None or message["UID"] != getUserIdFromAuthToken(authToken):
                            await wsSendEncrypted(ws, orjson.dumps({"type": "delMsgFailed"}), trackerId)
                            continue

                        message["content"] = "[message deleted]"
                        message["embed"] = []
                        message["deleted"] = True

                        await wsSendEncrypted(ws, orjson.dumps({"type": "delMsgSuccess"}), trackerId)

                        broadcastClients = []
                        for client in WS_CLIENTS:
                            cAuthToken = getattr(client, "authToken")

                            if cAuthToken is None:
                                continue
                            
                            userInfo = getUserInfoFromToken(cAuthToken)

                            if userInfo is None:
                                continue
                            
                            if decryptedBody["CID"] in userInfo["Chats"]:
                                broadcastClients.append(client)

                        await wsBroadcastEncrypted(broadcastClients, orjson.dumps({"type":"chatUpdate", "chat": chat}))
                    else:
                        break
                
                if decryptedBody["type"] == "editMsg":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        if not checkFields(decryptedBody, ["CID", "MSGID", "new"]):
                            await wsSendEncrypted(ws, orjson.dumps({"type": "editMsgFailed"}), trackerId)
                            continue

                        chat = None
                        for cht in chats:
                            if cht["CID"] == decryptedBody["CID"]:
                                chat = cht

                        if chat is None or not tokenInChat(authToken, chat["CID"]):
                            await wsSendEncrypted(ws, orjson.dumps({"type": "editMsgFailed"}), trackerId)
                            continue

                        message = None
                        for msg in chat["messages"]:
                            if msg["MSGID"] == decryptedBody["MSGID"]:
                                message = msg
                        
                        if message is None or message["UID"] != getUserIdFromAuthToken(authToken):
                            await wsSendEncrypted(ws, orjson.dumps({"type": "editMsgFailed"}), trackerId)
                            continue

                        message["content"] = decryptedBody["new"].strip()
                        message["edited"] = True

                        await wsSendEncrypted(ws, orjson.dumps({"type": "editMsgSuccess"}), trackerId)

                        broadcastClients = []
                        for client in WS_CLIENTS:
                            cAuthToken = getattr(client, "authToken")

                            if cAuthToken is None:
                                continue
                            
                            userInfo = getUserInfoFromToken(cAuthToken)

                            if userInfo is None:
                                continue
                            
                            if decryptedBody["CID"] in userInfo["Chats"]:
                                broadcastClients.append(client)

                        await wsBroadcastEncrypted(broadcastClients, orjson.dumps({"type":"chatUpdate", "chat": chat}))
                    else:
                        break

                if decryptedBody["type"] == "updateDisplayname":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        if not checkFields(decryptedBody, ["displayname"]):
                            await wsSendEncrypted(ws, orjson.dumps({"type":"updateDisplaynameFailed"}), trackerId)
                            continue

                        dn = decryptedBody["displayname"].strip()

                        if dn == "":
                            await wsSendEncrypted(ws, orjson.dumps({"type":"updateDisplaynameFailed"}), trackerId)
                            continue

                        if len(dn) > 30:
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
                        if not checkFields(decryptedBody, ["bd"]):
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
                        if not checkFields(decryptedBody, ["pronoun"]):
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
                        if not checkFields(decryptedBody, ["pfp"]):
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
                        if not checkFields(decryptedBody, ["bio"]):
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
                        if not checkFields(decryptedBody, ["unameSearch"]):
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

                        if not checkFields(decryptedBody, ["UID"]):
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
                            if wsUID is not None and wsUID == targetUID:
                                await wsSendEncrypted(ws2, orjson.dumps({"type": "updateFriendReqs", "friendReqs": targetFriendReqs}))
                                break
                    else:
                        break
                
                if decryptedBody["type"] == "cancelFriendReq":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        if not checkFields(decryptedBody, ["UID"]):
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
                            if wsUID is not None and wsUID == targetUID:
                                await wsSendEncrypted(ws2, orjson.dumps({"type": "updateFriendReqs", "friendReqs": targetFriendReqs}))
                                break
                    else:
                        break

                if decryptedBody["type"] == "declineFriendReq":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        if not checkFields(decryptedBody, ["UID"]):
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
                            if wsUID is not None and wsUID == targetUID:
                                await wsSendEncrypted(ws2, orjson.dumps({"type": "updateFriendReqs", "friendReqs": targetFriendReqs}))
                                break
                    else:
                        break

                if decryptedBody["type"] == "acceptFriendReq":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        if not checkFields(decryptedBody, ["UID"]):
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
                            if wsUID is not None and wsUID == targetUID:
                                await wsSendEncrypted(ws2, orjson.dumps({"type": "updateFriends", "friendReqs": targetFriendReqs, "friends": targetInfo["Friends"], "chats": targetInfo["Chats"]}))
                                break
                    else:
                        break

                continue
            

    except Exception:
        traceback.print_exc()
    finally:
        WS_CLIENTS.remove(ws)

async def shutdownWs(shutdownEvent: asyncio.Event, future: Future, shutdownEventDone: asyncio.Event):
    shutdownEvent.set()

    for ws in copy.copy(WS_CLIENTS):
        try:
            await asyncio.wait_for(ws.close(), 5)
            WS_CLIENTS.remove(ws)
        except TimeoutError:
            pass
        except Exception:
            logging.warning("Error when disconnecting client ws!", stack_info=True)
    
    await shutdownEventDone.wait()

    asyncio.get_running_loop().stop()

async def wsListen(ipAddrs: list, context: ssl.SSLContext, shutdownEvent: asyncio.Event, shutdownEventDone: asyncio.Event):
    servers = []

    for addr in ipAddrs:
        servers.append(serve(wsHandler, addr, WSS_PORT, max_size=(25*1024*1024 * 11), ssl=context, process_request=getAuth))
        logging.debug("[WS] wss://%s:%i", addr, WSS_PORT)
        servers.append(serve(wsHandler, addr, WS_PORT, max_size=(25*1024*1024 * 11), process_request=getAuth))
        logging.debug("[WS] ws://%s:%i", addr, WS_PORT)

    logging.info("[WS] Websockets running")
    
    await asyncio.gather(*servers, shutdownEvent.wait())
    logging.info("[WS] Websocket exited")
    shutdownEventDone.set()

def wsBootstrap(loop: asyncio.AbstractEventLoop):
    logging.info("[WS] Websocket Bootstrap")
    asyncio.set_event_loop(loop)
    loop.run_forever()

async def autosave(shutdownEvent: asyncio.Event, shutdownEventDone: asyncio.Event):
    try:
        while True:
            try:
                await asyncio.wait_for(asyncio.shield(shutdownEvent.wait()), AUTOSAVE_INTERVAL_SEC)
                break
            except asyncio.TimeoutError:
                logging.debug("[AS] The current time is %s", datetime.datetime.now().strftime("%b %d, %Y at %I:%M %p"))
                logging.debug("[AS] Autosaving...")
                saveUsers()
                saveChats()
                logging.debug("[AS] Autosave done")
    except asyncio.CancelledError:
        pass

    logging.info("[AS] Autosave thread exited")
    shutdownEventDone.set()

async def shutdownAutosave(shutdownEvent: asyncio.Event, future: Future, shutdownEventDone: asyncio.Event):
    logging.info("[AS] Stopping autosaves!")
    shutdownEvent.set()

    await shutdownEventDone.wait()

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
        format="%(asctime)s [%(filename)s] [%(levelname)s]: %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(LOG_DIR / f"{datetime.datetime.now().strftime("%Y-%m-%d %H-%M-%S")}.log")
        ]
    )

    logging.info("[MAIN] Open-LAN v%s-%s %s initalizing!", VER, STAGE, "(DEV)" if DEV else "")

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
    
    ipAddrs = httphelper.getIpAddrs()
    
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
        logging.info("[MAIN] Listening on %s:%i", addr, PORT)
    
    logging.debug("[MAIN] It's time to get async")

    wsLoop = asyncio.new_event_loop()
    wsShutdownEvent = asyncio.Event()
    wsShutdownEventDone = asyncio.Event()
    wsThread = threading.Thread(target=wsBootstrap, args=(wsLoop,), daemon=True)
    wsThread.start()

    wsFuture = asyncio.run_coroutine_threadsafe(wsListen(ipAddrs, context, wsShutdownEvent, wsShutdownEventDone), wsLoop)

    autosaveLoop = asyncio.new_event_loop()
    autosaveShutdownEvent = asyncio.Event()
    autosaveShutdownEventDone = asyncio.Event()
    autosaveThread = threading.Thread(target=autosaveBootstrap, args=(autosaveLoop,), daemon=True)
    autosaveThread.start()

    autosaveFuture = asyncio.run_coroutine_threadsafe(autosave(autosaveShutdownEvent, autosaveShutdownEventDone), autosaveLoop)

    logging.debug("[MAIN] HTTP Primed and ready to go")
    logging.info("[MAIN] Connect via:")

    for addr in ipAddrs:
        logging.info("[MAIN] http://%s:%i/", addr, PORT)
        logging.info("[MAIN] https://%s:%i/", addr, PORT)
    
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
                        logging.warning("[MAIN] SSL Handshake failure: %s", e)
                    except Exception as e:
                        logging.error("[MAIN] Error handling connection: %s", e)
                elif peekBytes in (b'GET', b'POS', b'PUT', b'DEL', b'HEA', b'OPT'):
                    handleRequest(cSocket)
                else:
                    logging.warning("[MAIN] Unknown Protocol. Bytes: %s", peekBytes)
                
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
                logging.warning("[MAIN] Attempting to recover (%i)", numErr)
            else:
                logging.fatal("[MAIN] Max Retry Attempts Exceeded")
                break
    
    logging.info("[MAIN] Shutting down Websocket thread (10s)")
    asyncio.run_coroutine_threadsafe(shutdownWs(wsShutdownEvent, wsFuture, wsShutdownEventDone), loop=wsLoop)
    wsThread.join(10)

    if wsThread.is_alive():
        logging.warning("[MAIN] Forcibly shutting down Websocket thread!")
        wsLoop.close()

    logging.info("[MAIN] Shutting down autosave thread (10s)")
    asyncio.run_coroutine_threadsafe(shutdownAutosave(autosaveShutdownEvent, autosaveFuture, autosaveShutdownEventDone), loop=autosaveLoop)
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
