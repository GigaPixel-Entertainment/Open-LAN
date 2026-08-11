from collections.abc import Iterable, Callable
from http import cookies
import mimetypes
import traceback
import logging
import secrets
import random
import asyncio
import base64
import time
import copy
import math
import ssl

from websockets.asyncio.server import serve, ServerConnection, Request

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet

import orjson
import bcrypt

import config
import httphelper

class WS():
    def __init__(self, validTokens: dict, redirTokens: dict, defaultPfps: list, chats: list, users: list, servers: list, invites: list, fernet: Fernet, resizePfpBytes: Callable) -> None:
        self.VALID_TOKENS: dict = validTokens
        self.SHORT_REDIRECT_TOKENS: dict = redirTokens
        self.DEFAULT_PFPS: list[str] = defaultPfps
        self.chats: list[dict] = chats
        self.users: list[dict] = users
        self.servers: list[dict] = servers
        self.invites: list[dict] = invites
        self.fernet: Fernet = fernet

        self.resizePfpBytes: Callable = resizePfpBytes

        self.WS_CLIENTS: set[ServerConnection] = set()
        self.RATELIMITED_IPS: list[dict] = []
        self.DUMMY_HASH: bytes = bcrypt.hashpw(b"DUMMY_PW", bcrypt.gensalt(config.NUM_ENCRYPT_ROUNDS))
        self.PRIV_KEY = ec.generate_private_key(ec.SECP256R1())
        self.PUB_KEY = self.PRIV_KEY.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

        mimetypes.add_type("application/java-archive", ".jar")
        mimetypes.add_type("text/plain", ".log")
        mimetypes.add_type("application/x-sh", ".sh")

    def isValidToken(self, authToken: str | None, username=None):
        if authToken is None:
            return False

        if username:
            if username not in self.VALID_TOKENS:
                return False

            if "EXPIRES" in self.VALID_TOKENS[username] and self.VALID_TOKENS[username]["EXPIRES"] < time.time():
                self.VALID_TOKENS.pop(username, None)
                return False

            if "TOKEN" in self.VALID_TOKENS[username] and self.VALID_TOKENS[username]["TOKEN"] == authToken:
                return True
        else:
            for key, value in self.VALID_TOKENS.items():
                if "TOKEN" in value and value["TOKEN"] == authToken:
                    if "EXPIRES" in value and value["EXPIRES"] < time.time():
                        self.VALID_TOKENS.pop(key, None)
                        return False

                    return True

        return False

    def isValidB64(self, b64: str) -> bool:
        try:
            base64.b64decode(b64, validate=True)
            return True
        except:
            return False

    def getUsernameFromAuthToken(self, token: str | None) -> str | None:
        for username, tk in self.VALID_TOKENS.items():
            if tk["TOKEN"] == token:
                return username

        return None

    def getUserIdFromAuthToken(self, token: str | None) -> int | None:
        userInfo = self.getUserInfoFromToken(token)

        if userInfo is None:
            return None

        return userInfo["UID"]

    def getUserInfoFromUserId(self, UID: int) -> dict | None:
        for user in self.users:
            if user["UID"] == UID:
                return user
        return None

    def getUserInfoFromUsername(self, username: str) -> dict | None:
        for user in self.users:
            if user["USRNAME"] == username:
                return user

        return None

    def getUserInfoFromToken(self, token: str | None) -> dict | None:
        username = self.getUsernameFromAuthToken(token)

        if username is None:
            return None

        return self.getUserInfoFromUsername(username)

    def getUserIdFromUserInfo(self, userInfo: dict | None) -> dict | None:
        if userInfo is None:
            return None

        return userInfo["UID"]

    def getChatFromCID(self, CID: int) -> dict | None:
        for chat in self.chats:
            if chat["CID"] == CID:
                return chat

        return None

    def getServerFromSID(self, SID: int) -> dict | None:
        for server in self.servers:
            if server["SID"] == SID:
                return server

        return None

    def setUserProperty(self, UID: int | None, propertyName: str, value) -> bool:
        if UID is None:
            return False

        success = False
        for usr in self.users:
            if usr["UID"] == UID:
                usr[propertyName] = value
                success = True
                break

        return success

    def tokenInChat(self, token: str | None, CID: int) -> bool:
        if CID < 0 or CID >= len(self.chats):
            return False

        chat = self.getChatFromCID(CID)

        if chat is None:
            return False

        if "Server" in chat and chat["Server"] != -1:
            return self.tokenInServer(token, chat["Server"])

        userInfo = self.getUserInfoFromToken(token)

        if userInfo is None:
            return False

        if not CID in userInfo["Chats"]:
            return False

        return True

    def tokenInServer(self, token: str | None, SID: int) -> bool:
        if SID < 0 or SID >= len(self.servers):
            return False

        server = self.getServerFromSID(SID)

        if server is None:
            return False

        userInfo = self.getUserInfoFromToken(token)

        if userInfo is None:
            return False

        if not SID in userInfo["Servers"]:
            return False

        return True


    def validateUsername(self, username: str):
        return username.replace("_", "").isalnum() and username.isascii() and len(username) >= 3 and len(username) <= 30

    def checkFields(self, obj: dict, fields: list[str]):
        for field in fields:
            if not field in obj:
                return False

        return True

    def resizePfp(self, pfp: str):
        if "," in pfp:
            pfp = pfp.split(",")[1]

        if not self.isValidB64(pfp):
            return random.choice(self.DEFAULT_PFPS)

        pfpBytes = base64.b64decode(pfp)
        return self.resizePfpBytes(pfpBytes)

    def delChat(self, chat: dict):
        chat["messages"] = []
        chat["Name"] = "deleted"
        chat["Icon"] = config.EMPTY_IMG
        chat["Owner"] = -1
        chat["Type"] = ""
        chat["Server"] = -1
        chat["Time"] = 0
        chat["Recipients"] = []

    def delServer(self, server: dict):
        server["Owner"] = -1
        server["Users"] = []
        server["Name"] = "deleted"
        server["Icon"] = config.EMPTY_IMG

        try:
            for cate in server["Categories"]:
                for cht in cate["Chats"]:
                    self.delChat(cht)
        except:
            pass

        server["Categories"] = []
        server["AnnouncementChat"] = -1

    async def checkInviteValid(self, inviteID: str) -> tuple[bool, dict | None]:
        valid = False
        targetServer = None

        for inv in self.invites:
            if inv["ID"] == inviteID:
                targetServer = self.getServerFromSID(inv["SID"])

                valid = True
                if targetServer is None:
                    valid = False
                elif inv["EXPIRE"] - int(time.time()) < 0:
                    valid = False
                elif not inv["BY"] in targetServer["Users"]:
                    valid = False

                break

        return (valid, targetServer)


    async def wsSendEncrypted(self, ws: ServerConnection, data: bytes, trackerId: int | None=None):
        if trackerId is not None:
            dataParsed = orjson.loads(data)
            dataParsed["trackerID"] = trackerId
            data = orjson.dumps(dataParsed)

        iv = secrets.token_bytes(12)
        encryptor = Cipher(algorithms.AES256(getattr(ws, "secretKey")), modes.GCM(iv)).encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize() + encryptor.tag

        await ws.send(orjson.dumps({"encryption":"AES","iv":iv.hex(),"body":ciphertext.hex()}), text=True)

    async def wsBroadcastEncrypted(self, clients: Iterable[ServerConnection], data: bytes):
        for client in clients:
            try:
                await self.wsSendEncrypted(client, data)
            except:
                traceback.print_exc()

    async def checkAuthTokenEncrypted(self, ws: ServerConnection, authToken: str | None):
        if not self.isValidToken(authToken):
            await self.wsSendEncrypted(ws, orjson.dumps({"type":"auth_expired"}))
            await ws.close()
            return False
        return True

    async def handleEncryption(self, ws: ServerConnection, msgDecoded: dict):
        clientKey = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            bytes.fromhex(msgDecoded["publicKey"])
        )

        setattr(ws, "secretKey", self.PRIV_KEY.exchange(ec.ECDH(), clientKey))

        await ws.send(orjson.dumps({"type":"encrypt-key-xch", "publicKey": self.PUB_KEY.hex()}), text=True)

    async def decrypt(self, ws: ServerConnection, msgDecoded: dict) -> tuple[dict, int] | tuple[None, None]:
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

    async def wsHandler(self, ws: ServerConnection):
        self.WS_CLIENTS.add(ws)

        try:
            authToken: str | None = getattr(ws, "authToken", None)

            if authToken:
                setattr(ws, "UID", self.getUserIdFromAuthToken(authToken))

            async for message in ws:
                msgDecoded = orjson.loads(message)

                if "type" in msgDecoded and msgDecoded["type"] == "encrypt-key-xch":
                    await self.handleEncryption(ws, msgDecoded)
                    continue

                if "encryption" in msgDecoded and msgDecoded["encryption"] == "AES":
                    decryptedBody, trackerId = await self.decrypt(ws, msgDecoded)

                    if decryptedBody is None or not self.checkFields(decryptedBody, ["type"]):
                        await self.wsSendEncrypted(ws, orjson.dumps({"type": "unknownRequest"}), trackerId)
                        continue

                    if decryptedBody["type"] == "login":
                        if not self.checkFields(decryptedBody, ["username", "password"]):
                            await self.wsSendEncrypted(ws, orjson.dumps({"type": "loginFailed"}))
                            continue

                        if not self.validateUsername(decryptedBody["username"]):
                            await self.wsSendEncrypted(ws, orjson.dumps({"type": "loginFailed"}))
                            continue

                        found = False

                        usrPwd = base64.b64decode(decryptedBody["password"])

                        for usr in self.users:
                            if usr["USRNAME"] == decryptedBody["username"]:
                                if bcrypt.checkpw(usrPwd, usr["PWD"].encode("utf-8")):
                                    token = secrets.token_urlsafe(32)
                                    self.SHORT_REDIRECT_TOKENS[usr["USRNAME"]] = {"TOKEN":token,"EXPIRES": time.time() + config.REDIRECT_TOKEN_EXPIRES_SEC}
                                    await self.wsSendEncrypted(ws, orjson.dumps({"type":"loginSuccess","redirect":f"/api/login?TK={token}"}))
                                    found = True
                                else:
                                    await self.wsSendEncrypted(ws, orjson.dumps({"type":"loginFailed"}))
                                    found = True
                                break

                        if not found:
                            bcrypt.checkpw(usrPwd, self.DUMMY_HASH)
                            await self.wsSendEncrypted(ws, data=orjson.dumps({"type":"loginFailed"}))

                    if decryptedBody["type"] == "signup":
                        if not self.checkFields(decryptedBody, ["realname", "username", "password", "securityKey"]):
                            await self.wsSendEncrypted(ws, orjson.dumps({"type": "signupFailed", "reason": "Request error. Please contact the server owner for help."}))
                            continue

                        allowed = True

                        for ip in copy.copy(self.RATELIMITED_IPS):
                            if ip["ip"] == ws.remote_address[0]:
                                if ip["expire"] > time.time():
                                    allowed = False
                                else:
                                    self.RATELIMITED_IPS.remove(ip)

                        if not allowed:
                            await self.wsSendEncrypted(ws, orjson.dumps({"type": "signupFailed", "reason": f"You have been ratelimited. Please try again in {int(config.ACC_CREATION_COOLDOWN_SEC / 60)} minutes."}))
                            continue

                        name = decryptedBody["realname"].strip()
                        username = decryptedBody["username"].strip()
                        password = base64.b64decode(decryptedBody["password"])
                        securityKey = decryptedBody["securityKey"]

                        if not self.validateUsername(username):
                            await self.wsSendEncrypted(ws, orjson.dumps({"type": "signupFailed", "reason": "Username must only contain uppercase, lowercase, numbers, and underscores. It must also be at least 3 characters."}))
                            continue

                        allowed = True
                        for usr in self.users:
                            if usr["USRNAME"] == username:
                                allowed = False

                        if not allowed:
                            await self.wsSendEncrypted(ws, orjson.dumps({"type": "signupFailed", "reason": "That username is already in use!"}))
                            continue

                        with open(config.SECURITY_DIR / f"{username}.sq", "wb") as f:
                            f.write(self.fernet.encrypt(orjson.dumps({"name": name, "username": username, "secQ": securityKey})))
                            f.close()

                        uid = len(self.users)
                        self.users.append({"UID": uid, "USRNAME": username, "PWD": bcrypt.hashpw(password, bcrypt.gensalt(config.NUM_ENCRYPT_ROUNDS)).decode("utf-8"), "Displayname": username, "Birthday": None, "BirthdayV": "PRIVATE", "AccCreated": time.time(), "Pronouns": "", "Bio": "", "PFP": self.DEFAULT_PFPS[secrets.randbelow(len(self.DEFAULT_PFPS))], "Friends": [], "Chats": [0], "FriendRequests": [], "ReadMsgs": {"0": 0}, "Servers": []})

                        chat0 = None
                        for cht in self.chats:
                            if cht["CID"] == 0:
                                cht["Recipients"].append(uid)
                                chat0 = cht
                                break

                        for ws2 in self.WS_CLIENTS:
                            wsUID = getattr(ws2, "UID", None)
                            targetInfo = self.getUserInfoFromUserId(wsUID)

                            if wsUID is not None and wsUID in chat0["Recipients"]:
                                await self.wsSendEncrypted(ws2, orjson.dumps({"type": "chatUpdate", "chat": chat0}))

                        self.RATELIMITED_IPS.append({"ip": ws.remote_address[0], "expire": time.time() + config.ACC_CREATION_COOLDOWN_SEC})

                        await self.wsSendEncrypted(ws, orjson.dumps({"type": "signupSuccess", "redirect": "/signupSuccess.html"}))

                    if decryptedBody["type"] == "reqUser":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            userinfo = self.getUserInfoFromToken(authToken)

                            if userinfo is None:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type":"reqUserFailed", "message": "User not found!"}), trackerId)
                                continue

                            await self.wsSendEncrypted(ws, orjson.dumps({
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
                                "friendReq": userinfo["FriendRequests"],
                                "readMsgs": userinfo["ReadMsgs"],
                                "servers": userinfo["Servers"]
                            }), trackerId)
                        else:
                            break

                    if decryptedBody["type"] == "reqChatMeta":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["CID"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "reqChatMetaFailed", "message": "Request error. Please contact the server owner for help."}), trackerId)
                                continue

                            if not self.tokenInChat(authToken, decryptedBody["CID"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type":"reqChatMetaFailed","message": "User not in chat!"}), trackerId)
                                continue

                            chat = self.getChatFromCID(decryptedBody["CID"])

                            if chat is None:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type":"reqChatMetaFailed","message":"Chat not found!"}), trackerId)
                                continue

                            lastMsg = chat["messages"][-1] if len(chat["messages"]) > 0 else None
                            lastRealMsg = None
                            for msg in chat["messages"]:
                                if not "SYSMSG" in msg and not "deleted" in msg:
                                    lastRealMsg = msg

                            await self.wsSendEncrypted(ws, orjson.dumps({"type":"reqChatMetaSuccess", "chat": {
                                "CID": chat["CID"],
                                "type": chat["Type"],
                                "name": chat["Name"],
                                "icon": chat["Icon"] if "Icon" in chat else random.choice(self.DEFAULT_PFPS),
                                "recipients": chat["Recipients"],
                                "lastMsg": {
                                    "time": lastMsg["time"] if lastMsg else chat["Time"],
                                    "MSGID": lastMsg["MSGID"] if lastMsg else 0,
                                    "content": lastRealMsg["content"] if lastRealMsg else ""
                                }
                            }}), trackerId)
                        else:
                            break

                    if decryptedBody["type"] == "reqChat":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["CID", "page"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "reqChatFailed", "message": "Request error. Please contact the server owner for help."}), trackerId)
                                continue

                            if not self.tokenInChat(authToken, decryptedBody["CID"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type":"reqChatFailed","message": "User not in chat!"}), trackerId)
                                continue

                            chat = self.getChatFromCID(decryptedBody["CID"])

                            if chat is None:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type":"reqChatFailed","message":"Chat not found!"}), trackerId)
                                continue

                            pagedChat = copy.deepcopy(chat)

                            if decryptedBody["page"] == 0:
                                pagedChat["messages"] = pagedChat["messages"][-100:]
                            else:
                                pagedChat["messages"] = pagedChat["messages"][-100 * (decryptedBody["page"] + 1):-100 * decryptedBody["page"]]

                            await self.wsSendEncrypted(ws, orjson.dumps({"type":"reqChatSuccess", "chat": pagedChat, "numPages": math.ceil(len(chat["messages"]) / 100 + 0.005) - 1}), trackerId)
                        else:
                            break

                    if decryptedBody["type"] == "reqMsg":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["CID", "MSGID"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "reqMsgFailed"}), trackerId)
                                continue

                            if not self.tokenInChat(authToken, decryptedBody["CID"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type":"reqMsgFailed"}), trackerId)
                                continue

                            chat = self.getChatFromCID(decryptedBody["CID"])

                            if chat is None:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type":"reqMsgFailed"}), trackerId)
                                continue

                            targetMsg = None
                            for msg in chat["messages"]:
                                if msg["MSGID"] == decryptedBody["MSGID"]:
                                    targetMsg = msg
                                    break

                            if targetMsg is None:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type":"reqMsgFailed"}), trackerId)
                                continue

                            await self.wsSendEncrypted(ws, orjson.dumps({"type": "reqMsgSuccess", "msg": targetMsg}), trackerId)
                        else:
                            break

                    if decryptedBody["type"] == "getEmbed":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["embedUrl"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "getEmbedFailed"}), trackerId)
                                continue

                            filePath = config.CWD / decryptedBody["embedUrl"]

                            if not httphelper.isSafePath(filePath) or not filePath.exists():
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "getEmbedFailed"}), trackerId)
                                continue

                            fileType, _ = mimetypes.guess_file_type(filePath, strict=False)

                            await self.wsSendEncrypted(ws, orjson.dumps({
                                "type": "getEmbedSuccess",
                                "embedType": fileType
                            }), trackerId)
                        else:
                            break

                    if decryptedBody["type"] == "reqUsersList":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["users"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "reqUsersListFailed"}), trackerId)
                                continue

                            userInfoList = []

                            for usr in decryptedBody["users"]:
                                userinfo = self.getUserInfoFromUserId(usr)

                                if userinfo is not None:
                                    userInfoList.append({
                                        "username": userinfo["USRNAME"],
                                        "UID": userinfo["UID"],
                                        "pfp": userinfo["PFP"],
                                        "displayname": userinfo["Displayname"],
                                        "bio": userinfo["Bio"],
                                        "pronouns": userinfo["Pronouns"]
                                    })

                            await self.wsSendEncrypted(ws, orjson.dumps({"type":"reqUsersListSuccess", "users":userInfoList}), trackerId)
                        else:
                            break

                    if decryptedBody["type"] == "sendMsg":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["CID", "msg", "embed", "replyTo"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "chatUpdateFailed"}), trackerId)
                                continue

                            if not self.tokenInChat(authToken, decryptedBody["CID"]) or len(decryptedBody["msg"]) > 4000 or len(decryptedBody["embed"]) > 10:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "chatUpdateFailed"}), trackerId)
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
                                fileType = mimetypes.guess_extension(embed["type"], strict=False)

                                if fileType is None:
                                    fileType = ".bin"

                                while True:
                                    uuid = secrets.token_urlsafe(48)

                                    if (config.CDN_DIR / f"{uuid}.{fNameSafe}{fileType}").exists():
                                        continue

                                    with open(config.CDN_DIR / f"{uuid}.{fNameSafe}{fileType}", "wb") as f:
                                        f.write(self.fernet.encrypt(embedBytes))
                                        f.close()

                                    break

                                embedFilePaths.append(str((config.CDN_DIR / f"{uuid}.{fNameSafe}{fileType}").resolve().relative_to(config.CWD)))

                            chat = self.getChatFromCID(decryptedBody["CID"])

                            if chat is None:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "chatUpdateFailed"}), trackerId)
                                continue

                            msgObj = {"time": int(time.time()), "content": decryptedBody["msg"], "embed": embedFilePaths, "replyTo": decryptedBody["replyTo"], "UID": self.getUserIdFromAuthToken(authToken), "MSGID": len(chat["messages"])}
                            chat["messages"].append(msgObj)

                            await self.wsSendEncrypted(ws, orjson.dumps({"type": "chatUpdateSuccess"}), trackerId)

                            broadcastClients = []
                            for client in self.WS_CLIENTS:
                                cAuthToken = getattr(client, "authToken", None)

                                if cAuthToken is None:
                                    continue

                                if self.tokenInChat(cAuthToken, decryptedBody["CID"]):
                                    broadcastClients.append(client)

                            await self.wsBroadcastEncrypted(broadcastClients, orjson.dumps({"type":"newMsg", "CID": chat["CID"], "message": msgObj}))
                        else:
                            break

                    if decryptedBody["type"] == "delMsg":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["CID", "MSGID"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "delMsgFailed"}), trackerId)
                                continue

                            chat = None
                            for cht in self.chats:
                                if cht["CID"] == decryptedBody["CID"]:
                                    chat = cht
                                    break

                            if chat is None or not self.tokenInChat(authToken, chat["CID"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "delMsgFailed"}), trackerId)
                                continue

                            message = None

                            for msg in chat["messages"]:
                                if msg["MSGID"] == decryptedBody["MSGID"]:
                                    message = msg
                                    break

                            if message is None or message["UID"] != self.getUserIdFromAuthToken(authToken):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "delMsgFailed"}), trackerId)
                                continue

                            message["content"] = "[message deleted]"
                            message["embed"] = []
                            message["deleted"] = True

                            await self.wsSendEncrypted(ws, orjson.dumps({"type": "delMsgSuccess"}), trackerId)

                            broadcastClients = []
                            for client in self.WS_CLIENTS:
                                cAuthToken = getattr(client, "authToken", None)

                                if cAuthToken is None:
                                    continue

                                if self.tokenInChat(cAuthToken, decryptedBody["CID"]):
                                    broadcastClients.append(client)

                            await self.wsBroadcastEncrypted(broadcastClients, orjson.dumps({"type":"metaChatUpdate", "chat": chat}))
                        else:
                            break

                    if decryptedBody["type"] == "editMsg":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["CID", "MSGID", "new"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "editMsgFailed"}), trackerId)
                                continue

                            chat = None
                            for cht in self.chats:
                                if cht["CID"] == decryptedBody["CID"]:
                                    chat = cht

                            if chat is None or not self.tokenInChat(authToken, chat["CID"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "editMsgFailed"}), trackerId)
                                continue

                            message = None
                            for msg in chat["messages"]:
                                if msg["MSGID"] == decryptedBody["MSGID"]:
                                    message = msg

                            if message is None or message["UID"] != self.getUserIdFromAuthToken(authToken):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "editMsgFailed"}), trackerId)
                                continue

                            message["content"] = decryptedBody["new"].strip()
                            message["edited"] = True

                            await self.wsSendEncrypted(ws, orjson.dumps({"type": "editMsgSuccess"}), trackerId)

                            broadcastClients = []
                            for client in self.WS_CLIENTS:
                                cAuthToken = getattr(client, "authToken", None)

                                if cAuthToken is None:
                                    continue

                                if self.tokenInChat(cAuthToken, decryptedBody["CID"]):
                                    broadcastClients.append(client)

                            await self.wsBroadcastEncrypted(broadcastClients, orjson.dumps({"type":"metaChatUpdate", "chat": chat}))
                        else:
                            break

                    if decryptedBody["type"] == "updateDisplayname":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["displayname"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type":"updateDisplaynameFailed"}), trackerId)
                                continue

                            dn = decryptedBody["displayname"].strip()

                            if dn == "":
                                await self.wsSendEncrypted(ws, orjson.dumps({"type":"updateDisplaynameFailed"}), trackerId)
                                continue

                            if len(dn) > 30:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type":"updateDisplaynameFailed"}), trackerId)
                                continue

                            if not self.setUserProperty(self.getUserIdFromAuthToken(authToken), "Displayname", dn):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type":"updateDisplaynameFailed"}), trackerId)
                                continue

                            await self.wsSendEncrypted(ws, orjson.dumps({"type":"updateDisplaynameSuccess"}), trackerId)
                            await self.wsBroadcastEncrypted(self.WS_CLIENTS, orjson.dumps({"type":"updateCachedDisplayname", "UID": self.getUserIdFromAuthToken(authToken), "Displayname": dn}))
                        else:
                            break

                    if decryptedBody["type"] == "updateBirthday":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["bd"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type":"updateBirthdayFailed"}), trackerId)
                                continue

                            bDay = decryptedBody["bd"]

                            if not self.setUserProperty(self.getUserIdFromAuthToken(authToken), "Birthday", bDay):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "updateBirthdayFailed"}), trackerId)
                                continue

                            await self.wsSendEncrypted(ws, orjson.dumps({"type": "updateBirthdaySuccess"}), trackerId)
                        else:
                            break

                    if decryptedBody["type"] == "updatePronoun":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["pronoun"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type":"updatePronounFailed"}), trackerId)
                                continue

                            pronouns = decryptedBody["pronoun"]

                            if not self.setUserProperty(self.getUserIdFromAuthToken(authToken), "Pronouns", pronouns):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "updatePronounFailed"}), trackerId)
                                continue

                            await self.wsSendEncrypted(ws, orjson.dumps({"type": "updatePronounSuccess"}), trackerId)
                            await self.wsBroadcastEncrypted(self.WS_CLIENTS, data=orjson.dumps({"type": "updateCachedPronouns", "UID": self.getUserIdFromAuthToken(authToken), "Pronouns": pronouns}))
                        else:
                            break

                    if decryptedBody["type"] == "updatePfp":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["pfp"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type":"updatePfpFailed"}), trackerId)
                                continue

                            pfp = decryptedBody["pfp"]
                            pfpResized = self.resizePfp(pfp)

                            if not self.setUserProperty(self.getUserIdFromAuthToken(authToken), "PFP", pfpResized):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "updatePfpFailed"}), trackerId)
                                continue

                            await self.wsSendEncrypted(ws, orjson.dumps({"type": "updatePfpSuccess"}), trackerId)
                            await self.wsBroadcastEncrypted(self.WS_CLIENTS, orjson.dumps({"type": "updateCachedPfp", "UID": self.getUserIdFromAuthToken(authToken), "PFP": pfpResized}))
                        else:
                            break

                    if decryptedBody["type"] == "updateBio":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["bio"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type":"updateBioFailed"}), trackerId)
                                continue

                            bio = decryptedBody["bio"]

                            if len(bio) > 1000:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type":"updateBioFailed"}), trackerId)
                                continue

                            if not self.setUserProperty(self.getUserIdFromAuthToken(authToken), "Bio", bio):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "updateBioFailed"}), trackerId)
                                continue

                            await self.wsSendEncrypted(ws, orjson.dumps({"type": "updateBioSuccess"}), trackerId)
                            await self.wsBroadcastEncrypted(self.WS_CLIENTS, data=orjson.dumps({"type": "updateCachedBio", "UID": self.getUserIdFromAuthToken(authToken), "Bio": bio}))
                        else:
                            break

                    if decryptedBody["type"] == "logout":
                        usrName = self.getUsernameFromAuthToken(authToken)

                        if usrName:
                            self.VALID_TOKENS.pop(usrName, None)

                        await self.wsSendEncrypted(ws, orjson.dumps({"type": "logoutSuccess"}))
                        await ws.close()
                        break

                    if decryptedBody["type"] == "userSearch":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["unameSearch"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "userSearchFailed"}), trackerId)
                                continue

                            usernameS = decryptedBody["unameSearch"].strip()

                            if not self.validateUsername(usernameS):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "userSearchFailed"}), trackerId)
                                continue

                            results = []
                            for usr in self.users:
                                if usernameS.lower() in usr["USRNAME"].lower():
                                    results.append(usr)

                            if len(results) == 0:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "userSearchFailed"}), trackerId)
                                continue

                            final = []

                            for res in results:
                                final.append({
                                    "displayname": res["Displayname"],
                                    "username": res["USRNAME"],
                                    "pfp": res["PFP"],
                                    "UID": res["UID"]
                                })

                            await self.wsSendEncrypted(ws, orjson.dumps({
                                "type": "userSearchSuccess",
                                "results": final
                            }), trackerId)
                        else:
                            break

                    if decryptedBody["type"] == "friendReq":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            # TODO: Blocking users & stuff idk

                            if not self.checkFields(decryptedBody, ["UID"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "friendReqFailed"}), trackerId)
                                continue

                            targetUID = decryptedBody["UID"]
                            selfUID = self.getUserIdFromAuthToken(authToken)

                            targetInfo = self.getUserInfoFromUserId(targetUID)
                            selfInfo = self.getUserInfoFromToken(authToken)

                            if targetInfo is None or selfInfo is None:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "friendReqFailed"}), trackerId)
                                continue

                            if targetUID == selfUID:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "friendReqFailed"}), trackerId)
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
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "friendReqFailed"}), trackerId)
                                continue

                            for usr in self.users:
                                if usr["UID"] == targetUID:
                                    usr["FriendRequests"].append({"UID":selfUID, "type":"incoming"})
                                    targetFriendReqs = usr["FriendRequests"]

                                if usr["UID"] == selfUID:
                                    usr["FriendRequests"].append({"UID":targetUID, "type":"outgoing"})
                                    selfFriendReqs = usr["FriendRequests"]

                            await self.wsSendEncrypted(ws, orjson.dumps({"type": "updateFriendReqs", "friendReqs": selfFriendReqs}), trackerId)

                            for ws2 in self.WS_CLIENTS:
                                wsUID = getattr(ws2, "UID", None)
                                if wsUID is not None and wsUID == targetUID:
                                    await self.wsSendEncrypted(ws2, orjson.dumps({"type": "updateFriendReqs", "friendReqs": targetFriendReqs}))
                                    break
                        else:
                            break

                    if decryptedBody["type"] == "cancelFriendReq":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["UID"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "cancelFriendReqFailed"}), trackerId)
                                continue

                            targetUID = decryptedBody["UID"]
                            selfUID = self.getUserIdFromAuthToken(authToken)

                            targetInfo = self.getUserInfoFromUserId(targetUID)
                            selfInfo = self.getUserInfoFromToken(authToken)

                            if targetInfo is None or selfInfo is None:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "cancelFriendReqFailed"}), trackerId)
                                continue

                            if targetUID == selfUID:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "cancelFriendReqFailed"}), trackerId)
                                continue

                            targetFriendReqs = targetInfo["FriendRequests"]
                            selfFriendReqs = selfInfo["FriendRequests"]

                            for usr in self.users:
                                if usr["UID"] == targetUID:
                                    usr["FriendRequests"].remove({"UID":selfUID, "type":"incoming"})
                                    targetFriendReqs = usr["FriendRequests"]

                                if usr["UID"] == selfUID:
                                    usr["FriendRequests"].remove({"UID":targetUID, "type":"outgoing"})
                                    selfFriendReqs = usr["FriendRequests"]

                            await self.wsSendEncrypted(ws, orjson.dumps({"type": "updateFriendReqs", "friendReqs": selfFriendReqs}), trackerId)

                            for ws2 in self.WS_CLIENTS:
                                wsUID = getattr(ws2, "UID", None)
                                if wsUID is not None and wsUID == targetUID:
                                    await self.wsSendEncrypted(ws2, orjson.dumps({"type": "updateFriendReqs", "friendReqs": targetFriendReqs}))
                                    break
                        else:
                            break

                    if decryptedBody["type"] == "declineFriendReq":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["UID"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "declineFriendReqFailed"}), trackerId)
                                continue

                            targetUID = decryptedBody["UID"]
                            selfUID = self.getUserIdFromAuthToken(authToken)

                            targetInfo = self.getUserInfoFromUserId(targetUID)
                            selfInfo = self.getUserInfoFromToken(authToken)

                            if targetInfo is None or selfInfo is None:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "declineFriendReqFailed"}), trackerId)
                                continue

                            if targetUID == selfUID:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "declineFriendReqFailed"}), trackerId)
                                continue

                            targetFriendReqs = targetInfo["FriendRequests"]
                            selfFriendReqs = selfInfo["FriendRequests"]

                            for usr in self.users:
                                if usr["UID"] == targetUID:
                                    usr["FriendRequests"].remove({"UID":selfUID, "type":"outgoing"})
                                    targetFriendReqs = usr["FriendRequests"]

                                if usr["UID"] == selfUID:
                                    usr["FriendRequests"].remove({"UID":targetUID, "type":"incoming"})
                                    selfFriendReqs = usr["FriendRequests"]

                            await self.wsSendEncrypted(ws, orjson.dumps({"type": "updateFriendReqs", "friendReqs": selfFriendReqs}), trackerId)

                            for ws2 in self.WS_CLIENTS:
                                wsUID = getattr(ws2, "UID", None)
                                if wsUID is not None and wsUID == targetUID:
                                    await self.wsSendEncrypted(ws2, orjson.dumps({"type": "updateFriendReqs", "friendReqs": targetFriendReqs}))
                                    break
                        else:
                            break

                    if decryptedBody["type"] == "acceptFriendReq":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["UID"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "acceptFriendReqFailed"}), trackerId)
                                continue

                            targetUID = decryptedBody["UID"]
                            selfUID = self.getUserIdFromAuthToken(authToken)

                            targetInfo = self.getUserInfoFromUserId(targetUID)
                            selfInfo = self.getUserInfoFromToken(authToken)

                            if targetInfo is None or selfInfo is None:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "acceptFriendReqFailed"}), trackerId)
                                continue

                            if targetUID == selfUID:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "acceptFriendReqFailed"}), trackerId)
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
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "acceptFriendReqFailed"}), trackerId)
                                continue

                            if not ({"UID": targetUID, "type": "incoming"} in selfFriendReqs and {"UID": selfUID, "type": "outgoing"} in targetFriendReqs):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "acceptFriendReqFailed"}), trackerId)
                                continue

                            cid = -1
                            chatExists = True
                            for cht in self.chats:
                                if cht["Type"] == "dm" and selfUID in cht["Recipients"] and targetUID in cht["Recipients"]:
                                    cid = cht["CID"]
                                    break

                            if cid == -1:
                                chatExists = False
                                cid = len(self.chats)

                                self.chats.append({"CID": cid, "Type": "dm", "Name": f"{targetInfo["Displayname"]} & {selfInfo["Displayname"]}", "Recipients": [selfUID, targetUID], "Icon": random.choice(self.DEFAULT_PFPS), "Time": int(time.time()), "messages": []})

                            for usr in self.users:
                                if usr["UID"] == targetUID:
                                    usr["FriendRequests"].remove({"UID": selfUID, "type": "outgoing"})
                                    usr["Friends"].append({"UID": selfUID, "CID": cid, "timestamp": int(time.time())})
                                    if not chatExists:
                                        usr["Chats"].append(cid)
                                        usr["ReadMsgs"][str(cid)] = 0

                                if usr["UID"] == selfUID:
                                    usr["FriendRequests"].remove({"UID": targetUID, "type": "incoming"})
                                    usr["Friends"].append({"UID": targetUID, "CID": cid, "timestamp": int(time.time())})
                                    if not chatExists:
                                        usr["Chats"].append(cid)
                                        usr["ReadMsgs"][str(cid)] = 0

                            await self.wsSendEncrypted(ws, orjson.dumps({"type": "updateFriends", "friendReqs": selfFriendReqs, "friends": selfInfo["Friends"], "chats": selfInfo["Chats"]}), trackerId)

                            for ws2 in self.WS_CLIENTS:
                                wsUID = getattr(ws2, "UID", None)
                                if wsUID is not None and wsUID == targetUID:
                                    await self.wsSendEncrypted(ws2, orjson.dumps({"type": "updateFriends", "friendReqs": targetFriendReqs, "friends": targetInfo["Friends"], "chats": targetInfo["Chats"]}))
                                    break
                        else:
                            break

                    if decryptedBody["type"] == "removeFriend":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["UID"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "removeFriendFailed"}), trackerId)
                                continue

                            targetUID = decryptedBody["UID"]
                            selfUID = self.getUserIdFromAuthToken(authToken)

                            targetInfo = self.getUserInfoFromUserId(targetUID)
                            selfInfo = self.getUserInfoFromToken(authToken)

                            if targetInfo is None or selfInfo is None:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "removeFriendFailed"}), trackerId)
                                continue

                            if targetUID == selfUID:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "removeFriendFailed"}), trackerId)
                                continue

                            targetFriendReqs: list = targetInfo["FriendRequests"]
                            selfFriendReqs: list = selfInfo["FriendRequests"]

                            isFriends = False
                            for fri in selfInfo["Friends"]:
                                if fri["UID"] == targetUID:
                                    isFriends = True
                                    break

                            if not isFriends:
                                for fri in targetInfo["Friends"]:
                                    if fri["UID"] == selfUID:
                                        isFriends = True
                                        break

                            if not isFriends:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "removeFriendFailed"}), trackerId)
                                continue

                            for usr in self.users:
                                if usr["UID"] == targetUID:
                                    for fri in usr["Friends"][:]:
                                        if fri.get("UID") == selfUID:
                                            usr["Friends"].remove(fri)
                                            break

                                if usr["UID"] == selfUID:
                                    for fri in usr["Friends"][:]:
                                        if fri.get("UID") == targetUID:
                                            usr["Friends"].remove(fri)
                                            break

                            await self.wsSendEncrypted(ws, orjson.dumps({"type": "updateFriends", "friendReqs": selfFriendReqs, "friends": selfInfo["Friends"], "chats": selfInfo["Chats"]}), trackerId)

                            for ws2 in self.WS_CLIENTS:
                                wsUID = getattr(ws2, "UID", None)
                                if wsUID is not None and wsUID == targetUID:
                                    await self.wsSendEncrypted(ws2, orjson.dumps({"type": "updateFriends", "friendReqs": targetFriendReqs, "friends": targetInfo["Friends"], "chats": targetInfo["Chats"]}))
                                    break
                        else:
                            break

                    if decryptedBody["type"] == "createGC":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["include"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "createGCFailed"}), trackerId)
                                continue

                            selfUID = self.getUserIdFromAuthToken(authToken)

                            if not selfUID:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "createGCFailed"}), trackerId)
                                continue

                            selfInfo = self.getUserInfoFromUserId(selfUID)

                            if not selfInfo:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "createGCFailed"}), trackerId)
                                continue

                            friendsList: list[int] = [friend["UID"] for friend in selfInfo["Friends"]]

                            success = True
                            for usr in decryptedBody["include"]:
                                if not usr in friendsList:
                                    success = False
                                    break

                            if not success:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "createGCFailed"}), trackerId)
                                continue

                            included = [selfUID] + decryptedBody["include"]

                            cid = len(self.chats)
                            chatName = ""
                            success = True
                            for usr in included:
                                uInfo = self.getUserInfoFromUserId(usr)

                                if uInfo is None:
                                    success = False
                                    break

                                chatName += uInfo["Displayname"] + ", "
                                uInfo["Chats"].append(cid)
                                uInfo["ReadMsgs"][str(cid)] = 0

                            if not success:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "createGCFailed"}), trackerId)
                                continue

                            chatName = chatName[:-2]

                            if len(chatName) > 100:
                                chatName = f"{len(included)} people"

                            self.chats.append({"CID": cid, "Type": "gc", "Name": chatName, "Recipients": included, "Owner": selfUID, "Icon": random.choice(self.DEFAULT_PFPS), "Time": int(time.time()), "messages": []})

                            for ws2 in self.WS_CLIENTS:
                                wsUID = getattr(ws2, "UID", None)
                                targetInfo = self.getUserInfoFromUserId(wsUID)

                                if wsUID is not None and targetInfo is not None and wsUID in included:
                                    await self.wsSendEncrypted(ws2, orjson.dumps({"type": "newChat", "chats": targetInfo["Chats"]}))
                        else:
                            break

                    if decryptedBody["type"] == "updateGcInfo":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["CID", "icon", "name"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "updateGcInfoFailed"}), trackerId)
                                continue

                            if not self.tokenInChat(authToken, decryptedBody["CID"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "updateGcInfoFailed"}), trackerId)
                                continue

                            uid = self.getUserIdFromAuthToken(authToken)
                            newChatName = decryptedBody["name"].strip()
                            chat = self.getChatFromCID(decryptedBody["CID"])

                            if chat is None or uid is None:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "updateGcInfoFailed"}), trackerId)
                                continue

                            iconB64 = self.resizePfp(decryptedBody["icon"])

                            isChanged = True
                            if iconB64 == chat["Icon"] and newChatName == chat["Name"]:
                                isChanged = False

                            chat["Icon"] = iconB64

                            if len(newChatName) <= 100 and len(newChatName) > 0:
                                chat["Name"] = newChatName

                            if isChanged:
                                chat["messages"].append({
                                    "SYSMSG": True,
                                    "MSGID": len(chat["messages"]),
                                    "TYPE": "editGcInfo",
                                    "TARGET": uid,
                                    "time": int(time.time())
                                })

                            for ws2 in self.WS_CLIENTS:
                                wsUID = getattr(ws2, "UID", None)
                                targetInfo = self.getUserInfoFromUserId(wsUID)

                                if wsUID is not None and decryptedBody["CID"] in targetInfo["Chats"]:
                                    await self.wsSendEncrypted(ws2, orjson.dumps({"type": "metaChatUpdate", "chat": chat}))
                        else:
                            break

                    if decryptedBody["type"] == "addUsrToChat":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["CID", "users"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "addUsrFailed"}), trackerId)
                                continue

                            if not self.tokenInChat(authToken, decryptedBody["CID"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "addUsrFailed"}), trackerId)
                                continue

                            selfInfo = self.getUserInfoFromToken(authToken)
                            uid = self.getUserIdFromUserInfo(selfInfo)
                            chat = self.getChatFromCID(decryptedBody["CID"])

                            if chat is None or uid is None or selfInfo is None:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "addUsrFailed"}), trackerId)
                                continue

                            friendsList: list[int] = [friend["UID"] for friend in selfInfo["Friends"]]

                            success = True
                            for usr in decryptedBody["users"]:
                                if not usr in friendsList:
                                    success = False
                                    break

                            if not success:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "addUsrFailed"}), trackerId)
                                continue

                            for usr in decryptedBody["users"]:
                                usrInfo = self.getUserInfoFromUserId(usr)

                                if usrInfo is None or decryptedBody["CID"] in usrInfo["Chats"]:
                                    continue

                                usrInfo["Chats"].append(decryptedBody["CID"])
                                chat["Recipients"].append(usr)


                            chat["messages"].append({
                                "SYSMSG": True,
                                "MSGID": len(chat["messages"]),
                                "TYPE": "addUsrToGc",
                                "TARGET": uid,
                                "TARGETS": decryptedBody["users"],
                                "time": int(time.time())
                            })

                            await self.wsSendEncrypted(ws, orjson.dumps({
                                "type": "addUsrSuccess"
                            }), trackerId)

                            for ws2 in self.WS_CLIENTS:
                                wsUID = getattr(ws2, "UID", None)
                                targetInfo = self.getUserInfoFromUserId(wsUID)

                                if wsUID is not None:
                                    if wsUID in decryptedBody["users"]:
                                        await self.wsSendEncrypted(ws2, orjson.dumps({"type": "newChat", "chats": targetInfo["Chats"]}))

                                    if decryptedBody["CID"] in targetInfo["Chats"]:
                                        await self.wsSendEncrypted(ws2, orjson.dumps({"type": "metaChatUpdate", "chat": chat}))
                        else:
                            break

                    if decryptedBody["type"] == "addUsrToServer":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["SID", "users"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "addUsrServerFailed"}), trackerId)
                                continue

                            if not self.tokenInServer(authToken, decryptedBody["SID"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "addUsrServerFailed"}), trackerId)
                                continue

                            selfInfo = self.getUserInfoFromToken(authToken)
                            uid = self.getUserIdFromUserInfo(selfInfo)
                            server = self.getServerFromSID(decryptedBody["SID"])

                            if server is None or uid is None or selfInfo is None:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "addUsrServerFailed"}), trackerId)
                                continue

                            if uid != server["Owner"]:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "addUsrServerFailed"}), trackerId)
                                continue

                            friendsList: list[int] = [friend["UID"] for friend in selfInfo["Friends"]]

                            success = True
                            for usr in decryptedBody["users"]:
                                if not usr in friendsList:
                                    success = False
                                    break

                            if not success:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "addUsrServerFailed"}), trackerId)
                                continue

                            for usr in decryptedBody["users"]:
                                for cht in selfInfo["Chats"]:
                                    chat = self.getChatFromCID(cht)

                                    if chat is not None and chat["Type"] == "dm" and usr in chat["Recipients"] and uid in chat["Recipients"]:
                                        inviteId = None
                                        while inviteId is None or any(d.get("ID") == inviteId for d in self.invites):
                                            inviteId = secrets.token_urlsafe(256)

                                        self.invites.append({"ID": inviteId, "SID": server["SID"], "BY": uid, "TO": usr, "CREATED": int(time.time()), "EXPIRE": int(time.time()) + config.INVITE_EXPIRE_TIME})

                                        msgObj = {
                                            "SYSMSG": True,
                                            "MSGID": len(chat["messages"]),
                                            "TYPE": "serverInvite",
                                            "TARGET": server["SID"],
                                            "ID": inviteId,
                                            "SELF": uid,
                                            "time": int(time.time()),
                                            "expire": int(time.time()) + config.INVITE_EXPIRE_TIME
                                        }

                                        chat["messages"].append(msgObj)

                                        for ws2 in self.WS_CLIENTS:
                                            wsUID = getattr(ws2, "UID", None)

                                            if wsUID is not None and wsUID == usr:
                                                await self.wsSendEncrypted(ws2, orjson.dumps({"type": "newMsg", "CID": cht, "message": msgObj}))
                                                break
                                        break
                            await self.wsSendEncrypted(ws, orjson.dumps({"type": "addUsrServerSuccess"}), trackerId)
                        else:
                            break

                    if decryptedBody["type"] == "leaveGc":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["CID"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "leaveGcFailed"}), trackerId)
                                continue

                            uid = self.getUserIdFromAuthToken(authToken)
                            cid = decryptedBody["CID"]
                            usrInfo = self.getUserInfoFromUserId(uid)
                            chat = self.getChatFromCID(cid)

                            if uid is None or usrInfo is None or chat is None:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "leaveGcFailed"}), trackerId)
                                continue

                            failed = False
                            try:
                                usrInfo["Chats"].remove(cid)
                                chat["Recipients"].remove(uid)
                            except:
                                failed = True
                                traceback.print_exc()
                                logging.warning("Failed to remove user from chat! UID: %i, CID: %i", uid, cid)

                            if failed:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "leaveGcFailed"}), trackerId)
                                continue

                            await self.wsSendEncrypted(ws, orjson.dumps({"type": "chatGone", "chats": usrInfo["Chats"]}), trackerId)

                            if uid == chat["Owner"] and len(chat["Recipients"]) > 0:
                                chat["Owner"] = chat["Recipients"][0]

                            if len(chat["Recipients"]) == 0:
                                self.delChat(chat)
                                continue

                            chat["messages"].append({
                                "SYSMSG": True,
                                "MSGID": len(chat["messages"]),
                                "TYPE": "usrLeaveGc",
                                "TARGET": uid,
                                "time": int(time.time())
                            })

                            for ws2 in self.WS_CLIENTS:
                                wsUID = getattr(ws2, "UID", None)
                                targetInfo = self.getUserInfoFromUserId(wsUID)

                                if wsUID is not None and cid in targetInfo["Chats"]:
                                    await self.wsSendEncrypted(ws2, orjson.dumps({"type": "metaChatUpdate", "chat": chat}))
                        else:
                            break

                    if decryptedBody["type"] == "rmUsrFromChat":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["CID", "UID"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "rmUsrFailed"}), trackerId)
                                continue

                            targetUID = decryptedBody["UID"]
                            targetInfo = self.getUserInfoFromUserId(targetUID)
                            cid = decryptedBody["CID"]
                            chat = self.getChatFromCID(cid)
                            selfUID = self.getUserIdFromAuthToken(authToken)

                            if targetInfo is None or chat is None:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "rmUsrFailed"}), trackerId)
                                continue

                            if chat["Owner"] != selfUID or chat["Owner"] == targetUID:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "rmUsrFailed"}), trackerId)
                                continue

                            failed = False
                            try:
                                targetInfo["Chats"].remove(cid)
                                chat["Recipients"].remove(targetUID)
                            except:
                                failed = True
                                traceback.print_exc()
                                logging.warning("Failed to remove user from chat! UID: %i, CID: %i", uid, cid)

                            if failed:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "rmUsrFailed"}), trackerId)
                                continue

                            chat["messages"].append({
                                "SYSMSG": True,
                                "MSGID": len(chat["messages"]),
                                "TYPE": "usrRemovedGc",
                                "TARGET": selfUID,
                                "TARGET2": targetUID,
                                "time": int(time.time())
                            })

                            for ws2 in self.WS_CLIENTS:
                                wsUID = getattr(ws2, "UID", None)
                                targetInfo = self.getUserInfoFromUserId(wsUID)

                                if wsUID is not None:
                                    if cid in targetInfo["Chats"]:
                                        await self.wsSendEncrypted(ws2, orjson.dumps({"type": "metaChatUpdate", "chat": chat}))

                                    if wsUID == targetUID:
                                        await self.wsSendEncrypted(ws2, orjson.dumps({"type": "chatGone", "chats": usrInfo["Chats"]}), trackerId)
                        else:
                            break

                    if decryptedBody["type"] == "setRead":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["CID", "MSGID"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "setReadFailed"}), trackerId)
                                continue

                            usrInfo = self.getUserInfoFromToken(authToken)
                            usrInfo["ReadMsgs"][str(decryptedBody["CID"])] = decryptedBody["MSGID"]

                            await self.wsSendEncrypted(ws, orjson.dumps({
                                "type": "setReadSuccess",
                                "readMsgs": usrInfo["ReadMsgs"]
                            }), trackerId)
                        else:
                            break

                    if decryptedBody["type"] == "createServer":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["icon", "name"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "createServerFailed"}), trackerId)
                                continue

                            selfInfo = self.getUserInfoFromToken(authToken)

                            if selfInfo is None:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "createServerFailed"}), trackerId)
                                continue

                            selfUID = selfInfo["UID"]

                            sid = len(self.servers)
                            cid = len(self.chats)
                            genChat = {"CID": cid, "Type": "channel", "Server": sid, "Name": "general", "Recipients": [], "Owner": selfUID, "Icon": config.EMPTY_IMG, "Time": int(time.time()), "messages": []}
                            textCategory = {
                                "categoryID": 0,
                                "name": "Text Channels",
                                "Chats": [cid]
                            }
                            serverDict = {
                                "SID": sid,
                                "Owner": selfUID,
                                "Users": [selfUID],
                                "Categories": [textCategory],
                                "AnnouncementChat": cid
                            }

                            serverDict["Icon"] = self.resizePfp(decryptedBody["icon"])

                            serverName = decryptedBody["name"].strip()
                            if len(serverName) == 0 or len(serverName) > 100:
                                serverDict["Name"] = f"{self.getUsernameFromAuthToken(authToken)}'s Server"
                            else:
                                serverDict["Name"] = serverName

                            self.servers.append(serverDict)
                            self.chats.append(genChat)
                            selfInfo["Servers"].append(sid)

                            await self.wsSendEncrypted(ws, orjson.dumps({
                                "type": "updateServers",
                                "servers": selfInfo["Servers"]
                            }), trackerId)
                        else:
                            break

                    if decryptedBody["type"] == "reqServerMeta":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["SID"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "reqServerMetaFailed"}), trackerId)
                                continue

                            server = self.getServerFromSID(decryptedBody["SID"])

                            if not server:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "reqServerMetaFailed"}), trackerId)
                                continue

                            await self.wsSendEncrypted(ws, orjson.dumps({
                                "type": "reqServerMetaSuccess",
                                "server": {
                                    "SID": server["SID"],
                                    "icon": server["Icon"],
                                    "name": server["Name"]
                                }
                            }), trackerId)
                        else:
                            break

                    if decryptedBody["type"] == "reqServer":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["SID"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "reqServerFailed"}), trackerId)
                                continue

                            if not self.tokenInServer(authToken, decryptedBody["SID"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "reqServerFailed"}), trackerId)
                                continue

                            server = self.getServerFromSID(decryptedBody["SID"])

                            if not server:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "reqServerFailed"}), trackerId)
                                continue

                            await self.wsSendEncrypted(ws, orjson.dumps({
                                "type": "reqServerSuccess",
                                "server": server
                            }), trackerId)
                        else:
                            break

                    if decryptedBody["type"] == "newChannel":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["SID", "categoryID", "name"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "newChannelFailed"}), trackerId)
                                continue

                            if not self.tokenInServer(authToken, decryptedBody["SID"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "newChannelFailed"}), trackerId)
                                continue

                            server = self.getServerFromSID(decryptedBody["SID"])

                            if server is None:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "newChannelFailed"}), trackerId)
                                continue

                            userId = self.getUserIdFromAuthToken(authToken)

                            if userId is None or not userId == server["Owner"]:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "newChannelFailed"}), trackerId)
                                continue

                            category = None
                            for cate in server["Categories"]:
                                if cate["categoryID"] == decryptedBody["categoryID"]:
                                    category = cate
                                    break

                            if category is None:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "newChannelFailed"}), trackerId)
                                continue

                            channelName = decryptedBody["name"].strip()

                            if len(channelName) == 0 or len(channelName) > 100:
                                channelName = "New Channel"

                            cid = len(self.chats)
                            channel = {"CID": cid, "Type": "channel", "Server": decryptedBody["SID"], "Name": channelName, "Recipients": [], "Owner": server["Owner"], "Icon": config.EMPTY_IMG, "Time": int(time.time()), "messages": []}
                            self.chats.append(channel)
                            category["Chats"].append(cid)

                            await self.wsSendEncrypted(ws, orjson.dumps({"type": "newChannelSuccess"}), trackerId)

                            for ws2 in self.WS_CLIENTS:
                                wsUID = getattr(ws2, "UID", None)
                                targetInfo = self.getUserInfoFromUserId(wsUID)

                                if wsUID is not None and decryptedBody["SID"] in targetInfo["Servers"]:
                                    await self.wsSendEncrypted(ws2, orjson.dumps({"type": "serverContentUpdate", "SID": server["SID"], "categories": server["Categories"]}))
                        else:
                            break

                    if decryptedBody["type"] == "newCategory":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["SID", "name"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "newCategoryFailed"}), trackerId)
                                continue

                            if not self.tokenInServer(authToken, decryptedBody["SID"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "newCategoryFailed"}), trackerId)
                                continue

                            server = self.getServerFromSID(decryptedBody["SID"])

                            if server is None:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "newCategoryFailed"}), trackerId)
                                continue

                            userId = self.getUserIdFromAuthToken(authToken)

                            if userId is None or not userId == server["Owner"]:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "newCategoryFailed"}), trackerId)
                                continue

                            categoryName = decryptedBody["name"].strip()

                            if len(categoryName) == 0 or len(categoryName) > 100:
                                categoryName = "New Category"

                            category = {"categoryID": len(server["Categories"]), "name": categoryName, "Chats": []}
                            server["Categories"].append(category)

                            await self.wsSendEncrypted(ws, orjson.dumps({"type": "newCategorySuccess"}), trackerId)

                            for ws2 in self.WS_CLIENTS:
                                wsUID = getattr(ws2, "UID", None)
                                targetInfo = self.getUserInfoFromUserId(wsUID)

                                if wsUID is not None and decryptedBody["SID"] in targetInfo["Servers"]:
                                    await self.wsSendEncrypted(ws2, orjson.dumps({"type": "serverContentUpdate", "SID": server["SID"], "categories": server["Categories"]}))
                        else:
                            break

                    if decryptedBody["type"] == "acceptInvite":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["inviteID"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "acceptInviteFailed"}), trackerId)
                                continue

                            uInfo = self.getUserInfoFromToken(authToken)
                            uid = self.getUserIdFromUserInfo(uInfo)

                            if uInfo is None or uid is None:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "acceptInviteFailed"}), trackerId)
                                continue

                            valid, targetServer = await self.checkInviteValid(decryptedBody["inviteID"])

                            if targetServer is None or not valid:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "acceptInviteFailed"}), trackerId)
                                continue

                            targetServer["Users"].append(uid)
                            uInfo["Servers"].append(targetServer["SID"])

                            chat = self.getChatFromCID(server["AnnouncementChat"])
                            newMemberMsg = None

                            if chat is not None and chat["CID"] != -1:
                                newMemberMsg = {
                                    "SYSMSG": True,
                                    "MSGID": len(chat["messages"]),
                                    "TYPE": "newServerMember",
                                    "TARGET": uid,
                                    "time": int(time.time())
                                }

                                chat["messages"].append(newMemberMsg)

                            await self.wsSendEncrypted(ws, orjson.dumps({
                                "type": "updateServers",
                                "servers": uInfo["Servers"],
                                "newServer": targetServer["SID"]
                            }), trackerId)

                            for ws2 in self.WS_CLIENTS:
                                wsUID = getattr(ws2, "UID", None)
                                targetInfo = self.getUserInfoFromUserId(wsUID)

                                if wsUID is not None and targetServer["SID"] in targetInfo["Servers"]:
                                    await self.wsSendEncrypted(ws2, orjson.dumps({"type": "serverMembersUpdate", "SID": targetServer["SID"], "members": server["Users"]}))

                                    if newMemberMsg is not None:
                                        await self.wsSendEncrypted(ws2, orjson.dumps({"type": "newMsg", "CID": chat["CID"], "message": newMemberMsg}))
                        else:
                            break

                    if decryptedBody["type"] == "kickUsrFromServer":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["SID", "UID"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "kickUsrFailed"}), trackerId)
                                continue

                            server = self.getServerFromSID(decryptedBody["SID"])

                            if server is None:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "kickUsrFailed"}), trackerId)
                                continue

                            uid = self.getUserIdFromAuthToken(authToken)

                            if uid is None or not uid == server["Owner"]:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "kickUsrFailed"}), trackerId)
                                continue

                            targetUsrInfo = self.getUserInfoFromUserId(decryptedBody["UID"])
                            if targetUsrInfo is None or uid == targetUsrInfo["UID"] or not server["SID"] in targetUsrInfo["Servers"]:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "kickUsrFailed"}), trackerId)
                                continue

                            failed = False
                            try:
                                targetUsrInfo["Servers"].remove(server["SID"])
                                server["Users"].remove(decryptedBody["UID"])
                            except:
                                failed = True
                                traceback.print_exc()
                                logging.warning("Failed to kick user from server! Owner UID: %i, Target UID: %i, SID: %i", uid, decryptedBody["UID"], sid)

                            if failed:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "kickUsrFailed"}), trackerId)
                                continue

                            for inv in copy.copy(self.invites):
                                if inv["SID"] == server["SID"] and inv["TO"] == targetUsrInfo["UID"]:
                                    self.invites.remove(inv)

                            await self.wsSendEncrypted(ws, orjson.dumps({"type": "kickUsrSuccess"}), trackerId)

                            for ws2 in self.WS_CLIENTS:
                                wsUID = getattr(ws2, "UID", None)
                                targetInfo = self.getUserInfoFromUserId(wsUID)

                                if wsUID is not None:
                                    if server["SID"] in targetInfo["Servers"]:
                                        await self.wsSendEncrypted(ws2, orjson.dumps({"type": "serverMembersUpdate", "SID": server["SID"], "members": server["Users"]}))
                                    if wsUID == targetUsrInfo["UID"]:
                                        await self.wsSendEncrypted(ws2, orjson.dumps({"type": "serverGone", "servers": targetUsrInfo["Servers"]}))
                        else:
                            break

                    if decryptedBody["type"] == "leaveServer":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["SID"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "leaveServerFailed"}), trackerId)
                                continue

                            server = self.getServerFromSID(decryptedBody["SID"])

                            if server is None:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "leaveServerFailed"}), trackerId)
                                continue

                            uInfo = self.getUserInfoFromToken(authToken)
                            uid = self.getUserIdFromUserInfo(uInfo)

                            if uid is None or uInfo is None:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "leaveServerFailed"}), trackerId)
                                continue

                            failed = False
                            try:
                                uInfo["Servers"].remove(server["SID"])
                                server["Users"].remove(uid)
                            except:
                                failed = True
                                traceback.print_exc()
                                logging.warning("Failed to leave server! UID: %i, SID: %i", uid, sid)

                            if failed:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "leaveServerFailed"}), trackerId)
                                continue

                            for inv in copy.copy(self.invites):
                                if inv["SID"] == server["SID"] and inv["TO"] == uid:
                                    self.invites.remove(inv)

                            await self.wsSendEncrypted(ws, orjson.dumps({"type": "serverGone", "servers": uInfo["Servers"]}), trackerId)

                            if len(server["Users"]) == 0:
                                self.delServer(server)
                                continue
                            elif uid == server["Owner"]:
                                server["Owner"] = server["Users"][0]

                            for ws2 in self.WS_CLIENTS:
                                wsUID = getattr(ws2, "UID", None)
                                targetInfo = self.getUserInfoFromUserId(wsUID)

                                if wsUID is not None:
                                    if server["SID"] in targetInfo["Servers"]:
                                        await self.wsSendEncrypted(ws2, orjson.dumps({"type": "serverMembersUpdate", "SID": server["SID"], "members": server["Users"]}))
                        else:
                            break

                    if decryptedBody["type"] == "checkInviteValid":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["inviteID"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "checkInviteFailed", "isValid": False}), trackerId)
                                continue

                            uInfo = self.getUserInfoFromToken(authToken)
                            uid = self.getUserIdFromUserInfo(uInfo)

                            if uInfo is None or uid is None:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "checkInviteFailed", "isValid": False}), trackerId)
                                continue

                            valid, targetServer = await self.checkInviteValid(decryptedBody["inviteID"])
                            if targetServer is None or not valid:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "checkInviteSuccess", "isValid": False}), trackerId)
                                continue

                            await self.wsSendEncrypted(ws, orjson.dumps({"type": "checkInviteSuccess", "isValid": True}), trackerId)
                        else:
                            break

                    if decryptedBody["type"] == "transferOwnershipGc":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["CID", "UID"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "transferOwnershipGcFailed"}), trackerId)
                                continue

                            chat = self.getChatFromCID(decryptedBody["CID"])
                            selfInfo = self.getUserInfoFromToken(authToken)
                            selfUid = self.getUserIdFromUserInfo(selfInfo)

                            if chat is None or selfUid not in chat["Recipients"] or chat["Owner"] == decryptedBody["UID"] or decryptedBody["UID"] not in chat["Recipients"]:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "transferOwnershipGcFailed"}), trackerId)
                                continue

                            chat["Owner"] = decryptedBody["UID"]
                            chat["messages"].append({
                                "SYSMSG": True,
                                "MSGID": len(chat["messages"]),
                                "TYPE": "transferOwnership",
                                "TARGET": decryptedBody["UID"],
                                "time": int(time.time())
                            })

                            await self.wsSendEncrypted(ws, orjson.dumps({"type": "transferOwnershipGcSuccess"}), trackerId)

                            for ws2 in self.WS_CLIENTS:
                                wsUID = getattr(ws2, "UID", None)
                                targetInfo = self.getUserInfoFromUserId(wsUID)

                                if wsUID is not None and chat["CID"] in targetInfo["Chats"]:
                                    await self.wsSendEncrypted(ws2, orjson.dumps({"type": "metaChatUpdate", "chat": chat}))

                        else:
                            break

                    if decryptedBody["type"] == "transferOwnershipServer":
                        if await self.checkAuthTokenEncrypted(ws, authToken):
                            if not self.checkFields(decryptedBody, ["SID", "UID"]):
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "transferOwnershipServerFailed"}), trackerId)
                                continue

                            server = self.getServerFromSID(decryptedBody["SID"])
                            selfInfo = self.getUserInfoFromToken(authToken)
                            selfUid = self.getUserIdFromUserInfo(selfInfo)

                            if server is None or selfUid not in server["Users"] or server["Owner"] == decryptedBody["UID"] or decryptedBody["UID"] not in server["Users"]:
                                await self.wsSendEncrypted(ws, orjson.dumps({"type": "transferOwnershipServerFailed"}), trackerId)
                                continue

                            server["Owner"] = decryptedBody["UID"]

                            chat = self.getChatFromCID(server["AnnouncementChat"])
                            newMemberMsg = None

                            if chat is not None and chat["CID"] != -1:
                                newMemberMsg = {
                                    "SYSMSG": True,
                                    "MSGID": len(chat["messages"]),
                                    "TYPE": "transferOwnership",
                                    "TARGET": decryptedBody["UID"],
                                    "time": int(time.time())
                                }

                                chat["messages"].append(newMemberMsg)

                            await self.wsSendEncrypted(ws, orjson.dumps({"type": "transferOwnershipServerSuccess"}), trackerId)

                            for ws2 in self.WS_CLIENTS:
                                wsUID = getattr(ws2, "UID", None)
                                targetInfo = self.getUserInfoFromUserId(wsUID)

                                if wsUID is not None and server["SID"] in targetInfo["Servers"]:
                                    await self.wsSendEncrypted(ws2, orjson.dumps({"type": "serverOwnerUpdate", "SID": server["SID"], "owner": server["Owner"]}))

                                    if newMemberMsg is not None:
                                        await self.wsSendEncrypted(ws2, orjson.dumps({"type": "newMsg", "CID": chat["CID"], "message": newMemberMsg}))

                        else:
                            break


                    continue

        except:
            traceback.print_exc()
        finally:
            self.WS_CLIENTS.remove(ws)

    async def shutdownWs(self, shutdownEvent: asyncio.Event, shutdownEventDone: asyncio.Event):
        shutdownEvent.set()

        for ws in copy.copy(self.WS_CLIENTS):
            try:
                await asyncio.wait_for(ws.close(), 5)

                if ws in self.WS_CLIENTS:
                    self.WS_CLIENTS.remove(ws)
            except TimeoutError:
                pass
            except:
                logging.warning("Error when disconnecting client ws!", stack_info=True)

        await shutdownEventDone.wait()

        asyncio.get_running_loop().stop()


    async def getAuth(self, connection: ServerConnection, request: Request):
        cookieHeader = request.headers.get("Cookie")

        if cookieHeader:
            parser = cookies.SimpleCookie()
            parser.load(cookieHeader)

            parsedCookies = {key: morsel.value for key, morsel in parser.items()}

            setattr(connection, "authToken", parsedCookies.get("authToken"))

    async def wsListen(self, ipAddrs: list, context: ssl.SSLContext, shutdownEvent: asyncio.Event, shutdownEventDone: asyncio.Event):
        servers = []

        for addr in ipAddrs:
            servers.append(serve(self.wsHandler, addr, config.WSS_PORT, max_size=(25*1024*1024 * 11), ssl=context, process_request=self.getAuth))
            logging.debug("[WS] wss://%s:%i", addr, config.WSS_PORT)
            servers.append(serve(self.wsHandler, addr, config.WS_PORT, max_size=(25*1024*1024 * 11), process_request=self.getAuth))
            logging.debug("[WS] ws://%s:%i", addr, config.WS_PORT)

        logging.info("[WS] Websockets running")

        await asyncio.gather(*servers, shutdownEvent.wait())
        logging.info("[WS] Websocket exited")
        shutdownEventDone.set()

    def wsBootstrap(self, loop: asyncio.AbstractEventLoop):
        logging.info("[WS] Websocket Bootstrap")
        asyncio.set_event_loop(loop)
        loop.run_forever()
