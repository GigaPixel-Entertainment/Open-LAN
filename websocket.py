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

from websockets.asyncio.server import serve, ServerConnection, Request, broadcast

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

        self.webRequests = {
            "reqUser": self.reqUser,
            "reqChatMeta": self.reqChatMeta,
            "reqChat": self.reqChat,
            "reqMsg": self.reqMsg,
            "getEmbed": self.getEmbed,
            "reqUsersList": self.reqUsersList,
            "sendMsg": self.sendMsg,
            "delMsg": self.delMsg,
            "editMsg": self.editMsg,
            "updateDisplayname": self.updateDisplayname,
            "updateBirthday": self.updateBirthday,
            "updatePronoun": self.updatePronoun,
            "updatePfp": self.updatePfp,
            "updateBio": self.updateBio,
            "userSearch": self.userSearch,
            "friendReq": self.friendReq,
            "cancelFriendReq": self.cancelFriendReq,
            "declineFriendReq": self.declineFriendReq,
            "acceptFriendReq": self.acceptFriendReq,
            "removeFriend": self.removeFriend,
            "createGC": self.createGC,
            "updateGcInfo": self.updateGcInfo,
            "addUsrToChat": self.addUsrToChat,
            "addUsrToServer": self.addUsrToServer,
            "leaveGc": self.leaveGc,
            "rmUsrFromChat": self.rmUsrFromChat,
            "setRead": self.setRead,
            "createServer": self.createServer,
            "reqServerMeta": self.reqServerMeta,
            "reqServer": self.reqServer,
            "newChannel": self.newChannel,
            "newCategory": self.newCategory,
            "acceptInvite": self.acceptInvite,
            "kickUsrFromServer": self.kickUsrFromServer,
            "leaveServer": self.leaveServer,
            "checkInviteValid": self.checkInviteValid,
            "transferOwnershipGc": self.transferOwnershipGc,
            "transferOwnershipServer": self.transferOwnershipServer,
            "moveChannel": self.moveChannel
        }

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

    def getUserInfoFromUserId(self, UID: int | None) -> dict | None:
        if UID is None:
            return None

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

    def isInviteValid(self, inviteID: str) -> tuple[bool, dict | None]:
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
        tasks = [self.wsSendEncrypted(client, data) for client in clients]
        await asyncio.gather(*tasks)

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

    def decrypt(self, ws: ServerConnection, msgDecoded: dict) -> tuple[dict, int] | tuple[None, None]:
        key = getattr(ws, "secretKey", None)

        if key is None:
            logging.warning("[WS] Encrypted message sent without key!")
            return (None, None)

        if len(key) != 32:
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
            return (None, None)

    async def reqUser(self, ws, decryptedBody, authToken, trackerId):
        userinfo = self.getUserInfoFromToken(authToken)

        if userinfo is None:
            await self.wsSendEncrypted(ws, orjson.dumps({"type":"reqUserFailed", "message": "User not found!"}), trackerId)
            return

        await self.wsSendEncrypted(ws, orjson.dumps({
            "type": "reqUserSuccess",
            "user": userinfo
        }), trackerId)

    async def reqChatMeta(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["CID"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "reqChatMetaFailed", "message": "Request error. Please contact the server owner for help."}), trackerId)
            return

        if not self.tokenInChat(authToken, decryptedBody["CID"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type":"reqChatMetaFailed","message": "User not in chat!"}), trackerId)
            return

        chat = self.getChatFromCID(decryptedBody["CID"])

        if chat is None:
            await self.wsSendEncrypted(ws, orjson.dumps({"type":"reqChatMetaFailed","message":"Chat not found!"}), trackerId)
            return

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
            "numMsgs": len(chat["messages"]),
            "lastMsg": {
                "time": lastMsg["time"] if lastMsg else chat["Time"],
                "MSGID": lastMsg["MSGID"] if lastMsg else 0,
                "content": lastRealMsg["content"] if lastRealMsg else ""
            }
        }}), trackerId)

    async def reqChat(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["CID", "page"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "reqChatFailed", "message": "Request error. Please contact the server owner for help."}), trackerId)
            return

        if not self.tokenInChat(authToken, decryptedBody["CID"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type":"reqChatFailed","message": "User not in chat!"}), trackerId)
            return

        chat = self.getChatFromCID(decryptedBody["CID"])

        if chat is None:
            await self.wsSendEncrypted(ws, orjson.dumps({"type":"reqChatFailed","message":"Chat not found!"}), trackerId)
            return

        pagedChat = copy.deepcopy(chat)

        if decryptedBody["page"] == 0:
            pagedChat["messages"] = pagedChat["messages"][-100:]
        else:
            pagedChat["messages"] = pagedChat["messages"][-100 * (decryptedBody["page"] + 1):-100 * decryptedBody["page"]]

        await self.wsSendEncrypted(ws, orjson.dumps({"type":"reqChatSuccess", "chat": pagedChat, "numPages": math.ceil(len(chat["messages"]) / 100 + 0.005) - 1}), trackerId)

    async def reqMsg(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["CID", "MSGID"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "reqMsgFailed"}), trackerId)
            return

        if not self.tokenInChat(authToken, decryptedBody["CID"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type":"reqMsgFailed"}), trackerId)
            return

        chat = self.getChatFromCID(decryptedBody["CID"])

        if chat is None:
            await self.wsSendEncrypted(ws, orjson.dumps({"type":"reqMsgFailed"}), trackerId)
            return

        targetMsg = None
        for msg in chat["messages"]:
            if msg["MSGID"] == decryptedBody["MSGID"]:
                targetMsg = msg
                break

        if targetMsg is None:
            await self.wsSendEncrypted(ws, orjson.dumps({"type":"reqMsgFailed"}), trackerId)
            return

        await self.wsSendEncrypted(ws, orjson.dumps({"type": "reqMsgSuccess", "msg": targetMsg}), trackerId)

    async def getEmbed(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["embedUrl"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "getEmbedFailed"}), trackerId)
            return

        filePath = config.CWD / decryptedBody["embedUrl"]

        if not httphelper.isSafePath(filePath) or not filePath.exists():
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "getEmbedFailed"}), trackerId)
            return

        fileType, _ = mimetypes.guess_file_type(filePath, strict=False)

        await self.wsSendEncrypted(ws, orjson.dumps({
            "type": "getEmbedSuccess",
            "embedType": fileType
        }), trackerId)

    async def reqUsersList(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["users"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "reqUsersListFailed"}), trackerId)
            return

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

    async def sendMsg(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["CID", "msg", "embed", "replyTo"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "chatUpdateFailed"}), trackerId)
            return

        if not self.tokenInChat(authToken, decryptedBody["CID"]) or len(decryptedBody["msg"]) > 4000 or len(decryptedBody["embed"]) > 10:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "chatUpdateFailed"}), trackerId)
            return

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
            return

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

    async def delMsg(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["CID", "MSGID"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "delMsgFailed"}), trackerId)
            return

        chat = None
        for cht in self.chats:
            if cht["CID"] == decryptedBody["CID"]:
                chat = cht
                break

        if chat is None or not self.tokenInChat(authToken, chat["CID"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "delMsgFailed"}), trackerId)
            return

        message = None

        for msg in chat["messages"]:
            if msg["MSGID"] == decryptedBody["MSGID"]:
                message = msg
                break

        if message is None or message["UID"] != self.getUserIdFromAuthToken(authToken):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "delMsgFailed"}), trackerId)
            return

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

    async def editMsg(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["CID", "MSGID", "new"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "editMsgFailed"}), trackerId)
            return

        chat = None
        for cht in self.chats:
            if cht["CID"] == decryptedBody["CID"]:
                chat = cht

        if chat is None or not self.tokenInChat(authToken, chat["CID"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "editMsgFailed"}), trackerId)
            return

        message = None
        for msg in chat["messages"]:
            if msg["MSGID"] == decryptedBody["MSGID"]:
                message = msg

        if message is None or message["UID"] != self.getUserIdFromAuthToken(authToken):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "editMsgFailed"}), trackerId)
            return

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

    async def updateDisplayname(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["displayname"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type":"updateDisplaynameFailed"}), trackerId)
            return

        dn = decryptedBody["displayname"].strip()

        if dn == "":
            await self.wsSendEncrypted(ws, orjson.dumps({"type":"updateDisplaynameFailed"}), trackerId)
            return

        if len(dn) > 30:
            await self.wsSendEncrypted(ws, orjson.dumps({"type":"updateDisplaynameFailed"}), trackerId)
            return

        if not self.setUserProperty(self.getUserIdFromAuthToken(authToken), "Displayname", dn):
            await self.wsSendEncrypted(ws, orjson.dumps({"type":"updateDisplaynameFailed"}), trackerId)
            return

        await self.wsSendEncrypted(ws, orjson.dumps({"type":"updateDisplaynameSuccess"}), trackerId)
        await self.wsBroadcastEncrypted(self.WS_CLIENTS, orjson.dumps({"type":"updateCachedDisplayname", "UID": self.getUserIdFromAuthToken(authToken), "Displayname": dn}))

    async def updateBirthday(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["bd"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type":"updateBirthdayFailed"}), trackerId)
            return

        bDay = decryptedBody["bd"]

        if not self.setUserProperty(self.getUserIdFromAuthToken(authToken), "Birthday", bDay):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "updateBirthdayFailed"}), trackerId)
            return

        await self.wsSendEncrypted(ws, orjson.dumps({"type": "updateBirthdaySuccess"}), trackerId)

    async def updatePronoun(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["pronoun"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type":"updatePronounFailed"}), trackerId)
            return

        pronouns = decryptedBody["pronoun"]

        if not self.setUserProperty(self.getUserIdFromAuthToken(authToken), "Pronouns", pronouns):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "updatePronounFailed"}), trackerId)
            return

        await self.wsSendEncrypted(ws, orjson.dumps({"type": "updatePronounSuccess"}), trackerId)
        await self.wsBroadcastEncrypted(self.WS_CLIENTS, data=orjson.dumps({"type": "updateCachedPronouns", "UID": self.getUserIdFromAuthToken(authToken), "Pronouns": pronouns}))

    async def updatePfp(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["pfp"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type":"updatePfpFailed"}), trackerId)
            return

        pfp = decryptedBody["pfp"]
        pfpResized = self.resizePfp(pfp)

        if not self.setUserProperty(self.getUserIdFromAuthToken(authToken), "PFP", pfpResized):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "updatePfpFailed"}), trackerId)
            return

        await self.wsSendEncrypted(ws, orjson.dumps({"type": "updatePfpSuccess"}), trackerId)
        await self.wsBroadcastEncrypted(self.WS_CLIENTS, orjson.dumps({"type": "updateCachedPfp", "UID": self.getUserIdFromAuthToken(authToken), "PFP": pfpResized}))

    async def updateBio(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["bio"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type":"updateBioFailed"}), trackerId)
            return

        bio = decryptedBody["bio"]

        if len(bio) > 1000:
            await self.wsSendEncrypted(ws, orjson.dumps({"type":"updateBioFailed"}), trackerId)
            return

        if not self.setUserProperty(self.getUserIdFromAuthToken(authToken), "Bio", bio):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "updateBioFailed"}), trackerId)
            return

        await self.wsSendEncrypted(ws, orjson.dumps({"type": "updateBioSuccess"}), trackerId)
        await self.wsBroadcastEncrypted(self.WS_CLIENTS, data=orjson.dumps({"type": "updateCachedBio", "UID": self.getUserIdFromAuthToken(authToken), "Bio": bio}))

    async def userSearch(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["unameSearch"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "userSearchFailed"}), trackerId)
            return

        usernameS = decryptedBody["unameSearch"].strip()

        if not self.validateUsername(usernameS):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "userSearchFailed"}), trackerId)
            return

        results = []
        for usr in self.users:
            if usernameS.lower() in usr["USRNAME"].lower() or usernameS.lower() in usr["Displayname"].lower():
                results.append(usr)

        if len(results) == 0:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "userSearchFailed"}), trackerId)
            return

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

    async def friendReq(self, ws, decryptedBody, authToken, trackerId):
        # TODO: Blocking users & stuff idk

        if not self.checkFields(decryptedBody, ["UID"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "friendReqFailed"}), trackerId)
            return

        targetUID = decryptedBody["UID"]
        selfUID = self.getUserIdFromAuthToken(authToken)

        targetInfo = self.getUserInfoFromUserId(targetUID)
        selfInfo = self.getUserInfoFromToken(authToken)

        if targetInfo is None or selfInfo is None:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "friendReqFailed"}), trackerId)
            return

        if targetUID == selfUID:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "friendReqFailed"}), trackerId)
            return


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
            return

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

    async def cancelFriendReq(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["UID"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "cancelFriendReqFailed"}), trackerId)
            return

        targetUID = decryptedBody["UID"]
        selfUID = self.getUserIdFromAuthToken(authToken)

        targetInfo = self.getUserInfoFromUserId(targetUID)
        selfInfo = self.getUserInfoFromToken(authToken)

        if targetInfo is None or selfInfo is None:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "cancelFriendReqFailed"}), trackerId)
            return

        if targetUID == selfUID:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "cancelFriendReqFailed"}), trackerId)
            return

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

    async def declineFriendReq(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["UID"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "declineFriendReqFailed"}), trackerId)
            return

        targetUID = decryptedBody["UID"]
        selfUID = self.getUserIdFromAuthToken(authToken)

        targetInfo = self.getUserInfoFromUserId(targetUID)
        selfInfo = self.getUserInfoFromToken(authToken)

        if targetInfo is None or selfInfo is None:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "declineFriendReqFailed"}), trackerId)
            return

        if targetUID == selfUID:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "declineFriendReqFailed"}), trackerId)
            return

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

    async def acceptFriendReq(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["UID"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "acceptFriendReqFailed"}), trackerId)
            return

        targetUID = decryptedBody["UID"]
        selfUID = self.getUserIdFromAuthToken(authToken)

        targetInfo = self.getUserInfoFromUserId(targetUID)
        selfInfo = self.getUserInfoFromToken(authToken)

        if targetInfo is None or selfInfo is None:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "acceptFriendReqFailed"}), trackerId)
            return

        if targetUID == selfUID:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "acceptFriendReqFailed"}), trackerId)
            return

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
            return

        if not ({"UID": targetUID, "type": "incoming"} in selfFriendReqs and {"UID": selfUID, "type": "outgoing"} in targetFriendReqs):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "acceptFriendReqFailed"}), trackerId)
            return

        cid = -1
        for cht in self.chats:
            if cht["Type"] == "dm" and selfUID in cht["Recipients"] and targetUID in cht["Recipients"]:
                cid = cht["CID"]
                break

        chatExists = True
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

    async def removeFriend(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["UID"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "removeFriendFailed"}), trackerId)
            return

        targetUID = decryptedBody["UID"]
        selfUID = self.getUserIdFromAuthToken(authToken)

        targetInfo = self.getUserInfoFromUserId(targetUID)
        selfInfo = self.getUserInfoFromToken(authToken)

        if targetInfo is None or selfInfo is None:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "removeFriendFailed"}), trackerId)
            return

        if targetUID == selfUID:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "removeFriendFailed"}), trackerId)
            return

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
            return

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

    async def createGC(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["include"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "createGCFailed"}), trackerId)
            return

        selfUID = self.getUserIdFromAuthToken(authToken)

        if not selfUID:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "createGCFailed"}), trackerId)
            return

        selfInfo = self.getUserInfoFromUserId(selfUID)

        if not selfInfo:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "createGCFailed"}), trackerId)
            return

        friendsList: list[int] = [friend["UID"] for friend in selfInfo["Friends"]]

        success = True
        for usr in decryptedBody["include"]:
            if not usr in friendsList:
                success = False
                break

        if not success:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "createGCFailed"}), trackerId)
            return

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
            return

        chatName = chatName[:-2]

        if len(chatName) > 100:
            chatName = f"{len(included)} people"

        self.chats.append({"CID": cid, "Type": "gc", "Name": chatName, "Recipients": included, "Owner": selfUID, "Icon": random.choice(self.DEFAULT_PFPS), "Time": int(time.time()), "messages": []})

        for ws2 in self.WS_CLIENTS:
            wsUID = getattr(ws2, "UID", None)
            targetInfo = self.getUserInfoFromUserId(wsUID)

            if wsUID is not None and targetInfo is not None and wsUID in included:
                await self.wsSendEncrypted(ws2, orjson.dumps({"type": "newChat", "chats": targetInfo["Chats"]}))

    async def updateGcInfo(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["CID", "icon", "name"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "updateGcInfoFailed"}), trackerId)
            return

        if not self.tokenInChat(authToken, decryptedBody["CID"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "updateGcInfoFailed"}), trackerId)
            return

        uid = self.getUserIdFromAuthToken(authToken)
        newChatName = decryptedBody["name"].strip()
        chat = self.getChatFromCID(decryptedBody["CID"])

        if chat is None or uid is None:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "updateGcInfoFailed"}), trackerId)
            return

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

        targetWS = []
        for ws2 in self.WS_CLIENTS:
            wsUID = getattr(ws2, "UID", None)
            targetInfo = self.getUserInfoFromUserId(wsUID)

            if wsUID is not None and targetInfo is not None and decryptedBody["CID"] in targetInfo["Chats"]:
                targetWS.append(ws2)

        await self.wsBroadcastEncrypted(targetWS, orjson.dumps({"type": "metaChatUpdate", "chat": chat}))

    async def addUsrToChat(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["CID", "users"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "addUsrFailed"}), trackerId)
            return

        if not self.tokenInChat(authToken, decryptedBody["CID"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "addUsrFailed"}), trackerId)
            return

        selfInfo = self.getUserInfoFromToken(authToken)
        uid = self.getUserIdFromUserInfo(selfInfo)
        chat = self.getChatFromCID(decryptedBody["CID"])

        if chat is None or uid is None or selfInfo is None:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "addUsrFailed"}), trackerId)
            return

        friendsList: list[int] = [friend["UID"] for friend in selfInfo["Friends"]]

        success = True
        for usr in decryptedBody["users"]:
            if not usr in friendsList:
                success = False
                break

        if not success:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "addUsrFailed"}), trackerId)
            return

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

        targetWS = []
        for ws2 in self.WS_CLIENTS:
            wsUID = getattr(ws2, "UID", None)
            targetInfo = self.getUserInfoFromUserId(wsUID)

            if wsUID is not None and targetInfo is not None:
                if wsUID in decryptedBody["users"]:
                    await self.wsSendEncrypted(ws2, orjson.dumps({"type": "newChat", "chats": targetInfo["Chats"]}))

                if decryptedBody["CID"] in targetInfo["Chats"]:
                    targetWS.append(ws2)

        await self.wsBroadcastEncrypted(targetWS, orjson.dumps({"type": "metaChatUpdate", "chat": chat}))

    async def addUsrToServer(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["SID", "users"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "addUsrServerFailed"}), trackerId)
            return

        if not self.tokenInServer(authToken, decryptedBody["SID"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "addUsrServerFailed"}), trackerId)
            return

        selfInfo = self.getUserInfoFromToken(authToken)
        uid = self.getUserIdFromUserInfo(selfInfo)
        server = self.getServerFromSID(decryptedBody["SID"])

        if server is None or uid is None or selfInfo is None:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "addUsrServerFailed"}), trackerId)
            return

        if uid != server["Owner"]:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "addUsrServerFailed"}), trackerId)
            return

        friendsList: list[int] = [friend["UID"] for friend in selfInfo["Friends"]]

        success = True
        for usr in decryptedBody["users"]:
            if not usr in friendsList:
                success = False
                break

        if not success:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "addUsrServerFailed"}), trackerId)
            return

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

    async def leaveGc(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["CID"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "leaveGcFailed"}), trackerId)
            return

        uid = self.getUserIdFromAuthToken(authToken)
        cid = decryptedBody["CID"]
        usrInfo = self.getUserInfoFromUserId(uid)
        chat = self.getChatFromCID(cid)

        if uid is None or usrInfo is None or chat is None:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "leaveGcFailed"}), trackerId)
            return

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
            return

        await self.wsSendEncrypted(ws, orjson.dumps({"type": "chatGone", "chats": usrInfo["Chats"]}), trackerId)

        if uid == chat["Owner"] and len(chat["Recipients"]) > 0:
            chat["Owner"] = chat["Recipients"][0]

        if len(chat["Recipients"]) == 0:
            self.delChat(chat)
            return

        chat["messages"].append({
            "SYSMSG": True,
            "MSGID": len(chat["messages"]),
            "TYPE": "usrLeaveGc",
            "TARGET": uid,
            "time": int(time.time())
        })

        targetWS = []
        for ws2 in self.WS_CLIENTS:
            wsUID = getattr(ws2, "UID", None)
            targetInfo = self.getUserInfoFromUserId(wsUID)

            if wsUID is not None and targetInfo is not None and cid in targetInfo["Chats"]:
                targetWS.append(ws2)

        await self.wsBroadcastEncrypted(targetWS, orjson.dumps({"type": "metaChatUpdate", "chat": chat}))

    async def rmUsrFromChat(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["CID", "UID"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "rmUsrFailed"}), trackerId)
            return

        targetUID = decryptedBody["UID"]
        targetInfo = self.getUserInfoFromUserId(targetUID)
        cid = decryptedBody["CID"]
        chat = self.getChatFromCID(cid)
        selfUID = self.getUserIdFromAuthToken(authToken)

        if targetInfo is None or chat is None:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "rmUsrFailed"}), trackerId)
            return

        if chat["Owner"] != selfUID or chat["Owner"] == targetUID:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "rmUsrFailed"}), trackerId)
            return

        failed = False
        try:
            targetInfo["Chats"].remove(cid)
            chat["Recipients"].remove(targetUID)
        except:
            failed = True
            traceback.print_exc()
            logging.warning("Failed to remove user from chat! UID: %i, CID: %i", targetUID, cid)

        if failed:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "rmUsrFailed"}), trackerId)
            return

        chat["messages"].append({
            "SYSMSG": True,
            "MSGID": len(chat["messages"]),
            "TYPE": "usrRemovedGc",
            "TARGET": selfUID,
            "TARGET2": targetUID,
            "time": int(time.time())
        })

        targetWS = []
        for ws2 in self.WS_CLIENTS:
            wsUID = getattr(ws2, "UID", None)
            targetInfo = self.getUserInfoFromUserId(wsUID)

            if wsUID is not None and targetInfo is not None:
                if cid in targetInfo["Chats"]:
                    targetWS.append(ws2)

                if wsUID == targetUID:
                    await self.wsSendEncrypted(ws2, orjson.dumps({"type": "chatGone", "chats": targetInfo["Chats"]}), trackerId)

        await self.wsBroadcastEncrypted(targetWS, orjson.dumps({"type": "metaChatUpdate", "chat": chat}))

    async def setRead(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["CID", "MSGID"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "setReadFailed"}), trackerId)
            return

        usrInfo = self.getUserInfoFromToken(authToken)

        if usrInfo is None:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "setReadFailed"}), trackerId)
            return

        usrInfo["ReadMsgs"][str(decryptedBody["CID"])] = decryptedBody["MSGID"]

        await self.wsSendEncrypted(ws, orjson.dumps({
            "type": "setReadSuccess",
            "readMsgs": usrInfo["ReadMsgs"]
        }), trackerId)

    async def createServer(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["icon", "name"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "createServerFailed"}), trackerId)
            return

        selfInfo = self.getUserInfoFromToken(authToken)

        if selfInfo is None:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "createServerFailed"}), trackerId)
            return

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

    async def reqServerMeta(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["SID"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "reqServerMetaFailed"}), trackerId)
            return

        server = self.getServerFromSID(decryptedBody["SID"])

        if not server:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "reqServerMetaFailed"}), trackerId)
            return

        await self.wsSendEncrypted(ws, orjson.dumps({
            "type": "reqServerMetaSuccess",
            "server": {
                "SID": server["SID"],
                "icon": server["Icon"],
                "name": server["Name"]
            }
        }), trackerId)

    async def reqServer(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["SID"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "reqServerFailed"}), trackerId)
            return

        if not self.tokenInServer(authToken, decryptedBody["SID"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "reqServerFailed"}), trackerId)
            return

        server = self.getServerFromSID(decryptedBody["SID"])

        if not server:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "reqServerFailed"}), trackerId)
            return

        await self.wsSendEncrypted(ws, orjson.dumps({
            "type": "reqServerSuccess",
            "server": server
        }), trackerId)

    async def newChannel(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["SID", "categoryID", "name"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "newChannelFailed"}), trackerId)
            return

        if not self.tokenInServer(authToken, decryptedBody["SID"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "newChannelFailed"}), trackerId)
            return

        server = self.getServerFromSID(decryptedBody["SID"])

        if server is None:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "newChannelFailed"}), trackerId)
            return

        userId = self.getUserIdFromAuthToken(authToken)

        if userId is None or not userId == server["Owner"]:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "newChannelFailed"}), trackerId)
            return

        category = None
        for cate in server["Categories"]:
            if cate["categoryID"] == decryptedBody["categoryID"]:
                category = cate
                break

        if category is None:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "newChannelFailed"}), trackerId)
            return

        channelName = decryptedBody["name"].strip()

        if len(channelName) == 0 or len(channelName) > 100:
            channelName = "New Channel"

        cid = len(self.chats)
        channel = {"CID": cid, "Type": "channel", "Server": decryptedBody["SID"], "Name": channelName, "Recipients": [], "Owner": server["Owner"], "Icon": config.EMPTY_IMG, "Time": int(time.time()), "messages": []}
        self.chats.append(channel)
        category["Chats"].append(cid)

        await self.wsSendEncrypted(ws, orjson.dumps({"type": "newChannelSuccess"}), trackerId)

        targetWS = []
        for ws2 in self.WS_CLIENTS:
            wsUID = getattr(ws2, "UID", None)
            targetInfo = self.getUserInfoFromUserId(wsUID)

            if wsUID is not None and targetInfo is not None and decryptedBody["SID"] in targetInfo["Servers"]:
                targetWS.append(ws2)

        await self.wsBroadcastEncrypted(targetWS, orjson.dumps({"type": "serverContentUpdate", "SID": server["SID"], "categories": server["Categories"]}))

    async def newCategory(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["SID", "name"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "newCategoryFailed"}), trackerId)
            return

        if not self.tokenInServer(authToken, decryptedBody["SID"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "newCategoryFailed"}), trackerId)
            return

        server = self.getServerFromSID(decryptedBody["SID"])

        if server is None:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "newCategoryFailed"}), trackerId)
            return

        userId = self.getUserIdFromAuthToken(authToken)

        if userId is None or not userId == server["Owner"]:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "newCategoryFailed"}), trackerId)
            return

        categoryName = decryptedBody["name"].strip()

        if len(categoryName) == 0 or len(categoryName) > 100:
            categoryName = "New Category"

        category = {"categoryID": len(server["Categories"]), "name": categoryName, "Chats": []}
        server["Categories"].append(category)

        await self.wsSendEncrypted(ws, orjson.dumps({"type": "newCategorySuccess"}), trackerId)

        targetWS = []
        for ws2 in self.WS_CLIENTS:
            wsUID = getattr(ws2, "UID", None)
            targetInfo = self.getUserInfoFromUserId(wsUID)

            if wsUID is not None and targetInfo is not None and decryptedBody["SID"] in targetInfo["Servers"]:
                targetWS.append(ws2)

        await self.wsBroadcastEncrypted(targetWS, orjson.dumps({"type": "serverContentUpdate", "SID": server["SID"], "categories": server["Categories"]}))

    async def acceptInvite(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["inviteID"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "acceptInviteFailed"}), trackerId)
            return

        uInfo = self.getUserInfoFromToken(authToken)
        uid = self.getUserIdFromUserInfo(uInfo)

        if uInfo is None or uid is None:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "acceptInviteFailed"}), trackerId)
            return

        valid, targetServer = self.isInviteValid(decryptedBody["inviteID"])

        if targetServer is None or not valid:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "acceptInviteFailed"}), trackerId)
            return

        targetServer["Users"].append(uid)
        uInfo["Servers"].append(targetServer["SID"])

        chat = self.getChatFromCID(targetServer["AnnouncementChat"])
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

        targetWS = []
        targetWS2 = []
        for ws2 in self.WS_CLIENTS:
            wsUID = getattr(ws2, "UID", None)
            targetInfo = self.getUserInfoFromUserId(wsUID)

            if wsUID is not None and targetInfo is not None and targetServer["SID"] in targetInfo["Servers"]:
                targetWS.append(ws2)

                if chat is not None and newMemberMsg is not None:
                    targetWS2.append(ws2)

        await self.wsBroadcastEncrypted(targetWS, orjson.dumps({"type": "serverMembersUpdate", "SID": targetServer["SID"], "members": targetServer["Users"]}))

        if chat is not None and newMemberMsg is not None:
            await self.wsBroadcastEncrypted(targetWS2, orjson.dumps({"type": "newMsg", "CID": chat["CID"], "message": newMemberMsg}))

    async def kickUsrFromServer(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["SID", "UID"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "kickUsrFailed"}), trackerId)
            return

        server = self.getServerFromSID(decryptedBody["SID"])

        if server is None:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "kickUsrFailed"}), trackerId)
            return

        uid = self.getUserIdFromAuthToken(authToken)

        if uid is None or not uid == server["Owner"]:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "kickUsrFailed"}), trackerId)
            return

        targetUsrInfo = self.getUserInfoFromUserId(decryptedBody["UID"])
        if targetUsrInfo is None or uid == targetUsrInfo["UID"] or not server["SID"] in targetUsrInfo["Servers"]:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "kickUsrFailed"}), trackerId)
            return

        failed = False
        try:
            targetUsrInfo["Servers"].remove(server["SID"])
            server["Users"].remove(decryptedBody["UID"])
        except:
            failed = True
            traceback.print_exc()
            logging.warning("Failed to kick user from server! Owner UID: %i, Target UID: %i, SID: %i", uid, decryptedBody["UID"], server["SID"])

        if failed:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "kickUsrFailed"}), trackerId)
            return

        for inv in copy.copy(self.invites):
            if inv["SID"] == server["SID"] and inv["TO"] == targetUsrInfo["UID"]:
                self.invites.remove(inv)

        await self.wsSendEncrypted(ws, orjson.dumps({"type": "kickUsrSuccess"}), trackerId)

        targetWS = []
        for ws2 in self.WS_CLIENTS:
            wsUID = getattr(ws2, "UID", None)
            targetInfo = self.getUserInfoFromUserId(wsUID)

            if wsUID is not None and targetInfo is not None:
                if server["SID"] in targetInfo["Servers"]:
                    targetWS.append(ws2)
                if wsUID == targetUsrInfo["UID"]:
                    await self.wsSendEncrypted(ws2, orjson.dumps({"type": "serverGone", "servers": targetUsrInfo["Servers"]}))
        await self.wsBroadcastEncrypted(targetWS, orjson.dumps({"type": "serverMembersUpdate", "SID": server["SID"], "members": server["Users"]}))

    async def leaveServer(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["SID"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "leaveServerFailed"}), trackerId)
            return

        server = self.getServerFromSID(decryptedBody["SID"])

        if server is None:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "leaveServerFailed"}), trackerId)
            return

        uInfo = self.getUserInfoFromToken(authToken)
        uid = self.getUserIdFromUserInfo(uInfo)

        if uid is None or uInfo is None:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "leaveServerFailed"}), trackerId)
            return

        failed = False
        try:
            uInfo["Servers"].remove(server["SID"])
            server["Users"].remove(uid)
        except:
            failed = True
            traceback.print_exc()
            logging.warning("Failed to leave server! UID: %i, SID: %i", uid, server["SID"])

        if failed:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "leaveServerFailed"}), trackerId)
            return

        for inv in copy.copy(self.invites):
            if inv["SID"] == server["SID"] and inv["TO"] == uid:
                self.invites.remove(inv)

        await self.wsSendEncrypted(ws, orjson.dumps({"type": "serverGone", "servers": uInfo["Servers"]}), trackerId)

        if len(server["Users"]) == 0:
            self.delServer(server)
            return

        elif uid == server["Owner"]:
            server["Owner"] = server["Users"][0]

        targetWS = []
        for ws2 in self.WS_CLIENTS:
            wsUID = getattr(ws2, "UID", None)
            targetInfo = self.getUserInfoFromUserId(wsUID)

            if wsUID is not None and targetInfo is not None:
                if server["SID"] in targetInfo["Servers"]:
                    targetWS.append(ws2)

        await self.wsBroadcastEncrypted(targetWS, orjson.dumps({"type": "serverMembersUpdate", "SID": server["SID"], "members": server["Users"]}))

    async def checkInviteValid(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["inviteID"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "checkInviteFailed", "isValid": False}), trackerId)
            return

        uInfo = self.getUserInfoFromToken(authToken)
        uid = self.getUserIdFromUserInfo(uInfo)

        if uInfo is None or uid is None:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "checkInviteFailed", "isValid": False}), trackerId)
            return

        valid, targetServer = self.isInviteValid(decryptedBody["inviteID"])
        if targetServer is None or not valid:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "checkInviteSuccess", "isValid": False}), trackerId)
            return

        await self.wsSendEncrypted(ws, orjson.dumps({"type": "checkInviteSuccess", "isValid": True}), trackerId)

    async def transferOwnershipGc(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["CID", "UID"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "transferOwnershipGcFailed"}), trackerId)
            return

        chat = self.getChatFromCID(decryptedBody["CID"])
        selfInfo = self.getUserInfoFromToken(authToken)
        selfUid = self.getUserIdFromUserInfo(selfInfo)

        if chat is None or selfUid != chat["Owner"] or chat["Owner"] == decryptedBody["UID"] or decryptedBody["UID"] not in chat["Recipients"]:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "transferOwnershipGcFailed"}), trackerId)
            return

        chat["Owner"] = decryptedBody["UID"]
        chat["messages"].append({
            "SYSMSG": True,
            "MSGID": len(chat["messages"]),
            "TYPE": "transferOwnership",
            "TARGET": decryptedBody["UID"],
            "time": int(time.time())
        })

        await self.wsSendEncrypted(ws, orjson.dumps({"type": "transferOwnershipGcSuccess"}), trackerId)

        targetWS = []
        for ws2 in self.WS_CLIENTS:
            wsUID = getattr(ws2, "UID", None)
            targetInfo = self.getUserInfoFromUserId(wsUID)

            if wsUID is not None and targetInfo is not None and chat["CID"] in targetInfo["Chats"]:
                targetWS.append(ws2)

        await self.wsBroadcastEncrypted(targetWS, orjson.dumps({"type": "metaChatUpdate", "chat": chat}))

    async def transferOwnershipServer(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["SID", "UID"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "transferOwnershipServerFailed"}), trackerId)
            return

        server = self.getServerFromSID(decryptedBody["SID"])
        selfInfo = self.getUserInfoFromToken(authToken)
        selfUid = self.getUserIdFromUserInfo(selfInfo)

        if server is None or selfUid != server["Owner"] or server["Owner"] == decryptedBody["UID"] or decryptedBody["UID"] not in server["Users"]:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "transferOwnershipServerFailed"}), trackerId)
            return

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

        targetWS = []
        targetWS2 = []
        for ws2 in self.WS_CLIENTS:
            wsUID = getattr(ws2, "UID", None)
            targetInfo = self.getUserInfoFromUserId(wsUID)

            if wsUID is not None and targetInfo is not None and server["SID"] in targetInfo["Servers"]:
                targetWS.append(ws2)

                if chat is not None and newMemberMsg is not None:
                    targetWS2.append(ws2)

        await self.wsBroadcastEncrypted(targetWS, orjson.dumps({"type": "serverOwnerUpdate", "SID": server["SID"], "owner": server["Owner"]}))

        if chat is not None and newMemberMsg is not None:
            await self.wsBroadcastEncrypted(targetWS2, orjson.dumps({"type": "newMsg", "CID": chat["CID"], "message": newMemberMsg}))

    async def moveChannel(self, ws, decryptedBody, authToken, trackerId):
        if not self.checkFields(decryptedBody, ["SID", "currCate", "currIdx", "targetCate", "targetIdx"]):
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "moveChannelFailed"}), trackerId)
            return

        server = self.getServerFromSID(decryptedBody["SID"])
        selfInfo = self.getUserInfoFromToken(authToken)
        selfUid = self.getUserIdFromUserInfo(selfInfo)

        if server is None or selfUid != server["Owner"]:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "moveChannelFailed"}), trackerId)
            return

        if len(server["Categories"]) <= decryptedBody["targetCate"] or len(server["Categories"]) <= decryptedBody["currCate"]:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "moveChannelFailed"}), trackerId)
            return

        currCate: dict | None = None
        targetCate: dict | None = None
        for cate in server["Categories"]:
            if cate["categoryID"] == decryptedBody["currCate"]:
                currCate = cate
            if cate["categoryID"] == decryptedBody["targetCate"]:
                targetCate = cate

        if currCate is None or targetCate is None:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "moveChannelFailed"}), trackerId)
            return

        currIdx = decryptedBody["currIdx"]
        targetIdx = decryptedBody["targetIdx"]
        cid = -1

        try:
            cid = currCate["Chats"].pop(currIdx)
        except IndexError:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "moveChannelFailed"}), trackerId)
            return

        if cid == -1:
            await self.wsSendEncrypted(ws, orjson.dumps({"type": "moveChannelFailed"}), trackerId)
            return

        if currCate["categoryID"] == targetCate["categoryID"] and currIdx < targetIdx:
            targetIdx -= 1

        targetCate["Chats"].insert(targetIdx, cid)

        await self.wsSendEncrypted(ws, orjson.dumps({"type": "moveChannelSuccess"}), trackerId)

        targetWS = []
        for ws2 in self.WS_CLIENTS:
            wsUID = getattr(ws2, "UID", None)
            targetInfo = self.getUserInfoFromUserId(wsUID)

            if wsUID is not None and targetInfo is not None and decryptedBody["SID"] in targetInfo["Servers"]:
                targetWS.append(ws2)

        await self.wsBroadcastEncrypted(targetWS, orjson.dumps({"type": "serverContentUpdate", "SID": server["SID"], "categories": server["Categories"]}))

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
                    decryptedBody, trackerId = self.decrypt(ws, msgDecoded)

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
                                cht["messages"].append({
                                    "SYSMSG": True,
                                    "MSGID": len(cht["messages"]),
                                    "TYPE": "newServerMember",
                                    "TARGET": uid,
                                    "time": int(time.time())
                                })

                                chat0 = cht
                                break

                        if chat0 is not None:
                            targetWS = []
                            for ws2 in self.WS_CLIENTS:
                                wsUID = getattr(ws2, "UID", None)
                                targetInfo = self.getUserInfoFromUserId(wsUID)

                                if wsUID is not None and wsUID in chat0["Recipients"]:
                                    targetWS.append(ws2)

                            await self.wsBroadcastEncrypted(targetWS, orjson.dumps({"type": "metaChatUpdate", "chat": chat0}))

                        self.RATELIMITED_IPS.append({"ip": ws.remote_address[0], "expire": time.time() + config.ACC_CREATION_COOLDOWN_SEC})

                        await self.wsSendEncrypted(ws, orjson.dumps({"type": "signupSuccess", "redirect": "/signupSuccess.html"}))

                    if decryptedBody["type"] == "logout":
                        usrName = self.getUsernameFromAuthToken(authToken)

                        if usrName:
                            self.VALID_TOKENS.pop(usrName, None)

                        await self.wsSendEncrypted(ws, orjson.dumps({"type": "logoutSuccess"}))
                        await ws.close()
                        break

                    if await self.checkAuthTokenEncrypted(ws, authToken):
                        reqType = decryptedBody["type"]

                        if reqType in self.webRequests:
                            await self.webRequests[reqType](ws, decryptedBody, authToken, trackerId)
                        else:
                            logging.warning("Unknown request type %s!", reqType)
                    else:
                        break
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
