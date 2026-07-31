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

"""Open-LAN allows you to host your own messaging server on the Local Area Network"""

from io import BytesIO
import traceback
import threading
import datetime
import logging
import secrets
import pathlib
import asyncio
import socket
import select
import base64
import time
import copy
import sys
import ssl

from cryptography.fernet import Fernet

from PIL import Image
import msgpack

import config
import httphelper
import websocket

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
""", flush=True)

VALID_TOKENS = {}
SHORT_REDIRECT_TOKENS = {}

DEFAULT_PFPS: list[str] = []

def genSaveKey():
    key = Fernet.generate_key()
    with open(config.SAVE_KEY, "wb") as f:
        f.write(key)
        f.close()

def validateImgFile(path: pathlib.Path | BytesIO):
    """Validates an image file"""
    try:
        with Image.open(path) as img:
            img.verify()
            return True
    except:
        return False

def loadPfps():
    logging.info("[IO] Loading default PFPs")
    for pfp in config.PFP_DIR.iterdir():
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

    if not config.USERS_DIR.exists():
        config.USERS_DIR.mkdir()

    for usr in config.USERS_DIR.iterdir():
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

                if not "ReadMsgs" in userData:
                    userData["ReadMsgs"] = {}
                    for cht in userData["Chats"]:
                        userData["ReadMsgs"][str(cht)] = 0

                userData["Chats"] = list(set(userData["Chats"]))

                users.append(userData)
                f.close()


    logging.info("[IO] Users loaded")

def loadChats():
    logging.info("[IO] Loading chats")

    if not config.CHATS_DIR.exists():
        config.CHATS_DIR.mkdir()

    for chat in config.CHATS_DIR.iterdir():
        if chat.is_file() and chat.suffix == ".enc":
            try:
                with open(chat, "rb") as f:
                    fileContents = msgpack.unpackb(f.read())
                    metadata = fileContents["meta"]
                    name = fileContents["Name"]
                    recipients = (fileContents["Recipients"] if "Recipients" in fileContents else [])
                    owner = (fileContents["Owner"] if "Owner" in fileContents else (recipients[0] if len(recipients) > 0 else 0))
                    icon = (fileContents["Icon"] if "Icon" in fileContents else secrets.choice(DEFAULT_PFPS))
                    messages = fileContents["messages"]

                    for msg in messages:
                        if not "SYSMSG" in msg:
                            msg["content"] = fernet.decrypt(msg["content"]).decode("utf-16")

                    if metadata["CID"] == 0:
                        recipients = list(range(len(users)))

                    chats.append({"CID": metadata["CID"], "Type": metadata["Type"], "Time": metadata["Time"] if "Time" in metadata else int(time.time()), "Name": name, "Recipients": recipients, "Owner": owner, "Icon": icon, "messages": messages})
                    f.close()
            except:
                traceback.print_exc()
                logging.error("[IO] Failed to load chat! %s", chat.name)

    logging.info("[IO] Chats loaded")

def saveUsers():
    logging.info("[IO] Saving users")

    for usr in users:
        try:
            with open(config.USERS_DIR / f"{usr["USRNAME"]}.usr", "wb") as f:
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
            with open(config.CHATS_DIR / f"{chatID}.enc", "wb") as f:
                metadata = {"CID": chatID, "Type": chat["Type"], "Time": chat["Time"]}
                messages = []

                for msg in chat["messages"]:
                    messageSaving = copy.deepcopy(msg)

                    if not "SYSMSG" in messageSaving:
                        messageSaving["content"] = fernet.encrypt(messageSaving["content"].encode("utf-16"))

                    messages.append(messageSaving)

                packed: bytes | None = msgpack.packb({"meta":metadata,"Name":chat["Name"],"Recipients": chat["Recipients"], "Owner": chat["Owner"] if "Owner" in chat else (chat["Recipients"][0] if len(chat["Recipients"]) > 0 else 0), "Icon": chat["Icon"], "messages":messages})

                if packed:
                    f.write(packed)
                else:
                    logging.error("[IO] Failed to save chat! %s", chat)

                f.close()
        except:
            traceback.print_exc()
            logging.error("[IO] Failed to save chat! %s", chat)

    logging.info("[IO] Chats saved")

def formatLoginResponse(username: str, cloudflare: bool):
    if not username:
        return httphelper.formatHttpHeader(500)

    token = secrets.token_urlsafe(256)
    VALID_TOKENS[username] = {"TOKEN": token, "EXPIRES": time.time() + config.TOKEN_EXPIRES_SEC}

    return httphelper.formatHttpHeader(308, {
        "Set-Cookie": f"authToken={token}; HttpOnly; SameSite=Strict; {"Domain=gigapixel.cc;" if cloudflare else ""} Path=/",
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

    if len(pathSplit) > 1:
        for pair in pathSplit[1].split("&"):
            if len(pair.split("=")) > 1:
                uri[pair.split("=")[0]] = pair.split("=")[1]

    if method == "GET":
        if page == "/":
            page = "/index.html"

        pagePath = config.CWD / page.removeprefix("/")

        if page == "/api/wsurl":
            currUrl = parsed.headers.get("Domain-Url")

            if currUrl and "openlan.gigapixel.cc" in currUrl:
                # POV: Cloudflare
                sk.sendall(httphelper.formatHttpHeader(204, {
                    "Url": "ws://openlanws.gigapixel.cc",
                    "Connection": "close"
                }))
            else:
                sk.sendall(httphelper.formatHttpHeader(204, {
                    "Url": f"ws://{currUrl}:{config.WS_PORT}",
                    "Connection": "close"
                }))
        elif page == "/api/wssurl":
            currUrl = parsed.headers.get("Domain-Url")

            if currUrl and "openlan.gigapixel.cc" in currUrl:
                # POV: Cloudflare
                sk.sendall(httphelper.formatHttpHeader(204, {
                    "Url": "wss://openlanws.gigapixel.cc",
                    "Connection": "close"
                }))
            else:
                sk.sendall(httphelper.formatHttpHeader(204, {
                    "Url": f"wss://{currUrl}:{config.WSS_PORT}",
                    "Connection": "close"
                }))
        elif page == "/api/login":
            if "TK" in uri and "hostname" in uri:
                username = isValidRedirectToken(uri["TK"])

                if username is not None:
                    sk.sendall(formatLoginResponse(username, "gigapixel.cc" in uri["hostname"]))
        elif httphelper.isSafePath(pagePath):
            sk.sendall(httphelper.formatHttpResponse(parsed, pagePath, fernet))
        else:
            sk.sendall(httphelper.formatHttpHeader(404))
    elif method == "HEAD":
        if page == "/":
            page = "/index.html"

        pagePath = config.CWD / page.removeprefix("/")

        if httphelper.isSafePath(pagePath):
            sk.sendall(httphelper.formatHEADResponse(parsed, pagePath))
        else:
            sk.sendall(httphelper.formatHttpHeader(statusCode=404))

    closeSocket(sk)

def isValidRedirectToken(redirectToken):
    for k, v in SHORT_REDIRECT_TOKENS.items():
        if "TOKEN" in v and v["TOKEN"] == redirectToken and v["EXPIRES"] > time.time():
            SHORT_REDIRECT_TOKENS.pop(k)
            return k

    return None

def resizePfpBytes(pfpBytes: bytes):
    pfpStream = BytesIO(pfpBytes)

    if not validateImgFile(pfpStream):
        return secrets.choice(DEFAULT_PFPS)

    img = Image.open(pfpStream)
    imgFormat = img.format if img.format else "JPEG"
    resized = img.resize((256, 256), Image.Resampling.LANCZOS)
    outputStream = BytesIO()
    resized.save(outputStream, format=imgFormat)
    resizedBytes = outputStream.getvalue()
    resizedPfp = base64.b64encode(resizedBytes).decode("utf-8")
    return f"data:image/{imgFormat.lower()};base64,{resizedPfp}"

async def autosave(shutdownEvent: asyncio.Event, shutdownEventDone: asyncio.Event):
    try:
        while True:
            try:
                await asyncio.wait_for(asyncio.shield(shutdownEvent.wait()), config.AUTOSAVE_INTERVAL_SEC)
                break
            except asyncio.TimeoutError:
                logging.debug("[AS] Autosaving...")
                saveUsers()
                saveChats()
                logging.debug("[AS] Autosave done")
    except asyncio.CancelledError:
        pass

    logging.info("[AS] Autosave thread exited")
    shutdownEventDone.set()

async def shutdownAutosave(shutdownEvent: asyncio.Event, shutdownEventDone: asyncio.Event):
    logging.info("[AS] Stopping autosaves!")
    shutdownEvent.set()

    await shutdownEventDone.wait()

    asyncio.get_running_loop().stop()

def autosaveBootstrap(loop: asyncio.AbstractEventLoop):
    logging.info("[AS] Autosave Bootstrap")
    asyncio.set_event_loop(loop)
    loop.run_forever()

def httpThread(sk):
    peekBytes = sk.recv(3, socket.MSG_PEEK)

    if len(peekBytes) < 3:
        closeSocket(sk)
        return

    if peekBytes[0] == 0x16:
        try:
            with context.wrap_socket(sk, server_side=True) as secureSk:
                handleRequest(secureSk)
        except ssl.SSLError as e:
            logging.warning("[MAIN] SSL Handshake failure: %s", e)
        except Exception as e:
            logging.error("[MAIN] Error handling connection: %s", e)
    elif peekBytes in (b'GET', b'POS', b'PUT', b'DEL', b'HEA', b'OPT'):
        handleRequest(sk)
    else:
        logging.warning("[MAIN] Unknown Protocol. Bytes: %s", peekBytes)

    closeSocket(sk)

def readSaveKey():
    logging.debug("[IO] Reading save key")
    saveKey = None
    with open(config.SAVE_KEY, "rb") as f:
        saveKey = f.read()
        f.close()
    return saveKey

if __name__ == "__main__":
    print("[MAIN] Hello, world!", flush=True)

    numErr = 0
    lastErr = time.time()

    print("[IO] Generating missing directories", flush=True)
    config.CA_CERT_DIR.mkdir(exist_ok=True)
    config.CDN_DIR.mkdir(exist_ok=True)
    config.CHATS_DIR.mkdir(exist_ok=True)
    config.CSS_DIR.mkdir(exist_ok=True)
    config.JS_DIR.mkdir(exist_ok=True)
    config.LOG_DIR.mkdir(exist_ok=True)
    config.MEDIA_DIR.mkdir(exist_ok=True)
    config.PFP_DIR.mkdir(exist_ok=True)
    config.SECURITY_DIR.mkdir(exist_ok=True)
    config.USERS_DIR.mkdir(exist_ok=True)

    print("[MAIN] Starting logger", flush=True)
    logging.basicConfig(
        level=config.LOG_LEVEL,
        format="%(asctime)s [%(filename)s] [%(levelname)s]: %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(config.LOG_DIR / f"{datetime.datetime.now().strftime("%Y-%m-%d %H-%M-%S")}.log")
        ]
    )

    logging.info("[MAIN] Open-LAN v%s-%s %sinitalizing!", config.VER, config.STAGE, "(DEV) " if config.DEV else "")

    users = []
    chats = []

    if not config.SAVE_KEY.exists():
        logging.info("[IO] Generating new save key!")
        genSaveKey()

    saveKey = readSaveKey()
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
    context.load_cert_chain(certfile=config.CA_CERT_DIR / "server.crt", keyfile=config.CA_CERT_DIR / "server.key")

    ws = websocket.WS(VALID_TOKENS, SHORT_REDIRECT_TOKENS, DEFAULT_PFPS, chats, users, fernet, resizePfpBytes)

    socketList: list[socket.socket] = []
    for addr in ipAddrs:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((addr, config.PORT))
        sock.listen(config.SOCKET_BACKLOG_NUM)

        socketList.append(sock)
        logging.info("[MAIN] Listening on %s:%i", addr, config.PORT)

    logging.debug("[MAIN] It's time to get async")

    wsLoop = asyncio.new_event_loop()
    wsShutdownEvent = asyncio.Event()
    wsShutdownEventDone = asyncio.Event()
    wsThread = threading.Thread(target=ws.wsBootstrap, args=(wsLoop,), daemon=True)
    wsThread.start()

    wsFuture = asyncio.run_coroutine_threadsafe(ws.wsListen(ipAddrs, context, wsShutdownEvent, wsShutdownEventDone), wsLoop)

    autosaveLoop = asyncio.new_event_loop()
    autosaveShutdownEvent = asyncio.Event()
    autosaveShutdownEventDone = asyncio.Event()
    autosaveThread = threading.Thread(target=autosaveBootstrap, args=(autosaveLoop,), daemon=True)
    autosaveThread.start()

    autosaveFuture = asyncio.run_coroutine_threadsafe(autosave(autosaveShutdownEvent, autosaveShutdownEventDone), autosaveLoop)

    logging.debug("[MAIN] HTTP Primed and ready to go")
    logging.info("[MAIN] Connect via:")

    for addr in ipAddrs:
        logging.info("[MAIN] http://%s:%i/", addr, config.PORT)
        logging.info("[MAIN] https://%s:%i/", addr, config.PORT)

    while True:
        try:
            readSockets, _, _ = select.select(socketList, [], [])

            for notifiedSocket in readSockets:
                cSocket, _ = notifiedSocket.accept()
                threading.Thread(target=httpThread, args=(cSocket,), daemon=True).start()

        except KeyboardInterrupt:
            print("opythat!", flush=True)
            break
        except:
            traceback.print_exc()

            if time.time() - lastErr >= config.RETRY_ATTEMPTS_CLEAR_AFTER_SEC:
                numErr = 0

            if numErr < config.MAX_RETRY_ATTEMPTS:
                numErr += 1
                logging.warning("[MAIN] Attempting to recover (%i)", numErr)
            else:
                logging.fatal("[MAIN] Max Retry Attempts Exceeded")
                break

    logging.info("[MAIN] Shutting down Websocket thread (10s)")
    asyncio.run_coroutine_threadsafe(ws.shutdownWs(wsShutdownEvent, wsShutdownEventDone), loop=wsLoop)
    wsThread.join(10)

    if wsThread.is_alive():
        logging.warning("[MAIN] Forcibly shutting down Websocket thread!")
        wsLoop.close()

    logging.info("[MAIN] Shutting down autosave thread (10s)")
    asyncio.run_coroutine_threadsafe(shutdownAutosave(autosaveShutdownEvent, autosaveShutdownEventDone), loop=autosaveLoop)
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
