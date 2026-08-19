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

"""The dedicated run script that opens both the server & dashboard"""

from http import cookies
import subprocess
import threading
import datetime
import logging
import secrets
import base64
import socket
import select
import signal
import time
import sys
import ssl
import os

import bcrypt
import orjson
import psutil # type: ignore

import config
import httphelper

VALID_TOKENS = []
serverProc = None
restart = False
endProc = False

class HttpHandler:
    def __init__(self, addrs) -> None:
        self.ipAddrs: list[str] = addrs
        self.socketList: list[socket.socket] = []
        self.listenerThread: threading.Thread | None = None
        self.keepListening: bool = False

        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_cert_chain(certfile=config.SERVER_CERT_FILE, keyfile=config.SERVER_KEY_FILE)

    def handleRequest(self, sk: socket.socket):
        pass

    def handleRequestHttp(self, sk: socket.socket):
        self.handleRequest(sk)

    def httpThread(self, sk: socket.socket):
        peekBytes = sk.recv(3, socket.MSG_PEEK)

        if len(peekBytes) < 3:
            self.closeSocket(sk)
            return

        if peekBytes[0] == 0x16:
            try:
                with self.context.wrap_socket(sk, server_side=True) as secureSk:
                    self.handleRequest(secureSk)
            except ssl.SSLError as e:
                logging.warning("SSL Handshake failure: %s", e)
            except Exception as e:
                logging.error("Error handling connection: %s", e)
        elif peekBytes in (b'GET', b'POS', b'PUT', b'DEL', b'HEA', b'OPT'):
            self.handleRequestHttp(sk)
        else:
            logging.warning("Unknown Protocol. Bytes: %s", peekBytes)

        self.closeSocket(sk)

    def listener(self) -> None:
        while self.keepListening:
            readSockets, _, _ = select.select(self.socketList, [], [], 1)

            for notifiedSocket in readSockets:
                cSocket, _ = notifiedSocket.accept()
                threading.Thread(target=self.httpThread, args=(cSocket,), daemon=True).start()

    def closeSocket(self, sk: socket.socket):
        try:
            sk.close()
        except:
            pass

    def startSocket(self, port) -> None:
        for addr in self.ipAddrs:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((addr, port))
            sock.listen(config.SOCKET_BACKLOG_NUM)

            self.socketList.append(sock)

        self.keepListening = True
        self.listenerThread = threading.Thread(target=self.listener, daemon=True)
        self.listenerThread.start()

    def stopSocket(self) -> None:
        self.keepListening = False

        if self.listenerThread:
            self.listenerThread.join(10)

        for sock in self.socketList:
            self.closeSocket(sock)
        self.socketList = []

class MaintenancePage(HttpHandler):
    def handleRequest(self, sk: socket.socket):
        fContents = None
        with open(config.WEB_DIR / "unavailable.html", "rb") as f:
            fContents = f.read()

        sk.sendall(httphelper.formatHttpHeader(503, {
            "Connection": "close"
        }) + fContents)

class Dashboard(HttpHandler):
    def __init__(self, ipAddrs) -> None:
        self.serverOnline = False
        self.liveLogs = []
        super().__init__(ipAddrs)

    def handleRequest(self, sk: socket.socket):
        global restart
        global endProc

        request = sk.recv(4096)
        parsed = httphelper.HTTPRequestParser(request)

        if parsed.error_code:
            logging.error("[MAIN] Failed to parse %s", request)
            self.closeSocket(sk)
            return

        isValid = False
        path = parsed.path
        pathSplit = path.split("?")
        page = pathSplit[0]

        cookieHeader = parsed.headers.get("Cookie")

        if cookieHeader:
            parser = cookies.SimpleCookie()
            parser.load(cookieHeader)

            parsedCookies = {key: morsel.value for key, morsel in parser.items()}
            dashboardToken = parsedCookies.get("dashboardToken")

            if dashboardToken and dashboardToken in VALID_TOKENS:
                isValid = True

        authHeader = parsed.headers.get("Authorization")

        if authHeader and not isValid:
            authHeaderSplit = authHeader.split(" ")

            if authHeaderSplit[0] == "Basic":
                authSplit = base64.b64decode(authHeaderSplit[1]).decode("utf-8").split(":")
                username = authSplit[0]
                pwd = authSplit[1]

                if username == config.DASHBOARD_USERNAME:
                    if bcrypt.checkpw(pwd.encode("utf-8"), config.DASHBOARD_HASHED_PWD.encode("utf-8")):
                        isValid = True
                else:
                    bcrypt.checkpw(pwd.encode("utf-8"), DUMMY_HASH)

        if isValid:
            if page == "/api/reqInfo":
                logfile = parsed.headers.get("Log-File")
                logs = self.liveLogs

                if logfile and logfile != "live":
                    logfilePath = config.LOG_DIR / logfile

                    if (logfilePath.exists() and config.LOG_DIR.resolve() in logfilePath.resolve().parents):
                        with open(logfilePath, "r", encoding="utf-8") as f:
                            logs = f.read().split("\n")
                            f.close()

                mem = psutil.virtual_memory()
                disk = psutil.disk_usage("/")

                sk.sendall(httphelper.formatHttpHeader(200, {}) + orjson.dumps({
                    "CPU": psutil.cpu_percent(interval=None),
                    "MEM": round(mem.used / (1024**3), 1),
                    "MEM_TOTAL": round(mem.total / (1024**3), 1),
                    "DISK": round(disk.used / (1024**3)),
                    "DISK_TOTAL": round(disk.total / (1024**3)),
                    "ONLINE": self.serverOnline,
                    "HTTP_PORT": config.PORT,
                    "WSS_PORT": config.WSS_PORT,
                    "LOGS": logs,
                    "LOG_FILES": [str(f.relative_to(config.LOG_DIR)) for f in config.LOG_DIR.iterdir()]
                }))
            elif page == "/api/restart":
                stopServerProc()
                restart = True
                sk.sendall(httphelper.formatHttpHeader(200))
            elif page == "/api/exit":
                if serverProc:
                    stopServerProc()
                else:
                    endProc = True
                sk.sendall(httphelper.formatHttpHeader(200))
            elif page == "/api/purgeLogs":
                for logF in config.LOG_DIR.iterdir():
                    logF.unlink(True)
                sk.sendall(httphelper.formatHttpHeader(200))
            else:
                token = secrets.token_urlsafe(256)
                VALID_TOKENS.append(token)
                sk.sendall(httphelper.formatHttpResponse(parsed, config.WEB_DIR / "dashboard.html", extraHeaders={
                    "Set-Cookie": f"dashboardToken={token}; HttpOnly; SameSite=Strict; Path=/"
                }))
        else:
            sk.sendall(httphelper.formatHttpHeader(401, {
                "WWW-Authenticate": "Basic realm=\"Dashboard\", charset=\"UTF-8\"",
                "Connection": "close"
            }))

    def handleRequestHttp(self, sk: socket.socket):
        sk.sendall(httphelper.formatHttpResponse(None, config.WEB_DIR / "httpsRequired.html"))

def stopServerProc():
    if serverProc:
        if os.name == "nt":
            serverProc.send_signal(signal.CTRL_C_EVENT)
        elif os.name == "posix":
            serverProc.send_signal(signal.SIGINT)
        else:
            logging.error("What kinda operating system are ya running???")
            serverProc.terminate()
        serverProc.wait()

if __name__ == "__main__":
    print("Starting logger")
    config.RUN_LOG_DIR.mkdir(exist_ok=True)

    logging.basicConfig(
        level=config.LOG_LEVEL,
        format="%(asctime)s [%(filename)s] [%(levelname)s]: %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(config.RUN_LOG_DIR / f"{datetime.datetime.now().strftime("%Y-%m-%d %H-%M-%S")}.log")
        ]
    )

    ipAddrs = httphelper.getIpAddrs()

    DUMMY_HASH = bcrypt.hashpw(b"DUMMY HASH", bcrypt.gensalt(config.NUM_ENCRYPT_ROUNDS))

    mp = MaintenancePage(ipAddrs)

    dashboard = None
    if config.DASHBOARD_ENABLED:
        dashboard = Dashboard(ipAddrs)
        dashboard.startSocket(config.DASHBOARD_PORT)

    logging.info("Dashboard available on port %i", config.DASHBOARD_PORT)

    logging.info("Checking files")

    canContinue = True
    for file in config.IMPORTANT_FILES:
        if not file.exists():
            canContinue = False
            logging.error("%s does not exist!", file)

    if not canContinue:
        logging.fatal("Some files are missing!")
        sys.exit(1)

    while True:
        logging.info("Starting server")
        mp.stopSocket()

        if dashboard:
            dashboard.serverOnline = True
            dashboard.liveLogs = []

        try:
            with subprocess.Popen([sys.executable, config.CWD / "server.py"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1) as serverProc:
                for line in serverProc.stdout: # pyright: ignore[reportOptionalIterable]
                    print(line, end="", flush=True)

                    if dashboard:
                        dashboard.liveLogs.append(line)

                serverProc.wait()
        except KeyboardInterrupt:
            if serverProc:
                endProc = True
                stopServerProc()
                print()
        except:
            logging.error("An exception occured while running the server!", stack_info=True)
            if serverProc:
                serverProc.send_signal(signal.SIGINT)
                serverProc.wait()
                print()

        serverProc = None

        if dashboard:
            dashboard.serverOnline = False

        mp.startSocket(config.PORT)

        while not restart and not endProc:
            time.sleep(1)

        if endProc:
            break

        restart = False

    if dashboard:
        dashboard.stopSocket()

    logging.info("Goodbye, World")
