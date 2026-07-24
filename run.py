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

import subprocess
import threading
import datetime
import logging
import socket
import select
import sys
import ssl

import config
import httphelper

class HttpHandler:
    def __init__(self, ipAddrs) -> None:
        self.ipAddrs: list[str] = ipAddrs
        self.socketList: list[socket.socket] = []
        self.listenerThread: threading.Thread | None = None
        self.keepListening: bool = False

        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certfile=config.CA_CERT_DIR / "server.crt", keyfile=config.CA_CERT_DIR / "server.key")

    def handleRequest(self, socket: socket.socket):
        pass

    def listener(self) -> None:
        while self.keepListening:
            readSockets, _, _ = select.select(self.socketList, [], [], 1)

            for notifiedSocket in readSockets:
                cSocket, _ = notifiedSocket.accept()
                peekBytes = cSocket.recv(3, socket.MSG_PEEK)

                if len(peekBytes) < 3:
                    self.closeSocket(cSocket)
                    continue

                if peekBytes[0] == 0x16:
                    try:
                        with self.context.wrap_socket(cSocket, server_side=True) as secureSk:
                            self.handleRequest(secureSk)
                    except ssl.SSLError as e:
                        logging.warning("SSL Handshake failure: %s", e)
                    except Exception as e:
                        logging.error("Error handling connection: %s", e)
                elif peekBytes in (b'GET', b'POS', b'PUT', b'DEL', b'HEA', b'OPT'):
                    self.handleRequest(cSocket)
                else:
                    logging.warning("Unknown Protocol. Bytes: %s", peekBytes)

                self.closeSocket(cSocket)

    def closeSocket(self, socket: socket.socket):
        try:
            socket.close()
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
            self.listenerThread.join()

        for sock in self.socketList:
            self.closeSocket(sock)
        self.socketList = []

class MaintenancePage(HttpHandler):
    def __init__(self, ipAddrs) -> None:
        super().__init__(ipAddrs)

    def handleRequest(self, socket: socket.socket):
        fContents = None
        with open(config.CWD / "unavailable.html", "rb") as f:
            fContents = f.read()

        socket.sendall(httphelper.formatHttpHeaderRaw(503) + fContents)

class Dashboard(HttpHandler):
    def __init__(self, ipAddrs) -> None:
        super().__init__(ipAddrs)

    def handleRequest(self, socket: socket.socket):
        fContents = None
        with open(config.CWD / "index.html", "rb") as f:
            fContents = f.read()

        socket.sendall(httphelper.formatHttpHeaderRaw(503) + fContents)

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

    mp = MaintenancePage(ipAddrs)

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

        try:
            subprocess.run([sys.executable, config.CWD / "server.py"], check=False)
        except KeyboardInterrupt:
            pass
        except:
            logging.error("An exception occured while running the server!", stack_info=True)

        mp.startSocket(config.PORT)
        restart = input("Restart the server? [y/n]")
        if restart.lower() != "y":
            break

    logging.info("Goodbye, World")
