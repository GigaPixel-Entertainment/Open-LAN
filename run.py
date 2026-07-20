import subprocess
import httphelper
import threading
import datetime
import logging
import socket
import select
import sys
import ssl

from config import *

class MaintenancePage:
    def __init__(self, ipAddrs) -> None:
        self.ipAddrs: list[str] = ipAddrs
        self.socketList: list[socket.socket] = []
        self.listenerThread: threading.Thread | None = None
        self.keepListening: bool = False

        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certfile=CA_CERT_DIR / "server.crt", keyfile=CA_CERT_DIR / "server.key")
    
    def handleRequest(self, socket: socket.socket):
        fContents = None
        with open(CWD / "unavailable.html", "rb") as f:
            fContents = f.read()

        socket.sendall(httphelper.formatHttpHeaderRaw(503) + fContents)

    def listener(self) -> None:
        while self.keepListening:
            read_sockets, _, _ = select.select(self.socketList, [], [], 1)
                
            for notified_socket in read_sockets:
                cSocket, ip = notified_socket.accept()
                peekBytes = cSocket.recv(3, socket.MSG_PEEK)

                if len(peekBytes) < 3:
                    self.closeSocket(cSocket)
                    continue

                if peekBytes[0] == 0x16:
                    try:
                        with self.context.wrap_socket(cSocket, server_side=True) as secureSk:
                            self.handleRequest(secureSk)
                    except ssl.SSLError as e:
                        logging.warning(f"SSL Handshake failure: {e}")
                    except Exception as e:
                        logging.error(f"Error handling connection: {e}")
                elif peekBytes in (b'GET', b'POS', b'PUT', b'DEL', b'HEA', b'OPT'):
                    self.handleRequest(cSocket)
                else:
                    logging.warning(f"Unknown Protocol. Bytes: {peekBytes}")
                
                self.closeSocket(cSocket)

    def closeSocket(self, socket: socket.socket):
        try:
            socket.close()
        except:
            pass

    def startSocket(self) -> None:
        for addr in self.ipAddrs:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((addr, PORT))
            sock.listen(SOCKET_BACKLOG_NUM)

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

if __name__ == "__main__":
    print("Starting logger")
    logging.basicConfig(
        level=LOG_LEVEL,
        format="%(asctime)s [%(filename)s] [%(levelname)s]: %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(RUN_LOG_DIR / f"{datetime.datetime.now().strftime("%Y-%m-%d %H-%M-%S")}.log")
        ]
    )

    ipAddrs = httphelper.getIpAddrs()

    mp = MaintenancePage(ipAddrs)

    logging.info("Checking files")
    
    canContinue = True
    for file in IMPORTANT_FILES:
        if not file.exists():
            canContinue = False
            logging.error(f"{file} does not exist!")
    
    if not canContinue:
        logging.fatal("Some files are missing!")
        sys.exit(1)

    while True:
        logging.info("Starting server")
        mp.stopSocket()

        try:
            subprocess.run([sys.executable, CWD / "server.py"])
        except KeyboardInterrupt:
            pass
        except Exception:
            logging.error("An exception occured while running the server!", stack_info=True)
        
        mp.startSocket()
        restart = input("Restart the server? [y/n]")
        if restart.lower() != "y":
            break
    
    logging.info("Goodbye, World")