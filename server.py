print("""
##############
#  Open-LAN  #
##############
by Gigapixel Entertainment LLC
""")

print("""
REQUIRED IMPORTS:
(use pip to install)
websockets,
http,
io,
traceback,
threading,
secrets,
pathlib,
asyncio,
msgpack,
asyncio,
bcrypt,
psutil,
socket,
select,
base64,
time,
json,
sys,
ssl
""")

from websockets.asyncio.server import serve, broadcast
from http.server import BaseHTTPRequestHandler
from io import BytesIO
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
import sys
import ssl

PORT = 33333
WS_PORT = 33334
SOCKET_BACKLOG_NUM = 5
MAX_RETRY_ATTEMPTS = 10
RETRY_ATTEMPTS_CLEAR_AFTER_SEC = 120
NUM_ENCRYPT_ROUNDS = 15

CWD = pathlib.Path(__file__).resolve().parent
CA_CERT_DIR = CWD / "CA_CERT"
CSS_DIR = CWD / "CSS"
MEDIA_DIR = CWD / "Media/"
USERS_DIR = CWD / "Users/"

FILEEXT_TO_MIME = {
    ".png": "image/png",
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8"
}

WS_CLIENTS = set()
WS_CLIENT_LOCK = threading.Lock()

users = []
_userData = []

class HTTPRequestParser(BaseHTTPRequestHandler):
    def __init__(self, request_bytes):
        self.rfile = BytesIO(request_bytes)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        
        self.parse_request()

    def send_error(self, code, message=None, explain=None):
        self.error_code = code
        self.error_message = message

def loadUsers():
    print("Loading users")

    for usr in USERS_DIR.iterdir():
        if usr.is_file():
            with open(usr, "rb") as f:
                users.append(msgpack.unpackb(f.read()))
                f.close()
    
    print("Users loaded successfully")


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

def formatLoginResponse():
    token = secrets.token_urlsafe(256)
    return (
        "HTTP/1.1 200 OK\r\n"
        f"Set-Cookie: authToken={token}; Secure; HttpOnly; SameSite=Strict; Path=/\r\n"
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
    
    return "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n".encode("utf-8")


def closeSocket(sk: socket.socket):
    try:
        sk.shutdown(socket.SHUT_WR)
        sk.close()
    except:
        pass

def isSafePath(path: pathlib.Path):
    reqPath = path.resolve()

    if CA_CERT_DIR.resolve() in reqPath.parents:
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

        if isSafePath(pagePath):
            sk.sendall(formatHttpResponse(pagePath))
        else:
            sk.sendall(formatErrorResponse(400))
    elif method == "POST":
        contentLength = int(parsed.headers.get("Content-Length", 0))
        contentType = parsed.headers.get("Content-Type", "")
        body = parsed.rfile.read(contentLength).decode("utf-8")

        if page == "/api/login":
            if contentType == "application/json":
                bodyJson = json.loads(body)
                found = False
                
                for usr in users:
                    if usr["USRNAME"] == bodyJson["username"]:
                        if bcrypt.checkpw(base64.b64decode(bodyJson["password"]).encode("utf-8"), usr["PWD"].encode("utf-8")):
                            sk.sendall(formatLoginResponse())
                            found = True
                        else:
                            sk.sendall(formatErrorResponse(401))
                
                if not found:
                    sk.sendall(formatErrorResponse(401))
            else:
                sk.sendall(formatErrorResponse(400))

    closeSocket(sk)

async def wsHandler(ws):
    WS_CLIENTS.add(ws)
    print(f"Client Connected. (Now {len(WS_CLIENTS)})")

    try:
        async for message in ws:
            print(message)
            broadcast(WS_CLIENTS, message)

    except Exception:
        traceback.print_exc()
    finally:
        WS_CLIENTS.remove(ws)
        print(f"Client Disconnected. ({len(WS_CLIENTS)} remaining)")

async def shutdownWs(shutdownEvent):
    for ws in list(WS_CLIENTS):
        await ws.close()

    shutdownEvent.set()
    asyncio.get_running_loop().stop()

async def wsListen(ipAddrs, shutdownEvent):
    with serve(wsHandler, ipAddrs, WS_PORT):
        await shutdownEvent.wait()

def wsBootstrap(loop: asyncio.AbstractEventLoop):
    print("Websocket Bootstrap")
    asyncio.set_event_loop(loop)
    loop.run_forever()

if __name__ == "__main__":
    numErr = 0
    lastErr = time.time()

    loadUsers()
    
    ipAddrs = getIpAddrs()
    
    if len(ipAddrs) == 0:
        print("No valid network interfaces found! Please connect to a network!")
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

    asyncio.run_coroutine_threadsafe(wsListen(ipAddrs, wsShutdownEvent), wsLoop)
    
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

    for sk in socketList:
        sk.close()
