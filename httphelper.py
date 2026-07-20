from http.server import BaseHTTPRequestHandler
from http.client import responses
from cryptography.fernet import Fernet
from io import BytesIO
import zstandard
import mimetypes
import logging
import pathlib
import psutil # type: ignore
import brotli
import socket
import gzip

from config import *

class HTTPRequestParser(BaseHTTPRequestHandler):
    def __init__(self, request_bytes: bytes):
        self.rfile = BytesIO(request_bytes)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        
        self.parse_request()

    def send_error(self, code: int, message: str | None=None, explain: str | None=None):
        self.error_code = code
        self.error_message = message

def formatHttpHeaderRaw(statusCode: int, headerDict: dict | None = None):
    respPhrase = ""

    try:
        respPhrase = responses[statusCode]
    except:
        pass

    header = f"HTTP/1.1 {statusCode} {respPhrase}\r\n"

    if headerDict:
        for k, v in headerDict.items():
            header = header + f"{k}: {v}\r\n"
    
    return (header + "\r\n").encode("utf-8")

def formatErrorResponse(statusCode: int):
    return formatHttpHeaderRaw(statusCode, {"Connection": "close"})

def formatHEADResponse(filePath: pathlib.Path, acceptEncoding: list):
    if not filePath.is_file():
        logging.warning(f"[MAIN] Invalid fetch {filePath}!")

        return formatErrorResponse(404)
    
    mime = mimetypes.guess_file_type(filePath)[0] or "application/octet-stream"

    encoding = None
    if "text/" in mime:
        if "zstd" in acceptEncoding:
            encoding = "zstd"
        elif "br" in acceptEncoding:
            encoding = "br"
        elif "gzip" in acceptEncoding:
            encoding = "gzip"

    header = {"Content-Type": mime, "Connection": "close"}

    if encoding != None:
        header["Content-Encoding"] = encoding

    return formatHttpHeaderRaw(200, header)

def formatHttpResponse(filePath: pathlib.Path, acceptEncoding: list, fernet: Fernet | None = None):
    if not filePath.is_file():
        logging.warning(f"[MAIN] Invalid fetch {filePath}!")

        return formatErrorResponse(404)
    
    fileContents = bytes()
    with open(filePath, "rb") as f:
        fileContents = f.read()
        f.close()
    
    if CDN_DIR.resolve() in filePath.resolve().parents and fernet:
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
    

    header = {"Content-Type": mime, "Content-Length": len(fileContents), "Connection": "close"}

    if encoding != None:
        header["Content-Encoding"] = encoding

    return formatHttpHeaderRaw(200, header) + fileContents

def isSafePath(path: pathlib.Path):
    reqPath = path.resolve()

    for privDir in PRIVATE_DIRS:
        if privDir.resolve() in reqPath.parents or privDir.resolve() == reqPath:
            return False

    if CWD.resolve() in reqPath.parents:
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