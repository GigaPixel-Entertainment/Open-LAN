# Copyright (C) 2026  GigaPixel Entertainment
# Licensed under the GNU General Public License v3, see <https://www.gnu.org/licenses/>.

"""HTTP helper functions for parsing and formatting HTTP responses"""

from http.server import BaseHTTPRequestHandler
from http.client import responses
from io import BytesIO
import mimetypes
import logging
import pathlib
import socket
import gzip

from cryptography.fernet import Fernet
import zstandard
import psutil # type: ignore
import brotli

import config

class HTTPRequestParser(BaseHTTPRequestHandler):
    # pylint: disable=super-init-not-called
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
        logging.warning("[MAIN] Invalid fetch %s!", filePath)

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

    header = {"Content-Type": mime, "Connection": "close", "Access-Control-Allow-Origin": "*", "Accept-Ranges": "bytes"}

    if encoding is not None:
        header["Content-Encoding"] = encoding

    return formatHttpHeaderRaw(200, header)

def formatHttpResponse(parsed: HTTPRequestParser | None, filePath: pathlib.Path, acceptEncoding: list, fernet: Fernet | None = None, extraHeaders: dict | None = None):
    if not filePath.is_file():
        logging.warning("[MAIN] Invalid fetch %s!", filePath)

        return formatErrorResponse(404)

    if extraHeaders is None:
        extraHeaders = {}

    fileContents = bytes()
    with open(filePath, "rb") as f:
        fileContents = f.read()
        f.close()

    if fernet and config.CDN_DIR.resolve() in filePath.resolve().parents:
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
            fileContents = zstandard.compress(fileContents, level=config.ZSTD_COMPRESSION_LEVEL)
        elif encoding == "br":
            fileContents = brotli.compress(fileContents, quality=config.BROTLI_COMPRESSION_LEVEL)
        elif encoding == "gzip":
            fileContents = gzip.compress(fileContents, compresslevel=config.GZIP_COMPRESSION_LEVEL)

    fullFileLen = len(fileContents)

    if parsed and parsed.headers.get("Range"):
        reqRange = parsed.headers.get("Range")

        if reqRange:
            if reqRange.startswith("bytes="):
                rangesNoPrefix = reqRange.split("bytes=", 1)[1]
                ranges = rangesNoPrefix.split(",")

                if len(ranges) == 1:
                    contentRange = rangesNoPrefix
                    rangeSplit = ranges[0].split("-")
                    firstSplit = rangeSplit[0].strip()
                    lastSplit = rangeSplit[1].strip()

                    if firstSplit == "":
                        lastSplit = int(lastSplit)
                        fileContents = fileContents[:lastSplit + 1]
                        contentRange = f"0{contentRange}"
                    elif lastSplit == "":
                        firstSplit = int(firstSplit)
                        fileContents = fileContents[firstSplit:]
                        contentRange = f"{contentRange}{fullFileLen - 1}"
                    else:
                        firstSplit = int(firstSplit)
                        lastSplit = int(lastSplit)
                        fileContents = fileContents[firstSplit:lastSplit + 1]

                    header = {"Content-Type": mime, "Content-Length": len(fileContents), "Content-Range": f"bytes {contentRange}/{fullFileLen}", "Accept-Ranges": "bytes", "Connection": "close"}

                    if encoding is not None:
                        header["Content-Encoding"] = encoding

                    return formatHttpHeaderRaw(206, header | extraHeaders) + fileContents
                else:
                    # TODO: multipart ranges
                    pass


    header = {"Content-Type": mime, "Content-Length": len(fileContents), "Accept-Ranges": "bytes", "Connection": "close"}

    if encoding is not None:
        header["Content-Encoding"] = encoding

    return formatHttpHeaderRaw(200, header | extraHeaders) + fileContents

def isSafePath(path: pathlib.Path) -> bool:
    reqPath = path.resolve()

    for privDir in config.PRIVATE_DIRS:
        if privDir.resolve() in reqPath.parents or privDir.resolve() == reqPath:
            return False

    if config.CWD.resolve() in reqPath.parents:
        return True

    return False

def getIpAddrs():
    ipList = []
    interfaces = psutil.net_if_addrs()

    for interfaceName, interfaceAddresses in interfaces.items():
        for address in interfaceAddresses:
            if address.family == socket.AF_INET and not address.address.startswith("127."):
                logging.debug("[MAIN] Interface: %s -> IP Address: %s", interfaceName, address.address)
                ipList.append(address.address)

    return ipList
