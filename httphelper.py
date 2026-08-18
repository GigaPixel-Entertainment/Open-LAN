# Copyright (C) 2026  GigaPixel Entertainment
# Licensed under the GNU General Public License v3, see <https://www.gnu.org/licenses/>.

"""HTTP helper functions for parsing and formatting HTTP responses"""

from http.server import BaseHTTPRequestHandler
from http.client import responses
from io import BytesIO
import mimetypes
import logging
import pathlib
import string
import random
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

def randStrUrlSafe(length: int) -> str:
    pool = string.ascii_letters + string.digits + "-_"
    return ''.join(random.choices(pool, k=length))

def formatHttpHeaderRaw(headerDict: dict) -> str:
    header = ""
    for k, v in headerDict.items():
        header = header + f"{k}: {v}\r\n"

    return header

def formatHttpHeader(statusCode: int, headerDict: dict | None = None) -> bytes:
    respPhrase = ""

    try:
        respPhrase = responses[statusCode]
    except:
        pass

    header = f"HTTP/1.1 {statusCode} {respPhrase}\r\n"

    if headerDict:
        header += formatHttpHeaderRaw(headerDict)

    return (header + "\r\n").encode("utf-8")

def formatHEADResponse(parsed: HTTPRequestParser, filePath: pathlib.Path) -> bytes:
    if not filePath.is_file():
        logging.warning("[MAIN] Invalid fetch %s!", filePath)

        return formatHttpHeader(404)

    acceptEncoding = []
    if parsed:
        acceptEncoding = [s.strip() for s in parsed.headers.get("Accept-Encoding", "").split(",")]

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

    return formatHttpHeader(200, header)

def formatHttpRange(fileContents: bytes, rangeStr: str) -> bytes | None:
    fullFileLen = len(fileContents)
    rangeSplit = rangeStr.split("-")

    if len(rangeSplit) != 2:
        return None

    firstSplit = rangeSplit[0].strip()
    lastSplit = rangeSplit[1].strip()
    contentRange = f"{firstSplit if firstSplit != "" else 0}-{lastSplit if lastSplit != "" else fullFileLen - 1}"

    if firstSplit == "":
        lastSplit = int(lastSplit)

        if lastSplit >= fullFileLen or lastSplit < 0:
            return None

        fileContents = fileContents[:lastSplit + 1]
    elif lastSplit == "":
        firstSplit = int(firstSplit)

        if firstSplit >= fullFileLen or firstSplit < 0:
            return None

        fileContents = fileContents[firstSplit:]
    else:
        firstSplit = int(firstSplit)
        lastSplit = int(lastSplit)

        if firstSplit >= fullFileLen or firstSplit < 0:
            return None

        if lastSplit >= fullFileLen or lastSplit < 0:
            return None

        if lastSplit < firstSplit:
            return None

        fileContents = fileContents[firstSplit:lastSplit + 1]

    return formatHttpHeaderRaw({
        "Content-Length": len(fileContents),
        "Content-Range": f"bytes {contentRange}/{fullFileLen}"
    }).encode("utf-8") + b"\r\n" + fileContents

def formatHttpResponse(parsed: HTTPRequestParser | None, filePath: pathlib.Path, fernet: Fernet | None = None, extraHeaders: dict | None = None) -> bytes:
    if not filePath.is_file() or not isSafePath(filePath):
        logging.warning("[MAIN] Invalid fetch %s!", filePath)

        return formatHttpHeader(404)

    acceptEncoding = []
    if parsed:
        acceptEncoding = [s.strip() for s in parsed.headers.get("Accept-Encoding", "").split(",")]

    if extraHeaders is None:
        extraHeaders = {}

    fileContents = bytes()
    with open(filePath, "rb") as f:
        fileContents = f.read()
        f.close()

    if fernet and config.CDN_DIR.resolve() in filePath.resolve().parents:
        fileContents = fernet.decrypt(fileContents)

    mime = mimetypes.guess_file_type(filePath)[0] or "application/octet-stream"

    if parsed and parsed.headers.get("Range"):
        reqRange = parsed.headers.get("Range")

        if reqRange:
            if reqRange.startswith("bytes="):
                rangesNoPrefix = reqRange.split("bytes=", 1)[1]
                ranges = rangesNoPrefix.split(",")

                if len(ranges) == 1:
                    header = {"Content-Type": mime, "Accept-Ranges": "bytes", "Connection": "close"}

                    final = formatHttpHeader(206, header | extraHeaders).rstrip(b"\r\n") + b"\r\n"
                    currRng = formatHttpRange(fileContents, ranges[0])

                    if not currRng:
                        return formatHttpHeader(416, {
                            "Content-Range": f"*/{len(fileContents)}"
                        })

                    final += currRng

                    return final

                # Multipart Ranges
                # Boundary must be max 70 characters
                boundary = f"Open-LAN-Boundary_{randStrUrlSafe(52)}"
                body = f"--{boundary}"
                fail = False

                for currRng in ranges:
                    currHead = formatHttpRange(fileContents, currRng)

                    if not currHead:
                        fail = True
                        break

                    body += f"\r\n{currHead.decode("utf-8")}\r\n--{boundary}"

                if fail:
                    return formatHttpHeader(416, {
                        "Content-Range": f"*/{len(fileContents)}"
                    })

                body += "--"

                header = {"Content-Type": f"multipart/byteranges; boundary={boundary}", "Content-Length": len(body), "Accept-Ranges": "bytes", "Connection": "close"}
                final = formatHttpHeader(206, header | extraHeaders) + body.encode("utf-8")

                return final

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

    header = {"Content-Type": mime, "Content-Length": len(fileContents), "Accept-Ranges": "bytes", "Connection": "close"}

    if encoding is not None:
        header["Content-Encoding"] = encoding

    return formatHttpHeader(200, header | extraHeaders) + fileContents

def isSafePath(path: pathlib.Path) -> bool:
    reqPath = path.resolve()

    for privDir in config.PRIVATE_DIRS:
        if privDir.resolve() in reqPath.parents or privDir.resolve() == reqPath:
            return False

    if config.CWD.resolve() in reqPath.parents:
        return True

    return False

def getIpAddrs() -> list[str]:
    ipList = []
    interfaces = psutil.net_if_addrs()

    for interfaceName, interfaceAddresses in interfaces.items():
        for address in interfaceAddresses:
            if address.family == socket.AF_INET and not address.address.startswith("127."):
                logging.debug("[MAIN] Interface: %s -> IP Address: %s", interfaceName, address.address)
                ipList.append(address.address)

    return ipList
