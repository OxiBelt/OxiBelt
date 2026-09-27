#!/usr/bin/env python3
"""Small HTTP/1 WebSocket echo peer for real-browser downstream tests."""

import base64
import binascii
import hashlib
import json
import os
import struct
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        return

    def do_GET(self):
        if self.path == "/ready":
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if urlsplit(self.path).path != "/ws/browser":
            self.send_error(404)
            return
        if self.headers.get("Upgrade", "").lower() != "websocket":
            self.send_error(400, "missing WebSocket upgrade")
            return
        if self.headers.get("Sec-WebSocket-Version") != "13":
            self.send_error(400, "unsupported WebSocket version")
            return
        key = self.headers.get("Sec-WebSocket-Key", "")
        try:
            if len(base64.b64decode(key, validate=True)) != 16:
                raise ValueError("invalid WebSocket key length")
        except (ValueError, binascii.Error):
            self.send_error(400, "invalid WebSocket key")
            return
        accept = base64.b64encode(hashlib.sha1(key.encode("ascii") + GUID).digest()).decode("ascii")
        self.send_response_only(101, "Switching Protocols")
        self.send_header("Connection", "Upgrade")
        self.send_header("Upgrade", "websocket")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        print(json.dumps({"event": "websocket-upstream-accepted", "path": self.path}), flush=True)
        self.connection.settimeout(15)
        while True:
            head = self.rfile.read(2)
            if len(head) != 2:
                return
            opcode = head[0] & 0x0F
            masked = bool(head[1] & 0x80)
            size = head[1] & 0x7F
            if size == 126:
                size = struct.unpack("!H", self.rfile.read(2))[0]
            elif size == 127:
                size = struct.unpack("!Q", self.rfile.read(8))[0]
            if not masked or size > 65536:
                return
            mask = self.rfile.read(4)
            data = bytearray(self.rfile.read(size))
            if len(data) != size:
                return
            for index in range(size):
                data[index] ^= mask[index % 4]
            response_opcode = 0xA if opcode == 0x9 else opcode
            self.connection.sendall(bytes([0x80 | response_opcode]) + (
                bytes([size]) if size < 126 else b"\x7e" + struct.pack("!H", size)
            ) + data)
            if opcode == 0x8:
                return


if __name__ == "__main__":
    ThreadingHTTPServer((
        os.environ.get("LISTEN_HOST", "127.0.0.1"),
        int(os.environ.get("LISTEN_PORT", "18081")),
    ), Handler).serve_forever()
