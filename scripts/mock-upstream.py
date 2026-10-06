#!/usr/bin/env python3
"""Tiny upstream (HTTP + WebSocket echo) for trying the reverse proxy:
  python3 scripts/mock-upstream.py 9000"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def _reply(self, body: bytes):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        self._reply(f"upstream GET {self.path}\nX-Forwarded-For: {self.headers.get('X-Forwarded-For')}\n".encode())
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(n)
        self._reply(f"upstream POST {self.path} ({len(data)} bytes)\n".encode())

# --- WebSocket echo (no frame parsing needed: Vajra tunnels raw bytes) ---
import base64, hashlib, struct

def ws_frames(sock):
    """Yield (opcode, payload) for client frames; answers close/ping minimally."""
    f = sock.makefile("rb")
    while True:
        h = f.read(2)
        if len(h) < 2: return
        op, ln = h[0] & 0x0F, h[1] & 0x7F
        if ln == 126: ln = struct.unpack(">H", f.read(2))[0]
        elif ln == 127: ln = struct.unpack(">Q", f.read(8))[0]
        mask = f.read(4) if h[1] & 0x80 else b"\0\0\0\0"
        data = bytearray(f.read(ln))
        for i in range(len(data)): data[i] ^= mask[i % 4]
        yield op, bytes(data)

def ws_frame(op, payload):
    n = len(payload)
    head = bytes([0x80 | op]) + (bytes([n]) if n < 126 else b"\x7e" + struct.pack(">H", n) if n < 65536 else b"\x7f" + struct.pack(">Q", n))
    return head + payload

_do_GET = H.do_GET
def do_GET(self):
    if self.headers.get("Upgrade", "").lower() != "websocket":
        return _do_GET(self)
    key = self.headers["Sec-WebSocket-Key"].encode()
    accept = base64.b64encode(hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest()).decode()
    self.send_response(101, "Switching Protocols")
    self.send_header("Upgrade", "websocket"); self.send_header("Connection", "Upgrade")
    self.send_header("Sec-WebSocket-Accept", accept); self.end_headers()
    self.wfile.flush()
    for op, data in ws_frames(self.connection):
        if op == 8: self.connection.sendall(ws_frame(8, data)); break
        if op == 9: self.connection.sendall(ws_frame(10, data)); continue
        self.connection.sendall(ws_frame(op, data))
    self.close_connection = True
H.do_GET = do_GET

ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 9000), H).serve_forever()
