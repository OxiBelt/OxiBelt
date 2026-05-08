import json
import os
import re
import ssl
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


TLS_CERT_FILE = os.environ.get("TLS_CERT_FILE")
TLS_KEY_FILE = os.environ.get("TLS_KEY_FILE")
TLS_ENABLED = bool(TLS_CERT_FILE and TLS_KEY_FILE)
UPSTREAM_NAME = os.environ.get("UPSTREAM_NAME", "mock-upstream")
UPSTREAM_MARKER = "mock-upstream"
ACCEPT_PROXY_PROTOCOL = os.environ.get("ACCEPT_PROXY_PROTOCOL", "0") == "1"
HTTP_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


class EchoHandler(BaseHTTPRequestHandler):
  protocol_version = "HTTP/1.1"

  def setup(self):
    super().setup()
    self.proxy_protocol_line = None
    if not ACCEPT_PROXY_PROTOCOL:
      return
    try:
      peeked = self.rfile.peek(5)
    except (AttributeError, OSError):
      return
    if not peeked.startswith(b"PROXY"):
      return
    line = self.rfile.readline(108)
    self.proxy_protocol_line = line.decode("ascii", "replace").rstrip("\r\n")

  def do_GET(self):
    if self._handle_upgrade():
      return
    self._handle()

  def do_POST(self):
    self._handle()

  def log_message(self, format, *args):
    return

  def _handle(self):
    body_length = int(self.headers.get("content-length", "0"))
    body = self.rfile.read(body_length).decode("utf-8", "replace") if body_length else ""
    parsed = urlsplit(self.path)
    query = parse_qs(parsed.query)
    header_delay_ms = _query_int(query, "header_delay_ms", 0)
    body_delay_ms = _query_int(query, "body_delay_ms", 0)
    status = 200
    if parsed.path.startswith("/status/"):
      try:
        status = int(parsed.path.split("/", 3)[2])
      except (IndexError, ValueError):
        status = 500
    payload = {
      "upstream": UPSTREAM_NAME,
      "scheme": "https" if TLS_ENABLED else "http",
      "method": self.command,
      "path": self.path,
      "request_version": self.request_version,
      "headers": {key.lower(): value for key, value in self.headers.items()},
      "body": body,
      "proxy_protocol_line": self.proxy_protocol_line,
    }
    encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
    if header_delay_ms > 0:
      time.sleep(header_delay_ms / 1000.0)
    self.send_response(status)
    self.send_header("content-type", "application/json")
    self.send_header("x-upstream-marker", UPSTREAM_MARKER)
    if query.get("set_cookie"):
      self.send_header("set-cookie", "upstream_session=present; Path=/")
    cache_control = {
      "private": "private",
      "no-store": "no-store",
      "private-no-store": "private, no-store",
      "public": "public, max-age=60",
    }.get(query.get("cache_control", [""])[0])
    if cache_control:
      self.send_header("cache-control", cache_control)
    self.send_header("content-length", str(len(encoded)))
    self.end_headers()
    if body_delay_ms > 0:
      time.sleep(body_delay_ms / 1000.0)
    self.wfile.write(encoded)

  def _handle_upgrade(self):
    upgrade = self.headers.get("upgrade")
    connection = self.headers.get("connection", "")
    if not upgrade or "upgrade" not in connection.lower():
      return False
    if not HTTP_TOKEN_RE.fullmatch(upgrade):
      self.send_error(400, "invalid Upgrade token")
      return True

    self.send_response_only(101, "Switching Protocols")
    self.send_header("Connection", "Upgrade")
    self.send_header("Upgrade", upgrade)
    self.end_headers()
    self.connection.settimeout(5.0)
    data = self.connection.recv(4096)
    self.connection.sendall(b"upgraded:" + data)
    return True


def _query_int(query, key, default):
  try:
    return int(query.get(key, [str(default)])[0])
  except (TypeError, ValueError):
    return default


def main():
  port = int(os.environ.get("LISTEN_PORT", "18080"))
  server = ThreadingHTTPServer(("0.0.0.0", port), EchoHandler)
  if TLS_ENABLED:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.options |= ssl.OP_NO_COMPRESSION
    context.load_cert_chain(TLS_CERT_FILE, TLS_KEY_FILE)
    server.socket = context.wrap_socket(server.socket, server_side=True)

  server.serve_forever()


if __name__ == "__main__":
  main()
