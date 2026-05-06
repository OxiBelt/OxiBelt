import json
import os
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


TLS_CERT_FILE = os.environ.get("TLS_CERT_FILE")
TLS_KEY_FILE = os.environ.get("TLS_KEY_FILE")
TLS_ENABLED = bool(TLS_CERT_FILE and TLS_KEY_FILE)
UPSTREAM_NAME = os.environ.get("UPSTREAM_NAME", "mock-upstream")
UPSTREAM_MARKER = "mock-upstream"


class EchoHandler(BaseHTTPRequestHandler):
  protocol_version = "HTTP/1.1"

  def do_GET(self):
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
    }
    encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
    self.send_response(status)
    self.send_header("content-type", "application/json")
    self.send_header("x-upstream-marker", UPSTREAM_MARKER)
    if query.get("set_cookie"):
      self.send_header("set-cookie", "upstream_session=present; Path=/")
    self.send_header("content-length", str(len(encoded)))
    self.end_headers()
    self.wfile.write(encoded)


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
