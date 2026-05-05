import json
import os
import re
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
TLS_CERT_FILE = os.environ.get("TLS_CERT_FILE")
TLS_KEY_FILE = os.environ.get("TLS_KEY_FILE")
TLS_ENABLED = bool(TLS_CERT_FILE and TLS_KEY_FILE)
UPSTREAM_NAME = os.environ.get("UPSTREAM_NAME", "mock-upstream")


def validate_header_name(raw_name):
  name = raw_name.strip()
  if not name:
    raise ValueError("response header name must not be empty")
  if not HEADER_NAME_RE.fullmatch(name):
    raise ValueError(f"invalid response header name {raw_name!r}")
  return name


def validate_header_value(raw_value):
  value = raw_value.strip()
  if "\r" in value or "\n" in value or "\0" in value:
    raise ValueError("response header value must not contain control characters")
  return value


def parse_response_header(raw_header):
  if ":" not in raw_header:
    return None

  name, value = raw_header.split(":", 1)
  return validate_header_name(name), validate_header_value(value)


UPSTREAM_MARKER = validate_header_value(UPSTREAM_NAME)


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
    extra_response_headers = []
    response_header_error = None
    try:
      for value in query.get("response_header", []):
        header = parse_response_header(value)
        if header:
          extra_response_headers.append(header)
    except ValueError as error:
      status = 400
      response_header_error = str(error)

    payload = {
      "upstream": UPSTREAM_NAME,
      "scheme": "https" if TLS_ENABLED else "http",
      "method": self.command,
      "path": self.path,
      "request_version": self.request_version,
      "headers": {key.lower(): value for key, value in self.headers.items()},
      "body": body,
    }
    if response_header_error:
      payload["error"] = response_header_error
    encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
    self.send_response(status)
    self.send_header("content-type", "application/json")
    self.send_header("x-upstream-marker", UPSTREAM_MARKER)
    for name, value in extra_response_headers:
      self.send_header(name, value)
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
