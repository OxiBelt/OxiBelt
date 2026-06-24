import json
import os
import re
import ssl
import threading
import time
import gzip
from email.utils import parsedate_to_datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


TLS_CERT_FILE = os.environ.get("TLS_CERT_FILE")
TLS_KEY_FILE = os.environ.get("TLS_KEY_FILE")
TLS_ENABLED = bool(TLS_CERT_FILE and TLS_KEY_FILE)
UPSTREAM_NAME = os.environ.get("UPSTREAM_NAME", "mock-upstream")
UPSTREAM_MARKER = "mock-upstream"
ACCEPT_PROXY_PROTOCOL = os.environ.get("ACCEPT_PROXY_PROTOCOL", "0") == "1"
HTTP_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
REQUEST_COUNTS = {}
REQUEST_COUNTS_LOCK = threading.Lock()


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

  def do_HEAD(self):
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
    sequence_index = _sequence_index(parsed.path, query)
    header_delay_ms = _query_int(query, "header_delay_ms", 0)
    body_delay_ms = _query_int(query, "body_delay_ms", 0)
    body_split_at = _query_int(query, "body_split_at", -1)
    body_split_delay_ms = _query_int(query, "body_split_delay_ms", 0)
    chunked_response = query.get("chunked_response", ["0"])[0] == "1"
    status = 200
    if parsed.path.startswith("/status/"):
      try:
        status = int(parsed.path.split("/", 3)[2])
      except (IndexError, ValueError):
        status = 500
    if "status" in query:
      status = _query_int(query, "status", status)
    status = _sequence_value(query, "status_sequence", sequence_index, str(status))
    try:
      status = int(status)
    except (TypeError, ValueError):
      status = 500
    if parsed.path == "/health/options":
      self._handle_health_options(body)
      return
    cache_control = {
      "private": "private",
      "no-store": "no-store",
      "private-no-store": "private, no-store",
      "public": "public, max-age=60",
      "public-max-age-1": "public, max-age=1",
      "public-stale-revalidate": "public, max-age=1, stale-while-revalidate=30",
      "public-stale-error": "public, max-age=1, stale-if-error=30",
    }.get(query.get("cache_control", [""])[0])
    try:
      etag = _query_header(query, "etag")
      last_modified = _query_header(query, "last_modified")
      early_link = _query_header(query, "early_link", "</style.css>; rel=preload; as=style")
      content_type = _query_header(query, "content_type", "application/json")
      content_encoding = _query_header(query, "content_encoding")
      cache_control = _safe_header_value(
        "cache_control_value",
        query.get("cache_control_value", [cache_control])[0],
      )
      surrogate_control = _query_header(query, "surrogate_control")
      surrogate_key = _query_header(query, "surrogate_key")
      cache_tag = _query_header(query, "cache_tag")
      expires = _query_header(query, "expires")
      vary = _query_header(query, "vary")
    except ValueError as error:
      self.send_error(400, str(error))
      return
    if etag and self.headers.get("if-none-match") == etag:
      self.send_response(304)
      self.send_header("etag", etag)
      if last_modified:
        self.send_header("last-modified", last_modified)
      self.end_headers()
      return
    if last_modified and _if_modified_since_matches(
      self.headers.get("if-modified-since"),
      last_modified,
    ):
      self.send_response(304)
      self.send_header("last-modified", last_modified)
      if etag:
        self.send_header("etag", etag)
      self.end_headers()
      return
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
    body_value = _sequence_value(query, "body_sequence", sequence_index, query.get("body", [""])[0])
    if query.get("body_repeat"):
      repeat_count = int(query.get("body_repeat", ["0"])[0])
      repeat_char = query.get("body_repeat_char", ["x"])[0][:1] or "x"
      body_value = repeat_char * repeat_count
    encoded = body_value.encode("utf-8") or json.dumps(payload, sort_keys=True).encode("utf-8")
    if content_encoding:
      if content_encoding != "gzip":
        self.send_error(400, f"unsupported test content_encoding {content_encoding}")
        return
      encoded = gzip.compress(encoded)
    if header_delay_ms > 0:
      time.sleep(header_delay_ms / 1000.0)
    if query.get("early_hints"):
      self.send_response_only(103, "Early Hints")
      self.send_header("link", early_link)
      self.end_headers()
    self.send_response(status)
    self.send_header("content-type", content_type)
    self.send_header("x-upstream-marker", UPSTREAM_MARKER)
    if content_encoding:
      self.send_header("content-encoding", content_encoding)
    if any(key in query for key in ("sequence_key", "body_sequence", "status_sequence")):
      self.send_header("x-sequence-index", str(sequence_index))
    if query.get("set_cookie"):
      self.send_header("set-cookie", "upstream_session=present; Path=/")
    if cache_control:
      self.send_header("cache-control", cache_control)
    if surrogate_control:
      self.send_header("surrogate-control", surrogate_control)
    if surrogate_key:
      self.send_header("surrogate-key", surrogate_key)
    if cache_tag:
      self.send_header("cache-tag", cache_tag)
    if etag:
      self.send_header("etag", etag)
    if last_modified:
      self.send_header("last-modified", last_modified)
    if expires:
      self.send_header("expires", expires)
    if vary:
      self.send_header("vary", vary)
    if chunked_response:
      self.send_header("transfer-encoding", "chunked")
    else:
      self.send_header("content-length", str(len(encoded)))
    self.end_headers()
    if self.command == "HEAD" or status == 304:
      return
    if body_delay_ms > 0:
      time.sleep(body_delay_ms / 1000.0)
    if chunked_response:
      self._write_chunked_body(encoded, body_split_at, body_split_delay_ms)
    elif 0 <= body_split_at < len(encoded):
      self.wfile.write(encoded[:body_split_at])
      self.wfile.flush()
      if body_split_delay_ms > 0:
        time.sleep(body_split_delay_ms / 1000.0)
      self.wfile.write(encoded[body_split_at:])
    else:
      self.wfile.write(encoded)

  def _handle_health_options(self, body):
    errors = []
    if self.command != "POST":
      errors.append(f"method={self.command}")
    if self.headers.get("host") != "health.internal.example":
      errors.append(f"host={self.headers.get('host')}")
    if self.headers.get("x-oxibelt-health") != "active":
      errors.append(f"x-oxibelt-health={self.headers.get('x-oxibelt-health')}")
    if body != '{"probe":"ok"}':
      errors.append(f"body={body}")
    if errors:
      encoded = json.dumps({"errors": errors}, sort_keys=True).encode("utf-8")
      self.send_response(428)
      self.send_header("content-type", "application/json")
      self.send_header("content-length", str(len(encoded)))
      self.end_headers()
      self.wfile.write(encoded)
      return
    encoded = b"ready"
    self.send_response(200)
    self.send_header("content-type", "text/plain")
    self.send_header("content-length", str(len(encoded)))
    self.end_headers()
    self.wfile.write(encoded)

  def _write_chunked_body(self, encoded, body_split_at, body_split_delay_ms):
    if 0 <= body_split_at < len(encoded):
      chunks = [encoded[:body_split_at], encoded[body_split_at:]]
    else:
      chunks = [encoded]
    for index, chunk in enumerate(chunk for chunk in chunks if chunk):
      self.wfile.write(f"{len(chunk):x}\r\n".encode("ascii"))
      self.wfile.write(chunk)
      self.wfile.write(b"\r\n")
      self.wfile.flush()
      if index == 0 and body_split_delay_ms > 0:
        time.sleep(body_split_delay_ms / 1000.0)
    self.wfile.write(b"0\r\n\r\n")

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


def _sequence_index(path, query):
  if not any(key in query for key in ("sequence_key", "body_sequence", "status_sequence")):
    return 0
  key = query.get("sequence_key", [path])[0]
  with REQUEST_COUNTS_LOCK:
    index = REQUEST_COUNTS.get(key, 0)
    REQUEST_COUNTS[key] = index + 1
    return index


def _sequence_value(query, key, index, default):
  raw = query.get(key, [""])[0]
  if not raw:
    return default
  values = raw.split("|")
  return values[min(index, len(values) - 1)]


def _query_header(query, key, default=""):
  return _safe_header_value(key, query.get(key, [default])[0])


def _if_modified_since_matches(request_value, last_modified):
  if not request_value:
    return False
  try:
    return parsedate_to_datetime(request_value) >= parsedate_to_datetime(last_modified)
  except (TypeError, ValueError, IndexError):
    return request_value == last_modified


def _safe_header_value(key, value):
  if value is None:
    return None
  if "\r" in value or "\n" in value:
    raise ValueError(f"invalid {key} header value")
  return value


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
