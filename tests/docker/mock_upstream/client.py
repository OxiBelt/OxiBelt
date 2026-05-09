import argparse
import base64
import http.client
import json
import re
import socket
import ssl
import sys
import time
import urllib.parse

TARGET_HOST = "proxy"
TARGET_PORT = 8443
TARGET_PATHS = {
  "http-ping": "/app/ping?source=http",
  "secure-health": "/secure/v1/health?source=https",
  "waf-blocked": "/app/blocked",
}
HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


def validate_header_name(raw_name: str) -> str:
  name = raw_name.strip()
  if not name:
    raise ValueError("header name must not be empty")
  if not HEADER_NAME_RE.fullmatch(name):
    raise ValueError(f"invalid header name {raw_name!r}")
  return name


def validate_http_token(raw_value: str, field_name: str) -> str:
  value = raw_value.strip()
  if not value:
    raise ValueError(f"{field_name} must not be empty")
  if not HEADER_NAME_RE.fullmatch(value):
    raise ValueError(f"invalid {field_name} {raw_value!r}")
  return value


def validate_header_value(raw_value: str) -> str:
  value = raw_value.strip()
  if "\r" in value or "\n" in value or "\0" in value:
    raise ValueError("header value must not contain control characters")
  return value


def validate_origin_form_path(raw_path: str) -> str:
  if not raw_path:
    raise ValueError("request path must not be empty")
  if "\r" in raw_path or "\n" in raw_path or "\0" in raw_path:
    raise ValueError("request path must not contain control characters")

  parsed = urllib.parse.urlsplit(raw_path)
  if parsed.scheme or parsed.netloc:
    raise ValueError("request path must be an origin-form path, not an absolute URL")
  if not parsed.path.startswith("/"):
    raise ValueError("request path must start with '/'")

  path = urllib.parse.quote(parsed.path, safe="/!$&'()*+,;=:@%~-._")
  query = urllib.parse.quote(parsed.query, safe="/!$&'()*+,;=:@?%~-._")
  return urllib.parse.urlunsplit(("", "", path, query, ""))


def validate_host_header(raw_host: str) -> str:
  if not raw_host:
    raise ValueError("Host header must not be empty")
  if any(ch.isspace() or ch == "\0" for ch in raw_host):
    raise ValueError("Host header must not contain whitespace or control characters")

  try:
    parsed = urllib.parse.urlsplit(f"//{raw_host}")
    _ = parsed.port
  except ValueError as error:
    raise ValueError(f"invalid Host header: {error}") from error

  if parsed.hostname is None or parsed.username or parsed.password:
    raise ValueError("Host header must contain only a host and optional port")

  return raw_host


def validate_proxy_protocol_line(raw_line: str) -> str:
  if not raw_line:
    raise ValueError("PROXY protocol line must not be empty")
  if "\r" in raw_line or "\n" in raw_line or "\0" in raw_line:
    raise ValueError("PROXY protocol line must not contain control characters")
  try:
    raw_line.encode("ascii")
  except UnicodeEncodeError as error:
    raise ValueError("PROXY protocol line must be ASCII") from error
  if not raw_line.startswith("PROXY "):
    raise ValueError("PROXY protocol line must start with 'PROXY '")
  return raw_line


def create_tls_context(ca_file):
  if ca_file:
    context = ssl.create_default_context(cafile=ca_file)
  else:
    context = ssl.create_default_context()
  context.minimum_version = ssl.TLSVersion.TLSv1_2
  context.options |= ssl.OP_NO_COMPRESSION
  return context


def open_proxy_socket(args, proxy_protocol_line=None):
  sock = socket.create_connection((args.target_host, args.port), timeout=args.timeout)
  try:
    if proxy_protocol_line:
      sock.sendall((proxy_protocol_line + "\r\n").encode("ascii"))
    if args.scheme == "https":
      sock = create_tls_context(args.ca_file).wrap_socket(sock, server_hostname=args.target_host)
    return sock
  except Exception:
    sock.close()
    raise


def send_http_request(
  sock,
  method,
  target_path,
  host_header,
  headers,
  body,
  connection,
  slow_body_delay_ms=0,
  hold_after_headers_ms=0,
  body_split_at=None,
  body_split_delay_ms=0,
):
  request_lines = [
    f"{method} {target_path} HTTP/1.1",
    f"Host: {host_header}",
  ]
  has_content_length = False
  for name, value in headers:
    if name.lower() == "host":
      continue
    if name.lower() == "content-length":
      has_content_length = True
    request_lines.append(f"{name}: {value}")
  if not has_content_length:
    request_lines.append(f"Content-Length: {len(body)}")
  request_lines.append(f"Connection: {connection}")
  head = ("\r\n".join(request_lines) + "\r\n\r\n").encode("utf-8")
  sock.sendall(head)
  if slow_body_delay_ms > 0 and body:
    time.sleep(slow_body_delay_ms / 1000.0)
  if body_split_at is None:
    sock.sendall(body)
  else:
    split_at = max(0, min(body_split_at, len(body)))
    sock.sendall(body[:split_at])
    if body_split_delay_ms > 0:
      time.sleep(body_split_delay_ms / 1000.0)
    sock.sendall(body[split_at:])
  return read_http_response(sock, hold_after_headers_ms)


def request_direct(args, target_path, host_header, headers, body):
  sock = open_proxy_socket(args)
  try:
    return send_http_request(
      sock,
      args.method,
      target_path,
      host_header,
      headers,
      body,
      args.connection,
      args.slow_body_delay_ms,
      args.hold_after_headers_ms,
      args.body_split_at,
      args.body_split_delay_ms,
    )
  finally:
    sock.close()


def request_with_proxy_protocol(args, target_path, host_header, headers, body):
  sock = open_proxy_socket(args, args.proxy_protocol_line)
  try:
    return send_http_request(
      sock,
      args.method,
      target_path,
      host_header,
      headers,
      body,
      args.connection,
      args.slow_body_delay_ms,
      args.hold_after_headers_ms,
      args.body_split_at,
      args.body_split_delay_ms,
    )
  finally:
    sock.close()

def read_http_response(sock, hold_after_headers_ms=0):
  response = http.client.HTTPResponse(sock)
  response.begin()
  if hold_after_headers_ms > 0:
    time.sleep(hold_after_headers_ms / 1000.0)
  return response, response.read()


def perform_connect_tunnel(args, host_header, target_path, headers):
  sock = open_proxy_socket(args)
  try:
    request_lines = [
      f"CONNECT {host_header}:443 HTTP/1.1",
      f"Host: {host_header}:443",
      "Content-Length: 0",
    ]
    for name, value in headers:
      if name.lower() not in {"host", "content-length"}:
        request_lines.append(f"{name}: {value}")
    request = ("\r\n".join(request_lines) + "\r\n\r\n").encode("utf-8")
    sock.sendall(request)
    response = http.client.HTTPResponse(sock)
    response.begin()
    if response.status != 200:
      return response, response.read()
    if args.hold_after_headers_ms > 0:
      time.sleep(args.hold_after_headers_ms / 1000.0)

    tunneled = (
      f"GET {target_path} HTTP/1.1\r\n"
      "Host: tunnel-upstream\r\n"
      "Connection: close\r\n"
      "Content-Length: 0\r\n"
      "\r\n"
    ).encode("ascii")
    sock.sendall(tunneled)
    return read_http_response(sock)
  finally:
    sock.close()


def perform_upgrade(args, host_header, target_path, headers, body):
  sock = open_proxy_socket(args)
  try:
    upgrade_token = args.upgrade_token
    request_lines = [
      f"GET {target_path} HTTP/1.1",
      f"Host: {host_header}",
      "Connection: Upgrade",
      f"Upgrade: {upgrade_token}",
      "Content-Length: 0",
    ]
    for name, value in headers:
      if name.lower() not in {"host", "connection", "upgrade", "content-length"}:
        request_lines.append(f"{name}: {value}")
    sock.sendall(("\r\n".join(request_lines) + "\r\n\r\n").encode("utf-8"))

    response = http.client.HTTPResponse(sock)
    response.begin()
    if response.status != 101:
      return response, response.read()
    if args.hold_after_headers_ms > 0:
      time.sleep(args.hold_after_headers_ms / 1000.0)
    sock.sendall(body)
    sock.settimeout(args.timeout)
    upgraded = sock.recv(4096)
    return response, upgraded
  finally:
    sock.close()


def main() -> int:
  parser = argparse.ArgumentParser()
  parser.add_argument("--target", choices=sorted(TARGET_PATHS))
  parser.add_argument("--target-host", default=TARGET_HOST)
  parser.add_argument("--path")
  parser.add_argument("--method", default="GET")
  parser.add_argument("--body", default="")
  parser.add_argument("--header", action="append", default=[])
  parser.add_argument("--host", required=True)
  parser.add_argument("--ca-file")
  parser.add_argument("--port", type=int, default=TARGET_PORT)
  parser.add_argument("--scheme", choices=("http", "https"), default="https")
  parser.add_argument("--proxy-protocol-line")
  parser.add_argument("--connect-tunnel", action="store_true")
  parser.add_argument("--upgrade-token")
  parser.add_argument("--dump-response-json", action="store_true")
  parser.add_argument("--expect-status", type=int)
  parser.add_argument("--timeout", type=float, default=5.0)
  parser.add_argument("--connection", choices=("close", "keep-alive"), default="close")
  parser.add_argument("--slow-body-delay-ms", type=int, default=0)
  parser.add_argument("--hold-after-headers-ms", type=int, default=0)
  parser.add_argument("--body-split-at", type=int)
  parser.add_argument("--body-split-delay-ms", type=int, default=0)
  args = parser.parse_args()

  try:
    args.method = validate_http_token(args.method, "HTTP method")
    if args.upgrade_token:
      args.upgrade_token = validate_http_token(args.upgrade_token, "Upgrade token")
    if args.proxy_protocol_line:
      args.proxy_protocol_line = validate_proxy_protocol_line(args.proxy_protocol_line)
    if args.path:
      target_path = validate_origin_form_path(args.path)
    elif args.target:
      target_path = TARGET_PATHS[args.target]
    else:
      raise ValueError("either --target or --path is required")
    host_header = validate_host_header(args.host)
  except ValueError as error:
    sys.stderr.write(f"{error}\n")
    return 2

  try:
    headers = [("Host", host_header)]
    for item in args.header:
      if ":" not in item:
        sys.stderr.write(f"invalid header {item!r}; expected Name: value\n")
        return 2
      name, value = item.split(":", 1)
      try:
        name = validate_header_name(name)
        value = validate_header_value(value)
      except ValueError as error:
        sys.stderr.write(f"{error}\n")
        return 2
      headers.append((name, value))

    body = args.body.encode("utf-8")
    if args.connect_tunnel:
      response, response_body_bytes = perform_connect_tunnel(
        args,
        host_header,
        target_path,
        headers,
      )
    elif args.upgrade_token:
      response, response_body_bytes = perform_upgrade(
        args,
        host_header,
        target_path,
        headers,
        body,
      )
    elif args.proxy_protocol_line:
      response, response_body_bytes = request_with_proxy_protocol(
        args,
        target_path,
        host_header,
        headers,
        body,
      )
    else:
      response, response_body_bytes = request_direct(
        args,
        target_path,
        host_header,
        headers,
        body,
      )
    response_body = response_body_bytes.decode("utf-8", "replace")
    if args.dump_response_json:
      sys.stdout.write(json.dumps({
        "status": response.status,
        "reason": response.reason,
        "headers": {key.lower(): value for key, value in response.getheaders()},
        "body": response_body,
        "body_base64": base64.b64encode(response_body_bytes).decode("ascii"),
      }, sort_keys=True))
    else:
      sys.stdout.write(response_body)

    if args.expect_status is not None:
      return 0 if response.status == args.expect_status else 1
    if 200 <= response.status < 400:
      return 0
    return 1
  except OSError as error:
    sys.stderr.write(f"{error}\n")
    return 1


if __name__ == "__main__":
  raise SystemExit(main())
