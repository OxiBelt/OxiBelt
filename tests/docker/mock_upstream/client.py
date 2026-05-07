import argparse
import http.client
import json
import re
import socket
import ssl
import sys
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

def request_with_proxy_protocol(args, target_path, host_header, headers, body):
  sock = socket.create_connection((args.target_host, args.port), timeout=args.timeout)
  try:
    sock.sendall((args.proxy_protocol_line + "\r\n").encode("ascii"))
    if args.scheme == "https":
      if args.ca_file:
        context = ssl.create_default_context(cafile=args.ca_file)
      else:
        context = ssl.create_default_context()
      sock = context.wrap_socket(sock, server_hostname=args.target_host)

    request_lines = [
      f"{args.method} {target_path} HTTP/1.1",
      f"Host: {host_header}",
    ]
    has_content_length = False
    for name, value in headers.items():
      if name.lower() == "content-length":
        has_content_length = True
      request_lines.append(f"{name}: {value}")
    if not has_content_length:
      request_lines.append(f"Content-Length: {len(body)}")
    request_lines.append("Connection: close")
    request = ("\r\n".join(request_lines) + "\r\n\r\n").encode("utf-8") + body
    sock.sendall(request)

    response = http.client.HTTPResponse(sock)
    response.begin()
    response_body = response.read().decode("utf-8", "replace")
    return response, response_body
  finally:
    sock.close()

def read_http_response(sock):
  response = http.client.HTTPResponse(sock)
  response.begin()
  response_body = response.read().decode("utf-8", "replace")
  return response, response_body


def perform_connect_tunnel(args, host_header, target_path):
  sock = socket.create_connection((args.target_host, args.port), timeout=args.timeout)
  try:
    if args.scheme == "https":
      context = ssl.create_default_context(cafile=args.ca_file) if args.ca_file else ssl.create_default_context()
      sock = context.wrap_socket(sock, server_hostname=args.target_host)

    request = (
      f"CONNECT {host_header}:443 HTTP/1.1\r\n"
      f"Host: {host_header}:443\r\n"
      "Content-Length: 0\r\n"
      "\r\n"
    ).encode("ascii")
    sock.sendall(request)
    response = http.client.HTTPResponse(sock)
    response.begin()
    if response.status != 200:
      return response, response.read().decode("utf-8", "replace")

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
  sock = socket.create_connection((args.target_host, args.port), timeout=args.timeout)
  try:
    if args.scheme == "https":
      context = ssl.create_default_context(cafile=args.ca_file) if args.ca_file else ssl.create_default_context()
      sock = context.wrap_socket(sock, server_hostname=args.target_host)

    upgrade_token = args.upgrade_token
    request_lines = [
      f"GET {target_path} HTTP/1.1",
      f"Host: {host_header}",
      "Connection: Upgrade",
      f"Upgrade: {upgrade_token}",
      "Content-Length: 0",
    ]
    for name, value in headers.items():
      if name.lower() not in {"host", "connection", "upgrade", "content-length"}:
        request_lines.append(f"{name}: {value}")
    sock.sendall(("\r\n".join(request_lines) + "\r\n\r\n").encode("utf-8"))

    response = http.client.HTTPResponse(sock)
    response.begin()
    if response.status != 101:
      response.read()
      return response, ""
    sock.sendall(body)
    sock.settimeout(args.timeout)
    upgraded = sock.recv(4096).decode("utf-8", "replace")
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
  args = parser.parse_args()

  try:
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

  if args.ca_file:
    context = ssl.create_default_context(cafile=args.ca_file)
  else:
    context = ssl.create_default_context()

  connection = None
  try:
    headers = {"Host": host_header}
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
      headers[name] = value

    body = args.body.encode("utf-8")
    if args.connect_tunnel:
      response, response_body = perform_connect_tunnel(
        args,
        host_header,
        target_path,
      )
    elif args.upgrade_token:
      response, response_body = perform_upgrade(
        args,
        host_header,
        target_path,
        headers,
        body,
      )
    elif args.proxy_protocol_line:
      response, response_body = request_with_proxy_protocol(
        args,
        target_path,
        host_header,
        headers,
        body,
      )
    else:
      if args.scheme == "https":
        connection = http.client.HTTPSConnection(
          args.target_host,
          args.port,
          context=context,
          timeout=args.timeout,
        )
      else:
        connection = http.client.HTTPConnection(
          args.target_host,
          args.port,
          timeout=args.timeout,
        )
      connection.putrequest(
        args.method,
        target_path,
        skip_host=True,
        skip_accept_encoding=True,
      )
      has_content_length = False
      for name, value in headers.items():
        if name.lower() == "content-length":
          has_content_length = True
        connection.putheader(name, value)
      if not has_content_length:
        connection.putheader("Content-Length", str(len(body)))
      connection.endheaders(body)
      response = connection.getresponse()
      response_body = response.read().decode("utf-8", "replace")
    if args.dump_response_json:
      sys.stdout.write(json.dumps({
        "status": response.status,
        "reason": response.reason,
        "headers": {key.lower(): value for key, value in response.getheaders()},
        "body": response_body,
      }, sort_keys=True))
    else:
      sys.stdout.write(response_body)

    if args.expect_status is not None:
      return 0 if response.status == args.expect_status else 1
    if 200 <= response.status < 400:
      return 0
    return 1
  finally:
    if connection:
      connection.close()


if __name__ == "__main__":
  raise SystemExit(main())
