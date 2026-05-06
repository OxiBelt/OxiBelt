import argparse
import http.client
import json
import re
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

def main() -> int:
  parser = argparse.ArgumentParser()
  parser.add_argument("--target", choices=sorted(TARGET_PATHS))
  parser.add_argument("--path")
  parser.add_argument("--method", default="GET")
  parser.add_argument("--body", default="")
  parser.add_argument("--header", action="append", default=[])
  parser.add_argument("--host", required=True)
  parser.add_argument("--ca-file")
  parser.add_argument("--port", type=int, default=TARGET_PORT)
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

  connection = http.client.HTTPSConnection(
    TARGET_HOST,
    args.port,
    context=context,
    timeout=args.timeout,
  )
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
    connection.close()


if __name__ == "__main__":
  raise SystemExit(main())
