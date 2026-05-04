import argparse
import http.client
import ssl
import sys
import urllib.parse

TARGET_HOST = "proxy"
TARGET_PORT = 8443


def normalize_hostname(raw: str) -> str:
  host = raw.strip().strip("[]").rstrip(".").lower()
  if not host:
    raise ValueError("host must not be empty")
  return host


def validate_target_url(raw_url: str) -> str:
  try:
    parsed = urllib.parse.urlsplit(raw_url)
    port = parsed.port or 443
  except ValueError as error:
    raise ValueError(f"invalid target URL: {error}") from error

  if parsed.scheme != "https":
    raise ValueError("target URL must use https")
  if parsed.username or parsed.password:
    raise ValueError("target URL must not include credentials")
  if parsed.fragment:
    raise ValueError("target URL must not include a fragment")
  if parsed.hostname is None:
    raise ValueError("target URL must include a host")

  host = normalize_hostname(parsed.hostname)
  if host != TARGET_HOST or port != TARGET_PORT:
    raise ValueError(f"target URL must point to https://{TARGET_HOST}:{TARGET_PORT}")

  path = parsed.path or "/"
  if not path.startswith("/"):
    raise ValueError("target URL path must start with '/'")
  target = f"{path}?{parsed.query}" if parsed.query else path
  if any(ch in target for ch in "\r\n\0"):
    raise ValueError("target URL path and query must not contain control characters")
  return target


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
  parser.add_argument("--url", required=True)
  parser.add_argument("--host", required=True)
  parser.add_argument("--ca-file")
  parser.add_argument("--timeout", type=float, default=5.0)
  args = parser.parse_args()

  try:
    target_path = validate_target_url(args.url)
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
    TARGET_PORT,
    context=context,
    timeout=args.timeout,
  )
  try:
    connection.request("GET", target_path, headers={"Host": host_header})
    response = connection.getresponse()
    sys.stdout.write(response.read().decode("utf-8"))
    if 200 <= response.status < 400:
      return 0
    return 1
  finally:
    connection.close()


if __name__ == "__main__":
  raise SystemExit(main())
