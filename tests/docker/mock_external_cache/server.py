"""Small, durable-in-process external cache handler for Docker integration tests."""

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


CAPABILITY = "cache-groups-v1"
STATE_LIMIT = 16 * 1024 * 1024
LOCK = threading.Lock()
ENTRIES = {}
GROUP_STATE = {}


def framed(metadata, body):
  encoded = json.dumps(metadata, separators=(",", ":")).encode("utf-8")
  return len(encoded).to_bytes(8, "big") + encoded + body


class Handler(BaseHTTPRequestHandler):
  protocol_version = "HTTP/1.1"

  def log_message(self, _format, *_args):
    return

  def do_POST(self):
    length = int(self.headers.get("content-length", "0"))
    body = self.rfile.read(length)
    operation = self.path.rstrip("/").rsplit("/", 1)[-1]
    try:
      if operation == "lookup":
        self.lookup(body)
      elif operation == "fill":
        self.fill(body)
      elif operation == "revalidate":
        self.revalidate(body)
      elif operation == "cache-group-state":
        self.group_state(body)
      else:
        self.respond(404)
    except (ValueError, KeyError, UnicodeDecodeError):
      self.respond(400)

  def respond(self, status, body=b"", content_type="application/json"):
    self.send_response(status)
    self.send_header("content-length", str(len(body)))
    if body:
      self.send_header("content-type", content_type)
    self.end_headers()
    if body:
      self.wfile.write(body)

  def lookup(self, body):
    request = json.loads(body)
    key = (request["policy"], request["partition"], request["base_key"], request["uri"], request["method"])
    with LOCK:
      value = ENTRIES.get(key)
    if value is None:
      self.respond(204)
      return
    metadata, payload = value
    self.respond(200, framed(metadata, payload), "application/octet-stream")

  def fill(self, body):
    if len(body) < 8:
      raise ValueError("missing frame")
    length = int.from_bytes(body[:8], "big")
    if length == 0 or length > STATE_LIMIT or len(body) < 8 + length:
      raise ValueError("invalid metadata frame")
    metadata = json.loads(body[8:8 + length])
    payload = body[8 + length:]
    if len(payload) != metadata["body_len"]:
      raise ValueError("body length mismatch")
    key = (metadata["policy"], metadata["partition"], metadata["base_key"], metadata["uri"], "GET")
    with LOCK:
      ENTRIES[key] = (metadata, payload)
    self.respond(204)

  def revalidate(self, body):
    metadata = json.loads(body)
    key = (metadata["policy"], metadata["partition"], metadata["base_key"], metadata["uri"], "GET")
    with LOCK:
      previous = ENTRIES.get(key)
      if previous is not None:
        ENTRIES[key] = (metadata, previous[1])
    self.respond(204)

  def group_state(self, body):
    request = json.loads(body)
    if request.get("protocol_version") != "oxibelt-external-cache-v1":
      raise ValueError("protocol version")
    if CAPABILITY not in request.get("required_capabilities", []):
      raise ValueError("capability required")
    key = request["key"]
    if not isinstance(key, str) or not key or len(key) > 256:
      raise ValueError("key")
    mode = request["mode"]
    with LOCK:
      if mode == "read":
        value = GROUP_STATE.get(key)
        response = {"capabilities": [CAPABILITY]}
        if value is not None:
          response["value_base64"] = base64.b64encode(value).decode("ascii")
      elif mode == "compare_exchange":
        expected = request.get("expected_base64")
        expected = None if expected is None else base64.b64decode(expected, validate=True)
        replacement = base64.b64decode(request["replacement_base64"], validate=True)
        if len(replacement) > STATE_LIMIT or (expected is not None and len(expected) > STATE_LIMIT):
          raise ValueError("state bound")
        current = GROUP_STATE.get(key)
        exchanged = (current is None) if expected is None else (current == expected)
        if exchanged:
          GROUP_STATE[key] = replacement
        response = {"exchanged": exchanged, "capabilities": [CAPABILITY]}
      else:
        raise ValueError("mode")
    self.respond(200, json.dumps(response, separators=(",", ":")).encode("utf-8"))


if __name__ == "__main__":
  ThreadingHTTPServer(("0.0.0.0", 18081), Handler).serve_forever()
