import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit


EXPECTED_TOKEN = os.environ.get("EXPECTED_TOKEN", "matrix-nomad-token")
SERVICE_NAME = os.environ.get("SERVICE_NAME", "app")
NAMESPACE = os.environ.get("NAMESPACE", "default")
INITIAL_ENDPOINT_IP = os.environ.get("INITIAL_ENDPOINT_IP", "127.0.0.1")
UPDATED_ENDPOINT_IP = os.environ.get("UPDATED_ENDPOINT_IP", "127.0.0.1")
INITIAL_PORT = int(os.environ.get("INITIAL_ENDPOINT_PORT", "18080"))
UPDATED_PORT = int(os.environ.get("UPDATED_ENDPOINT_PORT", "18081"))
MODIFIED_DELAY_SECONDS = float(os.environ.get("MODIFIED_DELAY_SECONDS", "3.0"))


def service_entry(entry_id, address, port):
  return {
    "ID": entry_id,
    "ServiceName": SERVICE_NAME,
    "Namespace": NAMESPACE,
    "Address": address,
    "Port": port,
  }


class NomadHandler(BaseHTTPRequestHandler):
  protocol_version = "HTTP/1.1"

  def do_GET(self):
    if self.headers.get("x-nomad-token") != EXPECTED_TOKEN:
      self._send_json(403, {"error": "forbidden"}, "1")
      return

    parsed = urlsplit(self.path)
    expected_path = f"/v1/service/{SERVICE_NAME}"
    if unquote(parsed.path) != expected_path:
      self._send_json(404, {"error": "not found"}, "1")
      return

    query = parse_qs(parsed.query)
    namespaces = query.get("namespace", [NAMESPACE])
    if namespaces[0] != NAMESPACE:
      self._send_json(404, {"error": "namespace not found"}, "1")
      return

    if "index" in query:
      time.sleep(MODIFIED_DELAY_SECONDS)
      self._send_json(
        200,
        [service_entry("nomad-app-updated", UPDATED_ENDPOINT_IP, UPDATED_PORT)],
        "2",
      )
      return

    self._send_json(
      200,
      [service_entry("nomad-app-initial", INITIAL_ENDPOINT_IP, INITIAL_PORT)],
      "1",
    )

  def log_message(self, format, *args):
    return

  def _send_json(self, status, payload, index):
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    self.send_response(status)
    self.send_header("content-type", "application/json")
    self.send_header("content-length", str(len(encoded)))
    self.send_header("x-nomad-index", index)
    self.end_headers()
    self.wfile.write(encoded)


def main():
  port = int(os.environ.get("LISTEN_PORT", "18091"))
  server = ThreadingHTTPServer(("0.0.0.0", port), NomadHandler)
  print(f"mock Nomad API listening on 0.0.0.0:{port}", flush=True)
  server.serve_forever()


if __name__ == "__main__":
  main()
