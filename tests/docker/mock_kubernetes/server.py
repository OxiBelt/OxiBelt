import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


EXPECTED_TOKEN = os.environ.get("EXPECTED_TOKEN", "matrix-kubernetes-token")
INITIAL_ENDPOINT_IP = os.environ.get("INITIAL_ENDPOINT_IP", "127.0.0.1")
UPDATED_ENDPOINT_IP = os.environ.get("UPDATED_ENDPOINT_IP", "127.0.0.1")
SERVICE_NAME = os.environ.get("SERVICE_NAME", "app")
NAMESPACE = os.environ.get("NAMESPACE", "default")
PORT_NAME = os.environ.get("PORT_NAME", "http")
PORT = int(os.environ.get("ENDPOINT_PORT", "18080"))
UPDATED_PORT = int(os.environ.get("UPDATED_ENDPOINT_PORT", "18081"))
MODIFIED_DELAY_SECONDS = float(os.environ.get("MODIFIED_DELAY_SECONDS", "5.0"))
DELETED_DELAY_SECONDS = float(os.environ.get("DELETED_DELAY_SECONDS", "1.0"))


def endpoint_slice(resource_version, addresses, port):
  return {
    "apiVersion": "discovery.k8s.io/v1",
    "kind": "EndpointSlice",
    "metadata": {
      "name": "app-slice",
      "namespace": NAMESPACE,
      "resourceVersion": str(resource_version),
      "labels": {
        "kubernetes.io/service-name": SERVICE_NAME,
      },
    },
    "addressType": "IPv4",
    "ports": [
      {
        "name": PORT_NAME,
        "protocol": "TCP",
        "port": port,
      }
    ],
    "endpoints": [
      {
        "addresses": addresses,
        "conditions": {
          "ready": True,
          "terminating": False,
        },
      }
    ],
  }


def endpoint_slice_list():
  return {
    "apiVersion": "discovery.k8s.io/v1",
    "kind": "EndpointSliceList",
    "metadata": {
      "resourceVersion": "1",
    },
    "items": [
      endpoint_slice("1", [INITIAL_ENDPOINT_IP], PORT),
    ],
  }


class KubernetesHandler(BaseHTTPRequestHandler):
  protocol_version = "HTTP/1.1"

  def do_GET(self):
    if not self._authorized():
      self._send_json(401, {"kind": "Status", "code": 401, "message": "unauthorized"})
      return
    parsed = urlsplit(self.path)
    expected_path = f"/apis/discovery.k8s.io/v1/namespaces/{NAMESPACE}/endpointslices"
    if parsed.path != expected_path:
      self._send_json(404, {"kind": "Status", "code": 404, "message": "not found"})
      return
    query = parse_qs(parsed.query)
    if query.get("watch", ["false"])[0] == "true":
      self._send_watch()
      return
    self._send_json(200, endpoint_slice_list())

  def log_message(self, format, *args):
    return

  def _authorized(self):
    expected = f"Bearer {EXPECTED_TOKEN}"
    return self.headers.get("authorization") == expected

  def _send_json(self, status, payload):
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    self.send_response(status)
    self.send_header("content-type", "application/json")
    self.send_header("content-length", str(len(encoded)))
    self.end_headers()
    self.wfile.write(encoded)

  def _send_watch(self):
    self.send_response(200)
    self.send_header("content-type", "application/json")
    self.send_header("connection", "close")
    self.end_headers()
    time.sleep(MODIFIED_DELAY_SECONDS)
    self._write_event(
      {
        "type": "MODIFIED",
        "object": endpoint_slice("2", [UPDATED_ENDPOINT_IP], UPDATED_PORT),
      }
    )
    time.sleep(DELETED_DELAY_SECONDS)
    self._write_event(
      {
        "type": "DELETED",
        "object": endpoint_slice("3", [UPDATED_ENDPOINT_IP], UPDATED_PORT),
      }
    )

  def _write_event(self, event):
    self.wfile.write(json.dumps(event, separators=(",", ":")).encode("utf-8") + b"\n")
    self.wfile.flush()


def main():
  port = int(os.environ.get("LISTEN_PORT", "18090"))
  server = ThreadingHTTPServer(("0.0.0.0", port), KubernetesHandler)
  print(f"mock Kubernetes API listening on 0.0.0.0:{port}", flush=True)
  server.serve_forever()


if __name__ == "__main__":
  main()
