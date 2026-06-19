
run_case_checks() {
  start_websocket_echo_upstream
  assert_websocket_stream_waf_frame_limit
}

start_websocket_echo_upstream() {
  docker run -d \
    --name "oxibelt-ws-upstream-${run_id}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --network-alias ws-upstream \
    --entrypoint python \
    "${mock_image}" \
    -c '
import base64
import hashlib
import socket
import struct
import sys
import threading

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

def read_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            return b""
        data += chunk
    return data

def read_http_headers(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("connection closed before headers")
        data += chunk
    return data.decode("iso-8859-1", "replace")

def read_frame(sock):
    head = read_exact(sock, 2)
    if not head:
        return None
    opcode = head[0] & 0x0f
    masked = (head[1] & 0x80) != 0
    length = head[1] & 0x7f
    if length == 126:
        length = struct.unpack("!H", read_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", read_exact(sock, 8))[0]
    mask = read_exact(sock, 4) if masked else b"\x00\x00\x00\x00"
    payload = bytearray(read_exact(sock, length))
    if len(payload) != length:
        return None
    if masked:
        for index in range(length):
            payload[index] ^= mask[index % 4]
    return opcode, bytes(payload)

def send_frame(sock, opcode, payload):
    length = len(payload)
    if length < 126:
        head = bytes([0x80 | opcode, length])
    elif length <= 65535:
        head = bytes([0x80 | opcode, 126]) + struct.pack("!H", length)
    else:
        head = bytes([0x80 | opcode, 127]) + struct.pack("!Q", length)
    sock.sendall(head + payload)

def handle(conn):
    with conn:
        try:
            headers = {}
            for line in read_http_headers(conn).split("\r\n")[1:]:
                if ":" in line:
                    name, value = line.split(":", 1)
                    headers[name.lower()] = value.strip()
            accept = base64.b64encode(
                hashlib.sha1((headers["sec-websocket-key"] + GUID).encode("ascii")).digest()
            ).decode("ascii")
            conn.sendall((
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Connection: Upgrade\r\n"
                "Upgrade: websocket\r\n"
                f"Sec-WebSocket-Accept: {accept}\r\n"
                "\r\n"
            ).encode("ascii"))
            frame = read_frame(conn)
            if frame is None:
                return
            opcode, payload = frame
            print(f"ws-upstream received {len(payload)} bytes", flush=True)
            send_frame(conn, opcode, payload)
        except Exception as error:
            print(f"ws-upstream connection failed: {error}", file=sys.stderr, flush=True)

server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("0.0.0.0", 18081))
server.listen()
while True:
    conn, _addr = server.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
' >/dev/null
  sleep 1
}

assert_websocket_stream_waf_frame_limit() {
  local client_container output
  client_container="oxibelt-ws-frame-limit-${run_id}-${RANDOM}"
  docker create \
    --name "${client_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --entrypoint python \
    "${mock_image}" \
    -c '
import base64
import os
import socket
import ssl
import struct

def read_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            if not data:
                return b""
            raise RuntimeError("unexpected EOF while reading frame")
        data += chunk
    return data

def read_http_headers(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("connection closed before WebSocket response")
        data += chunk
    return data.decode("iso-8859-1", "replace")

def connect_ws():
    context = ssl.create_default_context(cafile="/tmp/proxy-ca.pem")
    raw = socket.create_connection(("proxy", 8443), timeout=5)
    sock = context.wrap_socket(raw, server_hostname="proxy")
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    sock.sendall((
        "GET /ws HTTP/1.1\r\n"
        "Host: ws.example.test\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    ).encode("ascii"))
    response = read_http_headers(sock)
    if not response.startswith("HTTP/1.1 101 "):
        raise RuntimeError(f"unexpected WebSocket response: {response!r}")
    return sock

def send_masked_frame(sock, payload):
    mask = b"\x01\x02\x03\x04"
    length = len(payload)
    if length < 126:
        head = bytes([0x82, 0x80 | length])
    elif length <= 65535:
        head = bytes([0x82, 0x80 | 126]) + struct.pack("!H", length)
    else:
        head = bytes([0x82, 0x80 | 127]) + struct.pack("!Q", length)
    masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    sock.sendall(head + mask + masked)

def read_frame(sock):
    head = read_exact(sock, 2)
    if not head:
        return None
    opcode = head[0] & 0x0f
    masked = (head[1] & 0x80) != 0
    length = head[1] & 0x7f
    if length == 126:
        length = struct.unpack("!H", read_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", read_exact(sock, 8))[0]
    mask = read_exact(sock, 4) if masked else b"\x00\x00\x00\x00"
    payload = bytearray(read_exact(sock, length))
    if len(payload) != length:
        return None
    if masked:
        for index in range(length):
            payload[index] ^= mask[index % 4]
    return opcode, bytes(payload)

small = b"safe websocket frame"
small_sock = connect_ws()
try:
    send_masked_frame(small_sock, small)
    echoed = read_frame(small_sock)
    if echoed != (2, small):
        raise RuntimeError(f"small WebSocket frame was not echoed: {echoed!r}")
finally:
    small_sock.close()

large = b"x" * 2048
large_sock = connect_ws()
try:
    send_masked_frame(large_sock, large)
    large_sock.settimeout(3)
    try:
        frame = read_frame(large_sock)
    except socket.timeout as error:
        raise RuntimeError("oversized frame left the WebSocket open") from error
    except (ConnectionResetError, OSError, ssl.SSLError):
        frame = None
    if frame is not None and frame[0] in (1, 2) and frame[1] == large:
        raise RuntimeError("oversized WebSocket frame was proxied instead of rejected")
finally:
    large_sock.close()

print("small frame echoed")
print("oversized frame rejected")
' >/dev/null
  docker cp "${cert_dir}/fullchain.pem" "${client_container}:/tmp/proxy-ca.pem"

  if ! output="$(docker start -a "${client_container}" 2>&1)"; then
    echo "${output}" >&2
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    fail_with_diagnostics "WebSocket stream-WAF frame-limit client failed"
  fi
  docker rm -f "${client_container}" >/dev/null 2>&1 || true
  if ! grep -F "oversized frame rejected" <<<"${output}" >/dev/null; then
    echo "${output}" >&2
    fail_with_diagnostics "WebSocket frame-limit assertion did not run"
  fi
}
