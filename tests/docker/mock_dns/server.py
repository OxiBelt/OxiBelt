import ipaddress
import json
import os
import selectors
import socket
import struct


DNS_CLASS_IN = 1
DNS_TYPE_A = 1
DNS_TYPE_AAAA = 28
MAX_ADDRESSES = 64
MAX_PACKET_BYTES = 4096


class ServerState:
  def __init__(self):
    self.query_count = 0
    self.a_query_count = 0
    self.aaaa_query_count = 0
    self.reverse_answers = False

  def record_query(self, qtype):
    self.query_count += 1
    if qtype == DNS_TYPE_A:
      self.a_query_count += 1
    elif qtype == DNS_TYPE_AAAA:
      self.aaaa_query_count += 1

  def reset(self):
    self.query_count = 0
    self.a_query_count = 0
    self.aaaa_query_count = 0

  def summary(self):
    return {
      "query_count": self.query_count,
      "a_query_count": self.a_query_count,
      "aaaa_query_count": self.aaaa_query_count,
      "reverse_answers": self.reverse_answers,
    }


def parse_dns_name(packet, offset):
  labels = []
  cursor = offset
  jumped = False
  next_offset = offset
  for _ in range(32):
    if cursor >= len(packet):
      raise ValueError("DNS name is out of bounds")
    length = packet[cursor]
    if length & 0xC0 == 0xC0:
      if cursor + 1 >= len(packet):
        raise ValueError("DNS compression pointer is out of bounds")
      pointer = ((length & 0x3F) << 8) | packet[cursor + 1]
      if not jumped:
        next_offset = cursor + 2
      cursor = pointer
      jumped = True
      continue
    if length & 0xC0:
      raise ValueError("invalid DNS label length")
    cursor += 1
    if length == 0:
      if not jumped:
        next_offset = cursor
      return ".".join(labels).lower(), next_offset
    end = cursor + length
    if end > len(packet):
      raise ValueError("DNS label is out of bounds")
    labels.append(packet[cursor:end].decode("ascii", "strict"))
    cursor = end
  raise ValueError("DNS name compression chain is too deep")


def address_record(ip, record_type, ttl):
  if record_type == DNS_TYPE_A:
    rdata = ipaddress.IPv4Address(ip).packed
  elif record_type == DNS_TYPE_AAAA:
    rdata = ipaddress.IPv6Address(ip).packed
  else:
    raise ValueError("unsupported DNS record type")
  return (
    b"\xc0\x0c"
    + struct.pack("!HHIH", record_type, DNS_CLASS_IN, ttl, len(rdata))
    + rdata
  )


def configured_addresses(name, fallback, address_type):
  raw = os.environ.get(name, fallback)
  addresses = [item.strip() for item in raw.split(",") if item.strip()]
  if len(addresses) > MAX_ADDRESSES:
    raise ValueError(f"{name} exceeds the {MAX_ADDRESSES}-address limit")
  parsed = []
  for address in addresses:
    parsed_address = ipaddress.ip_address(address)
    if not isinstance(parsed_address, address_type):
      raise ValueError(f"{name} contains an address from the wrong family")
    parsed.append(str(parsed_address))
  return parsed


def configured_ttl():
  ttl = int(os.environ.get("VALID_TTL", "1"))
  if not 0 <= ttl <= 0xFFFFFFFF:
    raise ValueError("VALID_TTL must fit in an unsigned 32-bit field")
  return ttl


def build_response(packet, state):
  if len(packet) < 12:
    return None
  query_id = struct.unpack_from("!H", packet, 0)[0]
  try:
    name, offset = parse_dns_name(packet, 12)
    qtype, qclass = struct.unpack_from("!HH", packet, offset)
  except (struct.error, ValueError):
    return None

  question_end = offset + 4
  question = packet[12:question_end]
  response_id = query_id
  flags = 0x8180
  answers = []

  valid_name = os.environ.get("VALID_A_NAME", "valid.discovery.test").rstrip(".").lower()
  spoof_name = os.environ.get("SPOOF_A_NAME", "spoofed.discovery.test").rstrip(".").lower()
  valid_a = configured_addresses(
    "VALID_A_IPS",
    os.environ.get("VALID_A_IP", "127.0.0.1"),
    ipaddress.IPv4Address,
  )
  valid_aaaa = configured_addresses("VALID_AAAA_IPS", "", ipaddress.IPv6Address)
  spoof_ip = os.environ.get("SPOOF_A_IP", "203.0.113.66")
  ttl = configured_ttl()

  if qclass != DNS_CLASS_IN:
    flags = 0x8183
  elif name == valid_name and qtype in (DNS_TYPE_A, DNS_TYPE_AAAA):
    state.record_query(qtype)
    configured = valid_a if qtype == DNS_TYPE_A else valid_aaaa
    if not configured:
      flags = 0x8180
    else:
      ordered = list(reversed(configured)) if state.reverse_answers else configured
      answers.extend(address_record(address, qtype, ttl) for address in ordered)
  elif name == spoof_name and qtype == DNS_TYPE_A:
    state.record_query(qtype)
    response_id = query_id ^ 0xFFFF
    answers.append(address_record(spoof_ip, DNS_TYPE_A, ttl))
  else:
    state.record_query(qtype)
    flags = 0x8183

  header = struct.pack("!HHHHHH", response_id, flags, 1, len(answers), 0, 0)
  return header + question + b"".join(answers)


def handle_control(listener, state):
  connection, _ = listener.accept()
  connection.settimeout(1.0)
  try:
    command = connection.recv(128).decode("ascii", "strict").strip().upper()
    if command == "STATS":
      response = json.dumps(state.summary(), sort_keys=True)
    elif command == "RESET":
      state.reset()
      response = "ok"
    elif command == "REVERSE":
      state.reverse_answers = not state.reverse_answers
      response = "ok"
    else:
      response = "error: expected STATS, RESET, or REVERSE"
    connection.sendall(response.encode("ascii") + b"\n")
  except (OSError, UnicodeError):
    return
  finally:
    connection.close()


def main():
  host = os.environ.get("LISTEN_HOST", "127.0.0.1")
  port = int(os.environ.get("LISTEN_PORT", "53"))
  control_port = int(os.environ.get("CONTROL_PORT", str(port + 1)))
  if not 1 <= port <= 65535 or not 1 <= control_port <= 65535:
    raise ValueError("LISTEN_PORT and CONTROL_PORT must be valid TCP/UDP ports")
  if port == control_port:
    raise ValueError("CONTROL_PORT must differ from LISTEN_PORT")

  state = ServerState()
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  sock.bind((host, port))
  control = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  control.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  control.bind((host, control_port))
  control.listen(8)

  events = selectors.DefaultSelector()
  events.register(sock, selectors.EVENT_READ, "dns")
  events.register(control, selectors.EVENT_READ, "control")
  print(
    f"mock DNS listening on {host}:{port} with control port {control_port}",
    flush=True,
  )
  while True:
    for key, _ in events.select():
      if key.data == "control":
        handle_control(control, state)
        continue
      packet, address = sock.recvfrom(MAX_PACKET_BYTES)
      try:
        response = build_response(packet, state)
      except (ValueError, UnicodeError):
        response = None
      if response is not None and len(response) <= MAX_PACKET_BYTES:
        sock.sendto(response, address)


if __name__ == "__main__":
  main()
