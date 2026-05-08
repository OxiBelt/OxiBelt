import ipaddress
import os
import socket
import struct


DNS_CLASS_IN = 1
DNS_TYPE_A = 1


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
    labels.append(packet[cursor:end].decode("ascii", "replace"))
    cursor = end
  raise ValueError("DNS name compression chain is too deep")


def a_record(ip):
  rdata = ipaddress.IPv4Address(ip).packed
  return (
    b"\xc0\x0c"
    + struct.pack("!HHIH", DNS_TYPE_A, DNS_CLASS_IN, 1, len(rdata))
    + rdata
  )


def build_response(packet):
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
  valid_ip = os.environ.get("VALID_A_IP", "127.0.0.1")
  spoof_ip = os.environ.get("SPOOF_A_IP", "203.0.113.66")

  if qclass != DNS_CLASS_IN:
    flags = 0x8183
  elif name == valid_name and qtype == DNS_TYPE_A:
    answers.append(a_record(valid_ip))
  elif name == spoof_name and qtype == DNS_TYPE_A:
    response_id = query_id ^ 0xFFFF
    answers.append(a_record(spoof_ip))
  else:
    flags = 0x8183

  header = struct.pack("!HHHHHH", response_id, flags, 1, len(answers), 0, 0)
  return header + question + b"".join(answers)


def main():
  host = os.environ.get("LISTEN_HOST", "0.0.0.0")
  port = int(os.environ.get("LISTEN_PORT", "53"))
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  sock.bind((host, port))
  print(f"mock DNS listening on {host}:{port}", flush=True)
  while True:
    packet, address = sock.recvfrom(4096)
    response = build_response(packet)
    if response is not None:
      sock.sendto(response, address)


if __name__ == "__main__":
  main()
