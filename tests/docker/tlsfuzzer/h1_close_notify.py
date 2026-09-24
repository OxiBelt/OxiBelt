"""Require an orderly TLS shutdown after an HTTP/1.1 close response."""

import socket
import ssl


def main():
    context = ssl.create_default_context(cafile="/opt/probes/server.pem")
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    with socket.create_connection(("proxy", 8443), timeout=5) as tcp:
        with context.wrap_socket(
            tcp, server_hostname="proxy", suppress_ragged_eofs=False
        ) as tls:
            tls.settimeout(5)
            tls.sendall(
                b"GET / HTTP/1.1\r\nHost: proxy\r\nConnection: close\r\n\r\n"
            )
            response = bytearray()
            while chunk := tls.recv(4096):
                response.extend(chunk)
                if len(response) > 1024 * 1024:
                    raise AssertionError("HTTP response exceeded 1 MiB")
            # With suppress_ragged_eofs=False, an abrupt TCP close raises
            # SSLEOFError here; empty recv requires the server's close_notify.
            if not response.startswith(b"HTTP/1.1 ") or b"\r\n\r\n" not in response:
                raise AssertionError(f"unexpected HTTP/1.1 response: {response[:80]!r}")


if __name__ == "__main__":
    main()
