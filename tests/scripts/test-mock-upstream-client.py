#!/usr/bin/env python3
"""Focused tests for the mock-upstream request clients."""

from __future__ import annotations

import contextlib
import http.client
import importlib.util
import io
import pathlib
import sys
import threading
import types
import unittest
from unittest import mock


CLIENT_PATH = pathlib.Path(__file__).parents[1] / "docker" / "mock_upstream" / "client.py"
CLIENT_SPEC = importlib.util.spec_from_file_location("client", CLIENT_PATH)
if CLIENT_SPEC is None or CLIENT_SPEC.loader is None:
    raise RuntimeError(f"cannot import {CLIENT_PATH}")
CLIENT = importlib.util.module_from_spec(CLIENT_SPEC)
sys.modules[CLIENT_SPEC.name] = CLIENT
CLIENT_SPEC.loader.exec_module(CLIENT)

BURST_PATH = (
    pathlib.Path(__file__).parents[1] / "docker" / "mock_upstream" / "burst_client.py"
)
BURST_SPEC = importlib.util.spec_from_file_location("mock_upstream_burst_client", BURST_PATH)
if BURST_SPEC is None or BURST_SPEC.loader is None:
    raise RuntimeError(f"cannot import {BURST_PATH}")
BURST = importlib.util.module_from_spec(BURST_SPEC)
sys.modules[BURST_SPEC.name] = BURST
BURST_SPEC.loader.exec_module(BURST)

BAD_REQUEST = (
    b"HTTP/1.1 400 Bad Request\r\n"
    b"Content-Length: 0\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)


class EarlyResponseSocket:
    """Socket stub that rejects the first body write after buffering a response."""

    def __init__(self, response: bytes, write_error: OSError) -> None:
        self._response = io.BytesIO(response)
        self._write_error = write_error
        self.writes: list[bytes] = []

    def sendall(self, data: bytes) -> None:
        if self.writes:
            raise self._write_error
        self.writes.append(data)

    def makefile(self, mode: str) -> io.BytesIO:
        if mode != "rb":
            raise ValueError(f"unexpected mode {mode}")
        return self._response


class BurstSocket:
    def __init__(self, index: int) -> None:
        self.index = index
        self.closed = False

    def close(self) -> None:
        self.closed = True


class BurstResponse:
    def __init__(self, index: int, status: int = 503) -> None:
        self.status = status
        self.reason = "Service Unavailable"
        self._headers = [("X-Burst-Index", str(index))]

    def getheaders(self) -> list[tuple[str, str]]:
        return self._headers


class MockUpstreamClientEarlyResponseTests(unittest.TestCase):
    def send_ambiguous_request(
        self,
        sock: EarlyResponseSocket,
        *,
        read_after_error: bool,
    ) -> tuple[http.client.HTTPResponse, bytes]:
        return CLIENT.send_http_request(
            sock,
            "POST",
            "/ambiguous",
            "example.test",
            [
                ("Content-Type", "text/plain"),
                ("Content-Length", "4"),
            ],
            b"abcd",
            "close",
            chunked_body=True,
            read_response_after_body_write_error=read_after_error,
        )

    def test_reads_buffered_error_response_after_expected_body_write_errors(self) -> None:
        for write_error in (
            BrokenPipeError("peer closed"),
            ConnectionResetError("peer reset"),
        ):
            with self.subTest(error=type(write_error).__name__):
                sock = EarlyResponseSocket(BAD_REQUEST, write_error)
                response, body = self.send_ambiguous_request(
                    sock,
                    read_after_error=True,
                )

                self.assertEqual(response.status, 400)
                self.assertEqual(body, b"")
                self.assertIn(b"Transfer-Encoding: chunked\r\n", sock.writes[0])

    def test_strict_mode_propagates_body_write_error(self) -> None:
        sock = EarlyResponseSocket(BAD_REQUEST, BrokenPipeError("peer closed"))

        with self.assertRaises(BrokenPipeError):
            self.send_ambiguous_request(sock, read_after_error=False)

    def test_early_response_mode_still_requires_a_parseable_response(self) -> None:
        sock = EarlyResponseSocket(b"", BrokenPipeError("peer closed"))

        with self.assertRaises(http.client.RemoteDisconnected):
            self.send_ambiguous_request(sock, read_after_error=True)

    def invoke_main(self, *arguments: str) -> tuple[int, str]:
        stderr = io.StringIO()
        argv = [
            "client.py",
            "--host",
            "example.test",
            "--path",
            "/ambiguous",
            *arguments,
        ]
        with mock.patch.object(sys, "argv", argv), contextlib.redirect_stderr(stderr):
            return CLIENT.main(), stderr.getvalue()

    def test_early_response_mode_requires_chunked_body(self) -> None:
        status, stderr = self.invoke_main(
            "--expect-status",
            "400",
            "--read-response-after-body-write-error",
        )

        self.assertEqual(status, 2)
        self.assertIn("requires --chunked-body", stderr)

    def test_early_response_mode_requires_expected_error_status(self) -> None:
        status, stderr = self.invoke_main(
            "--chunked-body",
            "--expect-status",
            "399",
            "--read-response-after-body-write-error",
        )

        self.assertEqual(status, 2)
        self.assertIn("requires --expect-status in the 400-599 range", stderr)


class MockUpstreamBurstClientTests(unittest.TestCase):
    def args(self, concurrency: int = 4) -> types.SimpleNamespace:
        return types.SimpleNamespace(
            concurrency=concurrency,
            timeout=1.0,
        )

    def test_preconnects_every_socket_before_sending_requests(self) -> None:
        lock = threading.Lock()
        opened = 0
        send_open_counts: list[int] = []
        sockets: list[BurstSocket] = []

        def open_socket(_args: object) -> BurstSocket:
            nonlocal opened
            with lock:
                opened += 1
                sock = BurstSocket(opened)
                sockets.append(sock)
                return sock

        def send_request(
            sock: BurstSocket,
            _method: str,
            _path: str,
            _host: str,
            _headers: list[tuple[str, str]],
            _body: bytes,
            _connection: str,
        ) -> tuple[BurstResponse, bytes]:
            with lock:
                send_open_counts.append(opened)
            return BurstResponse(sock.index), f"response-{sock.index}".encode()

        results = BURST.run_burst(
            self.args(),
            "/burst",
            "example.test",
            open_socket=open_socket,
            send_request=send_request,
        )

        self.assertEqual(send_open_counts, [4, 4, 4, 4])
        self.assertEqual([result["burst_index"] for result in results], [1, 2, 3, 4])
        self.assertTrue(all(result["status"] == 503 for result in results))
        self.assertTrue(all(sock.closed for sock in sockets))

    def test_preconnect_failure_aborts_without_sending_requests(self) -> None:
        lock = threading.Lock()
        opened = 0
        sends = 0
        sockets: list[BurstSocket] = []

        def open_socket(_args: object) -> BurstSocket:
            nonlocal opened
            with lock:
                opened += 1
                index = opened
            if index == 2:
                raise OSError("injected preconnect failure")
            sock = BurstSocket(index)
            sockets.append(sock)
            return sock

        def send_request(*_args: object) -> tuple[BurstResponse, bytes]:
            nonlocal sends
            sends += 1
            return BurstResponse(0), b"unexpected"

        results = BURST.run_burst(
            self.args(),
            "/burst",
            "example.test",
            open_socket=open_socket,
            send_request=send_request,
        )

        self.assertEqual(sends, 0)
        self.assertTrue(all("error" in result for result in results))
        self.assertTrue(
            any(
                result["error"]["message"] == "injected preconnect failure"
                for result in results
            )
        )
        self.assertTrue(all(sock.closed for sock in sockets))

    def invoke_main(self, *arguments: str) -> tuple[int, str]:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            status = BURST.main([
                "--target-host",
                "proxy",
                "--port",
                "8443",
                "--scheme",
                "https",
                "--host",
                "example.test",
                "--path",
                "/burst",
                "--timeout",
                "10",
                *arguments,
            ])
        return status, stderr.getvalue()

    def test_rejects_out_of_range_concurrency(self) -> None:
        status, stderr = self.invoke_main("--concurrency", "65")

        self.assertEqual(status, 2)
        self.assertIn("concurrency must be in the range 1..64", stderr)

    def test_requires_a_ca_file_for_https(self) -> None:
        status, stderr = self.invoke_main("--concurrency", "4")

        self.assertEqual(status, 2)
        self.assertIn("HTTPS bursts require --ca-file", stderr)

    def test_response_document_preserves_binary_and_header_fields(self) -> None:
        document = CLIENT.response_document(BurstResponse(7, status=200), b"\xff")

        self.assertEqual(document["status"], 200)
        self.assertEqual(document["headers"], {"x-burst-index": "7"})
        self.assertEqual(document["body"], "\ufffd")
        self.assertEqual(document["body_base64"], "/w==")


if __name__ == "__main__":
    unittest.main()
