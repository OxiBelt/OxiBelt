#!/usr/bin/env python3
"""Focused tests for early HTTP rejection handling in the mock client."""

from __future__ import annotations

import contextlib
import http.client
import importlib.util
import io
import pathlib
import sys
import unittest
from unittest import mock


CLIENT_PATH = pathlib.Path(__file__).parents[1] / "docker" / "mock_upstream" / "client.py"
SPEC = importlib.util.spec_from_file_location("mock_upstream_client", CLIENT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot import {CLIENT_PATH}")
CLIENT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CLIENT
SPEC.loader.exec_module(CLIENT)

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


if __name__ == "__main__":
    unittest.main()
