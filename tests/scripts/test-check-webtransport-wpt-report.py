#!/usr/bin/env python3
"""Regression tests for the pinned WebTransport WPT parity classifier."""

import contextlib
import importlib.util
import io
import sys
import unittest
from pathlib import Path


sys.dont_write_bytecode = True
script_path = Path(__file__).with_name("check-webtransport-wpt-report.py")
spec = importlib.util.spec_from_file_location("check_webtransport_wpt_report", script_path)
assert spec is not None and spec.loader is not None
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)

WORKER = "/webtransport/streams-close.https.any.worker.html"
SHARED_WORKER = "/webtransport/streams-close.https.any.sharedworker.html"
OTHER = "/webtransport/streams-close.https.any.html"
SUBTEST = "Close and abort unidirectional stream"


def result(status, message=None, harness_status="OK"):
    return {
        "status": harness_status,
        "subtests": [{"name": SUBTEST, "status": status, "message": message}],
    }


class ChromeDirectRetryTests(unittest.TestCase):
    def setUp(self):
        self.direct = {
            WORKER: result("FAIL", checker.CHROME_DIRECT_RETRY_MESSAGE),
            SHARED_WORKER: result("FAIL", checker.CHROME_DIRECT_RETRY_MESSAGE),
        }
        self.proxied = {WORKER: result("PASS"), SHARED_WORKER: result("PASS")}

    def test_exact_worker_failures_allow_one_direct_replay(self):
        with self.assertRaisesRegex(
            checker.RetryableDirectBaselineMismatch,
            "direct/proxy baseline mismatch",
        ):
            checker.compare(self.direct, self.proxied, True)

    def test_one_worker_failure_is_also_eligible(self):
        self.direct[SHARED_WORKER] = result("PASS")
        with self.assertRaises(checker.RetryableDirectBaselineMismatch):
            checker.compare(self.direct, self.proxied, True)

    def test_replay_remains_strict(self):
        with self.assertRaises(ValueError) as caught:
            checker.compare(self.direct, self.proxied)
        self.assertIs(type(caught.exception), ValueError)

    def test_exact_matching_reports_pass(self):
        with contextlib.redirect_stdout(io.StringIO()):
            checker.compare(self.proxied, self.proxied, True)

    def test_other_failure_message_cannot_trigger_replay(self):
        self.direct[WORKER] = result("FAIL", "different Chrome failure")
        self.assert_not_retryable()

    def test_other_subtest_cannot_trigger_replay(self):
        self.direct[OTHER] = result("FAIL", checker.CHROME_DIRECT_RETRY_MESSAGE)
        self.proxied[OTHER] = result("PASS")
        self.assert_not_retryable()

    def test_proxy_regression_cannot_trigger_replay(self):
        self.direct[OTHER] = result("PASS")
        self.proxied[OTHER] = result("FAIL")
        self.assert_not_retryable()

    def test_harness_mismatch_cannot_trigger_replay(self):
        self.direct[WORKER]["status"] = "ERROR"
        self.assert_not_retryable()

    def test_subtest_selection_mismatch_cannot_trigger_replay(self):
        self.proxied[WORKER]["subtests"] = []
        self.assert_not_retryable()

    def test_case_selection_mismatch_cannot_trigger_replay(self):
        del self.proxied[WORKER]
        self.assert_not_retryable()

    def assert_not_retryable(self):
        with self.assertRaises(ValueError) as caught:
            checker.compare(self.direct, self.proxied, True)
        self.assertIs(type(caught.exception), ValueError)


if __name__ == "__main__":
    unittest.main()
