#!/usr/bin/env python3
"""Regression tests for the pinned WebTransport WPT parity classifier."""

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import textwrap
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
SERVICE_WORKER = "/webtransport/streams-close.https.any.serviceworker.html"
SUBTEST = "Close and abort unidirectional stream"


def result(status, message=None, harness_status="OK"):
    return {
        "status": harness_status,
        "subtests": [{"name": SUBTEST, "status": status, "message": message}],
    }


def pinned_report():
    """Generate the public pinned parent selection with synthetic passing results."""
    any_families = (
        "close congestion-control connect constructor-sharedarraybuffer "
        "datagram-bad-chunk datagrams draining echo-large-bidirectional-streams "
        "export-keying-material headers incoming-multiple-streams receive-stream-pull "
        "reliability sendgroup sendorder sendstream-bad-chunk server-certificate-hashes "
        "stats streams-close streams-echo"
    ).split()
    ids = []
    for families, prefix in ((any_families, "any"), (["constructor", "historical", "idlharness"], "sub.any")):
        for family in families:
            for context in ("", ".worker", ".sharedworker", ".serviceworker"):
                ids.append(f"/webtransport/{family}.https.{prefix}{context}.html")
    ids.extend(
        f"/webtransport/{name}.https.{suffix}"
        for name, suffix in (
            ("back-forward-cache-with-closed-webtransport-connection", "window.html"),
            ("back-forward-cache-with-closed-webtransport-connection-ccns", "tentative.window.html"),
            ("back-forward-cache-with-open-webtransport-connection", "window.html"),
            ("back-forward-cache-with-open-webtransport-connection-ccns", "tentative.window.html"),
            ("bidirectional-cancel-crash", "html"),
            ("csp-fail", "window.html"),
            ("csp-pass", "window.html"),
            ("datagram-cancel-crash", "sub.window.html"),
            ("datagrams-writable", "any.html"),
            ("in-removed-iframe", "html"),
            ("reliability", "window.html"),
        )
    )
    assert len(ids) == checker.EXPECTED_CASE_COUNT
    assert hashlib.sha256(("\n".join(sorted(ids)) + "\n").encode()).hexdigest() == checker.EXPECTED_CASE_IDS_SHA256
    results = [{"test": test, "status": "OK", "subtests": []} for test in sorted(ids)]
    indexed = {entry["test"]: entry for entry in results}
    for basename, control in checker.CONTROLS:
        indexed[f"/webtransport/{basename}.html"]["subtests"].append(
            {"name": control, "status": "PASS", "message": None}
        )
    for test in (WORKER, SHARED_WORKER, SERVICE_WORKER):
        indexed[test]["subtests"].append({"name": SUBTEST, "status": "PASS", "message": None})
    return {"results": results}


def set_subtest(report, test, status, message=None):
    entry = next(entry for entry in report["results"] if entry["test"] == test)
    subtest = next(subtest for subtest in entry["subtests"] if subtest["name"] == SUBTEST)
    subtest.update(status=status, message=message)


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


class ChromeProxyRetryTests(unittest.TestCase):
    def setUp(self):
        self.direct = {SERVICE_WORKER: result("PASS")}
        self.proxied = {SERVICE_WORKER: result("FAIL", checker.CHROME_DIRECT_RETRY_MESSAGE)}

    def assert_not_retryable(self):
        with self.assertRaises(ValueError) as caught:
            checker.compare(self.direct, self.proxied, True, True)
        self.assertIs(type(caught.exception), ValueError)

    def test_exact_serviceworker_failure_selects_proxy_replay(self):
        with self.assertRaises(checker.RetryableProxyBaselineMismatch):
            checker.compare(self.direct, self.proxied, False, True)

    def test_replay_comparison_and_original_direct_mode_remain_strict(self):
        for flags in ((), (True,)):
            with self.subTest(flags=flags), self.assertRaises(ValueError) as caught:
                checker.compare(self.direct, self.proxied, *flags)
            self.assertIs(type(caught.exception), ValueError)

    def test_matching_reports_do_not_request_replay(self):
        with contextlib.redirect_stdout(io.StringIO()):
            checker.compare(self.direct, self.direct, True, True)

    def test_other_messages_and_statuses_fail(self):
        for status, message in (
            ("FAIL", None), ("FAIL", "different failure"),
            ("TIMEOUT", checker.CHROME_DIRECT_RETRY_MESSAGE),
            ("ERROR", checker.CHROME_DIRECT_RETRY_MESSAGE),
            ("NOTRUN", checker.CHROME_DIRECT_RETRY_MESSAGE),
        ):
            with self.subTest(status=status, message=message):
                self.proxied[SERVICE_WORKER] = result(status, message)
                self.assert_not_retryable()

    def test_other_contexts_and_subtests_fail(self):
        for test in (OTHER, WORKER, SHARED_WORKER):
            with self.subTest(test=test):
                self.direct = {test: result("PASS")}
                self.proxied = {test: result("FAIL", checker.CHROME_DIRECT_RETRY_MESSAGE)}
                self.assert_not_retryable()
        self.setUp()
        for report in (self.direct, self.proxied):
            report[SERVICE_WORKER]["subtests"][0]["name"] = "different subtest"
        self.assert_not_retryable()

    def test_reverse_direction_cannot_select_proxy_replay(self):
        self.direct, self.proxied = self.proxied, self.direct
        self.assert_not_retryable()

    def test_harness_errors_cannot_select_proxy_replay(self):
        for before, after in (("OK", "ERROR"), ("ERROR", "OK"), ("ERROR", "ERROR"), ("TIMEOUT", "TIMEOUT")):
            with self.subTest(before=before, after=after):
                self.direct[SERVICE_WORKER]["status"] = before
                self.proxied[SERVICE_WORKER]["status"] = after
                self.assert_not_retryable()

    def test_duplicate_or_different_subtest_selection_fails(self):
        for side in ("direct", "proxied"):
            with self.subTest(side=side):
                self.setUp()
                getattr(self, side)[SERVICE_WORKER]["subtests"] *= 2
                self.assert_not_retryable()
        self.setUp()
        self.proxied[SERVICE_WORKER]["subtests"] = []
        self.assert_not_retryable()

    def test_different_case_selection_fails(self):
        self.direct[OTHER] = result("PASS")
        self.assert_not_retryable()

    def test_unrelated_mismatch_blocks_proxy_replay(self):
        self.direct[OTHER] = result("PASS")
        self.proxied[OTHER] = result("FAIL", checker.CHROME_DIRECT_RETRY_MESSAGE)
        self.assert_not_retryable()

    def test_mixed_direct_and_proxy_candidates_fail(self):
        self.direct[WORKER] = result("FAIL", checker.CHROME_DIRECT_RETRY_MESSAGE)
        self.proxied[WORKER] = result("PASS")
        self.assert_not_retryable()


class ClassifierCliTests(unittest.TestCase):
    def run_checker(self, direct, proxied, *flags, browser="chrome"):
        with tempfile.TemporaryDirectory(prefix="oxibelt-wpt-classifier-") as directory:
            root = Path(directory)
            for phase, report in (("direct", direct), ("proxied", proxied)):
                (root / f"{phase}.json").write_text(report if isinstance(report, str) else json.dumps(report))
            return subprocess.run(
                [sys.executable, "-B", str(script_path), *flags, browser,
                 str(root / "direct.json"), str(root / "proxied.json")],
                capture_output=True, text=True, timeout=10,
            )

    def test_exit_codes_and_strict_terminal_comparison(self):
        direct = pinned_report()
        proxied = copy.deepcopy(direct)
        set_subtest(proxied, SERVICE_WORKER, "FAIL", checker.CHROME_DIRECT_RETRY_MESSAGE)
        both = ("--classify-chrome-direct-retry", "--classify-chrome-proxy-retry")
        self.assertEqual(self.run_checker(direct, proxied, *both).returncode, 4)
        self.assertEqual(self.run_checker(direct, proxied, *reversed(both)).returncode, 4)
        self.assertEqual(self.run_checker(direct, proxied).returncode, 1)
        self.assertEqual(self.run_checker(direct, direct, *both).returncode, 0)
        set_subtest(direct, WORKER, "FAIL", checker.CHROME_DIRECT_RETRY_MESSAGE)
        self.assertEqual(self.run_checker(direct, proxied, *both).returncode, 1)
        self.assertEqual(self.run_checker(direct, pinned_report(), "--classify-chrome-direct-retry").returncode, 3)
        self.assertEqual(self.run_checker(direct, pinned_report(), *both).returncode, 3)
        self.assertEqual(self.run_checker(direct, pinned_report(), "--classify-chrome-proxy-retry").returncode, 1)

    def test_browser_and_option_restrictions(self):
        report = pinned_report()
        for flags, browser in (
            (("--classify-chrome-proxy-retry",), "firefox"),
            (("--classify-chrome-direct-retry", "--classify-chrome-proxy-retry"), "firefox"),
            (("--classify-chrome-proxy-retry", "--classify-chrome-proxy-retry"), "chrome"),
            (("--unknown-retry",), "chrome"),
        ):
            with self.subTest(flags=flags, browser=browser):
                self.assertEqual(self.run_checker(report, report, *flags, browser=browser).returncode, 1)

    def test_report_and_control_errors_cannot_request_replay(self):
        original = pinned_report()
        proxy = copy.deepcopy(original)
        set_subtest(proxy, SERVICE_WORKER, "FAIL", checker.CHROME_DIRECT_RETRY_MESSAGE)
        variants = ["{", {}, {"results": []}]
        missing_case = copy.deepcopy(original)
        missing_case["results"].pop()
        variants.append(missing_case)
        wrong_case = copy.deepcopy(original)
        wrong_case["results"][0]["test"] = "/webtransport/unpinned.https.any.html"
        variants.append(wrong_case)
        duplicate_case = copy.deepcopy(original)
        duplicate_case["results"].append(copy.deepcopy(duplicate_case["results"][0]))
        variants.append(duplicate_case)
        no_crashtest = copy.deepcopy(original)
        no_crashtest["results"] = [entry for entry in no_crashtest["results"] if "bidirectional-cancel-crash" not in entry["test"]]
        variants.append(no_crashtest)
        no_controls = copy.deepcopy(original)
        for entry in no_controls["results"]:
            if "connect.https.any" in entry["test"]:
                entry["subtests"] = []
        variants.append(no_controls)
        for report in variants:
            for side in ("direct", "proxied"):
                with self.subTest(side=side, report=variants.index(report)):
                    before, after = (report, proxy) if side == "direct" else (original, report)
                    self.assertEqual(self.run_checker(before, after, "--classify-chrome-proxy-retry").returncode, 1)


FAKE_DOCKER = r'''
import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
root = Path(os.environ["FAKE_WPT_ROOT"])
state = json.loads((root / "state.json").read_text())
scenario = os.environ["FAKE_WPT_SCENARIO"]
if args[0] == "exec" and "./wpt" in args:
    assert args[-1] == "webtransport/"
    assert args[args.index("--test-types") + 1:args.index("--test-types") + 3] == ["testharness", "crashtest"]
    report_name = next(arg.split("=", 1)[1] for arg in args if arg.startswith("--log-wptreport="))
    report_name = Path(report_name).stem
    state["runs"].append(report_name)
    retry = report_name == "chrome-proxied-retry"
    if "proxied" in report_name and not (retry and scenario == "missing-packets"):
        state["packets"] += 1
    (root / "state.json").write_text(json.dumps(state))
    report = json.loads((root / "passing.json").read_text())
    if report_name == "chrome-direct" and scenario == "mixed":
        entry = next(entry for entry in report["results"] if entry["test"] == "/webtransport/streams-close.https.any.worker.html")
        entry["subtests"][0].update(status="FAIL", message='assert_equals: reset_stream expected "reset" but got "FIN"')
    failure = report_name == "chrome-proxied" or (retry and scenario == "persistent")
    if failure or (retry and scenario == "migrating"):
        context = "worker" if retry and scenario == "migrating" else "serviceworker"
        target = f"/webtransport/streams-close.https.any.{context}.html"
        entry = next(entry for entry in report["results"] if entry["test"] == target)
        entry["subtests"][0].update(status="FAIL", message='assert_equals: reset_stream expected "reset" but got "FIN"')
        if report_name == "chrome-proxied" and scenario == "wrong-message":
            entry["subtests"][0]["message"] = "different failure"
    (root / "artifacts" / f"{report_name}.json").write_text(json.dumps(report))
    print(f"synthetic WPT {report_name}")
    sys.exit(7 if retry and scenario == "run-fails" else 0)
elif args[0] == "exec" and "--version" in args:
    print("Google Chrome for Testing 154.0.8037.57" if "/opt/chrome/chrome" in args else "Mozilla Firefox 156.0")
elif args[0] == "exec" and "-L" in args:
    print(f'{state["packets"]} 0 DNAT udp')
elif args[0] == "cp":
    if args[-2] == "-":
        sys.stdin.buffer.read()
    elif ":" not in args[-1]:
        Path(args[-1]).write_text("synthetic certificate fixture\n")
elif args[0] == "inspect":
    print("true")
elif args[0] == "logs":
    print("synthetic proxy log")
'''


class ProxyReplayShellTests(unittest.TestCase):
    def run_gate(self, scenario, expected_retries=1):
        temporary = tempfile.TemporaryDirectory(prefix="oxibelt-wpt-shell-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "artifacts").mkdir()
        (root / "bin").mkdir()
        (root / "passing.json").write_text(json.dumps(pinned_report()))
        (root / "state.json").write_text(json.dumps({"runs": [], "packets": 0}))
        docker = root / "bin" / "docker"
        docker.write_text(f"#!{sys.executable}\n" + textwrap.dedent(FAKE_DOCKER))
        docker.chmod(0o755)
        sleep = root / "bin" / "sleep"
        sleep.write_text("#!/bin/sh\nexit 0\n")
        sleep.chmod(0o755)
        environment = dict(os.environ, PATH=str(root / "bin") + os.pathsep + os.environ["PATH"],
                           TMPDIR=str(root), FAKE_WPT_ROOT=str(root), FAKE_WPT_SCENARIO=scenario,
                           OXIBELT_DOCKER_IMAGE="oxibelt:test", OXIBELT_TEST_ARTIFACT_DIR=str(root / "artifacts"))
        completed = subprocess.run(
            ["bash", str(script_path.with_name("run-webtransport-wpt-gate.sh"))],
            env=environment, capture_output=True, text=True, timeout=15,
        )
        state = json.loads((root / "state.json").read_text())
        self.assertEqual(state["runs"].count("chrome-proxied-retry"), expected_retries, completed.stderr)
        self.assertFalse(any("direct-retry" in name for name in state["runs"]), completed.stderr)
        reports = ["chrome-direct", "chrome-proxied"]
        if expected_retries:
            reports.append("chrome-proxied-retry")
        for name in reports:
            for suffix in ("json", "log", "exit"):
                self.assertTrue((root / "artifacts" / f"{name}.{suffix}").is_file(), completed.stderr)
        original = json.loads((root / "artifacts" / "chrome-proxied.json").read_text())
        target = next(entry for entry in original["results"] if entry["test"] == SERVICE_WORKER)
        self.assertEqual(target["subtests"][0]["status"], "FAIL")
        return completed, state, root

    def test_one_complete_proxy_replay_passes_and_preserves_reports(self):
        completed, state, root = self.run_gate("passes")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(state["runs"], ["chrome-direct", "firefox-direct", "chrome-proxied", "chrome-proxied-retry", "firefox-proxied"])
        self.assertEqual(state["packets"], 3)
        direct = json.loads((root / "artifacts" / "chrome-direct.json").read_text())
        self.assertEqual(direct, pinned_report())
        replay = json.loads((root / "artifacts" / "chrome-proxied-retry.json").read_text())
        self.assertEqual(replay, pinned_report())

    def test_persistent_or_migrating_failures_are_terminal(self):
        for scenario in ("persistent", "migrating"):
            with self.subTest(scenario=scenario):
                completed, state, _ = self.run_gate(scenario)
                self.assertEqual(completed.returncode, 1, completed.stderr)
                self.assertEqual(state["runs"], ["chrome-direct", "firefox-direct", "chrome-proxied", "chrome-proxied-retry"])

    def test_missing_retry_packets_is_terminal(self):
        completed, state, _ = self.run_gate("missing-packets")
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(state["packets"], 1)
        self.assertNotIn("firefox-proxied", state["runs"])

    def test_failed_wpt_replay_preserves_exit_status_and_stops(self):
        completed, state, root = self.run_gate("run-fails")
        self.assertEqual(completed.returncode, 7, completed.stderr)
        self.assertEqual((root / "artifacts" / "chrome-proxied-retry.exit").read_text().strip(), "7")
        self.assertNotIn("firefox-proxied", state["runs"])

    def test_initial_noneligible_and_mixed_mismatches_never_replay(self):
        for scenario in ("wrong-message", "mixed"):
            with self.subTest(scenario=scenario):
                completed, state, root = self.run_gate(scenario, expected_retries=0)
                self.assertEqual(completed.returncode, 1, completed.stderr)
                self.assertEqual(state["runs"], ["chrome-direct", "firefox-direct", "chrome-proxied"])
                self.assertFalse((root / "artifacts" / "chrome-proxied-retry.json").exists())


if __name__ == "__main__":
    unittest.main()
