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


def serviceworker_timeout_reports():
    """Reproduce the Chrome serviceworker sequence from hosted run 38205816664."""
    direct = pinned_report()
    target = next(entry for entry in direct["results"] if entry["test"] == SERVICE_WORKER)
    target["subtests"] = [
        {"name": name, "status": "PASS", "message": None, "known_intermittent": []}
        for name in (
            "Close outgoing stream / bidi-1",
            "Close outgoing stream / bidi-2",
            "Close outgoing stream / uni",
            "Abort client-created bidirectional stream",
            "Abort server-initiated bidirectional stream",
            "Abort unidirectional stream with WebTransportError",
            SUBTEST,
            "Abort unidirectional stream with default error code",
            "STOP_SENDING coming from server",
            "RESET_STREAM coming from server",
        )
    ]
    proxied = copy.deepcopy(direct)
    target = next(entry for entry in proxied["results"] if entry["test"] == SERVICE_WORKER)
    target["status"] = "TIMEOUT"
    for index, subtest in enumerate(target["subtests"][3:]):
        subtest.update(status="TIMEOUT" if index == 0 else "NOTRUN", expected="PASS")
        if index == 0:
            subtest["message"] = "Test timed out"
    return direct, proxied


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

    def test_serviceworker_alone_or_with_both_workers_selects_direct_replay(self):
        for cases in ((SERVICE_WORKER,), (WORKER, SHARED_WORKER, SERVICE_WORKER)):
            for flags in ((True,), (True, True)):
                with self.subTest(cases=cases, flags=flags):
                    direct = {test: result("FAIL", checker.CHROME_DIRECT_RETRY_MESSAGE) for test in cases}
                    proxied = {test: result("PASS") for test in cases}
                    with self.assertRaises(checker.RetryableDirectBaselineMismatch):
                        checker.compare(direct, proxied, *flags)
                    for strict_flags in ((), (False, True)):
                        with self.assertRaises(ValueError) as caught:
                            checker.compare(direct, proxied, *strict_flags)
                        self.assertIs(type(caught.exception), ValueError)

    def test_serviceworker_requires_exact_status_message_and_subtest(self):
        for status, message in (
            ("FAIL", None), ("FAIL", "different Chrome failure"),
            ("FAIL", checker.CHROME_DIRECT_RETRY_MESSAGE + " "),
            ("TIMEOUT", checker.CHROME_DIRECT_RETRY_MESSAGE),
            ("ERROR", checker.CHROME_DIRECT_RETRY_MESSAGE),
            ("NOTRUN", checker.CHROME_DIRECT_RETRY_MESSAGE),
        ):
            with self.subTest(status=status, message=message):
                self.direct = {SERVICE_WORKER: result(status, message)}
                self.proxied = {SERVICE_WORKER: result("PASS")}
                self.assert_not_retryable()
        self.direct = {SERVICE_WORKER: result("FAIL", checker.CHROME_DIRECT_RETRY_MESSAGE)}
        self.proxied = {SERVICE_WORKER: result("PASS")}
        for report in (self.direct, self.proxied):
            report[SERVICE_WORKER]["subtests"][0]["name"] = "Abort unidirectional stream with default error code"
        self.assert_not_retryable()

    def test_both_harnesses_must_be_ok_for_every_direct_context(self):
        for test in (WORKER, SHARED_WORKER, SERVICE_WORKER):
            for before, after in (("ERROR", "OK"), ("OK", "ERROR"), ("ERROR", "ERROR"), ("TIMEOUT", "TIMEOUT")):
                with self.subTest(test=test, before=before, after=after):
                    self.direct = {test: result("FAIL", checker.CHROME_DIRECT_RETRY_MESSAGE, before)}
                    self.proxied = {test: result("PASS", harness_status=after)}
                    self.assert_not_retryable()

    def test_serviceworker_candidate_cannot_hide_another_mismatch(self):
        for other in (OTHER, WORKER):
            with self.subTest(other=other):
                self.direct = {
                    SERVICE_WORKER: result("FAIL", checker.CHROME_DIRECT_RETRY_MESSAGE),
                    other: result("FAIL", "different failure"),
                }
                self.proxied = {test: result("PASS") for test in self.direct}
                self.assert_not_retryable()

    def test_duplicate_subtests_cannot_trigger_direct_replay(self):
        for side in ("direct", "proxied"):
            with self.subTest(side=side):
                self.direct = {SERVICE_WORKER: result("FAIL", checker.CHROME_DIRECT_RETRY_MESSAGE)}
                self.proxied = {SERVICE_WORKER: result("PASS")}
                getattr(self, side)[SERVICE_WORKER]["subtests"] *= 2
                self.assert_not_retryable()

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
        with self.assertRaises(checker.RetryableDirectBaselineMismatch):
            checker.compare(self.direct, self.proxied, True, True)
        with self.assertRaises(ValueError) as caught:
            checker.compare(self.direct, self.proxied, False, True)
        self.assertIs(type(caught.exception), ValueError)

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

    def test_hosted_serviceworker_timeout_cannot_select_either_replay(self):
        direct, proxied = serviceworker_timeout_reports()
        with self.assertRaises(ValueError) as caught:
            checker.compare(
                {entry["test"]: entry for entry in direct["results"]},
                {entry["test"]: entry for entry in proxied["results"]},
                True, True,
            )
        self.assertIs(type(caught.exception), ValueError)
        message = str(caught.exception)
        self.assertIn(f"{SERVICE_WORKER}: harness OK -> TIMEOUT", message)
        self.assertIn("Abort client-created bidirectional stream: PASS -> TIMEOUT", message)
        self.assertEqual(message.count(": PASS -> NOTRUN"), 6)
        self.assertNotIn("Retryable", message)


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
            (("--classify-chrome-direct-retry",), "firefox"),
            (("--classify-chrome-direct-retry", "--classify-chrome-proxy-retry"), "firefox"),
            (("--classify-chrome-proxy-retry", "--classify-chrome-proxy-retry"), "chrome"),
            (("--classify-chrome-direct-retry", "--classify-chrome-direct-retry"), "chrome"),
            (("--unknown-retry",), "chrome"),
        ):
            with self.subTest(flags=flags, browser=browser):
                self.assertEqual(self.run_checker(report, report, *flags, browser=browser).returncode, 1)

    def test_direct_serviceworker_exit_codes_and_strict_terminal_comparison(self):
        proxied = pinned_report()
        direct = copy.deepcopy(proxied)
        set_subtest(direct, SERVICE_WORKER, "FAIL", checker.CHROME_DIRECT_RETRY_MESSAGE)
        for flags, status in (
            (("--classify-chrome-direct-retry",), 3),
            (("--classify-chrome-direct-retry", "--classify-chrome-proxy-retry"), 3),
            (("--classify-chrome-proxy-retry", "--classify-chrome-direct-retry"), 3),
            (("--classify-chrome-proxy-retry",), 1),
            ((), 1),
        ):
            with self.subTest(flags=flags):
                completed = self.run_checker(direct, proxied, *flags)
                self.assertEqual(completed.returncode, status, completed.stderr)
                self.assertIn(f"{SERVICE_WORKER}: {SUBTEST}: FAIL -> PASS", completed.stderr)

    def test_direct_serviceworker_cli_rejects_noneligible_mismatches(self):
        for variation in ("message", "status", "harness", "matching-error-harnesses", "subtest", "extra-mismatch"):
            with self.subTest(variation=variation):
                proxied = pinned_report()
                direct = copy.deepcopy(proxied)
                set_subtest(direct, SERVICE_WORKER, "FAIL", checker.CHROME_DIRECT_RETRY_MESSAGE)
                target = next(entry for entry in direct["results"] if entry["test"] == SERVICE_WORKER)
                if variation == "message":
                    target["subtests"][0]["message"] = "different failure"
                elif variation == "status":
                    target["subtests"][0]["status"] = "TIMEOUT"
                elif variation in ("harness", "matching-error-harnesses"):
                    target["status"] = "ERROR"
                    if variation == "matching-error-harnesses":
                        next(entry for entry in proxied["results"] if entry["test"] == SERVICE_WORKER)["status"] = "ERROR"
                elif variation == "subtest":
                    for report in (direct, proxied):
                        next(entry for entry in report["results"] if entry["test"] == SERVICE_WORKER)["subtests"][0]["name"] = "different subtest"
                else:
                    set_subtest(direct, WORKER, "FAIL", "different failure")
                self.assertEqual(self.run_checker(
                    direct, proxied, "--classify-chrome-direct-retry", "--classify-chrome-proxy-retry",
                ).returncode, 1)

    def test_hosted_serviceworker_timeout_exits_one_with_both_classification_flags(self):
        direct, proxied = serviceworker_timeout_reports()
        completed = self.run_checker(
            direct, proxied, "--classify-chrome-direct-retry", "--classify-chrome-proxy-retry",
        )
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertIn(f"{SERVICE_WORKER}: harness OK -> TIMEOUT", completed.stderr)
        self.assertIn("Abort client-created bidirectional stream: PASS -> TIMEOUT", completed.stderr)
        self.assertEqual(completed.stderr.count(": PASS -> NOTRUN"), 6)
        self.assertNotIn("Retryable", completed.stderr)
        self.assertEqual(completed.stdout, "")

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
import hashlib
import json
import os
import sys
import tomllib
from pathlib import Path

args = sys.argv[1:]
root = Path(os.environ["FAKE_WPT_ROOT"])
state = json.loads((root / "state.json").read_text())
scenario = os.environ["FAKE_WPT_SCENARIO"]
with (root / "commands.jsonl").open("a") as trace:
    trace.write(json.dumps(args) + "\n")
if args[0] == "create":
    name = args[args.index("--name") + 1]
    network = args[args.index("--network") + 1] if "--network" in args else None
    state.setdefault("creates", []).append({"container": name, "network": network})
    state.setdefault("active", []).append(name)
    (root / "state.json").write_text(json.dumps(state))
elif args[0] == "start":
    state.setdefault("starts", []).extend(args[1:])
    (root / "state.json").write_text(json.dumps(state))
elif args[0] == "rm":
    containers = [arg for arg in args[1:] if not arg.startswith("-")]
    state.setdefault("removals", []).append(containers)
    state["active"] = [name for name in state.get("active", []) if name not in containers]
    (root / "state.json").write_text(json.dumps(state))
elif args[0] == "exec" and "./wpt" in args:
    assert args[-1] == "webtransport/"
    assert args[args.index("--test-types") + 1:args.index("--test-types") + 3] == ["testharness", "crashtest"]
    report_name = next(arg.split("=", 1)[1] for arg in args if arg.startswith("--log-wptreport="))
    report_name = Path(report_name).stem
    raw_path = next(arg.split("=", 1)[1] for arg in args if arg.startswith("--log-raw="))
    assert raw_path == f"/artifacts/{report_name}.events.jsonl"
    environment = dict(args[index + 1].split("=", 1) for index, arg in enumerate(args) if arg == "--env")
    assert environment["HOME"] == "/home/wpt"
    if report_name.startswith("firefox-"):
        assert environment["MOZ_LOG"] == "timestamp,rotate:32,nsHttp:5,neqo_http3::*:5,neqo_transport::*:5"
        log_template = f"/artifacts/{report_name}-moz%PID.log"
        assert environment["MOZ_LOG_FILE"] == log_template
        for parent_pid in (4200, 4201):
            for process, pid in (("main", parent_pid), ("child", parent_pid + 100)):
                expanded_path = Path(log_template.replace("%PID", f"-{process}.{pid}"))
                if not str(expanded_path).endswith(".moz_log"):
                    expanded_path = Path(f"{expanded_path}.moz_log")
                log_path = root / "artifacts" / expanded_path.name
                for rotation in range(4):
                    Path(f"{log_path}.{rotation}").unlink(missing_ok=True)
                log_path.unlink(missing_ok=True)
                log_path.write_text(f"synthetic Firefox {process} network log {report_name} {pid}\n")
                Path(f"{log_path}.0").write_text(f"synthetic Firefox {process} rotated log {report_name} {pid}\n")
    else:
        assert "MOZ_LOG" not in environment and "MOZ_LOG_FILE" not in environment
    with (root / "artifacts" / Path(raw_path).name).open("x") as raw:
        raw.write(json.dumps({"action": "suite_start", "time": 1234, "report": report_name}) + "\n")
    state["runs"].append(report_name)
    container = args[args.index("./wpt") - 1]
    assert container in state["active"] and container in state["starts"]
    state.setdefault("invocations", []).append({"report": report_name, "raw": raw_path, "environment": environment, "container": container})
    retry = report_name == "chrome-proxied-retry"
    direct_retry = report_name == "chrome-direct-retry"
    firefox_retry = report_name == "firefox-proxied-retry"
    if "proxied" in report_name and not (
        (retry and scenario == "missing-packets") or (firefox_retry and scenario == "firefox-missing-packets")
        or (report_name == "chrome-proxied" and scenario == "initial-missing-packets")
    ):
        state["packets"] += 1
    (root / "state.json").write_text(json.dumps(state))
    report = json.loads((root / "passing.json").read_text())
    if (report_name == "chrome-direct" and (scenario == "mixed" or scenario.startswith("direct-"))) or (
        direct_retry and scenario in ("direct-persistent", "direct-migrating")
    ):
        context = "worker" if scenario == "mixed" or (direct_retry and scenario == "direct-migrating") else "serviceworker"
        entry = next(entry for entry in report["results"] if entry["test"] == f"/webtransport/streams-close.https.any.{context}.html")
        entry["subtests"][0].update(status="FAIL", message='assert_equals: reset_stream expected "reset" but got "FIN"')
    if report_name == "chrome-proxied" and scenario == "serviceworker-timeout":
        report = json.loads((root / "timeout.json").read_text())
    failure = (report_name == "chrome-proxied" and scenario != "serviceworker-timeout" and not scenario.startswith(("firefox-", "direct-"))) or (retry and scenario == "persistent")
    if failure or (retry and scenario == "migrating"):
        context = "worker" if retry and scenario == "migrating" else "serviceworker"
        target = f"/webtransport/streams-close.https.any.{context}.html"
        entry = next(entry for entry in report["results"] if entry["test"] == target)
        entry["subtests"][0].update(status="FAIL", message='assert_equals: reset_stream expected "reset" but got "FIN"')
        if report_name == "chrome-proxied" and scenario == "wrong-message":
            entry["subtests"][0]["message"] = "different failure"
    if scenario.startswith("firefox-"):
        initial_failure = report_name == "firefox-proxied" and scenario != "firefox-normal"
        repeated_failure = firefox_retry and scenario in ("firefox-persistent", "firefox-migrating")
        if initial_failure or repeated_failure:
            if firefox_retry and scenario == "firefox-migrating":
                target = "/webtransport/streams-close.https.any.worker.html"
                name = "Close outgoing stream / bidi-2"
            else:
                target = "/webtransport/streams-echo.https.any.html"
                name = "WebTransport client should be able to create, accept, and handle a unidirectional stream"
            entry = next(entry for entry in report["results"] if entry["test"] == target)
            entry.update(status="ERROR", message="Unhandled rejection: WebTransport connection rejected")
            subtest = next(subtest for subtest in entry["subtests"] if subtest["name"] == name)
            subtest.update(status="FAIL", message='promise_test: Unhandled rejection with value: object "WebTransportError: WebTransport connection rejected"')
    report_path = root / "artifacts" / f"{report_name}.json"
    with report_path.open("x") as output:
        output.write(json.dumps(report))
    state.setdefault("artifact_digests", {})[report_name] = {
        suffix: hashlib.sha256((root / "artifacts" / f"{report_name}.{suffix}").read_bytes()).hexdigest()
        for suffix in ("json", "events.jsonl")
    }
    (root / "state.json").write_text(json.dumps(state))
    print(f"synthetic WPT {report_name}")
    sys.exit(7 if (retry and scenario == "run-fails") or (direct_retry and scenario == "direct-run-fails") or (firefox_retry and scenario == "firefox-run-fails") or (report_name == "chrome-direct" and scenario == "initial-direct-run-fails") else 0)
elif args[0] == "exec" and "--version" in args:
    print("Google Chrome for Testing 155.0.8059.84" if "/opt/chrome/chrome" in args else "Mozilla Firefox 158.0.1")
elif args[0] == "exec" and "/usr/sbin/iptables" in args:
    state.setdefault("nat_containers", []).append(args[args.index("/usr/sbin/iptables") - 1])
    (root / "state.json").write_text(json.dumps(state))
    if "-L" in args:
        print(f'{state["packets"]} 0 DNAT udp')
elif args[0] == "cp":
    if args[-2] == "-":
        sys.stdin.buffer.read()
    elif ":" not in args[-1]:
        Path(args[-1]).write_text("synthetic certificate fixture\n")
    elif args[-1].endswith("/oxibelt.toml"):
        config = Path(args[-2]).read_text()
        assert '[logging]\nlevel = "info,oxibelt::proxy::http3::webtransport_connect=debug"' in config
        assert "webtransport_only_connections = true" in config
        state["proxy_config"] = tomllib.loads(config)
        (root / "state.json").write_text(json.dumps(state))
elif args[0] == "inspect":
    print("true")
elif args[0] == "logs":
    print("synthetic proxy log")
'''


class ReplayShellTestCase(unittest.TestCase):
    def run_gate(self, scenario, expected_retries=1, expected_direct_retries=0):
        temporary = tempfile.TemporaryDirectory(prefix="oxibelt-wpt-shell-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "artifacts").mkdir()
        (root / "bin").mkdir()
        passing = pinned_report()
        if scenario.startswith("firefox-"):
            indexed = {entry["test"]: entry for entry in passing["results"]}
            indexed["/webtransport/streams-echo.https.any.worker.html"]["subtests"].extend(
                copy.deepcopy(indexed["/webtransport/streams-echo.https.any.html"]["subtests"])
            )
            indexed[WORKER]["subtests"].append(
                {"name": "Close outgoing stream / bidi-2", "status": "PASS", "message": None}
            )
        if scenario == "serviceworker-timeout":
            passing, timeout_report = serviceworker_timeout_reports()
            (root / "timeout.json").write_text(json.dumps(timeout_report))
        (root / "passing.json").write_text(json.dumps(passing))
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
        self.assertEqual(state["runs"].count("chrome-direct-retry"), expected_direct_retries, completed.stderr)
        self.assertEqual(state["active"], [], completed.stderr)
        for name in state["runs"]:
            for suffix in ("json", "log", "exit", "events.jsonl"):
                self.assertTrue((root / "artifacts" / f"{name}.{suffix}").is_file(), completed.stderr)
            raw = (root / "artifacts" / f"{name}.events.jsonl").read_text()
            self.assertEqual(json.loads(raw)["report"], name)
            for suffix, digest in state["artifact_digests"][name].items():
                self.assertEqual(hashlib.sha256((root / "artifacts" / f"{name}.{suffix}").read_bytes()).hexdigest(), digest)
            self.assertIn(f"synthetic WPT {name}", (root / "artifacts" / f"{name}.log").read_text())
            if name.startswith("firefox-"):
                artifacts = root / "artifacts"
                parent_logs = sorted(artifacts.glob(f"{name}-moz-main.*.log.moz_log"))
                child_logs = sorted(artifacts.glob(f"{name}-moz-child.*.log.moz_log"))
                self.assertEqual(len(parent_logs), 2, completed.stderr)
                self.assertEqual(len({path.name for path in parent_logs}), 2, completed.stderr)
                self.assertEqual(len(child_logs), 2, completed.stderr)
                for network_log in parent_logs + child_logs:
                    self.assertIn(name, network_log.read_text(), completed.stderr)
                    self.assertIn(name, Path(f"{network_log}.0").read_text(), completed.stderr)
            else:
                self.assertFalse(list((root / "artifacts").glob(f"{name}-moz*")))
        if "chrome-proxied" in state["runs"]:
            original = json.loads((root / "artifacts" / "chrome-proxied.json").read_text())
            target = next(entry for entry in original["results"] if entry["test"] == SERVICE_WORKER)
            if scenario == "serviceworker-timeout":
                self.assertEqual(original, timeout_report)
            elif not scenario.startswith(("firefox-", "direct-")):
                self.assertEqual(target["subtests"][0]["status"], "FAIL")
        return completed, state, root


class RunnerNamespaceShellTests(ReplayShellTestCase):
    def test_direct_and_proxied_passes_use_distinct_conntrack_namespaces(self):
        completed, state, root = self.run_gate("firefox-normal", expected_retries=0)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        invocations = {item["report"]: item for item in state["invocations"]}
        direct = invocations["chrome-direct"]["container"]
        proxied = invocations["chrome-proxied"]["container"]
        self.assertEqual(invocations["firefox-direct"]["container"], direct)
        self.assertEqual(invocations["firefox-proxied"]["container"], proxied)
        self.assertNotEqual(direct, proxied)
        creates = {item["container"]: item for item in state["creates"]}
        self.assertIsNone(creates[direct]["network"])
        self.assertIsNone(creates[proxied]["network"])
        proxy = next(name for name in creates if name not in (direct, proxied))
        self.assertEqual(creates[proxy]["network"], f"container:{proxied}")
        commands = [json.loads(line) for line in (root / "commands.jsonl").read_text().splitlines()]
        removed = next(i for i, args in enumerate(commands) if args[0] == "rm" and direct in args)
        proxy_runner_created = next(i for i, args in enumerate(commands) if args[0] == "create" and proxied in args)
        first_nat = next(i for i, args in enumerate(commands) if "/usr/sbin/iptables" in args)
        direct_runs = [i for i, args in enumerate(commands) if "./wpt" in args and direct == args[args.index("./wpt") - 1]]
        self.assertEqual(len(direct_runs), 2)
        self.assertLess(max(direct_runs), removed)
        self.assertLess(removed, proxy_runner_created)
        self.assertLess(proxy_runner_created, first_nat)
        self.assertEqual(set(state["nat_containers"]), {proxied})
        self.assertFalse(any("conntrack" in argument for args in commands for argument in args))

    def test_upstream_alias_partitions_nat_tuples_and_browser_counter(self):
        completed, state, root = self.run_gate("firefox-normal", expected_retries=0)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        commands = [json.loads(line) for line in (root / "commands.jsonl").read_text().splitlines()]
        nat = [(i, args) for i, args in enumerate(commands) if "/usr/sbin/iptables" in args]

        def value(args, option):
            return args[args.index(option) + 1] if option in args else None

        def matches(args, action, chain, owner, destination, target, translated=None):
            return (value(args, "-t") == "nat" and value(args, action) == chain
                    and value(args, "--uid-owner") == owner and value(args, "-d") == destination
                    and value(args, "-p") == "udp" and value(args, "--dport") == "11000"
                    and value(args, "-j") == target and value(args, "--to-destination") == translated)

        upstream = [(i, args) for i, args in nat if matches(
            args, "-A", "OUTPUT", "10001", "127.0.0.3/32", "DNAT", "127.0.0.1:11000")]
        browser = [(i, args) for i, args in nat if matches(
            args, "-A", "OUTPUT", "10002", "127.0.0.1/32", "OXIWPT")]
        browser_dnat = [(i, args) for i, args in nat if matches(
            args, "-A", "OXIWPT", None, "127.0.0.1/32", "DNAT", "127.0.0.2:11000")]
        self.assertEqual(len(upstream), 1)
        self.assertEqual(len(browser), 1)
        self.assertEqual(len(browser_dnat), 1)
        self.assertEqual([args for _, args in nat if value(args, "-A") == "OXIWPT"], [browser_dnat[0][1]])
        self.assertTrue(any(matches(args, "-C", "OUTPUT", "10001", "127.0.0.3/32", "DNAT", "127.0.0.1:11000") for _, args in nat))
        self.assertTrue(any(matches(args, "-C", "OUTPUT", "10002", "127.0.0.1/32", "OXIWPT") for _, args in nat))
        counters = [args for _, args in nat if "-L" in args]
        self.assertTrue(counters)
        self.assertTrue(all(value(args, "-L") == "OXIWPT" for args in counters))
        first_proxy_run = next(i for i, args in enumerate(commands)
                               if any(arg == "--log-wptreport=/artifacts/chrome-proxied.json" for arg in args))
        self.assertLess(max(upstream[0][0], browser[0][0], browser_dnat[0][0]), first_proxy_run)
        config = state["proxy_config"]
        self.assertEqual(config["listeners"]["https_bind"], "127.0.0.2:11000")
        upstream_config = config["upstreams"][0]
        self.assertEqual(upstream_config["origin"], "https://127.0.0.3:11000")
        self.assertTrue(upstream_config["preserve_host"])
        self.assertEqual(upstream_config["tls"]["server_name"], "web-platform.test")
        self.assertEqual(upstream_config["tls"]["trust"], "exclusive")
        self.assertEqual(upstream_config["tls"]["trusted_ca_certs"], ["cacert.pem"])
        self.assertEqual(config["routes"][0]["hosts"], ["web-platform.test", "not-web-platform.test"])

    def test_failed_initial_direct_run_stops_before_proxy_namespace_or_nat(self):
        completed, state, root = self.run_gate("initial-direct-run-fails", expected_retries=0)
        self.assertEqual(completed.returncode, 7, completed.stderr)
        self.assertEqual(state["runs"], ["chrome-direct"])
        self.assertEqual(len(state["creates"]), 1)
        self.assertEqual((root / "artifacts/chrome-direct.exit").read_text().strip(), "7")
        self.assertFalse(state.get("nat_containers"))

    def test_initial_proxy_without_browser_traversal_fails_before_replay(self):
        completed, state, _ = self.run_gate("initial-missing-packets", expected_retries=0)
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(state["runs"], ["chrome-direct", "firefox-direct", "chrome-proxied"])
        self.assertEqual(state["packets"], 0)
        self.assertIn("chrome: no browser WebTransport packets reached the proxy DNAT rule.", completed.stderr)


class ProxyReplayShellTests(ReplayShellTestCase):
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

    def test_hosted_serviceworker_timeout_preserves_initial_failure_without_replay(self):
        completed, state, root = self.run_gate("serviceworker-timeout", expected_retries=0)
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(state["runs"], ["chrome-direct", "firefox-direct", "chrome-proxied"])
        self.assertEqual(state["packets"], 1)
        direct, proxied = serviceworker_timeout_reports()
        for name, expected in (("chrome-direct", direct), ("chrome-proxied", proxied)):
            self.assertEqual(json.loads((root / "artifacts" / f"{name}.json").read_text()), expected)
            self.assertEqual((root / "artifacts" / f"{name}.exit").read_text().strip(), "0")
            self.assertIn(f"synthetic WPT {name}", (root / "artifacts" / f"{name}.log").read_text())
        self.assertIn(f"{SERVICE_WORKER}: harness OK -> TIMEOUT", completed.stderr)
        self.assertIn("Abort client-created bidirectional stream: PASS -> TIMEOUT", completed.stderr)
        self.assertEqual(completed.stderr.count(": PASS -> NOTRUN"), 6)
        self.assertNotIn("Retryable", completed.stderr)
        self.assertNotIn("retrying", completed.stderr)
        self.assertFalse(list((root / "artifacts").glob("*retry*")))

    def test_firefox_normal_pass_retains_separate_diagnostics_without_replay(self):
        completed, state, _ = self.run_gate("firefox-normal", expected_retries=0)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(state["runs"], ["chrome-direct", "firefox-direct", "chrome-proxied", "firefox-proxied"])
        self.assertEqual(state["packets"], 2)

    def test_firefox_one_complete_proxy_replay_preserves_original_rejection(self):
        completed, state, root = self.run_gate("firefox-passes", expected_retries=0)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(state["runs"], ["chrome-direct", "firefox-direct", "chrome-proxied", "firefox-proxied", "firefox-proxied-retry"])
        self.assertEqual(state["packets"], 3)
        self.assertEqual(completed.stderr.count("Firefox WPT parity mismatch; retrying one full proxied pass."), 1)
        target = "/webtransport/streams-echo.https.any.html"
        original = json.loads((root / "artifacts" / "firefox-proxied.json").read_text())
        self.assertEqual(next(entry for entry in original["results"] if entry["test"] == target)["status"], "ERROR")
        direct = json.loads((root / "artifacts" / "firefox-direct.json").read_text())
        replay = json.loads((root / "artifacts" / "firefox-proxied-retry.json").read_text())
        self.assertEqual(replay, direct)

    def test_firefox_persistent_and_hosted_migrating_rejections_are_terminal(self):
        for scenario in ("firefox-persistent", "firefox-migrating"):
            with self.subTest(scenario=scenario):
                completed, state, root = self.run_gate(scenario, expected_retries=0)
                self.assertEqual(completed.returncode, 1, completed.stderr)
                self.assertEqual(state["runs"], ["chrome-direct", "firefox-direct", "chrome-proxied", "firefox-proxied", "firefox-proxied-retry"])
                self.assertEqual(completed.stderr.count("Firefox WPT parity mismatch; retrying one full proxied pass."), 1)
                self.assertEqual(state["runs"].count("firefox-proxied-retry"), 1)
                original = json.loads((root / "artifacts" / "firefox-proxied.json").read_text())
                replay = json.loads((root / "artifacts" / "firefox-proxied-retry.json").read_text())
                echo = "/webtransport/streams-echo.https.any.html"
                self.assertEqual(next(entry for entry in original["results"] if entry["test"] == echo)["status"], "ERROR")
                target = WORKER if scenario == "firefox-migrating" else echo
                self.assertEqual(next(entry for entry in replay["results"] if entry["test"] == target)["status"], "ERROR")
                self.assertIn(f"{target}: harness OK -> ERROR", completed.stderr)
                if scenario == "firefox-migrating":
                    self.assertEqual(next(entry for entry in replay["results"] if entry["test"] == echo)["status"], "OK")
                    self.assertIn("Close outgoing stream / bidi-2: PASS -> FAIL", completed.stderr)

    def test_firefox_missing_retry_packets_is_terminal_with_diagnostics_retained(self):
        completed, state, _ = self.run_gate("firefox-missing-packets", expected_retries=0)
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(state["runs"].count("firefox-proxied-retry"), 1)
        self.assertEqual(state["packets"], 2)
        self.assertIn("Firefox retry: no browser WebTransport packets reached the proxy DNAT rule.", completed.stderr)

    def test_firefox_failed_replay_preserves_exit_status_and_diagnostics(self):
        completed, state, root = self.run_gate("firefox-run-fails", expected_retries=0)
        self.assertEqual(completed.returncode, 7, completed.stderr)
        self.assertEqual(state["runs"].count("firefox-proxied-retry"), 1)
        self.assertEqual((root / "artifacts" / "firefox-proxied-retry.exit").read_text().strip(), "7")


class DirectReplayShellTests(ReplayShellTestCase):
    def run_direct_gate(self, scenario):
        completed, state, root = self.run_gate(scenario, expected_retries=0, expected_direct_retries=1)
        self.assertEqual(completed.stderr.count("Chrome direct close/abort mismatch; retrying one full direct pass."), 1)
        self.assertNotIn("chrome-proxied-retry", state["runs"])
        self.assertFalse((root / "artifacts" / "chrome-proxied-retry.json").exists())
        invocations = {invocation["report"]: invocation for invocation in state["invocations"]}
        initial_runner = invocations["chrome-direct"]["container"]
        retry_runner = invocations["chrome-direct-retry"]["container"]
        self.assertNotEqual(retry_runner, initial_runner)
        proxied_runner = invocations["chrome-proxied"]["container"]
        self.assertEqual(len({initial_runner, proxied_runner, retry_runner}), 3)
        creates = {creation["container"]: creation for creation in state["creates"]}
        self.assertEqual(len(creates), 4)
        for runner in (initial_runner, proxied_runner, retry_runner):
            self.assertIsNone(creates[runner]["network"])
        proxy = next(name for name in creates if name not in (initial_runner, proxied_runner, retry_runner))
        self.assertEqual(creates[proxy]["network"], f"container:{proxied_runner}")
        self.assertEqual(state["starts"].count(retry_runner), 1)
        self.assertTrue(state["nat_containers"])
        self.assertEqual(set(state["nat_containers"]), {proxied_runner})
        self.assertTrue(any(retry_runner in removal for removal in state["removals"]))
        self.assertEqual(set(state["removals"][-1]), set(creates))
        original = json.loads((root / "artifacts" / "chrome-direct.json").read_text())
        target = next(entry for entry in original["results"] if entry["test"] == SERVICE_WORKER)
        self.assertEqual(target["subtests"][0]["status"], "FAIL")
        self.assertEqual(target["subtests"][0]["message"], checker.CHROME_DIRECT_RETRY_MESSAGE)
        self.assertEqual(json.loads((root / "artifacts" / "chrome-proxied.json").read_text()), pinned_report())
        self.assertEqual((root / "artifacts" / "chrome-direct.exit").read_text().strip(), "0")
        self.assertEqual((root / "artifacts" / "chrome-proxied.exit").read_text().strip(), "0")
        return completed, state, root

    def test_one_full_serviceworker_direct_replay_passes_in_fresh_container(self):
        completed, state, root = self.run_direct_gate("direct-passes")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(state["runs"], ["chrome-direct", "firefox-direct", "chrome-proxied", "chrome-direct-retry", "firefox-proxied"])
        self.assertEqual(state["packets"], 2)
        self.assertEqual(json.loads((root / "artifacts" / "chrome-direct-retry.json").read_text()), pinned_report())
        self.assertEqual((root / "artifacts" / "chrome-direct-retry.exit").read_text().strip(), "0")

    def test_persistent_or_migrating_direct_failure_is_terminal_after_one_replay(self):
        for scenario, failing_case in (("direct-persistent", SERVICE_WORKER), ("direct-migrating", WORKER)):
            with self.subTest(scenario=scenario):
                completed, state, root = self.run_direct_gate(scenario)
                self.assertEqual(completed.returncode, 1, completed.stderr)
                self.assertEqual(state["runs"], ["chrome-direct", "firefox-direct", "chrome-proxied", "chrome-direct-retry"])
                self.assertEqual(state["packets"], 1)
                replay = json.loads((root / "artifacts" / "chrome-direct-retry.json").read_text())
                target = next(entry for entry in replay["results"] if entry["test"] == failing_case)
                self.assertEqual(target["subtests"][0]["status"], "FAIL")
                self.assertIn(f"{failing_case}: {SUBTEST}: FAIL -> PASS", completed.stderr)
                self.assertEqual((root / "artifacts" / "chrome-direct-retry.exit").read_text().strip(), "0")
                if scenario == "direct-migrating":
                    recovered = next(entry for entry in replay["results"] if entry["test"] == SERVICE_WORKER)
                    self.assertEqual(recovered["subtests"][0]["status"], "PASS")

    def test_failed_direct_replay_propagates_wpt_exit_and_cleans_up(self):
        completed, state, root = self.run_direct_gate("direct-run-fails")
        self.assertEqual(completed.returncode, 7, completed.stderr)
        self.assertEqual(state["runs"], ["chrome-direct", "firefox-direct", "chrome-proxied", "chrome-direct-retry"])
        self.assertEqual((root / "artifacts" / "chrome-direct-retry.exit").read_text().strip(), "7")
        self.assertEqual(state["packets"], 1)


if __name__ == "__main__":
    unittest.main()
