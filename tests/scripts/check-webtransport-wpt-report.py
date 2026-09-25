#!/usr/bin/env python3
"""Compare full pinned WPT WebTransport runs without hiding baseline failures."""

import hashlib
import json
import sys
from pathlib import Path


CONTROLS = (
    ("connect.https.any", "WebTransport session is established with status code 200"),
    ("streams-echo.https.any", "WebTransport client should be able to create and handle a bidirectional stream"),
    ("streams-echo.https.any", "WebTransport client should be able to create, accept, and handle a unidirectional stream"),
    ("datagrams-writable.https.any", "WebTransportDatagramsWritable can write and receive datagrams"),
    ("close.https.any", "close"),
)

# All browser-expanded test IDs from the pinned WPT WebTransport tree with
# testharness and crashtest enabled. This catches missing variants as well as
# an accidentally narrowed selection that happens to keep the same count.
EXPECTED_CASE_COUNT = 103
EXPECTED_CASE_IDS_SHA256 = "ba9e567c8331d61352899f0463df184820b280dab2fe24a79a255a8b371f58c7"


def load(path):
    report = json.loads(Path(path).read_text())
    results = report.get("results")
    if not isinstance(results, list) or not results:
        raise ValueError(f"{path}: missing WPT results")
    indexed = {}
    for result in results:
        test = result["test"]
        if not test.startswith("/webtransport/") or test in indexed:
            raise ValueError(f"{path}: unexpected or duplicate test {test}")
        indexed[test] = result
    if "/webtransport/bidirectional-cancel-crash.https.html" not in indexed:
        raise ValueError(f"{path}: pinned WebTransport crashtest did not run")
    case_ids_hash = hashlib.sha256(("\n".join(sorted(indexed)) + "\n").encode()).hexdigest()
    if len(indexed) != EXPECTED_CASE_COUNT or case_ids_hash != EXPECTED_CASE_IDS_SHA256:
        raise ValueError(
            f"{path}: unexpected pinned WebTransport case set: "
            f"count={len(indexed)} sha256={case_ids_hash}"
        )
    return indexed


def passed_controls(results, label):
    for basename, control in CONTROLS:
        matches = [
            subtest
            for test, result in results.items()
            if basename in test and result.get("status") == "OK"
            for subtest in result.get("subtests", [])
            if subtest.get("name") == control and subtest.get("status") == "PASS"
        ]
        if not matches:
            raise ValueError(f"{label}: missing passing control: {basename}: {control}")


def compare(direct, proxied):
    if set(direct) != set(proxied):
        only_direct = sorted(set(direct) - set(proxied))
        only_proxy = sorted(set(proxied) - set(direct))
        raise ValueError(f"test selection differs: direct-only={only_direct}, proxy-only={only_proxy}")
    regressions = []
    for test in sorted(direct):
        before = direct[test]
        after = proxied[test]
        if before.get("status") != after.get("status"):
            regressions.append(f"{test}: harness {before.get('status')} -> {after.get('status')}")
        before_entries = before.get("subtests", [])
        after_entries = after.get("subtests", [])
        before_subtests = {entry["name"]: entry["status"] for entry in before_entries}
        after_subtests = {entry["name"]: entry["status"] for entry in after_entries}
        if len(before_subtests) != len(before_entries) or len(after_subtests) != len(after_entries):
            regressions.append(f"{test}: duplicate subtest name")
            continue
        if set(before_subtests) != set(after_subtests):
            regressions.append(f"{test}: subtest selection differs")
            continue
        for name, status in before_subtests.items():
            if status != after_subtests[name]:
                regressions.append(f"{test}: {name}: {status} -> {after_subtests[name]}")
    if regressions:
        raise ValueError("direct/proxy baseline mismatch:\n" + "\n".join(regressions))
    print(f"WPT WebTransport parity: {len(direct)} cases; no proxy regressions from direct baseline")


def main():
    if len(sys.argv) != 4:
        raise ValueError("usage: check-webtransport-wpt-report.py <browser> <direct.json> <proxied.json>")
    browser, direct_path, proxy_path = sys.argv[1:]
    direct = load(direct_path)
    proxied = load(proxy_path)
    passed_controls(direct, f"{browser} direct")
    passed_controls(proxied, f"{browser} proxied")
    compare(direct, proxied)


if __name__ == "__main__":
    try:
        main()
    except (KeyError, ValueError, json.JSONDecodeError) as exc:
        print(exc, file=sys.stderr)
        sys.exit(1)
