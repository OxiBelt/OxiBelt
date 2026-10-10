#!/usr/bin/env python3
"""Enforcement and ownership regressions without Docker or stress workloads."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import stat
import struct
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

SPEC = importlib.util.spec_from_file_location("native_enforcement", Path(__file__).with_name("check-riscv-rootless-enforcement.py"))
assert SPEC and SPEC.loader
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)
TOKEN = "a" * 32
INFO = {"ServerVersion": "29.8.0", "OSType": "linux", "Architecture": "riscv64", "CgroupVersion": "2",
        "CgroupDriver": "systemd", "SecurityOptions": ["name=rootless", "name=cgroupns", "name=seccomp,profile=builtin"]}


def logs(mode):
    value = json.dumps(PROBE.CONTROLS) + "\n"
    if mode == "cpu":
        value += json.dumps({"mode": mode, "nr_throttled_before": 0, "nr_throttled_after": 2}) + "\n"
    elif mode == "pids":
        value += json.dumps({"mode": mode, "children": 31, "fork_blocked": True,
                            "pids_max_before": 0, "pids_max_after": 1, "children_reaped": True}) + "\n"
    return value


class FakeDocker:
    def __init__(self):
        self.calls = []
        self.images = {}
        self.containers = {}
        self.fail_mode = None
        self.cleanup_failure = False
        self.image_id = "sha256:" + "b" * 64
        self.next_id = 1

    def begin_cleanup(self):
        pass

    def call(self, args):
        self.calls.append(args)
        if args[0] == "info":
            return 0, json.dumps(INFO)
        if args[:2] in (["image", "inspect"], ["container", "inspect"]):
            collection = self.images if args[0] == "image" else self.containers
            value = collection.get(args[2])
            return (0, json.dumps([value])) if value else (1, "")
        if args[:2] == ["image", "ls"]:
            name = args[-1].removeprefix("reference=")
            return 0, self.images.get(name, {}).get("Id", "")
        if args[:2] == ["container", "ls"]:
            name = args[-1].removeprefix("name=^/").removesuffix("$")
            return 0, self.containers.get(name, {}).get("Id", "")
        if args[0] == "build":
            root = Path(args[-1])
            assert (root / "Dockerfile").read_text().startswith("FROM scratch\n")
            assert (root / "limit-probe").is_file()
            tag = args[args.index("--tag") + 1]
            self.images[tag] = {"Id": self.image_id, "Config": {"Labels": {PROBE.LABEL: TOKEN}}}
            return 0, ""
        if args[0] == "create":
            if any(flag.startswith("--cpus=") for flag in args) and any(
                flag.startswith(("--cpu-period=", "--cpu-quota=")) for flag in args
            ):
                return 1, "Conflicting NanoCPUs and CPUPeriod/CPUQuota options"
            name = args[args.index("--name") + 1]
            identifier = f"{self.next_id:064x}"
            self.next_id += 1
            mode = args[-1]
            self.containers[name] = {"Id": identifier, "mode": mode, "Config": {"Labels": {PROBE.LABEL: TOKEN}},
                "State": {"Status": "exited", "ExitCode": 137 if mode == "memory" else 0, "OOMKilled": mode == "memory"}}
            return 0, identifier + "\n"
        if args[0] in ("start", "wait"):
            return 0, "0\n"
        if args[0] == "logs":
            container = next(value for value in self.containers.values() if value["Id"] == args[1])
            return 0, '{"error":"unverified"}\n' if container["mode"] == self.fail_mode else logs(container["mode"])
        if args[0] == "rm":
            if self.cleanup_failure:
                return 1, ""
            name = next(name for name, value in self.containers.items() if value["Id"] == args[-1])
            del self.containers[name]
            return 0, ""
        if args[:2] == ["image", "rm"]:
            name = next(name for name, value in self.images.items() if value["Id"] == args[-1])
            del self.images[name]
            return 0, ""
        raise AssertionError(args)

    def checked(self, args):
        code, value = self.call(args)
        if code:
            raise PROBE.ProbeError("docker-command-failed")
        return value


class EnforcementTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="oxibelt-enforcement-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.binary = self.root / "limit-probe"
        self.binary.write_bytes(b"not executed by tests")
        self.patch = mock.patch.object(PROBE, "PROBE_BINARY", self.binary)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def test_three_positive_controls_and_exact_ownership_cleanup(self):
        docker = FakeDocker()
        enforcement = PROBE.Enforcement(docker, TOKEN)
        receipt = {"checks": []}
        enforcement.run(receipt)
        self.assertEqual([row["mode"] for row in receipt["checks"]], ["cpu", "memory", "pids"])
        self.assertEqual(enforcement.cleanup(), [])
        self.assertFalse(docker.containers)
        self.assertFalse(docker.images)
        creates = [args for args in docker.calls if args[0] == "create"]
        for args in creates:
            for flag in ("--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                         "--cgroupns=private", "--cpu-period=100000", "--cpu-quota=50000",
                         "--memory=64m", "--memory-swap=64m", "--pids-limit=32"):
                self.assertIn(flag, args)
            self.assertFalse(any(flag.startswith("--cpus=") for flag in args))
            self.assertIn(docker.image_id, args)
        self.assertTrue(all("prune" not in args and "--privileged" not in args for args in docker.calls))

    def test_failed_positive_control_still_cleans_exact_resources(self):
        docker = FakeDocker()
        docker.fail_mode = "memory"
        enforcement = PROBE.Enforcement(docker, TOKEN)
        with self.assertRaises(PROBE.ProbeError):
            enforcement.run({"checks": []})
        self.assertEqual(enforcement.cleanup(), [])
        self.assertFalse(docker.images or docker.containers)

    def test_missing_inspect_is_not_cleanup_confirmation_on_transport_failure(self):
        docker = FakeDocker()
        enforcement = PROBE.Enforcement(docker, TOKEN)
        enforcement.run({"checks": []})
        docker.cleanup_failure = True
        failures = enforcement.cleanup()
        self.assertEqual(failures.count("container-cleanup-failed"), 3)
        self.assertEqual(len(docker.containers), 3)
        with mock.patch.object(docker, "call", return_value=(1, "secret transport error")):
            with self.assertRaises(PROBE.ProbeError):
                enforcement.owned("missing")

    def test_cleanup_does_not_remove_resources_with_different_ownership(self):
        docker = FakeDocker()
        enforcement = PROBE.Enforcement(docker, TOKEN)
        enforcement.run({"checks": []})
        for value in docker.containers.values():
            value["Config"]["Labels"][PROBE.LABEL] = "foreign"
        for value in docker.images.values():
            value["Config"]["Labels"][PROBE.LABEL] = "foreign"
        self.assertEqual(len(enforcement.cleanup()), 4)
        self.assertFalse(any(args[0] == "rm" or args[:2] == ["image", "rm"] for args in docker.calls))

    def test_rootful_wrong_version_architecture_driver_or_seccomp_are_rejected(self):
        for field, value in (("ServerVersion", "28.0.4"), ("Architecture", "x86_64"),
                             ("CgroupVersion", "1"), ("CgroupDriver", "none"), ("SecurityOptions", ["name=rootless"])):
            with self.subTest(field=field), self.assertRaises(PROBE.ProbeError):
                PROBE.validate_info({**INFO, field: value})
        self.assertNotIn("private=secret", str(PROBE.validate_info({**INFO, "SecurityOptions": INFO["SecurityOptions"] + ["private=secret"]})))

    def test_cgroup_effective_values_oom_state_and_positive_counters_are_required(self):
        state = {"Status": "exited", "ExitCode": 0, "OOMKilled": False}
        self.assertEqual(PROBE.validate_mode("cpu", logs("cpu"), state)["result"]["nr_throttled_after"], 2)
        for mode, output, wrong_state in (
            ("cpu", logs("cpu").replace('"nr_throttled_after": 2', '"nr_throttled_after": 0'), state),
            ("cpu", logs("cpu").replace("50000 100000", "max 100000"), state),
            ("pids", logs("pids").replace('"children_reaped": true', '"children_reaped": false'), state),
            ("memory", logs("memory"), {"Status": "exited", "ExitCode": 137, "OOMKilled": False}),
            ("memory", logs("memory"), {"Status": "exited", "ExitCode": 0, "OOMKilled": True}),
            ("cpu", logs("cpu") + "SECRET=credentials\n", state),
        ):
            with self.subTest(mode=mode), self.assertRaises(PROBE.ProbeError):
                PROBE.validate_mode(mode, output, wrong_state)

    def test_static_native_elf_rejects_foreign_dynamic_and_malformed_headers(self):
        raw = bytearray(120)
        raw[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<HH", raw, 16, 2, 243)
        struct.pack_into("<Q", raw, 32, 64)
        struct.pack_into("<HH", raw, 54, 56, 1)
        struct.pack_into("<I", raw, 64, 1)
        PROBE.native_elf(raw, static=True)
        for offset, value in ((18, 62), (64, 2), (64, 3), (54, 55)):
            broken = bytearray(raw)
            struct.pack_into("<H" if offset in (18, 54) else "<I", broken, offset, value)
            with self.subTest(offset=offset, value=value), self.assertRaises(PROBE.ProbeError):
                PROBE.native_elf(broken, static=True)

    def test_bootstrap_source_and_binary_pins_fail_before_docker_execution(self):
        elf = bytearray(120)
        elf[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<HH", elf, 16, 2, 243)
        struct.pack_into("<Q", elf, 32, 64)
        struct.pack_into("<HH", elf, 54, 56, 1)
        struct.pack_into("<I", elf, 64, 1)
        source = b"trusted finite workload"
        lock = {"schemaVersion": 1, "sources": {"engine": {"version": "29.8.0"}, "cli": {"version": "29.8.0"}},
                "probeSourceSha256": hashlib.sha256(source).hexdigest()}
        digest = hashlib.sha256(elf).hexdigest()
        manifest = {"schemaVersion": 1, "architecture": "riscv64",
                    "lockSha256": hashlib.sha256(json.dumps(lock).encode()).hexdigest(),
                    "binaries": {"docker": {"sha256": digest, "elfMachine": 243},
                                 "limit-probe": {"sha256": digest, "elfMachine": 243}}}

        def reader(path, maximum=256 * 1024):
            if path == PROBE.LOCK:
                return json.dumps(lock).encode()
            if path == PROBE.MANIFEST:
                return json.dumps(manifest).encode()
            if path.name == "riscv-rootless-limit-probe.c":
                return source
            return bytes(elf)

        with mock.patch.object(PROBE.platform, "system", return_value="Linux"), \
             mock.patch.object(PROBE.platform, "machine", return_value="riscv64"), \
             mock.patch.object(PROBE.os, "getuid", return_value=1001), \
             mock.patch.object(PROBE.os, "geteuid", return_value=1001), \
             mock.patch("builtins.open", mock.mock_open(read_data=bytes(elf))), \
             mock.patch.object(PROBE, "read_file", side_effect=reader):
            self.assertEqual(PROBE.prerequisites()["binaries"]["docker"], digest)
            lock["probeSourceSha256"] = "0" * 64
            with self.assertRaisesRegex(PROBE.ProbeError, "source-pin-mismatch"):
                PROBE.prerequisites()
            lock["probeSourceSha256"] = hashlib.sha256(source).hexdigest()
            manifest["lockSha256"] = "0" * 64
            with self.assertRaisesRegex(PROBE.ProbeError, "lock-binding-mismatch"):
                PROBE.prerequisites()
            manifest["lockSha256"] = hashlib.sha256(json.dumps(lock).encode()).hexdigest()
            manifest["binaries"]["docker"]["sha256"] = "0" * 64
            with self.assertRaisesRegex(PROBE.ProbeError, "binary-digest-mismatch"):
                PROBE.prerequisites()

    def test_malformed_ownership_and_state_are_fixed_failures(self):
        docker = FakeDocker()
        enforcement = PROBE.Enforcement(docker, TOKEN)
        for value in ({"Id": "1" * 64, "Config": None}, {"Id": "bad", "Config": {"Labels": {}}}):
            with self.subTest(value=value), mock.patch.object(docker, "call", return_value=(0, json.dumps([value]))), \
                 self.assertRaises(PROBE.ProbeError):
                enforcement.owned("anything")
        with self.assertRaises(PROBE.ProbeError):
            PROBE.validate_mode("cpu", logs("cpu"), None)

    def test_read_and_receipt_do_not_follow_links_overwrite_or_accept_large_inputs(self):
        output = self.root / "receipt.json"
        PROBE.write_evidence(output, {"supported": False})
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        with self.assertRaises(PROBE.ProbeError):
            PROBE.write_evidence(output, {})
        link = self.root / "link.json"
        link.symlink_to(output)
        with self.assertRaises(PROBE.ProbeError):
            PROBE.write_evidence(link, {})
        with self.assertRaises(PROBE.ProbeError):
            PROBE.read_file(link)
        with self.assertRaises(PROBE.ProbeError):
            PROBE.read_file(self.binary, 1)
        self.assertEqual(json.loads(output.read_text()), {"supported": False})

    def test_cli_failures_and_cleanup_failures_preserve_failed_receipt(self):
        for cleanup_failure in (False, True):
            docker = FakeDocker()
            docker.cleanup_failure = cleanup_failure
            if not cleanup_failure:
                docker.fail_mode = "pids"
            output = self.root / ("cleanup.json" if cleanup_failure else "mode.json")
            with mock.patch.object(PROBE, "prerequisites", return_value={}), mock.patch.object(PROBE, "Docker", return_value=docker), \
                 mock.patch.object(PROBE.secrets, "token_hex", return_value=TOKEN), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(PROBE.main(["--output", str(output)]), 1)
            receipt = json.loads(output.read_text())
            self.assertFalse(receipt["supported"])
            self.assertEqual(receipt["cleanup_confirmed"], not cleanup_failure)

    def test_workflow_dispatch_identity_is_preserved_without_environment_secrets(self):
        output = self.root / "identity.json"
        identity = {"GITHUB_REPOSITORY": "Prisma-Labs-Dev/OxiBelt", "GITHUB_SHA": "1" * 40,
                    "GITHUB_WORKFLOW_SHA": "1" * 40, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
                    "GITHUB_JOB": "native_preflight", "GITHUB_REF": "refs/heads/main",
                    "GITHUB_WORKFLOW_REF": "Prisma-Labs-Dev/OxiBelt/.github/workflows/riscv-native-preflight.yml@refs/heads/main",
                    "GITHUB_EVENT_NAME": "workflow_dispatch"}
        with mock.patch.dict(os.environ, {**identity, "GH_TOKEN": "SECRET"}, clear=True), \
             mock.patch.object(PROBE, "prerequisites", side_effect=PROBE.ProbeError("unsupported")), \
             contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(PROBE.main(["--output", str(output)]), 1)
        receipt = json.loads(output.read_text())
        self.assertEqual(receipt["identity"], identity)
        self.assertNotIn("SECRET", output.read_text())

    def test_transport_has_fixed_rootless_socket_sanitized_environment_and_bound(self):
        executable = self.root / "fake-docker"
        executable.write_text(f"#!{sys.executable}\nimport json, os, sys\nprint(json.dumps({{'argv':sys.argv[1:], 'env':dict(os.environ)}}))\n")
        executable.chmod(0o700)
        transport = PROBE.Docker(self.root)
        with mock.patch.object(PROBE, "DOCKER", str(executable)), mock.patch.dict(os.environ, {"GH_TOKEN": "SECRET", "DOCKER_HOST": "tcp://rootful"}):
            code, output = transport.call(["info"])
        result = json.loads(output)
        self.assertEqual(code, 0)
        self.assertEqual(result["argv"], ["--host", PROBE.SOCKET, "info"])
        self.assertNotIn("SECRET", output)
        self.assertNotIn("DOCKER_HOST", result["env"])
        executable.write_text(f"#!{sys.executable}\nimport time\ntime.sleep(3)\n")
        started = time.monotonic()
        with mock.patch.object(PROBE, "DOCKER", str(executable)), mock.patch.object(PROBE, "COMMAND_TIMEOUT", 0.05):
            with self.assertRaisesRegex(PROBE.ProbeError, "timeout"):
                transport.call(["info"])
        self.assertLess(time.monotonic() - started, 1)
        executable.write_text(f"#!{sys.executable}\nprint('SECRET'*20000)\n")
        with mock.patch.object(PROBE, "DOCKER", str(executable)), self.assertRaisesRegex(PROBE.ProbeError, "output-too-large"):
            transport.call(["info"])


if __name__ == "__main__":
    unittest.main()
