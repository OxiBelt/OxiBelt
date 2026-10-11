#!/usr/bin/env python3
"""Enforcement and ownership regressions without Docker or stress workloads."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
import stat
import struct
import sys
import tarfile
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
        "CgroupDriver": "systemd", "Driver": "vfs",
        "SecurityOptions": ["name=rootless", "name=cgroupns", "name=seccomp,profile=builtin"]}


def native_static_elf():
    raw = bytearray(120)
    raw[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<HH", raw, 16, 2, 243)
    struct.pack_into("<Q", raw, 32, 64)
    struct.pack_into("<HH", raw, 54, 56, 1)
    struct.pack_into("<I", raw, 64, 1)
    return bytes(raw)


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
        self.operation = "unknown"
        self.first_failure = None
        self.failure_log = b""
        self.last_result = None
        self.last_stdout = b""
        self.import_stdout = None
        self.import_overrides = {}
        self.partial_import_failure = False
        self.archive_bytes = None
        self.info = copy.deepcopy(INFO)

    def begin_cleanup(self):
        pass

    def call(self, args):
        command = "-".join(args[:2]) if args[0] in ("image", "container") else args[0]
        self.last_result = {"operation": self.operation, "command": command, "exit_code": None}
        code, output = self._call(args)
        self.last_result["exit_code"] = code
        self.last_stdout = output.encode()
        return code, output

    def _call(self, args):
        self.calls.append(args)
        if args[0] == "info":
            return 0, json.dumps(self.info)
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
        if args[:2] == ["image", "import"]:
            self.archive_bytes = Path(args[-2]).read_bytes()
            with tarfile.open(fileobj=io.BytesIO(self.archive_bytes), mode="r:") as archive:
                members = archive.getmembers()
                assert len(members) == 1 and members[0].name == "limit-probe" and members[0].isreg()
                assert archive.extractfile(members[0]).read() == native_static_elf()
            changes = [args[index+1] for index, value in enumerate(args[:-1]) if value == "--change"]
            assert set(changes) == {"LABEL " + PROBE.LABEL + "=" + TOKEN,
                                    "USER 1001:1001", 'ENTRYPOINT ["/limit-probe"]'}
            assert "--platform=linux/riscv64" in args
            self.images[args[-1]] = {"Id": self.image_id, "Os": "linux", "Architecture": "riscv64",
                "Config": {"Labels": {PROBE.LABEL: TOKEN}, "User": "1001:1001", "Entrypoint": ["/limit-probe"]}}
            self.images[args[-1]].update(copy.deepcopy(self.import_overrides))
            if self.partial_import_failure:
                return 1, ""
            return 0, (self.import_stdout if self.import_stdout is not None else self.image_id) + "\n"
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
            self.remember_failure("docker-command-failed")
            raise PROBE.ProbeError("docker-command-failed")
        return value

    def remember_failure(self, diagnostic):
        if self.first_failure is None:
            self.first_failure = {**self.last_result, "diagnostic": diagnostic}
            self.failure_log = (json.dumps(self.first_failure, sort_keys=True).encode()
                                + b"\nstderr:\nfake failure diagnostic\nstdout:\n" + self.last_stdout)[:65536]


class EnforcementTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="oxibelt-enforcement-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.binary = self.root / "limit-probe"
        self.binary.write_bytes(native_static_elf())
        self.binary_digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.patch = mock.patch.object(PROBE, "PROBE_BINARY", self.binary)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def receipt(self):
        return {"checks": [], "bootstrap": {"binaries": {"limit-probe": self.binary_digest}}}

    def test_archive_contains_only_pinned_native_probe_with_fixed_metadata(self):
        first, second = self.root / "first.tar", self.root / "second.tar"
        first_digest = PROBE.create_probe_archive(first, self.binary_digest)
        os.utime(self.binary, (1234, 5678))
        self.binary.chmod(0o600)
        second_digest = PROBE.create_probe_archive(second, self.binary_digest)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(first_digest, second_digest)
        self.assertEqual(first_digest, hashlib.sha256(first.read_bytes()).hexdigest())
        self.assertEqual(first.read_bytes()[257:263], b"ustar\0")
        with tarfile.open(first, mode="r:") as archive:
            members = archive.getmembers()
            self.assertEqual(len(members), 1)
            entry = members[0]
            self.assertEqual(entry.name, "limit-probe")
            self.assertEqual((entry.uid, entry.gid, entry.uname, entry.gname, entry.mode, entry.mtime),
                             (0, 0, "", "", 0o755, 0))
            self.assertTrue(entry.isreg())
            self.assertEqual(entry.pax_headers, {})
            self.assertEqual(archive.extractfile(entry).read(), native_static_elf())

    def test_archive_rejects_changed_pin_nonstatic_binary_and_existing_destination(self):
        output = self.root / "probe.tar"
        with self.assertRaises(PROBE.ProbeError):
            PROBE.create_probe_archive(output, "0"*64)
        self.assertFalse(output.exists())
        raw = bytearray(native_static_elf())
        struct.pack_into("<I", raw, 64, 3)
        self.binary.write_bytes(raw)
        with self.assertRaises(PROBE.ProbeError):
            PROBE.create_probe_archive(output, hashlib.sha256(raw).hexdigest())
        self.assertFalse(output.exists())
        self.binary.write_bytes(native_static_elf())
        output.write_bytes(b"preserve existing file")
        with self.assertRaises(PROBE.ProbeError):
            PROBE.create_probe_archive(output, self.binary_digest)
        self.assertEqual(output.read_bytes(), b"preserve existing file")

    def test_archive_rejects_oversized_binary_before_creating_archive(self):
        with self.binary.open("r+b") as stream:
            stream.truncate(64*1024*1024+1)
        output = self.root / "probe.tar"
        with self.assertRaises(PROBE.ProbeError):
            PROBE.create_probe_archive(output, self.binary_digest)
        self.assertFalse(output.exists())

    def test_three_positive_controls_and_exact_ownership_cleanup(self):
        docker = FakeDocker()
        enforcement = PROBE.Enforcement(docker, TOKEN)
        receipt = self.receipt()
        enforcement.run(receipt)
        self.assertEqual(receipt["daemon"]["Driver"], "vfs")
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
        self.assertTrue(all("prune" not in args and "--privileged" not in args and args[0] != "build" for args in docker.calls))

    def test_import_id_config_and_platform_mismatch_fail_before_container_create(self):
        variants = [({"Os": "windows"}, None), ({"Architecture": "x86_64"}, None),
                    ({"Config": {"Labels": {PROBE.LABEL: TOKEN}, "User": "0", "Entrypoint": ["/limit-probe"]}}, None),
                    ({"Config": {"Labels": {PROBE.LABEL: TOKEN}, "User": "1001:1001", "Entrypoint": ["/bin/sh"]}}, None),
                    ({}, "sha256:" + "c"*64), ({}, "not-an-image-id")]
        for overrides, output in variants:
            docker = FakeDocker()
            docker.import_overrides, docker.import_stdout = overrides, output
            enforcement = PROBE.Enforcement(docker, TOKEN)
            with self.subTest(overrides=overrides, output=output), self.assertRaises(PROBE.ProbeError):
                enforcement.run(self.receipt())
            self.assertFalse(any(args[0] == "create" for args in docker.calls))
            self.assertEqual(enforcement.cleanup(), [])
            self.assertFalse(docker.images)

    def test_partial_import_failure_cleans_owned_image_and_preserves_first_failure(self):
        docker = FakeDocker()
        docker.partial_import_failure = True
        enforcement = PROBE.Enforcement(docker, TOKEN)
        with self.assertRaises(PROBE.ProbeError):
            enforcement.run(self.receipt())
        self.assertEqual(len(docker.images), 1)
        failure, log = copy.deepcopy(docker.first_failure), docker.failure_log
        self.assertEqual(enforcement.cleanup(), [])
        self.assertFalse(docker.images)
        self.assertEqual(docker.first_failure, failure)
        self.assertEqual(docker.failure_log, log)

    def test_existing_foreign_tag_is_never_imported_or_removed(self):
        docker = FakeDocker()
        enforcement = PROBE.Enforcement(docker, TOKEN)
        docker.images[enforcement.image] = {"Id": docker.image_id, "Config": {"Labels": {PROBE.LABEL: "foreign"}}}
        with self.assertRaises(PROBE.ProbeError):
            enforcement.run(self.receipt())
        self.assertEqual(enforcement.cleanup(), [])
        self.assertFalse(any(args[:2] in (["image", "import"], ["image", "rm"]) for args in docker.calls))
        self.assertIn(enforcement.image, docker.images)

    def test_foreign_ownership_after_import_is_not_removed(self):
        docker = FakeDocker()
        docker.import_overrides = {"Config": {"Labels": {PROBE.LABEL: "foreign"}, "User": "1001:1001",
                                              "Entrypoint": ["/limit-probe"]}}
        enforcement = PROBE.Enforcement(docker, TOKEN)
        with self.assertRaises(PROBE.ProbeError):
            enforcement.run(self.receipt())
        self.assertEqual(len(enforcement.cleanup()), 1)
        self.assertFalse(any(args[:2] == ["image", "rm"] for args in docker.calls))
        self.assertIn(enforcement.image, docker.images)

    def test_failed_positive_control_still_cleans_exact_resources(self):
        docker = FakeDocker()
        docker.fail_mode = "memory"
        enforcement = PROBE.Enforcement(docker, TOKEN)
        with self.assertRaises(PROBE.ProbeError):
            enforcement.run(self.receipt())
        self.assertEqual(enforcement.cleanup(), [])
        self.assertFalse(docker.images or docker.containers)

    def test_missing_inspect_is_not_cleanup_confirmation_on_transport_failure(self):
        docker = FakeDocker()
        enforcement = PROBE.Enforcement(docker, TOKEN)
        enforcement.run(self.receipt())
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
        enforcement.run(self.receipt())
        for value in docker.containers.values():
            value["Config"]["Labels"][PROBE.LABEL] = "foreign"
        for value in docker.images.values():
            value["Config"]["Labels"][PROBE.LABEL] = "foreign"
        self.assertEqual(len(enforcement.cleanup()), 4)
        self.assertFalse(any(args[0] == "rm" or args[:2] == ["image", "rm"] for args in docker.calls))

    def test_rootful_wrong_version_architecture_driver_or_seccomp_are_rejected(self):
        for field, value in (("ServerVersion", "28.0.4"), ("Architecture", "x86_64"),
                             ("CgroupVersion", "1"), ("CgroupDriver", "none"),
                             ("Driver", "overlayfs"), ("Driver", "native"),
                             ("SecurityOptions", ["name=rootless"]),
                             ("SecurityOptions", ["name=cgroupns", "name=seccomp,profile=builtin"])):
            with self.subTest(field=field), self.assertRaises(PROBE.ProbeError):
                PROBE.validate_info({**INFO, field: value})
        with self.assertRaises(PROBE.ProbeError):
            PROBE.validate_info({key: value for key, value in INFO.items() if key != "Driver"})
        self.assertEqual(PROBE.validate_info(INFO)["Driver"], "vfs")
        self.assertNotIn("private=secret", str(PROBE.validate_info({**INFO, "SecurityOptions": INFO["SecurityOptions"] + ["private=secret"]})))

    def test_unqualified_storage_driver_fails_before_image_import(self):
        variants = [(None, True), ("overlayfs", True), ("native", True), ("overlay2", True),
                    ("vfs", False), ("overlayfs", False)]
        for driver, rootless in variants:
            with self.subTest(driver=driver, rootless=rootless):
                docker = FakeDocker()
                if driver is None:
                    del docker.info["Driver"]
                else:
                    docker.info["Driver"] = driver
                if not rootless:
                    docker.info["SecurityOptions"].remove("name=rootless")
                enforcement = PROBE.Enforcement(docker, TOKEN)
                with self.assertRaises(PROBE.ProbeError):
                    enforcement.run(self.receipt())
                self.assertEqual(docker.calls, [["info", "--format", "{{json .}}"]])
                self.assertEqual(enforcement.cleanup(), [])
                self.assertFalse(docker.images or docker.containers)

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
            evidence = self.root / ("cleanup" if cleanup_failure else "mode")
            evidence.mkdir()
            output = evidence / "enforcement.json"
            with mock.patch.object(PROBE, "prerequisites", return_value=self.receipt()["bootstrap"]), mock.patch.object(PROBE, "Docker", return_value=docker), \
                 mock.patch.object(PROBE.secrets, "token_hex", return_value=TOKEN), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(PROBE.main(["--output", str(output)]), 1)
            receipt = json.loads(output.read_text())
            self.assertFalse(receipt["supported"])
            self.assertEqual(receipt["cleanup_confirmed"], not cleanup_failure)
            log = evidence / "enforcement-docker.log"
            self.assertTrue(log.is_file())
            self.assertEqual(stat.S_IMODE(log.stat().st_mode), 0o600)

    def test_failed_import_main_retains_primary_diagnostic_and_bounded_log(self):
        docker = FakeDocker()
        docker.partial_import_failure = True
        output = self.root / "enforcement.json"
        with mock.patch.object(PROBE, "prerequisites", return_value=self.receipt()["bootstrap"]), \
             mock.patch.object(PROBE, "Docker", return_value=docker), \
             mock.patch.object(PROBE.secrets, "token_hex", return_value=TOKEN), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(PROBE.main(["--output", str(output)]), 1)
        value = json.loads(output.read_text())
        self.assertEqual(value["docker_failure"], docker.first_failure)
        self.assertEqual((self.root / "enforcement-docker.log").read_bytes(), docker.failure_log)
        self.assertTrue(value["cleanup_confirmed"])
        self.assertFalse(docker.images)

    def test_successful_inspect_output_survives_semantic_validation_failure(self):
        docker = FakeDocker()
        docker.import_overrides = {"Config": {"Labels": {PROBE.LABEL: TOKEN}, "User": "0",
                                              "Entrypoint": ["/limit-probe"]}}
        output = self.root / "enforcement.json"
        with mock.patch.object(PROBE, "prerequisites", return_value=self.receipt()["bootstrap"]), \
             mock.patch.object(PROBE, "Docker", return_value=docker), \
             mock.patch.object(PROBE.secrets, "token_hex", return_value=TOKEN), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(PROBE.main(["--output", str(output)]), 1)
        value = json.loads(output.read_text())
        self.assertEqual(value["stage"], "image-verify")
        self.assertEqual(value["docker_failure"]["operation"], "image-verify")
        self.assertEqual(value["docker_failure"]["command"], "image-inspect")
        self.assertEqual(value["docker_failure"]["exit_code"], 0)
        self.assertEqual(value["docker_failure"]["diagnostic"], value["failure"])
        self.assertIn(b'"User": "0"', (self.root / "enforcement-docker.log").read_bytes())
        self.assertTrue(value["cleanup_confirmed"])
        self.assertFalse(docker.images)

    def test_invalid_archive_is_not_attributed_to_previous_successful_docker_command(self):
        docker = FakeDocker()
        self.binary.write_bytes(b"invalid native executable")
        output = self.root / "enforcement.json"
        with mock.patch.object(PROBE, "prerequisites", return_value=self.receipt()["bootstrap"]), \
             mock.patch.object(PROBE, "Docker", return_value=docker), \
             mock.patch.object(PROBE.secrets, "token_hex", return_value=TOKEN), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(PROBE.main(["--output", str(output)]), 1)
        value = json.loads(output.read_text())
        self.assertEqual(value["stage"], "image-archive")
        self.assertNotIn("docker_failure", value)
        self.assertIsNone(docker.first_failure)
        self.assertEqual((self.root / "enforcement-docker.log").read_bytes(), b"")
        self.assertFalse(any(args[:2] == ["image", "import"] for args in docker.calls))

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

    def test_transport_separates_stdout_retains_stderr_and_first_fatal_operation(self):
        executable = self.root / "fake-docker"
        executable.write_text(f"#!{sys.executable}\nimport sys\nprint('stdout diagnostic')\nprint('stderr diagnostic',file=sys.stderr)\nsys.exit(23)\n")
        executable.chmod(0o700)
        transport = PROBE.Docker(self.root)
        transport.operation = "image-precheck"
        with mock.patch.object(PROBE, "DOCKER", str(executable)):
            code, output = transport.call(["image", "inspect", "absent"])
        self.assertEqual(code, 23)
        self.assertEqual(output, "stdout diagnostic\n")
        self.assertIsNone(transport.first_failure)
        transport.operation = "image-import"
        with mock.patch.object(PROBE, "DOCKER", str(executable)), self.assertRaises(PROBE.ProbeError):
            transport.checked(["image", "import", "local.tar", "owned"])
        self.assertEqual(transport.first_failure["operation"], "image-import")
        self.assertEqual(transport.first_failure["command"], "image-import")
        self.assertEqual(transport.first_failure["exit_code"], 23)
        self.assertEqual(transport.first_failure["diagnostic"], "docker-command-failed")
        self.assertIn(b"stdout diagnostic", transport.failure_log)
        self.assertIn(b"stderr diagnostic", transport.failure_log)
        self.assertLessEqual(len(transport.failure_log), 65536)
        first_failure, first_log = copy.deepcopy(transport.first_failure), transport.failure_log
        transport.begin_cleanup()
        transport.operation = "cleanup-image"
        executable.write_text(f"#!{sys.executable}\nimport sys\nprint('secondary cleanup failure',file=sys.stderr)\nsys.exit(42)\n")
        with mock.patch.object(PROBE, "DOCKER", str(executable)), self.assertRaises(PROBE.ProbeError):
            transport.checked(["image", "rm", "owned"])
        self.assertEqual(transport.first_failure, first_failure)
        self.assertEqual(transport.failure_log, first_log)
        self.assertNotIn(b"secondary", transport.failure_log)

    def test_timeout_and_combined_output_overflow_preserve_bounded_first_failure(self):
        executable = self.root / "fake-docker"
        variants = [("timeout", "import sys,time\nprint('started',flush=True)\nprint('waiting',file=sys.stderr,flush=True)\ntime.sleep(3)\n"),
                    ("output-too-large", "import sys\nprint('x'*40000,flush=True)\nprint('y'*40000,file=sys.stderr,flush=True)\n")]
        for diagnostic, script in variants:
            transport = PROBE.Docker(self.root)
            transport.operation = "cpu-start"
            executable.write_text(f"#!{sys.executable}\n" + script)
            executable.chmod(0o700)
            with self.subTest(diagnostic=diagnostic), mock.patch.object(PROBE, "DOCKER", str(executable)), \
                 mock.patch.object(PROBE, "COMMAND_TIMEOUT", 0.1 if diagnostic == "timeout" else 2):
                with self.assertRaisesRegex(PROBE.ProbeError, diagnostic):
                    transport.checked(["start", "owned"])
            self.assertEqual(transport.first_failure["operation"], "cpu-start")
            self.assertEqual(transport.first_failure["command"], "start")
            self.assertIn(diagnostic, transport.first_failure["diagnostic"])
            self.assertLessEqual(len(transport.failure_log), 65536)
            self.assertTrue(transport.failure_log)


if __name__ == "__main__":
    unittest.main()
