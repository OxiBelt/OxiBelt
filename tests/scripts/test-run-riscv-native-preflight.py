#!/usr/bin/env python3
"""Failure, ownership, and lifecycle regressions without a Docker daemon."""
import importlib.util
import contextlib
import io
import hashlib
import json
import os
import subprocess
import tempfile
import tarfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

SPEC = importlib.util.spec_from_file_location("native_preflight", Path(__file__).with_name("run-riscv-native-preflight.py"))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
REAL_EXECUTE = MODULE.execute
IDENTITY = {"GITHUB_SHA": "a" * 40, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_REPOSITORY": "OxiBelt/OxiBelt", "GITHUB_EVENT_NAME": "workflow_dispatch"}
CID = "b" * 64


def archive_bytes(filename, data, *, kind=tarfile.REGTYPE, extra=None):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        member = tarfile.TarInfo(filename)
        member.type = kind
        member.linkname = "target" if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
        member.size = len(data) if kind == tarfile.REGTYPE else 0
        archive.addfile(member, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
        if extra:
            other = tarfile.TarInfo(extra)
            archive.addfile(other, io.BytesIO())
    return output.getvalue()


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="oxibelt-preflight-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.patch = mock.patch.dict(os.environ, IDENTITY, clear=True)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.preflight = MODULE.Preflight(self.root)
        self.preflight.parent = "/kubepods/pod" + "c" * 36
        self.preflight.baseline = {"/": ["cpu", "memory", "pids"]}
        executor = mock.patch.object(MODULE, "execute", return_value=(1, b"unavailable"))
        executor.start()
        self.addCleanup(executor.stop)

    def state(self):
        p = self.preflight
        return {"Id": CID, "Name": "/" + p.name, "Config": {"Labels": dict(p.labels)},
                "HostConfig": {"Privileged": False, "CgroupParent": p.parent,
                               "CgroupnsMode": "private", "NetworkMode": "bridge", "PidMode": "",
                               "NanoCpus": 2000000000, "Memory": 4294967296,
                               "MemorySwap": 4294967296, "PidsLimit": 1024,
                               "DeviceCgroupRules": ["c 10:200 rwm"]},
                "State": {"Status": "running", "Running": True, "Pid": 321, "ExitCode": 0,
                          "OOMKilled": False, "Error": "", "StartedAt": "2026-10-12T00:00:00Z",
                          "FinishedAt": "0001-01-01T00:00:00Z"}}

    def test_explicit_provider_socket_and_no_credentials(self):
        with mock.patch.object(MODULE, "execute", return_value=(0, b"ok")) as call:
            self.assertEqual(self.preflight.command(["info"]), b"ok")
        argv, env, _timeout = call.call_args.args
        self.assertEqual(argv[:3], ["docker", "--host", MODULE.SOCKET])
        self.assertNotIn("GH_TOKEN", env)
        self.assertNotIn("GITHUB_TOKEN", env)

    def test_daemon_distro_versions_are_normalized_and_extra_fields_are_omitted(self):
        self.preflight.receipt["provider_daemon"] = {}
        versions = {"Components": [
            {"Name": "containerd", "Version": " v1.7.27 (ubuntu build) ", "Details": {"GitCommit": "a" * 40, "secret": "SECRET"}},
            {"Name": "runc", "Version": " \t1.3.3-0ubuntu2~24.04.3 \n", "Details": {"GitCommit": "b" * 40}},
            {"Name": "private SECRET", "Version": "SECRET"}, None]}
        with mock.patch.object(MODULE, "execute") as call:
            self.preflight.record_runtime_versions(versions)
        call.assert_not_called()
        provider = self.preflight.receipt["provider_daemon"]
        self.assertEqual(provider["runtime_components"]["runc"]["version"], "1.3.3-0ubuntu2~24.04.3")
        self.assertEqual(provider["runtime_components"]["containerd"]["version"], "1.7.27")
        self.assertEqual(provider["runtime_version_observations"]["malformed_entries"], 1)
        self.assertEqual(provider["runtime_version_observations"]["unknown_entries"], 1)
        self.assertNotIn("SECRET", json.dumps(provider))

    def test_missing_and_unrecognized_daemon_versions_use_sanitized_read_only_fallbacks(self):
        self.preflight.receipt["provider_daemon"] = {}
        versions = {"Components": [{"Name": "containerd", "Version": "private credential=SECRET"}]}
        outputs = [(0, b"containerd github.com/containerd/containerd v1.7.27 " + b"c" * 40 + b"\n"),
                   (0, b"runc version 1.3.3-0ubuntu2~24.04.3\ncommit: " + b"d" * 40 + b"\nSECRET=value\n")]
        with mock.patch.object(MODULE, "execute", side_effect=outputs) as call:
            self.preflight.record_runtime_versions(versions)
        self.assertEqual([args.args[0] for args in call.call_args_list], [["containerd", "--version"], ["runc", "--version"]])
        for args in call.call_args_list:
            self.assertEqual(args.args[1], self.preflight.env)
            self.assertEqual(args.kwargs["timeout"], 15)
            self.assertNotIn("GH_TOKEN", args.args[1])
        provider = self.preflight.receipt["provider_daemon"]
        self.assertEqual(provider["runtime_components"]["runc"]["source"], "runner-binary")
        self.assertEqual(provider["runtime_components"]["containerd"]["commit"], "c" * 40)
        self.assertEqual(provider["runtime_components"]["runc"]["commit"], "d" * 40)
        self.assertNotIn("SECRET", json.dumps(provider))

    def test_unavailable_version_metadata_is_recorded_without_becoming_boundary_failure(self):
        for version in (None, {"Components": None}, {"Components": []}):
            self.preflight.receipt["provider_daemon"] = {}
            with self.subTest(version=version), mock.patch.object(MODULE, "execute", side_effect=OSError("SECRET")):
                self.preflight.record_runtime_versions(version)
            provider = self.preflight.receipt["provider_daemon"]
            self.assertFalse(provider["runtime_components"])
            self.assertEqual(provider["runtime_version_fallbacks"]["runc"]["status"], "unavailable")
            self.assertNotIn("SECRET", json.dumps(provider))

    def test_runtime_observations_survive_a_later_failed_gate(self):
        def provision():
            self.preflight.receipt["provider_daemon"] = {"ServerVersion": "28.0.4"}
            self.preflight.record_runtime_versions({"Components": [{"Name": "runc", "Version": "SECRET"}]})
            raise MODULE.Failure("sandbox-base-must-be-pinned")
        with mock.patch.object(self.preflight, "provision", side_effect=provision), \
             mock.patch.object(MODULE, "execute", return_value=(0, b"unrecognized SECRET\n")), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.preflight.run(), 1)
        receipt = json.loads((self.root / "preflight.json").read_text())
        self.assertEqual(receipt["provider_daemon"]["runtime_version_observations"]["unrecognized_versions"], ["runc"])
        self.assertEqual(receipt["diagnostic"], "sandbox-base-must-be-pinned")
        self.assertNotIn("SECRET", json.dumps(receipt))

    def test_envelope_uses_private_namespaces_without_blanket_privilege(self):
        args = MODULE.sandbox_arguments(self.preflight.parent, "base@sha256:" + "d" * 64,
                                        self.preflight.name, self.preflight.labels)
        self.assertIn("--cgroupns=private", args)
        self.assertIn("--security-opt=writable-cgroups=true", args)
        self.assertIn("--cap-add=SYS_ADMIN", args)
        self.assertIn("--device-cgroup-rule=c 10:200 rwm", args)
        for flag in ("--cpus=2", "--memory=4g", "--memory-swap=4g", "--pids-limit=1024"):
            self.assertIn(flag, args)
        self.assertNotIn("--privileged", args)
        self.assertNotIn("--pid=host", args)
        self.assertNotIn("--network=host", args)
        self.assertNotIn("--security-opt=systempaths=unconfined", args)
        self.assertNotIn("--volume", args)

    def test_foreign_container_labels_block_cleanup(self):
        self.preflight.container = CID
        state = self.state()
        state["Config"]["Labels"][MODULE.RUN_LABEL] = "456-1"
        with mock.patch.object(self.preflight, "command", return_value=json.dumps([state]).encode()) as call:
            with self.assertRaisesRegex(MODULE.Failure, "sandbox-label-mismatch"):
                self.preflight.cleanup()
        self.assertEqual(len(call.call_args_list), 1)

    def test_privileged_or_host_bound_envelopes_are_rejected(self):
        self.preflight.container = CID
        for key, value in (("Privileged", True), ("PidMode", "host"), ("Binds", ["/:/host"]),
                           ("CgroupnsMode", "host"), ("CgroupParent", "/docker"),
                           ("DeviceCgroupRules", ["a *:* rwm"])):
            state = self.state()
            state["HostConfig"][key] = value
            with self.subTest(key=key), mock.patch.object(self.preflight, "command", return_value=json.dumps([state]).encode()):
                with self.assertRaisesRegex(MODULE.Failure, "sandbox-runtime-boundary-mismatch"):
                    self.preflight.container_state()

    def test_owned_boundary_failure_still_removes_exact_container(self):
        self.preflight.container = CID
        state = self.state()
        state["HostConfig"] = None
        calls = []
        def command(args, **_kwargs):
            calls.append(args)
            return json.dumps([state]).encode() if args[0] == "inspect" else b""
        with mock.patch.object(self.preflight, "command", side_effect=command), \
             mock.patch.object(self.preflight, "check_ancestors"):
            with self.assertRaisesRegex(MODULE.Failure, "invalid-sandbox-host-config"):
                self.preflight.container_state()
            self.preflight.cleanup()
        self.assertIn(["rm", "--force", CID], calls)
        self.assertTrue(self.preflight.receipt["cleanup_confirmed"])

    def test_malformed_inspection_fields_raise_bounded_failures(self):
        self.preflight.container = CID
        for field, value in (("Config", None), ("HostConfig", []), ("State", None)):
            state = self.state()
            state[field] = value
            with self.subTest(field=field), mock.patch.object(self.preflight, "command", return_value=json.dumps([state]).encode()), \
                 self.assertRaises(MODULE.Failure):
                self.preflight.container_state()
        for value in (None, [], "unexpected"):
            with self.subTest(value=value), mock.patch.object(self.preflight, "command", return_value=json.dumps([value]).encode()), \
                 self.assertRaisesRegex(MODULE.Failure, "invalid-sandbox-inspection"):
                self.preflight.owned_container()

    def test_image_pins_platform_child_and_config_identity(self):
        index, native = "sha256:" + "d" * 64, "sha256:" + "e" * 64
        lock = {"baseImage": {"indexDigest": index, "nativeDigest": native}}
        manifest = {"schemaVersion": 2, "manifests": [
            {"digest": native, "platform": {"os": "linux", "architecture": "riscv64"}},
            {"digest": "sha256:" + "f" * 64, "platform": {"os": "linux", "architecture": "amd64"}}]}
        image = {"Id": "sha256:" + CID, "Os": "linux", "Architecture": "riscv64", "RepoDigests": ["debian@" + native]}
        calls = []
        def command(args, **_kwargs):
            calls.append(args)
            if args[:2] == ["manifest", "inspect"]:
                return json.dumps(manifest).encode()
            if args[:2] == ["image", "inspect"]:
                return json.dumps([image]).encode()
            return b""
        with mock.patch.object(self.preflight, "command", side_effect=command):
            reference = self.preflight.prepare_image(lock)
            self.assertEqual(reference, "docker.io/library/debian:trixie@" + native)
            self.assertIn(["pull", "--platform=linux/riscv64", reference], calls)
            self.assertEqual(self.preflight.receipt["base_image"]["config_id"], image["Id"])
            manifest["manifests"][0]["digest"] = "sha256:" + "f" * 64
            with self.assertRaisesRegex(MODULE.Failure, "native-child-pin-mismatch"):
                self.preflight.prepare_image(lock)
            manifest["manifests"][0]["digest"] = native
            image["Architecture"] = "amd64"
            with self.assertRaisesRegex(MODULE.Failure, "native-image-mismatch"):
                self.preflight.prepare_image(lock)
            image["Architecture"] = "riscv64"
            image["RepoDigests"] = ["debian@sha256:" + "f" * 64]
            with self.assertRaisesRegex(MODULE.Failure, "native-image-mismatch"):
                self.preflight.prepare_image(lock)

    def test_running_boundary_rejects_foreign_leaf_shared_namespace_and_writable_sys(self):
        self.preflight.container = CID
        expected = "0::" + self.preflight.parent + "/" + CID
        mounts = "1 0 0:1 / /sys ro - sysfs sysfs ro\n2 0 0:2 /sys /proc/sys ro - proc proc ro\n3 0 0:3 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n"
        real_stat = MODULE.os.stat
        def stat(path, *args, **kwargs):
            if str(path).startswith("/proc/self/ns/"):
                return SimpleNamespace(st_dev=1, st_ino=2)
            return real_stat(path, *args, **kwargs)
        for fault, diagnostic in ((None, None), ("cgroup", "sandbox-process-outside-owned-cgroup"),
                                  ("init", None), ("init-non-systemd", "sandbox-process-outside-owned-cgroup"),
                                  ("init-child", "sandbox-process-outside-owned-cgroup"),
                                  ("prefix-sibling", "sandbox-process-outside-owned-cgroup"),
                                  ("traversal", "sandbox-process-outside-owned-cgroup"),
                                  ("multiline", "sandbox-process-outside-owned-cgroup"),
                                  ("other-scope", "sandbox-process-outside-owned-cgroup"),
                                  ("namespace", "sandbox-namespace-not-private"),
                                  ("sys", "sandbox-kernel-mount-boundary-mismatch")):
            def read(path):
                if str(path) == "/proc/321/cgroup":
                    return {"cgroup": "0::/foreign", "init": expected + "/init.scope",
                            "init-non-systemd": expected + "/init.scope",
                            "init-child": expected + "/init.scope/child",
                            "prefix-sibling": expected + "bad/init.scope",
                            "traversal": expected + "/../init.scope",
                            "multiline": expected + "/init.scope\n0::/foreign",
                            "other-scope": expected + "/other.scope"}.get(fault, expected)
                return "0::/outer"
            def command(args, **_kwargs):
                if args[-1] == "/proc/1/comm":
                    return b"bash" if fault == "init-non-systemd" else b"systemd"
                if args[2] == "stat":
                    return b"1:2" if fault == "namespace" else b"1:3"
                return (mounts.replace("/sys ro", "/sys rw") if fault == "sys" else mounts).encode()
            with self.subTest(fault=fault), mock.patch.object(self.preflight, "container_state", return_value=self.state()), \
                 mock.patch.object(self.preflight.probe, "Probe", return_value=SimpleNamespace(read=read)), \
                 mock.patch.object(MODULE.os, "stat", side_effect=stat), \
                 mock.patch.object(self.preflight, "command", side_effect=command):
                if diagnostic:
                    with self.assertRaisesRegex(MODULE.Failure, diagnostic):
                        self.preflight.verify_running_boundary()
                else:
                    self.preflight.verify_running_boundary()
                    self.assertEqual(self.preflight.receipt["pid1_cgroup"], {
                        "owned_root": expected[3:],
                        "path": expected[3:] + ("/init.scope" if fault == "init" else "")})

    def test_ready_poll_reports_only_bounded_progress_and_checks_failure(self):
        self.preflight.container = CID
        now = [0.0]
        def sleep(_seconds):
            now[0] += 30
        output = io.StringIO()
        with mock.patch.object(MODULE.time, "monotonic", side_effect=lambda: now[0]), \
             mock.patch.object(MODULE.time, "sleep", side_effect=sleep), \
             mock.patch.object(self.preflight, "container_state", return_value=self.state()), \
             mock.patch.object(self.preflight, "observe_bootstrap_phase"), \
             mock.patch.object(MODULE, "execute", side_effect=[(1, b"SECRET"), (1, b"SECRET"), (1, b"SECRET"), (0, b"")]), \
             mock.patch.object(self.preflight, "command", return_value=b""), contextlib.redirect_stdout(output):
            self.preflight.wait_ready()
        self.assertEqual(len(output.getvalue().splitlines()), 2)
        self.assertNotIn("SECRET", output.getvalue())
        with mock.patch.object(self.preflight, "container_state", return_value=self.state()), \
             mock.patch.object(self.preflight, "observe_bootstrap_phase"), \
             mock.patch.object(MODULE, "execute", return_value=(1, b"")), \
             mock.patch.object(self.preflight, "command", return_value=b"failed"), contextlib.redirect_stdout(io.StringIO()), \
             self.assertRaisesRegex(MODULE.Failure, "sandbox-tool-bootstrap-failed"):
            self.preflight.wait_ready()

    def test_early_network_receipt_is_qualified_once_before_tool_readiness(self):
        self.preflight.container = CID
        def qualify():
            self.preflight.receipt["network"] = {"supported": True}
        def command(args, **_kwargs):
            return b"ready" if "network-preflight-ready" in args[-1] else b""
        output = io.StringIO()
        with mock.patch.object(self.preflight, "container_state", return_value=self.state()), \
             mock.patch.object(self.preflight, "observe_bootstrap_phase"), \
             mock.patch.object(self.preflight, "command", side_effect=command), \
             mock.patch.object(self.preflight, "qualify_network", side_effect=qualify) as check, \
             mock.patch.object(MODULE, "execute", side_effect=[(1, b""), (0, b"")]), \
             mock.patch.object(MODULE.time, "sleep"), contextlib.redirect_stdout(output):
            self.preflight.wait_ready()
        check.assert_called_once_with()
        self.assertEqual(output.getvalue().count("Native detached network forwarding verified"), 1)

    def test_phase_hint_requires_owned_container_and_fixed_read_only_command(self):
        self.preflight.container = CID
        for value, expected in ((b"sys-mount\n", "sys-mount"), (b"native-tools\n", "native-tools"),
                                (b"qualified", "sandbox-bootstrap"), (b"SECRET", "sandbox-bootstrap"),
                                (b"sys-mount\nSECRET", "sandbox-bootstrap")):
            self.preflight.receipt["stage"] = "sandbox-bootstrap"
            with self.subTest(value=value), mock.patch.object(self.preflight, "owned_container") as owned, \
                 mock.patch.object(self.preflight, "inner", return_value=value) as inner:
                self.preflight.observe_bootstrap_phase()
                owned.assert_called_once_with()
                inner.assert_called_once_with(["python3", "-I", "-c", MODULE.PHASE_READER], allow_failure=True)
                self.assertEqual(self.preflight.receipt["stage"], expected)
                self.assertFalse(self.preflight.receipt["supported"])
        with mock.patch.object(self.preflight, "owned_container", side_effect=MODULE.Failure("sandbox-label-mismatch")), \
             mock.patch.object(self.preflight, "inner") as inner, \
             self.assertRaisesRegex(MODULE.Failure, "sandbox-label-mismatch"):
            self.preflight.observe_bootstrap_phase()
        inner.assert_not_called()

    def test_failed_sys_phase_does_not_replace_proc_network_or_sys_qualification(self):
        self.preflight.container = CID
        def command(args, **_kwargs):
            if "proc-preflight-ready" in args[-1] or "network-preflight-ready" in args[-1]:
                return b"ready"
            return b"failed" if "preflight-failed" in args[-1] else b""
        def proc():
            self.preflight.receipt["proc_mount"] = {"supported": True}
        def network():
            self.preflight.receipt["network"] = {"supported": True}
        with mock.patch.object(self.preflight, "container_state", return_value=self.state()), \
             mock.patch.object(self.preflight, "owned_container"), \
             mock.patch.object(self.preflight, "inner", return_value=b"sys-mount\n"), \
             mock.patch.object(self.preflight, "command", side_effect=command), \
             mock.patch.object(self.preflight, "qualify_proc", side_effect=proc) as proc_check, \
             mock.patch.object(self.preflight, "qualify_network", side_effect=network) as network_check, \
             mock.patch.object(self.preflight, "qualify_sys") as sys_check, \
             mock.patch.object(self.preflight, "qualify_tools") as tools_check, \
             mock.patch.object(MODULE, "execute", return_value=(1, b"")), \
             contextlib.redirect_stdout(io.StringIO()), \
             self.assertRaisesRegex(MODULE.Failure, "sandbox-tool-bootstrap-failed"):
            self.preflight.wait_ready()
        self.assertEqual(self.preflight.receipt["stage"], "sys-mount")
        self.assertFalse(self.preflight.receipt["supported"])
        self.assertNotIn("sys_mount", self.preflight.receipt)
        proc_check.assert_called_once_with()
        network_check.assert_called_once_with()
        sys_check.assert_not_called()
        tools_check.assert_not_called()

    def test_phase_hint_does_not_hide_source_qualification_failure(self):
        self.preflight.container = CID
        def command(args, **_kwargs):
            return b"ready" if "sys-preflight-ready" in args[-1] else b""
        with mock.patch.object(self.preflight, "container_state", return_value=self.state()), \
             mock.patch.object(self.preflight, "owned_container"), \
             mock.patch.object(self.preflight, "inner", return_value=b"native-tools\n"), \
             mock.patch.object(self.preflight, "command", side_effect=command), \
             mock.patch.object(self.preflight, "qualify_sys", side_effect=MODULE.Failure("sys-evidence-source-mismatch")) as check, \
             contextlib.redirect_stdout(io.StringIO()), \
             self.assertRaisesRegex(MODULE.Failure, "sys-evidence-source-mismatch"):
            self.preflight.wait_ready()
        check.assert_called_once_with()
        self.assertEqual(self.preflight.receipt["stage"], "sys-mount")
        self.assertFalse(self.preflight.receipt["supported"])

    def test_phase_reader_is_bounded_typed_and_does_not_follow_links(self):
        base = self.root / "phase-home"
        base.mkdir()
        home = base / "runner"
        home.mkdir(mode=0o700)
        evidence = home / "evidence"
        evidence.mkdir(mode=0o700)
        marker = evidence / "bootstrap-phase.json"
        # Substitute only the fixture root and ownership; execute the production
        # parser and descriptor-based no-follow reads unchanged.
        code = MODULE.PHASE_READER.replace("'/home'", repr(str(base)))
        code = code.replace("(1001, 1001, 0o700)", f"({os.getuid()}, {os.getgid()}, 0o700)")
        code = code.replace("metadata.st_uid == 1001 and metadata.st_gid == 1001",
                            f"metadata.st_uid == {os.getuid()} and metadata.st_gid == {os.getgid()}")
        def read():
            result = subprocess.run(["python3", "-I", "-c", code], capture_output=True,
                                    env={"PYTHONOPTIMIZE": "1", "SECRET": "canary"})
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stderr, b"")
            return result.stdout
        valid = b'{"schema_version":1,"phase":"sys-mount"}'
        cases = [(valid, b"sys-mount\n"), (b"{}", b""),
                 (b'{"schema_version":true,"phase":"sys-mount"}', b""),
                 (b'{"schema_version":1,"phase":"qualified"}', b""),
                 (b'{"schema_version":1,"phase":["sys-mount"]}', b""),
                 (b'{"schema_version":1,"phase":"sys-mount","secret":"canary"}', b""),
                 (valid + b" " * 513, b""), (b"invalid canary", b"")]
        for data, expected in cases:
            with self.subTest(data=data[:100]):
                marker.write_bytes(data)
                marker.chmod(0o600)
                self.assertEqual(read(), expected)
                if expected:
                    MODULE.validate_bootstrap_phase(data)
                else:
                    with self.assertRaises((MODULE.Failure, ValueError)):
                        MODULE.validate_bootstrap_phase(data)
        marker.write_bytes(valid)
        for path in (home, evidence, marker):
            with self.subTest(mode_path=path.name):
                original = path.stat().st_mode & 0o777
                path.chmod(0o777)
                self.assertEqual(read(), b"")
                path.chmod(original)
        for path in (base, home, evidence, marker):
            with self.subTest(link_path=path.name):
                target = path.with_name(path.name + "-real")
                path.rename(target)
                path.symlink_to(target)
                self.assertEqual(read(), b"")
                path.unlink()
                target.rename(path)
        marker.unlink()
        os.mkfifo(marker, mode=0o600)
        self.assertEqual(read(), b"")
        marker.unlink()
        self.assertEqual(read(), b"")

    def test_network_receipt_requires_the_actual_sandbox_namespace(self):
        self.preflight.container = CID
        receipt = {"supported": True, "sandbox_netns": 123}
        for actual in (b"123\n", b"456\n", b"invalid"):
            with self.subTest(actual=actual), \
                 mock.patch.object(self.preflight, "verify_running_boundary") as boundary, \
                 mock.patch.object(self.preflight, "copy_json", return_value=receipt), \
                 mock.patch.object(self.preflight, "command", return_value=actual):
                self.preflight.receipt.pop("network", None)
                if actual == b"123\n":
                    self.preflight.qualify_network()
                    self.assertEqual(self.preflight.receipt["network"], receipt)
                else:
                    with self.assertRaisesRegex(MODULE.Failure, "network-evidence-sandbox-namespace-mismatch"):
                        self.preflight.qualify_network()
                    self.assertNotIn("network", self.preflight.receipt)
                boundary.assert_called_once_with(require_network=True)

    def test_early_proc_receipt_is_qualified_once_before_tool_readiness(self):
        self.preflight.container = CID
        def qualify():
            self.preflight.receipt["proc_mount"] = {"supported": True}
        def command(args, **_kwargs):
            return b"ready" if "proc-preflight-ready" in args[-1] else b""
        output = io.StringIO()
        with mock.patch.object(self.preflight, "container_state", return_value=self.state()), \
             mock.patch.object(self.preflight, "observe_bootstrap_phase"), \
             mock.patch.object(self.preflight, "command", side_effect=command), \
             mock.patch.object(self.preflight, "qualify_proc", side_effect=qualify) as check, \
             mock.patch.object(MODULE, "execute", side_effect=[(1, b""), (0, b"")]), \
             mock.patch.object(MODULE.time, "sleep"), contextlib.redirect_stdout(output):
            self.preflight.wait_ready()
        check.assert_called_once_with()
        self.assertEqual(output.getvalue().count("Native isolated procfs mounting verified"), 1)

    def test_proc_receipt_requires_actual_namespaces_and_staged_sources(self):
        self.preflight.container = CID
        native = {"lock_sha256": hashlib.sha256((MODULE.HERE / "riscv-native-tools.lock.json").read_bytes()).hexdigest(),
                  "probe_sha256": hashlib.sha256((MODULE.HERE / "check-riscv-proc-mount.py").read_bytes()).hexdigest()}
        for actual, hashes, diagnostic in ((b"123\n", native, None), (b"456\n", native, "namespace-mismatch"),
                                           (b"invalid", native, "namespace-mismatch"),
                                           (b"123\n", {**native, "probe_sha256": "0" * 64}, "source-mismatch")):
            receipt = {"sandbox_pidns": 123, "sandbox_mntns": 123, "native": hashes}
            self.preflight.receipt.pop("proc_mount", None)
            with self.subTest(actual=actual, diagnostic=diagnostic), \
                 mock.patch.object(self.preflight, "verify_running_boundary"), \
                 mock.patch.object(self.preflight, "copy_json", return_value=receipt), \
                 mock.patch.object(self.preflight, "command", return_value=actual):
                if diagnostic:
                    with self.assertRaisesRegex(MODULE.Failure, diagnostic):
                        self.preflight.qualify_proc()
                    self.assertNotIn("proc_mount", self.preflight.receipt)
                else:
                    self.preflight.qualify_proc()
                    self.assertEqual(self.preflight.receipt["proc_mount"], receipt)

    def test_early_sys_receipt_is_qualified_once_before_tool_readiness(self):
        self.preflight.container = CID
        def qualify():
            self.preflight.receipt["sys_mount"] = {"supported": True}
        def command(args, **_kwargs):
            return b"ready" if "sys-preflight-ready" in args[-1] else b""
        output = io.StringIO()
        with mock.patch.object(self.preflight, "container_state", return_value=self.state()), \
             mock.patch.object(self.preflight, "observe_bootstrap_phase"), \
             mock.patch.object(self.preflight, "command", side_effect=command), \
             mock.patch.object(self.preflight, "qualify_sys", side_effect=qualify) as check, \
             mock.patch.object(MODULE, "execute", side_effect=[(1, b""), (0, b"")]), \
             mock.patch.object(MODULE.time, "sleep"), contextlib.redirect_stdout(output):
            self.preflight.wait_ready()
        check.assert_called_once_with()
        self.assertEqual(output.getvalue().count("Native isolated readonly sysfs mounting verified"), 1)

    def test_sys_receipt_requires_actual_namespaces_and_staged_sources(self):
        self.preflight.container = CID
        native = {"lock_sha256": hashlib.sha256((MODULE.HERE / "riscv-native-tools.lock.json").read_bytes()).hexdigest(),
                  "probe_sha256": hashlib.sha256((MODULE.HERE / "check-riscv-sys-mount.py").read_bytes()).hexdigest()}
        for key in ("sandbox_pidns", "sandbox_mntns", "sandbox_netns"):
            receipt = {"sandbox_pidns": 123, "sandbox_mntns": 123, "sandbox_netns": 123, "native": native}
            receipt[key] = 456
            with self.subTest(namespace=key), \
                 mock.patch.object(self.preflight, "verify_running_boundary") as boundary, \
                 mock.patch.object(self.preflight, "copy_json", return_value=receipt), \
                 mock.patch.object(self.preflight, "command", return_value=b"123\n"):
                with self.assertRaisesRegex(MODULE.Failure, "sys-evidence-sandbox-namespace-mismatch"):
                    self.preflight.qualify_sys()
                self.assertNotIn("sys_mount", self.preflight.receipt)
                boundary.assert_called_once_with(require_network=True)
        for hashes, diagnostic in ((native, None), ({**native, "probe_sha256": "0" * 64}, "source-mismatch"),
                                    ({**native, "lock_sha256": "0" * 64}, "source-mismatch")):
            receipt = {"sandbox_pidns": 123, "sandbox_mntns": 123, "sandbox_netns": 123, "native": hashes}
            self.preflight.receipt.pop("sys_mount", None)
            with self.subTest(diagnostic=diagnostic, hashes=hashes), \
                 mock.patch.object(self.preflight, "verify_running_boundary"), \
                 mock.patch.object(self.preflight, "copy_json", return_value=receipt), \
                 mock.patch.object(self.preflight, "command", return_value=b"123\n"):
                if diagnostic:
                    with self.assertRaisesRegex(MODULE.Failure, diagnostic):
                        self.preflight.qualify_sys()
                    self.assertNotIn("sys_mount", self.preflight.receipt)
                else:
                    self.preflight.qualify_sys()
                    self.assertEqual(self.preflight.receipt["sys_mount"], receipt)

    def test_v2_sys_receipt_requires_staged_network_observer_hash(self):
        self.preflight.container = CID
        native = {"lock_sha256": hashlib.sha256((MODULE.HERE / "riscv-native-tools.lock.json").read_bytes()).hexdigest(),
                  "probe_sha256": hashlib.sha256((MODULE.HERE / "check-riscv-sys-mount.py").read_bytes()).hexdigest(),
                  "observer_sha256": hashlib.sha256((MODULE.HERE / "riscv-network-observation.py").read_bytes()).hexdigest()}
        for digest in (native["observer_sha256"], "0" * 64):
            receipt = {"schema_version": 2, "sandbox_pidns": 123, "sandbox_mntns": 123, "sandbox_netns": 123,
                       "native": {**native, "observer_sha256": digest}}
            self.preflight.receipt.pop("sys_mount", None)
            with self.subTest(digest=digest), mock.patch.object(self.preflight, "verify_running_boundary"), \
                 mock.patch.object(self.preflight, "copy_json", return_value=receipt), \
                 mock.patch.object(self.preflight, "command", return_value=b"123\n"):
                if digest == "0" * 64:
                    with self.assertRaisesRegex(MODULE.Failure, "sys-evidence-source-mismatch"):
                        self.preflight.qualify_sys()
                    self.assertNotIn("sys_mount", self.preflight.receipt)
                else:
                    self.preflight.qualify_sys()
                    self.assertEqual(self.preflight.receipt["sys_mount"], receipt)

    def test_failed_sys_receipt_cannot_qualify_the_sandbox(self):
        self.preflight.container = CID
        def copy(_args, **_kwargs):
            (self.root / "sys-mount.json").write_text(json.dumps({"supported": False}))
            return b""
        with mock.patch.object(self.preflight, "command", side_effect=copy):
            with self.assertRaisesRegex(MODULE.Failure, "inner-sys-mount-qualification-failed"):
                self.preflight.copy_json("sys-mount.json")

    def test_proc_and_sys_receipts_require_the_final_rootlesskit_binary(self):
        tools = {"binaries": {"rootlesskit": {"sha256": "c" * 64}}}
        for changed in (None, "proc", "sys"):
            for kind in ("proc", "sys"):
                self.preflight.receipt[kind + "_mount"] = {
                    "native": {"rootlesskit_sha256": ("d" if changed == kind else "c") * 64}}
            with self.subTest(changed=changed), \
                 mock.patch.object(self.preflight, "copy_json", return_value=tools) as copy:
                if changed:
                    with self.assertRaisesRegex(MODULE.Failure, changed + "-evidence-rootlesskit-mismatch"):
                        self.preflight.qualify_tools()
                else:
                    self.preflight.qualify_tools()
                copy.assert_called_once_with("native-tools.json")
                self.assertEqual(self.preflight.receipt["tools"], tools)

    def test_sys_failure_evidence_is_preserved_before_owned_cleanup(self):
        self.preflight.container = CID
        failure = {"supported": False, "diagnostic": "private-sys-mount-denied"}
        calls = []
        def command(args, **_kwargs):
            calls.append(args)
            return json.dumps([self.state()]).encode() if args[0] == "inspect" else b""
        def execute(args, _env, **_kwargs):
            calls.append(args[3:])
            if args[3] == "cp":
                filename = args[4].rsplit("/", 1)[-1]
                data = {"sys-mount.json": json.dumps(failure).encode(),
                        "sys-mount.log": b'{"operation":"mount-sysfs","errno":1}\n'}.get(filename)
                return (0, archive_bytes(filename, data)) if data else (1, b"missing")
            return 0, b""
        with mock.patch.object(self.preflight, "command", side_effect=command), \
             mock.patch.object(MODULE, "execute", side_effect=execute), \
             mock.patch.object(self.preflight, "check_ancestors"):
            self.preflight.cleanup()
        self.assertEqual(json.loads((self.root / "sys-mount.json").read_text()), failure)
        self.assertIn(b'"errno":1', (self.root / "sys-mount.log").read_bytes())
        self.assertLess(next(i for i, call in enumerate(calls) if call[0] == "cp"),
                        calls.index(["rm", "--force", CID]))
        self.assertTrue(self.preflight.receipt["cleanup_confirmed"])

    def test_failed_proc_receipt_cannot_qualify_the_sandbox(self):
        self.preflight.container = CID
        def copy(_args, **_kwargs):
            (self.root / "proc-mount.json").write_text(json.dumps({"supported": False}))
            return b""
        with mock.patch.object(self.preflight, "command", side_effect=copy):
            with self.assertRaisesRegex(MODULE.Failure, "inner-proc-mount-qualification-failed"):
                self.preflight.copy_json("proc-mount.json")

    def test_proc_failure_evidence_is_preserved_before_owned_cleanup(self):
        self.preflight.container = CID
        failure = {"supported": False, "diagnostic": "private-proc-mount-denied"}
        calls = []
        def command(args, **_kwargs):
            calls.append(args)
            return json.dumps([self.state()]).encode() if args[0] == "inspect" else b""
        def execute(args, _env, **_kwargs):
            calls.append(args[3:])
            if args[3] == "cp":
                filename = args[4].rsplit("/", 1)[-1]
                data = {"proc-mount.json": json.dumps(failure).encode(),
                        "proc-mount.log": b'{"operation":"mount-proc","errno":1}\n'}.get(filename)
                return (0, archive_bytes(filename, data)) if data else (1, b"missing")
            return 0, b""
        with mock.patch.object(self.preflight, "command", side_effect=command), \
             mock.patch.object(MODULE, "execute", side_effect=execute), \
             mock.patch.object(self.preflight, "check_ancestors"):
            self.preflight.cleanup()
        self.assertEqual(json.loads((self.root / "proc-mount.json").read_text()), failure)
        self.assertIn(b'"errno":1', (self.root / "proc-mount.log").read_bytes())
        self.assertLess(next(i for i, call in enumerate(calls) if call[0] == "cp"),
                        calls.index(["rm", "--force", CID]))
        self.assertTrue(self.preflight.receipt["cleanup_confirmed"])


    def test_log_and_graceful_stop_failures_still_force_exact_removal(self):
        self.preflight.container = CID
        calls = []
        def command(args, **_kwargs):
            calls.append(args)
            if args[0] == "inspect":
                return json.dumps([self.state()]).encode()
            if args[0] in {"logs", "stop", "exec"}:
                raise MODULE.Failure("command-timeout")
            return b""
        with mock.patch.object(self.preflight, "command", side_effect=command), mock.patch.object(self.preflight, "check_ancestors"):
            self.preflight.cleanup()
        self.assertIn(["rm", "--force", CID], calls)
        self.assertTrue(self.preflight.receipt["cleanup_confirmed"])

    def test_unknown_creation_outcome_never_claims_clean(self):
        self.preflight.creation_attempted = True
        with mock.patch.object(self.preflight, "command", return_value=b""):
            with self.assertRaisesRegex(MODULE.Failure, "creation-outcome-unconfirmed"):
                self.preflight.cleanup()
        self.assertFalse(self.preflight.receipt["cleanup_confirmed"])

    def test_network_failure_evidence_survives_exact_container_cleanup(self):
        self.preflight.container = CID
        evidence = {"schema_version": 1, "supported": False,
                    "diagnostic": "sysctl-write-failed", "cleanup_confirmed": True}
        calls = []
        def command(args, **_kwargs):
            calls.append(args)
            return json.dumps([self.state()]).encode() if args[0] == "inspect" else b""
        def execute(args, _env, **_kwargs):
            if args[3] == "cp" and args[4].endswith("/network-sysctl.json"):
                return 0, archive_bytes("network-sysctl.json", json.dumps(evidence).encode())
            return 1, b"missing"
        with mock.patch.object(self.preflight, "command", side_effect=command), \
             mock.patch.object(MODULE, "execute", side_effect=execute), \
             mock.patch.object(self.preflight, "check_ancestors"):
            self.preflight.cleanup()
        self.assertEqual(json.loads((self.root / "network-sysctl.json").read_text()), evidence)
        self.assertIn(["rm", "--force", CID], calls)
        self.assertTrue(self.preflight.receipt["cleanup_confirmed"])


    def test_enforcement_diagnostics_survive_exact_container_cleanup(self):
        self.preflight.container = CID
        diagnostic = b'{"command":"image-import","exit_code":1}\nstderr:\nimport failed\n'
        calls = []
        def command(args, **_kwargs):
            calls.append(args)
            return json.dumps([self.state()]).encode() if args[0] == "inspect" else b""
        def execute(args, _env, **kwargs):
            calls.append(args[3:])
            if args[3] == "cp" and args[4].endswith("/enforcement-docker.log"):
                self.assertEqual(kwargs, {"timeout": 30, "maximum": MODULE.MAX_ARCHIVE_BYTES})
                return 0, archive_bytes("enforcement-docker.log", diagnostic)
            return 1, b"missing"
        with mock.patch.object(self.preflight, "command", side_effect=command), \
             mock.patch.object(MODULE, "execute", side_effect=execute), \
             mock.patch.object(self.preflight, "check_ancestors"):
            self.preflight.cleanup()
        log = self.root / "enforcement-docker.log"
        self.assertEqual(log.read_bytes(), diagnostic)
        self.assertEqual(log.stat().st_mode & 0o777, 0o600)
        capture = next(index for index, args in enumerate(calls)
                       if args[0] == "cp" and args[1].endswith("/enforcement-docker.log"))
        self.assertLess(capture, calls.index(["rm", "--force", CID]))
        self.assertTrue(self.preflight.receipt["cleanup_confirmed"])


    def test_failed_network_receipt_cannot_qualify_the_sandbox(self):
        self.preflight.container = CID
        def copy(_args, **_kwargs):
            (self.root / "network-sysctl.json").write_text(json.dumps({"supported": False}))
            return b""
        with mock.patch.object(self.preflight, "command", side_effect=copy):
            with self.assertRaisesRegex(MODULE.Failure, "inner-network-qualification-failed"):
                self.preflight.copy_json("network-sysctl.json")

    def test_timed_out_creation_recovers_only_matching_identity(self):
        self.preflight.creation_attempted = True
        def command(args, **_kwargs):
            if args[0] == "ps" and self.preflight.container is None:
                return (CID + "\n").encode()
            if args[0] == "inspect":
                return json.dumps([self.state()]).encode()
            return b""
        with mock.patch.object(self.preflight, "command", side_effect=command), mock.patch.object(self.preflight, "check_ancestors"):
            self.preflight.cleanup()
        self.assertEqual(self.preflight.container, CID)
        self.assertTrue(self.preflight.receipt["cleanup_confirmed"])

    def test_failure_receipt_survives_provisioning_error(self):
        with mock.patch.object(self.preflight, "provision", side_effect=MODULE.Failure("runner-prerequisites-failed")):
            self.assertEqual(self.preflight.run(), 1)
        receipt = json.loads((self.root / "preflight.json").read_text())
        self.assertFalse(receipt["supported"])
        self.assertEqual(receipt["diagnostic"], "runner-prerequisites-failed")
        self.assertEqual(receipt["stage"], "runner-prerequisites")
        self.assertTrue(receipt["cleanup_confirmed"])
        self.assertEqual(receipt["identity"], IDENTITY)

    def test_stopped_container_retains_real_files_and_sanitized_oom_state(self):
        self.preflight.container = CID
        state = self.state()
        state["State"].update(Status="exited", Running=False, Pid=0, ExitCode=137, OOMKilled=True,
                              Error="runtime SECRET", FinishedAt="2026-10-12T00:01:00.123Z")
        failure = {"schema_version": 1, "stage": "proc-helper", "line": 99, "exit_code": 1}
        sources = {"bootstrap-failure.json": json.dumps(failure).encode(),
                   "apt-update.log": b"discarded prefix\n" + b"z" * MODULE.MAX_EVIDENCE_BYTES}
        calls = []
        def command(args, **_kwargs):
            calls.append(args)
            return json.dumps([state]).encode() if args[0] == "inspect" else b""
        def execute(args, env, **kwargs):
            self.assertEqual(env, self.preflight.env)
            calls.append(args[3:])
            if args[3] == "logs":
                return 0, b"sandbox bootstrap failed: proc-helper\n"
            self.assertEqual(args[3], "cp")
            self.assertEqual(args[-1], "-")
            self.assertEqual(kwargs, {"timeout": 30, "maximum": MODULE.MAX_ARCHIVE_BYTES})
            filename = args[4].rsplit("/", 1)[-1]
            if filename in sources:
                return 0, archive_bytes(filename, sources[filename])
            return 1, b"Error: container SECRET is not running"
        with mock.patch.object(self.preflight, "command", side_effect=command), \
             mock.patch.object(MODULE, "execute", side_effect=execute), \
             mock.patch.object(self.preflight, "check_ancestors"):
            self.preflight.cleanup()
        self.assertEqual((self.root / "apt-update.log").read_bytes(), b"z" * MODULE.MAX_EVIDENCE_BYTES)
        self.assertEqual(json.loads((self.root / "bootstrap-failure.json").read_text()), failure)
        outcome = json.loads((self.root / "sandbox-exit.json").read_text())
        self.assertEqual(outcome["identity"], IDENTITY)
        self.assertEqual(outcome["container"], CID)
        self.assertEqual(outcome["state"]["exit_code"], 137)
        self.assertTrue(outcome["state"]["oom_killed"])
        self.assertTrue(outcome["state"]["runtime_error_present"])
        self.assertNotIn("SECRET", (self.root / "sandbox-exit.json").read_text())
        report = (self.root / "evidence-collection.json").read_text()
        self.assertNotIn("SECRET", report)
        self.assertFalse((self.root / "proc-mount.log").exists())
        self.assertFalse(any(call[0] == "exec" for call in calls))
        removal = calls.index(["rm", "--force", CID])
        self.assertLess(max(i for i, call in enumerate(calls) if call[0] == "cp"), removal)
        for filename in ("apt-update.log", "bootstrap-failure.json", "sandbox-exit.json", "bootstrap.log"):
            self.assertEqual((self.root / filename).stat().st_mode & 0o777, 0o600)
        self.assertTrue(self.preflight.receipt["cleanup_confirmed"])

    def test_malformed_exit_state_and_copy_timeout_never_bypass_removal(self):
        self.preflight.container = CID
        state = self.state()
        state["State"]["Status"] = ["SECRET"]
        calls = []
        def command(args, **_kwargs):
            calls.append(args)
            return json.dumps([state]).encode() if args[0] == "inspect" else b""
        with mock.patch.object(self.preflight, "command", side_effect=command), \
             mock.patch.object(MODULE, "execute", side_effect=MODULE.Failure("command-timeout")), \
             mock.patch.object(self.preflight, "check_ancestors"):
            self.preflight.cleanup()
        self.assertIn(["rm", "--force", CID], calls)
        self.assertFalse((self.root / "sandbox-exit.json").exists())
        report = json.loads((self.root / "evidence-collection.json").read_text())
        self.assertEqual(report["files"][0]["diagnostic"], "invalid-sandbox-exit-state")
        self.assertTrue(self.preflight.receipt["cleanup_confirmed"])

    def test_existing_evidence_and_output_symlinks_are_never_overwritten(self):
        self.preflight.container = CID
        existing = self.root / "proc-mount.json"
        existing.write_text('{"original":true}')
        target = self.root / "outside"
        target.write_text("private")
        (self.root / "network-sysctl.json").symlink_to(target)
        with mock.patch.object(self.preflight, "command", side_effect=lambda args, **kwargs:
                               json.dumps([self.state()]).encode() if args[0] == "inspect" else b""), \
             mock.patch.object(self.preflight, "check_ancestors"):
            self.preflight.cleanup()
        self.assertEqual(existing.read_text(), '{"original":true}')
        self.assertEqual(target.read_text(), "private")
        self.assertTrue(self.preflight.receipt["cleanup_confirmed"])

    def test_archive_reader_rejects_unsafe_members_truncation_and_extra_data(self):
        valid = archive_bytes("apt-update.log", b"real log")
        self.assertEqual(MODULE.archive_evidence(valid, "apt-update.log"), b"real log")
        variants = [b"invalid", valid[:1024], valid + b"daemon error", valid[:1536],
                    archive_bytes("../apt-update.log", b"escaped"),
                    archive_bytes("/apt-update.log", b"absolute"),
                    archive_bytes("apt-update.log", b"", extra="unexpected"),
                    archive_bytes("apt-update.log", b"", extra="apt-update.log")]
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE, tarfile.CHRTYPE, tarfile.FIFOTYPE):
            variants.append(archive_bytes("apt-update.log", b"", kind=kind))
        for raw in variants:
            with self.subTest(size=len(raw)), self.assertRaises(MODULE.Failure):
                MODULE.archive_evidence(raw, "apt-update.log")
        with self.assertRaisesRegex(MODULE.Failure, "unknown-evidence-file"):
            MODULE.archive_evidence(valid, "../apt-update.log")

    def test_archive_and_json_limits_keep_bounded_log_tails(self):
        data = b"x" * MODULE.MAX_EVIDENCE_FILE_BYTES
        self.assertEqual(MODULE.archive_evidence(archive_bytes("apt-install.log", data), "apt-install.log"),
                         b"x" * MODULE.MAX_EVIDENCE_BYTES)
        for filename, raw, diagnostic in (
            ("apt-install.log", b"x" * (MODULE.MAX_ARCHIVE_BYTES + 1), "evidence-archive-too-large"),
            ("apt-install.log", archive_bytes("apt-install.log", data + b"x"), "invalid-evidence-archive-member"),
            ("proc-mount.json", archive_bytes("proc-mount.json", b"x" * (MODULE.MAX_EVIDENCE_BYTES + 1)),
             "evidence-json-too-large"),
        ):
            with self.subTest(filename=filename), self.assertRaisesRegex(MODULE.Failure, diagnostic):
                MODULE.archive_evidence(raw, filename)

    def test_pax_metadata_chains_are_rejected_before_recursive_parsing(self):
        record = b"13 comment=x\n"
        header = tarfile.TarInfo("metadata")
        header.type, header.size = tarfile.XHDTYPE, len(record)
        metadata = header.tobuf(format=tarfile.USTAR_FORMAT) + record + b"\0" * (512 - len(record))
        for count in (1, 1100):
            raw = metadata * count + archive_bytes("apt-update.log", b"real log")
            with self.subTest(count=count), self.assertRaisesRegex(MODULE.Failure, "invalid-evidence-archive-member"):
                MODULE.archive_evidence(raw, "apt-update.log")

    def test_json_depth_bound_matches_utf8_decoder_and_preserves_strings(self):
        value = {"message": 'quote " and slash \\ plus []{} and \u2200', "nested": [[1]]}
        MODULE.validate_collected_json(json.dumps(value, ensure_ascii=False).encode())
        deep = '{"x":"\u2200","y":' + '[' * 1000 + '0' + ']' * 1000 + '}'
        with self.assertRaisesRegex(MODULE.Failure, "evidence-json-too-deep"):
            MODULE.validate_collected_json(deep.encode())
        for encoding in ("utf-16", "utf-32", "utf-16-le", "utf-32-be"):
            with self.subTest(encoding=encoding), self.assertRaises(ValueError):
                MODULE.validate_collected_json(deep.encode(encoding))

    def test_unexpected_collector_exception_still_removes_exact_container(self):
        self.preflight.container = CID
        calls = []
        def command(args, **kwargs):
            calls.append(args)
            return json.dumps([self.state()]).encode() if args[0] == "inspect" else b""
        with mock.patch.object(self.preflight, "command", side_effect=command), \
             mock.patch.object(self.preflight, "collect_diagnostics", side_effect=RecursionError()), \
             mock.patch.object(self.preflight, "check_ancestors"):
            with self.assertRaises(RecursionError):
                self.preflight.cleanup()
        self.assertIn(["rm", "--force", CID], calls)
        self.assertTrue(self.preflight.receipt["cleanup_confirmed"])

    def test_malformed_archives_and_json_are_reported_without_qualifying(self):
        self.preflight.container = CID
        def execute(args, env, **kwargs):
            if args[3] == "cp":
                filename = args[4].rsplit("/", 1)[-1]
                if filename == "proc-mount.json":
                    return 0, archive_bytes(filename, b"[]")
                return 0, b"malformed archive"
            return 1, b"daemon SECRET"
        with mock.patch.object(self.preflight, "command", side_effect=lambda args, **kwargs:
                               json.dumps([self.state()]).encode() if args[0] == "inspect" else b""), \
             mock.patch.object(MODULE, "execute", side_effect=execute), \
             mock.patch.object(self.preflight, "check_ancestors"):
            self.preflight.cleanup()
        self.assertFalse((self.root / "proc-mount.json").exists())
        self.assertFalse((self.root / "bootstrap.log").exists())
        self.assertTrue(self.preflight.receipt["cleanup_confirmed"])
        self.assertNotIn("SECRET", (self.root / "evidence-collection.json").read_text())
        self.assertFalse(self.preflight.receipt["supported"])

    def test_ancestor_state_change_blocks_success(self):
        with mock.patch.object(MODULE, "controls", return_value={"/": ["cpu", "io", "memory", "pids"]}):
            with self.assertRaisesRegex(MODULE.Failure, "external-cgroup-controller-state-changed"):
                self.preflight.check_ancestors()

    def test_evidence_from_another_attempt_is_rejected(self):
        self.preflight.container = CID
        receipt = {"supported": True, "identity": {**IDENTITY, "GITHUB_RUN_ATTEMPT": "2"}}
        def copy(_args, **_kwargs):
            (self.root / "sandbox.json").write_text(json.dumps(receipt))
            return b""
        with mock.patch.object(self.preflight, "command", side_effect=copy):
            with self.assertRaisesRegex(MODULE.Failure, "inner-evidence-identity-mismatch"):
                self.preflight.copy_json("sandbox.json")

    def test_shared_or_escaping_parent_is_rejected_before_filesystem_read(self):
        for parent in ("/", "relative", "/pod/../shared", "/pod//leaf"):
            with self.subTest(parent=parent), self.assertRaisesRegex(MODULE.Failure, "invalid-cgroup-parent"):
                MODULE.controls(parent)

    def test_subprocess_timeout_and_output_cap_are_bounded(self):
        env = {"PATH": "/usr/bin:/bin"}
        with self.assertRaisesRegex(MODULE.Failure, "command-timeout"):
            REAL_EXECUTE(["python3", "-c", "import time; time.sleep(5)"], env, timeout=0.05)
        with self.assertRaisesRegex(MODULE.Failure, "command-output-too-large"):
            REAL_EXECUTE(["python3", "-c", "print('x'*150000)"], env)

    def test_process_exit_race_does_not_mask_timeout(self):
        killpg = MODULE.os.killpg
        def race(pid, sig):
            killpg(pid, sig)
            raise ProcessLookupError()
        with mock.patch.object(MODULE.os, "killpg", side_effect=race), self.assertRaisesRegex(MODULE.Failure, "command-timeout"):
            REAL_EXECUTE(["python3", "-c", "import time; time.sleep(5)"], {"PATH": "/usr/bin:/bin"}, timeout=0.05)


if __name__ == "__main__":
    unittest.main()
