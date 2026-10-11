#!/usr/bin/env python3
"""Failure, ownership, and lifecycle regressions without a Docker daemon."""
import importlib.util
import contextlib
import io
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

SPEC = importlib.util.spec_from_file_location("native_preflight", Path(__file__).with_name("run-riscv-native-preflight.py"))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
IDENTITY = {"GITHUB_SHA": "a" * 40, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_REPOSITORY": "OxiBelt/OxiBelt", "GITHUB_EVENT_NAME": "workflow_dispatch"}
CID = "b" * 64


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

    def state(self):
        p = self.preflight
        return {"Id": CID, "Name": "/" + p.name, "Config": {"Labels": dict(p.labels)},
                "HostConfig": {"Privileged": False, "CgroupParent": p.parent,
                               "CgroupnsMode": "private", "NetworkMode": "bridge", "PidMode": "",
                               "NanoCpus": 2000000000, "Memory": 4294967296,
                               "MemorySwap": 4294967296, "PidsLimit": 1024,
                               "DeviceCgroupRules": ["c 10:200 rwm"]},
                "State": {"Running": True, "Pid": 321}}

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
             mock.patch.object(MODULE, "execute", side_effect=[(1, b"SECRET"), (1, b"SECRET"), (1, b"SECRET"), (0, b"")]), \
             mock.patch.object(self.preflight, "command", return_value=b""), contextlib.redirect_stdout(output):
            self.preflight.wait_ready()
        self.assertEqual(len(output.getvalue().splitlines()), 2)
        self.assertNotIn("SECRET", output.getvalue())
        with mock.patch.object(self.preflight, "container_state", return_value=self.state()), \
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
             mock.patch.object(self.preflight, "command", side_effect=command), \
             mock.patch.object(self.preflight, "qualify_network", side_effect=qualify) as check, \
             mock.patch.object(MODULE, "execute", side_effect=[(1, b""), (0, b"")]), \
             mock.patch.object(MODULE.time, "sleep"), contextlib.redirect_stdout(output):
            self.preflight.wait_ready()
        check.assert_called_once_with()
        self.assertEqual(output.getvalue().count("Native detached network forwarding verified"), 1)

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
        def command(args, **_kwargs):
            if args[0] == "inspect":
                return json.dumps([self.state()]).encode()
            if args[-1] == "/home/runner/evidence/proc-mount.log":
                return b'{"operation":"mount-proc","errno":1}\n'
            if args[-1].startswith("if test -f /home/runner/evidence/proc-mount.json"):
                return json.dumps(failure).encode()
            return b""
        with mock.patch.object(self.preflight, "command", side_effect=command), \
             mock.patch.object(self.preflight, "check_ancestors"):
            self.preflight.cleanup()
        self.assertEqual(json.loads((self.root / "proc-mount.json").read_text()), failure)
        self.assertIn(b'"errno":1', (self.root / "proc-mount.log").read_bytes())
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
            if args[0] == "inspect":
                return json.dumps([self.state()]).encode()
            if args[0] == "exec" and "cat /home/runner/evidence/network-sysctl.json" in args[-1]:
                return json.dumps(evidence).encode()
            return b""
        with mock.patch.object(self.preflight, "command", side_effect=command), \
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
            if args[0] == "inspect":
                return json.dumps([self.state()]).encode()
            if args[0] == "exec" and args[-1] == "/home/runner/evidence/enforcement-docker.log":
                self.assertEqual(args[2:6], ["tail", "-c", "65536", "--"])
                return diagnostic
            return b""
        with mock.patch.object(self.preflight, "command", side_effect=command), \
             mock.patch.object(self.preflight, "check_ancestors"):
            self.preflight.cleanup()
        log = self.root / "enforcement-docker.log"
        self.assertEqual(log.read_bytes(), diagnostic)
        self.assertEqual(log.stat().st_mode & 0o777, 0o600)
        capture = next(index for index, args in enumerate(calls)
                       if args[-1] == "/home/runner/evidence/enforcement-docker.log")
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
            MODULE.execute(["python3", "-c", "import time; time.sleep(5)"], env, timeout=0.05)
        with self.assertRaisesRegex(MODULE.Failure, "command-output-too-large"):
            MODULE.execute(["python3", "-c", "print('x'*150000)"], env)

    def test_process_exit_race_does_not_mask_timeout(self):
        killpg = MODULE.os.killpg
        def race(pid, sig):
            killpg(pid, sig)
            raise ProcessLookupError()
        with mock.patch.object(MODULE.os, "killpg", side_effect=race), self.assertRaisesRegex(MODULE.Failure, "command-timeout"):
            MODULE.execute(["python3", "-c", "import time; time.sleep(5)"], {"PATH": "/usr/bin:/bin"}, timeout=0.05)


if __name__ == "__main__":
    unittest.main()
