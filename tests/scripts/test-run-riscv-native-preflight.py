#!/usr/bin/env python3
"""Failure, ownership, and lifecycle regressions without a Docker daemon."""
import importlib.util
import contextlib
import io
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
                               "MemorySwap": 4294967296, "PidsLimit": 1024},
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
        for flag in ("--cpus=2", "--memory=4g", "--memory-swap=4g", "--pids-limit=1024"):
            self.assertIn(flag, args)
        self.assertNotIn("--privileged", args)
        self.assertNotIn("--pid=host", args)
        self.assertNotIn("--network=host", args)
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
                           ("CgroupnsMode", "host"), ("CgroupParent", "/docker")):
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
        mounts = "1 0 0:1 / /sys ro - sysfs sysfs ro\n2 0 0:2 / /proc/sys ro - proc proc ro\n3 0 0:3 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n"
        for fault, diagnostic in ((None, None), ("cgroup", "sandbox-process-outside-owned-cgroup"),
                                  ("namespace", "sandbox-namespace-not-private"),
                                  ("sys", "sandbox-kernel-mount-boundary-mismatch")):
            def read(path):
                if str(path) == "/proc/321/cgroup":
                    return "0::/foreign" if fault == "cgroup" else expected
                return "0::/outer"
            def command(args, **_kwargs):
                if args[2] == "stat":
                    return b"1:2" if fault == "namespace" else b"1:3"
                return (mounts.replace("/sys ro", "/sys rw") if fault == "sys" else mounts).encode()
            with self.subTest(fault=fault), mock.patch.object(self.preflight, "container_state", return_value=self.state()), \
                 mock.patch.object(self.preflight.probe, "Probe", return_value=SimpleNamespace(read=read)), \
                 mock.patch.object(MODULE.os, "stat", return_value=SimpleNamespace(st_dev=1, st_ino=2)), \
                 mock.patch.object(self.preflight, "command", side_effect=command):
                if diagnostic:
                    with self.assertRaisesRegex(MODULE.Failure, diagnostic):
                        self.preflight.verify_running_boundary()
                else:
                    self.preflight.verify_running_boundary()

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
