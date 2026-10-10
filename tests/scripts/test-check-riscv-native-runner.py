#!/usr/bin/env python3
"""Deterministic capability and evidence-boundary tests; no Docker or node changes."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("check-riscv-native-runner.py")
SPEC = importlib.util.spec_from_file_location("riscv_native_runner", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot import native runner probe")
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class NativeRunnerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="oxibelt-native-prerequisites-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.group = "/provider.slice/user.slice/user-1000.slice/user@1000.service"
        self.manager = self.root / "sys/fs/cgroup" / self.group.lstrip("/")
        self.manager.mkdir(parents=True)
        elf = bytearray(20)
        elf[:6] = b"\x7fELF\x02\x01"
        elf[18:20] = (243).to_bytes(2, "little")
        self.write("proc/self/exe", elf)
        self.write("proc/1/comm", b"tini\n")
        self.write(
            "proc/self/mountinfo",
            b"24 23 0:22 / /sys/fs/cgroup rw,nosuid,nodev,noexec - cgroup2 cgroup rw\n",
        )
        self.write("sys/fs/cgroup/cgroup.controllers", b"cpu memory pids io\n")
        (self.manager / "cgroup.controllers").write_text("cpu memory pids\n")
        (self.manager / "cgroup.subtree_control").write_text("cpu memory pids\n")
        (self.manager / "cgroup.procs").write_text("1234\n")
        self.write("etc/subuid", b"other:90000:1\nrunner:100000:65536\n")
        self.write("etc/subgid", b"1000:200000:65536\n")
        self.write("proc/sys/user/max_user_namespaces", b"10000\n")
        self.write("proc/sys/kernel/unprivileged_userns_clone", b"1\n")
        self.reader = mock.Mock(return_value=("ok", self.group))
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(PROBE.os, "getuid", return_value=1000).start()
        self.access = mock.patch.object(PROBE.os, "access", return_value=True).start()
        mock.patch.object(PROBE.shutil, "which", side_effect=lambda name: "/usr/bin/" + name).start()

    def write(self, relative: str, content: bytes) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    def run_probe(self, **kwargs: object) -> dict:
        return PROBE.Probe(
            root=self.root, uid=kwargs.pop("uid", 1000), username="runner",
            system=kwargs.pop("system", "Linux"), machine=kwargs.pop("machine", "riscv64"),
            command_reader=self.reader, **kwargs,
        ).run({"GITHUB_SHA": "a" * 40, "GITHUB_RUN_ID": "123"})

    def failed_check(self, receipt: dict, name: str) -> dict:
        self.assertFalse(receipt["supported"])
        return next(check for check in receipt["checks"] if check["name"] == name and not check["passed"])

    def test_delegation_at_actual_user_manager_path_succeeds_with_tini_pid1(self) -> None:
        receipt = self.run_probe()
        self.assertTrue(receipt["supported"], receipt)
        delegation = next(check for check in receipt["checks"] if check["name"] == "systemd_user_manager_delegation")
        self.assertEqual(delegation["control_group"], self.group)
        self.assertEqual(delegation["delegated_controllers"], ["cpu", "memory", "pids"])
        self.reader.assert_called_once_with()

    def test_global_controllers_do_not_substitute_for_enabled_user_subtree(self) -> None:
        (self.manager / "cgroup.subtree_control").write_text("memory pids\n")
        check = self.failed_check(self.run_probe(), "systemd_user_manager_delegation")
        self.assertEqual(check["diagnostic"], "user-manager-cpu-memory-pids-not-enabled")
        (self.manager / "cgroup.controllers").write_text("memory pids\n")
        self.assertEqual(
            self.failed_check(self.run_probe(), "systemd_user_manager_delegation")["diagnostic"],
            "user-manager-missing-cpu-memory-pids-controllers",
        )

    def test_reachable_manager_with_unwritable_delegation_is_unsupported(self) -> None:
        self.access.return_value = False
        self.assertEqual(
            self.failed_check(self.run_probe(), "systemd_user_manager_delegation")["diagnostic"],
            "user-manager-cgroup-not-writable",
        )

    def test_missing_manager_and_rootless_prerequisites_are_recorded_separately(self) -> None:
        self.reader.return_value = ("user-manager-unreachable", "secret diagnostic")
        (self.root / "etc/subgid").unlink()
        (self.root / "etc/subuid").write_text("runner:100000:65535\n")
        with mock.patch.object(PROBE.shutil, "which", return_value=None):
            receipt = self.run_probe()
        self.assertEqual(
            set(receipt["failed_prerequisites"]),
            {"systemd_user_manager_delegation", "uidmap_helpers", "subuid_mapping", "subgid_mapping"},
        )
        self.assertNotIn("secret diagnostic", json.dumps(receipt))

    def test_architecture_root_and_userspace_emulator_fail_closed(self) -> None:
        for kwargs, name in (
            ({"machine": "x86_64"}, "native_linux_riscv64"),
            ({"system": "FreeBSD"}, "native_linux_riscv64"),
            ({"uid": 0}, "nonroot_current_user"),
        ):
            with self.subTest(kwargs=kwargs):
                self.failed_check(self.run_probe(**kwargs), name)
        elf = bytearray((self.root / "proc/self/exe").read_bytes())
        elf[18:20] = (62).to_bytes(2, "little")
        self.write("proc/self/exe", elf)
        self.assertEqual(
            self.failed_check(self.run_probe(), "native_linux_riscv64")["diagnostic"],
            "requires-native-riscv64-executable",
        )

    def test_cgroup_v1_or_readonly_v2_cannot_claim_enforced_bounds(self) -> None:
        for filesystem, options, diagnostic in (
            ("cgroup", "rw", "requires-cgroup-v2-mount"),
            ("cgroup2", "ro", "cgroup-v2-mount-read-only"),
        ):
            with self.subTest(filesystem=filesystem, options=options):
                self.write(
                    "proc/self/mountinfo",
                    f"24 23 0:22 / /sys/fs/cgroup {options} - {filesystem} cgroup rw\n".encode(),
                )
                self.assertEqual(self.failed_check(self.run_probe(), "cgroup_v2")["diagnostic"], diagnostic)

    def test_namespaced_mount_mapping_and_malformed_mountinfo_fail_closed(self) -> None:
        for mountinfo, diagnostic in (
            ("24 23 0:22 /private /sys/fs/cgroup rw - cgroup2 cgroup rw\n", "cgroup-v2-mount-root-mapping-unsupported"),
            ("24 23 0:22 / /sys/fs/cgroup rw broken data data -\n", "requires-cgroup-v2-mount"),
        ):
            with self.subTest(diagnostic=diagnostic):
                self.write("proc/self/mountinfo", mountinfo.encode())
                receipt = self.run_probe()
                self.assertEqual(self.failed_check(receipt, "cgroup_v2")["diagnostic"], diagnostic)
                self.assertEqual(
                    self.failed_check(receipt, "systemd_user_manager_delegation")["diagnostic"],
                    "requires-verified-cgroup-v2-mount",
                )

    def test_manager_paths_cannot_escape_or_select_another_user(self) -> None:
        for group in (
            "/../../user-1000.slice/user@1000.service",
            "/user.slice/user-1001.slice/user@1001.service",
            "relative/user-1000.slice/user@1000.service",
            self.group + "\nSECRET=credentials",
        ):
            with self.subTest(group=group):
                self.reader.return_value = ("ok", group)
                check = self.failed_check(self.run_probe(), "systemd_user_manager_delegation")
                self.assertEqual(check["diagnostic"], "invalid-user-manager-cgroup-path")
        self.reader.return_value = ("ok", self.group)
        external = self.root / "outside"
        external.mkdir()
        for child in self.manager.iterdir():
            child.unlink()
        self.manager.rmdir()
        self.manager.symlink_to(external, target_is_directory=True)
        self.assertEqual(
            self.failed_check(self.run_probe(), "systemd_user_manager_delegation")["diagnostic"],
            "user-manager-cgroup-path-escape",
        )

    def test_large_inputs_and_disabled_namespaces_fail_without_raw_contents(self) -> None:
        self.write("etc/subuid", b"secret=" + b"x" * PROBE.MAX_READ_BYTES)
        self.write("proc/sys/user/max_user_namespaces", b"0\n")
        receipt = self.run_probe()
        self.assertEqual(self.failed_check(receipt, "subuid_mapping")["diagnostic"], "input-too-large")
        self.failed_check(receipt, "user_namespace_kernel_prerequisites")
        self.assertLess(len(json.dumps(receipt)), 5000)
        self.assertNotIn("secret=", json.dumps(receipt))

    def test_existing_ranges_are_validated_for_current_user_only(self) -> None:
        for row in ("runner:1:4294967296\n", "runner:bad:65536\n", "runner:0:65536\n"):
            with self.subTest(row=row):
                self.write("etc/subuid", row.encode())
                self.failed_check(self.run_probe(), "subuid_mapping")
        self.write("etc/subuid", b"other:garbage:range\n1000:100000:70000\n")
        self.assertTrue(self.run_probe()["supported"])

    def test_identity_is_allowlisted_validated_and_bounded(self) -> None:
        env = {
            "GITHUB_SHA": "a" * 40, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2",
            "GITHUB_REPOSITORY": "OxiBelt/OxiBelt", "GITHUB_ACTOR": "private-person",
            "GITHUB_WORKFLOW_REF": "OxiBelt/OxiBelt/.github/workflows/native.yml@refs/heads/main",
            "GITHUB_TOKEN": "secret", "AWS_SECRET_ACCESS_KEY": "secret",
            "GITHUB_REF": "refs/heads/main\nSECRET", "GITHUB_JOB": "x" * 257,
        }
        identity = PROBE.github_identity(env)
        self.assertEqual(set(identity), {"GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_REPOSITORY", "GITHUB_WORKFLOW_REF"})
        self.assertNotIn("secret", json.dumps(identity))

    def test_evidence_creates_only_new_private_regular_json_files(self) -> None:
        receipt = self.run_probe()
        output = self.root / "evidence.json"
        PROBE.write_evidence(output, receipt)
        self.assertEqual(json.loads(output.read_text()), receipt)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        with self.assertRaises(PROBE.ProbeError):
            PROBE.write_evidence(output, receipt)
        target = self.root / "target"
        target.write_text("untouched")
        symlink = self.root / "link.json"
        symlink.symlink_to(target)
        directory = self.root / "directory.json"
        directory.mkdir()
        fifo = self.root / "pipe.json"
        os.mkfifo(fifo)
        for path in (symlink, directory, fifo, self.root / "no-extension", self.root / "x/../escaped.json"):
            with self.subTest(path=path), self.assertRaises(PROBE.ProbeError):
                PROBE.write_evidence(path, receipt)
        self.assertEqual(target.read_text(), "untouched")
        parent_link = self.root / "parent-link"
        parent_link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(PROBE.ProbeError):
            PROBE.write_evidence(parent_link / "via-link.json", receipt)

    def test_cli_exit_status_preserves_unsupported_receipt(self) -> None:
        probe = mock.Mock()
        receipt = self.run_probe(machine="x86_64")
        probe.run.return_value = receipt
        output = self.root / "unsupported.json"
        with mock.patch.object(PROBE, "Probe", return_value=probe), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(PROBE.main(["--output", str(output)]), 1)
            self.assertEqual(PROBE.main(["--output", str(output)]), 2)
        self.assertFalse(json.loads(output.read_text())["supported"])

    def test_subprocess_errors_timeout_and_large_output_are_bounded_and_safe(self) -> None:
        executable = self.root / "fake-systemctl"
        for code, expected in (
            ("import sys; print('SECRET', file=sys.stderr); sys.exit(1)", "user-manager-unreachable"),
            ("print('x' * 8192)", "command-output-too-large"),
            ("import time; time.sleep(2)", "command-timeout"),
            (f"print({self.group!r})", "ok"),
        ):
            with self.subTest(expected=expected):
                executable.write_text(f"#!{sys.executable}\n{code}\n")
                executable.chmod(0o700)
                with mock.patch.object(PROBE.shutil, "which", return_value=str(executable)), mock.patch.object(PROBE, "COMMAND_TIMEOUT_SECONDS", 0.3):
                    status, value = PROBE.read_user_manager()
                self.assertEqual(status, expected)
                self.assertEqual(value, self.group if expected == "ok" else "")


if __name__ == "__main__":
    unittest.main()
