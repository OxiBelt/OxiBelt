#!/usr/bin/env python3
"""Network probe regressions without privileges or real sysctl writes."""
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SPEC = importlib.util.spec_from_file_location("network_sysctl", Path(__file__).with_name("check-riscv-network-sysctl.py"))
assert SPEC and SPEC.loader
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


def mounts(network="rw,nosuid,nodev,noexec"):
    text = ("1 0 0:1 / / rw - overlay overlay rw\n"
            "2 1 0:2 / /sys ro,nosuid,nodev,noexec - sysfs sysfs ro\n"
            "3 2 0:3 / /sys/fs/cgroup rw,nosuid,nodev,noexec - cgroup2 cgroup rw\n"
            "4 1 0:4 / /proc rw,nosuid,nodev,noexec - proc proc rw\n"
            "5 4 0:4 /sys /proc/sys ro,nosuid,nodev,noexec - proc proc rw\n")
    if network:
        text += "6 5 0:4 /sys/net /proc/sys/net " + network + " - proc proc rw\n"
    return text


def receipt():
    return {"schema_version": 1, "supported": True, "diagnostic": "passed",
            "sandbox_netns": 101, "detached_netns": 202,
            "ipv4": {"before": 0, "readback": 1, "restored": True, "status": "passed"},
            "ipv6": {"status": "unavailable"},
            "native": {"architecture": "riscv64", "executing_elf_machine": 243, "uid": 1001,
                       "rootlesskit_version": "3.2.0", "engine_source_version": "29.8.0"},
            "parent_before": 0, "parent_after": 0, "cleanup_confirmed": True}


class MountTests(unittest.TestCase):
    def protect(self, before, after=None, failure=None, wrong_namespace=False, no_remount=False):
        after = before if after is None else after
        def read(path, *args):
            return b"systemd\n" if str(path) == "/proc/1/comm" else next(reads).encode()
        reads = iter((before, after))
        def path_stat(path, *args, **kwargs):
            return mock.Mock(st_ino=2 if wrong_namespace and str(path) == "/proc/self/ns/mnt" else 1)
        with mock.patch.object(PROBE.os, "getuid", return_value=0), \
             mock.patch.object(PROBE.os, "geteuid", return_value=0), \
             mock.patch.object(PROBE.platform, "machine", return_value="riscv64"), \
             mock.patch.object(PROBE.Path, "is_file", return_value=True), \
             mock.patch.object(PROBE.Path, "stat", path_stat), \
             mock.patch.object(PROBE.Path, "resolve", lambda path, **kw: path), \
             mock.patch.object(PROBE, "read_file", side_effect=read), \
             mock.patch.object(PROBE.subprocess, "run", side_effect=failure) as run, \
             mock.patch("builtins.print"):
            try:
                PROBE.protect_systemd_mounts()
            finally:
                if no_remount:
                    run.assert_not_called()
            return run.call_args_list

    def test_restores_only_known_systemd_fusectl_mount(self):
        fuse = "7 2 0:7 / /sys/fs/fuse/connections rw,nosuid,nodev,noexec - fusectl fusectl rw\n"
        calls = self.protect(mounts() + fuse, mounts() + fuse.replace("connections rw,", "connections ro,"))
        self.assertEqual(calls[0].args[0], ["/usr/bin/mount", "-o", "remount,bind,ro,nosuid,nodev,noexec",
                                          "/sys/fs/fuse/connections"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.protect(mounts()), [])

    def test_systemd_protection_rejects_unknown_or_unrepaired_mounts(self):
        fuse = "7 2 0:7 / /sys/fs/fuse/connections rw,nosuid,nodev,noexec - fusectl fusectl rw\n"
        for before in (mounts() + fuse.replace("fusectl", "tmpfs"),
                       mounts() + fuse.replace("/sys/fs/fuse/connections", "/sys/kernel/debug"),
                       mounts() + fuse + fuse,
                       mounts() + fuse + "8 5 0:4 /sys/kernel /proc/sys/kernel rw - proc proc rw\n"):
            with self.subTest(before=before):
                with self.assertRaises(PROBE.ProbeError):
                    self.protect(before, no_remount=True)
        with self.assertRaisesRegex(PROBE.ProbeError, "writable-noncgroup-sys-mount"):
            self.protect(mounts() + fuse)
        with self.assertRaisesRegex(PROBE.ProbeError, "requires-sandbox-systemd"):
            self.protect(mounts(), wrong_namespace=True, no_remount=True)
        with self.assertRaises(PROBE.subprocess.CalledProcessError):
            self.protect(mounts() + fuse, failure=PROBE.subprocess.CalledProcessError(1, "mount"))

    def test_strict_positive_and_initial_optional_network(self):
        self.assertTrue(PROBE.validate_mounts(mounts())["network_sysctl_writable"])
        for network in (None, "ro,nosuid,nodev,noexec", "rw,nosuid,nodev,noexec"):
            PROBE.validate_mounts(mounts(network), require_network=False)

    def test_missing_network_mount_and_writable_kernel_are_rejected(self):
        bad_kernel = mounts() + "7 5 0:4 /sys/kernel /proc/sys/kernel rw,nosuid,nodev,noexec - proc proc rw\n"
        for text in (mounts(None), mounts("ro,nosuid,nodev,noexec"), bad_kernel):
            with self.subTest(text=text), self.assertRaises(PROBE.ProbeError):
                PROBE.validate_mounts(text)
        with self.assertRaises(PROBE.ProbeError):
            PROBE.validate_mounts(bad_kernel, require_network=False)

    def test_flags_filesystem_and_effective_overmounts(self):
        for text in (mounts("rw"), mounts().replace(" - proc proc", " - tmpfs tmpfs"),
                     mounts() + "7 5 0:5 / /proc/sys/user rw - tmpfs tmpfs rw\n",
                     mounts() + "7 6 0:5 / /proc/sys/net/ipv4 rw - tmpfs tmpfs rw\n",
                     mounts() + "7 2 0:2 / /sys/kernel rw,nosuid,nodev,noexec - sysfs sysfs rw\n",
                     mounts().replace("/sys ro,", "/sys rw,"),
                     mounts().replace("/sys/fs/cgroup rw,", "/sys/fs/cgroup ro,")):
            with self.subTest(text=text), self.assertRaises(PROBE.ProbeError):
                PROBE.validate_mounts(text)
        with self.assertRaises(PROBE.ProbeError):
            PROBE.validate_mounts(mounts("rw"), require_network=False)


class PrerequisiteTests(unittest.TestCase):
    def test_native_identity_and_source_version_are_required(self):
        lock = {"schemaVersion": 1, "architecture": "riscv64", "rootlesskit": {"version": "3.2.0"},
                "sources": {"engine": {"version": "29.8.0"}}}
        with mock.patch.object(PROBE.platform, "system", return_value="Linux"), \
             mock.patch.object(PROBE.platform, "machine", return_value="riscv64"), \
             mock.patch.object(PROBE.os, "getuid", return_value=1001), \
             mock.patch.object(PROBE.os, "geteuid", return_value=1001), \
             mock.patch.object(PROBE, "native_elf") as elf, \
             mock.patch.object(PROBE, "read_file", side_effect=[json.dumps(lock).encode(), mounts().encode()]):
            self.assertEqual(PROBE.prerequisites()["uid"], 1001)
            self.assertEqual(elf.call_count, 2)
        lock["rootlesskit"]["version"] = "3.1.0"
        with mock.patch.object(PROBE.platform, "system", return_value="Linux"), \
             mock.patch.object(PROBE.platform, "machine", return_value="riscv64"), \
             mock.patch.object(PROBE.os, "getuid", return_value=1001), \
             mock.patch.object(PROBE.os, "geteuid", return_value=1001), \
             mock.patch.object(PROBE, "native_elf"), \
             mock.patch.object(PROBE, "read_file", return_value=json.dumps(lock).encode()):
            with self.assertRaisesRegex(PROBE.ProbeError, "unexpected-source-lock"):
                PROBE.prerequisites()
        with mock.patch.object(PROBE.os, "getuid", return_value=0):
            with self.assertRaisesRegex(PROBE.ProbeError, "requires-native-nonroot"):
                PROBE.prerequisites()

    def test_elf_machine_rejects_non_native_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "binary"
            raw = bytearray(b"\x7fELF\x02\x01" + b"\0"*14)
            raw[18:20] = (243).to_bytes(2, "little")
            binary.write_bytes(raw)
            PROBE.native_elf(binary)
            raw[18:20] = (62).to_bytes(2, "little")
            binary.write_bytes(raw)
            with self.assertRaisesRegex(PROBE.ProbeError, "requires-native-riscv64-elf"):
                PROBE.native_elf(binary)


class ToggleTests(unittest.TestCase):
    def test_single_digit_write_accepts_ipv6_handlers_returning_one(self):
        stream = mock.MagicMock()
        stream.__enter__.return_value = stream
        stream.fileno.return_value = 10
        stream.write.side_effect = lambda raw: 1
        with mock.patch.object(PROBE.os, "open", return_value=10), \
             mock.patch.object(PROBE.os, "fdopen", return_value=stream):
            for value in (0, 1):
                PROBE.write_forwarding(PROBE.IPV6, value)
        self.assertEqual([call.args[0] for call in stream.write.call_args_list], [b"0", b"1"])
        state = [0]
        def apply(raw):
            state[0] = int(raw)
            return 1
        stream.write.reset_mock()
        stream.write.side_effect = apply
        evidence = {}
        with mock.patch.object(PROBE.os, "open", return_value=10), \
             mock.patch.object(PROBE.os, "fdopen", return_value=stream), \
             mock.patch.object(PROBE, "forwarding", side_effect=lambda path: state[0]):
            PROBE.toggle(PROBE.IPV6, evidence, optional=True)
        self.assertEqual([call.args[0] for call in stream.write.call_args_list], [b"1", b"0"])
        self.assertEqual(evidence, {"before": 0, "readback": 1, "restored": True, "status": "passed"})
        self.assertEqual(state[0], 0)
        stream.write.return_value = 0
        stream.write.side_effect = None
        with mock.patch.object(PROBE.os, "open", return_value=10), \
             mock.patch.object(PROBE.os, "fdopen", return_value=stream):
            with self.assertRaisesRegex(PROBE.ProbeError, "short-sysctl-write"):
                PROBE.write_forwarding(PROBE.IPV6, 1)

    def test_toggles_opposite_and_restores_for_either_initial_value(self):
        for before in (0, 1):
            evidence = {}
            with mock.patch.object(PROBE, "forwarding", side_effect=[before, 1-before, before]), \
                 mock.patch.object(PROBE, "write_forwarding") as write:
                PROBE.toggle(PROBE.IPV4, evidence)
            self.assertEqual([call.args[1] for call in write.call_args_list], [1-before, before])
            self.assertTrue(evidence["restored"])

    def test_failed_readback_still_restores(self):
        for readback in (0, PROBE.ProbeError("read-failed")):
            evidence = {}
            with mock.patch.object(PROBE, "forwarding", side_effect=[0, readback, 0]), \
                 mock.patch.object(PROBE, "write_forwarding") as write:
                with self.assertRaises(PROBE.ProbeError):
                    PROBE.toggle(PROBE.IPV4, evidence)
            self.assertEqual([call.args[1] for call in write.call_args_list], [1, 0])
            self.assertTrue(evidence["restored"])

    def test_readback_and_restore_failure_is_fail_closed(self):
        evidence = {}
        with mock.patch.object(PROBE, "forwarding", side_effect=[0, 0]), \
             mock.patch.object(PROBE, "write_forwarding", side_effect=[None, PROBE.ProbeError("write-failed")]):
            with self.assertRaisesRegex(PROBE.ProbeError, "forwarding-restore-failed"):
                PROBE.toggle(PROBE.IPV4, evidence)
        self.assertFalse(evidence["restored"])

    def test_ipv6_optional_denied_write_and_successful_write_restore(self):
        evidence = {}
        with mock.patch.object(PROBE, "forwarding", return_value=0), \
             mock.patch.object(PROBE, "write_forwarding", side_effect=PROBE.ProbeError("denied")) as write:
            PROBE.toggle(PROBE.IPV6, evidence, optional=True)
        self.assertEqual(write.call_count, 1)
        self.assertEqual(evidence["status"], "unavailable")
        self.assertTrue(evidence["restored"])
        value = receipt()
        value["ipv6"] = evidence
        PROBE.validate_receipt(value)
        evidence = {}
        with mock.patch.object(PROBE, "forwarding", side_effect=[1, 0, 1]), \
             mock.patch.object(PROBE, "write_forwarding") as write:
            PROBE.toggle(PROBE.IPV6, evidence, optional=True)
        self.assertEqual([call.args[1] for call in write.call_args_list], [0, 1])
        self.assertTrue(evidence["restored"])


class ChildTests(unittest.TestCase):
    def test_child_copyup_symlink_parent_requires_exact_state_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            actual = root / "original"
            actual.mkdir()
            runtime = root / "runtime"
            runtime.symlink_to(actual, target_is_directory=True)
            state = runtime / "oxibelt-network-test"
            state.mkdir(mode=0o700)
            info = state.stat()
            with mock.patch.object(PROBE, "RUNTIME", runtime), \
                 mock.patch.object(PROBE.os, "getuid", return_value=0):
                # This unprivileged fixture has a host owner; simulate the mapped owner.
                mapped = mock.Mock(st_mode=info.st_mode, st_uid=0, st_dev=info.st_dev, st_ino=info.st_ino)
                with mock.patch.object(PROBE.Path, "lstat", return_value=mapped):
                    PROBE.guarded_state(state, child=True, identity=(info.st_dev, info.st_ino))
                    with self.assertRaisesRegex(PROBE.ProbeError, "identity-mismatch"):
                        PROBE.guarded_state(state, child=True, identity=(info.st_dev, info.st_ino+1))
                    mapped.st_uid = 1001
                    with self.assertRaisesRegex(PROBE.ProbeError, "contains-symlink"):
                        PROBE.guarded_state(state)
                    mapped.st_uid = 0
                    mapped.st_mode = stat.S_IFLNK | 0o700
                    with self.assertRaisesRegex(PROBE.ProbeError, "invalid-exclusive-state-directory"):
                        PROBE.guarded_state(state, child=True, identity=(info.st_dev, info.st_ino))

    def test_shared_namespace_never_writes(self):
        value = receipt()
        with mock.patch.object(PROBE, "guarded_state"), mock.patch.object(PROBE.os, "getuid", return_value=0), \
             mock.patch.object(PROBE.os, "geteuid", return_value=0), \
             mock.patch.object(PROBE, "read_file", return_value=b"0 1001 1\n1 100000 65536\n"), \
             mock.patch.object(PROBE, "namespace_id", side_effect=[101, 101]), \
             mock.patch.object(PROBE, "write_forwarding") as write:
            with self.assertRaisesRegex(PROBE.ProbeError, "did-not-enter-detached"):
                PROBE.child_probe(Path("/run/user/1001/oxibelt-network-test"), 101, value, (1, 2))
        write.assert_not_called()

    def test_host_root_mapping_never_writes(self):
        with mock.patch.object(PROBE, "guarded_state"), mock.patch.object(PROBE.os, "getuid", return_value=0), \
             mock.patch.object(PROBE.os, "geteuid", return_value=0), \
             mock.patch.object(PROBE, "read_file", return_value=b"0 0 4294967295\n"), \
             mock.patch.object(PROBE, "write_forwarding") as write:
            with self.assertRaisesRegex(PROBE.ProbeError, "not-mapped-runner"):
                PROBE.child_probe(Path("/run/user/1001/oxibelt-network-test"), 101, receipt(), (1, 2))
        write.assert_not_called()

    def test_success_receipt_rejects_parent_change_shared_namespace_or_cleanup(self):
        self.assertEqual(PROBE.validate_receipt(receipt()), receipt())
        variants = [("parent_after", 1), ("detached_netns", 101), ("cleanup_confirmed", False),
                    ("supported", False), ("sandbox_netns", True), ("schema_version", True)]
        for field, value in variants:
            row = receipt()
            row[field] = value
            with self.subTest(field=field), self.assertRaises(PROBE.ProbeError):
                PROBE.validate_receipt(row)
        row = receipt()
        row["ipv4"]["restored"] = False
        with self.assertRaises(PROBE.ProbeError):
            PROBE.validate_receipt(row)
        row = receipt()
        row["ipv4"]["before"] = False
        with self.assertRaises(PROBE.ProbeError):
            PROBE.validate_receipt(row)


class ProcessTests(unittest.TestCase):
    def test_rootlesskit_removed_state_is_confirmed_only_after_process_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            commands = mock.Mock(cleanup_confirmed=True)
            child = {key: value for key, value in receipt().items()
                     if key not in ("native", "parent_before", "parent_after", "cleanup_confirmed")}
            def call(arguments):
                if arguments[1] == "--version":
                    return 0, "rootlesskit version 3.2.0\n"
                state = Path(arguments[1].split("=", 1)[1])
                state.rmdir()
                return 0, json.dumps(child)
            commands.call.side_effect = call
            original_lstat = PROBE.Path.lstat
            def lstat(path, *args, **kwargs):
                result = original_lstat(path, *args, **kwargs)
                return mock.Mock(st_mode=result.st_mode, st_uid=1001,
                                 st_dev=result.st_dev, st_ino=result.st_ino)
            value = receipt()
            with mock.patch.object(PROBE, "RUNTIME", runtime), \
                 mock.patch.object(PROBE, "prerequisites", return_value=value["native"]), \
                 mock.patch.object(PROBE, "namespace_id", return_value=101), \
                 mock.patch.object(PROBE, "forwarding", return_value=0), \
                 mock.patch.object(PROBE.Path, "lstat", lstat), \
                 mock.patch.object(PROBE.shutil, "rmtree") as remove:
                PROBE.parent_probe(value, commands)
                remove.assert_not_called()
            PROBE.validate_receipt(value)
            self.assertEqual(list(runtime.iterdir()), [])

    def test_timeout_and_output_limit_kill_and_reap_entire_tree(self):
        scripts = [("command-timeout", "import os,time; print(os.fork(),flush=True); time.sleep(20)", .15),
                   ("command-output-too-large", "import os,time; os.fork(); print('x'*70000,flush=True); time.sleep(20)", 3)]
        for diagnostic, script, bound in scripts:
            commands = PROBE.Commands()
            commands.deadline = PROBE.time.monotonic() + bound
            with mock.patch.object(PROBE, "group_members", wraps=PROBE.group_members) as members:
                with self.assertRaisesRegex(PROBE.ProbeError, diagnostic):
                    commands.call([sys.executable, "-c", script])
            self.assertTrue(commands.cleanup_confirmed)
            self.assertLessEqual(len(commands.log), PROBE.MAX_OUTPUT)
            group = members.call_args.args[0]
            self.assertEqual(PROBE.group_members(group), [])

    def test_nonzero_exit_also_removes_surviving_descendant(self):
        commands = PROBE.Commands()
        # Descendant closes the pipes, so leader exit cannot hide it from cleanup.
        script = "import os,time; pid=os.fork();\nif pid==0:\n os.close(1); os.close(2); time.sleep(20)\nelse:\n os._exit(7)"
        with mock.patch.object(PROBE, "group_members", wraps=PROBE.group_members) as members:
            code, _out = commands.call([sys.executable, "-c", script])
        self.assertEqual(code, 7)
        self.assertTrue(commands.cleanup_confirmed)
        self.assertEqual(PROBE.group_members(members.call_args.args[0]), [])

    def test_parent_change_is_failure_after_exclusive_state_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            commands = mock.Mock(cleanup_confirmed=True)
            child = {key: value for key, value in receipt().items()
                     if key not in ("native", "parent_before", "parent_after", "cleanup_confirmed")}
            commands.call.side_effect = [(0, "rootlesskit version 3.2.0\n"), (0, json.dumps(child))]
            value = receipt()
            with mock.patch.object(PROBE, "RUNTIME", runtime), \
                 mock.patch.object(PROBE, "prerequisites", return_value=value["native"]), \
                 mock.patch.object(PROBE, "namespace_id", return_value=101), \
                 mock.patch.object(PROBE, "forwarding", side_effect=[0, 1]), \
                 mock.patch.object(PROBE, "guarded_state"), mock.patch.object(PROBE.stat, "S_IMODE", return_value=0o700), \
                 mock.patch.object(PROBE.Path, "lstat", return_value=mock.Mock(st_mode=stat_directory(), st_uid=1001, st_dev=1, st_ino=2)):
                with self.assertRaisesRegex(PROBE.ProbeError, "sandbox-forwarding-changed"):
                    PROBE.parent_probe(value, commands)
            self.assertEqual(list(runtime.iterdir()), [])
            self.assertEqual(value["parent_after"], 1)
            args = commands.call.call_args.args[0]
            self.assertEqual(args[2:2+len(PROBE.FLAGS)], PROBE.FLAGS)
            self.assertIn("--parent-netns", args)

    def test_unconfirmed_process_cleanup_never_deletes_exclusive_state(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            commands = mock.Mock(cleanup_confirmed=False)
            commands.call.side_effect = [(0, "rootlesskit version 3.2.0\n"), PROBE.ProbeError("process-group-cleanup-failed")]
            value = receipt()
            with mock.patch.object(PROBE, "RUNTIME", runtime), \
                 mock.patch.object(PROBE, "prerequisites", return_value=value["native"]), \
                 mock.patch.object(PROBE, "namespace_id", return_value=101), \
                 mock.patch.object(PROBE, "forwarding", side_effect=[0, 0]), \
                 mock.patch.object(PROBE, "guarded_state"), mock.patch.object(PROBE.stat, "S_IMODE", return_value=0o700), \
                 mock.patch.object(PROBE.Path, "lstat", return_value=mock.Mock(st_mode=stat_directory(), st_uid=1001, st_dev=1, st_ino=2)), \
                 mock.patch.object(PROBE.shutil, "rmtree") as remove:
                with self.assertRaisesRegex(PROBE.ProbeError, "process-group-cleanup-failed"):
                    PROBE.parent_probe(value, commands)
                remove.assert_not_called()
            self.assertFalse(value["cleanup_confirmed"])
            self.assertEqual(len(list(runtime.iterdir())), 1)


def stat_directory():
    return stat.S_IFDIR | 0o700


if __name__ == "__main__":
    unittest.main()
