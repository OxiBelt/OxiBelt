#!/usr/bin/env python3
"""Proc mount probe regressions without privileged mounts or workload execution."""
import contextlib
import copy
import errno
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

SPEC = importlib.util.spec_from_file_location("proc_mount", Path(__file__).with_name("check-riscv-proc-mount.py"))
assert SPEC and SPEC.loader
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)
IDENTITY = {"GITHUB_REPOSITORY": "example/OxiBelt", "GITHUB_SHA": "a" * 40,
            "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_EVENT_NAME": "push"}


def child():
    value = PROBE.child_receipt()
    value.update(supported=True, diagnostic="passed", pidns=303, mntns=404, pid_one=True,
                 mapped_runner_root=True, proc_self_pid_one=True, proc_root_and_flags=True, unmounted=True)
    return value


def receipt():
    return {"schema_version": 1, "supported": True, "diagnostic": "passed", "identity": dict(IDENTITY),
            "native": {**PROBE.NATIVE_FIELDS, **{key: "b" * 64 for key in PROBE.HASH_FIELDS}},
            "kernel_release": "6.12.42-provider", "sandbox_pidns": 101, "sandbox_mntns": 202,
            "child": child(), "parent_mounts_sha256": "c" * 64, "parent_mounts_unchanged": True,
            "helper_inaccessible": True, "cleanup_confirmed": True}


def mountinfo(target, *, root="/", flags="rw,nosuid,nodev,noexec", filesystem="proc"):
    return f"1 0 0:1 / / rw - overlay overlay rw\n2 1 0:2 {root} {target} {flags} - {filesystem} proc rw\n"


class ReceiptTests(unittest.TestCase):
    def test_success_binds_exact_identity_and_native_hashes(self):
        value = receipt()
        hashes = {key: value["native"][key] for key in PROBE.HASH_FIELDS}
        self.assertIs(PROBE.validate_receipt(value, IDENTITY, hashes), value)
        for identity, expected_hashes in (({**IDENTITY, "GITHUB_SHA": "d"*40}, hashes),
                                          (IDENTITY, {**hashes, "probe_sha256": "d"*64})):
            with self.subTest(identity=identity), self.assertRaises(PROBE.ProbeError):
                PROBE.validate_receipt(value, identity, expected_hashes)

    def test_malformed_or_negative_receipts_are_rejected(self):
        variants = [("schema_version", True), ("supported", False), ("diagnostic", "failed"),
                    ("sandbox_pidns", True), ("sandbox_mntns", 0), ("cleanup_confirmed", False),
                    ("parent_mounts_unchanged", False), ("helper_inaccessible", False),
                    ("parent_mounts_sha256", "bad"), ("kernel_release", "release\nsecret"),
                    ("identity", {}), ("identity", {"GITHUB_SHA": True}),
                    ("identity", {"SECRET": "not-allowed"})]
        for field, wrong in variants:
            value = receipt()
            value[field] = wrong
            with self.subTest(field=field, wrong=wrong), self.assertRaises(PROBE.ProbeError):
                PROBE.validate_receipt(value)
        for field, wrong in (("uid", True), ("executing_elf_machine", 62), ("probe_sha256", "X"*64)):
            value = receipt()
            value["native"][field] = wrong
            with self.subTest(field=field), self.assertRaises(PROBE.ProbeError):
                PROBE.validate_receipt(value)

    def test_child_shared_namespace_or_missing_cleanup_never_passes(self):
        for field, wrong in (("pidns", 101), ("mntns", 202), ("pid_one", False),
                             ("unmounted", False), ("proc_self_pid_one", False),
                             ("mapped_runner_root", False), ("proc_root_and_flags", False),
                             ("schema_version", True), ("pidns", True), ("supported", False)):
            value = receipt()
            value["child"][field] = wrong
            with self.subTest(field=field), self.assertRaises(PROBE.ProbeError):
                PROBE.validate_receipt(value)

    def test_private_proc_requires_full_root_flags_and_no_child_mounts(self):
        target = Path("/run/user/1001/oxibelt-network-test/proc")
        PROBE.validate_proc_mount(mountinfo(target), target)
        variants = [mountinfo(target, root="/sys"), mountinfo(target, flags="rw,nosuid,nodev"),
                    mountinfo(target, flags="ro,nosuid,nodev,noexec"), mountinfo(target, filesystem="tmpfs"),
                    mountinfo(target) + f"3 2 0:3 / {target}/sys rw - proc proc rw\n",
                    mountinfo(target) + mountinfo(target), "malformed", "x" * 262145]
        for text in variants:
            with self.subTest(text=text[:100]), self.assertRaises(PROBE.ProbeError):
                PROBE.validate_proc_mount(text, target)


class ChildTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.state = Path(self.temporary.name)

    def run_child(self, *, uid_map=b"0 1001 1\n1 100000 65536\n", namespaces=(303, 404), pid=1,
                  mount_failure=None, status=b"Name:\tpython3\nPid:\t1\n", unmount_failure=None,
                  bad_mount=False):
        value = PROBE.child_receipt()
        target = self.state / "proc"
        texts = iter((mountinfo(target, root="/sys" if bad_mount else "/").encode(),
                      b"1 0 0:1 / / rw - overlay overlay rw\n"))
        def read(path, *args):
            if str(path) == "/proc/self/uid_map":
                return uid_map
            if path == PROBE.MOUNTINFO:
                return next(texts)
            return status
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(PROBE.NETWORK, "guarded_state"))
            stack.enter_context(mock.patch.object(PROBE.os, "getuid", return_value=0))
            stack.enter_context(mock.patch.object(PROBE.os, "geteuid", return_value=0))
            stack.enter_context(mock.patch.object(PROBE.os, "getpid", return_value=pid))
            stack.enter_context(mock.patch.object(PROBE.NETWORK, "read_file", side_effect=read))
            stack.enter_context(mock.patch.object(PROBE, "namespace_id", side_effect=namespaces))
            mount = stack.enter_context(mock.patch.object(PROBE, "mount_proc", side_effect=mount_failure))
            unmount = stack.enter_context(mock.patch.object(PROBE, "unmount_proc", side_effect=unmount_failure))
            try:
                PROBE.child_probe(self.state, 101, 202, (1, 2), value)
            except PROBE.ProbeError as error:
                return value, mount, unmount, error
        return value, mount, unmount, None

    def test_success_verifies_pid_one_mount_and_unmount(self):
        value, mount, unmount, error = self.run_child()
        self.assertIsNone(error)
        PROBE.validate_child(value, 101, 202)
        mount.assert_called_once_with(self.state / "proc")
        unmount.assert_called_once_with(self.state / "proc")
        self.assertFalse((self.state / "proc").exists())

    def test_copyup_symlink_ancestor_uses_resolved_mountpoint(self):
        runtime = self.state / "runtime"
        backing = self.state / ".ro-backing"
        backing.mkdir()
        runtime.symlink_to(backing, target_is_directory=True)
        state = runtime / "oxibelt-network-test"
        state.mkdir(mode=0o700)
        self.state = state
        # The mocked mountinfo generator must reflect the canonical VFS path.
        original = mountinfo
        with mock.patch.dict(globals(), {"mountinfo": lambda target, **kw: original(target.resolve(), **kw)}):
            value, mount, unmount, error = self.run_child()
        self.assertIsNone(error)
        mount.assert_called_once_with(backing / state.name / "proc")
        unmount.assert_called_once_with(backing / state.name / "proc")
        PROBE.validate_child(value, 101, 202)

    def test_host_root_shared_namespace_and_non_pid_one_never_mount(self):
        for kwargs in ({"uid_map": b"0 0 4294967295\n"}, {"uid_map": b"malformed\n"},
                       {"namespaces": (101, 404)}, {"namespaces": (303, 202)}, {"pid": 2}):
            with self.subTest(kwargs=kwargs):
                value, mount, unmount, error = self.run_child(**kwargs)
                self.assertIsInstance(error, PROBE.ProbeError)
                mount.assert_not_called()
                unmount.assert_not_called()
                self.assertFalse(value["supported"])

    def test_denied_mount_is_failure_and_never_claims_unmount(self):
        value, mount, unmount, error = self.run_child(mount_failure=PROBE.ProbeError("private-proc-mount-denied"))
        self.assertEqual(str(error), "private-proc-mount-denied")
        mount.assert_called_once()
        unmount.assert_not_called()
        self.assertFalse(value["supported"] or value["unmounted"])
        self.assertFalse((self.state / "proc").exists())

    def test_readback_failure_still_unmounts_and_unmount_failure_is_not_waived(self):
        for kwargs in ({"status": b"Pid:\t42\n"}, {"bad_mount": True}):
            with self.subTest(kwargs=kwargs):
                value, _mount, unmount, error = self.run_child(**kwargs)
                self.assertIsInstance(error, PROBE.ProbeError)
                unmount.assert_called_once()
                self.assertTrue(value["unmounted"])
                self.assertFalse(value["supported"])
        value, _mount, unmount, error = self.run_child(unmount_failure=PROBE.ProbeError("private-proc-unmount-failed"))
        self.assertEqual(str(error), "private-proc-unmount-failed")
        self.assertFalse(value["supported"] or value["unmounted"])

    def test_mount_syscall_has_exact_safe_flags_and_reports_errno(self):
        library = mock.Mock()
        library.mount.return_value = 0
        target = self.state / "proc"
        with mock.patch.object(PROBE.ctypes, "CDLL", return_value=library):
            PROBE.mount_proc(target)
        self.assertEqual(library.mount.call_args.args, (b"proc", os.fsencode(target), b"proc", 14, None))
        library.mount.return_value = -1
        with mock.patch.object(PROBE.ctypes, "CDLL", return_value=library), \
             mock.patch.object(PROBE.ctypes, "get_errno", return_value=errno.EPERM), \
             contextlib.redirect_stderr(io.StringIO()) as log:
            with self.assertRaisesRegex(PROBE.ProbeError, "private-proc-mount-denied"):
                PROBE.mount_proc(target)
        self.assertEqual(json.loads(log.getvalue()), {"operation": "mount-proc", "errno": errno.EPERM})


class ParentTests(unittest.TestCase):
    def test_only_eacces_proves_helper_inaccessible(self):
        with mock.patch.object(PROBE.os, "open", side_effect=PermissionError(errno.EACCES, "denied")):
            PROBE.helper_inaccessible()
        for error in (FileNotFoundError(errno.ENOENT, "missing"), PermissionError(errno.EPERM, "policy")):
            with mock.patch.object(PROBE.os, "open", side_effect=error), self.assertRaises(PROBE.ProbeError):
                PROBE.helper_inaccessible()
        with mock.patch.object(PROBE.os, "open", return_value=123), mock.patch.object(PROBE.os, "close") as close:
            with self.assertRaisesRegex(PROBE.ProbeError, "accessible-to-runner"):
                PROBE.helper_inaccessible()
            close.assert_called_once_with(123)

    def parent(self, runtime, commands, *, changed=False):
        mounts = iter((b"unchanged mounts", b"changed mounts" if changed else b"unchanged mounts"))
        def read(path, *args):
            if path == PROBE.MOUNTINFO:
                return next(mounts)
            if path == PROBE.IDENTITY_FILE:
                return json.dumps(IDENTITY).encode()
            return b"bounded pinned binary or source"
        original = Path.lstat
        def lstat(path, *args, **kwargs):
            info = original(path, *args, **kwargs)
            return mock.Mock(st_mode=info.st_mode, st_uid=1001, st_dev=info.st_dev, st_ino=info.st_ino)
        value = receipt()
        value.update(supported=False, diagnostic="probe-not-completed", cleanup_confirmed=False)
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(PROBE, "RUNTIME", runtime))
            stack.enter_context(mock.patch.object(PROBE.NETWORK, "prerequisites", return_value=PROBE.NATIVE_FIELDS))
            stack.enter_context(mock.patch.object(PROBE.NETWORK, "guarded_state"))
            stack.enter_context(mock.patch.object(PROBE.NETWORK, "read_file", side_effect=read))
            stack.enter_context(mock.patch.object(PROBE, "namespace_id", side_effect=(101, 202)))
            stack.enter_context(mock.patch.object(PROBE, "helper_inaccessible"))
            stack.enter_context(mock.patch.object(PROBE.platform, "release", return_value="6.12.42-test"))
            stack.enter_context(mock.patch.dict(PROBE.os.environ, IDENTITY, clear=True))
            stack.enter_context(mock.patch.object(Path, "lstat", lstat))
            try:
                PROBE.parent_probe(value, commands)
            except PROBE.ProbeError as error:
                return value, error
        return value, None

    def test_parent_checks_exact_wrapper_command_and_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            runtime.chmod(0o700)
            commands = mock.Mock(cleanup_confirmed=True)
            commands.call.side_effect = [(0, "rootlesskit version 3.2.0\n"), (0, json.dumps(child()))]
            value, error = self.parent(runtime, commands)
            self.assertIsNone(error)
            PROBE.validate_receipt(value, IDENTITY)
            self.assertEqual(list(runtime.iterdir()), [])
            args = commands.call.call_args.args[0]
            self.assertEqual(args[2:2+len(PROBE.NETWORK.FLAGS)], PROBE.NETWORK.FLAGS)
            unshare = args[2+len(PROBE.NETWORK.FLAGS):]
            self.assertEqual(unshare[:5], ["unshare", "--mount", "--pid", "--fork", "--propagation=private"])
            self.assertNotIn("--user", args)

    def test_denied_child_mount_is_preserved_after_group_and_state_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            runtime.chmod(0o700)
            failed = PROBE.child_receipt()
            failed.update(diagnostic="private-proc-mount-denied", pidns=303, mntns=404,
                          pid_one=True, mapped_runner_root=True)
            commands = mock.Mock(cleanup_confirmed=True)
            commands.call.side_effect = [(0, "rootlesskit version 3.2.0\n"), (1, json.dumps(failed))]
            value, error = self.parent(runtime, commands)
            self.assertEqual(str(error), "private-proc-mount-denied")
            self.assertEqual(value["child"], failed)
            self.assertTrue(value["cleanup_confirmed"] and value["parent_mounts_unchanged"])
            self.assertEqual(list(runtime.iterdir()), [])

    def test_staged_identity_must_be_canonical_and_complete_before_commands(self):
        variants = [b"not-json", b"[]", json.dumps({"GITHUB_SHA": "a"*40}).encode(),
                    json.dumps({**IDENTITY, "SECRET": "do-not-record"}).encode()]
        for raw in variants:
            with self.subTest(raw=raw):
                commands = mock.Mock()
                def read(path, maximum=262144):
                    if path == PROBE.IDENTITY_FILE:
                        self.assertEqual(maximum, 16384)
                        return raw
                    return b"pinned source or binary"
                with mock.patch.object(PROBE.NETWORK, "prerequisites", return_value=PROBE.NATIVE_FIELDS), \
                     mock.patch.object(PROBE.NETWORK, "read_file", side_effect=read):
                    with self.assertRaisesRegex(PROBE.ProbeError, "invalid-workflow-identity"):
                        PROBE.parent_probe(receipt(), commands)
                commands.call.assert_not_called()

    def test_timeout_or_unconfirmed_cleanup_preserves_failure_and_state(self):
        for confirmed in (True, False):
            with self.subTest(confirmed=confirmed), tempfile.TemporaryDirectory() as directory:
                runtime = Path(directory)
                runtime.chmod(0o700)
                commands = mock.Mock(cleanup_confirmed=confirmed)
                commands.call.side_effect = [(0, "rootlesskit version 3.2.0\n"), PROBE.ProbeError("command-timeout")]
                value, error = self.parent(runtime, commands)
                self.assertEqual(str(error), "command-timeout")
                self.assertEqual(value["cleanup_confirmed"], confirmed)
                self.assertEqual(len(list(runtime.iterdir())), 0 if confirmed else 1)

    def test_parent_mount_change_is_failure_after_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            runtime.chmod(0o700)
            commands = mock.Mock(cleanup_confirmed=True)
            commands.call.side_effect = [(0, "rootlesskit version 3.2.0\n"), (0, json.dumps(child()))]
            value, error = self.parent(runtime, commands, changed=True)
            self.assertEqual(str(error), "sandbox-mounts-changed")
            self.assertFalse(value["parent_mounts_unchanged"])
            self.assertTrue(value["cleanup_confirmed"])
            self.assertEqual(list(runtime.iterdir()), [])

    def test_failure_receipt_and_log_are_new_bounded_private_files(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "proc-mount.json"
            commands = mock.Mock(log=bytearray(b"bounded diagnostic"))
            with mock.patch.object(PROBE, "Commands", return_value=commands), \
                 mock.patch.object(PROBE, "parent_probe", side_effect=PROBE.ProbeError("command-timeout")):
                self.assertEqual(PROBE.main(["--output", str(output)]), 1)
                value = json.loads(output.read_text())
                self.assertEqual(value["diagnostic"], "command-timeout")
                self.assertFalse(value["supported"])
                log = output.parent / "proc-mount.log"
                self.assertEqual(log.read_bytes(), b"bounded diagnostic")
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(log.stat().st_mode), 0o600)
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(PROBE.main(["--output", str(output)]), 2)

    def test_reused_runner_kills_and_reaps_timeout_tree_and_bounds_output(self):
        variants = [("command-timeout", "import os,time; print(os.fork(),flush=True); time.sleep(20)", .15),
                    ("command-output-too-large", "import os,time; os.fork(); print('x'*70000,flush=True); time.sleep(20)", 3)]
        for diagnostic, script, timeout in variants:
            with self.subTest(diagnostic=diagnostic):
                commands = PROBE.Commands()
                commands.deadline = PROBE.NETWORK.time.monotonic() + timeout
                with mock.patch.object(PROBE.NETWORK, "group_members", wraps=PROBE.NETWORK.group_members) as members:
                    with self.assertRaisesRegex(PROBE.ProbeError, diagnostic):
                        commands.call([sys.executable, "-c", script])
                self.assertTrue(commands.cleanup_confirmed)
                self.assertLessEqual(len(commands.log), 65536)
                self.assertEqual(PROBE.NETWORK.group_members(members.call_args.args[0]), [])


if __name__ == "__main__":
    unittest.main()
