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


def namespace_mount(root="net:[4026532455]", *, filesystem="nsfs",
                    point="/run/user/1001/oxibelt-network-test/netns", options="rw"):
    return f"8 1 0:8 {root} {point} {options} - {filesystem} nsfs rw\n"


def proc_helper():
    return ("70 1 0:70 / /opt/oxibelt-preflight/private-proc/proc "
            "rw,nosuid,nodev,noexec - proc proc rw\n")


def sys_helper(super_options="rw", options="ro,nosuid,nodev,noexec"):
    return ("71 1 0:71 / /opt/oxibelt-preflight/private-sys/sys "
            f"{options} - sysfs sysfs {super_options}\n")


def receipt():
    return {"schema_version": 1, "supported": True, "diagnostic": "passed",
            "sandbox_netns": 101, "detached_netns": 202,
            "ipv4": {"before": 0, "readback": 1, "restored": True, "status": "passed"},
            "ipv6": {"status": "unavailable"},
            "native": {"architecture": "riscv64", "executing_elf_machine": 243, "uid": 1001,
                       "rootlesskit_version": "3.2.0", "engine_source_version": "29.8.0"},
            "parent_before": 0, "parent_after": 0, "cleanup_confirmed": True}


class MountTests(unittest.TestCase):
    def test_nsfs_network_inode_roots_preserve_metadata_and_protected_mounts(self):
        helper = ("7 1 0:7 / /opt/oxibelt-preflight/private-proc/proc "
                  "rw,nosuid,nodev,noexec - proc proc rw\n")
        for root in ("net:[1]", "net:[4026532455]", "net:[18446744073709551615]"):
            text = mounts() + helper + namespace_mount(root)
            with self.subTest(root=root):
                row = PROBE.mount_metadata(text)[-1]
                self.assertEqual(row["root"], root)
                self.assertEqual(row["filesystem"], "nsfs")
                self.assertEqual(PROBE.mount_rows(text)[-1], (row["point"], {"rw"}, "nsfs"))
                self.assertEqual(PROBE.validate_proc_helper(text, required=True)["root"], "/")
                self.assertTrue(PROBE.validate_mounts(text, require_helper=True)["network_sysctl_writable"])
        for root in ("/", "/ordinary/root", "/ordinary\\040root"):
            with self.subTest(root=root):
                self.assertEqual(PROBE.mount_metadata(namespace_mount(root, filesystem="tmpfs"))[0]["root"],
                                 root.replace("\\040", " "))

    def test_nsfs_inode_root_grammar_and_filesystem_fail_closed(self):
        roots = ("net:[]", "net:[0]", "net:[00]", "net:[01]", "net:[-1]", "net:[+1]",
                 "net:[18446744073709551616]", "net:[100000000000000000000]",
                 "net:[١]", "net:[１]", "net:[1.0]", "net:[ 1]", "net:[1 ]",
                 "net:[1]/", "net:[1]suffix", "prefixnet:[1]", "net:[1", "net:1]",
                 "NET:[1]", "mnt:[1]", "net:[1]\\040", "relative", "/root/../other")
        variants = [namespace_mount(root) for root in roots]
        variants += [namespace_mount(filesystem=filesystem) for filesystem in ("proc", "tmpfs", "NSFS")]
        variants += [namespace_mount(point=point) for point in ("relative", "/run/../netns")]
        variants += [namespace_mount(options=options) for options in ("rw,ro", "nosuid")]
        variants += ["8 1 0:8 net:[1] /run/netns rw - " + details + "\n"
                     for details in ("", "nsfs", "nsfs nsfs")]
        variants += ["8 1 0:8 net:[1] /run/netns - nsfs nsfs rw\n"]
        for text in variants:
            with self.subTest(text=text), self.assertRaisesRegex(PROBE.ProbeError, "^invalid-mountinfo$"):
                PROBE.mount_metadata(text)

    def test_accepted_nsfs_rows_cannot_hide_invalid_protected_mounts(self):
        hidden_kernel = ("9 5 0:4 /sys/kernel /proc/sys/kernel rw,nosuid,nodev,noexec - proc proc rw\n"
                         "10 5 0:4 /sys/kernel /proc/sys/kernel ro,nosuid,nodev,noexec - proc proc rw\n")
        variants = [mounts().replace("/proc/sys ro,", "/proc/sys rw,"),
                    mounts().replace("/sys ro,", "/sys rw,"),
                    mounts().replace("/sys/fs/cgroup rw,", "/sys/fs/cgroup ro,"),
                    mounts("rw"), mounts(None), mounts() + hidden_kernel,
                    mounts() + "9 1 0:4 / /tmp/proc-alias rw,nosuid,nodev,noexec - proc proc rw\n",
                    mounts() + namespace_mount(point="/sys/kernel"),
                    mounts() + namespace_mount(point="/sys/fs/cgroup"),
                    mounts() + namespace_mount(point="/proc/sys/net/ipv4"),
                    mounts() + namespace_mount(point="/proc/sys/kernel", options="ro")]
        for text in variants:
            with self.subTest(text=text), self.assertRaises(PROBE.ProbeError):
                PROBE.validate_mounts(namespace_mount() + text)

    def test_full_proc_helper_is_exact_and_does_not_relax_original_mounts(self):
        helper = ("7 1 0:7 / /opt/oxibelt-preflight/private-proc/proc "
                  "rw,nosuid,nodev,noexec - proc proc rw\n")
        self.assertEqual(PROBE.validate_proc_helper(mounts()), None)
        self.assertEqual(PROBE.validate_proc_helper(mounts() + helper, required=True)["root"], "/")
        PROBE.validate_mounts(mounts() + helper, require_helper=True)
        variants = [mounts(), mounts() + helper + helper,
                    mounts() + helper.replace("7 1 0:7 / ", "7 1 0:7 /sys "),
                    mounts() + helper.replace("rw,nosuid,nodev,noexec", "rw,nosuid,nodev"),
                    mounts() + helper.replace("rw,nosuid,nodev,noexec", "ro,nosuid,nodev,noexec"),
                    mounts() + helper.replace(" - proc proc rw", " - tmpfs tmpfs rw"),
                    mounts() + helper.replace(" - proc proc rw", " - proc proc ro"),
                    mounts() + helper.replace(" - proc proc rw", " - proc proc rw,subset=pid"),
                    mounts() + helper.replace(" - proc proc rw", " - proc proc rw,hidepid=2"),
                    mounts() + helper.replace(" - proc", " shared:7 - proc"),
                    mounts() + helper + "8 7 0:8 / /opt/oxibelt-preflight/private-proc/proc/sys ro - tmpfs tmpfs ro\n",
                    mounts() + helper + "8 1 0:8 / /tmp/alias ro,nosuid,nodev,noexec - proc proc ro\n",
                    mounts() + helper + "8 4 0:8 / /proc/extra rw,nosuid,nodev,noexec - proc proc rw\n",
                    mounts().replace("/proc/sys ro,", "/proc/sys rw,") + helper]
        for text in variants + [namespace_mount() + text for text in variants]:
            with self.subTest(text=text), self.assertRaises(PROBE.ProbeError):
                PROBE.validate_mounts(text, require_helper=True)

    def test_proc_helper_directory_rejects_modes_owners_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "opt" / "oxibelt-preflight"
            helper = base / "private-proc" / "proc"
            helper.mkdir(parents=True)
            base.chmod(0o755)
            base.parent.chmod(0o755)
            helper.chmod(0o700)
            helper.parent.chmod(0o700)
            real_lstat = Path.lstat
            def root_stat(path):
                info = real_lstat(path)
                return mock.Mock(st_mode=info.st_mode, st_uid=0, st_gid=0)
            with mock.patch.object(PROBE, "PROC_PARENT", helper.parent), \
                 mock.patch.object(PROBE, "PROC_HELPER", helper), \
                 mock.patch.object(PROBE.Path, "lstat", root_stat):
                PROBE.validate_proc_directories()
                for mode in (0o755, 0o770, 0o777):
                    helper.parent.chmod(mode)
                    with self.subTest(mode=mode), self.assertRaises(PROBE.ProbeError):
                        PROBE.validate_proc_directories()
                helper.parent.chmod(0o700)
                helper.rmdir()
                helper.symlink_to(base)
                with self.assertRaises(PROBE.ProbeError):
                    PROBE.validate_proc_directories()
            with mock.patch.object(PROBE.Path, "lstat", return_value=mock.Mock(st_mode=stat.S_IFDIR | 0o700, st_uid=1001, st_gid=0)):
                with self.assertRaises(PROBE.ProbeError):
                    PROBE.validate_proc_directories()

    def test_proc_mount_creation_rejects_host_and_non_pid_one_before_mutation(self):
        for change in ({"uid": 1001}, {"euid": 1001}, {"pid": 42}, {"machine": "x86_64"},
                       {"container": False}, {"cmdline": b"unexpected\0"}, {"namespace": 2}):
            with self.subTest(change=change), \
                 mock.patch.object(PROBE.os, "getuid", return_value=change.get("uid", 0)), \
                 mock.patch.object(PROBE.os, "geteuid", return_value=change.get("euid", 0)), \
                 mock.patch.object(PROBE.os, "getppid", return_value=change.get("pid", 1)), \
                 mock.patch.object(PROBE.platform, "machine", return_value=change.get("machine", "riscv64")), \
                 mock.patch.object(PROBE.Path, "is_file", return_value=change.get("container", True)), \
                 mock.patch.object(PROBE, "read_file", return_value=change.get("cmdline", b"/bin/bash\0/opt/oxibelt-preflight/riscv-native-sandbox-bootstrap.sh\0")), \
                 mock.patch.object(PROBE.Path, "stat", side_effect=[mock.Mock(st_ino=1), mock.Mock(st_ino=change.get("namespace", 1))]), \
                 mock.patch.object(PROBE.Path, "mkdir") as mkdir, \
                 mock.patch.object(PROBE, "Commands") as commands:
                with self.assertRaisesRegex(PROBE.ProbeError, "requires-sandbox-pid-one"):
                    PROBE.prepare_proc_mount()
                commands.assert_not_called()
                mkdir.assert_not_called()

    def prepare(self, commands, output, after=None):
        helper = ("7 1 0:7 / /opt/oxibelt-preflight/private-proc/proc "
                  "rw,nosuid,nodev,noexec - proc proc rw\n")
        reads = iter((mounts(), mounts() + helper if after is None else after))
        def read(path, *args):
            if str(path) == "/proc/1/cmdline":
                return b"/bin/bash\0/opt/oxibelt-preflight/riscv-native-sandbox-bootstrap.sh\0"
            return next(reads).encode()
        with mock.patch.object(PROBE.os, "getuid", return_value=0), \
             mock.patch.object(PROBE.os, "geteuid", return_value=0), \
             mock.patch.object(PROBE.os, "getppid", return_value=1), \
             mock.patch.object(PROBE.platform, "machine", return_value="riscv64"), \
             mock.patch.object(PROBE.Path, "is_file", return_value=True), \
             mock.patch.object(PROBE.Path, "stat", return_value=mock.Mock(st_ino=1)), \
             mock.patch.object(PROBE.Path, "lstat", return_value=mock.Mock(st_mode=stat.S_IFDIR | 0o700, st_uid=0, st_gid=0)), \
             mock.patch.object(PROBE.Path, "resolve", lambda path, **kw: path), \
             mock.patch.object(PROBE.Path, "mkdir"), \
             mock.patch.object(PROBE, "read_file", side_effect=read), \
             mock.patch.object(PROBE, "Commands", return_value=commands) as runner, \
             mock.patch("builtins.print", output):
            try:
                PROBE.prepare_proc_mount()
            finally:
                runner.assert_called_once_with(timeout=10)
                commands.call.assert_called_once_with(["/usr/bin/mount", "-t", "proc", "-o",
                    "rw,nosuid,nodev,noexec", "proc", str(PROBE.PROC_HELPER)])

    def test_proc_mount_failure_retains_denial_and_exit_status(self):
        commands = mock.Mock(log=bytearray(b"mount: permission denied\n"))
        commands.call.return_value = (32, "")
        output = mock.Mock()
        with self.assertRaisesRegex(PROBE.ProbeError, "^proc-helper-mount-failed-exit-32$"):
            self.prepare(commands, output)
        output.assert_called_once_with("Proc helper mount output:\nmount: permission denied\n", file=PROBE.sys.stderr)

    def test_proc_mount_runner_failures_preserve_specific_bounded_diagnostics(self):
        for diagnostic in ("command-timeout", "command-output-too-large", "process-group-cleanup-failed"):
            commands = mock.Mock(log=bytearray(b"x" * PROBE.MAX_OUTPUT))
            commands.call.side_effect = PROBE.ProbeError(diagnostic)
            output = mock.Mock()
            with self.subTest(diagnostic=diagnostic), \
                 self.assertRaisesRegex(PROBE.ProbeError, "^proc-helper-mount-" + diagnostic + "$"):
                self.prepare(commands, output)
            output.assert_called_once_with("Proc helper mount output:\n" + "x" * PROBE.MAX_OUTPUT, file=PROBE.sys.stderr)

    def test_proc_mount_success_requires_post_mount_validation(self):
        commands = mock.Mock(log=bytearray(b"successful mount output\n"))
        commands.call.return_value = (0, "")
        output = mock.Mock()
        self.prepare(commands, output)
        self.assertEqual(json.loads(output.call_args.args[0])["filesystem"], "proc")
        commands.call.reset_mock()
        with self.assertRaisesRegex(PROBE.ProbeError, "proc-helper-missing-or-duplicate"):
            self.prepare(commands, mock.Mock(), after=mounts())

    def protect(self, before, after=None, failure=None, wrong_namespace=False, no_remount=False,
                include_helpers=True, directory_failure=None):
        after = before if after is None else after
        if include_helpers:
            before += proc_helper() + sys_helper()
            after += proc_helper() + sys_helper()
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
             mock.patch.object(PROBE, "validate_proc_directories"), \
             mock.patch.object(PROBE, "validate_sys_directories", side_effect=directory_failure), \
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

    def test_systemd_requires_both_helpers_and_safe_directories_before_remount(self):
        fuse = "7 2 0:7 / /sys/fs/fuse/connections rw,nosuid,nodev,noexec - fusectl fusectl rw\n"
        for text in (mounts() + fuse, mounts() + fuse + proc_helper(), mounts() + fuse + sys_helper()):
            with self.subTest(text=text), self.assertRaises(PROBE.ProbeError):
                self.protect(text, include_helpers=False, no_remount=True)
        with self.assertRaisesRegex(PROBE.ProbeError, "unsafe-sys-helper-directory"):
            self.protect(mounts() + fuse, directory_failure=PROBE.ProbeError("unsafe-sys-helper-directory"),
                         no_remount=True)

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


class SysHelperTests(unittest.TestCase):
    def test_full_readonly_sys_helper_accepts_vfs_ro_with_super_rw_or_ro(self):
        self.assertIsNone(PROBE.validate_sys_helper(mounts()))
        for super_options in ("rw", "ro", "rw,seclabel", "ro,seclabel"):
            with self.subTest(super_options=super_options):
                text = mounts() + proc_helper() + sys_helper(super_options)
                self.assertEqual(PROBE.validate_sys_helper(text, required=True)["root"], "/")
                self.assertEqual(PROBE.validate_mounts(text, require_helper=True, require_sys_helper=True),
                                 PROBE.validate_mounts(mounts()))

    def test_realistic_kernel_atime_flags_preserve_readonly_sys_helper(self):
        for atime in ("relatime", "noatime", "strictatime"):
            options = "ro,nosuid,nodev,noexec," + atime
            text = mounts() + proc_helper() + sys_helper("rw", options)
            with self.subTest(atime=atime):
                self.assertEqual(PROBE.validate_sys_helper(text, required=True)["options"],
                                 sorted(options.split(",")))
                PROBE.validate_mounts(text, require_helper=True, require_sys_helper=True)

    def test_optional_present_helper_is_always_checked_and_bad_aliases_rejected(self):
        helper = sys_helper()
        variants = [helper + helper,
                    helper.replace("71 1 0:71 / ", "71 1 0:71 /kernel "),
                    helper.replace("ro,nosuid,nodev,noexec", "rw,nosuid,nodev,noexec"),
                    helper.replace("ro,nosuid,nodev,noexec", "ro,nosuid,nodev"),
                    helper.replace(" - sysfs sysfs rw", " - tmpfs tmpfs ro"),
                    helper.replace(" - sysfs sysfs rw", " - sysfs sysfs nosuid"),
                    helper.replace(" - sysfs sysfs rw", " - sysfs sysfs rw,ro"),
                    helper.replace(" - sysfs", " shared:7 - sysfs"),
                    helper.replace(" - sysfs", " master:7 - sysfs"),
                    helper.replace(" - sysfs", " master:7 propagate_from:8 - sysfs"),
                    helper + "72 71 0:72 / /opt/oxibelt-preflight/private-sys/sys/kernel ro - tmpfs tmpfs ro\n",
                    helper + "72 1 0:72 / /opt/oxibelt-preflight/private-sys ro - tmpfs tmpfs ro\n",
                    helper + "72 1 0:72 / /tmp/sys-alias ro - sysfs sysfs rw\n",
                    helper + "72 1 0:72 /kernel /tmp/sys-alias ro - sysfs sysfs rw\n",
                    helper + "72 2 0:72 /kernel /sys/kernel rw - sysfs sysfs rw\n",
                    helper + "72 2 0:72 / /sys/fs/cgroup/sys-alias rw - sysfs sysfs rw\n",
                    helper + "72 1 0:72 / /tmp/sys-alias rw - sysfs sysfs rw\n",
                    helper.replace("/private-sys/sys ", "/private-sys//sys ")]
        for extra in variants:
            with self.subTest(extra=extra), self.assertRaises(PROBE.ProbeError):
                PROBE.validate_mounts(mounts() + extra)
        with self.assertRaisesRegex(PROBE.ProbeError, "sys-helper-missing-or-duplicate"):
            PROBE.validate_mounts(mounts(), require_sys_helper=True)

    def test_sys_helper_preserves_original_mask_and_cgroup_boundaries(self):
        for text in (mounts().replace("/sys ro,", "/sys rw,"),
                     mounts().replace("/sys/fs/cgroup rw,", "/sys/fs/cgroup ro,"),
                     mounts() + "72 2 0:72 / /sys/kernel/debug rw - tmpfs tmpfs rw\n",
                     mounts() + "72 3 0:72 / /sys/fs/cgroup/unsafe rw - tmpfs tmpfs rw\n"):
            with self.subTest(text=text), self.assertRaises(PROBE.ProbeError):
                PROBE.validate_mounts(text + sys_helper(), require_sys_helper=True)
        masked = mounts() + "72 2 0:72 / /sys/firmware ro - tmpfs tmpfs ro\n"
        PROBE.validate_mounts(masked + sys_helper(), require_sys_helper=True)

    def test_sys_directories_reject_unsafe_modes_owners_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "opt" / "oxibelt-preflight"
            helper = base / "private-sys" / "sys"
            helper.mkdir(parents=True)
            base.chmod(0o755)
            base.parent.chmod(0o755)
            helper.chmod(0o700)
            helper.parent.chmod(0o700)
            real_lstat = Path.lstat
            def root_stat(path):
                info = real_lstat(path)
                return mock.Mock(st_mode=info.st_mode, st_uid=0, st_gid=0)
            with mock.patch.object(PROBE, "SYS_PARENT", helper.parent), \
                 mock.patch.object(PROBE, "SYS_HELPER", helper), \
                 mock.patch.object(PROBE.Path, "lstat", root_stat):
                PROBE.validate_sys_directories()
                for path, mode in ((helper.parent, 0o755), (helper.parent, 0o770),
                                   (helper, 0o777), (base, 0o775), (base.parent, 0o777)):
                    original = path.stat().st_mode & 0o777
                    path.chmod(mode)
                    with self.subTest(path=path, mode=mode), self.assertRaises(PROBE.ProbeError):
                        PROBE.validate_sys_directories()
                    path.chmod(original)
                helper.rmdir()
                helper.symlink_to(base)
                with self.assertRaises(PROBE.ProbeError):
                    PROBE.validate_sys_directories()
            for uid, gid in ((1001, 0), (0, 1001)):
                with mock.patch.object(PROBE.Path, "lstat", return_value=mock.Mock(
                        st_mode=stat.S_IFDIR | 0o700, st_uid=uid, st_gid=gid)):
                    with self.assertRaises(PROBE.ProbeError):
                        PROBE.validate_sys_directories()

    def prepare(self, *, before=None, after=None, change=None, code=0, mkdir_failure=None):
        change = change or {}
        before = mounts() + proc_helper() if before is None else before
        after = before + sys_helper() if after is None else after
        reads = iter((before, after))
        def read(path, *args):
            if str(path) == "/proc/1/cmdline":
                return change.get("cmdline", b"/bin/bash\0/opt/oxibelt-preflight/riscv-native-sandbox-bootstrap.sh\0")
            return next(reads).encode()
        commands = mock.Mock(log=bytearray(b"mount: permission denied\n" if code else b""))
        commands.call.return_value = (code, "")
        with mock.patch.object(PROBE.os, "getuid", return_value=change.get("uid", 0)), \
             mock.patch.object(PROBE.os, "geteuid", return_value=change.get("euid", 0)), \
             mock.patch.object(PROBE.os, "getppid", return_value=change.get("pid", 1)), \
             mock.patch.object(PROBE.platform, "machine", return_value=change.get("machine", "riscv64")), \
             mock.patch.object(PROBE.Path, "is_file", return_value=change.get("container", True)), \
             mock.patch.object(PROBE.Path, "stat", side_effect=[mock.Mock(st_ino=1), mock.Mock(st_ino=change.get("namespace", 1))]), \
             mock.patch.object(PROBE.Path, "lstat", return_value=mock.Mock(st_mode=stat.S_IFDIR | 0o700, st_uid=change.get("owner", 0), st_gid=0)), \
             mock.patch.object(PROBE.Path, "resolve", lambda path, **kw: path), \
             mock.patch.object(PROBE.Path, "mkdir", side_effect=mkdir_failure) as mkdir, \
             mock.patch.object(PROBE, "read_file", side_effect=read), \
             mock.patch.object(PROBE, "Commands", return_value=commands) as runner, \
             mock.patch("builtins.print") as output:
            try:
                PROBE.prepare_sys_mount()
            finally:
                self.mount_calls = commands.call.call_args_list
                self.runner_calls = runner.call_args_list
                self.mkdir_calls = mkdir.call_args_list
                self.output = output.call_args_list
        return output

    def test_sys_creation_rejects_host_non_pid_one_and_unsafe_owner_before_mutation(self):
        for change in ({"uid": 1001}, {"euid": 1001}, {"pid": 42}, {"machine": "x86_64"},
                       {"container": False}, {"cmdline": b"unexpected\0"}, {"namespace": 2}, {"owner": 1001}):
            with self.subTest(change=change), self.assertRaises(PROBE.ProbeError):
                self.prepare(change=change)
            self.assertEqual(self.mount_calls, [])
            self.assertEqual(self.mkdir_calls, [])

    def test_sys_creation_requires_private_root_and_new_exclusive_directories(self):
        for before in (mounts() + proc_helper() + sys_helper(),
                       mounts().replace("/ rw -", "/ rw shared:1 -") + proc_helper(),
                       mounts().replace("/ rw -", "/ rw master:1 -") + proc_helper(),
                       mounts()):
            with self.subTest(before=before), self.assertRaises(PROBE.ProbeError):
                self.prepare(before=before)
            self.assertEqual(self.mount_calls, [])
            self.assertEqual(self.mkdir_calls, [])
        with self.assertRaises(FileExistsError):
            self.prepare(mkdir_failure=FileExistsError())
        self.assertEqual(self.mount_calls, [])

    def test_sys_creation_uses_fresh_mount_and_retains_denial_diagnostic(self):
        output = self.prepare(after=mounts() + proc_helper() +
                              sys_helper("rw", "ro,nosuid,nodev,noexec,relatime"))
        self.assertEqual(self.mount_calls, [mock.call(["/usr/bin/mount", "-t", "sysfs", "-o",
                         "ro,nosuid,nodev,noexec", "sysfs", str(PROBE.SYS_HELPER)])])
        self.assertEqual(self.runner_calls, [mock.call(timeout=10)])
        self.assertEqual(self.mkdir_calls, [mock.call(mode=0o700), mock.call(mode=0o700)])
        self.assertEqual(json.loads(output.call_args.args[0])["filesystem"], "sysfs")
        self.assertIn("relatime", json.loads(output.call_args.args[0])["options"])
        with self.assertRaisesRegex(PROBE.ProbeError, "^sys-helper-mount-failed-exit-32$"):
            self.prepare(code=32)
        self.assertEqual(self.output[0].args[0], "Sys helper mount output:\nmount: permission denied\n")

    def test_sys_creation_checks_original_sys_rows_and_post_mount_helper(self):
        masked = mounts() + proc_helper() + "72 2 0:72 / /sys/firmware ro - tmpfs tmpfs ro\n"
        self.prepare(before=masked)
        for after in (masked.replace("0:72", "0:73") + sys_helper(),
                      masked.replace("/sys/firmware ro", "/sys/firmware rw") + sys_helper(),
                      masked.replace("cgroup2 cgroup rw", "cgroup2 cgroup rw,nsdelegate") + sys_helper()):
            with self.subTest(after=after), self.assertRaisesRegex(PROBE.ProbeError, "original-sys-mounts-changed"):
                self.prepare(before=masked, after=after)
        with self.assertRaisesRegex(PROBE.ProbeError, "sys-helper-missing-or-duplicate"):
            self.prepare(after=mounts() + proc_helper())

    def test_sys_prepare_cli_is_exclusive_and_check_can_require_helper(self):
        with mock.patch.object(PROBE, "prepare_sys_mount") as prepare:
            self.assertEqual(PROBE.main(["--prepare-sys-mount"]), 0)
            prepare.assert_called_once_with()
        for arguments in (["--prepare-sys-mount", "--prepare-proc-mount"],
                          ["--prepare-sys-mount", "--check-mounts"],
                          ["--prepare-sys-mount", "--child", "/tmp/state"], ["--require-sys-helper"]):
            with self.subTest(arguments=arguments), mock.patch("sys.stderr"), self.assertRaises(SystemExit) as error:
                PROBE.main(arguments)
            self.assertEqual(error.exception.code, 2)
        with mock.patch.object(PROBE, "read_file", return_value=mounts().encode()), mock.patch("sys.stderr"):
            self.assertEqual(PROBE.main(["--check-mounts", "--require-sys-helper"]), 1)


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
    def test_nonzero_command_retains_stderr_and_execution_identity(self):
        commands = PROBE.Commands(timeout=10)
        script = ("import os,sys; print(f'uid={os.getuid()},euid={os.geteuid()}'); "
                  "print('mount: permission denied',file=sys.stderr); sys.exit(32)")
        code, output = commands.call([sys.executable, "-c", script])
        self.assertEqual(code, 32)
        self.assertEqual(output, f"uid={os.getuid()},euid={os.geteuid()}\n")
        self.assertIn(b"mount: permission denied\n", commands.log)
        self.assertIn(output.encode(), commands.log)
        self.assertLessEqual(len(commands.log), PROBE.MAX_OUTPUT)
        self.assertTrue(commands.cleanup_confirmed)

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
            commands = PROBE.Commands(timeout=bound)
            with mock.patch.object(PROBE, "group_members", wraps=PROBE.group_members) as members:
                with self.assertRaisesRegex(PROBE.ProbeError, diagnostic):
                    commands.call([sys.executable, "-c", script])
            self.assertTrue(commands.cleanup_confirmed)
            self.assertLessEqual(len(commands.log), PROBE.MAX_OUTPUT)
            group = members.call_args.args[0]
            self.assertEqual(PROBE.group_members(group), [])

    def test_output_limit_combines_stdout_and_stderr(self):
        commands = PROBE.Commands(timeout=3)
        script = "import os,time; os.write(2,b'e'*40000); os.write(1,b'o'*30000); time.sleep(20)"
        with self.assertRaisesRegex(PROBE.ProbeError, "command-output-too-large"):
            commands.call([sys.executable, "-c", script])
        self.assertEqual(len(commands.log), PROBE.MAX_OUTPUT)
        self.assertIn(b"e", commands.log)
        self.assertIn(b"o", commands.log)
        self.assertTrue(commands.cleanup_confirmed)

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
