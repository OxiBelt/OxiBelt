#!/usr/bin/env python3
"""Bounded native RootlessKit proc mount qualification before source compilation."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
import platform
import re
import shutil
import stat
import sys
import tempfile
from pathlib import Path


def sibling(name: str):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), Path(__file__).with_name(name + ".py"))
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


NETWORK = sibling("check-riscv-network-sysctl")
RUNNER = sibling("check-riscv-native-runner")
ProbeError = NETWORK.ProbeError
Commands = NETWORK.Commands
RUNTIME = NETWORK.RUNTIME
HELPER = Path("/opt/oxibelt-preflight/private-proc/proc")
IDENTITY_FILE = Path("/opt/oxibelt-preflight/workflow-identity.json")
MOUNTINFO = Path("/proc/self/mountinfo")
MS_PROC_FLAGS = 2 | 4 | 8  # MS_NOSUID | MS_NODEV | MS_NOEXEC
NATIVE_FIELDS = {"architecture": "riscv64", "executing_elf_machine": 243, "uid": 1001,
                 "rootlesskit_version": "3.2.0", "engine_source_version": "29.8.0"}
HASH_FIELDS = {"rootlesskit_sha256", "probe_sha256", "lock_sha256"}
CHILD_FIELDS = {"schema_version", "supported", "diagnostic", "pidns", "mntns", "pid_one",
                "mapped_runner_root", "proc_self_pid_one", "proc_root_and_flags", "unmounted"}


def namespace_id(kind: str) -> int:
    try:
        return Path("/proc/self/ns" + "/" + kind).stat().st_ino
    except OSError as error:
        raise ProbeError("namespace-unavailable") from error


def helper_inaccessible() -> None:
    # A root-owned 0700 ancestor is the protection. Do not stat the protected
    # proc tree as uid 1001; prove that actual traversal returns EACCES.
    try:
        fd = os.open(HELPER, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except PermissionError as error:
        if error.errno == 13:
            return
        raise ProbeError("helper-traversal-unexpected-error") from error
    except OSError as error:
        raise ProbeError("helper-traversal-unexpected-error") from error
    else:
        os.close(fd)
        raise ProbeError("helper-is-accessible-to-runner")


def validate_proc_mount(text: str, target: Path) -> None:
    rows = NETWORK.mount_rows(text)
    matching = [row for row in rows if row[0] == str(target)]
    if (len(matching) != 1 or matching[0][2] != "proc"
        or not {"rw", "nosuid", "nodev", "noexec"} <= matching[0][1]
        or any(point.startswith(str(target) + "/") for point, _options, _fs in rows)):
        raise ProbeError("private-proc-mount-mismatch")
    # mount_rows intentionally omits roots, which matter for a full proc mount.
    if not any(line.split(" - ", 1)[0].split()[3:5] == ["/", str(target)]
               for line in text.splitlines()):
        raise ProbeError("private-proc-root-mismatch")


def mount_proc(target: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_void_p]
    libc.mount.restype = ctypes.c_int
    if libc.mount(b"proc", os.fsencode(target), b"proc", MS_PROC_FLAGS, None) != 0:
        number = ctypes.get_errno()
        print(json.dumps({"operation": "mount-proc", "errno": number}), file=sys.stderr)
        raise ProbeError("private-proc-mount-denied")


def unmount_proc(target: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
    libc.umount2.restype = ctypes.c_int
    if libc.umount2(os.fsencode(target), 0) != 0:
        print(json.dumps({"operation": "unmount-proc", "errno": ctypes.get_errno()}), file=sys.stderr)
        raise ProbeError("private-proc-unmount-failed")


def child_receipt() -> dict:
    return {"schema_version": 1, "supported": False, "diagnostic": "probe-not-completed",
            "pidns": None, "mntns": None, "pid_one": False, "mapped_runner_root": False,
            "proc_self_pid_one": False, "proc_root_and_flags": False, "unmounted": False}


def child_probe(state: Path, parent_pidns: int, parent_mntns: int,
                identity: tuple[int, int], receipt: dict) -> None:
    NETWORK.guarded_state(state, child=True, identity=identity)
    if os.getuid() != 0 or os.geteuid() != 0:
        raise ProbeError("requires-rootless-child-root")
    try:
        mappings = [tuple(map(int, row.split())) for row in
                    NETWORK.read_file(Path("/proc/self/uid_map")).decode().splitlines()]
    except (ValueError, UnicodeDecodeError) as error:
        raise ProbeError("invalid-child-uid-map") from error
    if not mappings or mappings[0] != (0, 1001, 1):
        raise ProbeError("child-is-not-mapped-runner-root")
    receipt["mapped_runner_root"] = True
    receipt["pidns"], receipt["mntns"] = namespace_id("pid"), namespace_id("mnt")
    if receipt["pidns"] == parent_pidns or receipt["mntns"] == parent_mntns:
        raise ProbeError("child-namespace-is-not-private")
    if os.getpid() != 1:
        raise ProbeError("child-is-not-pid-one")
    receipt["pid_one"] = True
    target = state / "proc"
    target.mkdir(mode=0o700)  # Exclusive target inside the guarded state.
    # RootlessKit copies /run up through .ro backing symlinks. Mountinfo names
    # the resolved target; the guarded state identity authenticates that tree.
    target = target.resolve(strict=True)
    mounted = False
    try:
        mount_proc(target)
        mounted = True
        validate_proc_mount(NETWORK.read_file(MOUNTINFO).decode(), target)
        receipt["proc_root_and_flags"] = True
        status = NETWORK.read_file(target / "self/status", 16384).decode()
        if not re.search(r"^Pid:\s+1$", status, re.M):
            raise ProbeError("private-proc-self-is-not-pid-one")
        receipt["proc_self_pid_one"] = True
    finally:
        if mounted:
            unmount_proc(target)
            if any(row[0] == str(target) for row in NETWORK.mount_rows(NETWORK.read_file(MOUNTINFO).decode())):
                raise ProbeError("private-proc-remains-mounted")
            receipt["unmounted"] = True
        target.rmdir()
    receipt.update(supported=True, diagnostic="passed")


def valid_id(value) -> bool:
    return type(value) is int and value > 0


def valid_identity(value) -> bool:
    required = {"GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_EVENT_NAME"}
    return (isinstance(value, dict) and required <= set(value)
            and all(isinstance(key, str) and isinstance(item, str) for key, item in value.items())
            and RUNNER.github_identity(value) == value)


def validate_child(value: dict, parent_pidns: int, parent_mntns: int) -> None:
    if (not isinstance(value, dict) or set(value) != CHILD_FIELDS
        or type(value["schema_version"]) is not int or value["schema_version"] != 1
        or type(value["supported"]) is not bool
        or not isinstance(value["diagnostic"], str)
        or not re.fullmatch(r"[a-z0-9-]{1,96}", value["diagnostic"])
        or any(type(value[key]) is not bool for key in
               ("pid_one", "mapped_runner_root", "proc_self_pid_one", "proc_root_and_flags", "unmounted"))
        or any(value[key] is not None and not valid_id(value[key]) for key in ("pidns", "mntns"))):
        raise ProbeError("invalid-proc-child-evidence")
    if value["supported"] and (value["diagnostic"] != "passed"
        or not valid_id(value["pidns"]) or value["pidns"] == parent_pidns
        or not valid_id(value["mntns"]) or value["mntns"] == parent_mntns
        or not all(value[key] is True for key in
                   ("pid_one", "mapped_runner_root", "proc_self_pid_one", "proc_root_and_flags", "unmounted"))):
        raise ProbeError("invalid-proc-child-success-evidence")


def validate_receipt(value: dict, expected_identity: dict | None = None,
                     expected_hashes: dict | None = None) -> dict:
    fields = {"schema_version", "supported", "diagnostic", "identity", "native", "kernel_release",
              "sandbox_pidns", "sandbox_mntns", "child", "parent_mounts_sha256",
              "parent_mounts_unchanged", "helper_inaccessible", "cleanup_confirmed"}
    if (not isinstance(value, dict) or set(value) != fields
        or type(value["schema_version"]) is not int or value["schema_version"] != 1
        or value["supported"] is not True or value["diagnostic"] != "passed"
        or any(value[key] is not True for key in ("parent_mounts_unchanged", "helper_inaccessible", "cleanup_confirmed"))
        or not valid_id(value["sandbox_pidns"]) or not valid_id(value["sandbox_mntns"])
        or not valid_identity(value["identity"])
        or (expected_identity is not None and value["identity"] != expected_identity)
        or not isinstance(value["native"], dict) or set(value["native"]) != set(NATIVE_FIELDS) | HASH_FIELDS
        or any(type(value["native"].get(key)) is not type(expected) or value["native"].get(key) != expected
               for key, expected in NATIVE_FIELDS.items())
        or any(not isinstance(value["native"].get(key), str)
               or not re.fullmatch(r"[0-9a-f]{64}", value["native"][key]) for key in HASH_FIELDS)
        or (expected_hashes is not None and {key: value["native"][key] for key in HASH_FIELDS} != expected_hashes)
        or not isinstance(value["kernel_release"], str) or not re.fullmatch(r"[A-Za-z0-9._+-]{1,128}", value["kernel_release"])
        or not isinstance(value["parent_mounts_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["parent_mounts_sha256"])):
        raise ProbeError("invalid-proc-mount-receipt")
    validate_child(value["child"], value["sandbox_pidns"], value["sandbox_mntns"])
    if value["child"]["supported"] is not True:
        raise ProbeError("invalid-proc-mount-receipt")
    return value


def parent_probe(receipt: dict, commands: Commands) -> None:
    receipt["native"] = dict(NETWORK.prerequisites())
    for key, path in (("rootlesskit_sha256", Path(NETWORK.ROOTLESSKIT)),
                      ("probe_sha256", Path(__file__).resolve()), ("lock_sha256", NETWORK.LOCK)):
        receipt["native"][key] = hashlib.sha256(NETWORK.read_file(path, 64 * 1024 * 1024)).hexdigest()
    try:
        receipt["identity"] = json.loads(NETWORK.read_file(IDENTITY_FILE, 16384))
    except (ValueError, UnicodeDecodeError) as error:
        raise ProbeError("invalid-workflow-identity") from error
    if not valid_identity(receipt["identity"]):
        raise ProbeError("invalid-workflow-identity")
    release = platform.release()
    if not re.fullmatch(r"[A-Za-z0-9._+-]{1,128}", release):
        raise ProbeError("invalid-kernel-release")
    receipt["kernel_release"] = release
    receipt["sandbox_pidns"], receipt["sandbox_mntns"] = namespace_id("pid"), namespace_id("mnt")
    helper_inaccessible()
    receipt["helper_inaccessible"] = True
    before = NETWORK.read_file(MOUNTINFO)
    receipt["parent_mounts_sha256"] = hashlib.sha256(before).hexdigest()
    state = None
    try:
        code, version = commands.call([NETWORK.ROOTLESSKIT, "--version"])
        if code or not re.fullmatch(r"rootlesskit version 3\.2\.0\s*", version):
            raise ProbeError("rootlesskit-version-mismatch")
        runtime = RUNTIME.lstat()
        if (not stat.S_ISDIR(runtime.st_mode) or runtime.st_uid != 1001
            or stat.S_IMODE(runtime.st_mode) != 0o700 or RUNTIME.resolve(strict=True) != RUNTIME):
            raise ProbeError("invalid-runtime-directory")
        state = Path(tempfile.mkdtemp(prefix="oxibelt-network-", dir=RUNTIME))
        NETWORK.guarded_state(state)
        info = state.lstat()
        code, output = commands.call([NETWORK.ROOTLESSKIT, "--state-dir=" + str(state), *NETWORK.FLAGS,
            "unshare", "--mount", "--pid", "--fork", "--propagation=private", "python3", str(Path(__file__).resolve()),
            "--child", str(state), "--parent-pidns", str(receipt["sandbox_pidns"]),
            "--parent-mntns", str(receipt["sandbox_mntns"]), "--state-device", str(info.st_dev),
            "--state-inode", str(info.st_ino)])
        try:
            child = json.loads(output)
        except (ValueError, TypeError) as error:
            raise ProbeError("invalid-proc-child-output") from error
        validate_child(child, receipt["sandbox_pidns"], receipt["sandbox_mntns"])
        receipt["child"] = child
        if code or not child["supported"]:
            raise ProbeError(child["diagnostic"] if child["diagnostic"] != "passed" else "rootlesskit-command-failed")
    finally:
        try:
            receipt["cleanup_confirmed"] = commands.cleanup_confirmed
            if state is not None and commands.cleanup_confirmed:
                receipt["cleanup_confirmed"] = False
                try:
                    state.lstat()
                except FileNotFoundError:
                    receipt["cleanup_confirmed"] = True
                else:
                    NETWORK.guarded_state(state)
                    shutil.rmtree(state)
                    receipt["cleanup_confirmed"] = not state.exists()
        finally:
            receipt["parent_mounts_unchanged"] = NETWORK.read_file(MOUNTINFO) == before
            if not receipt["parent_mounts_unchanged"]:
                raise ProbeError("sandbox-mounts-changed")
    if not receipt["cleanup_confirmed"]:
        raise ProbeError("cleanup-not-confirmed")
    receipt.update(supported=True, diagnostic="passed")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("/home/runner/evidence/proc-mount.json"))
    parser.add_argument("--child", type=Path)
    parser.add_argument("--parent-pidns", type=int)
    parser.add_argument("--parent-mntns", type=int)
    parser.add_argument("--state-device", type=int)
    parser.add_argument("--state-inode", type=int)
    args = parser.parse_args(argv)
    receipt = child_receipt() if args.child else {
        "schema_version": 1, "supported": False, "diagnostic": "probe-not-completed",
        "identity": {}, "native": None, "kernel_release": None, "sandbox_pidns": None, "sandbox_mntns": None,
        "child": None, "parent_mounts_sha256": None, "parent_mounts_unchanged": False,
        "helper_inaccessible": False, "cleanup_confirmed": False}
    commands = None
    try:
        if args.child:
            if (not valid_id(args.parent_pidns) or not valid_id(args.parent_mntns)
                or type(args.state_device) is not int or args.state_device < 0 or not valid_id(args.state_inode)):
                raise ProbeError("missing-parent-namespace-or-state-identity")
            child_probe(args.child, args.parent_pidns, args.parent_mntns,
                        (args.state_device, args.state_inode), receipt)
        else:
            commands = Commands()
            parent_probe(receipt, commands)
            validate_receipt(receipt)
    except (ProbeError, OSError, UnicodeDecodeError) as error:
        receipt.update(supported=False, diagnostic=str(error) if isinstance(error, ProbeError) else "probe-input-unavailable")
    if args.child:
        print(json.dumps(receipt, sort_keys=True))
    else:
        try:
            raw = (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode()
            if len(raw) > 16384:
                raise ProbeError("evidence-too-large")
            NETWORK.write_new(args.output, raw)
            NETWORK.write_new(args.output.parent / "proc-mount.log", bytes(commands.log) if commands else b"")
        except (ProbeError, OSError) as error:
            print("Cannot preserve proc mount evidence: " + str(error), file=sys.stderr)
            return 2
    return 0 if receipt["supported"] else 1


if __name__ == "__main__":
    sys.exit(main())
