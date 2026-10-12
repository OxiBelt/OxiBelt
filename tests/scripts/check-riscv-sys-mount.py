#!/usr/bin/env python3
"""Bounded native RootlessKit read-only sysfs qualification before compilation."""
from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import stat
import sys
import tempfile
from pathlib import Path

# Reuse the existing small validators and bounded process-group lifecycle.
import importlib.util
_spec = importlib.util.spec_from_file_location("riscv_proc_mount", Path(__file__).with_name("check-riscv-proc-mount.py"))
assert _spec and _spec.loader
PROC = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(PROC)
OBSERVER = PROC.sibling("riscv-network-observation")
NETWORK = PROC.NETWORK
ProbeError, Commands = NETWORK.ProbeError, NETWORK.Commands
RUNTIME, IDENTITY_FILE, MOUNTINFO = PROC.RUNTIME, PROC.IDENTITY_FILE, PROC.MOUNTINFO
NATIVE_FIELDS = dict(PROC.NATIVE_FIELDS)
V1_HASH_FIELDS = set(PROC.HASH_FIELDS)
HASH_FIELDS = V1_HASH_FIELDS | {"observer_sha256"}
valid_id, valid_identity, namespace_id = PROC.valid_id, PROC.valid_identity, PROC.namespace_id
MS_SYS_FLAGS = 1 | 2 | 4 | 8  # MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC
BOOLEAN_FIELDS = {"pid_one", "mapped_runner_root", "detached_network_entered", "sys_root_and_flags",
                  "rootfd_authenticated", "readonly_token_absent", "network_view_matches", "unmounted"}
NAMESPACE_FIELDS = {"pidns", "mntns", "netns", "entered_pidns", "entered_mntns", "detached_netns"}
V1_CHILD_FIELDS = {"schema_version", "supported", "diagnostic", "readonly_errno", "mount_id", "interfaces"} | BOOLEAN_FIELDS | NAMESPACE_FIELDS
CHILD_FIELDS = V1_CHILD_FIELDS | {"network_observation"}


def child_receipt() -> dict:
    return {"schema_version": 3, "supported": False, "diagnostic": "probe-not-completed",
            "readonly_errno": None, "mount_id": None, "interfaces": [],
            "network_observation": OBSERVER.empty(),
            **{key: False for key in BOOLEAN_FIELDS}, **{key: None for key in NAMESPACE_FIELDS}}


def parent_receipt() -> dict:
    return {"schema_version": 3, "supported": False, "diagnostic": "probe-not-completed", "identity": {},
            "native": None, "kernel_release": None, "sandbox_pidns": None, "sandbox_mntns": None,
            "sandbox_netns": None, "child": None, "parent_mounts_sha256": None,
            "parent_mounts_unchanged": False, "helper_inaccessible": False, "cleanup_confirmed": False}


def helper_inaccessible() -> None:
    try:
        fd = os.open(NETWORK.SYS_HELPER, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as error:
        if error.errno == errno.EACCES:
            return
        raise ProbeError("sys-helper-traversal-unexpected-error") from error
    os.close(fd)
    raise ProbeError("sys-helper-is-accessible-to-runner")


def mapped_root() -> None:
    if os.getuid() != 0 or os.geteuid() != 0:
        raise ProbeError("requires-rootless-child-root")
    try:
        mappings = [tuple(map(int, row.split())) for row in
                    NETWORK.read_file(Path("/proc/self/uid_map")).decode().splitlines()]
    except (ValueError, UnicodeDecodeError) as error:
        raise ProbeError("invalid-child-uid-map") from error
    if not mappings or mappings[0] != (0, 1001, 1):
        raise ProbeError("child-is-not-mapped-runner-root")


def validate_sys_mount(text: str, target: Path) -> int:
    rows = NETWORK.mount_metadata(text)
    matches = [row for row in rows if row["point"] == str(target)]
    roots = [row for row in rows if row["point"] == "/"]
    if (len(matches) != 1 or matches[0]["root"] != "/" or matches[0]["filesystem"] != "sysfs"
        or not {"ro", "nosuid", "nodev", "noexec"} <= matches[0]["options"]
        or matches[0]["propagation"] or len(roots) != 1 or roots[0]["propagation"]
        or any(row["point"].startswith(str(target) + "/") for row in rows)):
        raise ProbeError("private-sys-mount-mismatch")
    # mount ID authenticates the opened root fd, independently of path lookup.
    ids = [line.split(" - ", 1)[0].split()[0] for line in text.splitlines()
           if line.split(" - ", 1)[0].split()[4] == str(target)]
    if len(ids) != 1 or not re.fullmatch(r"[1-9][0-9]{0,19}", ids[0]):
        raise ProbeError("private-sys-mount-id-mismatch")
    return int(ids[0])


def mount_sys(target: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_void_p]
    libc.mount.restype = ctypes.c_int
    if libc.mount(b"sysfs", os.fsencode(target), b"sysfs", MS_SYS_FLAGS, None) != 0:
        print(json.dumps({"operation": "mount-sys", "errno": ctypes.get_errno()}), file=sys.stderr)
        raise ProbeError("private-sys-mount-denied")


def unmount_sys(target: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
    libc.umount2.restype = ctypes.c_int
    if libc.umount2(os.fsencode(target), 0) != 0:
        print(json.dumps({"operation": "unmount-sys", "errno": ctypes.get_errno()}), file=sys.stderr)
        raise ProbeError("private-sys-unmount-failed")


def token_absent(fd: int, token: str) -> None:
    try:
        os.stat(token, dir_fd=fd, follow_symlinks=False)
    except OSError as error:
        if error.errno == errno.ENOENT:
            return
        raise ProbeError("readonly-token-absence-unavailable") from error
    raise ProbeError("readonly-token-present")


def readonly_proof(target: Path, mount_id: int, receipt: dict) -> None:
    fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fdinfo = NETWORK.read_file(Path(f"/proc/self/fdinfo/{fd}"), 4096).decode()
        matches = re.findall(r"^mnt_id:\s*([1-9][0-9]*)$", fdinfo, re.M)
        if (not stat.S_ISDIR(os.fstat(fd).st_mode) or matches != [str(mount_id)]
            or validate_sys_mount(NETWORK.read_file(MOUNTINFO).decode(), target) != mount_id):
            raise ProbeError("fresh-sys-rootfd-mismatch")
        receipt["rootfd_authenticated"] = True
        token = ".oxibelt-sys-ro-" + secrets.token_hex(16)
        token_absent(fd, token)
        try:
            # mkdirat creates only this unique token; no existing control file is opened for writing.
            os.mkdir(token, mode=0o700, dir_fd=fd)
        except OSError as error:
            receipt["readonly_errno"] = error.errno
            if error.errno != errno.EROFS:
                raise ProbeError("readonly-proof-did-not-return-erofs") from error
        else:
            # Fail closed even if cleanup of the unexpectedly created own token succeeds.
            try:
                os.rmdir(token, dir_fd=fd)
            finally:
                raise ProbeError("readonly-proof-unexpectedly-succeeded")
        token_absent(fd, token)
        receipt["readonly_token_absent"] = True
    finally:
        os.close(fd)


def network_view(target: Path, observation: dict) -> list[dict]:
    try:
        OBSERVER.collect(target, observation, NETWORK.read_file)
        interfaces = OBSERVER.network_none_interfaces(observation)
    except OBSERVER.ObservationError as error:
        raise ProbeError(str(error)) from error
    return interfaces


def launch(state: Path, parents: tuple[int, int, int], identity: tuple[int, int]) -> None:
    NETWORK.guarded_state(state, child=True, identity=identity)
    mapped_root()
    detached = NETWORK.namespace_id(state / "netns")
    if namespace_id("net") != detached or detached == parents[2]:
        raise ProbeError("child-did-not-enter-detached-network-namespace")
    entered_pidns, entered_mntns = namespace_id("pid"), namespace_id("mnt")
    os.execvp("unshare", ["unshare", "--mount", "--pid", "--net", "--fork", "--propagation=private",
        "python3", str(Path(__file__).resolve()), "--child", str(state),
        "--parent-pidns", str(parents[0]), "--parent-mntns", str(parents[1]), "--parent-netns", str(parents[2]),
        "--entered-pidns", str(entered_pidns), "--entered-mntns", str(entered_mntns),
        "--detached-netns", str(detached), "--state-device", str(identity[0]), "--state-inode", str(identity[1])])


def child_probe(state: Path, parents: tuple[int, int, int], entered: tuple[int, int, int],
                identity: tuple[int, int], receipt: dict) -> None:
    NETWORK.guarded_state(state, child=True, identity=identity)
    mapped_root()
    receipt["mapped_runner_root"] = True
    receipt.update(entered_pidns=entered[0], entered_mntns=entered[1], detached_netns=entered[2])
    receipt.update(pidns=namespace_id("pid"), mntns=namespace_id("mnt"), netns=namespace_id("net"))
    if (receipt["pidns"] in (parents[0], entered[0]) or receipt["mntns"] in (parents[1], entered[1])
        or receipt["netns"] in (parents[2], entered[2]) or entered[2] == parents[2]):
        raise ProbeError("child-namespace-is-not-private")
    receipt["detached_network_entered"] = True
    if os.getpid() != 1:
        raise ProbeError("child-is-not-pid-one")
    receipt["pid_one"] = True
    target = state / "sys"
    target.mkdir(mode=0o700)
    target = target.resolve(strict=True)
    mounted = False
    try:
        mount_sys(target)
        mounted = True
        receipt["mount_id"] = validate_sys_mount(NETWORK.read_file(MOUNTINFO).decode(), target)
        receipt["sys_root_and_flags"] = True
        readonly_proof(target, receipt["mount_id"], receipt)
        receipt["interfaces"] = network_view(target, receipt["network_observation"])
        receipt["network_view_matches"] = True
    finally:
        if mounted:
            unmount_sys(target)
            if any(row["point"] == str(target) or row["point"].startswith(str(target) + "/")
                   for row in NETWORK.mount_metadata(NETWORK.read_file(MOUNTINFO).decode())):
                raise ProbeError("private-sys-remains-mounted")
            receipt["unmounted"] = True
        target.rmdir()
    receipt.update(supported=True, diagnostic="passed")


def validate_child(value: dict, parent_pidns: int, parent_mntns: int, parent_netns: int) -> None:
    version = value.get("schema_version") if isinstance(value, dict) else None
    if (not isinstance(value, dict) or set(value) != (V1_CHILD_FIELDS if version == 1 else CHILD_FIELDS)
        or type(version) is not int or version not in (1, 2, 3)
        or type(value["supported"]) is not bool or not isinstance(value["diagnostic"], str)
        or not re.fullmatch(r"[a-z0-9-]{1,96}", value["diagnostic"])
        or any(type(value[key]) is not bool for key in BOOLEAN_FIELDS)
        or any(value[key] is not None and not valid_id(value[key]) for key in NAMESPACE_FIELDS | {"mount_id"})
        or (value["readonly_errno"] is not None and (type(value["readonly_errno"]) is not int or value["readonly_errno"] < 1))
        or not isinstance(value["interfaces"], list)
        or any(not isinstance(item, dict) or set(item) != {"index", "name"}
               or not valid_id(item["index"]) or not isinstance(item["name"], str)
               or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", item["name"]) for item in value["interfaces"])):
        raise ProbeError("invalid-sys-child-evidence")
    if version in (2, 3):
        try:
            OBSERVER.validate(value["network_observation"], complete=value["supported"])
            if value["supported"]:
                classify = OBSERVER.network_none_interfaces if version == 3 else OBSERVER.matching_interfaces
                if classify(value["network_observation"]) != value["interfaces"]:
                    raise OBSERVER.ObservationError("sys-network-view-mismatch")
        except OBSERVER.ObservationError as error:
            raise ProbeError("invalid-sys-child-network-evidence") from error
    if value["supported"] and (value["diagnostic"] != "passed"
        or not all(value[key] is True for key in BOOLEAN_FIELDS)
        or not all(valid_id(value[key]) for key in NAMESPACE_FIELDS | {"mount_id"})
        or value["pidns"] in (parent_pidns, value["entered_pidns"])
        or value["mntns"] in (parent_mntns, value["entered_mntns"])
        or value["netns"] in (parent_netns, value["detached_netns"])
        or value["detached_netns"] == parent_netns
        or value["readonly_errno"] != errno.EROFS
        or (version != 3 and value["interfaces"] != [{"index": 1, "name": "lo"}])):
        raise ProbeError("invalid-sys-child-success-evidence")


def validate_receipt(value: dict, expected_identity: dict | None = None,
                     expected_hashes: dict | None = None) -> dict:
    version = value.get("schema_version") if isinstance(value, dict) else None
    hash_fields = V1_HASH_FIELDS if version == 1 else HASH_FIELDS
    if (not isinstance(value, dict) or set(value) != set(parent_receipt())
        or type(version) is not int or version not in (1, 2, 3)
        or value["supported"] is not True or value["diagnostic"] != "passed"
        or any(value[key] is not True for key in ("parent_mounts_unchanged", "helper_inaccessible", "cleanup_confirmed"))
        or any(not valid_id(value[key]) for key in ("sandbox_pidns", "sandbox_mntns", "sandbox_netns"))
        or not valid_identity(value["identity"])
        or (expected_identity is not None and value["identity"] != expected_identity)
        or not isinstance(value["native"], dict) or set(value["native"]) != set(NATIVE_FIELDS) | hash_fields
        or any(type(value["native"].get(key)) is not type(expected) or value["native"].get(key) != expected
               for key, expected in NATIVE_FIELDS.items())
        or any(not isinstance(value["native"].get(key), str)
               or not re.fullmatch(r"[0-9a-f]{64}", value["native"][key]) for key in hash_fields)
        or (expected_hashes is not None and {key: value["native"][key] for key in hash_fields} != expected_hashes)
        or not isinstance(value["kernel_release"], str) or not re.fullmatch(r"[A-Za-z0-9._+-]{1,128}", value["kernel_release"])
        or not isinstance(value["parent_mounts_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["parent_mounts_sha256"])):
        raise ProbeError("invalid-sys-mount-receipt")
    validate_child(value["child"], value["sandbox_pidns"], value["sandbox_mntns"], value["sandbox_netns"])
    if value["child"]["supported"] is not True or value["child"]["schema_version"] != version:
        raise ProbeError("invalid-sys-mount-receipt")
    return value


def parent_probe(receipt: dict, commands: Commands) -> None:
    receipt["native"] = dict(NETWORK.prerequisites())
    for key, path in (("rootlesskit_sha256", Path(NETWORK.ROOTLESSKIT)),
                      ("probe_sha256", Path(__file__).resolve()), ("lock_sha256", NETWORK.LOCK),
                      ("observer_sha256", Path(OBSERVER.__file__).resolve())):
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
    parents = tuple(namespace_id(kind) for kind in ("pid", "mnt", "net"))
    receipt.update(sandbox_pidns=parents[0], sandbox_mntns=parents[1], sandbox_netns=parents[2])
    before = NETWORK.read_file(MOUNTINFO)
    NETWORK.validate_sys_helper(before.decode(), required=True)
    helper_inaccessible()
    receipt["helper_inaccessible"] = True
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
            "nsenter", "-n" + str(state / "netns"), "python3", str(Path(__file__).resolve()),
            "--launch", str(state), "--parent-pidns", str(parents[0]), "--parent-mntns", str(parents[1]),
            "--parent-netns", str(parents[2]), "--state-device", str(info.st_dev), "--state-inode", str(info.st_ino)])
        try:
            child = json.loads(output)
        except (ValueError, TypeError) as error:
            raise ProbeError("invalid-sys-child-output") from error
        validate_child(child, *parents)
        receipt["child"] = child
        if child["schema_version"] != receipt["schema_version"]:
            raise ProbeError("sys-child-schema-mismatch")
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
    parser.add_argument("--output", type=Path, default=Path("/home/runner/evidence/sys-mount.json"))
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--child", type=Path)
    modes.add_argument("--launch", type=Path)
    for flag in ("parent-pidns", "parent-mntns", "parent-netns", "entered-pidns", "entered-mntns", "detached-netns", "state-device", "state-inode"):
        parser.add_argument("--" + flag, type=int)
    args = parser.parse_args(argv)
    internal = args.child is not None or args.launch is not None
    receipt = child_receipt() if internal else parent_receipt()
    commands = None
    try:
        if internal:
            parents = (args.parent_pidns, args.parent_mntns, args.parent_netns)
            if (not all(valid_id(item) for item in parents) or type(args.state_device) is not int
                or args.state_device < 0 or not valid_id(args.state_inode)):
                raise ProbeError("missing-parent-namespace-or-state-identity")
            identity = (args.state_device, args.state_inode)
            if args.launch is not None:
                launch(args.launch, parents, identity)
                raise ProbeError("namespace-launch-returned")
            entered = (args.entered_pidns, args.entered_mntns, args.detached_netns)
            if not all(valid_id(item) for item in entered):
                raise ProbeError("missing-entered-namespace-identity")
            child_probe(args.child, parents, entered, identity, receipt)
        else:
            commands = Commands()
            parent_probe(receipt, commands)
            validate_receipt(receipt)
    except (ProbeError, OSError, UnicodeDecodeError) as error:
        receipt.update(supported=False, diagnostic=str(error) if isinstance(error, ProbeError) else "probe-input-unavailable")
    if internal:
        print(json.dumps(receipt, sort_keys=True))
    else:
        try:
            raw = (json.dumps(receipt, sort_keys=True) + "\n").encode()
            if len(raw) > 65536:
                raise ProbeError("evidence-too-large")
            NETWORK.write_new(args.output, raw)
            NETWORK.write_new(args.output.parent / "sys-mount.log", bytes(commands.log) if commands else b"")
        except (ProbeError, OSError) as error:
            print("Cannot preserve sys mount evidence: " + str(error), file=sys.stderr)
            return 2
    return 0 if receipt["supported"] else 1


if __name__ == "__main__":
    sys.exit(main())
