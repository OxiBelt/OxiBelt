#!/usr/bin/env python3
"""Read-only prerequisites for a native, cgroup-bounded rootless RISC-V lane.

This does not install Docker, start services, create namespaces, enable
controllers, or qualify a running daemon. A supported receipt permits only the
next setup step; rootless Docker and its enforced limits still need smoke tests.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import pwd
import re
import selectors
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path, PurePosixPath
from typing import Callable


MAX_READ_BYTES = 256 * 1024
MAX_COMMAND_BYTES = 4096
COMMAND_TIMEOUT_SECONDS = 5
REQUIRED_CONTROLLERS = {"cpu", "memory", "pids"}
PROVIDER_PREREQUISITE = (
    "The provider must supply a native Linux riscv64 nonroot runner with an "
    "already reachable systemd user manager, writable cgroup v2 delegation of "
    "cpu/memory/pids, uidmap helpers, and existing subordinate UID/GID ranges "
    "of at least 65536 IDs. Provision these outside this lane; do not change "
    "node sysctls, security policy, or cgroups, or fall back to rootful Docker "
    "or QEMU."
)
IDENTITY_PATTERNS = {
    "GITHUB_REPOSITORY": r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",
    "GITHUB_SHA": r"[0-9a-f]{40}",
    "GITHUB_RUN_ID": r"[0-9]{1,24}",
    "GITHUB_RUN_ATTEMPT": r"[0-9]{1,8}",
    "GITHUB_JOB": r"[A-Za-z0-9_-]+",
    "GITHUB_REF": r"refs/[A-Za-z0-9_./-]+",
    "GITHUB_WORKFLOW_REF": r"[A-Za-z0-9_./-]+@refs/[A-Za-z0-9_./-]+",
    "GITHUB_WORKFLOW_SHA": r"[0-9a-f]{40}",
    "GITHUB_EVENT_NAME": r"[a-z_]+",
}


class ProbeError(ValueError):
    """A prerequisite cannot be proved from bounded, read-only evidence."""


def github_identity(env: dict[str, str]) -> dict[str, str]:
    return {
        name: value
        for name, pattern in IDENTITY_PATTERNS.items()
        if (value := env.get(name, ""))
        and len(value) <= 256
        and re.fullmatch(pattern, value)
    }


def read_user_manager() -> tuple[str, str]:
    """Return a bounded property, never raw command errors or environment."""
    executable = shutil.which("systemctl")
    if executable is None:
        return "missing-systemctl", ""
    env = {
        "LC_ALL": "C",
        "SYSTEMD_PAGER": "",
        "SYSTEMD_COLORS": "0",
        "SYSTEMD_PAGERSECURE": "1",
    }
    for name in ("XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"):
        if name in os.environ:
            env[name] = os.environ[name]
    try:
        process = subprocess.Popen(
            [executable, "--user", "--no-pager", "show", "--property=ControlGroup", "--value"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=env,
        )
    except OSError:
        return "command-unavailable", ""
    raw = bytearray()
    deadline = time.monotonic() + COMMAND_TIMEOUT_SECONDS
    try:
        assert process.stdout is not None
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    return "command-timeout", ""
                chunk = os.read(process.stdout.fileno(), MAX_COMMAND_BYTES + 1 - len(raw))
                if not chunk:
                    break
                raw.extend(chunk)
                if len(raw) > MAX_COMMAND_BYTES:
                    return "command-output-too-large", ""
        try:
            exit_code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            return "command-timeout", ""
        if exit_code != 0:
            return "user-manager-unreachable", ""
        try:
            return "ok", raw.decode("utf-8").strip()
        except UnicodeDecodeError:
            return "invalid-command-output", ""
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        if process.stdout is not None:
            process.stdout.close()


class Probe:
    def __init__(
        self,
        *,
        root: Path = Path("/"),
        uid: int | None = None,
        username: str | None = None,
        system: str | None = None,
        machine: str | None = None,
        command_reader: Callable[[], tuple[str, str]] = read_user_manager,
    ) -> None:
        self.root = root.resolve()
        self.uid = os.geteuid() if uid is None else uid
        if username is None:
            try:
                username = pwd.getpwuid(self.uid).pw_name
            except KeyError:
                username = ""
        self.username = username
        self.system = platform.system() if system is None else system
        self.machine = platform.machine() if machine is None else machine
        self.command_reader = command_reader
        self.checks: list[dict[str, object]] = []
        self.cgroup_mount_verified = False

    def path(self, absolute: str) -> Path:
        return self.root / absolute.lstrip("/")

    def read(self, path: Path) -> str:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise ProbeError("not-regular-file")
                raw = stream.read(MAX_READ_BYTES + 1)
            if len(raw) > MAX_READ_BYTES:
                raise ProbeError("input-too-large")
            return raw.decode("utf-8")
        except (OSError, UnicodeDecodeError) as error:
            raise ProbeError("input-unavailable") from error

    def check(self, name: str, callback: Callable[[], dict[str, object]]) -> None:
        try:
            details = callback()
        except ProbeError as error:
            self.checks.append({"name": name, "passed": False, "diagnostic": str(error)})
        else:
            self.checks.append({"name": name, "passed": True, **details})

    def native(self) -> dict[str, object]:
        if self.system != "Linux" or self.machine != "riscv64":
            raise ProbeError("requires-native-linux-riscv64")
        # Require a RISC-V interpreter as well as the kernel-reported machine.
        # Provider provenance remains necessary: userspace emulation can also
        # virtualize /proc/self/exe, so this is not proof that emulation is absent.
        try:
            with self.path("/proc/self/exe").open("rb") as stream:
                elf = stream.read(20)
        except OSError as error:
            raise ProbeError("native-executable-unavailable") from error
        if (
            len(elf) != 20
            or elf[:6] != b"\x7fELF\x02\x01"
            or int.from_bytes(elf[18:20], "little") != 243
        ):
            raise ProbeError("requires-native-riscv64-executable")
        return {"os": "linux", "architecture": "riscv64", "executable_machine": "riscv64"}

    def nonroot(self) -> dict[str, object]:
        if self.uid == 0 or os.getuid() == 0:
            raise ProbeError("requires-nonroot-current-user")
        return {"nonroot": True}

    def cgroup_v2(self) -> dict[str, object]:
        mountinfo = self.read(self.path("/proc/self/mountinfo"))
        for line in mountinfo.splitlines():
            fields = line.split()
            if "-" not in fields or len(fields) < 10:
                continue
            separator = fields.index("-")
            if separator < 6 or separator + 3 >= len(fields):
                continue
            if fields[4] == "/sys/fs/cgroup" and fields[separator + 1] == "cgroup2":
                if fields[3] != "/":
                    raise ProbeError("cgroup-v2-mount-root-mapping-unsupported")
                if "rw" not in fields[5].split(","):
                    raise ProbeError("cgroup-v2-mount-read-only")
                self.read(self.path("/sys/fs/cgroup/cgroup.controllers"))
                self.cgroup_mount_verified = True
                return {"version": 2}
        raise ProbeError("requires-cgroup-v2-mount")

    def delegation(self) -> dict[str, object]:
        status, value = self.command_reader()
        if status != "ok":
            # Only fixed diagnostics enter the receipt, including injected readers.
            allowed = {
                "missing-systemctl", "command-unavailable", "command-timeout",
                "command-output-too-large", "user-manager-unreachable", "invalid-command-output",
            }
            raise ProbeError(status if status in allowed else "user-manager-unreachable")
        if not self.cgroup_mount_verified:
            raise ProbeError("requires-verified-cgroup-v2-mount")
        group = PurePosixPath(value)
        if (
            len(value) > 512
            or not value.startswith("/")
            or ".." in group.parts
            or str(group) != value
            or not re.fullmatch(r"/[A-Za-z0-9_.:@/-]+", value)
            or group.name != f"user@{self.uid}.service"
            or group.parent.name != f"user-{self.uid}.slice"
        ):
            raise ProbeError("invalid-user-manager-cgroup-path")
        base = self.path("/sys/fs/cgroup")
        directory = base / value.lstrip("/")
        try:
            resolved = directory.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise ProbeError("user-manager-cgroup-unavailable") from error
        if not resolved.is_relative_to(base.resolve()) or resolved != directory:
            raise ProbeError("user-manager-cgroup-path-escape")
        controllers = set(self.read(directory / "cgroup.controllers").split())
        enabled = set(self.read(directory / "cgroup.subtree_control").split())
        if not REQUIRED_CONTROLLERS <= controllers:
            raise ProbeError("user-manager-missing-cpu-memory-pids-controllers")
        if not REQUIRED_CONTROLLERS <= enabled:
            raise ProbeError("user-manager-cpu-memory-pids-not-enabled")
        if not all(
            os.access(path, os.W_OK, effective_ids=True)
            for path in (directory, directory / "cgroup.procs", directory / "cgroup.subtree_control")
        ):
            raise ProbeError("user-manager-cgroup-not-writable")
        return {
            "control_group": value,
            "delegated_controllers": sorted(REQUIRED_CONTROLLERS),
            "subtree_controllers": sorted(REQUIRED_CONTROLLERS),
            "writable": True,
        }

    def uidmap(self) -> dict[str, object]:
        missing = [name for name in ("newuidmap", "newgidmap") if shutil.which(name) is None]
        if missing:
            raise ProbeError("missing-" + "-and-".join(missing))
        return {"newuidmap": True, "newgidmap": True}

    def mapping(self, kind: str) -> dict[str, object]:
        largest = 0
        for line in self.read(self.path(f"/etc/{kind}")).splitlines():
            fields = line.split(":")
            if not fields or fields[0] not in {self.username, str(self.uid)}:
                continue
            if (
                len(fields) != 3
                or not re.fullmatch(r"[0-9]{1,10}", fields[1])
                or not re.fullmatch(r"[0-9]{1,10}", fields[2])
            ):
                raise ProbeError("invalid-current-user-subordinate-range")
            start, count = int(fields[1]), int(fields[2])
            if start <= 0 or count <= 0 or start + count > 2**32:
                raise ProbeError("invalid-current-user-subordinate-range")
            largest = max(largest, count)
        if largest < 65536:
            raise ProbeError("requires-existing-65536-subordinate-ids")
        return {"largest_existing_range_count": largest, "required_count": 65536}

    def user_namespaces(self) -> dict[str, object]:
        maximum = self.read(self.path("/proc/sys/user/max_user_namespaces")).strip()
        if not re.fullmatch(r"[0-9]{1,10}", maximum) or int(maximum) == 0:
            raise ProbeError("user-namespaces-disabled")
        optional = self.path("/proc/sys/kernel/unprivileged_userns_clone")
        if optional.exists() and self.read(optional).strip() != "1":
            raise ProbeError("unprivileged-user-namespaces-disabled")
        return {"kernel_user_namespace_sysctls_allow": True}

    def run(self, env: dict[str, str]) -> dict[str, object]:
        for name, callback in (
            ("native_linux_riscv64", self.native),
            ("nonroot_current_user", self.nonroot),
            ("cgroup_v2", self.cgroup_v2),
            ("systemd_user_manager_delegation", self.delegation),
            ("uidmap_helpers", self.uidmap),
            ("subuid_mapping", lambda: self.mapping("subuid")),
            ("subgid_mapping", lambda: self.mapping("subgid")),
            ("user_namespace_kernel_prerequisites", self.user_namespaces),
        ):
            self.check(name, callback)
        failed = [check["name"] for check in self.checks if not check["passed"]]
        return {
            "schema_version": 1,
            "supported": not failed,
            "scope": "read-only-prerequisites-before-rootless-docker-setup",
            "identity": github_identity(env),
            "failed_prerequisites": failed,
            "checks": self.checks,
            "provider_prerequisite": PROVIDER_PREREQUISITE,
        }


def write_evidence(output: Path, evidence: dict[str, object]) -> None:
    """Create a private new regular file; never follow links or overwrite input."""
    absolute = output.absolute()
    if ".." in absolute.parts or absolute.suffix != ".json":
        raise ProbeError("output-requires-new-regular-json-file")
    try:
        parent = absolute.parent.resolve(strict=True)
        if parent != absolute.parent:
            raise ProbeError("output-parent-must-not-contain-symlinks")
        raw = (json.dumps(evidence, indent=2, sort_keys=True) + "\n").encode("utf-8")
        if len(raw) > 16384:
            raise ProbeError("evidence-too-large")
        fd = os.open(absolute, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
    except OSError as error:
        raise ProbeError("cannot-create-new-evidence-file") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="new .json file in an existing directory")
    args = parser.parse_args(argv)
    try:
        evidence = Probe().run({name: os.environ[name] for name in IDENTITY_PATTERNS if name in os.environ})
        write_evidence(args.output, evidence)
    except ProbeError as error:
        print(f"RISC-V prerequisite evidence failed: {error}", file=sys.stderr)
        return 2
    if not evidence["supported"]:
        print("Unsupported runner: " + ", ".join(evidence["failed_prerequisites"]), file=sys.stderr)
        print(PROVIDER_PREREQUISITE, file=sys.stderr)
        return 1
    print("Native RISC-V rootless Docker prerequisites passed; runtime enforcement remains unverified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
