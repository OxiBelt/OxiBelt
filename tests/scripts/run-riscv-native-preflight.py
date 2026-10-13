#!/usr/bin/env python3
"""Provision and qualify one disposable native rootless Docker sandbox.

Only the explicit provider socket manages trusted infrastructure. Qualification
uses the inner user's socket. No cgroup, namespace, or daemon fallback is used.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path, PurePosixPath


HERE = Path(__file__).resolve().parent
SOCKET = "unix:///var/run/docker.sock"
MAX_BYTES = 128 * 1024
MAX_ARCHIVE_BYTES = 5 * 1024 * 1024
MAX_EVIDENCE_FILE_BYTES = 4 * 1024 * 1024
MAX_EVIDENCE_BYTES = 64 * 1024
# The complete aggregate contains several bounded probe receipts and must fit
# the prerequisite reader's 256 KiB limit; individual writers retain 16 KiB.
MAX_PREFLIGHT_RECEIPT_BYTES = 256 * 1024
EVIDENCE_LOGS = (
    "apt-update.log", "apt-bootstrap.log", "apt-install.log", "build-engine.log",
    "build-cli.log", "build-containerd.log", "build-runc.log", "docker-start.log",
    "systemd-build-failure.log", "systemd-docker-failure.log", "network-mount.log",
    "network-sysctl.log", "proc-mount.log", "sys-mount.log", "enforcement-docker.log",
)
EVIDENCE_JSON = ("network-sysctl.json", "proc-mount.json", "sys-mount.json", "bootstrap-failure.json",
                 "bootstrap-phase.json")
SOURCE_LABEL = "org.oxibelt.preflight.source"
RUN_LABEL = "org.oxibelt.preflight.run"
VERSION_TOKEN = r"v?[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(?:[-+][A-Za-z0-9][A-Za-z0-9.+~:-]{0,63})?"
FILES = (
    "riscv-native-sandbox-bootstrap.sh", "riscv-native-sandbox-build-tools.sh",
    "riscv-native-tools.lock.json", "check-riscv-native-runner.py",
    "check-riscv-rootless-enforcement.py", "riscv-rootless-limit-probe.c",
    "check-riscv-network-sysctl.py",
    "check-riscv-proc-mount.py",
    "check-riscv-sys-mount.py",
    "riscv-network-observation.py",
)

# Fixed read-only code: hints can describe a failure, never qualify a probe.
PHASE_READER = """import json, os, stat
try:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    with_root = os.open('/home', flags)
    home = os.open('runner', flags, dir_fd=with_root)
    evidence = os.open('evidence', flags, dir_fd=home)
    for directory in (home, evidence):
        metadata = os.fstat(directory)
        assert (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)) == (1001, 1001, 0o700)
    descriptor = os.open('bootstrap-phase.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=evidence)
    with os.fdopen(descriptor, 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        assert stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 1001 and metadata.st_gid == 1001
        assert stat.S_IMODE(metadata.st_mode) == 0o600 and metadata.st_size <= 512
        raw = stream.read(513)
    assert len(raw) <= 512
    value = json.loads(raw)
    assert isinstance(value, dict) and set(value) == {'schema_version', 'phase'}
    assert type(value['schema_version']) is int and value['schema_version'] == 1
    assert isinstance(value['phase'], str) and value['phase'] in ('proc-mount', 'network', 'sys-mount', 'native-tools')
    print(value['phase'])
except (OSError, ValueError, AssertionError, KeyError, TypeError):
    pass
"""


class Failure(RuntimeError):
    pass


def mapping(value, diagnostic: str) -> dict:
    if not isinstance(value, dict):
        raise Failure(diagnostic)
    return value


def validate_bootstrap_phase(raw: bytes):
    """Bound diagnostic artifacts to the same small phase-only schema."""
    if len(raw) > 512:
        raise Failure("invalid-bootstrap-phase-evidence")
    value = mapping(json.loads(raw), "invalid-bootstrap-phase-evidence")
    if (set(value) != {"schema_version", "phase"}
        or type(value.get("schema_version")) is not int or value["schema_version"] != 1
        or not isinstance(value.get("phase"), str)
        or value["phase"] not in ("proc-mount", "network", "sys-mount", "native-tools")):
        raise Failure("invalid-bootstrap-phase-evidence")


def runtime_version(value, name: str) -> str | None:
    """Extract only a bounded version token, never copy arbitrary diagnostics."""
    if not isinstance(value, str) or len(value) > 512:
        return None
    prefix = {"containerd": r"(?:containerd(?: github\.com/containerd/containerd(?:/v2)?)? )?",
              "runc": r"(?:runc version )?"}.get(name, "")
    normalized = " ".join(value.split())
    matched = re.match(r"^" + prefix + "(" + VERSION_TOKEN + r")(?=\s|$)", normalized)
    return matched.group(1).removeprefix("v") if matched else None


def runtime_commit(value) -> str | None:
    return value if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{7,64}", value) else None


def load_probe():
    spec = importlib.util.spec_from_file_location("native_prerequisites", HERE / "check-riscv-native-runner.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_network_probe():
    spec = importlib.util.spec_from_file_location("network_prerequisites", HERE / "check-riscv-network-sysctl.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_proc_probe():
    spec = importlib.util.spec_from_file_location("proc_prerequisites", HERE / "check-riscv-proc-mount.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_sys_probe():
    spec = importlib.util.spec_from_file_location("sys_prerequisites", HERE / "check-riscv-sys-mount.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def execute(argv: list[str], env: dict[str, str], timeout: int = 30,
            *, maximum: int = MAX_BYTES) -> tuple[int, bytes]:
    """Bound command time and combined output, including failed CLI commands."""
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, env=env, start_new_session=True)
    output = bytearray()
    deadline = time.monotonic() + timeout
    try:
        assert process.stdout
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise Failure("command-timeout")
                chunk = os.read(process.stdout.fileno(), 8192)
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > maximum:
                    raise Failure("command-output-too-large")
        return process.wait(timeout=max(0.001, deadline - time.monotonic())), bytes(output)
    except subprocess.TimeoutExpired as error:
        raise Failure("command-timeout") from error
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait()
        if process.stdout:
            process.stdout.close()


def archive_evidence(raw: bytes, filename: str) -> bytes:
    """Read one named regular file from an uncompressed Docker archive."""
    if filename not in EVIDENCE_LOGS + EVIDENCE_JSON:
        raise Failure("unknown-evidence-file")
    if len(raw) > MAX_ARCHIVE_BYTES:
        raise Failure("evidence-archive-too-large")
    try:
        # Parse a single physical header directly. Recursive PAX/GNU metadata
        # parsing is unnecessary for these short fixed names and can exhaust
        # the call stack even in a bounded archive.
        member = tarfile.TarInfo.frombuf(raw[:512], encoding="utf-8", errors="strict")
        if (member.name not in (filename, "./" + filename)
            or member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE)
            or member.size < 0 or member.size > MAX_EVIDENCE_FILE_BYTES):
            raise Failure("invalid-evidence-archive-member")
        if filename.endswith(".json") and member.size > MAX_EVIDENCE_BYTES:
            raise Failure("evidence-json-too-large")
        end = 512 + ((member.size + 511) // 512) * 512
        if len(raw) < end + 1024 or any(raw[512 + member.size:]):
            raise Failure("invalid-evidence-archive-trailer")
        data = raw[512:512 + member.size]
    except (tarfile.TarError, OSError, ValueError) as error:
        raise Failure("invalid-evidence-archive") from error
    return data if filename.endswith(".json") else data[-MAX_EVIDENCE_BYTES:]


def validate_collected_json(data: bytes) -> None:
    """Bound nesting before decoding; retain validated bytes without expansion."""
    text = data.decode("utf-8")
    depth, quoted, escaped = 0, False, False
    for char in map(ord, text):
        if quoted:
            if escaped:
                escaped = False
            elif char == 92:
                escaped = True
            elif char == 34:
                quoted = False
        elif char == 34:
            quoted = True
        elif char in (91, 123):
            depth += 1
            if depth > 64:
                raise Failure("evidence-json-too-deep")
        elif char in (93, 125):
            depth -= 1
    mapping(json.loads(text), "invalid-collected-json")


def sanitized_exit_state(value: dict) -> dict:
    """Allowlist process outcome fields without copying runtime error text."""
    state = mapping(value.get("State"), "invalid-sandbox-exit-state")
    timestamp = r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z"
    if (not isinstance(state.get("Status"), str)
        or state["Status"] not in {"created", "running", "paused", "restarting", "removing", "exited", "dead"}
        or type(state.get("Running")) is not bool or type(state.get("OOMKilled")) is not bool
        or type(state.get("ExitCode")) is not int or not 0 <= state["ExitCode"] <= 255
        or not isinstance(state.get("Error"), str)
        or any(not isinstance(state.get(key), str) or not re.fullmatch(timestamp, state[key])
               for key in ("StartedAt", "FinishedAt"))):
        raise Failure("invalid-sandbox-exit-state")
    return {"status": state["Status"], "running": state["Running"],
            "exit_code": state["ExitCode"], "oom_killed": state["OOMKilled"],
            "started_at": state["StartedAt"], "finished_at": state["FinishedAt"],
            "runtime_error_present": bool(state["Error"])}


def controls(parent: str, root: Path = Path("/sys/fs/cgroup")) -> dict[str, list[str]]:
    """Snapshot only ancestors outside the pod; never change their controllers."""
    path = PurePosixPath(parent)
    if not parent.startswith("/") or str(path) != parent or ".." in path.parts or parent == "/":
        raise Failure("invalid-cgroup-parent")
    result = {}
    probe = load_probe().Probe(root=Path("/"))
    for group in reversed(path.parents):
        target = root / str(group).lstrip("/") / "cgroup.subtree_control"
        if target.resolve(strict=True) != target:
            raise Failure("cgroup-ancestor-symlink")
        result[str(group)] = sorted(probe.read(target).split())
    return result


def sandbox_arguments(parent: str, image: str, name: str, labels: dict[str, str]) -> list[str]:
    """The provider runtime allocates the leaf beneath the proved pod parent."""
    argv = ["create", "--name", name, "--platform", "linux/riscv64",
            "--cgroup-parent", parent, "--cgroupns=private", "--network=bridge",
            "--cpus=2", "--memory=4g", "--memory-swap=4g", "--pids-limit=1024",
            "--device-cgroup-rule=c 10:200 rwm",
            "--cap-add=SYS_ADMIN", "--cap-drop=AUDIT_WRITE",
            "--security-opt=seccomp=unconfined", "--security-opt=apparmor=unconfined",
            "--security-opt=writable-cgroups=true", "--stop-signal=SIGRTMIN+3",
            "--tmpfs=/run:rw,nosuid,nodev,mode=755", "--tmpfs=/run/lock:rw,nosuid,nodev,mode=755",
            "--tmpfs=/tmp:rw,nosuid,nodev,mode=1777,size=256m",
            "--entrypoint=/bin/bash"]
    for key, value in labels.items():
        argv += ["--label", f"{key}={value}"]
    return argv + [image, "/opt/oxibelt-preflight/riscv-native-sandbox-bootstrap.sh"]


class Preflight:
    def __init__(self, output: Path):
        self.probe = load_probe()
        self.output = output.absolute()
        self.identity = self.probe.github_identity(dict(os.environ))
        sha = self.identity.get("GITHUB_SHA", "")
        run = self.identity.get("GITHUB_RUN_ID", "")
        attempt = self.identity.get("GITHUB_RUN_ATTEMPT", "")
        if not sha or not run or not attempt:
            raise Failure("requires-workflow-source-run-and-attempt")
        if self.output.is_symlink() or not self.output.is_dir() or self.output.resolve() != self.output:
            raise Failure("requires-existing-private-evidence-directory")
        if self.output.stat().st_mode & 0o077:
            raise Failure("requires-private-evidence-directory")
        self.labels = {SOURCE_LABEL: sha, RUN_LABEL: f"{run}-{attempt}"}
        self.name = f"oxibelt-native-{run}-{attempt}"
        self.env = {"PATH": "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin",
                    "HOME": os.path.expanduser("~"), "LC_ALL": "C",
                    "DOCKER_CONFIG": str(self.output / "docker-config"), "PYTHONDONTWRITEBYTECODE": "1"}
        self.container: str | None = None
        self.creation_attempted = False
        self.parent: str | None = None
        self.baseline: dict[str, list[str]] | None = None
        self.base_image_id: str | None = None
        self.receipt = {"schema_version": 1, "identity": self.identity, "supported": False,
                        "stage": "runner-prerequisites",
                        "scope": "native-rootless-sandbox-resource-enforcement", "cleanup_confirmed": False}

    def command(self, args: list[str], timeout: int = 30, allow_failure: bool = False) -> bytes:
        code, output = execute(["docker", "--host", SOCKET, *args], self.env, timeout)
        if code and not allow_failure:
            # Do not expose arbitrary CLI diagnostics, credentials, or command arguments.
            raise Failure("provider-docker-command-failed")
        return output

    def owned_container(self) -> dict:
        """Only immutable container identity and job labels authorize deletion."""
        assert self.container
        result = json.loads(self.command(["inspect", self.container]))
        if not isinstance(result, list) or len(result) != 1:
            raise Failure("invalid-sandbox-inspection")
        state = mapping(result[0], "invalid-sandbox-inspection")
        if state.get("Id") != self.container or state.get("Name") != "/" + self.name:
            raise Failure("sandbox-identity-mismatch")
        config = mapping(state.get("Config"), "invalid-sandbox-config")
        actual = mapping(config.get("Labels"), "invalid-sandbox-labels")
        if any(actual.get(k) != v for k, v in self.labels.items()):
            raise Failure("sandbox-label-mismatch")
        return state

    def container_state(self) -> dict:
        state = self.owned_container()
        host = mapping(state.get("HostConfig"), "invalid-sandbox-host-config")
        mapping(state.get("State"), "invalid-sandbox-process-state")
        if (host.get("Privileged") is not False or host.get("CgroupParent") != self.parent
            or host.get("CgroupnsMode") != "private" or host.get("NetworkMode") != "bridge"
            or host.get("PidMode") not in ("", "private") or host.get("Binds") or host.get("Mounts")
            or host.get("NanoCpus") != 2000000000 or host.get("Memory") != 4294967296
            or host.get("MemorySwap") != 4294967296 or host.get("PidsLimit") != 1024
            or host.get("DeviceCgroupRules") != ["c 10:200 rwm"]
            or self.base_image_id is not None and state.get("Image") != self.base_image_id):
            raise Failure("sandbox-runtime-boundary-mismatch")
        return state

    def verify_running_boundary(self, *, require_network: bool = False):
        state = self.container_state()
        pid = state["State"].get("Pid")
        if type(pid) is not int or pid <= 1 or not self.parent:
            raise Failure("sandbox-process-unavailable")
        probe = self.probe.Probe()
        process = Path("/proc") / str(pid)
        group = probe.read(process / "cgroup").strip()
        expected = "0::" + self.parent + "/" + str(self.container)
        # Retain only a bounded canonical unified path, without raw proc data.
        if (len(group) <= 4096 and re.fullmatch(r"0::/[A-Za-z0-9_./-]*", group)
            and not any(part in (".", "..") for part in group[3:].split("/"))):
            self.receipt["pid1_cgroup"] = {"owned_root": expected[3:], "path": group[3:]}
        # Pinned systemd moves PID 1 into its init.scope below the owned root.
        # Accept only that exact lifecycle transition, never arbitrary children.
        if group not in (expected, expected + "/init.scope") or group == probe.read(Path("/proc/self/cgroup")).strip():
            raise Failure("sandbox-process-outside-owned-cgroup")
        if group.endswith("/init.scope"):
            manager = self.command(["exec", str(self.container), "cat", "/proc/1/comm"]).strip()
            if manager != b"systemd":
                raise Failure("sandbox-process-outside-owned-cgroup")
        for namespace in ("pid", "net", "mnt", "cgroup"):
            outer = os.stat(Path("/proc/self/ns") / namespace)
            # /proc/<root-pid>/ns is ptrace-protected from the outer nonroot
            # runner. Inspect the same namespace read-only inside its container.
            child = self.command(["exec", str(self.container), "stat", "--dereference",
                                  "--format=%d:%i", f"/proc/1/ns/{namespace}"]).decode().strip()
            if not re.fullmatch(r"[0-9]+:[0-9]+", child) or child == f"{outer.st_dev}:{outer.st_ino}":
                raise Failure("sandbox-namespace-not-private")
        mounts = self.command(["exec", str(self.container), "cat", "/proc/1/mountinfo"]).decode()
        network = load_network_probe()
        try:
            network.validate_mounts(mounts, require_network=require_network, require_helper=require_network,
                                    require_sys_helper=require_network)
            if require_network:
                for kind, parent in (("proc", network.PROC_PARENT), ("sys", network.SYS_PARENT)):
                    metadata = self.command(["exec", str(self.container), "stat", "--format=%u:%g:%a:%F",
                                             str(parent)]).decode().strip()
                    if metadata != "0:0:700:directory":
                        raise Failure("sandbox-" + kind + "-helper-directory-mismatch")
        except ValueError as error:
            raise Failure("sandbox-kernel-mount-boundary-mismatch") from error

    def check_ancestors(self):
        if self.parent and self.baseline is not None and controls(self.parent) != self.baseline:
            raise Failure("external-cgroup-controller-state-changed")

    def inner(self, args: list[str], timeout: int = 30, allow_failure: bool = False) -> bytes:
        assert self.container
        env = ["PATH=/home/runner/native-tools/bin:/usr/local/bin:/usr/bin:/bin",
               "HOME=/home/runner", "XDG_RUNTIME_DIR=/run/user/1001",
               "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1001/bus",
               "DOCKER_HOST=unix:///run/user/1001/docker.sock", "PYTHONDONTWRITEBYTECODE=1"]
        for key, value in self.identity.items():
            env.append(f"{key}={value}")
        argv = ["exec", "--user=1001:1001"]
        for entry in env:
            argv += ["--env", entry]
        return self.command(argv + [self.container, *args], timeout, allow_failure)

    def copy_json(self, filename: str):
        assert self.container
        destination = self.output / filename
        if destination.exists() or destination.is_symlink():
            raise Failure("evidence-output-already-exists")
        self.command(["cp", f"{self.container}:/home/runner/evidence/{filename}", str(destination)])
        data = json.loads(self.probe.Probe().read(destination))
        mapping(data, "invalid-inner-evidence")
        if filename in {"sandbox.json", "enforcement.json"}:
            if data.get("identity") != self.identity:
                raise Failure("inner-evidence-identity-mismatch")
            if data.get("supported") is not True:
                raise Failure("inner-qualification-failed")
        if filename == "network-sysctl.json":
            try:
                load_network_probe().validate_receipt(data)
            except ValueError as error:
                raise Failure("inner-network-qualification-failed") from error
        if filename == "proc-mount.json":
            try:
                load_proc_probe().validate_receipt(data, expected_identity=self.identity)
            except ValueError as error:
                raise Failure("inner-proc-mount-qualification-failed") from error
        if filename == "sys-mount.json":
            try:
                load_sys_probe().validate_receipt(data, expected_identity=self.identity)
            except ValueError as error:
                raise Failure("inner-sys-mount-qualification-failed") from error
        return data


    def qualify_proc(self):
        self.verify_running_boundary(require_network=True)
        proc = self.copy_json("proc-mount.json")
        for key, namespace in (("sandbox_pidns", "pid"), ("sandbox_mntns", "mnt")):
            actual = self.command(["exec", self.container, "stat", "--dereference",
                                   "--format=%i", f"/proc/1/ns/{namespace}"]).decode().strip()
            if not re.fullmatch(r"[0-9]+", actual) or proc[key] != int(actual):
                raise Failure("proc-evidence-sandbox-namespace-mismatch")
        native = proc["native"]
        if (native["lock_sha256"] != hashlib.sha256((HERE / "riscv-native-tools.lock.json").read_bytes()).hexdigest()
            or native["probe_sha256"] != hashlib.sha256((HERE / "check-riscv-proc-mount.py").read_bytes()).hexdigest()):
            raise Failure("proc-evidence-source-mismatch")
        self.receipt["proc_mount"] = proc


    def qualify_network(self):
        self.verify_running_boundary(require_network=True)
        network = self.copy_json("network-sysctl.json")
        actual_netns = self.command(["exec", self.container, "stat", "--dereference",
                                    "--format=%i", "/proc/1/ns/net"]).decode().strip()
        if (not re.fullmatch(r"[0-9]+", actual_netns)
            or network["sandbox_netns"] != int(actual_netns)):
            raise Failure("network-evidence-sandbox-namespace-mismatch")
        self.receipt["network"] = network

    def qualify_sys(self):
        self.verify_running_boundary(require_network=True)
        sys_mount = self.copy_json("sys-mount.json")
        for key, namespace in (("sandbox_pidns", "pid"), ("sandbox_mntns", "mnt"), ("sandbox_netns", "net")):
            actual = self.command(["exec", self.container, "stat", "--dereference",
                                   "--format=%i", f"/proc/1/ns/{namespace}"]).decode().strip()
            if not re.fullmatch(r"[0-9]+", actual) or sys_mount[key] != int(actual):
                raise Failure("sys-evidence-sandbox-namespace-mismatch")
        native = sys_mount["native"]
        if (native["lock_sha256"] != hashlib.sha256((HERE / "riscv-native-tools.lock.json").read_bytes()).hexdigest()
            or native["probe_sha256"] != hashlib.sha256((HERE / "check-riscv-sys-mount.py").read_bytes()).hexdigest()):
            raise Failure("sys-evidence-source-mismatch")
        if (sys_mount.get("schema_version") in (2, 3)
            and native["observer_sha256"] != hashlib.sha256((HERE / "riscv-network-observation.py").read_bytes()).hexdigest()):
            raise Failure("sys-evidence-source-mismatch")
        self.receipt["sys_mount"] = sys_mount

    def qualify_tools(self):
        self.receipt["tools"] = self.copy_json("native-tools.json")
        for kind in ("proc", "sys"):
            if (self.receipt[kind + "_mount"]["native"]["rootlesskit_sha256"]
                != self.receipt["tools"]["binaries"]["rootlesskit"]["sha256"]):
                raise Failure(kind + "-evidence-rootlesskit-mismatch")

    def prepare_image(self, lock: dict) -> str:
        self.receipt["stage"] = "native-image"
        base = mapping(lock.get("baseImage"), "invalid-sandbox-image-lock")
        index, native = base.get("indexDigest"), base.get("nativeDigest")
        if any(not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value)
               for value in (index, native)):
            raise Failure("sandbox-base-must-be-pinned")
        index_ref = "docker.io/library/debian:trixie@" + index
        native_ref = "docker.io/library/debian:trixie@" + native
        manifest = mapping(json.loads(self.command(["manifest", "inspect", index_ref], timeout=120)),
                           "invalid-sandbox-index")
        entries = manifest.get("manifests")
        if manifest.get("schemaVersion") != 2 or not isinstance(entries, list):
            raise Failure("invalid-sandbox-index")
        native_entries = []
        for entry in entries:
            entry = mapping(entry, "invalid-sandbox-index-entry")
            platform = mapping(entry.get("platform"), "invalid-sandbox-index-platform")
            if platform.get("os") == "linux" and platform.get("architecture") == "riscv64":
                native_entries.append(entry.get("digest"))
        if native_entries != [native]:
            raise Failure("sandbox-native-child-pin-mismatch")
        self.command(["pull", "--platform=linux/riscv64", native_ref], timeout=600)
        images = json.loads(self.command(["image", "inspect", native_ref]))
        if not isinstance(images, list) or len(images) != 1:
            raise Failure("invalid-sandbox-image-inspection")
        image = mapping(images[0], "invalid-sandbox-image-inspection")
        identifier, repo_digests = image.get("Id"), image.get("RepoDigests")
        expected_repos = {prefix + "@" + native for prefix in (
            "debian", "library/debian", "docker.io/library/debian")}
        if (image.get("Architecture") != "riscv64" or image.get("Os") != "linux"
            or not isinstance(identifier, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", identifier)
            or not isinstance(repo_digests, list) or not any(value in expected_repos for value in repo_digests
                                                          if isinstance(value, str))):
            raise Failure("sandbox-native-image-mismatch")
        self.base_image_id = identifier
        self.receipt["base_image"] = {"index_reference": index_ref, "native_reference": native_ref,
                                     "native_digest": native, "config_id": identifier,
                                     "architecture": "riscv64", "os": "linux"}
        return native_ref

    def observe_bootstrap_phase(self):
        """Apply only a bounded diagnostic hint from the exact owned container."""
        self.owned_container()
        try:
            phase = self.inner(["python3", "-I", "-c", PHASE_READER], allow_failure=True).strip()
        except (Failure, OSError):
            return
        if phase in (b"proc-mount", b"network", b"sys-mount", b"native-tools"):
            self.receipt["stage"] = phase.decode("ascii")

    def wait_ready(self):
        assert self.container
        started = time.monotonic()
        deadline, progress = started + 100 * 60, started
        while time.monotonic() < deadline:
            now = time.monotonic()
            if now >= progress:
                print(f"Native sandbox tool preparation pending ({int((now - started) // 60)} minutes elapsed).", flush=True)
                progress = now + 60
            state = self.container_state()
            if state["State"].get("Running") is not True:
                raise Failure("sandbox-bootstrap-exited")
            self.observe_bootstrap_phase()
            if "proc_mount" not in self.receipt and self.command([
                "exec", self.container, "/bin/sh", "-c",
                "if test -f /home/runner/proc-preflight-ready; then printf ready; fi",
            ]).strip() == b"ready":
                self.receipt["stage"] = "proc-mount"
                self.qualify_proc()
                print("Native isolated procfs mounting verified; tool compilation pending.", flush=True)
            if "network" not in self.receipt and self.command([
                "exec", self.container, "/bin/sh", "-c",
                "if test -f /home/runner/network-preflight-ready; then printf ready; fi",
            ]).strip() == b"ready":
                self.receipt["stage"] = "network"
                self.qualify_network()
                print("Native detached network forwarding verified; tool compilation pending.", flush=True)
            if "sys_mount" not in self.receipt and self.command([
                "exec", self.container, "/bin/sh", "-c",
                "if test -f /home/runner/sys-preflight-ready; then printf ready; fi",
            ]).strip() == b"ready":
                self.receipt["stage"] = "sys-mount"
                self.qualify_sys()
                print("Native isolated readonly sysfs mounting verified; tool compilation pending.", flush=True)
            code, _ = execute(["docker", "--host", SOCKET, "exec", self.container, "/bin/sh", "-c",
                               "test ! -f /home/runner/preflight-failed && test -f /home/runner/preflight-ready"], self.env)
            if code == 0:
                return
            if self.command(["exec", self.container, "/bin/sh", "-c", "if test -f /home/runner/preflight-failed; then printf failed; fi"]).strip() == b"failed":
                # Earlier successful qualifications can have changed stage.
                self.observe_bootstrap_phase()
                raise Failure("sandbox-tool-bootstrap-failed")
            time.sleep(5)
        raise Failure("sandbox-bootstrap-timeout")

    def record_runtime_versions(self, version) -> None:
        """Version observations supplement the mandatory native daemon boundary."""
        provider = self.receipt["provider_daemon"]
        components = {}
        observations = {"components_field": "invalid", "entries_inspected": 0,
                        "unknown_entries": 0, "malformed_entries": 0, "unrecognized_versions": []}
        provider["runtime_components"] = components
        provider["runtime_version_observations"] = observations
        entries = version.get("Components") if isinstance(version, dict) else None
        if isinstance(entries, list):
            observations["components_field"] = "list"
            observations["entries_inspected"] = min(len(entries), 32)
            observations["entries_truncated"] = len(entries) > 32
            for component in entries[:32]:
                if not isinstance(component, dict):
                    observations["malformed_entries"] += 1
                    continue
                name = component.get("Name")
                if not isinstance(name, str) or name not in ("Engine", "containerd", "runc", "docker-init"):
                    observations["unknown_entries"] += 1
                    continue
                parsed = runtime_version(component.get("Version"), name)
                if parsed is None:
                    if name not in observations["unrecognized_versions"]:
                        observations["unrecognized_versions"].append(name)
                    continue
                item = {"version": parsed, "source": "daemon-components"}
                details = component.get("Details")
                commit = runtime_commit(details.get("GitCommit")) if isinstance(details, dict) else None
                if commit:
                    item["commit"] = commit
                components[name] = item
        elif isinstance(version, dict) and "Components" not in version:
            observations["components_field"] = "missing"
        fallbacks = {}
        provider["runtime_version_fallbacks"] = fallbacks
        for name in ("containerd", "runc"):
            if name in components:
                continue
            fallback = {"status": "unavailable", "source": "runner-binary"}
            fallbacks[name] = fallback
            try:
                code, output = execute([name, "--version"], self.env, timeout=15)
            except (Failure, OSError):
                continue
            if code:
                fallback["status"] = "command-failed"
                continue
            if len(output) > 4096:
                fallback["status"] = "unrecognized"
                continue
            try:
                lines = output.decode("ascii").splitlines()
            except UnicodeDecodeError:
                fallback["status"] = "unrecognized"
                continue
            parsed = runtime_version(lines[0], name) if lines else None
            if parsed is None:
                fallback["status"] = "unrecognized"
                continue
            item = {"version": parsed, "source": "runner-binary"}
            if name == "containerd":
                commit = runtime_commit(lines[0].split()[-1])
            else:
                commit = None
                for line in lines[1:8]:
                    matched = re.fullmatch(r"commit:?[ \t]+(?:v[0-9][A-Za-z0-9.+-]{0,63}-g)?([0-9a-f]{7,64})", line)
                    if matched:
                        commit = runtime_commit(matched.group(1))
                        break
            if commit:
                item["commit"] = commit
            components[name] = item
            fallback["status"] = "observed"

    def provision(self):
        self.receipt["stage"] = "runner-prerequisites"
        outer = self.probe.Probe().run(dict(os.environ), phase="runner")
        self.probe.write_evidence(self.output / "runner.json", outer)
        if not outer["supported"]:
            raise Failure("runner-prerequisites-failed")
        self.parent = outer["sandbox_cgroup_parent"]
        self.baseline = controls(self.parent)
        self.receipt["stage"] = "provider-daemon"
        info = mapping(json.loads(self.command(["info", "--format", "{{json .}}" ])), "invalid-provider-daemon-evidence")
        security = info.get("SecurityOptions")
        server_version = info.get("ServerVersion")
        if (info.get("Architecture") != "riscv64" or info.get("CgroupVersion") != "2"
            or info.get("CgroupDriver") != "cgroupfs"
            or not isinstance(security, list) or any(not isinstance(value, str) or "rootless" in value for value in security)
            or not isinstance(server_version, str) or not re.fullmatch(r"(?:28|29)\.[0-9]+\.[0-9]+", server_version)):
            raise Failure("unsupported-provider-daemon")
        self.receipt["provider_daemon"] = {key: info[key] for key in (
            "Architecture", "CgroupVersion", "CgroupDriver", "ServerVersion")}
        try:
            version = json.loads(self.command(["version", "--format", "{{json .Server}}"] ))
        except (Failure, OSError, ValueError):
            version = None
        self.record_runtime_versions(version)
        lock = mapping(json.loads((HERE / "riscv-native-tools.lock.json").read_text()), "invalid-sandbox-tool-lock")
        image = self.prepare_image(lock)
        self.check_ancestors()
        existing = self.command(["ps", "--all", "--filter", f"name=^/{self.name}$", "--format", "{{.ID}}"])
        if existing.strip():
            raise Failure("sandbox-name-already-in-use")
        self.probe.write_evidence(self.output / "creation-intent.json", {
            "name": self.name, "labels": self.labels, "parent": self.parent, "ancestors": self.baseline,
        })
        self.creation_attempted = True
        self.receipt["stage"] = "sandbox-create"
        raw = self.command(sandbox_arguments(self.parent, image, self.name, self.labels), timeout=300).decode().strip()
        if not re.fullmatch(r"[0-9a-f]{64}", raw):
            raise Failure("invalid-sandbox-container-id")
        self.container = raw
        self.probe.write_evidence(self.output / "sandbox-state.json", {
            "container": self.container, "name": self.name, "labels": self.labels,
            "parent": self.parent, "ancestors": self.baseline,
        })
        self.container_state()
        self.receipt["stage"] = "sandbox-staging"
        with tempfile.TemporaryDirectory(prefix="oxibelt-native-bootstrap-") as temporary:
            staging = Path(temporary) / "oxibelt-preflight"
            staging.mkdir(mode=0o755)
            staging.chmod(0o755)
            for filename in FILES:
                shutil.copyfile(HERE / filename, staging / filename, follow_symlinks=False)
                (staging / filename).chmod(0o644)
            identity = staging / "workflow-identity.json"
            identity.write_text(json.dumps(self.identity, sort_keys=True) + "\n")
            identity.chmod(0o644)
            self.command(["cp", str(staging), f"{raw}:/opt/"])
        self.receipt["stage"] = "sandbox-start"
        self.command(["start", raw])
        self.check_ancestors()
        self.receipt["stage"] = "sandbox-boundary"
        self.verify_running_boundary()
        self.receipt["stage"] = "sandbox-bootstrap"
        self.wait_ready()
        self.verify_running_boundary(require_network=True)
        self.check_ancestors()
        if "network" not in self.receipt:
            self.qualify_network()
        if "proc_mount" not in self.receipt:
            self.receipt["stage"] = "proc-mount"
            self.qualify_proc()
        if "sys_mount" not in self.receipt:
            self.receipt["stage"] = "sys-mount"
            self.qualify_sys()
        self.qualify_tools()
        self.receipt["stage"] = "sandbox-prerequisites"
        self.inner(["python3", "/opt/oxibelt-preflight/check-riscv-native-runner.py", "--phase", "sandbox",
                    "--output", "/home/runner/evidence/sandbox.json"], allow_failure=True)
        self.copy_json("sandbox.json")
        self.receipt["stage"] = "rootless-enforcement"
        self.inner(["python3", "/opt/oxibelt-preflight/check-riscv-rootless-enforcement.py",
                    "--output", "/home/runner/evidence/enforcement.json"], timeout=600, allow_failure=True)
        self.receipt["enforcement"] = self.copy_json("enforcement.json")
        self.check_ancestors()
        self.receipt["stage"] = "qualified"

    def cleanup(self):
        if not self.container and self.creation_attempted:
            self.recover_container()
        if not self.container:
            self.receipt["cleanup_confirmed"] = True
            return
        state = self.owned_container()
        try:
            self.collect_diagnostics(state)
        finally:
            self.remove_container()

    def collect_diagnostics(self, state: dict):
        collection = []

        def collect(filename, action):
            destination = self.output / filename
            if destination.is_symlink():
                collection.append({"filename": filename, "status": "unavailable",
                                   "diagnostic": "evidence-output-symlink"})
                return
            if destination.exists():
                collection.append({"filename": filename, "status": "existing"})
                return
            try:
                action(destination)
                collection.append({"filename": filename, "status": "collected"})
            except (Failure, OSError, ValueError) as error:
                diagnostic = str(error) if isinstance(error, Failure) else "evidence-collection-failed"
                collection.append({"filename": filename, "status": "unavailable", "diagnostic": diagnostic})

        def write_exit(destination):
            self.probe.write_evidence(destination, {
                "schema_version": 1, "identity": self.identity, "container": self.container,
                "state": sanitized_exit_state(state),
            })

        collect("sandbox-exit.json", write_exit)

        def copy_file(filename, destination):
            code, raw = execute(["docker", "--host", SOCKET, "cp",
                                 f"{self.container}:/home/runner/evidence/{filename}", "-"],
                                self.env, timeout=30, maximum=MAX_ARCHIVE_BYTES)
            if code:
                raise Failure("evidence-copy-failed")
            data = archive_evidence(raw, filename)
            if filename.endswith(".json"):
                validate_collected_json(data)
                if filename == "bootstrap-phase.json":
                    validate_bootstrap_phase(data)
            with destination.open("xb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(data)

        for filename in EVIDENCE_LOGS + EVIDENCE_JSON:
            collect(filename, lambda destination, filename=filename: copy_file(filename, destination))

        def write_bootstrap_log(destination):
            code, logs = execute(["docker", "--host", SOCKET, "logs", "--tail=150", self.container],
                                 self.env, timeout=30)
            if code:
                raise Failure("bootstrap-log-command-failed")
            with destination.open("xb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(logs[-MAX_EVIDENCE_BYTES:])

        collect("bootstrap.log", write_bootstrap_log)
        try:
            destination = self.output / "evidence-collection.json"
            if not destination.exists() and not destination.is_symlink():
                self.probe.write_evidence(destination, {"schema_version": 1, "identity": self.identity,
                                                       "container": self.container, "files": collection})
        except OSError:
            # Diagnostic write failures must not bypass exact-container removal.
            pass

    def remove_container(self):
        try:
            self.command(["stop", "--time=15", self.container], timeout=30, allow_failure=True)
        except (Failure, OSError):
            pass
        self.command(["rm", "--force", self.container])
        remaining = self.command(["ps", "--all", "--no-trunc", "--filter", f"id={self.container}",
                                  "--format", "{{.ID}}"])
        if remaining.strip():
            raise Failure("sandbox-cleanup-incomplete")
        self.check_ancestors()
        self.receipt["cleanup_confirmed"] = True

    def recover_container(self):
        """Recover only the exact newly requested name and immutable run labels."""
        matches = self.command(["ps", "--all", "--no-trunc", "--filter", f"name=^/{self.name}$",
                                "--format", "{{.ID}}"] ).decode().split()
        if len(matches) != 1 or not re.fullmatch(r"[0-9a-f]{64}", matches[0]):
            raise Failure("sandbox-creation-outcome-unconfirmed")
        self.container = matches[0]
        self.owned_container()

    def run(self) -> int:
        diagnostic = None
        persistence_diagnostic = None
        try:
            self.provision()
        except (Failure, OSError, ValueError, KeyError) as error:
            diagnostic = str(error) if isinstance(error, Failure) else "preflight-evidence-or-command-failed"
        finally:
            try:
                self.cleanup()
            except (Failure, OSError, ValueError, KeyError):
                diagnostic = "sandbox-cleanup-or-ancestor-verification-failed"
            self.receipt["supported"] = diagnostic is None and self.receipt["cleanup_confirmed"]
            if diagnostic:
                self.receipt["diagnostic"] = diagnostic
            try:
                self.probe.write_evidence(self.output / "preflight.json", self.receipt,
                                          maximum_bytes=MAX_PREFLIGHT_RECEIPT_BYTES)
            except (OSError, ValueError, KeyError, TypeError) as error:
                persistence_diagnostic = (
                    "preflight-receipt-too-large"
                    if isinstance(error, self.probe.ProbeError) and str(error) == "evidence-too-large"
                    else "preflight-receipt-write-failed"
                )
        if persistence_diagnostic:
            print("Native rootless preflight could not preserve valid qualification evidence: "
                  + persistence_diagnostic, file=sys.stderr)
            return 2
        print("Native rootless preflight passed." if not diagnostic else f"Native rootless preflight failed: {diagnostic}")
        return int(diagnostic is not None)


def cleanup_from_state(output: Path) -> int:
    preflight = Preflight(output)
    state_path = output / "sandbox-state.json"
    if not state_path.exists():
        state_path = output / "creation-intent.json"
        if not state_path.exists():
            return 0
    state = mapping(json.loads(preflight.probe.Probe().read(state_path)), "invalid-cleanup-state")
    if (state.get("labels") != preflight.labels or state.get("name") != preflight.name
        or ("container" in state and (not isinstance(state["container"], str)
                                    or not re.fullmatch(r"[0-9a-f]{64}", state["container"])))):
        raise Failure("cleanup-state-identity-mismatch")
    preflight.parent = state["parent"]
    if not isinstance(preflight.parent, str):
        raise Failure("invalid-cleanup-parent")
    preflight.baseline = mapping(state["ancestors"], "invalid-cleanup-ancestors")
    if "container" not in state:
        # A preceding normal cleanup receipt settles the creation outcome.
        receipt_path = output / "preflight.json"
        if receipt_path.exists():
            receipt = mapping(json.loads(preflight.probe.Probe().read(receipt_path)), "invalid-cleanup-receipt")
            if receipt.get("identity") == preflight.identity and receipt.get("cleanup_confirmed") is True:
                preflight.check_ancestors()
                return 0
        preflight.creation_attempted = True
        preflight.cleanup()
        return 0
    preflight.container = state["container"]
    remaining = preflight.command(["ps", "--all", "--no-trunc", "--filter", f"id={preflight.container}", "--format", "{{.ID}}"])
    if remaining.strip():
        preflight.cleanup()
    else:
        preflight.check_ancestors()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--cleanup", action="store_true")
    args = parser.parse_args()
    def interrupted(_signum, _frame):
        raise Failure("preflight-interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        return cleanup_from_state(args.output_dir) if args.cleanup else Preflight(args.output_dir).run()
    except (Failure, OSError, ValueError, KeyError):
        print("Native rootless preflight could not preserve valid qualification evidence.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
