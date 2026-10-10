#!/usr/bin/env python3
"""Provision and qualify one disposable native rootless Docker sandbox.

Only the explicit provider socket manages trusted infrastructure. Qualification
uses the inner user's socket. No cgroup, namespace, or daemon fallback is used.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path, PurePosixPath


HERE = Path(__file__).resolve().parent
SOCKET = "unix:///var/run/docker.sock"
MAX_BYTES = 128 * 1024
SOURCE_LABEL = "org.oxibelt.preflight.source"
RUN_LABEL = "org.oxibelt.preflight.run"
VERSION_TOKEN = r"v?[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(?:[-+][A-Za-z0-9][A-Za-z0-9.+~:-]{0,63})?"
FILES = (
    "riscv-native-sandbox-bootstrap.sh", "riscv-native-sandbox-build-tools.sh",
    "riscv-native-tools.lock.json", "check-riscv-native-runner.py",
    "check-riscv-rootless-enforcement.py", "riscv-rootless-limit-probe.c",
)


class Failure(RuntimeError):
    pass


def mapping(value, diagnostic: str) -> dict:
    if not isinstance(value, dict):
        raise Failure(diagnostic)
    return value


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


def execute(argv: list[str], env: dict[str, str], timeout: int = 30) -> tuple[int, bytes]:
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
                if len(output) > MAX_BYTES:
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
            or self.base_image_id is not None and state.get("Image") != self.base_image_id):
            raise Failure("sandbox-runtime-boundary-mismatch")
        return state

    def verify_running_boundary(self):
        state = self.container_state()
        pid = state["State"].get("Pid")
        if type(pid) is not int or pid <= 1 or not self.parent:
            raise Failure("sandbox-process-unavailable")
        probe = self.probe.Probe()
        process = Path("/proc") / str(pid)
        group = probe.read(process / "cgroup").strip()
        expected = "0::" + self.parent + "/" + str(self.container)
        if group != expected or group == probe.read(Path("/proc/self/cgroup")).strip():
            raise Failure("sandbox-process-outside-owned-cgroup")
        for namespace in ("pid", "net", "mnt", "cgroup"):
            outer = os.stat(Path("/proc/self/ns") / namespace)
            # /proc/<root-pid>/ns is ptrace-protected from the outer nonroot
            # runner. Inspect the same namespace read-only inside its container.
            child = self.command(["exec", str(self.container), "stat", "--dereference",
                                  "--format=%d:%i", f"/proc/1/ns/{namespace}"]).decode().strip()
            if not re.fullmatch(r"[0-9]+:[0-9]+", child) or child == f"{outer.st_dev}:{outer.st_ino}":
                raise Failure("sandbox-namespace-not-private")
        mounts = {}
        for line in self.command(["exec", str(self.container), "cat", "/proc/1/mountinfo"]).decode().splitlines():
            fields = line.split()
            if len(fields) >= 6:
                mounts[fields[4]] = set(fields[5].split(","))
        if ("ro" not in mounts.get("/sys", set()) or "ro" not in mounts.get("/proc/sys", set())
            or "rw" not in mounts.get("/sys/fs/cgroup", set())):
            raise Failure("sandbox-kernel-mount-boundary-mismatch")

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
        return data

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
            code, _ = execute(["docker", "--host", SOCKET, "exec", self.container, "/bin/sh", "-c",
                               "test ! -f /home/runner/preflight-failed && test -f /home/runner/preflight-ready"], self.env)
            if code == 0:
                return
            if self.command(["exec", self.container, "/bin/sh", "-c", "if test -f /home/runner/preflight-failed; then printf failed; fi"]).strip() == b"failed":
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
            self.command(["cp", str(staging), f"{raw}:/opt/"])
        self.receipt["stage"] = "sandbox-start"
        self.command(["start", raw])
        self.check_ancestors()
        self.receipt["stage"] = "sandbox-boundary"
        self.verify_running_boundary()
        self.receipt["stage"] = "sandbox-bootstrap"
        self.wait_ready()
        self.check_ancestors()
        self.receipt["tools"] = self.copy_json("native-tools.json")
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
        self.owned_container()
        for filename in ("apt-update.log", "apt-bootstrap.log", "apt-install.log", "build-engine.log",
                         "build-cli.log", "build-containerd.log", "build-runc.log", "docker-start.log",
                         "systemd-build-failure.log", "systemd-docker-failure.log"):
            try:
                data = self.command(["exec", self.container, "tail", "-c", "65536", "--",
                                     f"/home/runner/evidence/{filename}"], allow_failure=True)
                with (self.output / filename).open("xb") as stream:
                    os.fchmod(stream.fileno(), 0o600)
                    stream.write(data)
            except (Failure, OSError):
                pass
        try:
            logs = self.command(["logs", "--tail=150", self.container], allow_failure=True)
            with (self.output / "bootstrap.log").open("xb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(logs)
        except (Failure, OSError):
            # A diagnostics failure must never bypass exact-container cleanup.
            pass
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
            self.probe.write_evidence(self.output / "preflight.json", self.receipt)
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
