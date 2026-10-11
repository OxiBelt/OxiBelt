#!/usr/bin/env python3
"""Bounded native CPU, memory, and PID enforcement on the pinned rootless daemon."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import platform
import re
import secrets
import selectors
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

DOCKER = "/home/runner/native-tools/bin/docker"
SOCKET = "unix:///run/user/1001/docker.sock"
LOCK = Path("/opt/oxibelt-preflight/riscv-native-tools.lock.json")
MANIFEST = Path("/home/runner/evidence/native-tools.json")
PROBE_BINARY = Path("/home/runner/limit-probe")
LABEL = "io.oxibelt.native-preflight.token"
MAX_OUTPUT = 65536
COMMAND_TIMEOUT = 120
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
CONTAINER_ID = DIGEST
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
CONTROLS = {
    "schema_version": 1, "architecture": "riscv64", "executable_machine": "riscv64",
    "nonroot": True, "membership": "0::/", "cpu_max": "50000 100000",
    "memory_max": 67108864, "memory_swap_max": 0, "pids_max": 32,
}
IDENTITY = {
    "GITHUB_REPOSITORY": r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",
    "GITHUB_SHA": r"[0-9a-f]{40}", "GITHUB_WORKFLOW_SHA": r"[0-9a-f]{40}",
    "GITHUB_RUN_ID": r"[0-9]{1,24}", "GITHUB_RUN_ATTEMPT": r"[0-9]{1,8}",
    "GITHUB_JOB": r"[A-Za-z0-9_-]+", "GITHUB_REF": r"refs/[A-Za-z0-9_./-]+",
    "GITHUB_WORKFLOW_REF": r"[A-Za-z0-9_./-]+@refs/[A-Za-z0-9_./-]+",
    "GITHUB_EVENT_NAME": r"[a-z_]+",
}


class ProbeError(ValueError):
    pass


def read_file(path: Path, maximum: int = 256 * 1024) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ProbeError("input-not-regular")
            value = stream.read(maximum + 1)
        if len(value) > maximum:
            raise ProbeError("input-too-large")
        return value
    except OSError as error:
        raise ProbeError("input-unavailable") from error


def parse_json(raw: bytes | str):
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProbeError("invalid-json-evidence") from error


def native_elf(raw: bytes, *, static: bool = False) -> None:
    if len(raw) < 64 or raw[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", raw, 18)[0] != 243:
        raise ProbeError("requires-native-riscv64-elf")
    if static:
        kind = struct.unpack_from("<H", raw, 16)[0]
        offset = struct.unpack_from("<Q", raw, 32)[0]
        width, count = struct.unpack_from("<HH", raw, 54)
        if kind != 2 or width != 56 or count == 0 or count > 128 or offset + width * count > len(raw):
            raise ProbeError("invalid-static-probe-elf")
        if any(struct.unpack_from("<I", raw, offset + index * width)[0] in (2, 3) for index in range(count)):
            raise ProbeError("probe-must-be-static")


def prerequisites() -> dict:
    if platform.system() != "Linux" or platform.machine() != "riscv64" or os.getuid() != 1001 or os.geteuid() != 1001:
        raise ProbeError("requires-native-nonroot-runner-1001")
    try:
        with open("/proc/self/exe", "rb") as stream:
            native_elf(stream.read(64))
    except OSError as error:
        raise ProbeError("executing-elf-unavailable") from error
    lock_bytes = read_file(LOCK)
    lock = parse_json(lock_bytes)
    try:
        if lock["schemaVersion"] != 1 or lock["sources"]["engine"]["version"] != "29.8.0" or lock["sources"]["cli"]["version"] != "29.8.0":
            raise ProbeError("unexpected-tool-lock")
        source_digest = lock["probeSourceSha256"]
        if not isinstance(source_digest, str) or not DIGEST.fullmatch(source_digest):
            raise ProbeError("invalid-probe-source-pin")
        if hashlib.sha256(read_file(Path(__file__).with_name("riscv-rootless-limit-probe.c"))).hexdigest() != source_digest:
            raise ProbeError("probe-source-pin-mismatch")
        manifest_bytes = read_file(MANIFEST)
        manifest = parse_json(manifest_bytes)
        if (manifest["schemaVersion"] != 1 or manifest["architecture"] != "riscv64"
            or manifest["lockSha256"] != hashlib.sha256(lock_bytes).hexdigest()):
            raise ProbeError("bootstrap-lock-binding-mismatch")
        digests = {}
        for name, path in (("docker", Path(DOCKER)), ("limit-probe", PROBE_BINARY)):
            raw = read_file(path, 64 * 1024 * 1024)
            native_elf(raw, static=name == "limit-probe")
            actual = hashlib.sha256(raw).hexdigest()
            expected = manifest["binaries"][name]["sha256"]
            if (manifest["binaries"][name]["elfMachine"] != 243
                or not isinstance(expected, str) or not DIGEST.fullmatch(expected) or actual != expected):
                raise ProbeError("bootstrap-binary-digest-mismatch")
            digests[name] = actual
    except (KeyError, TypeError) as error:
        raise ProbeError("invalid-bootstrap-evidence") from error
    return {"architecture": "riscv64", "executing_elf": "riscv64", "nonroot": True,
            "lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
            "bootstrap_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(), "binaries": digests}


class Docker:
    def __init__(self, config: Path):
        self.deadline = time.monotonic() + 420
        self.operation = "initialization"
        self.first_failure = None
        self.failure_log = b""
        self.last_result = None
        self.stdout = bytearray()
        self.stderr = bytearray()
        self.env = {"HOME": "/home/runner", "USER": "runner", "LOGNAME": "runner",
                    "PATH": "/home/runner/native-tools/bin:/usr/bin:/bin", "LC_ALL": "C",
                    "XDG_RUNTIME_DIR": "/run/user/1001", "DOCKER_CONFIG": str(config)}

    def begin_cleanup(self) -> None:
        self.deadline = time.monotonic() + 60

    def call(self, arguments: list[str]) -> tuple[int, str]:
        command = "-".join(arguments[:2]) if arguments[0] in {"image", "container"} else arguments[0]
        if command not in {"info", "image-import", "image-inspect", "image-ls", "image-rm",
                           "container-inspect", "container-ls", "create", "start", "wait", "logs", "rm"}:
            raise ProbeError("unsupported-docker-command")
        self.stdout, self.stderr = bytearray(), bytearray()
        self.last_result = {"operation": self.operation, "command": command, "exit_code": None}
        if time.monotonic() >= self.deadline:
            self.remember_failure("docker-phase-timeout")
            raise ProbeError("docker-phase-timeout")
        try:
            process = subprocess.Popen([DOCKER, "--host", SOCKET, *arguments], env=self.env,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        except OSError as error:
            self.remember_failure("docker-command-unavailable")
            raise ProbeError("docker-command-unavailable") from error
        total = 0
        deadline = min(time.monotonic() + COMMAND_TIMEOUT, self.deadline)
        try:
            with selectors.DefaultSelector() as selector:
                assert process.stdout is not None and process.stderr is not None
                selector.register(process.stdout, selectors.EVENT_READ, True)
                selector.register(process.stderr, selectors.EVENT_READ, False)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not (events := selector.select(remaining)):
                        raise ProbeError("docker-command-timeout")
                    for key, _mask in events:
                        raw = os.read(key.fd, MAX_OUTPUT + 1 - total)
                        if not raw:
                            selector.unregister(key.fileobj)
                            continue
                        target = self.stdout if key.data else self.stderr
                        target.extend(raw[:MAX_OUTPUT - total])
                        total += len(raw)
                        if total > MAX_OUTPUT:
                            raise ProbeError("docker-command-output-too-large")
            try:
                code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired as error:
                raise ProbeError("docker-command-timeout") from error
            try:
                self.last_result["exit_code"] = code
                return code, self.stdout.decode("utf-8")
            except UnicodeDecodeError as error:
                raise ProbeError("invalid-docker-output") from error
        except ProbeError as error:
            self.remember_failure(str(error))
            raise
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            if process.stdout:
                process.stdout.close()
            if process.stderr:
                process.stderr.close()

    def checked(self, arguments: list[str]) -> str:
        code, output = self.call(arguments)
        if code:
            self.remember_failure("docker-command-failed")
            raise ProbeError("docker-command-failed")
        return output

    def remember_failure(self, diagnostic: str) -> None:
        if self.first_failure is None:
            self.first_failure = {**self.last_result, "diagnostic": diagnostic}
            header = (json.dumps(self.first_failure, sort_keys=True) + "\nstderr:\n").encode()
            self.failure_log = (header + self.stderr + b"\nstdout:\n" + self.stdout)[:MAX_OUTPUT]


def create_probe_archive(output: Path, expected_digest: str) -> str:
    """Package only a freshly verified static native executable, without a builder."""
    raw = read_file(PROBE_BINARY, 64 * 1024 * 1024)
    native_elf(raw, static=True)
    if (not isinstance(expected_digest, str) or not DIGEST.fullmatch(expected_digest)
        or hashlib.sha256(raw).hexdigest() != expected_digest):
        raise ProbeError("probe-archive-binary-digest-mismatch")
    try:
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                member = tarfile.TarInfo("limit-probe")
                member.type = tarfile.REGTYPE
                member.size = len(raw)
                member.mode = 0o755
                member.uid = member.gid = member.mtime = 0
                member.uname = member.gname = ""
                archive.addfile(member, io.BytesIO(raw))
        return hashlib.sha256(read_file(output, 64 * 1024 * 1024 + 10240)).hexdigest()
    except (OSError, tarfile.TarError) as error:
        raise ProbeError("probe-archive-creation-failed") from error


def validate_info(info: dict) -> dict:
    try:
        security = info["SecurityOptions"]
        if (info["ServerVersion"] != "29.8.0" or info["OSType"] != "linux"
            or info["Architecture"] != "riscv64" or info["CgroupVersion"] != "2"
            or info["CgroupDriver"] != "systemd" or info["Driver"] != "vfs" or not isinstance(security, list)
            or not {"name=rootless", "name=cgroupns", "name=seccomp,profile=builtin"} <= set(security)):
            raise ProbeError("daemon-boundary-mismatch")
    except (KeyError, TypeError) as error:
        raise ProbeError("invalid-daemon-evidence") from error
    return {**{key: info[key] for key in ("ServerVersion", "OSType", "Architecture", "CgroupVersion", "CgroupDriver", "Driver")},
            "SecurityOptions": ["name=rootless", "name=cgroupns", "name=seccomp,profile=builtin"]}


def validate_mode(mode: str, logs: str, state: dict) -> dict:
    if mode not in ("cpu", "memory", "pids") or not isinstance(state, dict):
        raise ProbeError("invalid-limit-evidence")
    lines = logs.splitlines()
    expected_lines = 1 if mode == "memory" else 2
    if len(lines) != expected_lines or parse_json(lines[0]) != CONTROLS:
        raise ProbeError("effective-controls-mismatch")
    if state.get("Status") != "exited":
        raise ProbeError("probe-did-not-exit")
    if mode == "memory":
        if state.get("ExitCode") != 137 or state.get("OOMKilled") is not True:
            raise ProbeError("memory-oom-not-enforced")
        result = {"mode": mode, "oom_killed": True, "exit_code": 137}
    else:
        if state.get("ExitCode") != 0 or state.get("OOMKilled") is not False:
            raise ProbeError("probe-failed")
        result = parse_json(lines[1])
        if not isinstance(result, dict) or result.get("mode") != mode:
            raise ProbeError("invalid-limit-evidence")
        before_key, after_key = ("nr_throttled_before", "nr_throttled_after") if mode == "cpu" else ("pids_max_before", "pids_max_after")
        before, after = result.get(before_key), result.get(after_key)
        if type(before) is not int or type(after) is not int or not 0 <= before < after <= 2**64 - 1:
            raise ProbeError("limit-counter-did-not-increase")
        if mode == "pids" and (result.get("fork_blocked") is not True or result.get("children_reaped") is not True
                               or type(result.get("children")) is not int or not 1 <= result["children"] <= 31):
            raise ProbeError("pid-ceiling-not-enforced")
        allowed = {"mode", before_key, after_key} | ({"children", "fork_blocked", "children_reaped"} if mode == "pids" else set())
        if set(result) != allowed:
            raise ProbeError("unexpected-limit-evidence-fields")
    return {"effective_controls": CONTROLS, "result": result}


class Enforcement:
    def __init__(self, docker: Docker, token: str | None = None):
        self.docker = docker
        self.token = token or secrets.token_hex(16)
        if not re.fullmatch(r"[0-9a-f]{32}", self.token):
            raise ProbeError("invalid-resource-token")
        self.image = "oxibelt-native-limit-probe:" + self.token
        self.names: list[str] = []
        self.image_created = False

    def owned(self, name: str, *, image: bool = False) -> dict | None:
        code, output = self.docker.call(["image" if image else "container", "inspect", name])
        if code:
            # Verify nonexistence through a successful exact list query. Never
            # interpret transport failures as successful cleanup.
            arguments = ["image", "ls", "--no-trunc", "--quiet", "--filter", "reference=" + name] if image else [
                "container", "ls", "--all", "--no-trunc", "--quiet", "--filter", "name=^/" + name + "$"]
            if self.docker.checked(arguments).strip():
                raise ProbeError("resource-inspection-failed")
            return None
        values = parse_json(output)
        if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
            raise ProbeError("invalid-resource-inspection")
        value = values[0]
        identifier = value.get("Id", "")
        if not isinstance(identifier, str) or not (IMAGE_ID if image else CONTAINER_ID).fullmatch(identifier):
            raise ProbeError("invalid-resource-id")
        config = value.get("Config")
        labels = config.get("Labels") if isinstance(config, dict) else None
        if not isinstance(labels, dict) or labels.get(LABEL) != self.token:
            raise ProbeError("resource-ownership-mismatch")
        return value

    def stage(self, receipt: dict, name: str) -> None:
        receipt["stage"] = name
        self.docker.operation = name

    def run(self, receipt: dict) -> None:
        self.stage(receipt, "daemon-info")
        receipt["daemon"] = validate_info(parse_json(self.docker.checked(["info", "--format", "{{json .}}"])))
        # Random tag must be absent before setting ownership; never overwrite.
        self.stage(receipt, "image-precheck")
        if self.owned(self.image, image=True) is not None:
            raise ProbeError("probe-image-already-exists")
        self.stage(receipt, "image-archive")
        try:
            expected_digest = receipt["bootstrap"]["binaries"]["limit-probe"]
        except (KeyError, TypeError) as error:
            raise ProbeError("invalid-bootstrap-evidence") from error
        with tempfile.TemporaryDirectory(prefix="oxibelt-limit-image-") as directory:
            archive = Path(directory) / "probe-rootfs.tar"
            receipt["rootfs_sha256"] = create_probe_archive(archive, expected_digest)
            self.stage(receipt, "image-import")
            self.image_created = True
            imported = self.docker.checked([
                "image", "import", "--platform=linux/riscv64", "--change", "LABEL " + LABEL + "=" + self.token,
                "--change", "USER 1001:1001", "--change", 'ENTRYPOINT ["/limit-probe"]',
                str(archive), self.image]).strip()
            if not IMAGE_ID.fullmatch(imported):
                raise ProbeError("invalid-imported-image-id")
        self.stage(receipt, "image-verify")
        image = self.owned(self.image, image=True)
        if image is None:
            raise ProbeError("probe-image-missing")
        if image["Id"] != imported:
            raise ProbeError("imported-image-identity-mismatch")
        if (image.get("Os") != "linux" or image.get("Architecture") != "riscv64"
            or image["Config"].get("User") != "1001:1001"
            or image["Config"].get("Entrypoint") != ["/limit-probe"]):
            raise ProbeError("probe-image-configuration-mismatch")
        receipt["image_id"] = image["Id"]
        for mode in ("cpu", "memory", "pids"):
            name = "oxibelt-limit-" + mode + "-" + self.token
            self.names.append(name)
            self.stage(receipt, mode + "-create")
            identifier = self.docker.checked([
                "create", "--name", name, "--label", LABEL + "=" + self.token, "--pull=never",
                "--platform=linux/riscv64", "--cgroupns=private", "--network=none", "--read-only",
                "--cap-drop=ALL", "--security-opt=no-new-privileges", "--cpu-period=100000", "--cpu-quota=50000",
                "--memory=64m", "--memory-swap=64m", "--pids-limit=32", image["Id"], mode]).strip()
            if not CONTAINER_ID.fullmatch(identifier):
                raise ProbeError("invalid-created-container-id")
            self.stage(receipt, mode + "-inspect")
            owned = self.owned(name)
            if owned is None or owned["Id"] != identifier:
                raise ProbeError("created-container-identity-mismatch")
            self.stage(receipt, mode + "-start")
            self.docker.checked(["start", identifier])
            self.stage(receipt, mode + "-wait")
            self.docker.checked(["wait", identifier])
            self.stage(receipt, mode + "-inspect")
            owned = self.owned(name)
            if owned is None or owned["Id"] != identifier:
                raise ProbeError("finished-container-identity-mismatch")
            self.stage(receipt, mode + "-logs")
            logs = self.docker.checked(["logs", identifier])
            self.stage(receipt, mode + "-verify")
            evidence = validate_mode(mode, logs, owned.get("State", {}))
            receipt["checks"].append({"mode": mode, "container_id": identifier, "passed": True, **evidence})
        self.stage(receipt, "enforcement-complete")

    def cleanup(self) -> list[str]:
        self.docker.begin_cleanup()
        failures = []
        self.docker.operation = "cleanup-container"
        for name in reversed(self.names):
            try:
                owned = self.owned(name)
                if owned is not None:
                    self.docker.checked(["rm", "--force", owned["Id"]])
                    if self.owned(name) is not None:
                        raise ProbeError("container-cleanup-not-confirmed")
            except ProbeError:
                failures.append("container-cleanup-failed")
        if self.image_created:
            self.docker.operation = "cleanup-image"
            try:
                owned = self.owned(self.image, image=True)
                if owned is not None:
                    self.docker.checked(["image", "rm", owned["Id"]])
                    if self.owned(self.image, image=True) is not None:
                        raise ProbeError("image-cleanup-not-confirmed")
            except ProbeError:
                failures.append("image-cleanup-failed")
        return failures


def write_evidence(output: Path, receipt: dict) -> None:
    absolute = output.absolute()
    if ".." in absolute.parts or absolute.suffix != ".json":
        raise ProbeError("output-requires-new-regular-json-file")
    try:
        if absolute.parent.resolve(strict=True) != absolute.parent:
            raise ProbeError("output-parent-must-not-contain-symlinks")
        raw = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
        if len(raw) > 16384:
            raise ProbeError("evidence-too-large")
        fd = os.open(absolute, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
    except OSError as error:
        raise ProbeError("cannot-create-new-evidence-file") from error


def write_diagnostics(output: Path, raw: bytes) -> None:
    absolute = output.absolute()
    try:
        if ".." in absolute.parts or absolute.parent.resolve(strict=True) != absolute.parent:
            raise ProbeError("output-parent-must-not-contain-symlinks")
        if len(raw) > MAX_OUTPUT:
            raise ProbeError("diagnostics-too-large")
        fd = os.open(absolute, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
    except OSError as error:
        raise ProbeError("cannot-create-new-diagnostics-file") from error


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    receipt = {"schema_version": 1, "supported": False,
               "scope": "native-rootless-cpu-memory-pid-enforcement", "checks": [],
               "identity": {key: value for key, pattern in IDENTITY.items()
                            if (value := os.environ.get(key, "")) and len(value) <= 256 and re.fullmatch(pattern, value)}}
    enforcement = None
    docker = None
    try:
        receipt["bootstrap"] = prerequisites()
        with tempfile.TemporaryDirectory(prefix="oxibelt-limit-docker-config-") as config:
            docker = Docker(Path(config))
            enforcement = Enforcement(docker)
            try:
                enforcement.run(receipt)
            except ProbeError as error:
                # Preserve successful CLI output rejected by semantic checks,
                # before cleanup replaces the last command's buffers.
                if docker.last_result is not None and receipt.get("stage") != "image-archive":
                    docker.remember_failure(str(error))
                raise
            finally:
                failures = enforcement.cleanup()
                receipt["cleanup_confirmed"] = not failures
                if failures:
                    receipt["cleanup_failures"] = failures
            receipt["supported"] = receipt["cleanup_confirmed"] and len(receipt["checks"]) == 3
    except ProbeError as error:
        receipt["failure"] = str(error)
    if docker is not None and docker.first_failure is not None:
        receipt["docker_failure"] = docker.first_failure
    try:
        write_evidence(args.output, receipt)
        write_diagnostics(args.output.parent / "enforcement-docker.log", docker.failure_log if docker is not None else b"")
    except ProbeError as error:
        print("Cannot preserve enforcement receipt: " + str(error), file=sys.stderr)
        return 2
    if not receipt["supported"]:
        print("Native rootless enforcement failed; inspect the bounded receipt.", file=sys.stderr)
        return 1
    print("Native rootless CPU, memory, and PID enforcement and exact-resource cleanup passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
