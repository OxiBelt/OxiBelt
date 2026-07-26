#!/usr/bin/env python3
"""Run the bounded, digest-bound runtime contract for one RISC-V release image."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import http.server
import json
import os
import pathlib
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any, Callable


DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
GIT_OBJECT = re.compile(r"[0-9a-f]{40}\Z")
SOURCE_REF = re.compile(r"refs/tags/[A-Za-z0-9._/-]+\Z")
IMAGE_REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,511}\Z")
BUILD_IDENTITY_MARKER = re.compile(
    r"OXIBELT_BUILD_IDENTITY_V1=(\{[^}\x00\r\n]{1,4096}\})"
)
MAXIMUM_JSON_BYTES = 8 * 1024 * 1024
MAXIMUM_IMAGE_BYTES = 4 * 1024 * 1024 * 1024
MAXIMUM_ARCHIVE_MEMBERS = 4096
MAXIMUM_LOG_BYTES = 128 * 1024
ONE_SHOT_TIMEOUT_SECONDS = 20
STARTUP_TIMEOUT_SECONDS = 90
HTTP_TIMEOUT_SECONDS = 5
SHUTDOWN_TIMEOUT_SECONDS = 10
NATIVE_HELPER_IMAGE = (
    "docker.io/library/alpine:3.24@"
    "sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b"
)
KEYSIGNER_SEED_COMMAND = (
    "chown 0:0 /cert/privkey.pem /cert/keysigner-token.b64 && "
    "chmod 0550 /cert && "
    "chmod 0400 /cert/privkey.pem /cert/keysigner-token.b64 && "
    "chown 10002:10002 /cert/privkey.pem /cert/keysigner-token.b64 && "
    "chown 10002:10002 /cert"
)

ROLE_BINARIES = {
    "standalone": (
        "oxibelt",
        "oxibeltctl",
        "oxibelt-keysigner",
        "oxibelt-netport-switcher",
    ),
    "dataplane": ("oxibelt",),
    "dataplane-strict": ("oxibelt-dataplane-strict",),
    "controller": ("oxibelt-gateway-controller",),
    "tools": ("oxibeltctl",),
    "keysigner": ("oxibelt-keysigner",),
}

ROLE_PREFIXES = {
    "standalone": "oxibelt",
    "dataplane": "oxibelt-dataplane",
    "dataplane-strict": "oxibelt-dataplane-strict",
    "controller": "oxibelt-gateway-controller",
    "tools": "oxibelt-tools",
    "keysigner": "oxibelt-keysigner",
}

ROLE_USERS = {
    "standalone": "10001:10001",
    "dataplane": "10001:10001",
    "dataplane-strict": "10001:10001",
    "controller": "10001:10001",
    "tools": "10001:10001",
    "keysigner": "10002:10002",
}


class SmokeError(RuntimeError):
    """A fail-closed runtime-smoke contract violation."""


@dataclass(frozen=True)
class ReleaseArtifact:
    role: str
    image_id: str
    manifest_digest: str
    version: str
    revision: str
    source_ref: str
    binaries: tuple[str, ...]
    archive_references: tuple[str, ...]

    @property
    def identity(self) -> dict[str, str]:
        return {
            "version": self.version,
            "revision": self.revision,
            "source_ref": self.source_ref,
            "dirty": "clean",
            "kind": "official_release",
        }


def load_json(path: pathlib.Path, description: str) -> Any:
    if not path.is_file():
        raise SmokeError(f"missing {description}: {path}")
    if path.stat().st_size > MAXIMUM_JSON_BYTES:
        raise SmokeError(f"{description} exceeds the 8 MiB limit: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SmokeError(f"cannot read {description} {path}: {error}") from error


def sha256_file(path: pathlib.Path) -> str:
    if not path.is_file():
        raise SmokeError(f"missing image tar: {path}")
    if path.stat().st_size > MAXIMUM_IMAGE_BYTES:
        raise SmokeError(f"image tar exceeds the 4 GiB limit: {path}")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise SmokeError(f"cannot hash {path}: {error}") from error
    return f"sha256:{digest.hexdigest()}"


def docker_archive_identity(
    path: pathlib.Path,
) -> tuple[str, str, tuple[str, ...]]:
    try:
        with tarfile.open(path, mode="r:*") as archive:
            members = []
            for member in archive:
                members.append(member)
                if len(members) > MAXIMUM_ARCHIVE_MEMBERS:
                    raise SmokeError("Docker archive exceeds the 4096-member limit")
            names = [member.name for member in members]
            if len(names) != len(set(names)):
                raise SmokeError("Docker archive contains duplicate member names")

            def read_regular(name: str) -> bytes:
                member = archive.getmember(name)
                if not member.isfile() or member.size > MAXIMUM_JSON_BYTES:
                    raise SmokeError(
                        f"Docker archive member {name} is not a bounded regular file"
                    )
                stream = archive.extractfile(member)
                if stream is None:
                    raise SmokeError(f"Docker archive member {name} cannot be read")
                return stream.read()

            manifest = json.loads(read_regular("manifest.json"))
            if not isinstance(manifest, list) or len(manifest) != 1:
                raise SmokeError("Docker archive must contain exactly one image")
            manifest_entry = manifest[0]
            if not isinstance(manifest_entry, dict):
                raise SmokeError("Docker archive manifest entry must be an object")
            config_name = manifest_entry.get("Config")
            if not isinstance(config_name, str):
                raise SmokeError("Docker archive manifest is missing its config reference")
            repo_tags = manifest_entry.get("RepoTags")
            if repo_tags is None:
                references: tuple[str, ...] = ()
            elif (
                isinstance(repo_tags, list)
                and len(repo_tags) <= 16
                and all(
                    isinstance(value, str)
                    and IMAGE_REFERENCE.fullmatch(value) is not None
                    for value in repo_tags
                )
                and len(repo_tags) == len(set(repo_tags))
            ):
                references = tuple(repo_tags)
            else:
                raise SmokeError(
                    "Docker archive repository tags are not a bounded string array"
                )
            config_bytes = read_regular(config_name)

            index = json.loads(read_regular("index.json"))
            if not isinstance(index, dict) or index.get("schemaVersion") != 2:
                raise SmokeError(
                    "Docker archive OCI index must use schema version 2"
                )
            manifests = index.get("manifests")
            if not isinstance(manifests, list) or len(manifests) != 1:
                raise SmokeError(
                    "Docker archive OCI index must contain exactly one manifest"
                )
            manifest_descriptor = manifests[0]
            if not isinstance(manifest_descriptor, dict):
                raise SmokeError(
                    "Docker archive OCI manifest descriptor must be an object"
                )
            manifest_digest = manifest_descriptor.get("digest")
            if not isinstance(manifest_digest, str) or DIGEST.fullmatch(
                manifest_digest
            ) is None:
                raise SmokeError(
                    "Docker archive OCI manifest descriptor digest is invalid"
                )
            manifest_bytes = read_regular(
                f"blobs/sha256/{manifest_digest.removeprefix('sha256:')}"
            )
            if f"sha256:{hashlib.sha256(manifest_bytes).hexdigest()}" != manifest_digest:
                raise SmokeError(
                    "Docker archive OCI manifest blob digest does not match "
                    "its descriptor"
                )
            if manifest_descriptor.get("size") != len(manifest_bytes):
                raise SmokeError(
                    "Docker archive OCI manifest descriptor size is invalid"
                )
            image_manifest = json.loads(manifest_bytes)
            if (
                not isinstance(image_manifest, dict)
                or image_manifest.get("schemaVersion") != 2
            ):
                raise SmokeError(
                    "Docker archive OCI image manifest must use schema version 2"
                )
            config_descriptor = image_manifest.get("config")
            if not isinstance(config_descriptor, dict):
                raise SmokeError(
                    "Docker archive OCI config descriptor must be an object"
                )
    except (KeyError, tarfile.TarError, json.JSONDecodeError) as error:
        raise SmokeError(f"invalid Docker archive {path}: {error}") from error
    config_hash = hashlib.sha256(config_bytes).hexdigest()
    config_digest = f"sha256:{config_hash}"
    if config_name not in (
        f"{config_hash}.json",
        f"blobs/sha256/{config_hash}",
    ):
        raise SmokeError(
            "Docker archive config path is not content addressed by its digest"
        )
    if config_descriptor.get("digest") != config_digest:
        raise SmokeError(
            "Docker archive OCI image manifest config does not match "
            "the content-addressed config"
        )
    if config_descriptor.get("size") != len(config_bytes):
        raise SmokeError("Docker archive OCI config descriptor size is invalid")
    return (
        config_digest,
        manifest_digest,
        references,
    )


def validate_release_artifact(args: argparse.Namespace) -> ReleaseArtifact:
    if args.role not in ROLE_BINARIES:
        raise SmokeError(f"unsupported image role: {args.role}")
    if not args.expected_version:
        raise SmokeError("expected release version must not be empty")
    if GIT_OBJECT.fullmatch(args.expected_revision) is None:
        raise SmokeError("expected revision must be a full lowercase Git object ID")
    if SOURCE_REF.fullmatch(args.expected_source_ref) is None:
        raise SmokeError("expected source ref must be a full release tag ref")

    plan = load_json(args.image_plan, "image release plan")
    contract = load_json(args.artifact_contract, "image artifact contract")
    metadata = load_json(args.build_metadata, "Buildx metadata")
    if not isinstance(plan, dict) or plan.get("schemaVersion") != 8:
        raise SmokeError("unsupported image release plan schema")
    if not isinstance(contract, dict) or contract.get("schema") != 3:
        raise SmokeError("unsupported image artifact contract schema")
    if not isinstance(metadata, dict):
        raise SmokeError("Buildx metadata must be a JSON object")

    expected_plan_identity = {
        "version": args.expected_version,
        "revision": args.expected_revision,
        "sourceRef": args.expected_source_ref,
        "sourceDirty": "clean",
        "buildKind": "official_release",
    }
    for field, expected in expected_plan_identity.items():
        if plan.get(field) != expected:
            raise SmokeError(
                f"image release plan {field} was {plan.get(field)!r}, expected {expected!r}"
            )
    if plan.get("tag") != args.expected_version or plan.get("kind") not in (
        "stable",
        "beta",
        "build",
    ):
        raise SmokeError("image release plan is not a supported official release")

    roles = [
        value
        for value in plan.get("roles", [])
        if isinstance(value, dict) and value.get("role") == args.role
    ]
    if len(roles) != 1:
        raise SmokeError(f"image release plan must contain one {args.role} role")
    expected_binaries = ROLE_BINARIES[args.role]
    if tuple(roles[0].get("binaries", [])) != expected_binaries:
        raise SmokeError(
            f"image release plan binary inventory for {args.role} "
            "does not match the independent allowlist"
        )

    artifacts = [
        value
        for value in plan.get("artifacts", [])
        if isinstance(value, dict)
        and value.get("role") == args.role
        and value.get("artifactArch") == "riscv64"
    ]
    if len(artifacts) != 1:
        raise SmokeError(
            f"image release plan must contain one {args.role}/riscv64 artifact"
        )
    artifact = artifacts[0]
    if (
        artifact.get("platform") != "linux/riscv64"
        or artifact.get("dockerArchitecture") != "riscv64"
        or tuple(artifact.get("binaries", [])) != expected_binaries
        or artifact.get("imageTar") != args.image_tar.name
    ):
        raise SmokeError("RISC-V release artifact does not match its role contract")
    expected_archive_reference = (
        f"{ROLE_PREFIXES[args.role]}:alpine-musl-riscv64"
    )
    if artifact.get("localTag") != expected_archive_reference:
        raise SmokeError(
            "RISC-V release artifact local tag does not match its role contract"
        )

    for field, expected in {
        "role": args.role,
        "artifact_arch": "riscv64",
        "platform": "linux/riscv64",
        "docker_architecture": "riscv64",
        "version": args.expected_version,
        "revision": args.expected_revision,
        "source_ref": args.expected_source_ref,
        "source_dirty": "clean",
        "build_kind": "official_release",
        "image_tar": args.image_tar.name,
        "build_metadata": args.build_metadata.name,
    }.items():
        if contract.get(field) != expected:
            raise SmokeError(
                f"artifact contract {field} was {contract.get(field)!r}, expected {expected!r}"
            )

    contract_binaries = contract.get("binaries")
    if not isinstance(contract_binaries, list):
        raise SmokeError("artifact contract binaries must be an array")
    actual_contract_binaries = {
        value.get("name")
        for value in contract_binaries
        if isinstance(value, dict)
        and value.get("path") == f"/usr/local/bin/{value.get('name')}"
        and value.get("version") == args.expected_version
    }
    if actual_contract_binaries != set(expected_binaries) or len(
        contract_binaries
    ) != len(expected_binaries):
        raise SmokeError("artifact contract binary inventory does not match the role")

    image_tar_digest = sha256_file(args.image_tar)
    if contract.get("image_tar_sha256") != image_tar_digest:
        raise SmokeError("image tar digest does not match the artifact contract")

    config_digest = contract.get("config_digest")
    manifest_digest = contract.get("image_digest")
    if not isinstance(config_digest, str) or DIGEST.fullmatch(config_digest) is None:
        raise SmokeError("artifact contract config digest is invalid")
    if not isinstance(manifest_digest, str) or DIGEST.fullmatch(manifest_digest) is None:
        raise SmokeError("artifact contract image digest is invalid")
    if contract.get("descriptor_digest") != manifest_digest:
        raise SmokeError("artifact contract descriptor and image digests differ")
    if metadata.get("containerimage.config.digest") != config_digest:
        raise SmokeError("Buildx config digest does not match the artifact contract")
    if metadata.get("containerimage.digest") != manifest_digest:
        raise SmokeError("Buildx image digest does not match the artifact contract")
    descriptor = metadata.get("containerimage.descriptor")
    if not isinstance(descriptor, dict) or descriptor.get("digest") != manifest_digest:
        raise SmokeError("Buildx descriptor digest does not match the artifact contract")
    (
        archive_config_digest,
        archive_manifest_digest,
        archive_references,
    ) = docker_archive_identity(args.image_tar)
    if archive_config_digest != config_digest:
        raise SmokeError("Docker archive config digest does not match the artifact contract")
    if archive_manifest_digest != manifest_digest:
        raise SmokeError(
            "Docker archive OCI manifest digest does not match the artifact contract"
        )
    if archive_references != (expected_archive_reference,):
        raise SmokeError(
            "Docker archive repository tag does not match the release plan"
        )

    return ReleaseArtifact(
        role=args.role,
        image_id=config_digest,
        manifest_digest=manifest_digest,
        version=args.expected_version,
        revision=args.expected_revision,
        source_ref=args.expected_source_ref,
        binaries=expected_binaries,
        archive_references=archive_references,
    )


def parse_build_identity(output: str, expected: dict[str, str]) -> dict[str, str]:
    matches = BUILD_IDENTITY_MARKER.findall(output)
    if len(matches) != 1:
        raise SmokeError(
            "version output must contain exactly one canonical build identity marker"
        )
    try:
        identity = json.loads(matches[0])
    except json.JSONDecodeError as error:
        raise SmokeError(f"version output contains invalid build identity JSON: {error}") from error
    if identity != expected:
        raise SmokeError(
            f"version output identity was {identity!r}, expected {expected!r}"
        )
    return identity


def inspect_rootfs_inventory(
    rootfs_tar: pathlib.Path, expected_binaries: tuple[str, ...]
) -> None:
    expected = {f"usr/local/bin/{name}" for name in expected_binaries}
    actual: dict[str, tarfile.TarInfo] = {}
    try:
        with tarfile.open(rootfs_tar, mode="r:*") as archive:
            for member in archive:
                name = member.name
                while name.startswith("./"):
                    name = name[2:]
                name = name.lstrip("/")
                if name == "usr/local/bin" and not member.isdir():
                    raise SmokeError("/usr/local/bin is not a directory")
                if not name.startswith("usr/local/bin/"):
                    continue
                actual[name.rstrip("/")] = member
    except tarfile.TarError as error:
        raise SmokeError(f"cannot inspect exported image rootfs: {error}") from error

    if set(actual) != expected:
        raise SmokeError(
            "loaded /usr/local/bin inventory does not match the role contract "
            f"(missing={sorted(expected - set(actual))}, "
            f"unexpected={sorted(set(actual) - expected)})"
        )
    for path, member in actual.items():
        if not member.isfile() or member.mode & 0o111 == 0:
            raise SmokeError(f"loaded role executable {path} is not an executable file")


def wait_for_service(
    label: str,
    state_probe: Callable[[], tuple[bool, int | None]],
    ready_probe: Callable[[], bool],
    *,
    timeout_seconds: float = STARTUP_TIMEOUT_SECONDS,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    deadline = clock() + timeout_seconds
    while True:
        running, exit_code = state_probe()
        if not running:
            raise SmokeError(
                f"{label} exited before readiness with code {exit_code!r}"
            )
        if ready_probe():
            return
        if clock() >= deadline:
            raise SmokeError(f"{label} did not become ready within {timeout_seconds:g}s")
        sleep(0.25)


class CommandRunner:
    def run(
        self,
        args: list[str],
        *,
        timeout: int,
        check: bool = True,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        try:
            result = subprocess.run(
                args,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise SmokeError(f"command did not complete: {args!r}: {error}") from error
        if check and result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()[-4096:]
            raise SmokeError(
                f"command failed with code {result.returncode}: {args!r}: {detail}"
            )
        return result


class KubernetesLeaseMock:
    def __init__(
        self,
        cert_path: pathlib.Path,
        key_path: pathlib.Path,
        token: str,
    ) -> None:
        self.token = token
        self.requests: list[tuple[str, str, bool]] = []
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, _format: str, *_args: object) -> None:
                return

            def _authorized(self) -> bool:
                return self.headers.get("Authorization") == f"Bearer {owner.token}"

            def _send_json(self, status: int, value: Any) -> None:
                body = json.dumps(value, separators=(",", ":")).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
                authorized = self._authorized()
                owner.requests.append(("GET", self.path, authorized))
                if not authorized:
                    self._send_json(401, {"message": "unauthorized"})
                    return
                parsed = urllib.parse.urlsplit(self.path)
                lease_path = (
                    "/apis/coordination.k8s.io/v1/namespaces/smoke/"
                    "leases/oxibelt-gateway-controller"
                )
                lease = {
                    "apiVersion": "coordination.k8s.io/v1",
                    "kind": "Lease",
                    "metadata": {
                        "name": "oxibelt-gateway-controller",
                        "namespace": "smoke",
                        "resourceVersion": "1",
                        "uid": "00000000-0000-0000-0000-000000000001",
                    },
                    "spec": {
                        "holderIdentity": "smoke-peer",
                        "leaseDurationSeconds": 30,
                        "leaseTransitions": 1,
                    },
                }
                if parsed.path == lease_path:
                    self._send_json(200, lease)
                    return
                if parsed.path == lease_path.rsplit("/", 1)[0]:
                    query = urllib.parse.parse_qs(parsed.query)
                    if query.get("watch") == ["true"]:
                        self._send_json(200, {"type": "MODIFIED", "object": lease})
                        return
                self._send_json(404, {"message": "not found"})

            def _reject_write(self) -> None:
                owner.requests.append(
                    (self.command, self.path, self._authorized())
                )
                self._send_json(403, {"message": "writes are forbidden in smoke"})

            do_PATCH = _reject_write  # type: ignore[assignment]
            do_POST = _reject_write  # type: ignore[assignment]
            do_PUT = _reject_write  # type: ignore[assignment]
            do_DELETE = _reject_write  # type: ignore[assignment]

        self.server = http.server.ThreadingHTTPServer(("0.0.0.0", 0), Handler)
        self.server.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            name="riscv64-release-kubernetes-mock",
            daemon=True,
        )

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=HTTP_TIMEOUT_SECONDS)


class DockerSmoke:
    def __init__(
        self,
        runner: CommandRunner,
        artifact: ReleaseArtifact,
        args: argparse.Namespace,
        receipt: dict[str, Any],
    ) -> None:
        self.runner = runner
        self.artifact = artifact
        self.args = args
        self.receipt = receipt
        suffix = secrets.token_hex(4)
        raw_run = (
            f"{os.environ.get('GITHUB_RUN_ID', 'local')}-"
            f"{os.environ.get('GITHUB_RUN_ATTEMPT', '0')}-{artifact.role}-{suffix}"
        )
        self.run_token = re.sub(r"[^a-zA-Z0-9_.-]", "-", raw_run)[:96]
        self.label = f"io.oxibelt.release-riscv64-smoke={self.run_token}"
        self.containers: list[str] = []
        self.volumes: list[str] = []
        self.networks: list[str] = []
        self.preexisting_image_ids: set[str] = set()
        self.image_references_before_load: set[str] = set()
        self.loaded_image_references: set[str] = set()
        self.runtime_image_id: str | None = None
        self.native_helper_preexisting = False
        self.native_helper_pulled = False
        self.sequence = 0
        self.temporary = tempfile.TemporaryDirectory(
            prefix=f"oxibelt-riscv64-{artifact.role}-"
        )
        self.root = pathlib.Path(self.temporary.name)

    def check(self, name: str, operation: Callable[[], Any]) -> Any:
        entry: dict[str, Any] = {"name": name, "status": "running"}
        self.receipt["checks"].append(entry)
        try:
            result = operation()
        except Exception as error:
            entry["status"] = "failed"
            entry["error"] = str(error)[:4096]
            raise
        entry["status"] = "passed"
        return result

    def docker(
        self,
        args: list[str],
        *,
        timeout: int = ONE_SHOT_TIMEOUT_SECONDS,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        return self.runner.run(["docker", *args], timeout=timeout, check=check)

    def resource_name(self, kind: str) -> str:
        self.sequence += 1
        return f"oxibelt-riscv64-smoke-{kind}-{self.run_token}-{self.sequence}"[:128]

    def runtime_image_reference(self) -> str:
        if self.runtime_image_id is None:
            raise SmokeError("RISC-V release image has not been loaded and verified")
        return self.runtime_image_id

    def target_options(self, *, network: str = "none") -> list[str]:
        return [
            "--platform",
            "linux/riscv64",
            "--pull",
            "never",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "256",
            "--memory",
            "1g",
            "--cpus",
            "2",
            "--network",
            network,
        ]

    def native_helper_options(self, *, user: str) -> list[str]:
        return [
            "--network",
            "none",
            "--user",
            user,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "64",
            "--memory",
            "128m",
            "--cpus",
            "1",
        ]

    def create_container(
        self,
        image: str,
        entrypoint: str,
        command: list[str],
        options: list[str],
        *,
        kind: str,
    ) -> str:
        name = self.resource_name(kind)
        result = self.docker(
            [
                "create",
                "--name",
                name,
                "--label",
                self.label,
                *options,
                "--entrypoint",
                entrypoint,
                image,
                *command,
            ]
        )
        container = result.stdout.strip()
        if not container:
            raise SmokeError("docker create did not return a container ID")
        self.containers.append(container)
        return container

    def remove_container(self, container: str) -> None:
        result = self.docker(["rm", "--force", container], check=False)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()[-4096:]
            raise SmokeError(f"failed to remove container {container}: {detail}")
        if container in self.containers:
            self.containers.remove(container)

    def run_one_shot(
        self,
        entrypoint: str,
        command: list[str],
        *,
        options: list[str] | None = None,
        image: str | None = None,
        target: bool = True,
        expect_success: bool = True,
        kind: str = "oneshot",
    ) -> subprocess.CompletedProcess[str]:
        runtime_options = (
            [*self.target_options(), *(options or [])]
            if target
            else ["--pull", "never", *(options or [])]
        )
        container = self.create_container(
            image or self.runtime_image_reference(),
            entrypoint,
            command,
            runtime_options,
            kind=kind,
        )
        completed = False
        try:
            result = self.docker(
                ["start", "--attach", container],
                timeout=ONE_SHOT_TIMEOUT_SECONDS,
                check=False,
            )
            if expect_success and result.returncode != 0:
                detail = (result.stderr or result.stdout).strip()[-4096:]
                raise SmokeError(
                    f"{entrypoint} exited with code {result.returncode}: {detail}"
                )
            if not expect_success and result.returncode == 0:
                raise SmokeError(f"{entrypoint} unexpectedly accepted invalid input")
            completed = True
            return result
        finally:
            if completed:
                self.remove_container(container)

    def create_network(self) -> str:
        name = self.resource_name("network")
        self.docker(["network", "create", "--label", self.label, name])
        self.networks.append(name)
        return name

    def create_volume(self, kind: str) -> str:
        name = self.resource_name(kind)
        self.docker(["volume", "create", "--label", self.label, name])
        self.volumes.append(name)
        return name

    def container_state(self, container: str) -> tuple[bool, int | None]:
        result = self.docker(
            ["inspect", "--format", "{{json .State}}", container],
            check=False,
        )
        if result.returncode != 0:
            return False, None
        try:
            state = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise SmokeError(f"cannot parse Docker state for {container}: {error}") from error
        return bool(state.get("Running")), state.get("ExitCode")

    def host_port(self, container: str, container_port: int) -> int:
        result = self.docker(["port", container, f"{container_port}/tcp"])
        endpoint = result.stdout.strip().splitlines()[0]
        try:
            return int(endpoint.rsplit(":", 1)[1])
        except (IndexError, ValueError) as error:
            raise SmokeError(f"cannot parse published Docker port {endpoint!r}") from error

    def http_response(
        self,
        port: int,
        path: str,
        *,
        host: str = "127.0.0.1",
        host_header: str | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        connection = http.client.HTTPConnection(
            host, port, timeout=HTTP_TIMEOUT_SECONDS
        )
        try:
            headers = {"Host": host_header} if host_header else {}
            connection.request("GET", path, headers=headers)
            response = connection.getresponse()
            body = response.read(64 * 1024)
            return (
                response.status,
                {key.lower(): value for key, value in response.getheaders()},
                body,
            )
        finally:
            connection.close()

    def wait_for_http(
        self,
        label: str,
        container: str,
        port: int,
        path: str,
        expected_status: int,
    ) -> None:
        def ready() -> bool:
            try:
                status, _, _ = self.http_response(port, path)
                return status == expected_status
            except (OSError, http.client.HTTPException):
                return False

        wait_for_service(
            label,
            lambda: self.container_state(container),
            ready,
        )

    def stop_container(self, container: str) -> None:
        result = self.docker(
            ["stop", "--time", str(SHUTDOWN_TIMEOUT_SECONDS), container],
            timeout=SHUTDOWN_TIMEOUT_SECONDS + 5,
            check=False,
        )
        if result.returncode != 0:
            raise SmokeError(f"container {container} did not stop cleanly")

    def generate_certificate(
        self, directory: pathlib.Path, common_name: str
    ) -> tuple[pathlib.Path, pathlib.Path]:
        directory.mkdir(parents=True, exist_ok=True)
        key = directory / "privkey.pem"
        cert = directory / "fullchain.pem"
        self.runner.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-sha256",
                "-days",
                "1",
                "-nodes",
                "-subj",
                f"/CN={common_name}",
                "-addext",
                f"subjectAltName=DNS:{common_name}",
                "-keyout",
                str(key),
                "-out",
                str(cert),
            ],
            timeout=ONE_SHOT_TIMEOUT_SECONDS,
        )
        key.chmod(0o444)
        cert.chmod(0o444)
        return cert, key

    def generate_controller_pki(
        self, directory: pathlib.Path, common_name: str
    ) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
        directory.mkdir(parents=True, exist_ok=True)
        ca_key = directory / "ca-key.pem"
        ca_cert = directory / "ca.pem"
        leaf_key = directory / "server-key.pem"
        leaf_request = directory / "server.csr"
        leaf_cert = directory / "server.pem"
        self.runner.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-sha256",
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=OxiBelt RISC-V release smoke CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE,pathlen:0",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
                "-keyout",
                str(ca_key),
                "-out",
                str(ca_cert),
            ],
            timeout=ONE_SHOT_TIMEOUT_SECONDS,
        )
        self.runner.run(
            [
                "openssl",
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-sha256",
                "-nodes",
                "-subj",
                f"/CN={common_name}",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
                "-addext",
                "keyUsage=critical,digitalSignature,keyEncipherment",
                "-addext",
                "extendedKeyUsage=serverAuth",
                "-addext",
                f"subjectAltName=DNS:{common_name}",
                "-keyout",
                str(leaf_key),
                "-out",
                str(leaf_request),
            ],
            timeout=ONE_SHOT_TIMEOUT_SECONDS,
        )
        self.runner.run(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                str(leaf_request),
                "-CA",
                str(ca_cert),
                "-CAkey",
                str(ca_key),
                "-set_serial",
                "1",
                "-days",
                "1",
                "-sha256",
                "-copy_extensions",
                "copy",
                "-out",
                str(leaf_cert),
            ],
            timeout=ONE_SHOT_TIMEOUT_SECONDS,
        )
        ca_cert.chmod(0o444)
        leaf_cert.chmod(0o444)
        leaf_key.chmod(0o400)
        leaf_request.unlink()
        ca_key.unlink()
        return leaf_cert, leaf_key, ca_cert

    def prepare_data_fixture(
        self,
    ) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
        config_dir = self.root / "data-config"
        cert_dir = self.root / "data-cert"
        config_dir.mkdir(parents=True, exist_ok=True)
        source_config = self.args.fixture_root / "oxibelt.toml"
        if not source_config.is_file():
            raise SmokeError(f"missing data-plane smoke fixture: {source_config}")
        config = config_dir / "oxibelt.toml"
        shutil.copyfile(source_config, config)
        strict_admin = config_dir / "strict-admin.toml"
        strict_admin.write_text(
            config.read_text(encoding="utf-8")
            + '\n[admin]\nenabled = true\nbind = "0.0.0.0:9092"\n',
            encoding="utf-8",
        )
        config.chmod(0o444)
        strict_admin.chmod(0o444)
        self.generate_certificate(cert_dir, "smoke.oxibelt.test")
        return config_dir, cert_dir, strict_admin

    def fixture_mounts(
        self, config_dir: pathlib.Path, cert_dir: pathlib.Path
    ) -> list[str]:
        return [
            "--mount",
            f"type=bind,src={config_dir},dst=/etc/oxibelt/config,readonly",
            "--mount",
            f"type=bind,src={cert_dir},dst=/etc/oxibelt/cert,readonly",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777",
            "--tmpfs",
            "/run:rw,noexec,nosuid,nodev,size=64m,mode=1777",
        ]

    def load_and_verify_image(self) -> None:
        allowed_image_ids = {
            self.artifact.image_id,
            self.artifact.manifest_digest,
        }
        for image_id in sorted(allowed_image_ids):
            before = self.docker(
                [
                    "image",
                    "inspect",
                    "--format",
                    "{{json .}}",
                    image_id,
                ],
                check=False,
            )
            if before.returncode == 0:
                try:
                    image = json.loads(before.stdout)
                except json.JSONDecodeError as error:
                    raise SmokeError(
                        f"cannot parse preexisting image identity: {error}"
                    ) from error
                if not isinstance(image, dict):
                    raise SmokeError(
                        "preexisting Docker image inspection is not an object"
                    )
                canonical_image_id = image.get("Id")
                if canonical_image_id not in allowed_image_ids:
                    raise SmokeError(
                        "preexisting Docker image lookup resolved to an "
                        "unexpected image ID"
                    )
                self.preexisting_image_ids.add(canonical_image_id)
                references = image.get("RepoTags")
                if isinstance(references, list):
                    self.image_references_before_load.update(
                        value for value in references if isinstance(value, str)
                    )
                continue
            detail = (before.stderr or before.stdout).strip().lower()
            if "no such image" not in detail and "no such object" not in detail:
                raise SmokeError(
                    "cannot determine whether the release image already exists "
                    f"in the Docker daemon: {detail[-1024:]}"
                )

        for reference in self.artifact.archive_references:
            existing_reference = self.docker(
                ["image", "inspect", "--format", "{{.Id}}", reference],
                check=False,
            )
            if existing_reference.returncode == 0:
                existing_image_id = existing_reference.stdout.strip()
                raise SmokeError(
                    "refusing to replace preexisting Docker image reference "
                    f"{reference!r} ({existing_image_id or 'unknown ID'})"
                )
            detail = (
                existing_reference.stderr or existing_reference.stdout
            ).strip().lower()
            if "no such image" not in detail and "no such object" not in detail:
                raise SmokeError(
                    f"cannot inspect Docker image reference {reference!r}: "
                    f"{detail[-1024:]}"
                )

        archive_reference = self.artifact.archive_references[0]
        self.loaded_image_references.update(
            set(self.artifact.archive_references)
            - self.image_references_before_load
        )
        self.docker(
            ["load", "--input", str(self.args.image_tar)],
            timeout=120,
        )
        result = self.docker(
            ["image", "inspect", "--format", "{{json .}}", archive_reference]
        )
        try:
            image = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise SmokeError(f"cannot parse loaded image inspection: {error}") from error
        runtime_image_id = image.get("Id")
        if (
            not isinstance(runtime_image_id, str)
            or DIGEST.fullmatch(runtime_image_id) is None
            or runtime_image_id not in allowed_image_ids
            or image.get("Os") != "linux"
            or image.get("Architecture") != "riscv64"
        ):
            raise SmokeError(
                "loaded image identity or architecture is not the expected "
                "RISC-V artifact"
            )
        addressed = self.docker(
            ["image", "inspect", "--format", "{{.Id}}", runtime_image_id]
        )
        if addressed.stdout.strip() != runtime_image_id:
            raise SmokeError(
                "loaded image ID is not an exact Docker daemon reference"
            )
        self.runtime_image_id = runtime_image_id
        runtime_config = image.get("Config", {})
        if runtime_config.get("User") != ROLE_USERS[self.artifact.role]:
            raise SmokeError(
                f"loaded image runtime user does not match the {self.artifact.role} role"
            )
        references = image.get("RepoTags")
        if isinstance(references, list):
            self.loaded_image_references = {
                value for value in references if isinstance(value, str)
            } - self.image_references_before_load
        labels = runtime_config.get("Labels", {})
        for field, expected in {
            "io.oxibelt.image.role": self.artifact.role,
            "org.opencontainers.image.version": self.artifact.version,
            "org.opencontainers.image.revision": self.artifact.revision,
            "io.oxibelt.build.source-ref": self.artifact.source_ref,
            "io.oxibelt.build.dirty": "clean",
            "io.oxibelt.build.kind": "official_release",
        }.items():
            if labels.get(field) != expected:
                raise SmokeError(
                    f"loaded image label {field} was {labels.get(field)!r}, expected {expected!r}"
                )

    def verify_loaded_inventory(self) -> None:
        container = self.create_container(
            self.runtime_image_reference(),
            f"/usr/local/bin/{self.artifact.binaries[0]}",
            [],
            self.target_options(),
            kind="inventory",
        )
        rootfs = self.root / "rootfs.tar"
        try:
            self.docker(
                ["export", "--output", str(rootfs), container],
                timeout=120,
            )
            inspect_rootfs_inventory(rootfs, self.artifact.binaries)
        finally:
            self.remove_container(container)

    def run_versions(self) -> None:
        for binary in self.artifact.binaries:
            result = self.run_one_shot(
                f"/usr/local/bin/{binary}",
                ["--version"],
                kind=f"version-{binary}",
            )
            parse_build_identity(
                f"{result.stdout}\n{result.stderr}", self.artifact.identity
            )

    def validate_config_with_ctl(
        self, config_dir: pathlib.Path, cert_dir: pathlib.Path
    ) -> None:
        result = self.run_one_shot(
            "/usr/local/bin/oxibeltctl",
            [
                "--output",
                "json",
                "config",
                "validate",
                "/etc/oxibelt/config/oxibelt.toml",
                "--local-only",
            ],
            options=self.fixture_mounts(config_dir, cert_dir),
            kind="config-validate",
        )
        try:
            report = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise SmokeError(f"oxibeltctl returned invalid JSON: {error}") from error
        if report.get("ok") is not True:
            raise SmokeError("oxibeltctl local configuration validation did not return ok=true")

    def run_server_role(self) -> None:
        config_dir, cert_dir, _ = self.prepare_data_fixture()
        mounts = self.fixture_mounts(config_dir, cert_dir)
        server_binary = (
            "oxibelt-dataplane-strict"
            if self.artifact.role == "dataplane-strict"
            else "oxibelt"
        )
        if self.artifact.role == "standalone":
            self.validate_config_with_ctl(config_dir, cert_dir)
        self.run_one_shot(
            f"/usr/local/bin/{server_binary}",
            ["--config", "/etc/oxibelt/config/oxibelt.toml", "--check"],
            options=mounts,
            kind="server-config-check",
        )
        if self.artifact.role == "dataplane-strict":
            self.run_one_shot(
                f"/usr/local/bin/{server_binary}",
                ["--config", "/etc/oxibelt/config/strict-admin.toml", "--check"],
                options=mounts,
                expect_success=False,
                kind="strict-admin-rejection",
            )

        network = self.create_network()
        options = [
            *self.target_options(network=network),
            *mounts,
            "--publish",
            "127.0.0.1::8080",
            "--publish",
            "127.0.0.1::9091",
        ]
        if self.artifact.role == "dataplane-strict":
            options.extend(["--publish", "127.0.0.1::9092"])
        container = self.create_container(
            self.runtime_image_reference(),
            f"/usr/local/bin/{server_binary}",
            ["--config", "/etc/oxibelt/config/oxibelt.toml"],
            options,
            kind="server",
        )
        self.docker(["start", container])
        health_port = self.host_port(container, 9091)
        http_port = self.host_port(container, 8080)
        self.wait_for_http(
            f"{self.artifact.role} readiness",
            container,
            health_port,
            "/ready",
            200,
        )
        status, _, _ = self.http_response(health_port, "/live")
        if status != 200:
            raise SmokeError(f"{self.artifact.role} liveness returned HTTP {status}")
        status, headers, _ = self.http_response(
            http_port,
            "/smoke",
            host_header="smoke.oxibelt.test",
        )
        if status != 308 or headers.get("location") != "/smoke-ok":
            raise SmokeError(
                f"HTTP/1 data-plane probe returned {status} and "
                f"Location={headers.get('location')!r}"
            )
        if self.artifact.role == "dataplane-strict":
            admin_port = self.host_port(container, 9092)
            try:
                admin_status, _, _ = self.http_response(admin_port, "/")
            except (OSError, http.client.HTTPException):
                admin_status = None
            if admin_status is not None:
                raise SmokeError(
                    f"strict data-plane unexpectedly exposed Admin HTTP status {admin_status}"
                )
            running, exit_code = self.container_state(container)
            if not running:
                raise SmokeError(
                    f"strict data-plane exited during Admin listener check with {exit_code!r}"
                )
        self.stop_container(container)
        self.remove_container(container)

    def run_tools_role(self) -> None:
        config_dir, cert_dir, _ = self.prepare_data_fixture()
        self.validate_config_with_ctl(config_dir, cert_dir)

    def run_controller_role(self) -> None:
        fixture = self.args.fixture_root / "controller-empty-list.json"
        if not fixture.is_file():
            raise SmokeError(f"missing controller smoke fixture: {fixture}")
        render = self.run_one_shot(
            "/usr/local/bin/oxibelt-gateway-controller",
            ["render", "--input", "/smoke/controller-empty-list.json", "--output", "-"],
            options=[
                "--mount",
                f"type=bind,src={self.args.fixture_root},dst=/smoke,readonly",
            ],
            kind="controller-render",
        )
        if not render.stdout.startswith(
            "# Generated by oxibelt-gateway-controller. Do not edit."
        ):
            raise SmokeError("Gateway controller render output is not the expected managed TOML")

        mock_dir = self.root / "controller-mock"
        cert, key, ca_cert = self.generate_controller_pki(
            mock_dir, "host.docker.internal"
        )
        service_account = self.root / "service-account"
        service_account.mkdir()
        token = secrets.token_urlsafe(32)
        (service_account / "token").write_text(f"{token}\n", encoding="utf-8")
        (service_account / "namespace").write_text("smoke\n", encoding="utf-8")
        shutil.copyfile(ca_cert, service_account / "ca.crt")
        (service_account / "token").chmod(0o444)
        (service_account / "namespace").chmod(0o444)
        (service_account / "ca.crt").chmod(0o444)

        mock = KubernetesLeaseMock(cert, key, token)
        mock.start()
        try:
            network = self.create_network()
            options = [
                *self.target_options(network=network),
                "--add-host",
                "host.docker.internal:host-gateway",
                "--env",
                "KUBERNETES_SERVICE_HOST=host.docker.internal",
                "--env",
                f"KUBERNETES_SERVICE_PORT_HTTPS={mock.port}",
                "--env",
                "POD_NAME=riscv64-smoke",
                "--env",
                "POD_UID=00000000-0000-0000-0000-000000000002",
                "--mount",
                (
                    f"type=bind,src={service_account},"
                    "dst=/var/run/secrets/kubernetes.io/serviceaccount,readonly"
                ),
                "--publish",
                "127.0.0.1::8081",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777",
            ]
            container = self.create_container(
                self.runtime_image_reference(),
                "/usr/local/bin/oxibelt-gateway-controller",
                [
                    "--health-bind",
                    "0.0.0.0:8081",
                    "--dry-run",
                    "run",
                    "--poll-interval-ms",
                    "1000",
                    "--rollout-target-namespace",
                    "smoke",
                    "--rollout-target-name",
                    "smoke",
                    "--leader-election-namespace",
                    "smoke",
                    "--leader-election-lease-name",
                    "oxibelt-gateway-controller",
                    "--leader-election-lease-duration-seconds",
                    "30",
                    "--leader-election-renew-deadline-seconds",
                    "20",
                    "--leader-election-retry-period-seconds",
                    "5",
                ],
                options,
                kind="controller",
            )
            self.docker(["start", container])
            health_port = self.host_port(container, 8081)
            self.wait_for_http(
                "Gateway controller readiness",
                container,
                health_port,
                "/readyz",
                200,
            )
            for path, expected in (
                ("/healthz", 200),
                ("/leaderz", 503),
                ("/reconcilez", 503),
            ):
                status, _, _ = self.http_response(health_port, path)
                if status != expected:
                    raise SmokeError(
                        f"Gateway controller {path} returned {status}, expected {expected}"
                    )
            authenticated_gets = [
                path
                for method, path, authorized in mock.requests
                if method == "GET" and authorized
            ]
            if not authenticated_gets or not any(
                "watch=true" in path for path in authenticated_gets
            ):
                raise SmokeError(
                    "Gateway controller did not perform authenticated Lease GET/watch requests"
                )
            if any(method != "GET" for method, _, _ in mock.requests):
                raise SmokeError("Gateway controller attempted a Kubernetes write as nonleader")
            self.stop_container(container)
            self.remove_container(container)
        finally:
            mock.close()

    def pull_native_helper(self) -> None:
        inspect = self.docker(
            ["image", "inspect", NATIVE_HELPER_IMAGE],
            check=False,
        )
        if inspect.returncode == 0:
            self.native_helper_preexisting = True
        else:
            detail = (inspect.stderr or inspect.stdout).strip().lower()
            if "no such image" not in detail and "no such object" not in detail:
                raise SmokeError(
                    "cannot determine whether the native helper image already exists "
                    f"in the Docker daemon: {detail[-1024:]}"
                )
        last_error = ""
        for _attempt in range(3):
            result = self.docker(
                ["pull", NATIVE_HELPER_IMAGE],
                timeout=60,
                check=False,
            )
            if result.returncode == 0:
                self.native_helper_pulled = True
                return
            last_error = (result.stderr or result.stdout).strip()[-4096:]
        raise SmokeError(f"failed to pull the pinned native helper image: {last_error}")

    def run_keysigner_role(self) -> None:
        self.pull_native_helper()
        key_dir = self.root / "keysigner"
        key_dir.mkdir()
        key = key_dir / "privkey.pem"
        token = key_dir / "keysigner-token.b64"
        self.runner.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                str(key),
            ],
            timeout=ONE_SHOT_TIMEOUT_SECONDS,
        )
        token.write_text(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
            encoding="utf-8",
        )
        key.chmod(0o400)
        token.chmod(0o400)

        cert_volume = self.create_volume("keysigner-cert")
        socket_volume = self.create_volume("keysigner-socket")
        seed_options = [
            "--pull",
            "never",
            *self.native_helper_options(user="0:0"),
            "--cap-add",
            "CHOWN",
            "--mount",
            f"type=volume,src={cert_volume},dst=/cert",
        ]
        seed = self.create_container(
            NATIVE_HELPER_IMAGE,
            "/bin/sh",
            [
                "-c",
                KEYSIGNER_SEED_COMMAND,
            ],
            seed_options,
            kind="keysigner-seed",
        )
        try:
            self.docker(["cp", str(key), f"{seed}:/cert/privkey.pem"])
            self.docker(["cp", str(token), f"{seed}:/cert/keysigner-token.b64"])
            result = self.docker(["start", "--attach", seed], check=False)
            if result.returncode != 0:
                detail = (result.stderr or result.stdout).strip()[-4096:]
                raise SmokeError(
                    "failed to seed the keysigner certificate volume "
                    f"with code {result.returncode}: {detail}"
                )
        finally:
            self.remove_container(seed)

        self.run_one_shot(
            "/bin/sh",
            ["-c", "chown 10002:10002 /sock && chmod 0770 /sock"],
            options=[
                *self.native_helper_options(user="0:0"),
                "--cap-add",
                "CHOWN",
                "--mount",
                f"type=volume,src={socket_volume},dst=/sock",
            ],
            image=NATIVE_HELPER_IMAGE,
            target=False,
            kind="keysigner-socket-init",
        )

        container = self.create_container(
            self.runtime_image_reference(),
            "/usr/local/bin/oxibelt-keysigner",
            [
                "--socket",
                "/run/oxibelt-keysigner/smoke.sock",
                "--key",
                "smoke=/etc/oxibelt/cert/privkey.pem",
                "--token-file",
                "/etc/oxibelt/cert/keysigner-token.b64",
                "--socket-mode",
                "0660",
                "--max-connections",
                "4",
                "--io-timeout-ms",
                "500",
            ],
            [
                *self.target_options(),
                "--ulimit",
                "nofile=64:64",
                "--mount",
                (
                    f"type=volume,src={socket_volume},"
                    "dst=/run/oxibelt-keysigner"
                ),
                "--mount",
                (
                    f"type=volume,src={cert_volume},"
                    "dst=/etc/oxibelt/cert,readonly"
                ),
            ],
            kind="keysigner",
        )
        self.docker(["start", container])

        # The probe command is expected to fail until the socket exists; use a
        # dedicated non-raising probe so readiness is event-driven.
        def safe_socket_ready() -> bool:
            probe = self.create_container(
                NATIVE_HELPER_IMAGE,
                "/bin/sh",
                ["-c", "test -S /sock/smoke.sock"],
                [
                    "--pull",
                    "never",
                    *self.native_helper_options(user="10002:10002"),
                    "--mount",
                    f"type=volume,src={socket_volume},dst=/sock,readonly",
                ],
                kind="keysigner-probe",
            )
            try:
                result = self.docker(["start", "--attach", probe], check=False)
                return result.returncode == 0
            finally:
                self.remove_container(probe)

        wait_for_service(
            "keysigner socket",
            lambda: self.container_state(container),
            safe_socket_ready,
        )
        logs = self.docker(["logs", "--tail", "200", container], check=False)
        if "remote private-key signer listening" not in f"{logs.stdout}\n{logs.stderr}":
            raise SmokeError("keysigner did not emit its bounded readiness log")
        self.stop_container(container)
        self.remove_container(container)

    def run_role(self) -> None:
        if self.artifact.role in ("standalone", "dataplane", "dataplane-strict"):
            self.run_server_role()
        elif self.artifact.role == "controller":
            self.run_controller_role()
        elif self.artifact.role == "tools":
            self.run_tools_role()
        elif self.artifact.role == "keysigner":
            self.run_keysigner_role()
        else:
            raise SmokeError(f"unsupported runtime role: {self.artifact.role}")

    def capture_diagnostics(self) -> None:
        self.args.evidence_dir.mkdir(parents=True, exist_ok=True)
        for index, container in enumerate(list(self.containers), start=1):
            try:
                state = self.docker(
                    ["inspect", "--format", "{{json .State}}", container],
                    check=False,
                )
                state_text = state.stdout
            except SmokeError as error:
                state_text = json.dumps({"diagnostic_error": str(error)})
            try:
                logs = self.docker(
                    ["logs", "--timestamps", "--tail", "200", container],
                    check=False,
                )
                logs_text = f"{logs.stdout}\n{logs.stderr}"
            except SmokeError as error:
                logs_text = f"failed to capture Docker logs: {error}"
            (self.args.evidence_dir / f"container-{index}-state.json").write_text(
                state_text[:MAXIMUM_LOG_BYTES],
                encoding="utf-8",
            )
            (self.args.evidence_dir / f"container-{index}.log").write_text(
                logs_text[-MAXIMUM_LOG_BYTES:],
                encoding="utf-8",
            )

    def cleanup(self) -> list[str]:
        errors: list[str] = []

        def remove(
            args: list[str],
            description: str,
            *,
            missing_ok: bool = False,
        ) -> None:
            try:
                result = self.docker(args, check=False)
            except SmokeError as error:
                errors.append(f"{description}: {error}")
                return
            if result.returncode != 0:
                detail = (result.stderr or result.stdout).strip()[-1024:]
                normalized_detail = detail.lower()
                if missing_ok and (
                    "no such image" in normalized_detail
                    or "no such object" in normalized_detail
                ):
                    return
                errors.append(f"{description}: {detail or f'exit {result.returncode}'}")

        for container in reversed(self.containers):
            remove(["rm", "--force", container], f"container {container}")
        self.containers.clear()
        for volume in reversed(self.volumes):
            remove(["volume", "rm", volume], f"volume {volume}")
        self.volumes.clear()
        for network in reversed(self.networks):
            remove(["network", "rm", network], f"network {network}")
        self.networks.clear()
        try:
            for reference in sorted(self.loaded_image_references):
                remove(
                    ["image", "rm", reference],
                    f"image reference {reference}",
                    missing_ok=True,
                )
            if (
                self.runtime_image_id is not None
                and self.runtime_image_id not in self.preexisting_image_ids
            ):
                runtime_image_id = self.runtime_image_id
                try:
                    remaining = self.docker(
                        ["image", "inspect", runtime_image_id],
                        check=False,
                    )
                except SmokeError as error:
                    errors.append(
                        f"inspect image {runtime_image_id}: {error}"
                    )
                else:
                    if remaining.returncode == 0:
                        remove(
                            ["image", "rm", runtime_image_id],
                            f"image {runtime_image_id}",
                        )
                    else:
                        detail = (
                            remaining.stderr or remaining.stdout
                        ).strip().lower()
                        if (
                            "no such image" not in detail
                            and "no such object" not in detail
                        ):
                            errors.append(
                                f"inspect image {runtime_image_id}: "
                                f"{detail[-1024:]}"
                            )
            if self.native_helper_pulled and not self.native_helper_preexisting:
                remove(
                    ["image", "rm", NATIVE_HELPER_IMAGE],
                    "native helper image",
                )
        finally:
            try:
                self.temporary.cleanup()
            except OSError as error:
                errors.append(f"temporary directory: {error}")
        return errors


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image-plan", required=True, type=pathlib.Path)
    parser.add_argument("--artifact-contract", required=True, type=pathlib.Path)
    parser.add_argument("--build-metadata", required=True, type=pathlib.Path)
    parser.add_argument("--image-tar", required=True, type=pathlib.Path)
    parser.add_argument("--fixture-root", required=True, type=pathlib.Path)
    parser.add_argument("--strict-validator", required=True, type=pathlib.Path)
    parser.add_argument("--role", required=True, choices=tuple(ROLE_BINARIES))
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("--expected-source-ref", required=True)
    parser.add_argument("--evidence-dir", required=True, type=pathlib.Path)
    return parser.parse_args()


def write_receipt(path: pathlib.Path, receipt: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as stream:
        temporary = pathlib.Path(stream.name)
        json.dump(receipt, stream, indent=2, sort_keys=True)
        stream.write("\n")
    os.replace(temporary, path)


def main() -> int:
    args = parse_args()
    args.evidence_dir.mkdir(parents=True, exist_ok=True)
    receipt: dict[str, Any] = {
        "schemaVersion": 1,
        "role": args.role,
        "artifactArch": "riscv64",
        "outcome": "failed",
        "checks": [],
    }
    smoke: DockerSmoke | None = None
    try:
        artifact = validate_release_artifact(args)
        receipt["imageId"] = artifact.image_id
        receipt["manifestDigest"] = artifact.manifest_digest
        receipt["identity"] = artifact.identity
        smoke = DockerSmoke(CommandRunner(), artifact, args, receipt)
        smoke.check("load immutable RISC-V image", smoke.load_and_verify_image)
        smoke.check("verify exact role executable inventory", smoke.verify_loaded_inventory)
        if args.role == "dataplane-strict":
            smoke.check(
                "verify strict image filesystem and Admin asset absence",
                lambda: smoke.runner.run(
                    [
                        sys.executable,
                        str(args.strict_validator),
                        str(args.image_tar),
                    ],
                    timeout=60,
                ),
            )
        smoke.check("verify canonical version and revision", smoke.run_versions)
        smoke.check(f"run {args.role} runtime contract", smoke.run_role)
        receipt["outcome"] = "passed"
        return_code = 0
    except Exception as error:
        receipt["failure"] = str(error)[:4096]
        if smoke is not None:
            try:
                smoke.capture_diagnostics()
            except Exception as diagnostic_error:
                receipt["diagnosticFailure"] = str(diagnostic_error)[:4096]
        print(f"RISC-V release image smoke failed: {error}", file=sys.stderr)
        return_code = 1
    finally:
        if smoke is not None:
            cleanup_errors = smoke.cleanup()
            if cleanup_errors:
                receipt["cleanupFailures"] = cleanup_errors
                receipt["outcome"] = "failed"
                receipt.setdefault(
                    "failure",
                    "one or more exact Docker resource cleanup operations failed",
                )
                return_code = 1
        write_receipt(args.evidence_dir / "runtime-smoke-receipt.json", receipt)
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
