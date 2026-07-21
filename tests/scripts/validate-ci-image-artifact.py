#!/usr/bin/env python3
"""Create and validate the identity contract for a CI Docker image artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import tarfile
import tempfile
from typing import Any


MAXIMUM_ARCHIVE_BYTES = 4 * 1024 * 1024 * 1024
MAXIMUM_ARCHIVE_MEMBERS = 4096
MAXIMUM_JSON_BYTES = 8 * 1024 * 1024
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")

ARCHITECTURES = {
    "amd64v2": {
        "platform": "linux/amd64",
        "docker_architecture": "amd64",
        "rust_target": "x86_64-unknown-linux-musl",
        "target_cpu": "x86-64-v2",
    },
    "amd64": {
        "platform": "linux/amd64",
        "docker_architecture": "amd64",
        "rust_target": "x86_64-unknown-linux-musl",
        "target_cpu": "x86-64-v3",
    },
    "amd64v4": {
        "platform": "linux/amd64",
        "docker_architecture": "amd64",
        "rust_target": "x86_64-unknown-linux-musl",
        "target_cpu": "x86-64-v4",
    },
    "arm64": {
        "platform": "linux/arm64",
        "docker_architecture": "arm64",
        "rust_target": "aarch64-unknown-linux-musl",
        "target_cpu": None,
    },
    "riscv64": {
        "platform": "linux/riscv64",
        "docker_architecture": "riscv64",
        "rust_target": "riscv64gc-unknown-linux-musl",
        "target_cpu": None,
    },
}

ROLES = {
    "standalone": {
        "prefix": "oxibelt",
        "user": "10001:10001",
        "entrypoint": [
            "/usr/local/bin/oxibelt",
            "--config",
            "/etc/oxibelt/config/oxibelt.toml",
        ],
        "ports": ["8443/tcp", "8443/udp"],
    },
    "dataplane": {
        "prefix": "oxibelt-dataplane",
        "user": "10001:10001",
        "entrypoint": [
            "/usr/local/bin/oxibelt",
            "--config",
            "/etc/oxibelt/config/oxibelt.toml",
        ],
        "ports": ["8443/tcp", "8443/udp"],
    },
    "dataplane-strict": {
        "prefix": "oxibelt-dataplane-strict",
        "user": "10001:10001",
        "entrypoint": [
            "/usr/local/bin/oxibelt-dataplane-strict",
            "--config",
            "/etc/oxibelt/config/oxibelt.toml",
        ],
        "ports": ["8443/tcp", "8443/udp"],
    },
    "controller": {
        "prefix": "oxibelt-gateway-controller",
        "user": "10001:10001",
        "entrypoint": ["/usr/local/bin/oxibelt-gateway-controller"],
        "ports": [],
    },
    "tools": {
        "prefix": "oxibelt-tools",
        "user": "10001:10001",
        "entrypoint": ["/usr/local/bin/oxibeltctl"],
        "ports": [],
    },
    "keysigner": {
        "prefix": "oxibelt-keysigner",
        "user": "10002:10002",
        "entrypoint": ["/usr/local/bin/oxibelt-keysigner"],
        "ports": [],
    },
}

CONTRACT_KEYS = {
    "schema",
    "revision",
    "source",
    "role",
    "platform",
    "artifact_arch",
    "docker_architecture",
    "rust_target",
    "target_cpu",
    "image_tar",
    "image_tar_sha256",
    "build_metadata",
    "config_digest",
    "descriptor_digest",
    "image_digest",
}


def fail(message: str) -> None:
    raise SystemExit(f"CI image artifact validation failed: {message}")


def load_json(path: pathlib.Path, description: str) -> Any:
    if not path.is_file():
        fail(f"missing {description}: {path}")
    if path.stat().st_size > MAXIMUM_JSON_BYTES:
        fail(f"{description} exceeds the 8 MiB limit: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot read {description} {path}: {error}")


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        fail(f"cannot hash {path}: {error}")
    return f"sha256:{digest.hexdigest()}"


def safe_member_name(name: str) -> str:
    if "\x00" in name or "\\" in name:
        fail(f"unsafe Docker archive member name {name!r}")
    path = pathlib.PurePosixPath(name)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        fail(f"unsafe Docker archive member name {name!r}")
    return path.as_posix()


def read_regular_member(archive: tarfile.TarFile, name: str) -> bytes:
    try:
        member = archive.getmember(name)
    except KeyError:
        fail(f"Docker archive is missing {name!r}")
    if not member.isfile() or member.size > MAXIMUM_JSON_BYTES:
        fail(f"Docker archive member {name!r} is not a bounded regular file")
    stream = archive.extractfile(member)
    if stream is None:
        fail(f"Docker archive member {name!r} cannot be read")
    return stream.read()


def content_digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def metadata_digest(metadata: dict[str, Any], key: str) -> str:
    value = metadata.get(key)
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        fail(f"Buildx metadata {key!r} is not a SHA-256 digest")
    return value


def descriptor_digest(metadata: dict[str, Any]) -> str:
    descriptor = metadata.get("containerimage.descriptor")
    value = descriptor.get("digest") if isinstance(descriptor, dict) else None
    if value is None:
        value = metadata.get("containerimage.descriptor.digest")
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        fail("Buildx metadata does not contain a valid descriptor digest")
    return value


def expected_paths(
    image_tar: pathlib.Path, build_metadata: pathlib.Path, role: str, artifact_arch: str
) -> tuple[str, str, str]:
    role_contract = ROLES.get(role)
    if role_contract is None:
        fail(f"unknown role {role!r}")
    if artifact_arch not in ARCHITECTURES:
        fail(f"unknown artifact architecture {artifact_arch!r}")
    prefix = role_contract["prefix"]
    expected_tar = f"{prefix}-alpine-musl-{artifact_arch}.tar"
    expected_metadata = f"{prefix}-alpine-musl-{artifact_arch}-build-metadata.json"
    expected_contract = f"{prefix}-alpine-musl-{artifact_arch}-artifact-contract.json"
    if image_tar.name != expected_tar:
        fail(f"image tar is named {image_tar.name!r}, expected {expected_tar!r}")
    if build_metadata.name != expected_metadata:
        fail(
            f"build metadata is named {build_metadata.name!r}, expected {expected_metadata!r}"
        )
    return expected_tar, expected_metadata, expected_contract


def inspect_artifact(
    image_tar: pathlib.Path,
    build_metadata_path: pathlib.Path,
    role: str,
    artifact_arch: str,
    revision: str,
    source: str,
) -> dict[str, Any]:
    if not image_tar.is_file():
        fail(f"missing image tar: {image_tar}")
    if image_tar.stat().st_size > MAXIMUM_ARCHIVE_BYTES:
        fail(f"image tar exceeds the 4 GiB limit: {image_tar}")
    expected_tar, expected_metadata, _ = expected_paths(
        image_tar, build_metadata_path, role, artifact_arch
    )
    metadata = load_json(build_metadata_path, "Buildx metadata")
    if not isinstance(metadata, dict):
        fail("Buildx metadata must be a JSON object")
    config_digest = metadata_digest(metadata, "containerimage.config.digest")
    image_digest = metadata_digest(metadata, "containerimage.digest")
    build_descriptor_digest = descriptor_digest(metadata)
    if build_descriptor_digest != image_digest:
        fail("Buildx descriptor digest does not match the image digest")

    try:
        with tarfile.open(image_tar, mode="r:*") as archive:
            members = []
            for member in archive:
                members.append(member)
                if len(members) > MAXIMUM_ARCHIVE_MEMBERS:
                    fail("Docker archive exceeds the 4096-member limit")
            names = [safe_member_name(member.name) for member in members]
            if len(names) != len(set(names)):
                fail("Docker archive contains duplicate member names")
            manifest_bytes = read_regular_member(archive, "manifest.json")
            manifest = json.loads(manifest_bytes)
            if not isinstance(manifest, list) or len(manifest) != 1:
                fail("Docker archive must contain exactly one image manifest")
            descriptor = manifest[0]
            if not isinstance(descriptor, dict):
                fail("Docker archive manifest entry must be an object")
            config_name = descriptor.get("Config")
            if not isinstance(config_name, str):
                fail("Docker archive manifest lacks a config reference")
            safe_member_name(config_name)
            config_bytes = read_regular_member(archive, config_name)
            archive_config_digest = content_digest(config_bytes)
            config = json.loads(config_bytes)
    except (tarfile.TarError, json.JSONDecodeError) as error:
        fail(f"invalid Docker archive: {error}")

    if archive_config_digest != config_digest:
        fail("Docker archive config digest does not match Buildx metadata")
    config_hash = config_digest.removeprefix("sha256:")
    if config_name not in (f"{config_hash}.json", f"blobs/sha256/{config_hash}"):
        fail("Docker archive config path is not content addressed by its digest")
    if not isinstance(config, dict):
        fail("Docker image config must be an object")

    architecture = ARCHITECTURES[artifact_arch]
    if config.get("os") != "linux" or config.get("architecture") != architecture["docker_architecture"]:
        fail("Docker image OS/architecture does not match the artifact architecture")
    runtime = config.get("config")
    if not isinstance(runtime, dict):
        fail("Docker image lacks a runtime config object")
    role_contract = ROLES[role]
    if runtime.get("User") != role_contract["user"]:
        fail(f"Docker image has an unexpected runtime user for role {role}")
    if runtime.get("Entrypoint") != role_contract["entrypoint"] or runtime.get("Cmd") not in (
        None,
        [],
    ):
        fail(f"Docker image has an unexpected entrypoint/Cmd for role {role}")
    ports = runtime.get("ExposedPorts") or {}
    if not isinstance(ports, dict) or sorted(ports) != role_contract["ports"]:
        fail(f"Docker image has unexpected exposed ports for role {role}")
    labels = runtime.get("Labels")
    if not isinstance(labels, dict):
        fail("Docker image lacks OCI labels")
    for key, value in {
        "org.opencontainers.image.revision": revision,
        "org.opencontainers.image.source": source,
        "org.opencontainers.image.url": source,
        "io.oxibelt.image.role": role,
    }.items():
        if labels.get(key) != value:
            fail(f"Docker image label {key!r} does not match the expected identity")

    return {
        "schema": 1,
        "revision": revision,
        "source": source,
        "role": role,
        "platform": architecture["platform"],
        "artifact_arch": artifact_arch,
        "docker_architecture": architecture["docker_architecture"],
        "rust_target": architecture["rust_target"],
        "target_cpu": architecture["target_cpu"],
        "image_tar": expected_tar,
        "image_tar_sha256": sha256_file(image_tar),
        "build_metadata": expected_metadata,
        "config_digest": config_digest,
        "descriptor_digest": build_descriptor_digest,
        "image_digest": image_digest,
    }


def write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
    ) as stream:
        temporary = pathlib.Path(stream.name)
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
    os.replace(temporary, path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("create", "validate"))
    parser.add_argument("--image-tar", required=True, type=pathlib.Path)
    parser.add_argument("--build-metadata", required=True, type=pathlib.Path)
    parser.add_argument("--contract", required=True, type=pathlib.Path)
    parser.add_argument("--role", required=True, choices=tuple(ROLES))
    parser.add_argument("--artifact-arch", required=True, choices=tuple(ARCHITECTURES))
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("--expected-source", required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    _, _, expected_contract = expected_paths(
        args.image_tar, args.build_metadata, args.role, args.artifact_arch
    )
    if args.contract.name != expected_contract:
        fail(f"contract is named {args.contract.name!r}, expected {expected_contract!r}")
    observed = inspect_artifact(
        args.image_tar,
        args.build_metadata,
        args.role,
        args.artifact_arch,
        args.expected_revision,
        args.expected_source,
    )
    if args.mode == "create":
        write_json(args.contract, observed)
    else:
        contract = load_json(args.contract, "artifact contract")
        if not isinstance(contract, dict) or set(contract) != CONTRACT_KEYS:
            fail("artifact contract has an unexpected schema")
        if contract != observed:
            fail("artifact contract does not match the downloaded image and Buildx metadata")
    print(f"validated CI image artifact: {args.role}/{args.artifact_arch}")


if __name__ == "__main__":
    main()
