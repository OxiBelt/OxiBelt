#!/usr/bin/env python3
"""Create and validate the identity contract for a CI Docker image artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import tarfile
import tempfile
from typing import Any


MAXIMUM_ARCHIVE_BYTES = 4 * 1024 * 1024 * 1024
MAXIMUM_ARCHIVE_MEMBERS = 4096
MAXIMUM_JSON_BYTES = 8 * 1024 * 1024
MAXIMUM_BINARY_BYTES = 256 * 1024 * 1024
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
GIT_OBJECT = re.compile(r"[0-9a-f]{40}\Z")
CREATED = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
SOURCE_REF = re.compile(r"refs/(?:heads|tags)/[A-Za-z0-9._/-]+\Z")
BUILD_IDENTITY_MARKER = re.compile(
    rb"OXIBELT_BUILD_IDENTITY_V1=(\{[^}\x00\r\n]{1,4096}\})"
)

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
        "docker_target": "standalone",
        "cargo_builds": [
            {"package": "oxibelt", "binary": "oxibelt", "default_features": True},
            {"package": "oxibelt-keysigner", "binary": "oxibelt-keysigner", "default_features": True},
            {"package": "oxibelt-netport-switcher", "binary": "oxibelt-netport-switcher", "default_features": True},
            {"package": "oxibeltctl", "binary": "oxibeltctl", "default_features": True},
        ],
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
        "docker_target": "dataplane",
        "cargo_builds": [
            {"package": "oxibelt", "binary": "oxibelt", "default_features": True}
        ],
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
        "docker_target": "dataplane-strict",
        "cargo_builds": [
            {
                "package": "oxibelt-dataplane-strict",
                "binary": "oxibelt-dataplane-strict",
                "default_features": False,
            }
        ],
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
        "docker_target": "controller",
        "cargo_builds": [
            {
                "package": "oxibelt-gateway-controller",
                "binary": "oxibelt-gateway-controller",
                "default_features": True,
            }
        ],
        "user": "10001:10001",
        "entrypoint": ["/usr/local/bin/oxibelt-gateway-controller"],
        "ports": [],
    },
    "tools": {
        "prefix": "oxibelt-tools",
        "docker_target": "tools",
        "cargo_builds": [
            {"package": "oxibeltctl", "binary": "oxibeltctl", "default_features": True}
        ],
        "user": "10001:10001",
        "entrypoint": ["/usr/local/bin/oxibeltctl"],
        "ports": [],
    },
    "keysigner": {
        "prefix": "oxibelt-keysigner",
        "docker_target": "keysigner",
        "cargo_builds": [
            {
                "package": "oxibelt-keysigner",
                "binary": "oxibelt-keysigner",
                "default_features": True,
            }
        ],
        "user": "10002:10002",
        "entrypoint": ["/usr/local/bin/oxibelt-keysigner"],
        "ports": [],
    },
}

CONTRACT_KEYS = {
    "schema",
    "revision",
    "source",
    "source_tree",
    "version",
    "ref_name",
    "source_ref",
    "source_dirty",
    "build_kind",
    "created",
    "role",
    "platform",
    "artifact_arch",
    "docker_architecture",
    "rust_target",
    "target_cpu",
    "docker_target",
    "cargo_builds",
    "build_parameters",
    "source_inputs",
    "source_inputs_sha256",
    "image_tar",
    "image_tar_sha256",
    "build_metadata",
    "config_digest",
    "normalized_config_sha256",
    "descriptor_digest",
    "image_digest",
    "layers",
    "binaries",
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


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return content_digest(encoded)


def rebuild_source_inputs(repo_root: pathlib.Path) -> dict[str, Any]:
    try:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(repo_root),
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "-z",
            ],
            check=True,
            capture_output=True,
        )
        relative_paths = result.stdout.decode("utf-8").removesuffix("\x00").split("\x00")
    except (OSError, subprocess.CalledProcessError, UnicodeDecodeError) as error:
        fail(f"cannot enumerate rebuild source inputs: {error}")
    if not relative_paths or relative_paths == [""]:
        fail("rebuild source input inventory is empty")
    inputs: dict[str, Any] = {}
    for relative in sorted(relative_paths):
        safe_member_name(relative)
        path = repo_root / relative
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            # A local pre-commit validation can observe an index entry deleted
            # by the working tree. Record the absence so it cannot compare as
            # equivalent to a build where the file exists.
            inputs[relative] = {"type": "absent"}
            continue
        except OSError as error:
            fail(f"cannot inspect rebuild input {relative}: {error}")
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISREG(metadata.st_mode):
            inputs[relative] = {
                "type": "file",
                "mode": mode,
                "sha256": sha256_file(path),
            }
        elif stat.S_ISLNK(metadata.st_mode):
            target = os.readlink(path)
            if "\x00" in target:
                fail(f"rebuild input symlink contains NUL: {relative}")
            inputs[relative] = {"type": "symlink", "mode": mode, "target": target}
        else:
            fail(f"rebuild input must be a regular file or symlink: {relative}")
    return inputs


def safe_member_name(name: str) -> str:
    if "\x00" in name or "\\" in name:
        fail(f"unsafe Docker archive member name {name!r}")
    path = pathlib.PurePosixPath(name)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        fail(f"unsafe Docker archive member name {name!r}")
    if path.as_posix() != name.rstrip("/"):
        fail(f"non-canonical Docker archive member name {name!r}")
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


def hash_regular_member(archive: tarfile.TarFile, name: str) -> str:
    try:
        member = archive.getmember(name)
    except KeyError:
        fail(f"Docker archive is missing {name!r}")
    if not member.isfile() or member.size > MAXIMUM_ARCHIVE_BYTES:
        fail(f"Docker archive member {name!r} is not a bounded regular file")
    stream = archive.extractfile(member)
    if stream is None:
        fail(f"Docker archive member {name!r} cannot be read")
    digest = hashlib.sha256()
    total = 0
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        total += len(block)
        if total > member.size:
            fail(f"Docker archive member {name!r} exceeded its declared size")
        digest.update(block)
    if total != member.size:
        fail(f"Docker archive member {name!r} was truncated")
    return f"sha256:{digest.hexdigest()}"


def content_digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def normalized_config_digest(config: dict[str, Any]) -> str:
    normalized = json.loads(json.dumps(config))
    normalized.pop("created", None)
    history = normalized.get("history")
    if isinstance(history, list):
        for entry in history:
            if isinstance(entry, dict):
                entry.pop("created", None)
    return canonical_digest(normalized)


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


def inspect_binary_identities(
    archive: tarfile.TarFile,
    layer_paths: list[str],
    role_contract: dict[str, Any],
    expected_identity: dict[str, str],
) -> list[dict[str, str]]:
    binary_names = sorted(
        {build["binary"] for build in role_contract["cargo_builds"]}
    )
    expected_paths = {f"usr/local/bin/{name}": name for name in binary_names}
    binaries: dict[str, bytes] = {}
    for layer_path in layer_paths:
        layer_member = archive.getmember(layer_path)
        layer_stream = archive.extractfile(layer_member)
        if layer_stream is None:
            fail(f"Docker layer {layer_path!r} cannot be read")
        try:
            with tarfile.open(fileobj=layer_stream, mode="r:*") as layer:
                for member in layer:
                    normalized = member.name.removeprefix("./").lstrip("/")
                    if normalized == "usr/local/bin/.wh..wh..opq":
                        binaries.clear()
                        continue
                    if normalized.startswith("usr/local/bin/.wh."):
                        removed_path = normalized.replace("/.wh.", "/", 1)
                        removed_name = expected_paths.get(removed_path)
                        if removed_name is not None:
                            binaries.pop(removed_name, None)
                        continue
                    name = expected_paths.get(normalized)
                    if name is None:
                        continue
                    if not member.isfile() or member.size > MAXIMUM_BINARY_BYTES:
                        fail(f"image binary {normalized!r} is not a bounded regular file")
                    stream = layer.extractfile(member)
                    if stream is None:
                        fail(f"image binary {normalized!r} cannot be read")
                    binaries[name] = stream.read()
        except tarfile.TarError as error:
            fail(f"invalid Docker layer {layer_path!r}: {error}")

    inventory: list[dict[str, str]] = []
    for name in binary_names:
        binary = binaries.get(name)
        if binary is None:
            fail(f"Docker image is missing expected binary /usr/local/bin/{name}")
        markers = BUILD_IDENTITY_MARKER.findall(binary)
        if len(markers) != 1:
            fail(f"binary {name} does not contain exactly one canonical build identity marker")
        try:
            identity = json.loads(markers[0].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            fail(f"binary {name} contains an invalid build identity marker: {error}")
        if identity != expected_identity:
            fail(f"binary {name} build identity does not match labels and build inputs")
        inventory.append(
            {
                "name": name,
                "path": f"/usr/local/bin/{name}",
                "sha256": hashlib.sha256(binary).hexdigest(),
                "version": identity["version"],
            }
        )
    return inventory


def inspect_artifact(
    image_tar: pathlib.Path,
    build_metadata_path: pathlib.Path,
    role: str,
    artifact_arch: str,
    revision: str,
    source: str,
    source_tree: str,
    version: str,
    ref_name: str,
    source_ref: str,
    source_dirty: str,
    build_kind: str,
    created: str,
    rust_builder_image: str,
    node_builder_image: str,
    runtime_image: str,
    repo_root: pathlib.Path,
) -> dict[str, Any]:
    if GIT_OBJECT.fullmatch(revision) is None:
        fail("expected revision must be a full lowercase Git object ID")
    if GIT_OBJECT.fullmatch(source_tree) is None:
        fail("expected source tree must be a full lowercase Git object ID")
    if not version or not ref_name:
        fail("expected version and ref name must be non-empty")
    if source_ref != "unknown" and SOURCE_REF.fullmatch(source_ref) is None:
        fail("expected source ref must be unknown or a canonical full Git ref")
    if source_dirty not in ("clean", "dirty", "unknown"):
        fail("expected source dirty state is invalid")
    if build_kind not in (
        "official_release",
        "tagged_development",
        "git_development",
        "source_archive",
    ):
        fail("expected build kind is invalid")
    if CREATED.fullmatch(created) is None:
        fail("expected creation time must be second-resolution UTC RFC 3339")
    for description, value in (
        ("source", source),
        ("Rust builder image", rust_builder_image),
        ("Node builder image", node_builder_image),
        ("runtime image", runtime_image),
    ):
        if not value or any(character.isspace() for character in value):
            fail(f"expected {description} must be a non-empty value without whitespace")
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
            layer_names = descriptor.get("Layers")
            if not isinstance(layer_names, list) or not all(
                isinstance(item, str) for item in layer_names
            ):
                fail("Docker archive manifest lacks an ordered layer list")
            layer_paths = [safe_member_name(item) for item in layer_names]
            if len(layer_paths) != len(set(layer_paths)):
                fail("Docker archive manifest contains duplicate layer paths")
            layer_digests = [hash_regular_member(archive, item) for item in layer_paths]
            expected_identity = {
                "version": version,
                "revision": revision,
                "source_ref": source_ref,
                "dirty": source_dirty,
                "kind": build_kind,
            }
            binaries = inspect_binary_identities(
                archive, layer_paths, ROLES[role], expected_identity
            )
    except (tarfile.TarError, json.JSONDecodeError) as error:
        fail(f"invalid Docker archive: {error}")

    if archive_config_digest != config_digest:
        fail("Docker archive config digest does not match Buildx metadata")
    config_hash = config_digest.removeprefix("sha256:")
    if config_name not in (f"{config_hash}.json", f"blobs/sha256/{config_hash}"):
        fail("Docker archive config path is not content addressed by its digest")
    if not isinstance(config, dict):
        fail("Docker image config must be an object")
    rootfs = config.get("rootfs")
    diff_ids = rootfs.get("diff_ids") if isinstance(rootfs, dict) else None
    if not isinstance(diff_ids, list) or len(diff_ids) != len(layer_digests):
        fail("Docker image config rootfs diff IDs do not match the layer list")
    if not all(isinstance(item, str) and DIGEST.fullmatch(item) for item in diff_ids):
        fail("Docker image config contains an invalid rootfs diff ID")

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
        "org.opencontainers.image.created": created,
        "org.opencontainers.image.version": version,
        "org.opencontainers.image.ref.name": ref_name,
        "org.opencontainers.image.revision": revision,
        "org.opencontainers.image.source": source,
        "org.opencontainers.image.url": source,
        "io.oxibelt.image.role": role,
        "io.oxibelt.build.source-ref": source_ref,
        "io.oxibelt.build.dirty": source_dirty,
        "io.oxibelt.build.kind": build_kind,
    }.items():
        if labels.get(key) != value:
            fail(f"Docker image label {key!r} does not match the expected identity")

    source_inputs = rebuild_source_inputs(repo_root)
    build_parameters = {
        "rust_builder_image": rust_builder_image,
        "node_builder_image": node_builder_image,
        "runtime_image": runtime_image,
        "rust_builder_stage": (
            "builder-riscv64" if artifact_arch == "riscv64" else "builder-native"
        ),
        "rust_target": architecture["rust_target"],
        "rust_target_cpu": architecture["target_cpu"],
        "docker_platform": architecture["platform"],
        "docker_target": role_contract["docker_target"],
        "version": version,
        "revision": revision,
        "created": created,
        "source": source,
        "ref_name": ref_name,
        "source_ref": source_ref,
        "source_dirty": source_dirty,
        "build_kind": build_kind,
    }
    layers = [
        {"path": path, "content_digest": digest, "diff_id": diff_id}
        for path, digest, diff_id in zip(
            layer_paths, layer_digests, diff_ids, strict=True
        )
    ]

    return {
        "schema": 3,
        "revision": revision,
        "source": source,
        "source_tree": source_tree,
        "version": version,
        "ref_name": ref_name,
        "source_ref": source_ref,
        "source_dirty": source_dirty,
        "build_kind": build_kind,
        "created": created,
        "role": role,
        "platform": architecture["platform"],
        "artifact_arch": artifact_arch,
        "docker_architecture": architecture["docker_architecture"],
        "rust_target": architecture["rust_target"],
        "target_cpu": architecture["target_cpu"],
        "docker_target": role_contract["docker_target"],
        "cargo_builds": role_contract["cargo_builds"],
        "build_parameters": build_parameters,
        "source_inputs": source_inputs,
        "source_inputs_sha256": canonical_digest(source_inputs),
        "image_tar": expected_tar,
        "image_tar_sha256": sha256_file(image_tar),
        "build_metadata": expected_metadata,
        "config_digest": config_digest,
        "normalized_config_sha256": normalized_config_digest(config),
        "descriptor_digest": build_descriptor_digest,
        "image_digest": image_digest,
        "layers": layers,
        "binaries": binaries,
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
    parser.add_argument("--expected-source-tree", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-ref-name", required=True)
    parser.add_argument("--expected-source-ref", required=True)
    parser.add_argument("--expected-source-dirty", required=True)
    parser.add_argument("--expected-build-kind", required=True)
    parser.add_argument("--expected-created", required=True)
    parser.add_argument("--rust-builder-image", required=True)
    parser.add_argument("--node-builder-image", required=True)
    parser.add_argument("--runtime-image", required=True)
    parser.add_argument(
        "--repo-root",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parents[2],
    )
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
        args.expected_source_tree,
        args.expected_version,
        args.expected_ref_name,
        args.expected_source_ref,
        args.expected_source_dirty,
        args.expected_build_kind,
        args.expected_created,
        args.rust_builder_image,
        args.node_builder_image,
        args.runtime_image,
        args.repo_root.resolve(),
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
