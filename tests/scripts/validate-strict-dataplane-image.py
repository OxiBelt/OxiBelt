#!/usr/bin/env python3
"""Validate the exact filesystem and OCI runtime contract of a docker-save archive."""

from __future__ import annotations

import hashlib
import io
import json
import pathlib
import posixpath
import re
import sys
import tarfile
from dataclasses import dataclass


EXPECTED_FILES = {
    "etc/group",
    "etc/oxibelt/config/oxibelt.toml",
    "etc/passwd",
    "etc/ssl/certs/ca-certificates.crt",
    "usr/local/bin/oxibelt-dataplane-strict",
}
ALLOWED_DIRECTORIES = {
    "app",
    "etc",
    "etc/oxibelt",
    "etc/oxibelt/cert",
    "etc/oxibelt/config",
    "etc/oxibelt/oxirule",
    "etc/ssl",
    "etc/ssl/certs",
    "usr",
    "usr/local",
    "usr/local/bin",
}
EXPECTED_ENTRYPOINT = [
    "/usr/local/bin/oxibelt-dataplane-strict",
    "--config",
    "/etc/oxibelt/config/oxibelt.toml",
]
EXPECTED_PORTS = {"8443/tcp", "8443/udp"}
EXPECTED_PASSWD = b"oxibelt:x:10001:10001:OxiBelt strict data plane:/nonexistent:/sbin/nologin\n"
EXPECTED_GROUP = b"oxibelt:x:10001:\n"
PERSON_PROOF_MARKER = b'<meta name="oxibelt-person-proof-session"'
ADMIN_MARKERS = (
    b'"title": "OxiBelt Admin API"',
    b"/admin/v1/config/load",
    b"/admin/v1/openapi.json",
)
ADMIN_CONFIG_SECTION = re.compile(rb"(?m)^[ \t]*\[\[?[ \t]*admin(?:[ \t]*[.\]])")
MAXIMUM_ARCHIVE_BYTES = 1024 * 1024 * 1024
MAXIMUM_LAYER_BYTES = 512 * 1024 * 1024
MAXIMUM_FILE_BYTES = 256 * 1024 * 1024


@dataclass(frozen=True)
class FileRecord:
    data: bytes
    mode: int
    uid: int
    gid: int


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"strict data-plane image validation failed: {message}")


def safe_name(name: str, context: str) -> str:
    if "\x00" in name or "\\" in name or name.startswith("/"):
        fail(f"unsafe {context} path {name!r}")
    candidate = name
    while candidate.startswith("./"):
        candidate = candidate[2:]
    candidate = candidate.rstrip("/")
    if any(part in ("", ".", "..") for part in candidate.split("/")):
        fail(f"ambiguous or traversing {context} path {name!r}")
    normalized = posixpath.normpath(candidate)
    if normalized.startswith("/"):
        fail(f"absolute {context} path after normalization {name!r}")
    if normalized in ("", "."):
        return ""
    if normalized == ".." or normalized.startswith("../") or name.endswith("/.."):
        fail(f"traversing {context} path {name!r}")
    return normalized.rstrip("/")


def checked_members(archive: tarfile.TarFile, context: str) -> list[tarfile.TarInfo]:
    members = archive.getmembers()
    seen: set[str] = set()
    for member in members:
        name = safe_name(member.name, context)
        if not name:
            continue
        if name in seen:
            fail(f"duplicate {context} member {name!r}")
        seen.add(name)
        if member.size < 0 or member.size > MAXIMUM_LAYER_BYTES:
            fail(f"oversized {context} member {name!r}")
        if not (member.isfile() or member.isdir()):
            fail(f"unsupported {context} member type for {name!r}")
    return members


def member_bytes(archive: tarfile.TarFile, name: str, context: str) -> bytes:
    try:
        member = archive.getmember(name)
    except KeyError:
        fail(f"missing {context} member {name!r}")
    if not member.isfile():
        fail(f"{context} member {name!r} is not a regular file")
    stream = archive.extractfile(member)
    if stream is None:
        fail(f"cannot read {context} member {name!r}")
    return stream.read()


def verify_content_address(name: str, data: bytes, context: str) -> None:
    match = re.fullmatch(r"blobs/sha256/([0-9a-f]{64})", name)
    if match is not None and hashlib.sha256(data).hexdigest() != match.group(1):
        fail(f"{context} content does not match its sha256 path")


def validate_layer(layer_bytes: bytes, layer_name: str, filesystem: dict[str, FileRecord]) -> None:
    try:
        with tarfile.open(fileobj=io.BytesIO(layer_bytes), mode="r:*") as layer:
            members = checked_members(layer, f"layer {layer_name}")
            if sum(member.size for member in members) > MAXIMUM_LAYER_BYTES:
                fail(f"decompressed layer {layer_name!r} exceeds the 512 MiB limit")
            for member in members:
                name = safe_name(member.name, f"layer {layer_name}")
                if not name:
                    continue
                if posixpath.basename(name).startswith(".wh."):
                    fail(f"whiteout is not allowed in scratch strict image: {name!r}")
                if member.uid != 0 or member.gid != 0:
                    fail(f"image-owned path {name!r} must be root-owned")
                if member.mode & 0o022:
                    fail(f"image-owned path {name!r} must not be group/world writable")
                if member.isdir():
                    if name not in ALLOWED_DIRECTORIES:
                        fail(f"unexpected directory {name!r}")
                    if member.mode & 0o7777 != 0o755:
                        fail(f"directory {name!r} must have mode 0755")
                    continue
                if name not in EXPECTED_FILES:
                    fail(f"unexpected regular file {name!r}")
                stream = layer.extractfile(member)
                if stream is None:
                    fail(f"cannot read layer file {name!r}")
                if member.size > MAXIMUM_FILE_BYTES:
                    fail(f"layer file {name!r} exceeds the 256 MiB limit")
                filesystem[name] = FileRecord(stream.read(), member.mode & 0o7777, member.uid, member.gid)
    except tarfile.TarError as error:
        fail(f"invalid layer archive {layer_name!r}: {error}")


def validate_config(config: dict[str, object]) -> None:
    runtime = config.get("config")
    if not isinstance(runtime, dict):
        fail("image configuration lacks config object")
    if runtime.get("User") != "10001:10001":
        fail("runtime user must be exactly 10001:10001")
    if runtime.get("WorkingDir") != "/app":
        fail("working directory must be /app")
    if runtime.get("Entrypoint") != EXPECTED_ENTRYPOINT or runtime.get("Cmd") not in (None, []):
        fail("entrypoint/Cmd does not match the strict executable contract")
    ports = runtime.get("ExposedPorts")
    if not isinstance(ports, dict) or set(ports) != EXPECTED_PORTS:
        fail("exposed ports must be exactly 8443/tcp and 8443/udp")
    if runtime.get("StopSignal") != "SIGINT":
        fail("stop signal must be SIGINT")
    labels = runtime.get("Labels")
    if not isinstance(labels, dict) or labels.get("io.oxibelt.image.role") != "dataplane-strict":
        fail("strict image role label is missing")


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: validate-strict-dataplane-image.py <docker-save.tar>")
    image_path = pathlib.Path(sys.argv[1])
    if not image_path.is_file():
        fail(f"archive does not exist: {image_path}")
    if image_path.stat().st_size > MAXIMUM_ARCHIVE_BYTES:
        fail("archive exceeds the 1 GiB validation limit")

    try:
        with tarfile.open(image_path, mode="r:*") as docker_archive:
            checked_members(docker_archive, "docker archive")
            manifest = json.loads(member_bytes(docker_archive, "manifest.json", "docker archive"))
            if not isinstance(manifest, list) or len(manifest) != 1 or not isinstance(manifest[0], dict):
                fail("docker archive must contain exactly one image manifest")
            descriptor = manifest[0]
            config_name = descriptor.get("Config")
            layers = descriptor.get("Layers")
            if not isinstance(config_name, str) or not (
                re.fullmatch(r"[0-9a-f]{64}\.json", config_name)
                or re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", config_name)
            ):
                fail("docker archive config name is not a content-addressed JSON path")
            if not isinstance(layers, list) or not layers or not all(isinstance(item, str) for item in layers):
                fail("docker archive has no ordered layer list")
            config_bytes = member_bytes(docker_archive, config_name, "docker archive")
            verify_content_address(config_name, config_bytes, "image configuration")
            config = json.loads(config_bytes)
            if not isinstance(config, dict):
                fail("image configuration is not an object")
            validate_config(config)

            filesystem: dict[str, FileRecord] = {}
            for layer_name in layers:
                normalized = safe_name(layer_name, "layer reference")
                legacy_layer = re.fullmatch(r"[0-9a-f]{64}/layer\.tar", normalized)
                content_blob = re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", normalized)
                if normalized != layer_name or (legacy_layer is None and content_blob is None):
                    fail(f"invalid layer reference {layer_name!r}")
                layer_bytes = member_bytes(docker_archive, layer_name, "docker archive")
                verify_content_address(layer_name, layer_bytes, f"layer {layer_name}")
                validate_layer(layer_bytes, layer_name, filesystem)
    except (json.JSONDecodeError, tarfile.TarError) as error:
        fail(f"invalid docker archive: {error}")

    if set(filesystem) != EXPECTED_FILES:
        fail(f"effective files differ: expected {sorted(EXPECTED_FILES)}, got {sorted(filesystem)}")
    if filesystem["etc/passwd"].data != EXPECTED_PASSWD or filesystem["etc/group"].data != EXPECTED_GROUP:
        fail("passwd/group are not the minimized strict identities")
    strict_config = filesystem["etc/oxibelt/config/oxibelt.toml"].data
    if ADMIN_CONFIG_SECTION.search(strict_config):
        fail("strict default configuration contains an Admin table")
    for name in EXPECTED_FILES - {"usr/local/bin/oxibelt-dataplane-strict"}:
        if filesystem[name].mode != 0o644:
            fail(f"metadata/config file {name!r} must have mode 0644")
    binary = filesystem["usr/local/bin/oxibelt-dataplane-strict"]
    if binary.mode != 0o755 or not binary.data.startswith(b"\x7fELF"):
        fail("strict executable must be a root-owned mode-0755 ELF")
    for name, record in filesystem.items():
        if name != "usr/local/bin/oxibelt-dataplane-strict" and record.mode & 0o111:
            fail(f"unexpected executable file {name!r}")
    if PERSON_PROOF_MARKER not in binary.data:
        fail("strict executable does not contain the Person Proof asset marker")
    for marker in ADMIN_MARKERS:
        if marker in binary.data:
            fail(f"strict executable contains forbidden Admin marker {marker!r}")

    print(f"validated strict data-plane image: {image_path}")


if __name__ == "__main__":
    main()
