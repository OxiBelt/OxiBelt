#!/usr/bin/env python3
"""Compare independently built Docker archives without extracting untrusted paths."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from typing import Any


MAXIMUM_ARCHIVE_BYTES = 4 * 1024 * 1024 * 1024
MAXIMUM_ARCHIVE_MEMBERS = 32768
MAXIMUM_FILE_BYTES = 1024 * 1024 * 1024
MAXIMUM_TOTAL_FILE_BYTES = 8 * 1024 * 1024 * 1024
MAXIMUM_JSON_BYTES = 32 * 1024 * 1024
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
NORMALIZATION = (
    "outer-archive-order",
    "layer-compression",
    "filesystem-mtime",
    "oci-created-and-history-timestamps",
)
PAX_HEADERS_ALREADY_REPRESENTED = frozenset(
    {"path", "linkpath", "size", "uid", "gid", "uname", "gname"}
)
PAX_HEADERS_NORMALIZED = frozenset({"mtime"})
OUTPUT_FIELDS = {
    "image_tar",
    "image_tar_sha256",
    "config_digest",
    "normalized_config_sha256",
    "descriptor_digest",
    "image_digest",
    "layers",
}


class ComparisonError(Exception):
    """An input cannot be compared safely or conclusively."""


@dataclass(frozen=True)
class FileRecord:
    kind: str
    mode: int
    uid: int
    gid: int
    uname: str
    gname: str
    link: str | None
    content_sha256: str | None
    size: int
    device_major: int
    device_minor: int
    pax_metadata: tuple[tuple[str, str], ...]


def safe_path(name: str, description: str) -> str:
    if not name or "\x00" in name or "\\" in name:
        raise ComparisonError(f"unsafe {description} path {name!r}")
    path = pathlib.PurePosixPath(name)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ComparisonError(f"unsafe {description} path {name!r}")
    if path.as_posix() != name.rstrip("/"):
        raise ComparisonError(f"non-canonical {description} path {name!r}")
    return path.as_posix()


def read_json(path: pathlib.Path, description: str) -> Any:
    if not path.is_file() or path.is_symlink():
        raise ComparisonError(f"{description} is not a regular file: {path}")
    if path.stat().st_size > MAXIMUM_JSON_BYTES:
        raise ComparisonError(f"{description} exceeds the 32 MiB limit: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ComparisonError(f"cannot read {description} {path}: {error}") from error


def file_digest(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return f"sha256:{digest.hexdigest()}"


def content_digest(stream: Any, size: int, description: str) -> str:
    if size > MAXIMUM_FILE_BYTES:
        raise ComparisonError(f"{description} exceeds the 1 GiB file limit")
    digest = hashlib.sha256()
    total = 0
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        total += len(block)
        if total > size:
            raise ComparisonError(f"{description} exceeded its declared size")
        digest.update(block)
    if total != size:
        raise ComparisonError(f"{description} was truncated")
    return f"sha256:{digest.hexdigest()}"


def archive_members(archive: tarfile.TarFile, description: str) -> list[tarfile.TarInfo]:
    members: list[tarfile.TarInfo] = []
    names: set[str] = set()
    for member in archive:
        name = safe_path(member.name, description)
        if name in names:
            raise ComparisonError(f"{description} contains duplicate member {name!r}")
        names.add(name)
        members.append(member)
        if len(members) > MAXIMUM_ARCHIVE_MEMBERS:
            raise ComparisonError(f"{description} exceeds the member limit")
    return members


def bounded_member(archive: tarfile.TarFile, member: tarfile.TarInfo, limit: int) -> bytes:
    if not member.isfile() or member.size > limit:
        raise ComparisonError(f"archive member {member.name!r} is not a bounded regular file")
    stream = archive.extractfile(member)
    if stream is None:
        raise ComparisonError(f"archive member {member.name!r} cannot be read")
    value = stream.read(limit + 1)
    if len(value) != member.size:
        raise ComparisonError(f"archive member {member.name!r} was truncated")
    return value


def docker_archive(path: pathlib.Path) -> tuple[dict[str, Any], dict[str, FileRecord]]:
    if not path.is_file() or path.is_symlink():
        raise ComparisonError(f"Docker archive is not a regular file: {path}")
    if path.stat().st_size > MAXIMUM_ARCHIVE_BYTES:
        raise ComparisonError(f"Docker archive exceeds the 4 GiB limit: {path}")
    try:
        with tarfile.open(path, mode="r:*") as archive:
            members = archive_members(archive, "Docker archive")
            by_name = {safe_path(member.name, "Docker archive"): member for member in members}
            manifest_member = by_name.get("manifest.json")
            if manifest_member is None:
                raise ComparisonError("Docker archive is missing manifest.json")
            manifest = json.loads(bounded_member(archive, manifest_member, MAXIMUM_JSON_BYTES))
            if not isinstance(manifest, list) or len(manifest) != 1 or not isinstance(manifest[0], dict):
                raise ComparisonError("Docker archive must contain one image manifest")
            descriptor = manifest[0]
            config_name = descriptor.get("Config")
            layer_names = descriptor.get("Layers")
            if not isinstance(config_name, str) or not isinstance(layer_names, list):
                raise ComparisonError("Docker archive manifest lacks config or layers")
            config_member = by_name.get(safe_path(config_name, "config"))
            if config_member is None:
                raise ComparisonError("Docker archive is missing its image config")
            config = json.loads(bounded_member(archive, config_member, MAXIMUM_JSON_BYTES))
            if not isinstance(config, dict):
                raise ComparisonError("Docker image config must be an object")
            filesystem: dict[str, FileRecord] = {}
            total_file_bytes = 0
            for index, item in enumerate(layer_names):
                if not isinstance(item, str):
                    raise ComparisonError("Docker archive layer path must be a string")
                member = by_name.get(safe_path(item, "layer"))
                if member is None or not member.isfile():
                    raise ComparisonError(f"Docker archive is missing layer {item!r}")
                layer_stream = archive.extractfile(member)
                if layer_stream is None:
                    raise ComparisonError(f"Docker archive layer {item!r} cannot be read")
                total_file_bytes += apply_layer(
                    filesystem, layer_stream, member.size, index
                )
                if total_file_bytes > MAXIMUM_TOTAL_FILE_BYTES:
                    raise ComparisonError("expanded image exceeds the 8 GiB comparison limit")
            return config, filesystem
    except (OSError, tarfile.TarError, json.JSONDecodeError) as error:
        raise ComparisonError(f"invalid Docker archive {path}: {error}") from error


def member_kind(member: tarfile.TarInfo) -> str:
    if member.isfile():
        return "file"
    if member.isdir():
        return "directory"
    if member.issym():
        return "symlink"
    if member.islnk():
        return "hardlink"
    if member.ischr():
        return "character-device"
    if member.isblk():
        return "block-device"
    if member.isfifo():
        return "fifo"
    raise ComparisonError(f"unsupported layer member type for {member.name!r}")


def pax_metadata(member: tarfile.TarInfo) -> tuple[tuple[str, str], ...]:
    excluded = PAX_HEADERS_ALREADY_REPRESENTED | PAX_HEADERS_NORMALIZED
    return tuple(
        (key, value)
        for key, value in member.pax_headers.items()
        if key not in excluded
    )


def remove_path(filesystem: dict[str, FileRecord], path: str) -> None:
    prefix = f"{path}/"
    for existing in list(filesystem):
        if existing == path or existing.startswith(prefix):
            del filesystem[existing]


def apply_layer(
    filesystem: dict[str, FileRecord], layer_stream: Any, layer_size: int, index: int
) -> int:
    total_bytes = 0
    if layer_size > MAXIMUM_ARCHIVE_BYTES:
        raise ComparisonError(f"filesystem layer {index} exceeds the 4 GiB limit")
    try:
        with tempfile.SpooledTemporaryFile(max_size=64 * 1024 * 1024) as backing:
            copied = 0
            for block in iter(lambda: layer_stream.read(1024 * 1024), b""):
                copied += len(block)
                if copied > layer_size:
                    raise ComparisonError(
                        f"filesystem layer {index} exceeded its declared size"
                    )
                backing.write(block)
            if copied != layer_size:
                raise ComparisonError(f"filesystem layer {index} was truncated")
            backing.seek(0)
            with tarfile.open(fileobj=backing, mode="r:*") as archive:
                members = archive_members(archive, f"layer {index}")
                if archive.pax_headers:
                    raise ComparisonError(
                        f"layer {index} contains unsupported global PAX headers"
                    )
                opaque_directories: set[str] = set()
                whiteouts: set[str] = set()
                regular_members: list[tarfile.TarInfo] = []
                for member in members:
                    name = safe_path(member.name, f"layer {index}")
                    base = pathlib.PurePosixPath(name).name
                    parent = pathlib.PurePosixPath(name).parent.as_posix()
                    if base == ".wh..wh..opq":
                        opaque_directories.add("" if parent == "." else parent)
                    elif base.startswith(".wh."):
                        target = pathlib.PurePosixPath(parent, base.removeprefix(".wh.")).as_posix()
                        whiteouts.add(target)
                    else:
                        regular_members.append(member)
                for directory in sorted(opaque_directories):
                    prefix = f"{directory}/" if directory else ""
                    for existing in list(filesystem):
                        if existing.startswith(prefix) and existing != directory:
                            del filesystem[existing]
                for target in sorted(whiteouts):
                    remove_path(filesystem, target)
                for member in regular_members:
                    name = safe_path(member.name, f"layer {index}")
                    kind = member_kind(member)
                    link: str | None = None
                    digest: str | None = None
                    if kind == "file":
                        stream = archive.extractfile(member)
                        if stream is None:
                            raise ComparisonError(f"layer file {name!r} cannot be read")
                        digest = content_digest(stream, member.size, f"layer file {name!r}")
                        total_bytes += member.size
                    elif kind in ("symlink", "hardlink"):
                        if "\x00" in member.linkname:
                            raise ComparisonError(f"layer link {name!r} contains NUL")
                        link = member.linkname
                        if kind == "hardlink":
                            safe_path(link, f"hardlink target for {name}")
                    remove_path(filesystem, name)
                    filesystem[name] = FileRecord(
                        kind=kind,
                        mode=member.mode,
                        uid=member.uid,
                        gid=member.gid,
                        uname=member.uname,
                        gname=member.gname,
                        link=link,
                        content_sha256=digest,
                        size=member.size if kind == "file" else 0,
                        device_major=member.devmajor,
                        device_minor=member.devminor,
                        pax_metadata=pax_metadata(member),
                    )
    except (OSError, tarfile.TarError) as error:
        raise ComparisonError(f"invalid filesystem layer {index}: {error}") from error
    return total_bytes


def normalized_config(config: dict[str, Any]) -> dict[str, Any]:
    result = json.loads(json.dumps(config))
    result.pop("created", None)
    rootfs = result.get("rootfs")
    if isinstance(rootfs, dict):
        # Diff IDs commit to tar ordering and mtimes; the reconstructed
        # filesystem comparison below retains the security-relevant content.
        rootfs.pop("diff_ids", None)
    history = result.get("history")
    if isinstance(history, list):
        for item in history:
            if isinstance(item, dict):
                item.pop("created", None)
    return result


def normalized_sbom(value: Any) -> Any:
    result = json.loads(json.dumps(value))
    if not isinstance(result, dict) or result.get("bomFormat") != "CycloneDX":
        raise ComparisonError("SBOM must be a CycloneDX JSON object")
    result.pop("serialNumber", None)
    metadata = result.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("timestamp", None)
        root = metadata.get("component")
        if isinstance(root, dict):
            root.pop("hashes", None)
            properties = root.get("properties")
            if isinstance(properties, list):
                root["properties"] = [
                    item
                    for item in properties
                    if not (
                        isinstance(item, dict)
                        and item.get("name") == "io.oxibelt.image.digest"
                    )
                ]
    return result


def contract_identity(contract: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in contract.items() if key not in OUTPUT_FIELDS}


def validated_contract(
    path: pathlib.Path, image_tar: pathlib.Path, *, require_archive_digest: bool
) -> dict[str, Any]:
    value = read_json(path, "artifact contract")
    if not isinstance(value, dict) or value.get("schema") != 3:
        raise ComparisonError("artifact contract schema must be 3")
    for key in ("image_digest", "image_tar_sha256", "normalized_config_sha256"):
        if not isinstance(value.get(key), str) or DIGEST.fullmatch(value[key]) is None:
            raise ComparisonError(f"artifact contract {key} is not a SHA-256 digest")
    if require_archive_digest and file_digest(image_tar) != value["image_tar_sha256"]:
        raise ComparisonError("Docker archive does not match its artifact contract")
    return value


def write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
    ) as stream:
        temporary = pathlib.Path(stream.name)
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
    os.replace(temporary, path)


def compare(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    published = validated_contract(
        args.published_contract, args.published_image_tar, require_archive_digest=False
    )
    rebuilt = validated_contract(
        args.rebuilt_contract, args.rebuilt_image_tar, require_archive_digest=True
    )
    if published["image_digest"] != args.published_subject_digest:
        raise ComparisonError(
            "published artifact contract does not match the verified registry subject"
        )
    receipt: dict[str, Any] = {
        "schemaVersion": 1,
        "published": {
            "imageDigest": published["image_digest"],
            "imageTarSha256": published["image_tar_sha256"],
        },
        "rebuilt": {
            "imageDigest": rebuilt["image_digest"],
            "imageTarSha256": rebuilt["image_tar_sha256"],
        },
        "normalization": {"schemaVersion": 1, "ignored": list(NORMALIZATION)},
        "differences": [],
    }
    if contract_identity(published) != contract_identity(rebuilt):
        receipt.update(
            outcome="mismatch",
            guarantee="build identity or parameters differ",
            differences=["artifact-contract-identity"],
        )
        return receipt, 1
    published_sbom = normalized_sbom(read_json(args.published_sbom, "published SBOM"))
    rebuilt_sbom = normalized_sbom(read_json(args.rebuilt_sbom, "rebuilt SBOM"))
    if published["image_digest"] == rebuilt["image_digest"]:
        if published_sbom != rebuilt_sbom:
            receipt.update(
                outcome="mismatch",
                guarantee="OCI manifest matches but normalized SBOM graphs differ",
                differences=["sbom-graph"],
            )
            return receipt, 1
        receipt.update(
            outcome="exact",
            guarantee="published and rebuilt OCI manifest digests match exactly",
        )
        return receipt, 0

    published_config, published_filesystem = docker_archive(args.published_image_tar)
    rebuilt_config, rebuilt_filesystem = docker_archive(args.rebuilt_image_tar)
    differences: list[str] = []
    if normalized_config(published_config) != normalized_config(rebuilt_config):
        differences.append("runtime-config")
    if published_filesystem != rebuilt_filesystem:
        differences.append("filesystem")
    if published_sbom != rebuilt_sbom:
        differences.append("sbom-graph")
    if differences:
        receipt.update(
            outcome="mismatch",
            guarantee="security-relevant normalized image content differs",
            differences=differences,
        )
        return receipt, 1
    receipt.update(
        outcome="normalized_equivalent",
        guarantee="security-relevant content matches after the documented normalization; this is not byte-for-byte reproducibility",
    )
    return receipt, 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--published-image-tar", required=True, type=pathlib.Path)
    parser.add_argument("--published-contract", required=True, type=pathlib.Path)
    parser.add_argument("--published-sbom", required=True, type=pathlib.Path)
    parser.add_argument("--published-subject-digest", required=True)
    parser.add_argument("--rebuilt-image-tar", required=True, type=pathlib.Path)
    parser.add_argument("--rebuilt-contract", required=True, type=pathlib.Path)
    parser.add_argument("--rebuilt-sbom", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        if DIGEST.fullmatch(args.published_subject_digest) is None:
            raise ComparisonError("published subject digest is not a SHA-256 digest")
        receipt, status = compare(args)
    except ComparisonError as error:
        receipt = {
            "schemaVersion": 1,
            "outcome": "unverifiable",
            "guarantee": "comparison evidence was missing, malformed, or outside safety limits",
            "normalization": {"schemaVersion": 1, "ignored": list(NORMALIZATION)},
            "differences": [str(error)],
        }
        status = 2
    write_json(args.output, receipt)
    print(json.dumps(receipt, sort_keys=True))
    raise SystemExit(status)


if __name__ == "__main__":
    main()
