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
from collections import Counter
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from typing import Any


MAXIMUM_ARCHIVE_BYTES = 4 * 1024 * 1024 * 1024
MAXIMUM_ARCHIVE_MEMBERS = 32768
MAXIMUM_FILE_BYTES = 1024 * 1024 * 1024
MAXIMUM_TOTAL_FILE_BYTES = 8 * 1024 * 1024 * 1024
MAXIMUM_JSON_BYTES = 32 * 1024 * 1024
MAXIMUM_DIAGNOSTICS = 8
MAXIMUM_ERROR_TEXT_BYTES = 256
MAXIMUM_PATH_CHARACTERS = 4096
MAXIMUM_SBOM_DEPTH = 64
MAXIMUM_SBOM_NODES = 65536
MAXIMUM_SBOM_COLLECTION_ITEMS = 16384
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


def opaque_identifier(value: str) -> str:
    prefix = value[:MAXIMUM_PATH_CHARACTERS]
    digest = hashlib.sha256(prefix.encode("utf-8", "surrogatepass")).hexdigest()
    if len(value) > MAXIMUM_PATH_CHARACTERS:
        return f"sha256-prefix:{digest}"
    return f"sha256:{digest}"


def bounded_error_text(error: ComparisonError) -> str:
    encoded = str(error).encode("utf-8", "replace")
    if len(encoded) <= MAXIMUM_ERROR_TEXT_BYTES:
        return encoded.decode("utf-8", "replace")
    suffix = b"...[truncated]"
    return (encoded[: MAXIMUM_ERROR_TEXT_BYTES - len(suffix)] + suffix).decode(
        "utf-8", "replace"
    )


def safe_path(name: str, description: str) -> str:
    if len(name) > MAXIMUM_PATH_CHARACTERS:
        raise ComparisonError(f"oversize {description} path {opaque_identifier(name)}")
    if len(name.encode("utf-8", "surrogatepass")) > MAXIMUM_PATH_CHARACTERS:
        raise ComparisonError(f"oversize {description} path {opaque_identifier(name)}")
    if not name or "\x00" in name or "\\" in name:
        raise ComparisonError(f"unsafe {description} path {opaque_identifier(name)}")
    path = pathlib.PurePosixPath(name)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ComparisonError(f"unsafe {description} path {opaque_identifier(name)}")
    if path.as_posix() != name.rstrip("/"):
        raise ComparisonError(f"non-canonical {description} path {opaque_identifier(name)}")
    return path.as_posix()


def read_json(path: pathlib.Path, description: str) -> Any:
    try:
        if not path.is_file() or path.is_symlink():
            raise ComparisonError(f"{description} is not a regular file")
        if path.stat().st_size > MAXIMUM_JSON_BYTES:
            raise ComparisonError(f"{description} exceeds the 32 MiB limit")
        return json.loads(path.read_text(encoding="utf-8"))
    except ComparisonError:
        raise
    except (OSError, RecursionError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ComparisonError(f"cannot read {description}") from error


def file_digest(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise ComparisonError("cannot hash regular file") from error
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
            raise ComparisonError(
                f"{description} contains duplicate member {opaque_identifier(name)}"
            )
        names.add(name)
        members.append(member)
        if len(members) > MAXIMUM_ARCHIVE_MEMBERS:
            raise ComparisonError(f"{description} exceeds the member limit")
    return members


def bounded_member(archive: tarfile.TarFile, member: tarfile.TarInfo, limit: int) -> bytes:
    if not member.isfile() or member.size > limit:
        raise ComparisonError(
            f"archive member {opaque_identifier(member.name)} is not a bounded regular file"
        )
    stream = archive.extractfile(member)
    if stream is None:
        raise ComparisonError(f"archive member {opaque_identifier(member.name)} cannot be read")
    value = stream.read(limit + 1)
    if len(value) != member.size:
        raise ComparisonError(f"archive member {opaque_identifier(member.name)} was truncated")
    return value


def docker_archive(path: pathlib.Path) -> tuple[dict[str, Any], dict[str, FileRecord]]:
    try:
        if not path.is_file() or path.is_symlink():
            raise ComparisonError("Docker archive is not a regular file")
        if path.stat().st_size > MAXIMUM_ARCHIVE_BYTES:
            raise ComparisonError("Docker archive exceeds the 4 GiB limit")
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
            if len(layer_names) > MAXIMUM_ARCHIVE_MEMBERS:
                raise ComparisonError("Docker archive manifest exceeds the layer limit")
            config_member = by_name.get(safe_path(config_name, "config"))
            if config_member is None:
                raise ComparisonError(
                    f"Docker archive is missing config {opaque_identifier(config_name)}"
                )
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
                    raise ComparisonError(
                        f"Docker archive is missing layer {opaque_identifier(item)}"
                    )
                layer_stream = archive.extractfile(member)
                if layer_stream is None:
                    raise ComparisonError(
                        f"Docker archive layer {opaque_identifier(item)} cannot be read"
                    )
                total_file_bytes += apply_layer(
                    filesystem, layer_stream, member.size, index
                )
                if total_file_bytes > MAXIMUM_TOTAL_FILE_BYTES:
                    raise ComparisonError("expanded image exceeds the 8 GiB comparison limit")
            return config, filesystem
    except ComparisonError:
        raise
    except (OSError, RecursionError, tarfile.TarError, json.JSONDecodeError) as error:
        raise ComparisonError("invalid Docker archive") from error


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
    raise ComparisonError(
        f"unsupported layer member type {opaque_identifier(member.name)}"
    )


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
                            raise ComparisonError(
                                f"layer file {opaque_identifier(name)} cannot be read"
                            )
                        digest = content_digest(
                            stream,
                            member.size,
                            f"layer file {opaque_identifier(name)}",
                        )
                        total_bytes += member.size
                    elif kind in ("symlink", "hardlink"):
                        if "\x00" in member.linkname:
                            raise ComparisonError(
                                f"layer link {opaque_identifier(name)} contains NUL"
                            )
                        link = member.linkname
                        if kind == "hardlink":
                            safe_path(link, "hardlink target")
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
    except ComparisonError:
        raise
    except (OSError, tarfile.TarError) as error:
        raise ComparisonError(f"invalid filesystem layer {index}") from error
    return total_bytes


def normalized_config(config: dict[str, Any]) -> dict[str, Any]:
    try:
        result = json.loads(json.dumps(config))
    except (RecursionError, TypeError, ValueError) as error:
        raise ComparisonError("Docker image config cannot be normalized") from error
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


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sort_token(value: Any) -> str:
    """Return a fixed-size deterministic sort token for canonical JSON data.

    The caller retains the complete canonical object for the final equality
    comparison. A theoretical SHA-256 collision can therefore preserve input
    order and fail closed as a mismatch; it cannot make unequal objects pass.
    """

    return f"sha256:{hashlib.sha256(canonical_json(value).encode()).hexdigest()}"


def validate_sbom_resources(value: Any) -> None:
    nodes = 0
    collection_items = 0
    pending = [(value, 0)]
    while pending:
        current, depth = pending.pop()
        if depth > MAXIMUM_SBOM_DEPTH:
            raise ComparisonError("SBOM exceeds the nesting-depth limit")
        nodes += 1
        if nodes > MAXIMUM_SBOM_NODES:
            raise ComparisonError("SBOM exceeds the node limit")
        if isinstance(current, dict):
            pending.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            collection_items += len(current)
            if collection_items > MAXIMUM_SBOM_COLLECTION_ITEMS:
                raise ComparisonError("SBOM exceeds the collection-item limit")
            pending.extend((item, depth + 1) for item in current)


def canonicalize_generic(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: canonicalize_generic(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return [canonicalize_generic(item) for item in value]
    return value


def require_object(value: Any, description: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ComparisonError(f"SBOM {description} must be an object")
    return value


def require_string(value: Any, description: str) -> str:
    if not isinstance(value, str):
        raise ComparisonError(f"SBOM {description} must be a string")
    return value


def canonicalize_component_hashes(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ComparisonError("SBOM component hashes must be an array")
    hashes: list[dict[str, Any]] = []
    for item in value:
        item_object = require_object(item, "component hash")
        require_string(item_object.get("alg"), "component hash alg")
        require_string(item_object.get("content"), "component hash content")
        hashes.append(canonicalize_generic(item_object))
    return sorted(hashes, key=canonical_json)


def canonicalize_component_properties(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ComparisonError("SBOM component properties must be an array")
    properties: list[dict[str, Any]] = []
    for item in value:
        item_object = require_object(item, "component property")
        require_string(item_object.get("name"), "component property name")
        require_string(item_object.get("value"), "component property value")
        properties.append(canonicalize_generic(item_object))
    return sorted(properties, key=canonical_json)


def canonicalize_component(value: Any) -> dict[str, Any]:
    result, _ = canonicalize_component_with_key(value)
    return result


def canonicalize_component_with_key(value: Any) -> tuple[dict[str, Any], str]:
    component = require_object(value, "component")
    require_string(component.get("type"), "component type")
    require_string(component.get("name"), "component name")
    result: dict[str, Any] = {}
    key_parts: list[tuple[str, str]] = []
    for key, item in sorted(component.items()):
        if key == "components":
            result[key], item_key = canonicalize_components_with_key(item)
        elif key == "hashes":
            result[key] = canonicalize_component_hashes(item)
            item_key = sort_token(result[key])
        elif key == "properties":
            result[key] = canonicalize_component_properties(item)
            item_key = sort_token(result[key])
        else:
            result[key] = canonicalize_generic(item)
            item_key = sort_token(result[key])
        key_parts.append((key, item_key))
    return result, sort_token(key_parts)


def canonicalize_components(value: Any) -> list[dict[str, Any]]:
    result, _ = canonicalize_components_with_key(value)
    return result


def canonicalize_components_with_key(value: Any) -> tuple[list[dict[str, Any]], str]:
    if not isinstance(value, list):
        raise ComparisonError("SBOM components must be an array")
    components = sorted(
        (canonicalize_component_with_key(item) for item in value), key=lambda item: item[1]
    )
    return (
        [item for item, _ in components],
        sort_token([key for _, key in components]),
    )


def canonicalize_dependency(value: Any) -> dict[str, Any]:
    dependency = require_object(value, "dependency")
    require_string(dependency.get("ref"), "dependency ref")
    result: dict[str, Any] = {}
    for key, item in sorted(dependency.items()):
        if key == "dependsOn":
            if not isinstance(item, list) or not all(isinstance(entry, str) for entry in item):
                raise ComparisonError("SBOM dependency dependsOn must be an array of strings")
            result[key] = sorted(item)
        else:
            result[key] = canonicalize_generic(item)
    return result


def canonicalize_dependencies(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ComparisonError("SBOM dependencies must be an array")
    return sorted((canonicalize_dependency(item) for item in value), key=canonical_json)


def canonicalize_metadata(value: Any) -> dict[str, Any]:
    metadata = require_object(value, "metadata")
    result: dict[str, Any] = {}
    for key, item in sorted(metadata.items()):
        if key == "component":
            result[key] = canonicalize_component(item)
        else:
            result[key] = canonicalize_generic(item)
    return result


def canonicalize_sbom(value: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, item in sorted(value.items()):
        if key == "components":
            result[key] = canonicalize_components(item)
        elif key == "dependencies":
            result[key] = canonicalize_dependencies(item)
        elif key == "metadata":
            result[key] = canonicalize_metadata(item)
        else:
            result[key] = canonicalize_generic(item)
    return result


def expected_subject_binding(
    root: dict[str, Any], subject_digest: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Validate and remove exactly one generated root binding for this subject."""

    subject_hash = subject_digest.removeprefix("sha256:")
    hashes = root.get("hashes")
    properties = root.get("properties")
    if not isinstance(hashes, list) or not isinstance(properties, list):
        raise ComparisonError("SBOM metadata component is missing subject bindings")
    expected_hash = {"alg": "SHA-256", "content": subject_hash}
    expected_property = {"name": "io.oxibelt.image.digest", "value": subject_digest}
    if any(
        isinstance(item, dict)
        and item.get("alg") == "SHA-256"
        and item.get("content") == subject_hash
        and item != expected_hash
        for item in hashes
    ) or any(
        isinstance(item, dict)
        and item.get("name") == "io.oxibelt.image.digest"
        and item.get("value") == subject_digest
        and item != expected_property
        for item in properties
    ):
        raise ComparisonError("SBOM metadata component has malformed subject bindings")
    matching_hashes = [item for item in hashes if item == expected_hash]
    matching_properties = [item for item in properties if item == expected_property]
    if len(matching_hashes) != 1 or len(matching_properties) != 1:
        raise ComparisonError("SBOM metadata component has invalid subject bindings")
    return (
        [item for item in hashes if item != expected_hash],
        [item for item in properties if item != expected_property],
    )


def normalized_sbom(value: Any, subject_digest: str) -> Any:
    if DIGEST.fullmatch(subject_digest) is None:
        raise ComparisonError("SBOM subject digest is not a SHA-256 digest")
    validate_sbom_resources(value)
    result = json.loads(json.dumps(value))
    if not isinstance(result, dict) or result.get("bomFormat") != "CycloneDX":
        raise ComparisonError("SBOM bomFormat must be CycloneDX")
    if result.get("specVersion") not in {"1.6", "1.7"}:
        raise ComparisonError("SBOM specVersion must be 1.6 or 1.7")
    result.pop("serialNumber", None)
    metadata = require_object(result.get("metadata"), "metadata")
    metadata.pop("timestamp", None)
    root = require_object(metadata.get("component"), "metadata component")
    root["hashes"], root["properties"] = expected_subject_binding(root, subject_digest)
    return canonicalize_sbom(result)


def fingerprint(value: Any) -> str:
    return sort_token(value)


def bounded_records(
    records: Iterable[dict[str, Any]], key: Callable[[dict[str, Any]], Any] = canonical_json
) -> dict[str, Any]:
    retained: list[dict[str, Any]] = []
    total = 0
    for record in records:
        count = record.get("count", 1)
        total += count
        retained.append(record)
        retained.sort(key=key)
        if len(retained) > MAXIMUM_DIAGNOSTICS:
            retained.pop()
    return {
        "records": retained,
        "total": total,
        "truncated": total - sum(record.get("count", 1) for record in retained),
    }


def filesystem_diagnostics(
    published: dict[str, FileRecord], rebuilt: dict[str, FileRecord]
) -> dict[str, Any]:
    fields = (
        ("kind", "type"),
        ("mode", "mode"),
        ("uid", "uid"),
        ("gid", "gid"),
        ("uname", "uname"),
        ("gname", "gname"),
        ("link", "link"),
        ("content_sha256", "content"),
        ("size", "size"),
        ("device_major", "device"),
        ("device_minor", "device"),
        ("pax_metadata", "metadata"),
    )
    def records() -> Iterator[dict[str, Any]]:
        for path in set(published) | set(rebuilt):
            published_record = published.get(path)
            rebuilt_record = rebuilt.get(path)
            if published_record is None:
                categories = ["only-rebuilt"]
            elif rebuilt_record is None:
                categories = ["only-published"]
            else:
                categories = sorted(
                    {
                        category
                        for field, category in fields
                        if getattr(published_record, field)
                        != getattr(rebuilt_record, field)
                    }
                )
            if categories:
                yield {
                    "categories": categories,
                    "pathFingerprint": fingerprint(path),
                }

    return bounded_records(records(), key=lambda record: record["pathFingerprint"])


def component_items(component: dict[str, Any]) -> Iterator[dict[str, Any]]:
    yield component
    nested = component.get("components")
    if isinstance(nested, list):
        for item in nested:
            if isinstance(item, dict):
                yield from component_items(item)


def sbom_components(value: Any) -> Iterator[dict[str, Any]]:
    if not isinstance(value, dict):
        return
    metadata = value.get("metadata")
    if isinstance(metadata, dict) and isinstance(metadata.get("component"), dict):
        yield from component_items(metadata["component"])
    components = value.get("components")
    if isinstance(components, list):
        for item in components:
            if isinstance(item, dict):
                yield from component_items(item)


def sbom_dependencies(value: Any) -> Iterator[dict[str, Any]]:
    if not isinstance(value, dict):
        return
    dependencies = value.get("dependencies")
    if isinstance(dependencies, list):
        for item in dependencies:
            if isinstance(item, dict):
                yield item


def sbom_collection_diagnostics(
    published: Iterable[dict[str, Any]], rebuilt: Iterable[dict[str, Any]]
) -> dict[str, Any]:
    published_fingerprints = Counter(fingerprint(item) for item in published)
    rebuilt_fingerprints = Counter(fingerprint(item) for item in rebuilt)

    def records() -> Iterator[dict[str, Any]]:
        for item in sorted(set(published_fingerprints) | set(rebuilt_fingerprints)):
            published_count = published_fingerprints[item]
            rebuilt_count = rebuilt_fingerprints[item]
            if published_count > rebuilt_count:
                yield {
                    "count": published_count - rebuilt_count,
                    "fingerprint": item,
                    "side": "only-published",
                }
            elif rebuilt_count > published_count:
                yield {
                    "count": rebuilt_count - published_count,
                    "fingerprint": item,
                    "side": "only-rebuilt",
                }

    return bounded_records(records(), key=lambda record: (record["fingerprint"], record["side"]))


def sbom_diagnostics(published: Any, rebuilt: Any) -> dict[str, Any]:
    return {
        "components": sbom_collection_diagnostics(
            sbom_components(published), sbom_components(rebuilt)
        ),
        "dependencies": sbom_collection_diagnostics(
            sbom_dependencies(published), sbom_dependencies(rebuilt)
        ),
        "publishedFingerprint": fingerprint(published),
        "rebuiltFingerprint": fingerprint(rebuilt),
    }


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
    published_sbom = normalized_sbom(
        read_json(args.published_sbom, "published SBOM"), published["image_digest"]
    )
    rebuilt_sbom = normalized_sbom(
        read_json(args.rebuilt_sbom, "rebuilt SBOM"), rebuilt["image_digest"]
    )
    if (
        published["image_digest"] == rebuilt["image_digest"]
        and published["image_tar_sha256"] == rebuilt["image_tar_sha256"]
    ):
        if published_sbom != rebuilt_sbom:
            receipt.update(
                outcome="mismatch",
                guarantee="OCI manifest matches but normalized SBOM graphs differ",
                differences=["sbom-graph"],
                diagnostics={"sbom": sbom_diagnostics(published_sbom, rebuilt_sbom)},
            )
            return receipt, 1
        receipt.update(
            outcome="exact",
            guarantee="published and rebuilt OCI manifest and image archive digests match exactly",
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
        diagnostics: dict[str, Any] = {}
        if published_filesystem != rebuilt_filesystem:
            diagnostics["filesystem"] = filesystem_diagnostics(
                published_filesystem, rebuilt_filesystem
            )
        if published_sbom != rebuilt_sbom:
            diagnostics["sbom"] = sbom_diagnostics(published_sbom, rebuilt_sbom)
        receipt.update(
            outcome="mismatch",
            guarantee="security-relevant normalized image content differs",
            differences=differences,
            diagnostics=diagnostics,
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
            "differences": [bounded_error_text(error)],
        }
        status = 2
    try:
        write_json(args.output, receipt)
    except OSError:
        print("comparison receipt cannot be written", file=sys.stderr)
        raise SystemExit(2)
    print(json.dumps(receipt, sort_keys=True))
    raise SystemExit(status)


if __name__ == "__main__":
    main()
