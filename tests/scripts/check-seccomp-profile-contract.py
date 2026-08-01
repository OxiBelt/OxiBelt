#!/usr/bin/env python3
"""Validate OxiBelt's versioned OCI seccomp profile contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


CATALOG_KEYS = {"schema_version", "digest_algorithm", "profiles"}
ENTRY_KEYS = {
    "identity",
    "file",
    "digest",
    "qualification",
    "execution_scope",
    "runtime",
    "composed_from",
}
PROFILE_KEYS = {"defaultAction", "architectures", "syscalls"}
SYSCALL_BLOCK_KEYS = {"names", "action"}
ARCHITECTURES = [
    "SCMP_ARCH_X86_64",
    "SCMP_ARCH_AARCH64",
    "SCMP_ARCH_RISCV64",
]
IDENTITY_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,126}[a-z0-9])?-v1$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SYSCALL_RE = re.compile(r"^[a-z0-9_]+$")
EXECUTION_SCOPES = {
    "dataplane",
    "netport-switcher",
    "netport-switcher+dataplane",
}
RUNTIMES = {"none", "tokio", "compio"}
MAX_JSON_BYTES = 1024 * 1024


class ContractError(ValueError):
    """Raised when a checked-in seccomp contract is invalid."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"JSON object contains duplicate key {key!r}")
        result[key] = value
    return result


def load_json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    require(len(raw) <= MAX_JSON_BYTES, f"{path.name} exceeds {MAX_JSON_BYTES} bytes")
    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ContractError(f"{path.name} is not valid UTF-8 JSON: {error}") from error
    require(isinstance(value, dict), f"{path.name} must contain one JSON object")
    return value, raw


def validate_profile(path: Path) -> tuple[dict[str, Any], list[str], bytes]:
    profile, raw = load_json(path)
    require(set(profile) == PROFILE_KEYS, f"{path.name} has unexpected or missing top-level fields")
    require(
        profile["defaultAction"] == "SCMP_ACT_ERRNO",
        f"{path.name} must fail closed with SCMP_ACT_ERRNO",
    )
    require(
        profile["architectures"] == ARCHITECTURES,
        f"{path.name} architectures must match the ordered supported architecture contract",
    )
    syscall_blocks = profile["syscalls"]
    require(
        isinstance(syscall_blocks, list) and len(syscall_blocks) == 1,
        f"{path.name} must contain exactly one syscall rule block",
    )
    block = syscall_blocks[0]
    require(isinstance(block, dict), f"{path.name} syscall rule must be an object")
    require(
        set(block) == SYSCALL_BLOCK_KEYS,
        f"{path.name} syscall rule has unexpected or missing fields",
    )
    require(block["action"] == "SCMP_ACT_ALLOW", f"{path.name} syscall rule must allow")
    names = block["names"]
    require(isinstance(names, list) and names, f"{path.name} syscall names must be nonempty")
    require(
        all(isinstance(name, str) and SYSCALL_RE.fullmatch(name) for name in names),
        f"{path.name} contains an invalid syscall name",
    )
    require(names == sorted(names), f"{path.name} syscall names must be sorted")
    require(len(names) == len(set(names)), f"{path.name} contains duplicate syscall names")
    return profile, names, raw


def validate(seccomp_dir: Path) -> int:
    seccomp_dir = seccomp_dir.resolve()
    catalog_path = seccomp_dir / "profile-catalog-v1.json"
    require(catalog_path.is_file(), f"missing profile catalog: {catalog_path}")
    catalog, _ = load_json(catalog_path)
    require(set(catalog) == CATALOG_KEYS, "profile catalog has unexpected or missing fields")
    require(catalog["schema_version"] == 1, "profile catalog schema_version must be 1")
    require(catalog["digest_algorithm"] == "sha256", "profile catalog digest_algorithm must be sha256")

    entries = catalog["profiles"]
    require(isinstance(entries, list) and entries, "profile catalog profiles must be nonempty")
    require(
        all(isinstance(entry, dict) and set(entry) == ENTRY_KEYS for entry in entries),
        "every profile catalog entry must use the exact version-1 field set",
    )

    identities = [entry["identity"] for entry in entries]
    require(identities == sorted(identities), "profile catalog entries must be sorted by identity")
    require(len(identities) == len(set(identities)), "profile catalog identities must be unique")
    by_identity = {entry["identity"]: entry for entry in entries}

    profile_names: dict[str, list[str]] = {}
    profile_documents: dict[str, dict[str, Any]] = {}
    catalogued_files: set[str] = set()
    for entry in entries:
        identity = entry["identity"]
        file_name = entry["file"]
        digest = entry["digest"]
        composed_from = entry["composed_from"]
        require(isinstance(identity, str) and IDENTITY_RE.fullmatch(identity), f"invalid profile identity: {identity!r}")
        require(
            isinstance(file_name, str)
            and Path(file_name).name == file_name
            and file_name.startswith("oxibelt-")
            and file_name.endswith(".json"),
            f"{identity} must reference a safe profile basename",
        )
        require(identity == f"{Path(file_name).stem}-v1", f"{identity} must be the versioned profile filename")
        require(file_name not in catalogued_files, f"profile file is catalogued more than once: {file_name}")
        catalogued_files.add(file_name)
        require(isinstance(digest, str) and DIGEST_RE.fullmatch(digest), f"{identity} has an invalid digest")
        require(
            entry["qualification"] == "unverified",
            f"{identity} must remain unverified until a reviewed dynamic qualification contract is added",
        )
        require(entry["execution_scope"] in EXECUTION_SCOPES, f"{identity} has an invalid execution_scope")
        require(entry["runtime"] in RUNTIMES, f"{identity} has an invalid runtime")
        require(
            isinstance(composed_from, list)
            and composed_from == sorted(composed_from)
            and len(composed_from) == len(set(composed_from))
            and all(isinstance(source, str) for source in composed_from),
            f"{identity} composed_from must be a sorted unique string array",
        )

        profile_path = seccomp_dir / file_name
        require(profile_path.is_file(), f"{identity} profile file is missing: {file_name}")
        profile, names, raw = validate_profile(profile_path)
        actual_digest = f"sha256:{hashlib.sha256(raw).hexdigest()}"
        require(actual_digest == digest, f"{identity} raw-file digest mismatch: expected {digest}, found {actual_digest}")
        profile_names[identity] = names
        profile_documents[identity] = profile

    checked_in_files = {path.name for path in seccomp_dir.glob("oxibelt-*.json")}
    require(
        checked_in_files == catalogued_files,
        "profile catalog membership differs from checked-in oxibelt-*.json files",
    )

    for identity, entry in by_identity.items():
        sources = entry["composed_from"]
        if not sources:
            continue
        require(len(sources) == 2, f"{identity} composed profile must have exactly two sources")
        require(identity not in sources, f"{identity} must not compose itself")
        require(all(source in by_identity for source in sources), f"{identity} references an unknown source profile")
        require(
            all(not by_identity[source]["composed_from"] for source in sources),
            f"{identity} sources must be base profiles",
        )
        expected_names = sorted({name for source in sources for name in profile_names[source]})
        require(
            profile_names[identity] == expected_names,
            f"{identity} syscall names must be the exact union of composed_from profiles",
        )
        for source in sources:
            source_profile = profile_documents[source]
            combined_profile = profile_documents[identity]
            require(
                source_profile["defaultAction"] == combined_profile["defaultAction"]
                and source_profile["architectures"] == combined_profile["architectures"],
                f"{identity} must preserve source default action and architectures",
            )

    print(f"Seccomp profile contract passed: {len(entries)} versioned profiles (all unverified)")
    return len(entries)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    default_dir = Path(__file__).resolve().parents[2] / "deploy" / "seccomp"
    parser.add_argument("--seccomp-dir", type=Path, default=default_dir)
    args = parser.parse_args()
    try:
        validate(args.seccomp_dir)
    except (ContractError, OSError) as error:
        print(f"Seccomp profile contract failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
