#!/usr/bin/env python3
"""Normalize and validate a local Trivy GitHub dependency snapshot."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import tempfile
from typing import Any


MAXIMUM_SNAPSHOT_BYTES = 128 * 1024 * 1024
SHA = re.compile(r"[0-9a-f]{40,64}\Z")
ROLES = (
    "standalone",
    "dataplane",
    "dataplane-strict",
    "controller",
    "tools",
    "keysigner",
)
ARCHITECTURES = ("amd64v2", "amd64", "amd64v4", "arm64", "riscv64")
SNAPSHOT_KEYS = {"version", "sha", "ref", "job", "detector", "scanned", "manifests"}
CONTRACT_KEYS = {
    "schema",
    "revision",
    "ref",
    "role",
    "artifact_arch",
    "snapshot_file",
    "snapshot_sha256",
}


def fail(message: str) -> None:
    raise SystemExit(f"CI dependency snapshot validation failed: {message}")


def load_json(path: pathlib.Path, description: str) -> Any:
    if not path.is_file():
        fail(f"missing {description}: {path}")
    if path.stat().st_size > MAXIMUM_SNAPSHOT_BYTES:
        fail(f"{description} exceeds the 128 MiB limit: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot read {description} {path}: {error}")


def write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
    ) as stream:
        temporary = pathlib.Path(stream.name)
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
    os.replace(temporary, path)


def file_sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return f"sha256:{digest.hexdigest()}"


def expected_names(role: str, artifact_arch: str) -> tuple[str, str]:
    return (
        f"dependency-snapshot-{role}-{artifact_arch}.json",
        f"dependency-snapshot-{role}-{artifact_arch}-contract.json",
    )


def validate_identity(value: str, description: str, pattern: re.Pattern[str] | None = None) -> None:
    if not value or "\x00" in value or "\n" in value or "\r" in value:
        fail(f"invalid {description}")
    if pattern is not None and pattern.fullmatch(value) is None:
        fail(f"invalid {description}: {value!r}")


def expected_job(role: str, artifact_arch: str, run_id: str, run_attempt: str, html_url: str) -> dict[str, str]:
    return {
        "id": f"{run_id}.{run_attempt}.{role}.{artifact_arch}",
        "correlator": f"oxibelt-image:{role}:{artifact_arch}",
        "html_url": html_url,
    }


def normalized_snapshot(
    raw: Any,
    role: str,
    artifact_arch: str,
    revision: str,
    ref: str,
    run_id: str,
    run_attempt: str,
    html_url: str,
) -> dict[str, Any]:
    if not isinstance(raw, dict):
        fail("Trivy snapshot must be a JSON object")
    detector = raw.get("detector")
    manifests = raw.get("manifests", {})
    scanned = raw.get("scanned")
    if not isinstance(detector, dict) or not isinstance(detector.get("name"), str):
        fail("Trivy snapshot lacks detector identity")
    if not isinstance(manifests, dict):
        fail("Trivy snapshot manifests must be an object")
    if not isinstance(scanned, str) or not scanned:
        fail("Trivy snapshot lacks a scan timestamp")
    return {
        "version": 0,
        "sha": revision,
        "ref": ref,
        "job": expected_job(role, artifact_arch, run_id, run_attempt, html_url),
        "detector": detector,
        "scanned": scanned,
        "manifests": manifests,
    }


def validate_snapshot(
    snapshot: Any,
    role: str,
    artifact_arch: str,
    revision: str,
    ref: str,
    run_id: str,
    run_attempt: str,
    html_url: str,
) -> None:
    if not isinstance(snapshot, dict) or set(snapshot) != SNAPSHOT_KEYS:
        fail("normalized snapshot has an unexpected top-level schema")
    if snapshot.get("version") != 0 or snapshot.get("sha") != revision or snapshot.get("ref") != ref:
        fail("normalized snapshot commit identity does not match the workflow")
    if snapshot.get("job") != expected_job(role, artifact_arch, run_id, run_attempt, html_url):
        fail("normalized snapshot job identity does not match the workflow")
    if not isinstance(snapshot.get("detector"), dict) or not isinstance(
        snapshot["detector"].get("name"), str
    ):
        fail("normalized snapshot detector is invalid")
    if not isinstance(snapshot.get("scanned"), str) or not snapshot["scanned"]:
        fail("normalized snapshot scan timestamp is invalid")
    if not isinstance(snapshot.get("manifests"), dict):
        fail("normalized snapshot manifests are invalid")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("normalize", "validate"))
    parser.add_argument("--input", type=pathlib.Path)
    parser.add_argument("--snapshot", required=True, type=pathlib.Path)
    parser.add_argument("--contract", required=True, type=pathlib.Path)
    parser.add_argument("--role", required=True, choices=ROLES)
    parser.add_argument("--artifact-arch", required=True, choices=ARCHITECTURES)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--html-url", required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    validate_identity(args.revision, "revision", SHA)
    validate_identity(args.ref, "Git ref")
    validate_identity(args.run_id, "run ID")
    validate_identity(args.run_attempt, "run attempt")
    validate_identity(args.html_url, "run URL")
    snapshot_name, contract_name = expected_names(args.role, args.artifact_arch)
    if args.snapshot.name != snapshot_name or args.contract.name != contract_name:
        fail("snapshot or contract filename does not match its role and architecture")

    if args.mode == "normalize":
        if args.input is None:
            fail("normalize mode requires --input")
        snapshot = normalized_snapshot(
            load_json(args.input, "raw Trivy snapshot"),
            args.role,
            args.artifact_arch,
            args.revision,
            args.ref,
            args.run_id,
            args.run_attempt,
            args.html_url,
        )
        validate_snapshot(
            snapshot,
            args.role,
            args.artifact_arch,
            args.revision,
            args.ref,
            args.run_id,
            args.run_attempt,
            args.html_url,
        )
        write_json(args.snapshot, snapshot)
        contract = {
            "schema": 1,
            "revision": args.revision,
            "ref": args.ref,
            "role": args.role,
            "artifact_arch": args.artifact_arch,
            "snapshot_file": snapshot_name,
            "snapshot_sha256": file_sha256(args.snapshot),
        }
        write_json(args.contract, contract)
    else:
        snapshot = load_json(args.snapshot, "normalized snapshot")
        validate_snapshot(
            snapshot,
            args.role,
            args.artifact_arch,
            args.revision,
            args.ref,
            args.run_id,
            args.run_attempt,
            args.html_url,
        )
        contract = load_json(args.contract, "snapshot contract")
        if not isinstance(contract, dict) or set(contract) != CONTRACT_KEYS:
            fail("snapshot contract has an unexpected schema")
        expected_contract = {
            "schema": 1,
            "revision": args.revision,
            "ref": args.ref,
            "role": args.role,
            "artifact_arch": args.artifact_arch,
            "snapshot_file": snapshot_name,
            "snapshot_sha256": file_sha256(args.snapshot),
        }
        if contract != expected_contract:
            fail("snapshot contract does not match the snapshot and workflow identity")
    print(f"validated CI dependency snapshot: {args.role}/{args.artifact_arch}")


if __name__ == "__main__":
    main()
