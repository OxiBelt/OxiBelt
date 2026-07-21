#!/usr/bin/env python3
"""Focused tests for the release-image normalizer and receipt contract."""

from __future__ import annotations

import hashlib
import io
import json
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import unittest
from typing import Any


SCRIPT = pathlib.Path(__file__).with_name("compare-release-image-artifacts.py")
VALIDATOR = pathlib.Path(__file__).with_name("validate-ci-image-artifact.py")
REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


def digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def layer(entries: list[tuple[str, bytes, int]], mtime: int = 0) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, content, mode in entries:
            member = tarfile.TarInfo(name)
            member.size = len(content)
            member.mode = mode
            member.uid = 10001
            member.gid = 10001
            member.mtime = mtime
            archive.addfile(member, io.BytesIO(content))
    return output.getvalue()


def docker_archive(path: pathlib.Path, layer_value: bytes, created: str) -> str:
    layer_digest = digest(layer_value)
    config = {
        "created": created,
        "architecture": "amd64",
        "os": "linux",
        "config": {
            "User": "10001:10001",
            "Entrypoint": [
                "/usr/local/bin/oxibelt",
                "--config",
                "/etc/oxibelt/config/oxibelt.toml",
            ],
            "Cmd": None,
            "ExposedPorts": {"8443/tcp": {}, "8443/udp": {}},
            "Labels": {
                "org.opencontainers.image.created": "2026-07-21T00:00:00Z",
                "org.opencontainers.image.version": "1.2.3",
                "org.opencontainers.image.ref.name": "1.2.3",
                "org.opencontainers.image.revision": "a" * 40,
                "org.opencontainers.image.source": "https://github.com/OxiBelt/OxiBelt",
                "org.opencontainers.image.url": "https://github.com/OxiBelt/OxiBelt",
                "io.oxibelt.image.role": "standalone",
            },
        },
        "rootfs": {"type": "layers", "diff_ids": [layer_digest]},
        "history": [{"created": created, "created_by": "fixture"}],
    }
    config_bytes = json.dumps(config, separators=(",", ":")).encode()
    config_name = f"{hashlib.sha256(config_bytes).hexdigest()}.json"
    layer_name = f"{layer_digest.removeprefix('sha256:')}/layer.tar"
    manifest = json.dumps(
        [{"Config": config_name, "RepoTags": ["fixture:test"], "Layers": [layer_name]}]
    ).encode()
    with tarfile.open(path, mode="w") as archive:
        for name, content in (
            ("manifest.json", manifest),
            (config_name, config_bytes),
            (layer_name, layer_value),
        ):
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    return digest(config_bytes)


def write_json(path: pathlib.Path, value: Any) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def sbom(image_digest: str) -> dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{image_digest[-32:]}",
        "metadata": {
            "timestamp": "2026-07-21T00:00:00Z",
            "component": {
                "type": "container",
                "name": "fixture:test",
                "bom-ref": "fixture:test",
                "hashes": [{"alg": "SHA-256", "content": image_digest[-64:]}],
                "properties": [
                    {"name": "io.oxibelt.image.digest", "value": image_digest},
                    {"name": "io.oxibelt.image.role", "value": "standalone"},
                ],
            },
        },
        "components": [{"type": "library", "name": "musl", "version": "1.2.5", "bom-ref": "musl"}],
        "dependencies": [{"ref": "fixture:test", "dependsOn": ["musl"]}],
    }


class ComparatorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="oxibelt-rebuild-compare-")
        self.root = pathlib.Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def artifact(
        self,
        prefix: str,
        entries: list[tuple[str, bytes, int]],
        *,
        layer_mtime: int = 0,
        created: str = "2026-07-21T00:00:00Z",
    ) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
        image = self.root / f"{prefix}.tar"
        config_digest = docker_archive(image, layer(entries, layer_mtime), created)
        image_digest = digest(image.read_bytes() + b"manifest")
        contract = self.root / f"{prefix}-contract.json"
        value = {
            "schema": 2,
            "revision": "a" * 40,
            "source": "https://github.com/OxiBelt/OxiBelt",
            "source_tree": "b" * 40,
            "version": "1.2.3",
            "ref_name": "1.2.3",
            "created": "2026-07-21T00:00:00Z",
            "role": "standalone",
            "platform": "linux/amd64",
            "artifact_arch": "amd64",
            "docker_architecture": "amd64",
            "rust_target": "x86_64-unknown-linux-musl",
            "target_cpu": "x86-64-v3",
            "docker_target": "standalone",
            "cargo_builds": [],
            "build_parameters": {"docker_target": "standalone"},
            "source_inputs": {"Cargo.lock": "sha256:" + "c" * 64},
            "source_inputs_sha256": "sha256:" + "d" * 64,
            "image_tar": image.name,
            "image_tar_sha256": digest(image.read_bytes()),
            "build_metadata": "oxibelt-alpine-musl-amd64-build-metadata.json",
            "config_digest": config_digest,
            "normalized_config_sha256": "sha256:" + "e" * 64,
            "descriptor_digest": image_digest,
            "image_digest": image_digest,
            "layers": [],
        }
        write_json(contract, value)
        sbom_path = self.root / f"{prefix}-sbom.json"
        write_json(sbom_path, sbom(image_digest))
        return image, contract, sbom_path

    def compare(
        self,
        published: tuple[pathlib.Path, pathlib.Path, pathlib.Path],
        rebuilt: tuple[pathlib.Path, pathlib.Path, pathlib.Path],
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
        output = self.root / "receipt.json"
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--published-image-tar",
                str(published[0]),
                "--published-contract",
                str(published[1]),
                "--published-sbom",
                str(published[2]),
                "--published-subject-digest",
                str(json.loads(published[1].read_text(encoding="utf-8"))["image_digest"]),
                "--rebuilt-image-tar",
                str(rebuilt[0]),
                "--rebuilt-contract",
                str(rebuilt[1]),
                "--rebuilt-sbom",
                str(rebuilt[2]),
                "--output",
                str(output),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        return result, json.loads(output.read_text(encoding="utf-8"))

    def test_exact_manifest_digest_is_byte_for_byte_reproducible(self) -> None:
        published = self.artifact("published", [("app/oxibelt", b"binary", 0o755)])
        rebuilt = self.artifact("rebuilt", [("app/oxibelt", b"binary", 0o755)])
        rebuilt_contract = json.loads(rebuilt[1].read_text(encoding="utf-8"))
        published_contract = json.loads(published[1].read_text(encoding="utf-8"))
        rebuilt_contract["image_digest"] = published_contract["image_digest"]
        write_json(rebuilt[1], rebuilt_contract)
        write_json(rebuilt[2], sbom(published_contract["image_digest"]))

        result, receipt = self.compare(published, rebuilt)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(receipt["outcome"], "exact")

    def test_timestamp_and_archive_order_drift_is_normalized(self) -> None:
        entries = [("app/oxibelt", b"binary", 0o755), ("etc/config", b"value", 0o640)]
        published = self.artifact("published", entries, layer_mtime=1, created="2026-07-21T01:00:00Z")
        rebuilt = self.artifact("rebuilt", list(reversed(entries)), layer_mtime=2, created="2026-07-21T02:00:00Z")

        result, receipt = self.compare(published, rebuilt)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(receipt["outcome"], "normalized_equivalent")
        self.assertIn("not byte-for-byte", receipt["guarantee"])

    def test_content_or_mode_drift_is_a_mismatch(self) -> None:
        published = self.artifact("published", [("app/oxibelt", b"binary", 0o755)])
        rebuilt = self.artifact("rebuilt", [("app/oxibelt", b"changed", 0o700)])

        result, receipt = self.compare(published, rebuilt)

        self.assertEqual(result.returncode, 1)
        self.assertEqual(receipt["outcome"], "mismatch")
        self.assertIn("filesystem", receipt["differences"])

    def test_traversal_layer_is_unverifiable(self) -> None:
        published = self.artifact("published", [("app/oxibelt", b"binary", 0o755)])
        rebuilt = self.artifact("rebuilt", [("../escape", b"bad", 0o644)])

        result, receipt = self.compare(published, rebuilt)

        self.assertEqual(result.returncode, 2)
        self.assertEqual(receipt["outcome"], "unverifiable")
        self.assertIn("unsafe", receipt["differences"][0])

    def test_artifact_validator_creates_and_revalidates_schema_two_evidence(self) -> None:
        image = self.root / "oxibelt-alpine-musl-amd64.tar"
        config_digest = docker_archive(
            image, layer([("usr/local/bin/oxibelt", b"binary", 0o755)]),
            "2026-07-21T00:00:00Z"
        )
        image_digest = digest(b"manifest")
        metadata = self.root / "oxibelt-alpine-musl-amd64-build-metadata.json"
        write_json(metadata, {
            "containerimage.config.digest": config_digest,
            "containerimage.digest": image_digest,
            "containerimage.descriptor": {"digest": image_digest},
        })
        contract = self.root / "oxibelt-alpine-musl-amd64-artifact-contract.json"
        common = [
            sys.executable, str(VALIDATOR),
            "--image-tar", str(image),
            "--build-metadata", str(metadata),
            "--contract", str(contract),
            "--role", "standalone",
            "--artifact-arch", "amd64",
            "--expected-revision", "a" * 40,
            "--expected-source", "https://github.com/OxiBelt/OxiBelt",
            "--expected-source-tree", "b" * 40,
            "--expected-version", "1.2.3",
            "--expected-ref-name", "1.2.3",
            "--expected-created", "2026-07-21T00:00:00Z",
            "--rust-builder-image", "rust:1.97.0-trixie@sha256:" + "1" * 64,
            "--node-builder-image", "node:24-alpine3.24@sha256:" + "2" * 64,
            "--runtime-image", "alpine:3.24@sha256:" + "3" * 64,
            "--repo-root", str(REPO_ROOT),
        ]
        created = subprocess.run([*common[:2], "create", *common[2:]], check=False, capture_output=True, text=True)
        self.assertEqual(created.returncode, 0, created.stdout + created.stderr)
        value = json.loads(contract.read_text(encoding="utf-8"))
        self.assertEqual(value["schema"], 2)
        self.assertEqual(value["image_digest"], image_digest)
        self.assertEqual(value["source_inputs"]["Cargo.lock"]["type"], "file")
        self.assertEqual(len(value["layers"]), 1)

        validated = subprocess.run([*common[:2], "validate", *common[2:]], check=False, capture_output=True, text=True)
        self.assertEqual(validated.returncode, 0, validated.stdout + validated.stderr)


if __name__ == "__main__":
    unittest.main()
