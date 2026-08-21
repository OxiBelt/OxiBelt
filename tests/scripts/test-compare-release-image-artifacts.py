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


def layer(
    entries: list[tuple[str, bytes, int]],
    mtime: int = 0,
    *,
    pax_headers: dict[str, str] | None = None,
    global_pax_headers: dict[str, str] | None = None,
    uname: str = "",
    gname: str = "",
) -> bytes:
    output = io.BytesIO()
    with tarfile.open(
        fileobj=output,
        mode="w",
        format=tarfile.PAX_FORMAT,
        pax_headers=global_pax_headers,
    ) as archive:
        for name, content, mode in entries:
            member = tarfile.TarInfo(name)
            member.size = len(content)
            member.mode = mode
            member.uid = 10001
            member.gid = 10001
            member.uname = uname
            member.gname = gname
            member.mtime = mtime
            member.pax_headers = dict(pax_headers or {})
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
                "io.oxibelt.build.source-ref": "refs/tags/1.2.3",
                "io.oxibelt.build.dirty": "clean",
                "io.oxibelt.build.kind": "official_release",
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


def replace_outer_member(path: pathlib.Path, target: str, replacement: bytes) -> None:
    rewritten = path.with_name(f"{path.name}.rewritten")
    replaced = False
    with tarfile.open(path, mode="r") as source, tarfile.open(rewritten, mode="w") as output:
        for member in source:
            stream = source.extractfile(member)
            if stream is None:
                raise AssertionError(f"fixture member {member.name!r} is not a regular file")
            content = stream.read()
            if member.name == target:
                content = replacement
                replaced = True
            replacement_member = tarfile.TarInfo(member.name)
            replacement_member.size = len(content)
            output.addfile(replacement_member, io.BytesIO(content))
    if not replaced:
        raise AssertionError(f"fixture is missing {target!r}")
    rewritten.replace(path)


def append_outer_members(path: pathlib.Path, name: str, contents: list[bytes]) -> None:
    with tarfile.open(path, mode="a") as archive:
        for content in contents:
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))


def unsupported_layer(name: str) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
        member = tarfile.TarInfo(name)
        member.type = b"Z"
        member.size = 0
        archive.addfile(member)
    return output.getvalue()


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
        pax_headers: dict[str, str] | None = None,
        global_pax_headers: dict[str, str] | None = None,
        uname: str = "",
        gname: str = "",
    ) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
        image = self.root / f"{prefix}.tar"
        layer_value = layer(
            entries,
            layer_mtime,
            pax_headers=pax_headers,
            global_pax_headers=global_pax_headers,
            uname=uname,
            gname=gname,
        )
        config_digest = docker_archive(image, layer_value, created)
        image_digest = digest(image.read_bytes() + b"manifest")
        contract = self.root / f"{prefix}-contract.json"
        value = {
            "schema": 3,
            "revision": "a" * 40,
            "source": "https://github.com/OxiBelt/OxiBelt",
            "source_tree": "b" * 40,
            "version": "1.2.3",
            "ref_name": "1.2.3",
            "source_ref": "refs/tags/1.2.3",
            "source_dirty": "clean",
            "build_kind": "official_release",
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

    def refresh_archive_digest(self, contract: pathlib.Path, image: pathlib.Path) -> None:
        value = json.loads(contract.read_text(encoding="utf-8"))
        value["image_tar_sha256"] = digest(image.read_bytes())
        write_json(contract, value)

    def assert_redacted_unverifiable(
        self,
        result: subprocess.CompletedProcess[str],
        receipt: dict[str, Any],
        *secrets: str,
    ) -> None:
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(receipt["outcome"], "unverifiable")
        self.assertLessEqual(len(receipt["differences"][0].encode("utf-8")), 256)
        rendered = result.stdout + result.stderr + json.dumps(receipt)
        for secret in secrets:
            self.assertNotIn(secret, rendered)

    def test_exact_manifest_and_archive_digests_are_byte_for_byte_reproducible(self) -> None:
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

    def test_same_manifest_with_different_archive_is_only_normalized(self) -> None:
        entries = [("app/oxibelt", b"binary", 0o755), ("etc/config", b"value", 0o640)]
        published = self.artifact("published", entries, layer_mtime=1)
        rebuilt = self.artifact("rebuilt", list(reversed(entries)), layer_mtime=2)
        published_contract = json.loads(published[1].read_text(encoding="utf-8"))
        rebuilt_contract = json.loads(rebuilt[1].read_text(encoding="utf-8"))
        self.assertNotEqual(
            published_contract["image_tar_sha256"],
            rebuilt_contract["image_tar_sha256"],
        )
        rebuilt_contract["image_digest"] = published_contract["image_digest"]
        write_json(rebuilt[1], rebuilt_contract)
        write_json(rebuilt[2], sbom(published_contract["image_digest"]))

        result, receipt = self.compare(published, rebuilt)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(receipt["outcome"], "normalized_equivalent")
        self.assertEqual(receipt["differences"], [])

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

    def test_apk_transaction_log_content_drift_remains_a_mismatch(self) -> None:
        published = self.artifact(
            "published-apk-log",
            [("var/log/apk.log", b"apk transaction at 2026-08-21 05:28:01\n", 0o644)],
        )
        rebuilt = self.artifact(
            "rebuilt-apk-log",
            [("var/log/apk.log", b"apk transaction at 2026-08-21 06:07:22\n", 0o644)],
        )

        result, receipt = self.compare(published, rebuilt)

        self.assertEqual(result.returncode, 1)
        self.assertEqual(receipt["outcome"], "mismatch")
        self.assertIn("filesystem", receipt["differences"])
        self.assertEqual(
            receipt["diagnostics"]["filesystem"]["records"],
            [
                {
                    "categories": ["content"],
                    "pathFingerprint": "sha256:37681810e003fa38f27f134d7fd89b48c3b33bd150b85985751c842177777985",
                }
            ],
        )

    def test_sbom_order_only_drift_is_normalized(self) -> None:
        entries = [("app/oxibelt", b"binary", 0o755)]
        published = self.artifact("published-sbom-order", entries)
        rebuilt = self.artifact("rebuilt-sbom-order", entries)
        image_digest = json.loads(published[1].read_text(encoding="utf-8"))["image_digest"]
        published_sbom = sbom(image_digest)
        published_sbom["components"] = [
            {
                "type": "library",
                "name": "musl",
                "version": "1.2.5",
                "bom-ref": "musl",
                "hashes": [
                    {"alg": "SHA-512", "content": "b" * 128},
                    {"alg": "SHA-256", "content": "a" * 64},
                ],
                "properties": [
                    {"name": "io.oxibelt.z", "value": "z"},
                    {"name": "io.oxibelt.a", "value": "a"},
                ],
            },
            {"type": "library", "name": "zlib", "version": "1.3", "bom-ref": "zlib"},
        ]
        published_sbom["dependencies"] = [
            {"ref": "fixture:test", "dependsOn": ["zlib", "musl"]},
            {"ref": "musl", "dependsOn": []},
        ]
        rebuilt_sbom = json.loads(json.dumps(published_sbom))
        rebuilt_sbom["components"].reverse()
        rebuilt_sbom["components"][1]["hashes"].reverse()
        rebuilt_sbom["components"][1]["properties"].reverse()
        rebuilt_sbom["dependencies"].reverse()
        rebuilt_sbom["dependencies"][1]["dependsOn"].reverse()
        write_json(published[2], published_sbom)
        write_json(rebuilt[2], rebuilt_sbom)

        result, receipt = self.compare(published, rebuilt)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(receipt["outcome"], "exact")

    def test_semantic_sbom_change_is_a_mismatch_with_fingerprints(self) -> None:
        entries = [("app/oxibelt", b"binary", 0o755)]
        published = self.artifact("published-sbom-change", entries)
        rebuilt = self.artifact("rebuilt-sbom-change", entries)
        rebuilt_sbom = json.loads(rebuilt[2].read_text(encoding="utf-8"))
        rebuilt_sbom["components"][0]["version"] = "1.2.6"
        write_json(rebuilt[2], rebuilt_sbom)

        result, receipt = self.compare(published, rebuilt)

        self.assertEqual(result.returncode, 1)
        self.assertEqual(receipt["outcome"], "mismatch")
        self.assertEqual(receipt["differences"], ["sbom-graph"])
        diagnostics = receipt["diagnostics"]["sbom"]
        self.assertEqual(diagnostics["components"]["total"], 2)
        self.assertEqual(diagnostics["components"]["truncated"], 0)
        self.assertNotEqual(
            diagnostics["publishedFingerprint"], diagnostics["rebuiltFingerprint"]
        )

    def test_non_subject_root_hash_remains_comparison_significant(self) -> None:
        entries = [("app/oxibelt", b"binary", 0o755)]
        published = self.artifact("published-sbom-root-hash", entries)
        rebuilt = self.artifact("rebuilt-sbom-root-hash", entries)
        rebuilt_sbom = json.loads(rebuilt[2].read_text(encoding="utf-8"))
        rebuilt_sbom["metadata"]["component"]["hashes"].append(
            {"alg": "SHA-512", "content": "a" * 128}
        )
        write_json(rebuilt[2], rebuilt_sbom)

        result, receipt = self.compare(published, rebuilt)

        self.assertEqual(result.returncode, 1)
        self.assertEqual(receipt["outcome"], "mismatch")
        self.assertEqual(receipt["differences"], ["sbom-graph"])

    def test_custom_dependencies_array_order_is_comparison_significant(self) -> None:
        entries = [("app/oxibelt", b"binary", 0o755)]
        published = self.artifact("published-custom-dependencies", entries)
        rebuilt = self.artifact("rebuilt-custom-dependencies", entries)
        published_sbom = json.loads(published[2].read_text(encoding="utf-8"))
        published_sbom["custom"] = {
            "dependencies": [{"name": "first"}, {"name": "second"}]
        }
        rebuilt_sbom = json.loads(json.dumps(published_sbom))
        rebuilt_sbom["custom"]["dependencies"].reverse()
        write_json(published[2], published_sbom)
        write_json(rebuilt[2], rebuilt_sbom)

        result, receipt = self.compare(published, rebuilt)

        self.assertEqual(result.returncode, 1)
        self.assertEqual(receipt["outcome"], "mismatch")
        self.assertEqual(receipt["differences"], ["sbom-graph"])

    def test_malformed_component_collections_fail_closed_before_sorting(self) -> None:
        entries = [("app/oxibelt", b"binary", 0o755)]
        published = self.artifact("published-malformed-components", entries)
        rebuilt = self.artifact("rebuilt-malformed-components", entries)
        published_sbom = json.loads(published[2].read_text(encoding="utf-8"))
        published_sbom["components"] = [{"sequence": 1}, {"sequence": 2}]
        rebuilt_sbom = json.loads(json.dumps(published_sbom))
        rebuilt_sbom["components"].reverse()
        write_json(published[2], published_sbom)
        write_json(rebuilt[2], rebuilt_sbom)

        result, receipt = self.compare(published, rebuilt)

        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(receipt["outcome"], "unverifiable")
        self.assertIn("component type", receipt["differences"][0])

    def test_cyclonedx_version_is_limited_to_supported_versions(self) -> None:
        entries = [("app/oxibelt", b"binary", 0o755)]
        published = self.artifact("published-invalid-spec", entries)
        rebuilt = self.artifact("rebuilt-invalid-spec", entries)
        published_sbom = json.loads(published[2].read_text(encoding="utf-8"))
        published_sbom["specVersion"] = "1.5"
        write_json(published[2], published_sbom)

        result, receipt = self.compare(published, rebuilt)

        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(receipt["outcome"], "unverifiable")
        self.assertIn("specVersion", receipt["differences"][0])

        published = self.artifact("published-supported-spec", entries)
        rebuilt = self.artifact("rebuilt-supported-spec", entries)
        for artifact in (published, rebuilt):
            document = json.loads(artifact[2].read_text(encoding="utf-8"))
            document["specVersion"] = "1.6"
            write_json(artifact[2], document)

        result, receipt = self.compare(published, rebuilt)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(receipt["outcome"], "exact")

    def test_invalid_subject_bindings_fail_closed_on_both_inputs(self) -> None:
        entries = [("app/oxibelt", b"binary", 0o755)]
        cases: tuple[tuple[str, Any], ...] = (
            (
                "duplicate-hash",
                lambda document: document["metadata"]["component"]["hashes"].append(
                    dict(document["metadata"]["component"]["hashes"][0])
                ),
            ),
            (
                "missing-hash",
                lambda document: document["metadata"]["component"]["hashes"].clear(),
            ),
            (
                "wrong-property",
                lambda document: document["metadata"]["component"]["properties"].__setitem__(
                    0,
                    {
                        "name": "io.oxibelt.image.digest",
                        "value": "sha256:" + "0" * 64,
                    },
                ),
            ),
            (
                "extra-property-key",
                lambda document: document["metadata"]["component"]["properties"].append(
                    {
                        "name": "io.oxibelt.image.digest",
                        "value": document["metadata"]["component"]["properties"][0]["value"],
                        "unexpected": "field",
                    }
                ),
            ),
            (
                "extra-hash-key",
                lambda document: document["metadata"]["component"]["hashes"].append(
                    {
                        "alg": "SHA-256",
                        "content": document["metadata"]["component"]["hashes"][0][
                            "content"
                        ],
                        "unexpected": "field",
                    }
                ),
            ),
        )
        for name, mutate in cases:
            with self.subTest(name=name):
                published = self.artifact(f"published-subject-{name}", entries)
                rebuilt = self.artifact(f"rebuilt-subject-{name}", entries)
                published_sbom = json.loads(published[2].read_text(encoding="utf-8"))
                rebuilt_sbom = json.loads(rebuilt[2].read_text(encoding="utf-8"))
                mutate(published_sbom)
                mutate(rebuilt_sbom)
                write_json(published[2], published_sbom)
                write_json(rebuilt[2], rebuilt_sbom)

                result, receipt = self.compare(published, rebuilt)

                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertEqual(receipt["outcome"], "unverifiable")

    def test_sbom_resource_limits_fail_closed(self) -> None:
        entries = [("app/oxibelt", b"binary", 0o755)]
        published = self.artifact("published-sbom-depth", entries)
        rebuilt = self.artifact("rebuilt-sbom-depth", entries)
        deep: dict[str, Any] = {"leaf": "value"}
        for _ in range(65):
            deep = {"nested": deep}
        published_sbom = json.loads(published[2].read_text(encoding="utf-8"))
        published_sbom["custom"] = deep
        write_json(published[2], published_sbom)

        result, receipt = self.compare(published, rebuilt)

        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("nesting-depth", receipt["differences"][0])

        published = self.artifact("published-sbom-collection", entries)
        rebuilt = self.artifact("rebuilt-sbom-collection", entries)
        published_sbom = json.loads(published[2].read_text(encoding="utf-8"))
        component = {"type": "library", "name": "fixture", "version": "1", "bom-ref": "fixture"}
        published_sbom["components"] = [component] * 16385
        write_json(published[2], published_sbom)

        result, receipt = self.compare(published, rebuilt)

        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("collection-item", receipt["differences"][0])

    def test_near_limit_nested_component_chain_compares_successfully(self) -> None:
        entries = [("app/oxibelt", b"binary", 0o755)]
        published = self.artifact("published-nested-components", entries)
        rebuilt = self.artifact("rebuilt-nested-components", entries)

        nested: dict[str, Any] = {
            "type": "library",
            "name": "nested-30",
            "version": "1",
            "bom-ref": "nested-30",
        }
        for index in range(29, 0, -1):
            nested = {
                "type": "library",
                "name": f"nested-{index}",
                "version": "1",
                "bom-ref": f"nested-{index}",
                "components": [nested],
            }
        for artifact in (published, rebuilt):
            document = json.loads(artifact[2].read_text(encoding="utf-8"))
            document["metadata"]["component"]["components"] = [nested]
            write_json(artifact[2], document)

        result, receipt = self.compare(published, rebuilt)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(receipt["outcome"], "exact")

    def test_filesystem_diagnostics_are_classified_and_bounded(self) -> None:
        entries = [(f"app/file-{index:02d}", b"published", 0o755) for index in range(10)]
        published = self.artifact("published-filesystem-diagnostics", entries)
        rebuilt = self.artifact(
            "rebuilt-filesystem-diagnostics",
            [(name, b"rebuild!!", 0o700) for name, _, _ in entries],
        )

        result, receipt = self.compare(published, rebuilt)

        self.assertEqual(result.returncode, 1)
        diagnostics = receipt["diagnostics"]["filesystem"]
        self.assertEqual(diagnostics["total"], 10)
        self.assertEqual(diagnostics["truncated"], 2)
        self.assertEqual(len(diagnostics["records"]), 8)
        self.assertEqual(
            {tuple(record["categories"]) for record in diagnostics["records"]},
            {("content", "mode")},
        )
        self.assertTrue(
            all(record["pathFingerprint"].startswith("sha256:") for record in diagnostics["records"])
        )

    def test_extended_pax_metadata_drift_is_a_mismatch(self) -> None:
        metadata = (
            "LIBARCHIVE.xattr.security.capability",
            "SCHILY.xattr.security.capability",
            "SCHILY.acl.access",
            "SCHILY.fflags",
            "RHT.security.selinux",
            "atime",
            "ctime",
            "VENDOR.security.label",
        )
        for index, key in enumerate(metadata):
            with self.subTest(key=key):
                published = self.artifact(
                    f"published-pax-{index}",
                    [("app/oxibelt", b"binary", 0o755)],
                    pax_headers={key: "published-value"},
                )
                rebuilt = self.artifact(
                    f"rebuilt-pax-{index}",
                    [("app/oxibelt", b"binary", 0o755)],
                )

                result, receipt = self.compare(published, rebuilt)

                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertEqual(receipt["outcome"], "mismatch")
                self.assertIn("filesystem", receipt["differences"])

    def test_identical_pax_metadata_with_mtime_drift_is_normalized(self) -> None:
        entries = [("app/oxibelt", b"binary", 0o755)]
        published = self.artifact(
            "published-pax-mtime",
            entries,
            pax_headers={
                "LIBARCHIVE.xattr.security.capability": "same-value",
                "mtime": "1.25",
            },
        )
        rebuilt = self.artifact(
            "rebuilt-pax-mtime",
            entries,
            pax_headers={
                "LIBARCHIVE.xattr.security.capability": "same-value",
                "mtime": "2.5",
            },
        )

        result, receipt = self.compare(published, rebuilt)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(receipt["outcome"], "normalized_equivalent")

    def test_conflicting_pax_namespace_order_is_a_mismatch(self) -> None:
        entries = [("app/oxibelt", b"binary", 0o755)]
        published = self.artifact(
            "published-pax-order",
            entries,
            pax_headers={
                "SCHILY.xattr.security.capability": "schily-value",
                "LIBARCHIVE.xattr.security.capability": "libarchive-value",
            },
        )
        rebuilt = self.artifact(
            "rebuilt-pax-order",
            entries,
            pax_headers={
                "LIBARCHIVE.xattr.security.capability": "libarchive-value",
                "SCHILY.xattr.security.capability": "schily-value",
            },
        )

        result, receipt = self.compare(published, rebuilt)

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(receipt["outcome"], "mismatch")
        self.assertIn("filesystem", receipt["differences"])

    def test_global_pax_metadata_is_unverifiable(self) -> None:
        published = self.artifact(
            "published-global-pax",
            [("app/oxibelt", b"binary", 0o755)],
            global_pax_headers={"SCHILY.xattr.security.capability": "capability"},
        )
        rebuilt = self.artifact(
            "rebuilt-global-pax", [("app/oxibelt", b"binary", 0o755)]
        )

        result, receipt = self.compare(published, rebuilt)

        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(receipt["outcome"], "unverifiable")
        self.assertIn("global PAX", receipt["differences"][0])

    def test_owner_name_drift_is_a_mismatch(self) -> None:
        entries = [("app/oxibelt", b"binary", 0o755)]
        published = self.artifact(
            "published-owner", entries, uname="release", gname="release"
        )
        rebuilt = self.artifact(
            "rebuilt-owner", entries, uname="builder", gname="builder"
        )

        result, receipt = self.compare(published, rebuilt)

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(receipt["outcome"], "mismatch")
        self.assertIn("filesystem", receipt["differences"])

    def test_traversal_layer_is_unverifiable(self) -> None:
        published = self.artifact("published", [("app/oxibelt", b"binary", 0o755)])
        rebuilt = self.artifact("rebuilt", [("../escape", b"bad", 0o644)])

        result, receipt = self.compare(published, rebuilt)

        self.assertEqual(result.returncode, 2)
        self.assertEqual(receipt["outcome"], "unverifiable")
        self.assertIn("unsafe", receipt["differences"][0])
        self.assertNotIn("../escape", result.stdout)

    def test_archive_and_local_path_errors_are_redacted_and_bounded(self) -> None:
        published = self.artifact("published-redaction", [("app/oxibelt", b"binary", 0o755)])

        rebuilt = self.artifact("rebuilt-duplicate", [("app/oxibelt", b"binary", 0o755)])
        duplicate_name = "secret/archive/member"
        append_outer_members(rebuilt[0], duplicate_name, [b"one", b"two"])
        self.refresh_archive_digest(rebuilt[1], rebuilt[0])
        result, receipt = self.compare(published, rebuilt)
        self.assert_redacted_unverifiable(result, receipt, duplicate_name)

        rebuilt = self.artifact("rebuilt-long-pax", [("app/oxibelt", b"binary", 0o755)])
        long_name = "secret/" + "x" * 32768
        long_layer = layer([(long_name, b"one", 0o644), (long_name, b"two", 0o644)])
        with tarfile.open(rebuilt[0], mode="r") as archive:
            manifest = json.loads(archive.extractfile("manifest.json").read())
        replace_outer_member(rebuilt[0], manifest[0]["Layers"][0], long_layer)
        self.refresh_archive_digest(rebuilt[1], rebuilt[0])
        result, receipt = self.compare(published, rebuilt)
        self.assert_redacted_unverifiable(result, receipt, long_name)

        rebuilt = self.artifact("rebuilt-missing-layer", [("app/oxibelt", b"binary", 0o755)])
        with tarfile.open(rebuilt[0], mode="r") as archive:
            manifest = json.loads(archive.extractfile("manifest.json").read())
        missing_layer = "secret/missing/layer.tar"
        manifest[0]["Layers"] = [missing_layer]
        replace_outer_member(rebuilt[0], "manifest.json", json.dumps(manifest).encode())
        self.refresh_archive_digest(rebuilt[1], rebuilt[0])
        result, receipt = self.compare(published, rebuilt)
        self.assert_redacted_unverifiable(result, receipt, missing_layer)

        rebuilt = self.artifact("rebuilt-missing-config", [("app/oxibelt", b"binary", 0o755)])
        with tarfile.open(rebuilt[0], mode="r") as archive:
            manifest = json.loads(archive.extractfile("manifest.json").read())
        missing_config = "secret/missing/config.json"
        manifest[0]["Config"] = missing_config
        replace_outer_member(rebuilt[0], "manifest.json", json.dumps(manifest).encode())
        self.refresh_archive_digest(rebuilt[1], rebuilt[0])
        result, receipt = self.compare(published, rebuilt)
        self.assert_redacted_unverifiable(result, receipt, missing_config)

        rebuilt = self.artifact("rebuilt-unsupported", [("app/oxibelt", b"binary", 0o755)])
        with tarfile.open(rebuilt[0], mode="r") as archive:
            manifest = json.loads(archive.extractfile("manifest.json").read())
        unsupported_name = "secret/unsupported-type"
        replace_outer_member(
            rebuilt[0], manifest[0]["Layers"][0], unsupported_layer(unsupported_name)
        )
        self.refresh_archive_digest(rebuilt[1], rebuilt[0])
        result, receipt = self.compare(published, rebuilt)
        self.assert_redacted_unverifiable(result, receipt, unsupported_name)

        rebuilt = self.artifact("rebuilt-local", [("app/oxibelt", b"binary", 0o755)])
        local_path = self.root / "private/local/evidence.json"
        result, receipt = self.compare((published[0], published[1], local_path), rebuilt)
        self.assert_redacted_unverifiable(result, receipt, str(local_path))

    def test_artifact_validator_creates_and_revalidates_schema_three_evidence(self) -> None:
        image = self.root / "oxibelt-alpine-musl-amd64.tar"
        marker = (
            b'binary\x00OXIBELT_BUILD_IDENTITY_V1='
            b'{"version":"1.2.3","revision":"' + b'a' * 40
            + b'","source_ref":"refs/tags/1.2.3","dirty":"clean","kind":"official_release"}\x00'
        )
        config_digest = docker_archive(
            image,
            layer([
                (f"usr/local/bin/{name}", marker, 0o755)
                for name in (
                    "oxibelt",
                    "oxibeltctl",
                    "oxibelt-keysigner",
                    "oxibelt-netport-switcher",
                )
            ]),
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
            "--expected-source-ref", "refs/tags/1.2.3",
            "--expected-source-dirty", "clean",
            "--expected-build-kind", "official_release",
            "--expected-created", "2026-07-21T00:00:00Z",
            "--rust-builder-image", "rust:1.97.1-trixie@sha256:" + "1" * 64,
            "--node-builder-image", "node:24-alpine3.24@sha256:" + "2" * 64,
            "--runtime-image", "alpine:3.24@sha256:" + "3" * 64,
            "--repo-root", str(REPO_ROOT),
        ]
        created = subprocess.run([*common[:2], "create", *common[2:]], check=False, capture_output=True, text=True)
        self.assertEqual(created.returncode, 0, created.stdout + created.stderr)
        value = json.loads(contract.read_text(encoding="utf-8"))
        self.assertEqual(value["schema"], 3)
        self.assertEqual(value["image_digest"], image_digest)
        self.assertEqual(value["source_inputs"]["Cargo.lock"]["type"], "file")
        self.assertEqual(len(value["layers"]), 1)

        validated = subprocess.run([*common[:2], "validate", *common[2:]], check=False, capture_output=True, text=True)
        self.assertEqual(validated.returncode, 0, validated.stdout + validated.stderr)

        unexpected_config_digest = docker_archive(
            image,
            layer([
                (f"usr/local/bin/{name}", marker, 0o755)
                for name in (
                    "oxibelt",
                    "oxibeltctl",
                    "oxibelt-keysigner",
                    "oxibelt-netport-switcher",
                    "oxibelt-admin",
                )
            ]),
            "2026-07-21T00:00:00Z",
        )
        write_json(metadata, {
            "containerimage.config.digest": unexpected_config_digest,
            "containerimage.digest": image_digest,
            "containerimage.descriptor": {"digest": image_digest},
        })
        unexpected = subprocess.run(
            [*common[:2], "create", *common[2:]],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(unexpected.returncode, 0)
        self.assertIn("unexpected=['usr/local/bin/oxibelt-admin']", unexpected.stderr)


if __name__ == "__main__":
    unittest.main()
