#!/usr/bin/env python3
"""Focused tests for the official RISC-V release runtime-smoke contract."""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import importlib.util
import io
import json
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("run-riscv64-release-image-smoke.py")
SPEC = importlib.util.spec_from_file_location("riscv64_release_image_smoke", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot import {SCRIPT}")
SMOKE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SMOKE
SPEC.loader.exec_module(SMOKE)


def write_json(path: pathlib.Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def docker_archive(path: pathlib.Path) -> str:
    config = json.dumps(
        {"architecture": "riscv64", "os": "linux"},
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(config).hexdigest()
    manifest = json.dumps(
        [{"Config": f"{digest}.json", "RepoTags": [], "Layers": []}],
        separators=(",", ":"),
    ).encode("utf-8")
    with tarfile.open(path, mode="w") as archive:
        for name, content in (
            ("manifest.json", manifest),
            (f"{digest}.json", config),
        ):
            member = tarfile.TarInfo(name)
            member.size = len(content)
            member.mode = 0o644
            archive.addfile(member, io.BytesIO(content))
    return f"sha256:{digest}"


class FakeCrashRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def run(
        self,
        args: list[str],
        *,
        timeout: int,
        check: bool = True,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        del timeout, check, env
        self.calls.append(args)
        if args[:2] == ["docker", "create"]:
            return subprocess.CompletedProcess(args, 0, "crash-container\n", "")
        if args[:4] == ["docker", "start", "--attach", "crash-container"]:
            return subprocess.CompletedProcess(args, 139, "", "startup crash")
        if args[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(
                args, 0, '{"Running":false,"ExitCode":139}\n', ""
            )
        if args[:2] == ["docker", "logs"]:
            return subprocess.CompletedProcess(args, 0, "startup crash\n", "")
        return subprocess.CompletedProcess(args, 0, "", "")


class Riscv64ReleaseImageSmokeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="oxibelt-riscv64-smoke-test-"
        )
        self.root = pathlib.Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def release_args(self) -> argparse.Namespace:
        image = self.root / "oxibelt-alpine-musl-riscv64.tar"
        config_digest = docker_archive(image)
        manifest_digest = "sha256:" + "b" * 64
        metadata = self.root / "oxibelt-alpine-musl-riscv64-build-metadata.json"
        contract = self.root / "oxibelt-alpine-musl-riscv64-artifact-contract.json"
        plan = self.root / "image-plan.json"
        binaries = [
            "oxibelt",
            "oxibeltctl",
            "oxibelt-keysigner",
            "oxibelt-netport-switcher",
        ]
        write_json(
            plan,
            {
                "schemaVersion": 8,
                "tag": "1.2.3",
                "version": "1.2.3",
                "kind": "stable",
                "revision": "a" * 40,
                "sourceRef": "refs/tags/1.2.3",
                "sourceDirty": "clean",
                "buildKind": "official_release",
                "roles": [{"role": "standalone", "binaries": binaries}],
                "artifacts": [
                    {
                        "role": "standalone",
                        "artifactArch": "riscv64",
                        "platform": "linux/riscv64",
                        "dockerArchitecture": "riscv64",
                        "binaries": binaries,
                        "imageTar": image.name,
                    }
                ],
            },
        )
        write_json(
            metadata,
            {
                "containerimage.config.digest": config_digest,
                "containerimage.digest": manifest_digest,
                "containerimage.descriptor": {"digest": manifest_digest},
            },
        )
        write_json(
            contract,
            {
                "schema": 3,
                "role": "standalone",
                "artifact_arch": "riscv64",
                "platform": "linux/riscv64",
                "docker_architecture": "riscv64",
                "version": "1.2.3",
                "revision": "a" * 40,
                "source_ref": "refs/tags/1.2.3",
                "source_dirty": "clean",
                "build_kind": "official_release",
                "image_tar": image.name,
                "image_tar_sha256": SMOKE.sha256_file(image),
                "build_metadata": metadata.name,
                "config_digest": config_digest,
                "descriptor_digest": manifest_digest,
                "image_digest": manifest_digest,
                "binaries": [
                    {
                        "name": binary,
                        "path": f"/usr/local/bin/{binary}",
                        "version": "1.2.3",
                    }
                    for binary in binaries
                ],
            },
        )
        return argparse.Namespace(
            image_plan=plan,
            artifact_contract=contract,
            build_metadata=metadata,
            image_tar=image,
            fixture_root=self.root,
            strict_validator=self.root / "strict.py",
            role="standalone",
            expected_version="1.2.3",
            expected_revision="a" * 40,
            expected_source_ref="refs/tags/1.2.3",
            evidence_dir=self.root / "evidence",
        )

    def test_validates_digest_bound_official_release_artifact(self) -> None:
        args = self.release_args()

        artifact = SMOKE.validate_release_artifact(args)

        self.assertEqual(artifact.image_id, "sha256:" + hashlib.sha256(
            b'{"architecture":"riscv64","os":"linux"}'
        ).hexdigest())
        self.assertEqual(artifact.manifest_digest, "sha256:" + "b" * 64)
        self.assertEqual(artifact.binaries, SMOKE.ROLE_BINARIES["standalone"])
        self.assertEqual(artifact.archive_references, ())

    def test_rejects_non_tag_source_and_manifest_digest_mismatch(self) -> None:
        args = self.release_args()
        args.expected_source_ref = "main"
        with self.assertRaisesRegex(SMOKE.SmokeError, "full release tag ref"):
            SMOKE.validate_release_artifact(args)

        args = self.release_args()
        metadata = json.loads(args.build_metadata.read_text(encoding="utf-8"))
        metadata["containerimage.digest"] = "sha256:" + "c" * 64
        write_json(args.build_metadata, metadata)
        with self.assertRaisesRegex(SMOKE.SmokeError, "Buildx image digest"):
            SMOKE.validate_release_artifact(args)

    def test_build_identity_requires_one_exact_marker(self) -> None:
        expected = {
            "version": "1.2.3",
            "revision": "a" * 40,
            "source_ref": "refs/tags/1.2.3",
            "dirty": "clean",
            "kind": "official_release",
        }
        marker = f"OXIBELT_BUILD_IDENTITY_V1={json.dumps(expected)}"
        self.assertEqual(SMOKE.parse_build_identity(marker, expected), expected)
        with self.assertRaisesRegex(SMOKE.SmokeError, "exactly one"):
            SMOKE.parse_build_identity(f"{marker}\n{marker}", expected)
        wrong = dict(expected)
        wrong["revision"] = "b" * 40
        with self.assertRaisesRegex(SMOKE.SmokeError, "identity was"):
            SMOKE.parse_build_identity(
                f"OXIBELT_BUILD_IDENTITY_V1={json.dumps(wrong)}",
                expected,
            )

    def rootfs(self, entries: list[tuple[str, int]]) -> pathlib.Path:
        path = self.root / f"rootfs-{len(list(self.root.glob('rootfs-*')))}.tar"
        with tarfile.open(path, mode="w") as archive:
            directory = tarfile.TarInfo("usr/local/bin")
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o755
            archive.addfile(directory)
            for name, mode in entries:
                content = b"binary"
                member = tarfile.TarInfo(f"usr/local/bin/{name}")
                member.size = len(content)
                member.mode = mode
                archive.addfile(member, io.BytesIO(content))
        return path

    def test_rootfs_inventory_rejects_missing_and_unexpected_executables(self) -> None:
        expected = ("oxibelt",)
        SMOKE.inspect_rootfs_inventory(self.rootfs([("oxibelt", 0o755)]), expected)
        with self.assertRaisesRegex(SMOKE.SmokeError, "unexpected=.*oxibelt-admin"):
            SMOKE.inspect_rootfs_inventory(
                self.rootfs(
                    [
                        ("oxibelt", 0o755),
                        ("oxibelt-admin", 0o755),
                    ]
                ),
                expected,
            )
        with self.assertRaisesRegex(SMOKE.SmokeError, "missing=.*oxibelt"):
            SMOKE.inspect_rootfs_inventory(self.rootfs([]), expected)

    def test_readiness_fails_immediately_on_startup_crash(self) -> None:
        with self.assertRaisesRegex(SMOKE.SmokeError, "code 139"):
            SMOKE.wait_for_service(
                "server",
                lambda: (False, 139),
                lambda: False,
            )

    def test_readiness_timeout_is_bounded(self) -> None:
        moments = iter((0.0, 0.0, 1.0))
        with self.assertRaisesRegex(SMOKE.SmokeError, "within 0.5s"):
            SMOKE.wait_for_service(
                "server",
                lambda: (True, None),
                lambda: False,
                timeout_seconds=0.5,
                clock=lambda: next(moments),
                sleep=lambda _seconds: None,
            )

    def test_startup_crash_is_retained_for_bounded_diagnostics_and_cleanup(
        self,
    ) -> None:
        args = self.release_args()
        artifact = SMOKE.validate_release_artifact(args)
        runner = FakeCrashRunner()
        receipt = {"checks": []}
        smoke = SMOKE.DockerSmoke(runner, artifact, args, receipt)
        try:
            with self.assertRaisesRegex(SMOKE.SmokeError, "code 139"):
                smoke.run_one_shot("/usr/local/bin/oxibelt", ["--version"])
            self.assertEqual(smoke.containers, ["crash-container"])
            smoke.capture_diagnostics()
            self.assertIn(
                "startup crash",
                (args.evidence_dir / "container-1.log").read_text(encoding="utf-8"),
            )
        finally:
            smoke.cleanup()
        self.assertTrue(
            any(
                call[:4] == ["docker", "rm", "--force", "crash-container"]
                for call in runner.calls
            )
        )

    def test_cleanup_preserves_a_preexisting_release_image(self) -> None:
        args = self.release_args()
        artifact = SMOKE.validate_release_artifact(args)
        runner = FakeCrashRunner()
        smoke = SMOKE.DockerSmoke(runner, artifact, args, {"checks": []})
        smoke.image_preexisting = True

        self.assertEqual(smoke.cleanup(), [])
        self.assertFalse(
            any(call[:3] == ["docker", "image", "rm"] for call in runner.calls)
        )

    def test_load_refuses_to_replace_a_preexisting_archive_tag(self) -> None:
        args = self.release_args()
        artifact = dataclasses.replace(
            SMOKE.validate_release_artifact(args),
            archive_references=("oxibelt:existing",),
        )
        runner = FakeCrashRunner()
        smoke = SMOKE.DockerSmoke(runner, artifact, args, {"checks": []})
        try:
            with self.assertRaisesRegex(
                SMOKE.SmokeError,
                "refusing to replace preexisting Docker image reference",
            ):
                smoke.load_and_verify_image()
            self.assertFalse(
                any(call[:2] == ["docker", "load"] for call in runner.calls)
            )
        finally:
            smoke.image_preexisting = True
            smoke.cleanup()


if __name__ == "__main__":
    unittest.main()
