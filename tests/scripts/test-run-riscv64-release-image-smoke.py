#!/usr/bin/env python3
"""Focused tests for the official RISC-V release runtime-smoke contract."""

from __future__ import annotations

import argparse
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


def docker_archive(
    path: pathlib.Path,
    *,
    config_layout: str = "legacy",
    repository_tag: str = "oxibelt:alpine-musl-riscv64",
) -> tuple[str, str]:
    config = json.dumps(
        {"architecture": "riscv64", "os": "linux"},
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(config).hexdigest()
    if config_layout == "legacy":
        config_name = f"{digest}.json"
    elif config_layout == "oci":
        config_name = f"blobs/sha256/{digest}"
    else:
        raise ValueError(f"unsupported config layout: {config_layout}")
    manifest = json.dumps(
        [{"Config": config_name, "RepoTags": [repository_tag], "Layers": []}],
        separators=(",", ":"),
    ).encode("utf-8")
    image_manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": f"sha256:{digest}",
                "size": len(config),
            },
            "layers": [],
        },
        separators=(",", ":"),
    ).encode("utf-8")
    manifest_digest = hashlib.sha256(image_manifest).hexdigest()
    index = json.dumps(
        {
            "schemaVersion": 2,
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": f"sha256:{manifest_digest}",
                    "size": len(image_manifest),
                }
            ],
        },
        separators=(",", ":"),
    ).encode("utf-8")
    with tarfile.open(path, mode="w") as archive:
        for name, content in (
            ("manifest.json", manifest),
            ("index.json", index),
            (config_name, config),
            (f"blobs/sha256/{manifest_digest}", image_manifest),
        ):
            member = tarfile.TarInfo(name)
            member.size = len(content)
            member.mode = 0o644
            archive.addfile(member, io.BytesIO(content))
    return f"sha256:{digest}", f"sha256:{manifest_digest}"


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


class RecordingCommandRunner(SMOKE.CommandRunner):
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
        self.calls.append(args)
        return super().run(args, timeout=timeout, check=check, env=env)


class FakeKeysignerSeedRunner:
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
        if args[:2] == ["openssl", "genpkey"]:
            pathlib.Path(args[args.index("-out") + 1]).write_text(
                "test key\n", encoding="utf-8"
            )
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[:4] == ["docker", "image", "inspect", SMOKE.NATIVE_HELPER_IMAGE]:
            return subprocess.CompletedProcess(args, 0, "{}\n", "")
        if args[:2] == ["docker", "create"]:
            return subprocess.CompletedProcess(args, 0, "keysigner-seed\n", "")
        if args[:4] == ["docker", "start", "--attach", "keysigner-seed"]:
            return subprocess.CompletedProcess(
                args,
                1,
                "",
                f"discarded-prefix-{'x' * 5000}-bounded-tail",
            )
        return subprocess.CompletedProcess(args, 0, "", "")


class FakeKeysignerSocketInitRunner:
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
        if args[:2] == ["openssl", "genpkey"]:
            pathlib.Path(args[args.index("-out") + 1]).write_text(
                "test key\n", encoding="utf-8"
            )
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[:4] == ["docker", "image", "inspect", SMOKE.NATIVE_HELPER_IMAGE]:
            return subprocess.CompletedProcess(args, 0, "{}\n", "")
        if args[:2] == ["docker", "create"]:
            command = args[args.index("-c") + 1] if "-c" in args else ""
            if command == SMOKE.KEYSIGNER_SEED_COMMAND:
                return subprocess.CompletedProcess(args, 0, "keysigner-seed\n", "")
            if command == "chmod 0770 /sock && chown 10002:10002 /sock":
                return subprocess.CompletedProcess(
                    args, 0, "keysigner-socket-init\n", ""
                )
            return subprocess.CompletedProcess(args, 0, "", "")
        return subprocess.CompletedProcess(args, 0, "", "")


class FakeImageRunner:
    def __init__(
        self,
        runtime_image_id: str,
        *,
        fail_load: bool = False,
        preexisting_reference_id: str | None = None,
    ) -> None:
        self.calls: list[list[str]] = []
        self.fail_load = fail_load
        self.runtime_image_id = runtime_image_id
        self.preexisting_reference_id = preexisting_reference_id
        self.loaded = False
        self.archive_reference = "oxibelt:alpine-musl-riscv64"

    def missing(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args,
            1,
            "",
            f"Error response from daemon: No such image: {args[-1]}",
        )

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
        if args[:2] == ["docker", "load"]:
            self.loaded = True
            if self.fail_load:
                raise SMOKE.SmokeError("simulated partial Docker load failure")
            return subprocess.CompletedProcess(
                args, 0, f"Loaded image: {self.archive_reference}\n", ""
            )
        if args[:3] != ["docker", "image", "inspect"]:
            return subprocess.CompletedProcess(args, 0, "", "")

        target = args[-1]
        format_value = args[4] if len(args) >= 6 and args[3] == "--format" else None
        active_image_id = (
            self.runtime_image_id
            if self.loaded or self.preexisting_reference_id is None
            else self.preexisting_reference_id
        )
        if format_value == "{{json .RepoTags}}":
            if (
                self.preexisting_reference_id is not None
                and target == self.preexisting_reference_id
            ):
                return subprocess.CompletedProcess(
                    args, 0, json.dumps([self.archive_reference]) + "\n", ""
                )
            return self.missing(args)
        if format_value == "{{.Id}}":
            if target == self.archive_reference:
                if not self.loaded:
                    if self.preexisting_reference_id is None:
                        return self.missing(args)
                    return subprocess.CompletedProcess(
                        args, 0, self.preexisting_reference_id + "\n", ""
                    )
                return subprocess.CompletedProcess(
                    args, 0, self.runtime_image_id + "\n", ""
                )
            if target == active_image_id and (
                self.loaded or self.preexisting_reference_id is not None
            ):
                return subprocess.CompletedProcess(
                    args, 0, active_image_id + "\n", ""
                )
            return self.missing(args)
        if format_value == "{{json .}}" and (
            self.loaded or self.preexisting_reference_id is not None
        ) and target in (self.archive_reference, active_image_id):
            image = {
                "Id": active_image_id,
                "Os": "linux",
                "Architecture": "riscv64",
                "RepoTags": [self.archive_reference],
                "Config": {
                    "User": "10001:10001",
                    "Labels": {
                        "io.oxibelt.image.role": "standalone",
                        "org.opencontainers.image.version": "1.2.3",
                        "org.opencontainers.image.revision": "a" * 40,
                        "io.oxibelt.build.source-ref": "refs/tags/1.2.3",
                        "io.oxibelt.build.dirty": "clean",
                        "io.oxibelt.build.kind": "official_release",
                    },
                },
            }
            return subprocess.CompletedProcess(args, 0, json.dumps(image) + "\n", "")
        if (
            format_value is None
            and target == active_image_id
            and (self.loaded or self.preexisting_reference_id is not None)
        ):
            return subprocess.CompletedProcess(args, 0, "{}\n", "")
        return self.missing(args)


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
        config_digest, manifest_digest = docker_archive(image)
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
                        "localTag": "oxibelt:alpine-musl-riscv64",
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
        self.assertRegex(artifact.manifest_digest, r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(artifact.binaries, SMOKE.ROLE_BINARIES["standalone"])
        self.assertEqual(
            artifact.archive_references,
            ("oxibelt:alpine-musl-riscv64",),
        )

    def test_accepts_oci_layout_config_path(self) -> None:
        args = self.release_args()
        config_digest, manifest_digest = docker_archive(
            args.image_tar, config_layout="oci"
        )
        metadata = json.loads(args.build_metadata.read_text(encoding="utf-8"))
        metadata["containerimage.config.digest"] = config_digest
        metadata["containerimage.digest"] = manifest_digest
        metadata["containerimage.descriptor"]["digest"] = manifest_digest
        write_json(args.build_metadata, metadata)
        contract = json.loads(args.artifact_contract.read_text(encoding="utf-8"))
        contract["config_digest"] = config_digest
        contract["descriptor_digest"] = manifest_digest
        contract["image_digest"] = manifest_digest
        contract["image_tar_sha256"] = SMOKE.sha256_file(args.image_tar)
        write_json(args.artifact_contract, contract)

        artifact = SMOKE.validate_release_artifact(args)

        self.assertEqual(artifact.image_id, config_digest)

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

    def test_rejects_false_manifest_subject_even_when_metadata_agrees(self) -> None:
        args = self.release_args()
        false_digest = "sha256:" + "f" * 64
        metadata = json.loads(args.build_metadata.read_text(encoding="utf-8"))
        metadata["containerimage.digest"] = false_digest
        metadata["containerimage.descriptor"]["digest"] = false_digest
        write_json(args.build_metadata, metadata)
        contract = json.loads(args.artifact_contract.read_text(encoding="utf-8"))
        contract["descriptor_digest"] = false_digest
        contract["image_digest"] = false_digest
        write_json(args.artifact_contract, contract)

        with self.assertRaisesRegex(
            SMOKE.SmokeError,
            "OCI manifest digest does not match the artifact contract",
        ):
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

    def test_controller_pki_uses_distinct_constrained_ca_and_server_leaf(
        self,
    ) -> None:
        args = self.release_args()
        artifact = SMOKE.validate_release_artifact(args)
        runner = RecordingCommandRunner()
        smoke = SMOKE.DockerSmoke(runner, artifact, args, {"checks": []})
        self.addCleanup(smoke.cleanup)
        leaf_cert, leaf_key, ca_cert = smoke.generate_controller_pki(
            self.root / "controller-pki",
            "host.docker.internal",
        )

        ca_text = runner.run(
            ["openssl", "x509", "-in", str(ca_cert), "-noout", "-text"],
            timeout=10,
        ).stdout
        leaf_text = runner.run(
            ["openssl", "x509", "-in", str(leaf_cert), "-noout", "-text"],
            timeout=10,
        ).stdout
        verified = runner.run(
            [
                "openssl",
                "verify",
                "-CAfile",
                str(ca_cert),
                "-verify_hostname",
                "host.docker.internal",
                "-purpose",
                "sslserver",
                str(leaf_cert),
            ],
            timeout=10,
        )

        self.assertIn("CA:TRUE, pathlen:0", ca_text)
        self.assertIn("Certificate Sign", ca_text)
        self.assertIn("CA:FALSE", leaf_text)
        self.assertIn("TLS Web Server Authentication", leaf_text)
        self.assertIn("DNS:host.docker.internal", leaf_text)
        self.assertEqual(verified.stdout.strip(), f"{leaf_cert}: OK")
        self.assertEqual(leaf_key.stat().st_mode & 0o777, 0o400)
        self.assertEqual(leaf_cert.stat().st_mode & 0o777, 0o444)
        self.assertEqual(ca_cert.stat().st_mode & 0o777, 0o444)
        self.assertFalse((leaf_cert.parent / "ca-key.pem").exists())
        self.assertFalse((leaf_cert.parent / "server.csr").exists())
        signing = next(
            call for call in runner.calls if call[:3] == ["openssl", "x509", "-req"]
        )
        self.assertIn("-copy_extensions", signing)
        self.assertEqual(signing[signing.index("-copy_extensions") + 1], "copy")

    def test_keysigner_seed_keeps_narrow_caps_and_bounded_failure_detail(
        self,
    ) -> None:
        args = self.release_args()
        artifact = SMOKE.validate_release_artifact(args)
        runner = FakeKeysignerSeedRunner()
        smoke = SMOKE.DockerSmoke(runner, artifact, args, {"checks": []})
        try:
            with self.assertRaises(SMOKE.SmokeError) as raised:
                smoke.run_keysigner_role()
            message = str(raised.exception)
            self.assertIn("with code 1", message)
            self.assertIn("bounded-tail", message)
            self.assertNotIn("discarded-prefix", message)
            self.assertLessEqual(len(message), 4200)

            create = next(
                call for call in runner.calls if call[:2] == ["docker", "create"]
            )
            self.assertEqual(
                create[create.index("-c") + 1],
                (
                    "chown 0:0 /cert/privkey.pem "
                    "/cert/keysigner-token.b64 && "
                    "chmod 0550 /cert && "
                    "chmod 0400 /cert/privkey.pem /cert/keysigner-token.b64 && "
                    "chown 10002:10002 /cert/privkey.pem "
                    "/cert/keysigner-token.b64 && "
                    "chown 10002:10002 /cert"
                ),
            )
            self.assertIn("--cap-drop", create)
            self.assertEqual(create[create.index("--cap-drop") + 1], "ALL")
            self.assertIn("--cap-add", create)
            self.assertEqual(create[create.index("--cap-add") + 1], "CHOWN")
            self.assertNotIn("FOWNER", create)
            self.assertEqual(smoke.containers, [])
        finally:
            self.assertEqual(smoke.cleanup(), [])

    def test_keysigner_socket_init_sets_mode_before_owner_with_narrow_caps(
        self,
    ) -> None:
        args = self.release_args()
        artifact = SMOKE.validate_release_artifact(args)
        runner = FakeKeysignerSocketInitRunner()
        smoke = SMOKE.DockerSmoke(runner, artifact, args, {"checks": []})
        smoke.runtime_image_id = artifact.manifest_digest
        try:
            with self.assertRaisesRegex(
                SMOKE.SmokeError,
                "docker create did not return a container ID",
            ):
                smoke.run_keysigner_role()

            socket_create = next(
                call
                for call in runner.calls
                if call[:2] == ["docker", "create"]
                and "-c" in call
                and call[call.index("-c") + 1]
                == "chmod 0770 /sock && chown 10002:10002 /sock"
            )
            socket_mounts = [
                socket_create[index + 1]
                for index, value in enumerate(socket_create)
                if value == "--mount"
            ]
            self.assertEqual(len(socket_mounts), 1)
            socket_mount = socket_mounts[0]
            self.assertEqual(
                socket_create,
                [
                    "docker",
                    "create",
                    "--name",
                    socket_create[3],
                    "--label",
                    smoke.label,
                    "--pull",
                    "never",
                    "--network",
                    "none",
                    "--user",
                    "0:0",
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--pids-limit",
                    "64",
                    "--memory",
                    "128m",
                    "--cpus",
                    "1",
                    "--cap-add",
                    "CHOWN",
                    "--mount",
                    socket_mount,
                    "--entrypoint",
                    "/bin/sh",
                    SMOKE.NATIVE_HELPER_IMAGE,
                    "-c",
                    "chmod 0770 /sock && chown 10002:10002 /sock",
                ],
            )
            self.assertRegex(
                socket_mount,
                (
                    r"^type=volume,src=oxibelt-riscv64-smoke-keysigner-socket-"
                    r".+,dst=/sock$"
                ),
            )
            socket_start = runner.calls.index(
                [
                    "docker",
                    "start",
                    "--attach",
                    "keysigner-socket-init",
                ]
            )
            socket_remove = runner.calls.index(
                [
                    "docker",
                    "rm",
                    "--force",
                    "keysigner-socket-init",
                ]
            )
            self.assertLess(runner.calls.index(socket_create), socket_start)
            self.assertLess(socket_start, socket_remove)
            self.assertEqual(smoke.containers, [])
        finally:
            volumes = list(smoke.volumes)
            self.assertEqual(len(volumes), 2)
            self.assertEqual(smoke.cleanup(), [])

        for volume in volumes:
            self.assertIn(["docker", "volume", "rm", volume], runner.calls)
        self.assertEqual(smoke.volumes, [])

    def test_startup_crash_is_retained_for_bounded_diagnostics_and_cleanup(
        self,
    ) -> None:
        args = self.release_args()
        artifact = SMOKE.validate_release_artifact(args)
        runner = FakeCrashRunner()
        receipt = {"checks": []}
        smoke = SMOKE.DockerSmoke(runner, artifact, args, receipt)
        smoke.runtime_image_id = artifact.manifest_digest
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
        smoke.preexisting_image_ids.add(artifact.manifest_digest)
        smoke.runtime_image_id = artifact.manifest_digest

        self.assertEqual(smoke.cleanup(), [])
        self.assertFalse(
            any(call[:3] == ["docker", "image", "rm"] for call in runner.calls)
        )

    def test_load_refuses_to_replace_a_preexisting_archive_tag(self) -> None:
        args = self.release_args()
        artifact = SMOKE.validate_release_artifact(args)
        runner = FakeImageRunner(
            artifact.manifest_digest,
            preexisting_reference_id="sha256:" + "d" * 64,
        )
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
            smoke.cleanup()

    def test_load_uses_containerd_manifest_digest_as_runtime_reference(self) -> None:
        args = self.release_args()
        artifact = SMOKE.validate_release_artifact(args)
        runner = FakeImageRunner(artifact.manifest_digest)
        smoke = SMOKE.DockerSmoke(runner, artifact, args, {"checks": []})
        try:
            smoke.load_and_verify_image()

            self.assertEqual(
                smoke.runtime_image_reference(),
                artifact.manifest_digest,
            )
            self.assertTrue(
                any(
                    call
                    == [
                        "docker",
                        "image",
                        "inspect",
                        "--format",
                        "{{json .}}",
                        "oxibelt:alpine-musl-riscv64",
                    ]
                    for call in runner.calls
                )
            )
        finally:
            smoke.cleanup()

    def test_load_accepts_legacy_config_digest_as_runtime_reference(self) -> None:
        args = self.release_args()
        artifact = SMOKE.validate_release_artifact(args)
        runner = FakeImageRunner(artifact.image_id)
        smoke = SMOKE.DockerSmoke(runner, artifact, args, {"checks": []})
        try:
            smoke.load_and_verify_image()

            self.assertEqual(smoke.runtime_image_reference(), artifact.image_id)
        finally:
            smoke.cleanup()

    def test_load_rejects_unbound_daemon_image_id(self) -> None:
        args = self.release_args()
        artifact = SMOKE.validate_release_artifact(args)
        runner = FakeImageRunner("sha256:" + "d" * 64)
        smoke = SMOKE.DockerSmoke(runner, artifact, args, {"checks": []})
        try:
            with self.assertRaisesRegex(
                SMOKE.SmokeError,
                "identity or architecture",
            ):
                smoke.load_and_verify_image()
        finally:
            self.assertEqual(smoke.cleanup(), [])
        self.assertTrue(
            any(
                call[:4]
                == [
                    "docker",
                    "image",
                    "rm",
                    "oxibelt:alpine-musl-riscv64",
                ]
                for call in runner.calls
            )
        )

    def test_partial_load_failure_cleans_absent_archive_tag(self) -> None:
        args = self.release_args()
        artifact = SMOKE.validate_release_artifact(args)
        runner = FakeImageRunner(artifact.manifest_digest, fail_load=True)
        smoke = SMOKE.DockerSmoke(runner, artifact, args, {"checks": []})
        try:
            with self.assertRaisesRegex(
                SMOKE.SmokeError,
                "partial Docker load failure",
            ):
                smoke.load_and_verify_image()
        finally:
            self.assertEqual(smoke.cleanup(), [])

        self.assertTrue(
            any(
                call[:4]
                == [
                    "docker",
                    "image",
                    "rm",
                    "oxibelt:alpine-musl-riscv64",
                ]
                for call in runner.calls
            )
        )

    def test_load_refuses_preexisting_manifest_bound_archive_tag(self) -> None:
        args = self.release_args()
        artifact = SMOKE.validate_release_artifact(args)
        runner = FakeImageRunner(
            artifact.manifest_digest,
            preexisting_reference_id=artifact.manifest_digest,
        )
        smoke = SMOKE.DockerSmoke(runner, artifact, args, {"checks": []})
        try:
            with self.assertRaisesRegex(
                SMOKE.SmokeError,
                "refusing to replace preexisting Docker image reference",
            ):
                smoke.load_and_verify_image()
        finally:
            self.assertEqual(smoke.cleanup(), [])

        self.assertFalse(any(call[:2] == ["docker", "load"] for call in runner.calls))
        self.assertFalse(
            any(call[:3] == ["docker", "image", "rm"] for call in runner.calls)
        )

    def test_load_refuses_preexisting_config_bound_archive_tag(self) -> None:
        args = self.release_args()
        artifact = SMOKE.validate_release_artifact(args)
        runner = FakeImageRunner(
            artifact.manifest_digest,
            preexisting_reference_id=artifact.image_id,
        )
        smoke = SMOKE.DockerSmoke(runner, artifact, args, {"checks": []})
        try:
            with self.assertRaisesRegex(
                SMOKE.SmokeError,
                "refusing to replace preexisting Docker image reference",
            ):
                smoke.load_and_verify_image()
        finally:
            self.assertEqual(smoke.cleanup(), [])

        self.assertFalse(any(call[:2] == ["docker", "load"] for call in runner.calls))
        self.assertFalse(
            any(call[:3] == ["docker", "image", "rm"] for call in runner.calls)
        )


if __name__ == "__main__":
    unittest.main()
