#!/usr/bin/env python3
"""Regression tests for check-cargo-package-boundaries.py."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


sys.dont_write_bytecode = True
SCRIPT_PATH = Path(__file__).with_name("check-cargo-package-boundaries.py")
FIXTURE_ROOT = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "cargo-package-boundaries"
)
SPEC = importlib.util.spec_from_file_location(
    "check_cargo_package_boundaries",
    SCRIPT_PATH,
)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)

WORKSPACE_PACKAGES = frozenset(
    package
    for policy in CHECKER.POLICIES
    for package in policy.allowed_workspace_packages
)


def fixture(name: str) -> str:
    return (FIXTURE_ROOT / name).read_text(encoding="utf-8")


def local_identity(name: str, version: str, path: str) -> object:
    return CHECKER.LocalPackageIdentity(name, version, str(Path(path).resolve()))


class CargoPackageBoundaryTests(unittest.TestCase):
    def test_accepts_the_strict_data_plane_graph(self) -> None:
        summary = CHECKER.validate_profile_graph(
            CHECKER.POLICY_BY_LABEL["strict data plane"],
            fixture("allowed-strict.txt"),
            WORKSPACE_PACKAGES,
        )
        self.assertEqual(summary.packages, 5)
        self.assertEqual(summary.workspace_packages, 4)

    def test_rejects_a_transitive_control_plane_workspace_package(self) -> None:
        with self.assertRaisesRegex(
            CHECKER.BoundaryError,
            "unexpected workspace packages: oxibelt-gateway-controller",
        ):
            CHECKER.validate_profile_graph(
                CHECKER.POLICY_BY_LABEL["strict data plane"],
                fixture("forbidden-control-plane.txt"),
                WORKSPACE_PACKAGES,
            )

    def test_rejects_an_unknown_local_path_package(self) -> None:
        with self.assertRaisesRegex(
            CHECKER.BoundaryError,
            "unknown local/path packages: unregistered-local-helper",
        ):
            CHECKER.validate_profile_graph(
                CHECKER.POLICY_BY_LABEL["strict data plane"],
                fixture("forbidden-unknown-local.txt"),
                WORKSPACE_PACKAGES,
            )

    def test_reviewed_vendored_identities_require_exact_name_version_and_path(
        self,
    ) -> None:
        policy = CHECKER.POLICY_BY_LABEL["strict data plane"]
        reviewed = frozenset(
            {
                local_identity("h2", "0.4.19", "/workspace/source/third_party/h2"),
                local_identity(
                    "hyper", "1.11.1", "/workspace/source/third_party/hyper"
                ),
            }
        )
        graph = (
            f"{fixture('allowed-strict.txt')}"
            "h2 v0.4.19 (/workspace/source/third_party/h2)|\n"
            "hyper v1.11.1 (/workspace/source/third_party/hyper)|http2\n"
        )
        summary = CHECKER.validate_profile_graph(
            policy,
            graph,
            WORKSPACE_PACKAGES,
            reviewed,
        )
        self.assertEqual(summary.packages, 7)
        self.assertEqual(summary.workspace_packages, 4)

        uri_graph = (
            f"{fixture('allowed-strict.txt')}"
            "h2 v0.4.19 (file:///workspace/source/third_party/h2)|\n"
            "hyper v1.11.1 (path+file:///workspace/source/third_party/hyper)|http2\n"
        )
        self.assertEqual(
            CHECKER.validate_profile_graph(
                policy,
                uri_graph,
                WORKSPACE_PACKAGES,
                reviewed,
            ),
            summary,
        )

        for package in [
            "h2 v0.4.20 (/workspace/source/third_party/h2)|",
            "h2 v0.4.19 (/workspace/source/third_party/h2-unreviewed)|",
        ]:
            with self.subTest(package=package):
                with self.assertRaisesRegex(
                    CHECKER.BoundaryError,
                    r"unknown local/path packages: h2 v0\.4",
                ):
                    CHECKER.validate_profile_graph(
                        policy,
                        f"{fixture('allowed-strict.txt')}{package}\n",
                        WORKSPACE_PACKAGES,
                        reviewed,
                    )

        mixed_graph = (
            f"{fixture('allowed-strict.txt')}"
            "h2 v0.4.19 (/workspace/source/third_party/h2)|\n"
            "h2 v0.4.19 (/workspace/source/third_party/h2-unreviewed)|\n"
        )
        with self.assertRaisesRegex(
            CHECKER.BoundaryError,
            r"unknown local/path packages: h2 v0\.4\.19 "
            r"\(/workspace/source/third_party/h2-unreviewed\)",
        ):
            CHECKER.validate_profile_graph(
                policy,
                mixed_graph,
                WORKSPACE_PACKAGES,
                reviewed,
            )

    def test_vendored_source_inventory_is_strict_and_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repo_root = Path(temporary_directory)

            def write_policy(sources: object) -> None:
                policy_path = repo_root / "supply-chain/dependency-policy.json"
                policy_path.parent.mkdir(exist_ok=True)
                policy_path.write_text(
                    json.dumps({"rust": {"vendoredRustSources": sources}}),
                    encoding="utf-8",
                )

            def create_vendor(path: str) -> None:
                vendor = repo_root / path
                vendor.mkdir(parents=True, exist_ok=True)
                (vendor / "Cargo.toml").touch()

            create_vendor("vendor/h2")
            create_vendor("vendor/hyper")
            valid_sources = [
                {"name": "h2", "version": "0.4.19", "path": "vendor/h2"},
                {"name": "hyper", "version": "1.11.1", "path": "vendor/hyper"},
            ]
            write_policy(valid_sources)
            self.assertEqual(
                CHECKER.load_reviewed_vendored_rust_sources(repo_root),
                frozenset(
                    {
                        local_identity("h2", "0.4.19", str(repo_root / "vendor/h2")),
                        local_identity(
                            "hyper", "1.11.1", str(repo_root / "vendor/hyper")
                        ),
                    }
                ),
            )

            cases = [
                ("not-a-list", "source array"),
                (
                    [
                        {
                            "name": "h2",
                            "version": "0.4.19",
                            "path": "../outside",
                        }
                    ],
                    "normalized repository-relative path",
                ),
                (
                    [
                        valid_sources[0],
                        {
                            "name": "h2",
                            "version": "0.4.19",
                            "path": "vendor/hyper",
                        },
                    ],
                    "repeats a package identity",
                ),
            ]
            for sources, expected in cases:
                with self.subTest(sources=sources):
                    write_policy(sources)
                    with self.assertRaisesRegex(CHECKER.BoundaryError, expected):
                        CHECKER.load_reviewed_vendored_rust_sources(repo_root)

    def test_vendored_source_inventory_rejects_resolved_path_aliases_and_escapes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            repo_root = temporary_root / "repo"
            repo_root.mkdir()
            policy_path = repo_root / "supply-chain/dependency-policy.json"
            policy_path.parent.mkdir()
            vendor = repo_root / "vendor/h2"
            vendor.mkdir(parents=True)
            (vendor / "Cargo.toml").touch()

            alias = repo_root / "vendor/h2-alias"
            escaped_vendor = temporary_root / "outside"
            escaped_vendor.mkdir()
            (escaped_vendor / "Cargo.toml").touch()
            try:
                alias.symlink_to("h2", target_is_directory=True)
                (repo_root / "vendor/escape").symlink_to(
                    escaped_vendor,
                    target_is_directory=True,
                )
            except OSError as error:
                self.skipTest(f"symlink creation is unavailable: {error}")

            policy_path.write_text(
                json.dumps(
                    {
                        "rust": {
                            "vendoredRustSources": [
                                {
                                    "name": "h2",
                                    "version": "0.4.19",
                                    "path": "vendor/h2",
                                },
                                {
                                    "name": "hyper",
                                    "version": "1.11.1",
                                    "path": "vendor/h2-alias",
                                },
                            ]
                        }
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                CHECKER.BoundaryError,
                "repeats a canonical path",
            ):
                CHECKER.load_reviewed_vendored_rust_sources(repo_root)

            policy_path.write_text(
                json.dumps(
                    {
                        "rust": {
                            "vendoredRustSources": [
                                {
                                    "name": "h2",
                                    "version": "0.4.19",
                                    "path": "vendor/escape",
                                }
                            ]
                        }
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                CHECKER.BoundaryError,
                "escapes the repository",
            ):
                CHECKER.load_reviewed_vendored_rust_sources(repo_root)

    def test_repository_vendor_inventory_matches_the_resolved_patch_identities(
        self,
    ) -> None:
        repo_root = SCRIPT_PATH.parents[2]
        self.assertEqual(
            CHECKER.load_reviewed_vendored_rust_sources(repo_root),
            frozenset(
                {
                    local_identity(
                        "h2", "0.4.19", str(repo_root / "source/third_party/h2")
                    ),
                    local_identity(
                        "hyper",
                        "1.11.1",
                        str(repo_root / "source/third_party/hyper"),
                    ),
                }
            ),
        )

    def test_rejects_default_and_admin_feature_leakage(self) -> None:
        with self.assertRaisesRegex(
            CHECKER.BoundaryError,
            r"oxibelt features are \[admin-runtime, default\] but must be \[\]",
        ):
            CHECKER.validate_profile_graph(
                CHECKER.POLICY_BY_LABEL["strict data plane"],
                fixture("forbidden-feature-leak.txt"),
                WORKSPACE_PACKAGES,
            )

    def test_compatibility_data_plane_policies_allow_the_allocator(self) -> None:
        expected_features = {
            "compatibility data plane (default features)": frozenset(
                {
                    "admin-runtime",
                    "allocator-mimalloc-experiment",
                    "default",
                }
            ),
            "compatibility data plane (all features)": frozenset(
                {
                    "admin-runtime",
                    "allocator-mimalloc-experiment",
                    "config-tooling",
                    "crypto-ring",
                    "default",
                    "fuzzing",
                    "mutation-pqc",
                }
            ),
        }
        allocator = (
            "oxibelt-allocator v0.0.0 "
            "(file:///workspace/source/crates/oxibelt-allocator)|native-mimalloc\n"
        )

        for label, features in expected_features.items():
            with self.subTest(policy=label):
                policy = CHECKER.POLICY_BY_LABEL[label]
                self.assertEqual(
                    policy.allowed_workspace_packages,
                    CHECKER.RUNTIME_WORKSPACE_PACKAGES | {"oxibelt-allocator"},
                )
                self.assertEqual(dict(policy.expected_features)["oxibelt"], features)
                graph = (
                    "oxibelt v0.0.0 (file:///workspace/source)|"
                    f"{','.join(sorted(features))}\n{allocator}"
                )
                summary = CHECKER.validate_profile_graph(
                    policy,
                    graph,
                    WORKSPACE_PACKAGES,
                )
                self.assertEqual(summary.workspace_packages, 2)

    def test_strict_data_plane_rejects_the_allocator_workspace_package(self) -> None:
        graph = (
            "oxibelt-dataplane-strict v0.0.0 "
            "(file:///workspace/source/apps/oxibelt-dataplane-strict)|\n"
            "oxibelt v0.0.0 (file:///workspace/source)|\n"
            "oxibelt-allocator v0.0.0 "
            "(file:///workspace/source/crates/oxibelt-allocator)|native-mimalloc\n"
        )
        with self.assertRaisesRegex(
            CHECKER.BoundaryError,
            "unexpected workspace packages: oxibelt-allocator",
        ):
            CHECKER.validate_profile_graph(
                CHECKER.POLICY_BY_LABEL["strict data plane"],
                graph,
                WORKSPACE_PACKAGES,
            )

    def test_rejects_runtime_code_in_the_controller_production_graph(self) -> None:
        with self.assertRaisesRegex(
            CHECKER.BoundaryError,
            "unexpected workspace packages: oxibelt",
        ):
            CHECKER.validate_profile_graph(
                CHECKER.POLICY_BY_LABEL["Gateway Controller"],
                fixture("forbidden-controller-runtime.txt"),
                WORKSPACE_PACKAGES,
            )

    def test_rejects_empty_and_malformed_graphs(self) -> None:
        for fixture_name, expected in [
            ("empty.txt", "did not contain any package nodes"),
            ("malformed.txt", "separator"),
        ]:
            with self.subTest(fixture=fixture_name):
                with self.assertRaisesRegex(CHECKER.BoundaryError, expected):
                    CHECKER.validate_profile_graph(
                        CHECKER.POLICY_BY_LABEL["strict data plane"],
                        fixture(fixture_name),
                        WORKSPACE_PACKAGES,
                    )

    def test_rejects_target_specific_kubernetes_and_config_tooling_packages(
        self,
    ) -> None:
        base = fixture("allowed-strict.txt")
        for package in ["kube-client", "jsonschema-value"]:
            with self.subTest(package=package):
                graph = f"{base}{package} v1.0.0|default\n"
                with self.assertRaisesRegex(
                    CHECKER.BoundaryError,
                    f"forbidden transitive packages: {package}",
                ):
                    CHECKER.validate_profile_graph(
                        CHECKER.POLICY_BY_LABEL["strict data plane"],
                        graph,
                        WORKSPACE_PACKAGES,
                    )

    def test_every_graph_command_is_target_complete_and_excludes_dev_edges(
        self,
    ) -> None:
        for policy in CHECKER.POLICIES:
            with self.subTest(policy=policy.label):
                command = CHECKER.cargo_tree_command(policy)
                self.assertIn("--locked", command)
                self.assertEqual(
                    command[command.index("--target") + 1],
                    "all",
                )
                self.assertEqual(
                    command[command.index("-e") + 1],
                    "normal,build",
                )
                self.assertNotIn("dev", command)

    def test_every_graph_command_disables_color_for_machine_parsing(
        self,
    ) -> None:
        for policy in CHECKER.POLICIES:
            with self.subTest(policy=policy.label):
                command = CHECKER.cargo_tree_command(policy)
                self.assertEqual(command.count("--color"), 1)
                self.assertEqual(
                    command[command.index("--color") + 1],
                    "never",
                )

    def test_operator_tools_commands_enable_only_the_cli_feature(self) -> None:
        policy = CHECKER.POLICY_BY_LABEL["operator tools"]
        self.assertEqual(
            policy.feature_arguments,
            ("--no-default-features", "--features", "cli"),
        )
        self.assertEqual(
            dict(policy.expected_features),
            {
                "oxibeltctl": frozenset({"cli"}),
                "oxibelt": frozenset({"admin-runtime", "config-tooling"}),
            },
        )

        compile_command = dict(CHECKER.COMPILE_COMMANDS)["operator tools"]
        self.assertIn("--bin", compile_command)
        self.assertEqual(
            compile_command[compile_command.index("--bin") + 1],
            "oxibeltctl",
        )
        self.assertEqual(compile_command.count("--no-default-features"), 1)
        self.assertNotIn("--all-features", compile_command)
        self.assertEqual(compile_command.count("--features"), 1)
        self.assertEqual(
            compile_command[compile_command.index("--features") + 1],
            "cli",
        )

    def test_operator_tools_graph_rejects_missing_or_extra_features(self) -> None:
        policy = CHECKER.POLICY_BY_LABEL["operator tools"]
        runtime = (
            "oxibelt v0.0.0 (file:///workspace/source)|"
            "admin-runtime,config-tooling\n"
        )
        allowed_graph = (
            "oxibeltctl v0.0.0 "
            "(file:///workspace/source/apps/oxibeltctl)|cli\n"
            f"{runtime}"
        )
        summary = CHECKER.validate_profile_graph(
            policy,
            allowed_graph,
            WORKSPACE_PACKAGES,
        )
        self.assertEqual(summary.workspace_packages, 2)

        for features in ["", "default,cli", "fuzzing", "cli,fuzzing"]:
            with self.subTest(features=features):
                graph = (
                    "oxibeltctl v0.0.0 "
                    "(file:///workspace/source/apps/oxibeltctl)|"
                    f"{features}\n{runtime}"
                )
                with self.assertRaisesRegex(
                    CHECKER.BoundaryError,
                    "oxibeltctl features are",
                ):
                    CHECKER.validate_profile_graph(
                        policy,
                        graph,
                        WORKSPACE_PACKAGES,
                    )

    def test_workspace_metadata_is_structured_and_complete(self) -> None:
        packages = [
            {"id": f"path+file:///workspace/{name}#0.0.0", "name": name}
            for name in sorted(WORKSPACE_PACKAGES)
        ]
        metadata = json.dumps(
            {
                "packages": packages,
                "workspace_members": [package["id"] for package in packages],
            }
        )
        self.assertEqual(
            CHECKER.parse_workspace_metadata(metadata),
            WORKSPACE_PACKAGES,
        )

    def test_workspace_metadata_rejects_an_unresolved_member(self) -> None:
        metadata = json.dumps(
            {
                "packages": [],
                "workspace_members": ["path+file:///workspace/missing#0.0.0"],
            }
        )
        with self.assertRaisesRegex(CHECKER.BoundaryError, "unresolved"):
            CHECKER.parse_workspace_metadata(metadata)


if __name__ == "__main__":
    unittest.main()
