#!/usr/bin/env python3
"""Regression tests for check-cargo-package-boundaries.py."""

from __future__ import annotations

import importlib.util
import json
import sys
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
