#!/usr/bin/env python3
"""Compile and validate OxiBelt's production Cargo package boundaries."""

from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn, Sequence


MAXIMUM_CARGO_OUTPUT_BYTES = 16 * 1024 * 1024
PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.+-]*$")
VERSION_RE = re.compile(r"^[^()\s|]+$")
FEATURE_RE = re.compile(r"^[A-Za-z0-9_+.-]+$")
WINDOWS_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]")


class BoundaryError(ValueError):
    """A malformed graph or architecture-policy violation."""


@dataclass(frozen=True)
class GraphPolicy:
    label: str
    package: str
    feature_arguments: tuple[str, ...]
    allowed_workspace_packages: frozenset[str]
    expected_features: tuple[tuple[str, frozenset[str]], ...]
    forbidden_packages: frozenset[str] = frozenset()
    forbidden_package_prefixes: tuple[str, ...] = ()


@dataclass(frozen=True)
class GraphSummary:
    packages: int
    workspace_packages: int


@dataclass(frozen=True)
class ParsedCargoTree:
    features_by_package: dict[str, frozenset[str]]
    local_packages: frozenset[str]


RUNTIME_WORKSPACE_PACKAGES = frozenset(
    {
        "oxibelt",
        "oxibelt-build-identity",
        "oxibelt-control-protocol",
    }
)
STRICT_WORKSPACE_PACKAGES = RUNTIME_WORKSPACE_PACKAGES | {
    "oxibelt-dataplane-strict"
}
KEYSIGNER_WORKSPACE_PACKAGES = RUNTIME_WORKSPACE_PACKAGES | {
    "oxibelt-keysigner"
}
NETPORT_WORKSPACE_PACKAGES = RUNTIME_WORKSPACE_PACKAGES | {
    "oxibelt-netport-switcher"
}
CONTROLLER_WORKSPACE_PACKAGES = frozenset(
    {
        "oxibelt-build-identity",
        "oxibelt-control-http",
        "oxibelt-control-protocol",
        "oxibelt-gateway-controller",
    }
)
TOOLS_WORKSPACE_PACKAGES = RUNTIME_WORKSPACE_PACKAGES | {
    "oxibelt-deployment-diagnostics",
    "oxibeltctl",
}
DIAGNOSTICS_WORKSPACE_PACKAGES = RUNTIME_WORKSPACE_PACKAGES | {
    "oxibelt-deployment-diagnostics"
}
KUBERNETES_PACKAGES = frozenset({"k8s-openapi", "kube"})
DATA_PLANE_FORBIDDEN_PACKAGES = KUBERNETES_PACKAGES | {"sequoia-openpgp"}
DATA_PLANE_FORBIDDEN_PREFIXES = ("k8s-", "kube-")
STRICT_FORBIDDEN_PACKAGES = DATA_PLANE_FORBIDDEN_PACKAGES | {"jsonschema"}
STRICT_FORBIDDEN_PREFIXES = DATA_PLANE_FORBIDDEN_PREFIXES + ("jsonschema-",)

POLICIES = (
    GraphPolicy(
        label="compatibility data plane (default features)",
        package="oxibelt",
        feature_arguments=(),
        allowed_workspace_packages=RUNTIME_WORKSPACE_PACKAGES,
        expected_features=(
            ("oxibelt", frozenset({"admin-runtime", "default"})),
        ),
        forbidden_packages=DATA_PLANE_FORBIDDEN_PACKAGES,
        forbidden_package_prefixes=DATA_PLANE_FORBIDDEN_PREFIXES,
    ),
    GraphPolicy(
        label="compatibility data plane (all features)",
        package="oxibelt",
        feature_arguments=("--all-features",),
        allowed_workspace_packages=RUNTIME_WORKSPACE_PACKAGES,
        expected_features=(
            (
                "oxibelt",
                frozenset(
                    {
                        "admin-runtime",
                        "config-tooling",
                        "crypto-ring",
                        "default",
                        "fuzzing",
                        "mutation-pqc",
                    }
                ),
            ),
        ),
        forbidden_packages=DATA_PLANE_FORBIDDEN_PACKAGES,
        forbidden_package_prefixes=DATA_PLANE_FORBIDDEN_PREFIXES,
    ),
    GraphPolicy(
        label="strict data plane",
        package="oxibelt-dataplane-strict",
        feature_arguments=("--no-default-features",),
        allowed_workspace_packages=STRICT_WORKSPACE_PACKAGES,
        expected_features=(
            ("oxibelt-dataplane-strict", frozenset()),
            ("oxibelt", frozenset()),
        ),
        forbidden_packages=STRICT_FORBIDDEN_PACKAGES,
        forbidden_package_prefixes=STRICT_FORBIDDEN_PREFIXES,
    ),
    GraphPolicy(
        label="key signer",
        package="oxibelt-keysigner",
        feature_arguments=("--no-default-features",),
        allowed_workspace_packages=KEYSIGNER_WORKSPACE_PACKAGES,
        expected_features=(
            ("oxibelt-keysigner", frozenset()),
            ("oxibelt", frozenset()),
        ),
        forbidden_packages=STRICT_FORBIDDEN_PACKAGES,
        forbidden_package_prefixes=STRICT_FORBIDDEN_PREFIXES,
    ),
    GraphPolicy(
        label="netport switcher",
        package="oxibelt-netport-switcher",
        feature_arguments=("--no-default-features",),
        allowed_workspace_packages=NETPORT_WORKSPACE_PACKAGES,
        expected_features=(
            ("oxibelt-netport-switcher", frozenset()),
            ("oxibelt", frozenset()),
        ),
        forbidden_packages=STRICT_FORBIDDEN_PACKAGES,
        forbidden_package_prefixes=STRICT_FORBIDDEN_PREFIXES,
    ),
    GraphPolicy(
        label="Gateway Controller",
        package="oxibelt-gateway-controller",
        feature_arguments=("--no-default-features",),
        allowed_workspace_packages=CONTROLLER_WORKSPACE_PACKAGES,
        expected_features=(
            ("oxibelt-gateway-controller", frozenset()),
        ),
    ),
    GraphPolicy(
        label="operator tools",
        package="oxibeltctl",
        feature_arguments=("--no-default-features",),
        allowed_workspace_packages=TOOLS_WORKSPACE_PACKAGES,
        expected_features=(
            ("oxibeltctl", frozenset()),
            ("oxibelt", frozenset({"admin-runtime", "config-tooling"})),
        ),
    ),
    GraphPolicy(
        label="deployment diagnostics",
        package="oxibelt-deployment-diagnostics",
        feature_arguments=("--no-default-features",),
        allowed_workspace_packages=DIAGNOSTICS_WORKSPACE_PACKAGES,
        expected_features=(
            ("oxibelt-deployment-diagnostics", frozenset()),
            ("oxibelt", frozenset()),
        ),
    ),
)
POLICY_BY_LABEL = {policy.label: policy for policy in POLICIES}

COMPILE_COMMANDS = (
    (
        "compatibility data plane",
        (
            "cargo",
            "check",
            "-p",
            "oxibelt",
            "--lib",
            "--bin",
            "oxibelt",
            "--locked",
        ),
    ),
    (
        "compatibility package contract",
        (
            "cargo",
            "test",
            "-p",
            "oxibelt",
            "--test",
            "package_boundaries",
            "--locked",
        ),
    ),
    (
        "all-feature compatibility data plane",
        (
            "cargo",
            "check",
            "-p",
            "oxibelt",
            "--lib",
            "--bin",
            "oxibelt",
            "--locked",
            "--all-features",
        ),
    ),
    (
        "all-feature package contract",
        (
            "cargo",
            "test",
            "-p",
            "oxibelt",
            "--test",
            "package_boundaries",
            "--locked",
            "--all-features",
        ),
    ),
    (
        "strict data plane",
        (
            "cargo",
            "check",
            "-p",
            "oxibelt-dataplane-strict",
            "--bin",
            "oxibelt-dataplane-strict",
            "--locked",
            "--no-default-features",
        ),
    ),
    (
        "key signer",
        (
            "cargo",
            "check",
            "-p",
            "oxibelt-keysigner",
            "--bin",
            "oxibelt-keysigner",
            "--locked",
            "--no-default-features",
        ),
    ),
    (
        "netport switcher",
        (
            "cargo",
            "check",
            "-p",
            "oxibelt-netport-switcher",
            "--bin",
            "oxibelt-netport-switcher",
            "--locked",
            "--no-default-features",
        ),
    ),
    (
        "Gateway Controller",
        (
            "cargo",
            "check",
            "-p",
            "oxibelt-gateway-controller",
            "--bin",
            "oxibelt-gateway-controller",
            "--locked",
            "--no-default-features",
        ),
    ),
    (
        "operator tools",
        (
            "cargo",
            "check",
            "-p",
            "oxibeltctl",
            "--bin",
            "oxibeltctl",
            "--locked",
            "--no-default-features",
        ),
    ),
    (
        "deployment diagnostics",
        (
            "cargo",
            "check",
            "-p",
            "oxibelt-deployment-diagnostics",
            "--lib",
            "--locked",
            "--no-default-features",
        ),
    ),
)


def _fail(message: str) -> NoReturn:
    raise BoundaryError(message)


def _bounded_output(output: str, label: str) -> str:
    size = len(output.encode("utf-8"))
    if size > MAXIMUM_CARGO_OUTPUT_BYTES:
        _fail(
            f"{label} output is {size} bytes and exceeds "
            f"{MAXIMUM_CARGO_OUTPUT_BYTES} bytes"
        )
    return output


def _is_local_source(source: str) -> bool:
    return source.startswith(
        ("/", "\\\\", "./", "../", "file://", "path+file://")
    ) or WINDOWS_PATH_RE.match(source) is not None


def _parse_cargo_tree(output: str) -> ParsedCargoTree:
    """Parse package features and local sources from Cargo tree output."""

    _bounded_output(output, "cargo tree")
    packages: dict[str, set[str]] = {}
    local_packages: set[str] = set()
    for line_number, raw_line in enumerate(output.splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        if line.endswith(" (*)"):
            line = line[:-4]
        if line.count("|") != 1:
            _fail(
                f"cargo tree line {line_number} must contain exactly one "
                f"package/features separator: {raw_line!r}"
            )
        descriptor, feature_text = line.split("|", 1)
        if " v" not in descriptor:
            _fail(
                f"cargo tree line {line_number} lacks a package version: "
                f"{raw_line!r}"
            )
        package, version_and_source = descriptor.split(" v", 1)
        if not PACKAGE_NAME_RE.fullmatch(package):
            _fail(
                f"cargo tree line {line_number} has an invalid package name: "
                f"{package!r}"
            )
        version, separator, source_annotation = version_and_source.partition(" ")
        if not VERSION_RE.fullmatch(version):
            _fail(
                f"cargo tree line {line_number} has an invalid package version: "
                f"{version!r}"
            )
        if separator:
            source_annotation = source_annotation.strip()
            if (
                len(source_annotation) < 3
                or not source_annotation.startswith("(")
                or not source_annotation.endswith(")")
            ):
                _fail(
                    f"cargo tree line {line_number} has an invalid package "
                    f"source: {source_annotation!r}"
                )
            source = source_annotation[1:-1]
            if _is_local_source(source):
                local_packages.add(package)

        features: set[str] = set()
        if feature_text:
            feature_values = feature_text.split(",")
            if any(not FEATURE_RE.fullmatch(feature) for feature in feature_values):
                _fail(
                    f"cargo tree line {line_number} has an invalid feature list: "
                    f"{feature_text!r}"
                )
            if len(set(feature_values)) != len(feature_values):
                _fail(
                    f"cargo tree line {line_number} repeats an enabled feature: "
                    f"{feature_text!r}"
                )
            features.update(feature_values)
        packages.setdefault(package, set()).update(features)

    if not packages:
        _fail("cargo tree output did not contain any package nodes")
    return ParsedCargoTree(
        features_by_package={
            package: frozenset(features)
            for package, features in sorted(packages.items())
        },
        local_packages=frozenset(local_packages),
    )


def parse_cargo_tree(output: str) -> dict[str, frozenset[str]]:
    """Parse `cargo tree --prefix none --format {p}|{f}` output."""

    return _parse_cargo_tree(output).features_by_package


def validate_profile_graph(
    policy: GraphPolicy,
    output: str,
    workspace_packages: frozenset[str],
) -> GraphSummary:
    """Validate one resolved production graph against its role policy."""

    parsed_graph = _parse_cargo_tree(output)
    graph = parsed_graph.features_by_package
    violations: list[str] = []
    if policy.package not in graph:
        violations.append(f"root package {policy.package!r} is missing")

    unknown_local = sorted(parsed_graph.local_packages - workspace_packages)
    if unknown_local:
        violations.append(
            "unknown local/path packages: " + ", ".join(unknown_local)
        )

    resolved_workspace = frozenset(graph).intersection(workspace_packages)
    unexpected_workspace = sorted(
        resolved_workspace.difference(policy.allowed_workspace_packages)
    )
    if unexpected_workspace:
        violations.append(
            "unexpected workspace packages: " + ", ".join(unexpected_workspace)
        )

    for package, expected in policy.expected_features:
        actual = graph.get(package)
        if actual is None:
            violations.append(
                f"feature-constrained package {package!r} is missing"
            )
        elif actual != expected:
            violations.append(
                f"{package} features are [{', '.join(sorted(actual))}] but "
                f"must be [{', '.join(sorted(expected))}]"
            )

    forbidden = sorted(set(graph).intersection(policy.forbidden_packages))
    forbidden.extend(
        sorted(
            package
            for package in graph
            if package not in policy.forbidden_packages
            and any(
                package.startswith(prefix)
                for prefix in policy.forbidden_package_prefixes
            )
        )
    )
    if forbidden:
        violations.append(
            "forbidden transitive packages: " + ", ".join(forbidden)
        )

    if violations:
        formatted = "\n  - ".join(violations)
        _fail(f"{policy.label} boundary failed:\n  - {formatted}")
    return GraphSummary(
        packages=len(graph),
        workspace_packages=len(resolved_workspace),
    )


def parse_workspace_metadata(output: str) -> frozenset[str]:
    """Extract the unique workspace package names from Cargo metadata."""

    _bounded_output(output, "cargo metadata")
    try:
        document = json.loads(output)
    except json.JSONDecodeError as error:
        _fail(f"cargo metadata is not valid JSON: {error}")
    if not isinstance(document, dict):
        _fail("cargo metadata root must be an object")
    packages = document.get("packages")
    workspace_members = document.get("workspace_members")
    if not isinstance(packages, list) or not isinstance(workspace_members, list):
        _fail("cargo metadata must contain package and workspace member arrays")

    package_names_by_id: dict[str, str] = {}
    for index, package in enumerate(packages):
        if not isinstance(package, dict):
            _fail(f"cargo metadata package {index} must be an object")
        package_id = package.get("id")
        name = package.get("name")
        if not isinstance(package_id, str) or not isinstance(name, str):
            _fail(f"cargo metadata package {index} needs string id and name")
        package_names_by_id[package_id] = name

    names: list[str] = []
    for index, member in enumerate(workspace_members):
        if not isinstance(member, str):
            _fail(f"cargo metadata workspace member {index} must be a string")
        name = package_names_by_id.get(member)
        if name is None:
            _fail(f"cargo metadata workspace member is unresolved: {member}")
        names.append(name)
    if not names:
        _fail("cargo metadata did not contain workspace packages")
    if len(set(names)) != len(names):
        _fail("Cargo workspace package names must be unique")

    workspace_packages = frozenset(names)
    policy_packages = frozenset(
        package
        for policy in POLICIES
        for package in policy.allowed_workspace_packages
    )
    missing_policy_packages = sorted(policy_packages - workspace_packages)
    if missing_policy_packages:
        _fail(
            "boundary policy references missing workspace packages: "
            + ", ".join(missing_policy_packages)
        )
    return workspace_packages


def cargo_tree_command(policy: GraphPolicy) -> tuple[str, ...]:
    return (
        "cargo",
        "tree",
        "-p",
        policy.package,
        "--locked",
        "--target",
        "all",
        "-e",
        "normal,build",
        "--prefix",
        "none",
        "--format",
        "{p}|{f}",
        *policy.feature_arguments,
    )


def _run(
    command: Sequence[str],
    repo_root: Path,
    *,
    capture_stdout: bool,
) -> str:
    print(f"+ {shlex.join(command)}", flush=True)
    result = subprocess.run(
        list(command),
        cwd=repo_root,
        check=False,
        stdout=subprocess.PIPE if capture_stdout else None,
        text=True,
    )
    if result.returncode != 0:
        _fail(
            f"command exited with status {result.returncode}: "
            f"{shlex.join(command)}"
        )
    return result.stdout if capture_stdout and result.stdout is not None else ""


def validate_repository(repo_root: Path) -> None:
    repo_root = repo_root.resolve()
    if not repo_root.is_dir() or not (repo_root / "Cargo.toml").is_file():
        _fail(f"repository root does not contain Cargo.toml: {repo_root}")

    metadata = _run(
        (
            "cargo",
            "metadata",
            "--locked",
            "--no-deps",
            "--format-version",
            "1",
        ),
        repo_root,
        capture_stdout=True,
    )
    workspace_packages = parse_workspace_metadata(metadata)

    for label, command in COMPILE_COMMANDS:
        _run(command, repo_root, capture_stdout=False)
        print(f"OxiBelt {label} compilation contract passed.")

    for policy in POLICIES:
        graph = _run(
            cargo_tree_command(policy),
            repo_root,
            capture_stdout=True,
        )
        summary = validate_profile_graph(policy, graph, workspace_packages)
        print(
            f"OxiBelt {policy.label} package boundary passed "
            f"({summary.packages} packages; "
            f"{summary.workspace_packages} workspace packages)."
        )


def parse_arguments(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compile and validate OxiBelt Cargo package boundaries."
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="repository root (defaults to the script's repository)",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_arguments(sys.argv[1:] if argv is None else argv)
    try:
        validate_repository(arguments.repo_root)
    except (BoundaryError, OSError) as error:
        print(f"Cargo package boundary check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
