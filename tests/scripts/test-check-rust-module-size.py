#!/usr/bin/env python3
"""Regression tests for check-rust-module-size.sh."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).with_name("check-rust-module-size.sh")
UNSET = object()


class RustModuleSizeScriptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(
            prefix="oxibelt-module-size-"
        )
        temporary_root = Path(self.temporary_directory.name)
        temporary_root.chmod(0o755)

        self.repo_root = temporary_root / "repo"
        self.script_path = self.repo_root / "tests/scripts/check-rust-module-size.sh"
        self.script_path.parent.mkdir(parents=True)
        shutil.copy2(SCRIPT_PATH, self.script_path)

        for relative_root in ("source/src", "source/apps", "source/crates"):
            (self.repo_root / relative_root).mkdir(parents=True)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def write_rust_file(self, relative_path: str, line_count: int) -> Path:
        path = self.repo_root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fn checked() {}\n" * line_count, encoding="utf-8")
        return path

    def run_checker(
        self,
        *arguments: str,
        line_limit: object = UNSET,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.pop("OXIBELT_RUST_SOURCE_LINE_LIMIT", None)
        if line_limit is not UNSET:
            environment["OXIBELT_RUST_SOURCE_LINE_LIMIT"] = str(line_limit)

        return subprocess.run(
            ["bash", str(self.script_path), *arguments],
            cwd=self.repo_root,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_default_mode_warns_without_failing(self) -> None:
        self.write_rust_file("source/src/oversized.rs", 4)

        result = self.run_checker(line_limit="3")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("oversized.rs: 4 lines (target 3)", result.stderr)
        self.assertIn("continuing in --warn mode", result.stderr)

    def test_explicit_warn_mode_warns_without_failing(self) -> None:
        self.write_rust_file("source/apps/oversized.rs", 2)

        result = self.run_checker("--warn", line_limit="1")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Rust module size advisory", result.stderr)

    def test_enforce_mode_fails_on_oversized_file(self) -> None:
        self.write_rust_file("source/crates/oversized.rs", 3)

        result = self.run_checker("--enforce", line_limit="2")

        self.assertEqual(result.returncode, 1)
        self.assertIn("oversized.rs: 3 lines (target 2)", result.stderr)
        self.assertIn("Split oversized Rust files", result.stderr)

    def test_file_at_limit_passes(self) -> None:
        self.write_rust_file("source/src/at-limit.rs", 3)

        result = self.run_checker("--enforce", line_limit="3")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "Rust module size check passed for 1 files (limit: 3 lines).",
            result.stdout,
        )

    def test_invalid_arguments_fail_closed(self) -> None:
        self.write_rust_file("source/src/valid.rs", 1)

        for arguments in (("--unknown",), ("--warn", "--enforce")):
            with self.subTest(arguments=arguments):
                result = self.run_checker(*arguments)
                self.assertEqual(result.returncode, 2)
                self.assertIn("Usage:", result.stderr)

    def test_invalid_limits_fail_closed(self) -> None:
        self.write_rust_file("source/src/valid.rs", 1)

        for line_limit in ("", "0", "-1", "1.5", "not-a-number"):
            with self.subTest(line_limit=line_limit):
                result = self.run_checker(line_limit=line_limit)
                self.assertEqual(result.returncode, 2)
                self.assertIn("must be a positive base-10 integer", result.stderr)

    def test_missing_source_root_fails_closed(self) -> None:
        self.write_rust_file("source/src/valid.rs", 1)
        shutil.rmtree(self.repo_root / "source/crates")

        result = self.run_checker()

        self.assertEqual(result.returncode, 1)
        self.assertIn("required Rust source root is missing", result.stderr)

    def test_unreadable_source_file_fails_closed(self) -> None:
        source_file = self.write_rust_file("source/src/unreadable.rs", 1)
        source_file.chmod(0)
        try:
            result = self.run_checker()
        finally:
            source_file.chmod(0o644)

        self.assertEqual(result.returncode, 1)
        self.assertIn("Rust source file is not readable", result.stderr)

    def test_zero_source_files_fails_closed(self) -> None:
        result = self.run_checker()

        self.assertEqual(result.returncode, 1)
        self.assertIn("no Rust source files were found", result.stderr)


if __name__ == "__main__":
    unittest.main()
