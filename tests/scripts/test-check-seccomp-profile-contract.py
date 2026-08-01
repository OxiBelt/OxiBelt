#!/usr/bin/env python3
"""Regression tests for the checked-in seccomp profile contract validator."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[1]
VALIDATOR = SCRIPT_DIR / "check-seccomp-profile-contract.py"
SOURCE_DIR = REPO_ROOT / "deploy" / "seccomp"


class SeccompProfileContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="oxibelt-seccomp-contract-")
        self.seccomp_dir = Path(self.temp_dir.name) / "seccomp"
        shutil.copytree(SOURCE_DIR, self.seccomp_dir)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def run_validator(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(VALIDATOR), "--seccomp-dir", str(self.seccomp_dir)],
            check=False,
            capture_output=True,
            text=True,
        )

    def update_catalog_digest(self, file_name: str) -> None:
        profile_path = self.seccomp_dir / file_name
        digest = f"sha256:{hashlib.sha256(profile_path.read_bytes()).hexdigest()}"
        catalog_path = self.seccomp_dir / "profile-catalog-v1.json"
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        for entry in catalog["profiles"]:
            if entry["file"] == file_name:
                entry["digest"] = digest
                break
        else:
            self.fail(f"profile is not catalogued: {file_name}")
        catalog_path.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")

    def test_checked_in_contract_passes(self) -> None:
        result = self.run_validator()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_raw_file_digest_mismatch_fails(self) -> None:
        profile_path = self.seccomp_dir / "oxibelt-tokio.json"
        profile_path.write_bytes(profile_path.read_bytes() + b"\n")
        result = self.run_validator()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("raw-file digest mismatch", result.stderr)

    def test_duplicate_syscall_fails_even_with_updated_digest(self) -> None:
        file_name = "oxibelt-tokio.json"
        profile_path = self.seccomp_dir / file_name
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        profile["syscalls"][0]["names"].append(profile["syscalls"][0]["names"][-1])
        profile_path.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
        self.update_catalog_digest(file_name)
        result = self.run_validator()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate syscall names", result.stderr)

    def test_composed_profile_cannot_be_broader_than_its_union(self) -> None:
        file_name = "oxibelt-netport-switcher-tokio.json"
        profile_path = self.seccomp_dir / file_name
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        profile["syscalls"][0]["names"].append("acct")
        profile["syscalls"][0]["names"].sort()
        profile_path.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
        self.update_catalog_digest(file_name)
        result = self.run_validator()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exact union", result.stderr)


if __name__ == "__main__":
    unittest.main()
