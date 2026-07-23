#!/usr/bin/env python3
"""Regression tests for check-markdown-links.py."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


sys.dont_write_bytecode = True
SCRIPT_PATH = Path(__file__).with_name("check-markdown-links.py")
SPEC = importlib.util.spec_from_file_location("check_markdown_links", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)


class MarkdownContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        self.write(
            "source/assets/admin-openapi.json",
            json.dumps(
                {
                    "paths": {
                        "/admin/v1/config/status": {
                            "get": {"operationId": "getConfigStatus"}
                        }
                    },
                    "components": {
                        "schemas": {
                            "AdminCapabilities": {
                                "properties": {
                                    "features": {
                                        "properties": {"config_load": {"type": "boolean"}}
                                    }
                                }
                            }
                        }
                    },
                }
            ),
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def write(self, relative_path: str, content: str, *, track: bool = True) -> Path:
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        if track:
            subprocess.run(
                ["git", "-C", str(self.root), "add", "--", relative_path],
                check=True,
            )
        return path

    def messages(self) -> list[str]:
        return [diagnostic.render() for diagnostic in CHECKER.scan_repository(self.root)]

    def test_validates_links_images_references_anchors_and_source_contracts(self) -> None:
        self.write(
            "docs/target.md",
            "# Target Heading\n\n## Repeat\n\n## Repeat\n\n<a id=\"explicit\"></a>\n",
        )
        self.write("docs/image.svg", "<svg xmlns=\"http://www.w3.org/2000/svg\"/>")
        self.write("docs/space name.md", "# Spaced\n")
        self.write(
            "README.md",
            "\n".join(
                [
                    "[heading](docs/target.md#target-heading)",
                    "[duplicate](docs/target.md#repeat-1)",
                    "[explicit](docs/target.md#explicit)",
                    "![image](docs/image.svg)",
                    "[encoded](docs/space%20name.md#spaced)",
                    "[reference][target]",
                    "[target]: docs/target.md",
                    "[external](https://example.com/not-checked)",
                    "`[inline](missing.md)`",
                    "```text",
                    "[fenced](missing.md)",
                    "features.not_a_real_capability",
                    "GET /admin/v1/missing",
                    "```",
                    "`GET",
                    "/admin/v1/config/status` and `features.config_load`",
                ]
            )
            + "\n",
        )
        self.assertEqual(self.messages(), [])

    def test_rejects_deleted_tracked_target(self) -> None:
        target = self.write("docs/deleted.md", "# Deleted\n")
        self.write("README.md", "[deleted](docs/deleted.md)\n")
        target.unlink()
        self.assertTrue(any("does not exist" in message for message in self.messages()))

    def test_rejects_untracked_target_and_missing_anchor(self) -> None:
        self.write("docs/untracked.md", "# Present\n", track=False)
        self.write(
            "README.md",
            "[untracked](docs/untracked.md)\n[anchor](README.md#absent)\n",
        )
        messages = self.messages()
        self.assertTrue(any("not tracked" in message for message in messages))
        self.assertTrue(any("anchor does not exist" in message for message in messages))

    def test_rejects_repository_traversal(self) -> None:
        self.write("docs/README.md", "[escape](../../outside.md)\n")
        self.assertTrue(any("escapes the repository" in message for message in self.messages()))

    def test_rejects_symlink_escape(self) -> None:
        outside = self.root.parent / f"{self.root.name}-outside.md"
        outside.write_text("# Outside\n", encoding="utf-8")
        try:
            symlink = self.root / "docs/outside.md"
            symlink.parent.mkdir(parents=True, exist_ok=True)
            symlink.symlink_to(outside)
            subprocess.run(
                ["git", "-C", str(self.root), "add", "--", "docs/outside.md"],
                check=True,
            )
            self.write("README.md", "[outside](docs/outside.md)\n")
            self.assertTrue(
                any("escapes the repository" in message for message in self.messages())
            )
        finally:
            outside.unlink(missing_ok=True)

    def test_rejects_stale_admin_operation_and_capability(self) -> None:
        self.write(
            "README.md",
            "`POST /admin/v1/config/status`\n`features.removed_capability`\n",
        )
        messages = self.messages()
        self.assertTrue(any("Admin operation is absent" in message for message in messages))
        self.assertTrue(any("Admin capability is absent" in message for message in messages))

    def test_rejects_undefined_reference_and_unsafe_file_url(self) -> None:
        self.write(
            "README.md",
            "[missing][reference]\n[file](file:///etc/passwd)\n[bad](docs/bad%zz.md)\n",
        )
        messages = self.messages()
        self.assertTrue(any("undefined Markdown reference" in message for message in messages))
        self.assertTrue(any("unsafe link scheme" in message for message in messages))
        self.assertTrue(any("malformed percent encoding" in message for message in messages))


if __name__ == "__main__":
    unittest.main()
