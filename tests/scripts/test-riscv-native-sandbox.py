#!/usr/bin/env python3
"""Exercise native tool receipt failures without a daemon or privileged host work."""
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
LOCK = json.loads((ROOT / 'riscv-native-tools.lock.json').read_text())
SCRIPT = (ROOT / 'riscv-native-sandbox-build-tools.sh').read_text()
MANIFEST_CODE = re.search(r'python3 - "\$\{lock\}" "\$\{tools\}/bin"[^\n]*<<\'PY\'\n(.*?)\nPY', SCRIPT, re.S).group(1)


class NativeToolReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.lock = self.root / 'lock.json'
        self.lock.write_text(json.dumps(LOCK))
        self.output = self.root / 'receipt.json'
        self.probe = self.root / 'limit-probe'
        elf = bytearray(64)
        elf[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<H', elf, 18, 243)
        names = ['docker', 'dockerd', 'docker-proxy', 'containerd', 'containerd-shim-runc-v2', 'ctr', 'runc', 'rootlesskit']
        for name in names:
            (self.root / name).write_bytes(elf)
        self.probe.write_bytes(elf)
        for name in ('dockerd-rootless.sh', 'dockerd-rootless-setuptool.sh'):
            (self.root / name).write_text('#!/bin/sh\n')
        self.versions = {name: '29.8.0' for name in ['docker', 'dockerd', 'docker-proxy']}
        self.versions.update({name: '2.3.4' for name in ['containerd', 'containerd-shim-runc-v2', 'ctr']})
        self.versions.update(runc='runc version 1.5.1\nlibseccomp: 2.6.0', rootlesskit='3.2.0')

    def run_manifest(self):
        arguments = ['', str(self.lock), str(self.root), str(self.output), str(self.probe)]
        with patch.object(sys, 'argv', arguments), patch.object(subprocess, 'check_output', side_effect=lambda args, **kwargs: self.versions[Path(args[0]).name]):
            exec(compile(MANIFEST_CODE, '<native tool receipt>', 'exec'), {})

    def test_binds_every_binary_and_lock(self):
        self.run_manifest()
        manifest = json.loads(self.output.read_text())
        self.assertEqual(manifest['lockSha256'], hashlib.sha256(self.lock.read_bytes()).hexdigest())
        self.assertEqual(len(manifest['binaries']), 9)
        for name, item in manifest['binaries'].items():
            self.assertEqual(item['sha256'], hashlib.sha256((self.root / name).read_bytes()).hexdigest())
            self.assertEqual(item['elfMachine'], 243)

    def test_rejects_foreign_machine(self):
        data = bytearray((self.root / 'docker').read_bytes())
        struct.pack_into('<H', data, 18, 62)
        (self.root / 'docker').write_bytes(data)
        with self.assertRaises(AssertionError):
            self.run_manifest()
        self.assertFalse(self.output.exists())

    def test_rejects_similar_version(self):
        self.versions['dockerd'] = '129.8.0'
        with self.assertRaises(AssertionError):
            self.run_manifest()

    def test_rejects_runc_without_seccomp(self):
        self.versions['runc'] = 'runc version 1.5.1'
        with self.assertRaises(AssertionError):
            self.run_manifest()

    def test_rejects_foreign_probe(self):
        self.probe.write_bytes(b'not an ELF')
        with self.assertRaises(AssertionError):
            self.run_manifest()

    def test_bootstrap_refuses_non_container_invocation(self):
        result = subprocess.run(['bash', str(ROOT / 'riscv-native-sandbox-bootstrap.sh')], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
