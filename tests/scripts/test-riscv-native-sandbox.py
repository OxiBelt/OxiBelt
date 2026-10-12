#!/usr/bin/env python3
"""Exercise native tool receipt failures without a daemon or privileged host work."""
import ast
import copy
import hashlib
import json
import os
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
BOOTSTRAP = (ROOT / 'riscv-native-sandbox-bootstrap.sh').read_text()
BOOTSTRAP_FAILURE_SETUP = BOOTSTRAP[BOOTSTRAP.index('bootstrap_stage=guard\n'):
                                    BOOTSTRAP.index('[[ $(id -u) == 0')]
STAGED_NAMES = ast.literal_eval(re.search(
    r'^FILES = (\(.*?\n\))', (ROOT / 'run-riscv-native-preflight.py').read_text(), re.M | re.S).group(1)) + ('workflow-identity.json',)
MANIFEST_CODE = re.search(r'python3 - "\$\{lock\}" "\$\{tools\}/bin"[^\n]*<<\'PY\'\n(.*?)\nPY', SCRIPT, re.S).group(1)


class BootstrapFailureReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        self.evidence = self.home / 'evidence'
        self.evidence.mkdir()
        self.receipt = self.evidence / 'bootstrap-failure.json'
        self.canary = 'private-command-and-environment-canary'

    def run_bootstrap(self, commands, *, enable_receipt=True):
        shell = 'set -euo pipefail\numask 077\n' + BOOTSTRAP_FAILURE_SETUP
        if enable_receipt:
            shell += 'bootstrap_receipt_enabled=1\n'
        shell += commands + '\nprintf unexpected-continuation\n'
        result = subprocess.run(['bash', '-c', shell],
                                env={'home': str(self.home), 'evidence': str(self.evidence),
                                     'SECRET_ENVIRONMENT': self.canary},
                                capture_output=True, text=True, timeout=10)
        return shell, result

    def assert_failure(self, shell, result, *, stage, status, command):
        line = shell[:shell.index(command)].count('\n') + 1
        expected = {'schema_version': 1, 'stage': stage, 'line': line, 'exit_code': status}
        self.assertEqual(result.returncode, status)
        self.assertEqual(json.loads(self.receipt.read_text()), expected)
        self.assertEqual(self.receipt.stat().st_mode & 0o777, 0o600)
        self.assertLessEqual(self.receipt.stat().st_size, 256)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr,
                         f'sandbox bootstrap failed: stage={stage} line={line} exit_code={status}\n')
        self.assertNotIn(self.canary, self.receipt.read_text() + result.stderr)
        self.assertNotIn(command, self.receipt.read_text() + result.stderr)
        self.assertEqual((self.home / 'preflight-failed').read_text(), 'sandbox bootstrap failed\n')

    def test_silent_locked_python_assertion_records_production_stage(self):
        stage = re.search(r'^bootstrap_stage=python-install$', BOOTSTRAP, re.M).group(0)
        assertion = re.search(r'^\[\[ \$\{python_version\} == 3\.13\.5-1 \]\]$',
                              BOOTSTRAP, re.M).group(0)
        shell, result = self.run_bootstrap(stage + '\npython_version=unlocked\n' + assertion)
        self.assert_failure(shell, result, stage='python-install', status=1, command=assertion)

    def test_redirected_update_pipeline_preserves_original_status_and_stderr(self):
        pipeline = re.search(r'^bootstrap_stage=apt-update\ntimeout[^\n]+', BOOTSTRAP, re.M).group(0)
        shell, result = self.run_bootstrap(
            'timeout() { printf "%s\\n" "$SECRET_ENVIRONMENT"; return 23; }\n' + pipeline)
        self.assert_failure(shell, result, stage='apt-update', status=23, command='timeout 600 apt-get update')
        self.assertEqual((self.evidence / 'apt-update.log').read_text(), self.canary + '\n')

    def test_redirected_proc_helper_preserves_original_stderr(self):
        helper = re.search(r'^bootstrap_stage=proc-helper\npython3[^\n]+\\\n[^\n]+',
                           BOOTSTRAP, re.M).group(0)
        shell, result = self.run_bootstrap(
            'root=/fixture\npython3() { printf "%s\\n" "$SECRET_ENVIRONMENT"; return 37; }\n' + helper)
        self.assert_failure(shell, result, stage='proc-helper', status=37,
                            command='python3 "${root}/check-riscv-network-sysctl.py" --prepare-proc-mount')
        self.assertEqual((self.evidence / 'network-mount.log').read_text(), self.canary + '\n')

    def test_redirected_sys_helper_preserves_original_stderr_and_receipt(self):
        helper = re.search(r'^bootstrap_stage=sys-helper\npython3[^\n]+\\\n[^\n]+',
                           BOOTSTRAP, re.M).group(0)
        shell, result = self.run_bootstrap(
            'root=/fixture\npython3() { printf "%s\\n" "$SECRET_ENVIRONMENT"; return 39; }\n' + helper)
        self.assert_failure(shell, result, stage='sys-helper', status=39,
                            command='python3 "${root}/check-riscv-network-sysctl.py" --prepare-sys-mount')
        self.assertEqual((self.evidence / 'network-mount.log').read_text(), self.canary + '\n')

    def test_preserves_first_receipt_and_refuses_existing_symlink_or_fifo(self):
        for kind in ('receipt', 'symlink', 'fifo'):
            with self.subTest(kind=kind):
                target = self.home / 'existing'
                target.write_text('first failure\n')
                if kind == 'receipt':
                    self.receipt.write_text('first failure\n')
                elif kind == 'symlink':
                    self.receipt.symlink_to(target)
                else:
                    os.mkfifo(self.receipt)
                _, result = self.run_bootstrap('false')
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stderr.count('sandbox bootstrap failed:'), 1)
                if kind == 'receipt':
                    self.assertEqual(self.receipt.read_text(), 'first failure\n')
                else:
                    self.assertEqual(target.read_text(), 'first failure\n')
                self.receipt.unlink()

    def test_unwritable_evidence_does_not_recurse_or_replace_failure_status(self):
        self.evidence.rmdir()
        self.evidence.write_text('not a directory\n')
        _, result = self.run_bootstrap('(exit 43)')
        self.assertEqual(result.returncode, 43)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr.count('sandbox bootstrap failed:'), 1)
        self.assertIn('exit_code=43\n', result.stderr)

    def test_unsafe_guard_emits_marker_without_creating_receipt(self):
        _, result = self.run_bootstrap('false', enable_receipt=False)
        self.assertEqual(result.returncode, 1)
        self.assertIn('stage=guard', result.stderr)
        self.assertFalse(self.receipt.exists())
        self.assertFalse((self.home / 'preflight-failed').exists())

    def test_systemd_exec_failure_uses_production_handler(self):
        handoff = BOOTSTRAP[BOOTSTRAP.index('bootstrap_stage=systemd-exec\n'):]
        shell, result = self.run_bootstrap(
            'exec() { builtin exec "${home}/missing-systemd"; }\n' + handoff)
        self.assertEqual(result.returncode, 127)
        receipt = json.loads(self.receipt.read_text())
        self.assertEqual(receipt['stage'], 'systemd-exec')
        self.assertEqual(receipt['exit_code'], 127)
        line = shell[:shell.index('  || bootstrap_failure')].count('\n') + 1
        self.assertEqual(receipt['line'], line)
        self.assertIn(f'stage=systemd-exec line={line} exit_code=127\n', result.stderr)
        self.assertNotIn(self.canary, result.stderr + self.receipt.read_text())

    def test_successful_systemd_handoff_closes_diagnostic_descriptor(self):
        handoff = BOOTSTRAP[BOOTSTRAP.index('bootstrap_stage=systemd-exec\n'):]
        _, result = self.run_bootstrap(
            '''exec() {
  builtin exec python3 -c 'import os
try:
    os.fstat(3)
except OSError:
    print("descriptor closed")
else:
    raise AssertionError("diagnostic descriptor leaked")'
}
''' + handoff)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, 'descriptor closed\n')
        self.assertEqual(result.stderr, '')
        self.assertFalse(self.receipt.exists())

    def test_unit_modes_do_not_install_bootstrap_failure_trap(self):
        shell = 'set -euo pipefail\n' + BOOTSTRAP_FAILURE_SETUP + 'false\n'
        for mode in ('--prepare-user', '--record-failure'):
            with self.subTest(mode=mode):
                result = subprocess.run(['bash', '-c', shell, 'bootstrap-fixture', mode],
                                        env={'home': str(self.home), 'evidence': str(self.evidence)},
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stderr, '')
                self.assertFalse(self.receipt.exists())

    def staging_block(self):
        return BOOTSTRAP[BOOTSTRAP.index('bootstrap_stage=staging-ownership\n'):
                         BOOTSTRAP.index('# Detach propagation')]

    def make_staging(self, parent):
        staging = parent / 'preflight'
        staging.mkdir(parents=True)
        staging.chmod(0o777)
        for name in STAGED_NAMES:
            (staging / name).write_text('fixture; never execute\n')
            (staging / name).chmod(0o600)
        return staging

    def staging_commands(self, relative_root):
        return ('root="${home}/' + relative_root + '"\n'
                'chown() { printf "%s\\0" "$@" >"${home}/chown-arguments"; }\n'
                + self.staging_block())

    def test_staged_sources_have_root_ownership_arguments_and_safe_modes(self):
        staging = self.make_staging(self.home / 'stage-parent')
        _, result = self.run_bootstrap(self.staging_commands('stage-parent/preflight'))
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, '')
        arguments = (self.home / 'chown-arguments').read_bytes().decode().split('\0')[:-1]
        self.assertEqual(arguments[:4], ['--no-dereference', '0:0', '--', str(staging)])
        self.assertEqual(set(arguments[4:]), {str(staging / name) for name in STAGED_NAMES})
        self.assertEqual(len(arguments[4:]), len(STAGED_NAMES))
        self.assertEqual(staging.stat().st_mode & 0o777, 0o755)
        for name in STAGED_NAMES:
            self.assertEqual((staging / name).stat().st_mode & 0o777, 0o644)
        self.assertFalse(self.receipt.exists())

    def test_staging_rejects_symlinks_and_unexpected_entries_before_chown(self):
        cases = ('parent-symlink', 'root-symlink', 'child-symlink', 'dangling-symlink',
                 'directory', 'fifo', 'unexpected-file', 'hidden-file')
        for index, kind in enumerate(cases):
            with self.subTest(kind=kind):
                case = self.home / str(index)
                staging = self.make_staging(case / 'stage-parent')
                staged_root = case / 'stage-parent' / 'preflight'
                if kind == 'parent-symlink':
                    staging.parent.rename(case / 'real-parent')
                    staged_root.parent.symlink_to(case / 'real-parent')
                    staging = case / 'real-parent' / 'preflight'
                elif kind == 'root-symlink':
                    staging.rename(case / 'stage-parent' / 'real-staging')
                    staged_root.symlink_to(staged_root.parent / 'real-staging')
                    staging = staged_root.parent / 'real-staging'
                elif kind in ('child-symlink', 'dangling-symlink', 'directory', 'fifo'):
                    entry = staging / 'check-riscv-proc-mount.py'
                    entry.unlink()
                    if kind == 'child-symlink':
                        entry.symlink_to(staging / 'check-riscv-network-sysctl.py')
                    elif kind == 'dangling-symlink':
                        entry.symlink_to(staging / 'absent')
                    elif kind == 'directory':
                        entry.mkdir()
                    else:
                        os.mkfifo(entry)
                else:
                    name = '.unexpected' if kind == 'hidden-file' else 'unexpected.py'
                    (staging / name).write_text('unexpected\n')
                _, result = self.run_bootstrap(self.staging_commands(f'{index}/stage-parent/preflight'))
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, '')
                self.assertEqual(json.loads(self.receipt.read_text())['stage'], 'staging-ownership')
                self.assertIn('stage=staging-ownership', result.stderr)
                self.assertFalse((self.home / 'chown-arguments').exists())
                self.assertEqual(staging.stat().st_mode & 0o777, 0o777)
                self.receipt.unlink()

    def test_staging_normalization_precedes_package_work_and_runner_startup(self):
        ownership = BOOTSTRAP.index('bootstrap_stage=staging-ownership\n')
        self.assertLess(BOOTSTRAP.index('\nbootstrap_receipt_enabled=1\n'), ownership)
        self.assertLess(ownership, BOOTSTRAP.index('bootstrap_stage=apt-sources\n'))
        self.assertLess(ownership, BOOTSTRAP.index('useradd --uid 1001'))
        self.assertLess(BOOTSTRAP.index('chmod 644 -- "${staged_files[@]}"'),
                        BOOTSTRAP.index('bootstrap_stage=proc-helper\n'))

    def test_handoff_restores_both_private_helpers_and_checks_before_systemd(self):
        handoff = BOOTSTRAP[BOOTSTRAP.rindex('bootstrap_stage=propagation\n'):]
        shared = handoff.index('mount --make-rshared /')
        private = handoff.index('mount --make-private "${root}/private-proc/proc"')
        sys_private = handoff.index('mount --make-private "${root}/private-sys/sys"')
        check = handoff.index('--check-mounts')
        systemd = handoff.index('exec /lib/systemd/systemd')
        self.assertLess(shared, private)
        self.assertLess(private, sys_private)
        self.assertLess(sys_private, check)
        self.assertIn('--check-mounts --require-sys-helper', handoff)
        self.assertLess(check, systemd)
        self.assertIn('tail -c 4194304 >>"${evidence}/network-mount.log"', handoff)
        for failure, status, stage in [('none', 0, None), ('shared', 41, 'propagation'),
                                       ('private', 43, 'proc-helper'), ('sys-private', 45, 'sys-helper'),
                                       ('check', 47, 'network-mount')]:
            with self.subTest(failure=failure):
                commands = '''root=/fixture
mount() {
  printf '%s %s\\n' "$1" "$2" >>"${home}/mount-calls"
  if [[ $1 == --make-rshared && $failure == shared ]]; then return 41; fi
  if [[ $1 == --make-private && $failure == private ]]; then return 43; fi
  if [[ $2 == /fixture/private-sys/sys && $failure == sys-private ]]; then return 45; fi
}
python3() {
  printf '%s\\n' "$*" >"${home}/mount-check"
  printf '%s\\n' "$SECRET_ENVIRONMENT"
  if [[ $failure == check ]]; then return 47; fi
}
exec() { printf started >"${home}/systemd-started"; builtin exec /usr/bin/true; }
''' + f'failure={failure}\n' + handoff
                (self.evidence / 'network-mount.log').write_text('before\n')
                _, result = self.run_bootstrap(commands)
                self.assertEqual(result.returncode, status)
                self.assertEqual(result.stdout, '')
                calls = (self.home / 'mount-calls').read_text().splitlines()
                expected = ['--make-rshared /']
                if failure != 'shared':
                    expected.append('--make-private /fixture/private-proc/proc')
                if failure not in ('shared', 'private'):
                    expected.append('--make-private /fixture/private-sys/sys')
                self.assertEqual(calls, expected)
                self.assertEqual((self.home / 'mount-check').exists(), failure in ('none', 'check'))
                self.assertEqual((self.home / 'systemd-started').exists(), failure == 'none')
                if status:
                    receipt = json.loads(self.receipt.read_text())
                    self.assertEqual(receipt['stage'], stage)
                    self.assertEqual(receipt['exit_code'], status)
                    self.assertIn(f'stage={stage}', result.stderr)
                    self.assertNotIn(self.canary, result.stderr + self.receipt.read_text())
                    self.receipt.unlink()
                else:
                    self.assertEqual(result.stderr, '')
                    self.assertFalse(self.receipt.exists())
                if failure in ('none', 'check'):
                    self.assertEqual((self.home / 'mount-check').read_text(),
                                     '/fixture/check-riscv-network-sysctl.py --check-mounts --require-sys-helper\n')
                    self.assertEqual((self.evidence / 'network-mount.log').read_text(),
                                     'before\n' + self.canary + '\n')
                for name in ('mount-calls', 'mount-check', 'systemd-started'):
                    (self.home / name).unlink(missing_ok=True)

    def test_handler_is_installed_before_guard_and_writes_only_after_pid1_guard(self):
        first_guard = BOOTSTRAP.index('[[ $(id -u) == 0')
        pid1_guard = BOOTSTRAP.index('[[ $$ == 1 && $(id -u) == 0 && $(uname -m) == riscv64 ]]')
        enabled = BOOTSTRAP.index('\nbootstrap_receipt_enabled=1\n')
        lock_guard = BOOTSTRAP.index('[[ -f ${root}/riscv-native-tools.lock.json')
        self.assertLess(BOOTSTRAP.index("trap 'bootstrap_failure"), first_guard)
        self.assertLess(pid1_guard, enabled)
        self.assertLess(enabled, lock_guard)
        stages = set(re.findall(r'^bootstrap_stage=([a-z-]+)$', BOOTSTRAP, re.M))
        self.assertEqual(stages, {'guard', 'staging-ownership', 'propagation', 'apt-sources', 'apt-update',
                                 'python-install', 'package-install', 'package-verify',
                                 'network-mount', 'proc-helper', 'sys-helper', 'runner-user', 'tun',
                                 'systemd-setup', 'systemd-exec'})


class NativeToolReceiptTests(unittest.TestCase):
    def test_daemon_configuration_selects_vfs_and_disables_containerd_snapshotter(self):
        config = re.search(r'cat >"\$\{home\}/\.config/docker/daemon\.json" <<\'EOF\'\n(.*?)\nEOF',
                           SCRIPT, re.S)
        self.assertIsNotNone(config)
        daemon = json.loads(config.group(1))
        self.assertEqual(daemon['storage-driver'], 'vfs')
        self.assertIs(daemon['features']['containerd-snapshotter'], False)
        self.assertEqual(daemon['exec-opts'], ['native.cgroupdriver=systemd'])
        self.assertEqual(daemon['data-root'], '/home/runner/.local/share/docker')

    def test_daemon_readiness_requires_vfs_and_preserves_boundary_checks(self):
        start = SCRIPT.index('python3 - "${evidence}/docker-info.json"')
        publication = SCRIPT.index('>"${home}/preflight-ready"', start)
        validator = SCRIPT[start:SCRIPT.index('\n', publication)]
        info = {'Architecture': 'riscv64', 'ServerVersion': '29.8.0', 'Driver': 'vfs',
                'CgroupVersion': '2', 'CgroupDriver': 'systemd',
                'SecurityOptions': ['name=rootless', 'name=cgroupns', 'name=seccomp,profile=builtin']}
        variants = [('valid', info)]
        for field, value in [('Driver', None), ('Driver', 'overlayfs'), ('Driver', 'native'),
                             ('Architecture', 'x86_64'), ('ServerVersion', '28.0.4'),
                             ('CgroupVersion', '1'), ('CgroupDriver', 'none')]:
            invalid = copy.deepcopy(info)
            if value is None:
                del invalid[field]
            else:
                invalid[field] = value
            variants.append((f'{field}-{value}', invalid))
        for missing in info['SecurityOptions']:
            invalid = copy.deepcopy(info)
            invalid['SecurityOptions'].remove(missing)
            variants.append((missing, invalid))
        for index, (name, fixture) in enumerate(variants):
            with self.subTest(name=name):
                evidence = self.root / str(index)
                evidence.mkdir()
                (evidence / 'docker-info.json').write_text(json.dumps(fixture))
                result = subprocess.run(['bash', '-c', 'set -e\n' + validator],
                                        env={'evidence': str(evidence), 'home': str(evidence)},
                                        capture_output=True, text=True)
                ready = evidence / 'preflight-ready'
                self.assertEqual(result.returncode == 0, name == 'valid')
                self.assertEqual(ready.exists(), name == 'valid')
                if name == 'valid':
                    self.assertEqual(ready.read_text(), 'native rootless tools ready\n')

    def test_locks_sysctl_provider_and_installs_the_full_package_set(self):
        self.assertEqual(LOCK['debian']['packages']['procps'], '2:4.0.4-9')
        bootstrap = (ROOT / 'riscv-native-sandbox-bootstrap.sh').read_text()
        count = re.search(r'\[\[ \$\{#packages\[@\]\} == (\d+) \]\]', bootstrap)
        self.assertEqual(int(count.group(1)), len(LOCK['debian']['packages']))

    def test_missing_sysctl_fails_before_compilation(self):
        prerequisites = re.search(r'for command in .*?\ndone', SCRIPT, re.S).group(0)
        self.assertLess(SCRIPT.index(prerequisites), SCRIPT.index('build_logged engine'))
        for missing, expected in [('', 0), ('sysctl', 1)]:
            with self.subTest(missing=missing):
                result = subprocess.run(
                    ['bash', '-c', 'set -e; command() { [[ "$2" != "${MISSING}" ]]; };\n'
                     + prerequisites + '\nprintf compiled'],
                    env={'MISSING': missing}, capture_output=True, text=True)
                self.assertEqual(result.returncode, expected)
                self.assertEqual(result.stdout, 'compiled' if expected == 0 else '')

    def test_network_device_stays_inside_the_guarded_sandbox(self):
        bootstrap = (ROOT / 'riscv-native-sandbox-bootstrap.sh').read_text()
        guard = bootstrap.index('[[ $$ == 1 && $(id -u) == 0 && $(uname -m) == riscv64 ]]')
        node = bootstrap.index('mknod -m 600 /dev/net/tun c 10 200')
        systemd = bootstrap.index('exec /lib/systemd/systemd')
        self.assertLess(guard, node)
        self.assertLess(node, systemd)
        self.assertIn('chown runner:runner /dev/net/tun', bootstrap)
        self.assertIn('chmod 600 /dev/net/tun', bootstrap)
        self.assertIn("$(stat -c '%t:%T' /dev/net/tun) == a:c8", bootstrap)

    def test_network_mount_is_prepared_before_any_user_namespace(self):
        bootstrap = (ROOT / 'riscv-native-sandbox-bootstrap.sh').read_text()
        guard = bootstrap.index('[[ $$ == 1 && $(id -u) == 0 && $(uname -m) == riscv64 ]]')
        private = bootstrap.index('mount --make-rprivate /')
        bind = bootstrap.index('mount --bind /proc/sys/net /proc/sys/net')
        remount = bootstrap.index('mount -o remount,bind,rw,nosuid,nodev,noexec /proc/sys/net')
        check = bootstrap.index('--check-mounts')
        self.assertLess(guard, private)
        self.assertLess(private, bind)
        self.assertLess(bind, remount)
        self.assertLess(remount, check)
        self.assertLess(check, bootstrap.index('useradd --uid 1001'))

    def test_systemd_mount_protection_precedes_runner_startup(self):
        bootstrap = (ROOT / 'riscv-native-sandbox-bootstrap.sh').read_text()
        preparation = bootstrap[bootstrap.index('if [[ ${1:-} == --prepare-user'):
                                bootstrap.index('if [[ ${1:-} == --record-failure')]
        self.assertLess(preparation.index('--protect-systemd-mounts'),
                        preparation.index('loginctl enable-linger runner'))
        self.assertLess(preparation.index('--protect-systemd-mounts'),
                        preparation.index('systemctl start user@1001.service'))

    def test_proc_helper_is_prepared_before_any_user_namespace(self):
        bootstrap = (ROOT / 'riscv-native-sandbox-bootstrap.sh').read_text()
        helper = bootstrap.index('--prepare-proc-mount')
        self.assertLess(bootstrap.index('mount --make-rprivate /'), helper)
        self.assertLess(helper, bootstrap.index('useradd --uid 1001'))

    def test_sys_helper_is_prepared_after_proc_before_any_user_namespace(self):
        helper = BOOTSTRAP.index('--prepare-sys-mount')
        self.assertLess(BOOTSTRAP.index('mount --make-rprivate /'), helper)
        self.assertLess(BOOTSTRAP.index('--prepare-proc-mount'), helper)
        self.assertLess(helper, BOOTSTRAP.index('useradd --uid 1001'))
        self.assertIn('check-riscv-sys-mount.py|workflow-identity.json', BOOTSTRAP)

    def test_failed_proc_probe_prevents_network_probe_and_compilation(self):
        start = SCRIPT.index('download rootlesskit ')
        end = SCRIPT.index('export GOTOOLCHAIN=')
        shell = '''set -e
download() { printf 'download:%s\\n' "$1"; }
field() { :; }
tar() { :; }
python3() { printf '%s\\n' "$1"; return 1; }
''' + SCRIPT[start:end] + '\nprintf compiled'
        result = subprocess.run(['bash', '-c', shell], env={'tools': '/tools', 'root': '/root',
                                'evidence': '/evidence', 'home': str(self.root)}, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn('/root/check-riscv-proc-mount.py', result.stdout)
        self.assertNotIn('/root/check-riscv-network-sysctl.py', result.stdout)
        self.assertNotIn('download:go', result.stdout)
        self.assertNotIn('compiled', result.stdout)
        self.assertFalse((self.root / 'proc-preflight-ready').exists())

    def test_failed_sys_probe_prevents_go_download_and_compilation(self):
        start = SCRIPT.index('download rootlesskit ')
        end = SCRIPT.index('export GOTOOLCHAIN=')
        for status in ('1', '0'):
            home = self.root / ('sys-' + status)
            home.mkdir()
            shell = '''set -e
download() { printf 'download:%s\\n' "$1"; }
field() { :; }
tar() { :; }
python3() {
  printf 'probe:%s\\n' "$1"
  if [[ "$1" == */check-riscv-sys-mount.py ]]; then return "${SYS_STATUS}"; fi
}
''' + SCRIPT[start:end] + '\nprintf compiled'
            with self.subTest(status=status):
                result = subprocess.run(['bash', '-c', shell],
                                        env={'SYS_STATUS': status, 'tools': '/tools', 'root': '/root',
                                             'evidence': '/evidence', 'home': str(home)},
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, int(status))
                self.assertIn('probe:/root/check-riscv-sys-mount.py', result.stdout)
                self.assertTrue((home / 'proc-preflight-ready').exists())
                self.assertTrue((home / 'network-preflight-ready').exists())
                self.assertEqual((home / 'sys-preflight-ready').exists(), status == '0')
                self.assertEqual('download:go' in result.stdout, status == '0')
                self.assertEqual('compiled' in result.stdout, status == '0')

    def test_failed_network_probe_prevents_go_download_and_compilation(self):
        start = SCRIPT.index('download rootlesskit ')
        end = SCRIPT.index('export GOTOOLCHAIN=')
        preparation = SCRIPT[start:end]
        for status in ('0', '1'):
            with self.subTest(status=status):
                shell = '''set -e
download() { printf 'download:%s\\n' "$1"; }
field() { :; }
tar() { :; }
python3() { return "${NETWORK_STATUS}"; }
''' + preparation + '\nprintf compiled'
                result = subprocess.run(['bash', '-c', shell],
                                        env={'NETWORK_STATUS': status, 'tools': '/tools',
                                             'root': '/root', 'evidence': '/evidence',
                                             'home': str(self.root)},
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, int(status))
                self.assertIn('download:rootlesskit', result.stdout)
                if status == '1':
                    self.assertNotIn('download:go', result.stdout)
                    self.assertNotIn('compiled', result.stdout)
                    self.assertFalse((self.root / 'network-preflight-ready').exists())
                else:
                    self.assertIn('download:go', result.stdout)
                    self.assertTrue(result.stdout.endswith('compiled'))
                    (self.root / 'network-preflight-ready').unlink()
                    (self.root / 'proc-preflight-ready').unlink()

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
