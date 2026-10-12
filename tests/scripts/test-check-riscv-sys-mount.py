#!/usr/bin/env python3
"""Sysfs mount preflight regressions without privileged mounts or native builds."""
import contextlib
import errno
import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SPEC = importlib.util.spec_from_file_location("sys_mount", Path(__file__).with_name("check-riscv-sys-mount.py"))
assert SPEC and SPEC.loader
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)
IDENTITY = {"GITHUB_REPOSITORY": "example/OxiBelt", "GITHUB_SHA": "a" * 40,
            "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_EVENT_NAME": "push"}
PARENTS, ENTERED = (101, 202, 303), (101, 404, 505)
BASE = "1 0 0:1 / / rw - overlay overlay rw\n"
PIN = "3 1 0:3 net:[505] /run/user/1001/oxibelt-network-test/netns rw - nsfs nsfs rw\n"
NATIVE_OBSERVATION = json.loads(Path(__file__).with_name("fixtures").joinpath("riscv-network-defaults-rv5.10.json").read_text())


def mountinfo(target, root="/", flags="ro,nosuid,nodev,noexec", fs="sysfs", propagation="", super_flags="rw"):
    extra = " " + propagation if propagation else ""
    return BASE + f"2 1 0:2 {root} {target} {flags}{extra} - {fs} sysfs {super_flags}\n" + PIN


def observation(names=((1, "lo"),)):
    if names == ((1, "lo"),):
        value = json.loads(json.dumps(NATIVE_OBSERVATION))
        value["socket_interfaces"] = [{"index": 1, "name": "lo"}]
        value["sys_interfaces"]["names"] = ["lo"]
        value["sys_interfaces"]["interfaces"] = [item for item in value["sys_interfaces"]["interfaces"] if item["name"] == "lo"]
        for view in ("link", "address"):
            value["ip"][view] = [item for item in value["ip"][view] if item["ifname"] == "lo"]
        return value
    return {"schema_version": 1,
            "socket_interfaces": [{"index": index, "name": name} for index, name in names],
            "sys_interfaces": {"names": sorted(name for _, name in names),
                               "interfaces": [{"index": index, "name": name, "type": 772 if name == "lo" else 1,
                                               "flags": 8 if name == "lo" else 0} for index, name in names]},
            "ip": {"link": [{"ifindex": index, "ifname": name, "flags": ["LOOPBACK"] if name == "lo" else []}
                            for index, name in names],
                   "address": [{"ifindex": index, "ifname": name, "addr_info": []} for index, name in names],
                   "route4": [], "route6": []}, "errors": {}}


def child(version=3):
    value = PROBE.child_receipt()
    value.update(supported=True, diagnostic="passed", pidns=606, mntns=707, netns=808,
                 entered_pidns=ENTERED[0], entered_mntns=ENTERED[1], detached_netns=ENTERED[2],
                 mount_id=2, readonly_errno=30, interfaces=[{"index": 1, "name": "lo"}],
                 network_observation=observation(),
                 **{key: True for key in PROBE.BOOLEAN_FIELDS})
    value["schema_version"] = version
    if version == 1:
        del value["network_observation"]
    return value


def receipt(version=3):
    value = PROBE.parent_receipt()
    value.update(supported=True, diagnostic="passed", identity=dict(IDENTITY),
                 native={**PROBE.NATIVE_FIELDS, **{key: "b" * 64 for key in PROBE.HASH_FIELDS}},
                 kernel_release="6.12.42-provider", sandbox_pidns=101, sandbox_mntns=202, sandbox_netns=303,
                 child=child(version), parent_mounts_sha256="c" * 64, parent_mounts_unchanged=True,
                 helper_inaccessible=True, cleanup_confirmed=True)
    value["schema_version"] = version
    if version == 1:
        del value["native"]["observer_sha256"]
    return value


class ReceiptTests(unittest.TestCase):
    def test_legacy_v1_keeps_exact_fields_hashes_and_loopback_contract(self):
        value = receipt(1)
        hashes = {key: value["native"][key] for key in PROBE.V1_HASH_FIELDS}
        self.assertIs(PROBE.validate_receipt(value, IDENTITY, hashes), value)
        for mutate in (lambda v: v["native"].update(observer_sha256="b" * 64),
                       lambda v: v["child"].update(network_observation=observation()),
                       lambda v: v["child"].update(interfaces=[{"index": 1, "name": "lo"}, {"index": 2, "name": "gre0"}]),
                       lambda v: v["child"].update(readonly_errno=errno.EPERM)):
            changed = json.loads(json.dumps(value))
            mutate(changed)
            with self.assertRaises(PROBE.ProbeError):
                PROBE.validate_receipt(changed)
        self.assertEqual(PROBE.V1_HASH_FIELDS, {"rootlesskit_sha256", "probe_sha256", "lock_sha256"})
        self.assertIsNot(PROBE.V1_HASH_FIELDS, PROBE.PROC.HASH_FIELDS)

    def test_parent_and_child_schema_versions_cannot_mix(self):
        for parent_version in (1, 2, 3):
            for child_version in (1, 2, 3):
                if parent_version == child_version:
                    continue
                value = receipt(parent_version)
                value["child"] = child(child_version)
                with self.subTest(parent=parent_version, child=child_version), self.assertRaises(PROBE.ProbeError):
                    PROBE.validate_receipt(value)

    def test_v2_network_observation_must_be_complete_and_match_to_pass(self):
        for change in (lambda v: v.update(network_observation=PROBE.OBSERVER.empty()),
                       lambda v: v.update(network_observation=None),
                       lambda v: v["network_observation"]["ip"].update(route4=None),
                       lambda v: v["network_observation"].update(errors={"route6": "network-observation-timeout"}),
                       lambda v: v["network_observation"]["ip"]["link"][0].update(ifindex=2),
                       lambda v: v.update(network_observation=observation(((1, "lo"), (2, "gre0"))))):
            value = receipt(2)
            change(value["child"])
            with self.assertRaises(PROBE.ProbeError):
                PROBE.validate_receipt(value)

    def test_legacy_schemas_reject_the_observed_additional_defaults(self):
        interfaces = [{"index": 1, "name": "lo"}, {"index": 2, "name": "ip_vti0"}, {"index": 3, "name": "sit0"}]
        for version in (1, 2):
            value = receipt(version)
            value["child"]["interfaces"] = interfaces
            if version == 2:
                value["child"]["network_observation"] = json.loads(json.dumps(NATIVE_OBSERVATION))
            with self.subTest(version=version), self.assertRaisesRegex(PROBE.ProbeError, "success-evidence"):
                PROBE.validate_receipt(value)

    def native_receipt(self):
        value = receipt()
        value["child"]["network_observation"] = json.loads(json.dumps(NATIVE_OBSERVATION))
        value["child"]["interfaces"] = [{"index": 1, "name": "lo"}, {"index": 2, "name": "ip_vti0"},
                                         {"index": 3, "name": "sit0"}]
        return value

    def test_v3_reclassifies_complete_native_observation_before_success(self):
        value = self.native_receipt()
        hashes = {key: value["native"][key] for key in PROBE.HASH_FIELDS}
        with mock.patch.object(PROBE.OBSERVER, "network_none_interfaces",
                               wraps=PROBE.OBSERVER.network_none_interfaces) as classified:
            self.assertIs(PROBE.validate_receipt(value, IDENTITY, hashes), value)
        classified.assert_called_once_with(value["child"]["network_observation"])
        self.assertEqual(value["schema_version"], 3)
        self.assertEqual(PROBE.child_receipt()["schema_version"], 3)

    def test_v3_does_not_trust_supported_or_interface_facts(self):
        mutations = [lambda v: v.update(interfaces=[{"index": 1, "name": "lo"}]),
                     lambda v: v["network_observation"]["ip"].update(route4=[{"dev": "ip_vti0", "dst": "default"}]),
                     lambda v: v["network_observation"]["ip"].update(route6=[{"dev": "sit0", "dst": "default"}]),
                     lambda v: v["network_observation"]["ip"]["link"][1]["linkinfo"]["info_data"].update(remote="192.0.2.1"),
                     lambda v: v["network_observation"]["ip"]["link"][2]["linkinfo"]["info_data"].update(ttl=63),
                     lambda v: v["network_observation"]["ip"]["link"][1]["linkinfo"]["info_data"].update(fwmark="0x1"),
                     lambda v: v["network_observation"]["ip"]["link"][1].update(master="bridge0"),
                     lambda v: v["network_observation"]["ip"]["link"][2].update(flags=["NOARP", "UP"]),
                     lambda v: v["network_observation"]["ip"]["address"][1].update(addr_info=[{"family": "inet", "local": "192.0.2.1"}]),
                     lambda v: v["network_observation"]["sys_interfaces"]["interfaces"][0].update(flags=129),
                     lambda v: v["network_observation"]["ip"].update(route6=None),
                     lambda v: v["network_observation"].update(errors={"route6": "network-observation-timeout"})]
        for number, change in enumerate(mutations):
            value = self.native_receipt()
            change(value["child"])
            with self.subTest(mutation=number), self.assertRaises(PROBE.ProbeError):
                PROBE.validate_receipt(value)

    def test_v3_observer_hash_is_required_and_bound_to_expected_source(self):
        for change in (lambda v: v["native"].pop("observer_sha256"),
                       lambda v: v["native"].update(observer_sha256="d" * 64)):
            value = self.native_receipt()
            hashes = {key: value["native"][key] for key in PROBE.HASH_FIELDS}
            change(value)
            with self.assertRaisesRegex(PROBE.ProbeError, "invalid-sys-mount-receipt"):
                PROBE.validate_receipt(value, IDENTITY, hashes)

    def test_success_binds_identity_and_hashes(self):
        value = receipt()
        hashes = {key: value["native"][key] for key in PROBE.HASH_FIELDS}
        self.assertIs(PROBE.validate_receipt(value, IDENTITY, hashes), value)
        for identity, expected in (({**IDENTITY, "GITHUB_SHA": "d"*40}, hashes),
                                   (IDENTITY, {**hashes, "probe_sha256": "d"*64})):
            with self.subTest(identity=identity), self.assertRaises(PROBE.ProbeError):
                PROBE.validate_receipt(value, identity, expected)

    def test_legacy_v2_retains_exact_observation_and_hash_contract(self):
        value = receipt(2)
        hashes = {key: value["native"][key] for key in PROBE.HASH_FIELDS}
        self.assertIs(PROBE.validate_receipt(value, IDENTITY, hashes), value)
        legacy = json.loads(json.dumps(value))
        legacy["child"]["network_observation"]["ip"]["link"] = [{"ifindex": 1, "ifname": "lo", "flags": ["LOOPBACK"]}]
        legacy["child"]["network_observation"]["ip"]["address"] = [{"ifindex": 1, "ifname": "lo", "addr_info": []}]
        self.assertIs(PROBE.validate_receipt(legacy, IDENTITY, hashes), legacy)
        for change in (lambda v: v["native"].pop("observer_sha256"),
                       lambda v: v["child"].pop("network_observation"),
                       lambda v: v["child"].update(extra=True)):
            changed = json.loads(json.dumps(value))
            change(changed)
            with self.assertRaises(PROBE.ProbeError):
                PROBE.validate_receipt(changed, IDENTITY, hashes)

    def test_receipt_requires_strict_types_and_all_parent_evidence(self):
        for key, bad in (("schema_version", True), ("supported", 1), ("diagnostic", "failed"),
                         ("sandbox_pidns", True), ("sandbox_mntns", 0), ("sandbox_netns", None),
                         ("cleanup_confirmed", False), ("parent_mounts_unchanged", False),
                         ("helper_inaccessible", False), ("parent_mounts_sha256", "bad"),
                         ("kernel_release", "kernel\nsecret"), ("identity", {}),
                         ("identity", {**IDENTITY, "SECRET": "redact"}), ("child", None)):
            value = receipt()
            value[key] = bad
            with self.subTest(key=key), self.assertRaises(PROBE.ProbeError):
                PROBE.validate_receipt(value)
        value = receipt()
        value["extra"] = True
        with self.assertRaises(PROBE.ProbeError):
            PROBE.validate_receipt(value)

    def test_native_fields_and_hashes_are_typed_and_exact(self):
        for key, bad in (("uid", True), ("executing_elf_machine", 62), ("architecture", "x86_64"),
                         ("rootlesskit_version", "3.2.1"), ("engine_source_version", "29.9.0"),
                         ("lock_sha256", "X"*64), ("probe_sha256", 123)):
            value = receipt()
            value["native"][key] = bad
            with self.subTest(key=key), self.assertRaises(PROBE.ProbeError):
                PROBE.validate_receipt(value)

    def test_child_requires_every_success_fact(self):
        for key in PROBE.BOOLEAN_FIELDS:
            value = receipt()
            value["child"][key] = False
            with self.subTest(key=key), self.assertRaises(PROBE.ProbeError):
                PROBE.validate_receipt(value)
        for key, bad in (("readonly_errno", errno.EPERM), ("readonly_errno", True), ("mount_id", True),
                         ("schema_version", True), ("supported", False), ("interfaces", []),
                         ("interfaces", [{"index": True, "name": "lo"}]),
                         ("interfaces", [{"index": 1, "name": "eth0"}])):
            value = receipt()
            value["child"][key] = bad
            with self.subTest(key=key), self.assertRaises(PROBE.ProbeError):
                PROBE.validate_receipt(value)

    def test_child_all_namespaces_must_differ_from_relevant_ancestors(self):
        for key, bad in (("pidns", 101), ("pidns", ENTERED[0]), ("mntns", 202),
                         ("mntns", ENTERED[1]), ("netns", 303), ("netns", ENTERED[2]),
                         ("detached_netns", 303), ("netns", True), ("entered_mntns", None)):
            value = receipt()
            value["child"][key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(PROBE.ProbeError):
                PROBE.validate_receipt(value)

    def test_mount_requires_full_private_sysfs_without_children(self):
        target = Path("/run/user/1001/oxibelt-network-test/sys")
        for sb in ("rw", "ro"):
            self.assertEqual(PROBE.validate_sys_mount(mountinfo(target, super_flags=sb), target), 2)
            self.assertEqual(PROBE.validate_sys_mount(
                mountinfo(target, flags="ro,nosuid,nodev,noexec,relatime", super_flags=sb), target), 2)
        for text in (mountinfo(target, root="/devices"), mountinfo(target, flags="rw,nosuid,nodev,noexec"),
                     mountinfo(target, flags="ro,nosuid,nodev"), mountinfo(target, fs="tmpfs"),
                     mountinfo(target, propagation="shared:9"), mountinfo(target, propagation="master:9"),
                     mountinfo(target).replace("/ / rw -", "/ / rw shared:8 -"),
                     mountinfo(target) + f"4 2 0:4 / {target}/class ro - sysfs sysfs rw\n",
                     mountinfo(target) + mountinfo(target), "malformed", "x" * 262145):
            with self.subTest(text=text[:80]), self.assertRaises(PROBE.ProbeError):
                PROBE.validate_sys_mount(text, target)


class ReadonlyTests(unittest.TestCase):
    def proof(self, error=errno.EROFS, *, fd_mount_id=2, token_present=False, mounted_id=2,
              post_present=False, removal_error=None):
        target = Path("/run/user/1001/oxibelt-network-test/sys")
        value = PROBE.child_receipt()
        with contextlib.ExitStack() as stack:
            opened = stack.enter_context(mock.patch.object(PROBE.os, "open", return_value=91))
            close = stack.enter_context(mock.patch.object(PROBE.os, "close"))
            stack.enter_context(mock.patch.object(PROBE.os, "fstat", return_value=mock.Mock(st_mode=stat.S_IFDIR | 0o700)))
            stack.enter_context(mock.patch.object(PROBE.NETWORK, "read_file", side_effect=(f"mnt_id:\t{fd_mount_id}\n".encode(), mountinfo(target).encode())))
            stack.enter_context(mock.patch.object(PROBE, "validate_sys_mount", return_value=mounted_id))
            stack.enter_context(mock.patch.object(PROBE.secrets, "token_hex", return_value="a"*32))
            absent = FileNotFoundError(errno.ENOENT, "absent")
            stat_token = stack.enter_context(mock.patch.object(PROBE.os, "stat", side_effect=(
                [absent, mock.Mock()] if post_present else None if token_present else absent)))
            mkdir = stack.enter_context(mock.patch.object(PROBE.os, "mkdir", side_effect=(OSError(error, "denied") if error else None)))
            rmdir = stack.enter_context(mock.patch.object(PROBE.os, "rmdir", side_effect=removal_error))
            try:
                PROBE.readonly_proof(target, 2, value)
            except PROBE.ProbeError as caught:
                failure = caught
            else:
                failure = None
        return value, failure, opened, close, stat_token, mkdir, rmdir

    def test_erofs_proof_uses_authenticated_rootfd_and_verifies_absence(self):
        value, error, opened, close, stat_token, mkdir, rmdir = self.proof()
        self.assertIsNone(error)
        opened.assert_called_once_with(Path("/run/user/1001/oxibelt-network-test/sys"),
                                       os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        mkdir.assert_called_once_with(".oxibelt-sys-ro-" + "a"*32, mode=0o700, dir_fd=91)
        self.assertEqual(stat_token.call_count, 2)
        self.assertTrue(all(call.kwargs == {"dir_fd": 91, "follow_symlinks": False} for call in stat_token.call_args_list))
        self.assertTrue(value["rootfd_authenticated"] and value["readonly_token_absent"])
        self.assertEqual(value["readonly_errno"], 30)
        rmdir.assert_not_called()
        close.assert_called_once_with(91)

    def test_other_errno_is_not_readonly_proof(self):
        for number in (errno.EPERM, errno.EACCES, errno.ENOENT, errno.ENOSPC):
            value, error, _open, close, _stat, mkdir, rmdir = self.proof(number)
            self.assertEqual(str(error), "readonly-proof-did-not-return-erofs")
            self.assertEqual(value["readonly_errno"], number)
            self.assertFalse(value["readonly_token_absent"])
            mkdir.assert_called_once()
            rmdir.assert_not_called()
            close.assert_called_once_with(91)

    def test_unexpected_success_removes_only_own_token_and_fails(self):
        value, error, _open, close, _stat, mkdir, rmdir = self.proof(0)
        self.assertEqual(str(error), "readonly-proof-unexpectedly-succeeded")
        rmdir.assert_called_once_with(mkdir.call_args.args[0], dir_fd=91)
        self.assertFalse(value["readonly_token_absent"])
        close.assert_called_once_with(91)

    def test_unexpected_success_cleanup_failure_still_fails_closed(self):
        value, error, _open, close, _stat, mkdir, rmdir = self.proof(
            0, removal_error=PermissionError(errno.EPERM, "denied"))
        self.assertEqual(str(error), "readonly-proof-unexpectedly-succeeded")
        rmdir.assert_called_once_with(mkdir.call_args.args[0], dir_fd=91)
        self.assertFalse(value["readonly_token_absent"])
        close.assert_called_once_with(91)

    def test_rootfd_mount_mismatch_never_attempts_write(self):
        for kwargs in ({"fd_mount_id": 3}, {"mounted_id": 3}):
            value, error, _open, close, _stat, mkdir, rmdir = self.proof(**kwargs)
            self.assertEqual(str(error), "fresh-sys-rootfd-mismatch")
            mkdir.assert_not_called()
            rmdir.assert_not_called()
            self.assertFalse(value["rootfd_authenticated"])
            close.assert_called_once_with(91)

    def test_collision_never_attempts_or_removes_existing_token(self):
        _value, error, _open, close, _stat, mkdir, rmdir = self.proof(token_present=True)
        self.assertEqual(str(error), "readonly-token-present")
        mkdir.assert_not_called()
        rmdir.assert_not_called()
        close.assert_called_once_with(91)

    def test_post_attempt_absence_is_required(self):
        value, error, _open, close, _stat, mkdir, rmdir = self.proof(post_present=True)
        self.assertEqual(str(error), "readonly-token-present")
        self.assertEqual(value["readonly_errno"], 30)
        self.assertFalse(value["readonly_token_absent"])
        mkdir.assert_called_once()
        rmdir.assert_not_called()
        close.assert_called_once_with(91)
        with mock.patch.object(PROBE.os, "stat", side_effect=PermissionError(errno.EACCES, "denied")):
            with self.assertRaisesRegex(PROBE.ProbeError, "absence-unavailable"):
                PROBE.token_absent(91, "own-token")


class NamespaceAndNetworkTests(unittest.TestCase):
    def test_launcher_proves_detached_entry_before_unshare(self):
        with mock.patch.object(PROBE.NETWORK, "guarded_state"), mock.patch.object(PROBE, "mapped_root"), \
             mock.patch.object(PROBE.NETWORK, "namespace_id", return_value=505), \
             mock.patch.object(PROBE, "namespace_id", side_effect=(505, 101, 404)), \
             mock.patch.object(PROBE.os, "execvp") as execute:
            PROBE.launch(Path("/run/user/1001/oxibelt-network-test"), PARENTS, (1, 2))
        args = execute.call_args.args[1]
        self.assertEqual(args[:6], ["unshare", "--mount", "--pid", "--net", "--fork", "--propagation=private"])
        self.assertEqual(args[args.index("--detached-netns") + 1], "505")
        self.assertNotIn("--user", args)

    def test_failed_detached_entry_never_unshares(self):
        for current, pinned in ((303, 303), (303, 505), (606, 505)):
            with mock.patch.object(PROBE.NETWORK, "guarded_state"), mock.patch.object(PROBE, "mapped_root"), \
                 mock.patch.object(PROBE.NETWORK, "namespace_id", return_value=pinned), \
                 mock.patch.object(PROBE, "namespace_id", return_value=current), \
                 mock.patch.object(PROBE.os, "execvp") as execute:
                with self.assertRaisesRegex(PROBE.ProbeError, "did-not-enter-detached"):
                    PROBE.launch(Path("/run/user/1001/oxibelt-network-test"), PARENTS, (1, 2))
                execute.assert_not_called()

    def test_network_view_collects_before_observed_default_classifier(self):
        for names in (((1, "lo"),), ((1, "lo"), (2, "gre0"), (3, "gretap0"))):
            output = PROBE.OBSERVER.empty()
            def collect(_target, value, _read):
                value.update(observation(names))
            with mock.patch.object(PROBE.OBSERVER, "collect", side_effect=collect) as collected:
                if len(names) == 1:
                    self.assertEqual(PROBE.network_view(Path("/fresh/sys"), output), [{"index": 1, "name": "lo"}])
                else:
                    with self.assertRaisesRegex(PROBE.ProbeError, "private-network-is-not-network-none"):
                        PROBE.network_view(Path("/fresh/sys"), output)
                collected.assert_called_once()
                self.assertEqual(output, observation(names))

    def test_network_view_accepts_full_actual_inactive_defaults(self):
        output = PROBE.OBSERVER.empty()
        def collect(_target, value, _read):
            value.update(json.loads(json.dumps(NATIVE_OBSERVATION)))
        with mock.patch.object(PROBE.OBSERVER, "collect", side_effect=collect):
            self.assertEqual(PROBE.network_view(Path("/fresh/sys"), output),
                             [{"index": 1, "name": "lo"}, {"index": 2, "name": "ip_vti0"}, {"index": 3, "name": "sit0"}])
        self.assertEqual(output, NATIVE_OBSERVATION)

    def test_wrong_network_view_fails_after_complete_capture(self):
        output = observation()
        output["sys_interfaces"]["interfaces"][0]["index"] = 2
        with mock.patch.object(PROBE.OBSERVER, "collect"), self.assertRaisesRegex(PROBE.ProbeError, "sys-network-view-mismatch"):
            PROBE.network_view(Path("/fresh/sys"), output)
        self.assertEqual(output["socket_interfaces"], [{"index": 1, "name": "lo"}])
        self.assertEqual(output["ip"]["link"][0]["ifname"], "lo")

    def test_mapped_root_rejects_host_root_and_bad_map(self):
        for mapping in (b"0 0 4294967295\n", b"invalid\n", b""):
            with mock.patch.object(PROBE.os, "getuid", return_value=0), \
                 mock.patch.object(PROBE.os, "geteuid", return_value=0), \
                 mock.patch.object(PROBE.NETWORK, "read_file", return_value=mapping), self.assertRaises(PROBE.ProbeError):
                PROBE.mapped_root()


class ChildTests(unittest.TestCase):
    def run_child(self, *, namespaces=(606, 707, 808), pid=1, mount_error=None, proof_error=None,
                  network_error=None, unmount_error=None, remains=False, bad_mount=False, symlink=False,
                  network_observation=None):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            if symlink:
                backing = state / "backing"
                backing.mkdir()
                (state / "link").symlink_to(backing, target_is_directory=True)
                state = state / "link"
            target = (state / "sys").resolve()
            value = PROBE.child_receipt()
            reads = iter((mountinfo(target, root="/devices" if bad_mount else "/").encode(),
                          (mountinfo(target) if remains else BASE + PIN).encode()))
            def proof(_target, _mount_id, output):
                if proof_error:
                    raise proof_error
                output.update(rootfd_authenticated=True, readonly_token_absent=True, readonly_errno=30)
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(PROBE.NETWORK, "guarded_state"))
                stack.enter_context(mock.patch.object(PROBE, "mapped_root"))
                stack.enter_context(mock.patch.object(PROBE, "namespace_id", side_effect=namespaces))
                stack.enter_context(mock.patch.object(PROBE.os, "getpid", return_value=pid))
                stack.enter_context(mock.patch.object(PROBE.NETWORK, "read_file", side_effect=lambda *a: next(reads)))
                mount = stack.enter_context(mock.patch.object(PROBE, "mount_sys", side_effect=mount_error))
                unmount = stack.enter_context(mock.patch.object(PROBE, "unmount_sys", side_effect=unmount_error))
                proof_mock = stack.enter_context(mock.patch.object(PROBE, "readonly_proof", side_effect=proof))
                def collect(_target, output, _read):
                    output.update(json.loads(json.dumps(network_observation)) if network_observation is not None else observation())
                    if network_error:
                        raise network_error
                stack.enter_context(mock.patch.object(PROBE.OBSERVER, "collect", side_effect=collect))
                try:
                    PROBE.child_probe(state, PARENTS, ENTERED, (1, 2), value)
                except PROBE.ProbeError as error:
                    failure = error
                else:
                    failure = None
            exists = target.exists()
        return value, failure, target, mount, unmount, proof_mock, exists

    def test_fresh_sys_mount_readback_unmount_and_disappearance(self):
        value, error, target, mount, unmount, proof, exists = self.run_child()
        self.assertIsNone(error)
        PROBE.validate_child(value, *PARENTS)
        mount.assert_called_once_with(target)
        unmount.assert_called_once_with(target)
        proof.assert_called_once_with(target, 2, value)
        self.assertFalse(exists)

    def test_fresh_child_accepts_and_records_actual_default_interface_pairs(self):
        value, error, target, mount, unmount, proof, exists = self.run_child(network_observation=NATIVE_OBSERVATION)
        self.assertIsNone(error)
        PROBE.validate_child(value, *PARENTS)
        self.assertEqual(value["interfaces"],
                         [{"index": 1, "name": "lo"}, {"index": 2, "name": "ip_vti0"}, {"index": 3, "name": "sit0"}])
        self.assertEqual(value["network_observation"], NATIVE_OBSERVATION)
        self.assertTrue(all(value[key] for key in PROBE.BOOLEAN_FIELDS))
        mount.assert_called_once_with(target)
        unmount.assert_called_once_with(target)
        proof.assert_called_once_with(target, 2, value)
        self.assertFalse(exists)

    def test_copyup_symlink_mountpoint_is_resolved(self):
        value, error, target, mount, unmount, _proof, exists = self.run_child(symlink=True)
        self.assertIsNone(error)
        self.assertIn("backing/sys", str(target))
        mount.assert_called_once_with(target)
        unmount.assert_called_once_with(target)
        self.assertFalse(exists)
        PROBE.validate_child(value, *PARENTS)

    def test_shared_namespaces_or_non_pid_one_never_mount(self):
        for kwargs in ({"namespaces": (101, 707, 808)}, {"namespaces": (606, 404, 808)},
                       {"namespaces": (606, 707, 303)}, {"namespaces": (606, 707, 505)}, {"pid": 2}):
            value, error, _target, mount, unmount, proof, _exists = self.run_child(**kwargs)
            self.assertIsInstance(error, PROBE.ProbeError)
            mount.assert_not_called()
            unmount.assert_not_called()
            proof.assert_not_called()
            self.assertFalse(value["supported"])

    def test_mount_denied_does_not_claim_unmount(self):
        value, error, _target, mount, unmount, proof, exists = self.run_child(mount_error=PROBE.ProbeError("private-sys-mount-denied"))
        self.assertEqual(str(error), "private-sys-mount-denied")
        mount.assert_called_once()
        unmount.assert_not_called()
        proof.assert_not_called()
        self.assertFalse(value["unmounted"] or value["supported"] or exists)

    def test_bad_readback_or_proof_still_normally_unmounts(self):
        for kwargs in ({"bad_mount": True}, {"proof_error": PROBE.ProbeError("readonly-failed")},
                       {"network_error": PROBE.ProbeError("network-failed")}):
            value, error, _target, _mount, unmount, _proof, exists = self.run_child(**kwargs)
            self.assertIsInstance(error, PROBE.ProbeError)
            unmount.assert_called_once()
            self.assertTrue(value["unmounted"])
            self.assertFalse(value["supported"] or exists)

    def test_unmount_failure_or_remaining_mount_fails_closed(self):
        for kwargs, expected in (({"unmount_error": PROBE.ProbeError("private-sys-unmount-failed")}, "private-sys-unmount-failed"),
                                 ({"remains": True}, "private-sys-remains-mounted")):
            value, error, _target, _mount, unmount, _proof, exists = self.run_child(**kwargs)
            self.assertEqual(str(error), expected)
            unmount.assert_called_once()
            self.assertFalse(value["unmounted"] or value["supported"])
            self.assertTrue(exists)

    def test_syscalls_use_exact_flags_and_normal_unmount(self):
        target = Path("/fresh/sys")
        library = mock.Mock()
        library.mount.return_value = library.umount2.return_value = 0
        with mock.patch.object(PROBE.ctypes, "CDLL", return_value=library):
            PROBE.mount_sys(target)
            PROBE.unmount_sys(target)
        self.assertEqual(library.mount.call_args.args, (b"sysfs", b"/fresh/sys", b"sysfs", 15, None))
        self.assertEqual(library.umount2.call_args.args, (b"/fresh/sys", 0))
        for method, operation in ((PROBE.mount_sys, "mount-sys"), (PROBE.unmount_sys, "unmount-sys")):
            library.mount.return_value = library.umount2.return_value = -1
            with mock.patch.object(PROBE.ctypes, "CDLL", return_value=library), \
                 mock.patch.object(PROBE.ctypes, "get_errno", return_value=errno.EPERM), \
                 contextlib.redirect_stderr(io.StringIO()) as log, self.assertRaises(PROBE.ProbeError):
                method(target)
            self.assertEqual(json.loads(log.getvalue()), {"operation": operation, "errno": errno.EPERM})


class ParentTests(unittest.TestCase):
    def parent(self, runtime, commands, *, changed=False, helper_error=None):
        reads = iter((b"unchanged mounts", b"changed mounts" if changed else b"unchanged mounts"))
        def read(path, *args):
            if path == PROBE.MOUNTINFO:
                return next(reads)
            if path == PROBE.IDENTITY_FILE:
                return json.dumps(IDENTITY).encode()
            return b"bounded pinned binary or source"
        original = Path.lstat
        def lstat(path, *args, **kwargs):
            info = original(path, *args, **kwargs)
            return mock.Mock(st_mode=info.st_mode, st_uid=1001, st_dev=info.st_dev, st_ino=info.st_ino)
        value = PROBE.parent_receipt()
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(PROBE, "RUNTIME", runtime))
            stack.enter_context(mock.patch.object(PROBE.NETWORK, "prerequisites", return_value=PROBE.NATIVE_FIELDS))
            stack.enter_context(mock.patch.object(PROBE.NETWORK, "guarded_state"))
            helper = stack.enter_context(mock.patch.object(PROBE.NETWORK, "validate_sys_helper", side_effect=helper_error))
            stack.enter_context(mock.patch.object(PROBE.NETWORK, "read_file", side_effect=read))
            stack.enter_context(mock.patch.object(PROBE, "namespace_id", side_effect=PARENTS))
            stack.enter_context(mock.patch.object(PROBE, "helper_inaccessible"))
            stack.enter_context(mock.patch.object(PROBE.platform, "release", return_value="6.12.42-test"))
            stack.enter_context(mock.patch.object(Path, "lstat", lstat))
            try:
                PROBE.parent_probe(value, commands)
            except PROBE.ProbeError as error:
                failure = error
            else:
                failure = None
        helper.assert_called_once_with("unchanged mounts", required=True)
        return value, failure

    def test_parent_requires_real_helper_before_any_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            commands = mock.Mock(cleanup_confirmed=True)
            value, error = self.parent(Path(directory), commands, helper_error=PROBE.ProbeError("sys-helper-missing-or-duplicate"))
            self.assertEqual(str(error), "sys-helper-missing-or-duplicate")
            commands.call.assert_not_called()
            self.assertFalse(value["supported"])

    def test_invalid_staged_identity_fails_before_commands(self):
        for raw in (b"not-json", b"[]", json.dumps({"GITHUB_SHA": "a"*40}).encode(),
                    json.dumps({**IDENTITY, "SECRET": "redact"}).encode()):
            commands = mock.Mock()
            def read(path, maximum=262144):
                return raw if path == PROBE.IDENTITY_FILE else b"pinned source or binary"
            with self.subTest(raw=raw), \
                 mock.patch.object(PROBE.NETWORK, "prerequisites", return_value=PROBE.NATIVE_FIELDS), \
                 mock.patch.object(PROBE.NETWORK, "read_file", side_effect=read):
                with self.assertRaisesRegex(PROBE.ProbeError, "invalid-workflow-identity"):
                    PROBE.parent_probe(PROBE.parent_receipt(), commands)
                commands.call.assert_not_called()

    def test_parent_exact_rootless_detached_wrapper_and_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            runtime.chmod(0o700)
            commands = mock.Mock(cleanup_confirmed=True)
            commands.call.side_effect = [(0, "rootlesskit version 3.2.0\n"), (0, json.dumps(child()))]
            value, error = self.parent(runtime, commands)
            self.assertIsNone(error)
            PROBE.validate_receipt(value, IDENTITY)
            self.assertEqual(list(runtime.iterdir()), [])
            args = commands.call.call_args.args[0]
            self.assertEqual(args[2:2+len(PROBE.NETWORK.FLAGS)], PROBE.NETWORK.FLAGS)
            tail = args[2+len(PROBE.NETWORK.FLAGS):]
            self.assertEqual(tail[0], "nsenter")
            self.assertTrue(tail[1].startswith("-n" + str(runtime)))
            self.assertIn("--launch", tail)
            self.assertIn("--parent-netns", tail)
            self.assertNotIn("--user", args)

    def test_timeout_or_unconfirmed_group_cleanup_retains_failure(self):
        for confirmed in (True, False):
            with self.subTest(confirmed=confirmed), tempfile.TemporaryDirectory() as directory:
                runtime = Path(directory)
                runtime.chmod(0o700)
                commands = mock.Mock(cleanup_confirmed=confirmed)
                commands.call.side_effect = [(0, "rootlesskit version 3.2.0\n"), PROBE.ProbeError("command-timeout")]
                value, error = self.parent(runtime, commands)
                self.assertEqual(str(error), "command-timeout")
                self.assertEqual(value["cleanup_confirmed"], confirmed)
                self.assertEqual(len(list(runtime.iterdir())), 0 if confirmed else 1)

    def test_mount_change_fails_after_exact_state_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            runtime.chmod(0o700)
            commands = mock.Mock(cleanup_confirmed=True)
            commands.call.side_effect = [(0, "rootlesskit version 3.2.0\n"), (0, json.dumps(child()))]
            value, error = self.parent(runtime, commands, changed=True)
            self.assertEqual(str(error), "sandbox-mounts-changed")
            self.assertFalse(value["parent_mounts_unchanged"])
            self.assertTrue(value["cleanup_confirmed"])
            self.assertEqual(list(runtime.iterdir()), [])

    def test_failed_child_receipt_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            runtime.chmod(0o700)
            failed = PROBE.child_receipt()
            failed["diagnostic"] = "private-sys-mount-denied"
            commands = mock.Mock(cleanup_confirmed=True)
            commands.call.side_effect = [(0, "rootlesskit version 3.2.0\n"), (1, json.dumps(failed))]
            value, error = self.parent(runtime, commands)
            self.assertEqual(str(error), "private-sys-mount-denied")
            self.assertEqual(value["child"], failed)
            self.assertTrue(value["cleanup_confirmed"] and value["parent_mounts_unchanged"])

    def test_non_loopback_and_partial_network_failures_preserve_all_actual_observations(self):
        for partial in (False, True):
            with self.subTest(partial=partial), tempfile.TemporaryDirectory() as directory:
                runtime = Path(directory)
                runtime.chmod(0o700)
                failed = child()
                failed.update(supported=False, interfaces=[], network_view_matches=False,
                              diagnostic="private-network-is-not-network-none",
                              network_observation=observation(((1, "lo"), (2, "gre0"), (3, "gretap0"))))
                if partial:
                    failed["diagnostic"] = "network-observation-timeout"
                    failed["network_observation"]["ip"]["route6"] = None
                    failed["network_observation"]["errors"]["route6"] = "network-observation-timeout"
                commands = mock.Mock(cleanup_confirmed=True)
                commands.call.side_effect = [(0, "rootlesskit version 3.2.0\n"), (1, json.dumps(failed))]
                value, error = self.parent(runtime, commands)
                self.assertEqual(str(error), failed["diagnostic"])
                self.assertEqual(value["child"], failed)
                self.assertFalse(value["supported"])
                self.assertTrue(value["cleanup_confirmed"] and value["parent_mounts_unchanged"])
                self.assertEqual(len(value["child"]["network_observation"]["socket_interfaces"]), 3)

    def test_only_eacces_proves_direct_helper_traversal_denied(self):
        with mock.patch.object(PROBE.os, "open", side_effect=PermissionError(errno.EACCES, "denied")):
            PROBE.helper_inaccessible()
        for error in (FileNotFoundError(errno.ENOENT, "missing"), PermissionError(errno.EPERM, "policy")):
            with mock.patch.object(PROBE.os, "open", side_effect=error), self.assertRaises(PROBE.ProbeError):
                PROBE.helper_inaccessible()
        with mock.patch.object(PROBE.os, "open", return_value=91), mock.patch.object(PROBE.os, "close") as close:
            with self.assertRaisesRegex(PROBE.ProbeError, "accessible-to-runner"):
                PROBE.helper_inaccessible()
            close.assert_called_once_with(91)

    def test_failure_receipt_and_log_are_new_bounded_private_files(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "sys-mount.json"
            commands = mock.Mock(log=bytearray(b"bounded diagnostic"))
            with mock.patch.object(PROBE, "Commands", return_value=commands), \
                 mock.patch.object(PROBE, "parent_probe", side_effect=PROBE.ProbeError("command-timeout")):
                self.assertEqual(PROBE.main(["--output", str(output)]), 1)
                self.assertEqual(json.loads(output.read_text())["diagnostic"], "command-timeout")
                log = output.parent / "sys-mount.log"
                self.assertEqual(log.read_bytes(), b"bounded diagnostic")
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(log.stat().st_mode), 0o600)
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(PROBE.main(["--output", str(output)]), 2)

    def test_internal_modes_missing_bound_ids_fail_with_typed_receipt(self):
        for mode in ("--child", "--launch"):
            with contextlib.redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(PROBE.main([mode, "/run/user/1001/oxibelt-network-test"]), 1)
            value = json.loads(stdout.getvalue())
            self.assertEqual(value["diagnostic"], "missing-parent-namespace-or-state-identity")
            PROBE.validate_child(value, *PARENTS)

    def test_reused_runner_bounds_output_and_kills_exact_timeout_tree(self):
        commands = PROBE.Commands(timeout=.15)
        script = "import os,time; print(os.fork(),flush=True); time.sleep(20)"
        with mock.patch.object(PROBE.NETWORK, "group_members", wraps=PROBE.NETWORK.group_members) as members:
            with self.assertRaisesRegex(PROBE.ProbeError, "command-timeout"):
                commands.call([sys.executable, "-c", script])
        self.assertTrue(commands.cleanup_confirmed)
        self.assertLessEqual(len(commands.log), 65536)
        self.assertEqual(PROBE.NETWORK.group_members(members.call_args.args[0]), [])


if __name__ == "__main__":
    unittest.main()
