#!/usr/bin/env python3
"""Read-only bounded network collectors and receipt-shape regressions."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SPEC = importlib.util.spec_from_file_location("observer", Path(__file__).with_name("riscv-network-observation.py"))
assert SPEC and SPEC.loader
OBSERVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OBSERVER)
INTERFACES = [(1, "lo"), (2, "gre0"), (3, "gretap0")]
# Native source: https://github.com/OxiBelt/OxiBelt/actions/runs/38279621761/job/114913439439
# Source revision: 7bdc28ac87946d9ac3ea7b2e1f12184cb354fdd2
# Uploaded ZIP artifact 11769875214 SHA256:
# 11ec6f89090dbe874a0c929e2a7fbf57b904532e69355107dc2a6101c37fb9a8
# Extracted sys-mount.json member SHA256:
# 9751fffddf82d5301e882f72c60823546054aa4e160fc55f8093f944c0820d24
# Fixture content is exactly child.network_observation, without identity fields.
NATIVE_FIXTURE = Path(__file__).with_name("fixtures") / "riscv-network-defaults-rv5.10.json"


def native_observation(names=("lo", "ip_vti0", "sit0")):
    value = json.loads(NATIVE_FIXTURE.read_text())
    value["socket_interfaces"] = [item for item in value["socket_interfaces"] if item["name"] in names]
    value["sys_interfaces"]["names"] = [name for name in value["sys_interfaces"]["names"] if name in names]
    value["sys_interfaces"]["interfaces"] = [item for item in value["sys_interfaces"]["interfaces"] if item["name"] in names]
    for view in ("link", "address"):
        value["ip"][view] = [item for item in value["ip"][view] if item["ifname"] in names]
    return value


def native_interface(value, view, name):
    if view == "sys":
        return next(item for item in value["sys_interfaces"]["interfaces"] if item["name"] == name)
    return next(item for item in value["ip"][view] if item["ifname"] == name)


def snapshots(interfaces=INTERFACES):
    return {"link": [{"ifindex": index, "ifname": name, "flags": ["LOOPBACK"] if name == "lo" else [],
                      "linkinfo": {"info_kind": "gretap" if name == "gretap0" else "gre"}}
                     for index, name in interfaces],
            "address": [{"ifindex": index, "ifname": name, "addr_info": []} for index, name in interfaces],
            "route4": [], "route6": []}


class CollectionTests(unittest.TestCase):
    def collect(self, *, interfaces=INTERFACES, ip=None, sys_names=None, bad_file=None):
        output = OBSERVER.empty()
        values = snapshots(interfaces) if ip is None else ip
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            for index, name in (interfaces if sys_names is None else sys_names):
                net = target / "class/net" / name
                net.mkdir(parents=True)
                for field, raw in (("ifindex", str(index)), ("type", "772" if name == "lo" else "65534"),
                                   ("flags", "0x8" if name == "lo" else "0x0")):
                    (net / field).write_text(raw + "\n")
            if bad_file:
                (target / "class/net" / bad_file[0] / bad_file[1]).write_text(bad_file[2])
            def ip_snapshot(view):
                value = values[view]
                if isinstance(value, Exception):
                    raise value
                OBSERVER.ip_shape(view, value)
                return value
            def read(path, maximum):
                raw = path.read_bytes()
                self.assertLessEqual(len(raw), maximum)
                return raw
            with mock.patch.object(OBSERVER.socket, "if_nameindex", return_value=interfaces), \
                 mock.patch.object(OBSERVER, "ip_snapshot", side_effect=ip_snapshot) as commands:
                try:
                    OBSERVER.collect(target, output, read)
                except OBSERVER.ObservationError as error:
                    failure = error
                else:
                    failure = None
                self.assertEqual([call.args[0] for call in commands.call_args_list], list(OBSERVER.VIEWS))
        return output, failure

    def test_all_actual_views_retained_including_unknown_interfaces(self):
        output, error = self.collect()
        self.assertIsNone(error)
        self.assertEqual(output["socket_interfaces"], [{"index": i, "name": n} for i, n in INTERFACES])
        self.assertEqual(output["sys_interfaces"]["names"], ["gre0", "gretap0", "lo"])
        self.assertEqual({i["name"]: (i["index"], i["type"], i["flags"])
                          for i in output["sys_interfaces"]["interfaces"]},
                         {"lo": (1, 772, 8), "gre0": (2, 65534, 0), "gretap0": (3, 65534, 0)})
        self.assertEqual(output["ip"], snapshots())
        self.assertEqual(OBSERVER.matching_interfaces(output), output["socket_interfaces"])

    def test_parity_compares_maps_independent_of_order(self):
        output, error = self.collect(interfaces=list(reversed(INTERFACES)))
        self.assertIsNone(error)
        output["ip"]["link"].reverse()
        output["ip"]["address"].reverse()
        OBSERVER.matching_interfaces(output)

    def test_every_cli_failure_preserves_other_views(self):
        for view in OBSERVER.VIEWS:
            for reason in OBSERVER.ERRORS:
                values = snapshots()
                values[view] = OBSERVER.ObservationError(reason)
                with self.subTest(view=view, reason=reason):
                    output, error = self.collect(ip=values)
                    self.assertEqual(str(error), reason)
                    OBSERVER.validate(output)
                    self.assertEqual(output["errors"], {view: reason})
                    self.assertIsNone(output["ip"][view])
                    self.assertIsNotNone(output["socket_interfaces"])
                    self.assertIsNotNone(output["sys_interfaces"])
                    self.assertTrue(all(snapshot is not None for key, snapshot in output["ip"].items() if key != view))
                    with self.assertRaises(OBSERVER.ObservationError):
                        OBSERVER.matching_interfaces(output)

    def test_sys_read_failure_keeps_names_and_remaining_metadata(self):
        output, error = self.collect(bad_file=("gre0", "type", "malformed\n"))
        self.assertEqual(str(error), "network-observation-invalid")
        OBSERVER.validate(output)
        self.assertEqual(output["sys_interfaces"]["names"], ["gre0", "gretap0", "lo"])
        self.assertEqual(output["sys_interfaces"]["interfaces"][0],
                         {"index": 2, "name": "gre0", "type": None, "flags": 0})
        self.assertEqual(output["sys_interfaces"]["interfaces"][1]["index"], 3)
        self.assertEqual(output["ip"], snapshots())

    def test_wrong_parity_never_qualifies(self):
        for view in ("sys", "link", "address"):
            output, error = self.collect()
            self.assertIsNone(error)
            if view == "sys":
                output["sys_interfaces"]["interfaces"][0]["index"] = 9
            else:
                output["ip"][view][0]["ifindex"] = 9
            with self.subTest(view=view), self.assertRaisesRegex(OBSERVER.ObservationError, "sys-network-view-mismatch"):
                OBSERVER.matching_interfaces(output)

    def test_duplicate_socket_pairs_and_collection_limit_fail_closed(self):
        for interfaces in ([(1, "lo"), (1, "eth0")], [(1, "lo"), (2, "lo")],
                           [(i + 1, "net" + str(i)) for i in range(33)]):
            output, error = self.collect(interfaces=interfaces, sys_names=[(1, "lo")], ip=snapshots([(1, "lo")]))
            self.assertIsNotNone(error)
            OBSERVER.validate(output)
            self.assertIsNone(output["socket_interfaces"])
            self.assertIsNotNone(output["sys_interfaces"])
            self.assertIsNotNone(output["ip"]["link"])

    def test_sys_interface_limit_is_fail_closed_with_other_views(self):
        output, error = self.collect(interfaces=[(1, "lo")],
                                    sys_names=[(i + 1, "net" + str(i)) for i in range(33)])
        self.assertEqual(str(error), "network-observation-too-large")
        OBSERVER.validate(output)
        self.assertIsNone(output["sys_interfaces"])
        self.assertIsNotNone(output["socket_interfaces"])
        self.assertIsNotNone(output["ip"]["route6"])

    def test_aggregate_limit_retains_prior_views_with_default_json_envelope_space(self):
        interfaces = [(1, "lo")] + [(i + 1, "net" + str(i)) for i in range(1, 32)]
        values = snapshots(interfaces)
        values["route4"] = [{}]
        values["route6"] = [{}]
        for records in values.values():
            for number in range(64):
                remaining = OBSERVER.MAX_BYTES - len(json.dumps(records).encode()) - 24
                if remaining <= 0:
                    break
                records[0]["metadata_" + str(number)] = "x" * min(256, remaining)
            self.assertLessEqual(len(json.dumps(records).encode()), OBSERVER.MAX_BYTES)
        output, error = self.collect(interfaces=interfaces, ip=values)
        self.assertEqual(str(error), "network-observation-too-large")
        OBSERVER.validate(output)
        self.assertEqual(output["errors"], {"route6": "network-observation-too-large"})
        self.assertIsNotNone(output["ip"]["link"])
        self.assertIsNotNone(output["ip"]["address"])
        self.assertIsNotNone(output["ip"]["route4"])
        self.assertIsNone(output["ip"]["route6"])
        # The real enclosing Sys receipt contributes less than this reserve.
        envelope = {"child": {"network_observation": output}, "other_receipt_fields": "x" * 8192}
        self.assertLess(len(json.dumps(envelope).encode()), 65536)


class CommandTests(unittest.TestCase):
    def run_script(self, script, *, timeout=1):
        processes = []
        original = subprocess.Popen
        def launch(*args, **kwargs):
            process = original(*args, **kwargs)
            processes.append(process)
            return process
        with mock.patch.object(OBSERVER, "IP", sys.executable), \
             mock.patch.dict(OBSERVER.VIEWS, {"link": ["-c", script]}), \
             mock.patch.object(OBSERVER, "TIMEOUT", timeout), \
             mock.patch.object(OBSERVER.subprocess, "Popen", side_effect=launch) as spawned:
            try:
                value = OBSERVER.ip_snapshot("link")
            except OBSERVER.ObservationError as error:
                result = str(error)
            else:
                result = value
        self.assertEqual(len(processes), 1)
        self.assertIsNotNone(processes[0].poll())
        self.assertTrue(processes[0].stdout.closed)
        return result, spawned.call_args

    def test_absolute_argv_explicit_environment_and_parent_process_group(self):
        result, call = self.run_script('import json; print(json.dumps([{ "ifindex": 1, "ifname": "lo", "flags": []}]))')
        self.assertEqual(result, [{"ifindex": 1, "ifname": "lo", "flags": []}])
        self.assertEqual(call.args[0][0], sys.executable)
        self.assertEqual(call.kwargs["env"], {"LANG": "C", "LC_ALL": "C"})
        self.assertIs(call.kwargs["start_new_session"], False)
        self.assertNotIn("shell", call.kwargs)
        self.assertEqual(call.kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(call.kwargs["stderr"], subprocess.DEVNULL)
        self.assertEqual(OBSERVER.IP, "/usr/sbin/ip")
        self.assertEqual(OBSERVER.VIEWS["link"], ["-j", "-details", "link", "show"])
        self.assertEqual(OBSERVER.VIEWS["route6"], ["-j", "-6", "route", "show", "table", "all"])

    def test_actual_timeout_and_output_limit_kill_child(self):
        for script, timeout, reason in (("import time;time.sleep(20)", .05, "network-observation-timeout"),
            ("import sys,time;sys.stdout.write('x'*12289);sys.stdout.flush();time.sleep(20)", 1,
             "network-observation-too-large")):
            with self.subTest(reason=reason):
                result, _call = self.run_script(script, timeout=timeout)
                self.assertEqual(result, reason)

    def test_invalid_json_duplicate_keys_and_nonzero_are_fixed_diagnostics(self):
        for raw in ("not json", '{"secret":"must-not-appear"}', '[{"ifindex":1,"ifindex":2,"ifname":"lo","flags":[]}]',
                    '[{"ifindex":true,"ifname":"lo","flags":[]}]'):
            result, _call = self.run_script("print(" + repr(raw) + ")")
            self.assertEqual(result, "network-observation-invalid")
        result, _call = self.run_script("import sys;print('must-not-appear', file=sys.stderr);sys.exit(3)")
        self.assertEqual(result, "network-observation-command-failed")


class ShapeTests(unittest.TestCase):
    def test_metadata_limits_and_untyped_values_are_rejected(self):
        for view, value in (("link", [{"ifindex": 1, "ifname": "lo", "flags": []}] * 2),
                            ("address", [{"ifindex": 1, "ifname": "lo", "addr_info": [None]}]),
                            ("route4", [{"dev": "bad/name"}]), ("route6", [{}] * 129),
                            ("route4", [{"dev": ".."}]),
                            ("link", [{"ifindex": 1, "ifname": "lo", "flags": [], "secret": "bad\nvalue"}]),
                            ("route4", [{"x": "x" * 257}]), ("route4", [{"x": 1.5}])):
            with self.subTest(view=view), self.assertRaises(OBSERVER.ObservationError):
                OBSERVER.ip_shape(view, value)
        with self.assertRaisesRegex(OBSERVER.ObservationError, "network-observation-too-large"):
            OBSERVER.ip_shape("route4", [{"metadata": "x" * 256}] * 64)

    def test_schema_and_fixed_errors_are_exact_and_partial_cannot_succeed(self):
        for key, value in (("schema_version", True), ("schema_version", 2), ("errors", {"route4": "raw secret"}),
                           ("errors", {"route4": []}), ("errors", {"unknown": "network-observation-invalid"}),
                           ("socket_interfaces", [{"index": 1, "name": "lo", "extra": 3}])):
            output = OBSERVER.empty()
            output[key] = value
            with self.subTest(key=key), self.assertRaises(OBSERVER.ObservationError):
                OBSERVER.validate(output)
        OBSERVER.validate(OBSERVER.empty())
        with self.assertRaises(OBSERVER.ObservationError):
            OBSERVER.validate(OBSERVER.empty(), complete=True)


class NetworkNoneTests(unittest.TestCase):
    def assert_rejected(self, value):
        with self.assertRaises(OBSERVER.ObservationError):
            OBSERVER.network_none_interfaces(value)

    def test_sanitized_verified_native_fixture_and_only_observed_subsets_pass(self):
        self.assertEqual(OBSERVER.network_none_interfaces(native_observation()),
                         [{"index": 1, "name": "lo"}, {"index": 2, "name": "ip_vti0"}, {"index": 3, "name": "sit0"}])
        for names, expected in ((("lo",), [{"index": 1, "name": "lo"}]),
                                (("lo", "ip_vti0"), [{"index": 1, "name": "lo"}, {"index": 2, "name": "ip_vti0"}]),
                                (("lo", "sit0"), [{"index": 1, "name": "lo"}, {"index": 3, "name": "sit0"}])):
            with self.subTest(names=names):
                self.assertEqual(OBSERVER.network_none_interfaces(native_observation(names)), expected)
        self.assertEqual(set(json.loads(NATIVE_FIXTURE.read_text())), set(OBSERVER.empty()))
        self.assertEqual(set(OBSERVER.INACTIVE_DEFAULTS), {"ip_vti0", "sit0"})

    def test_profile_builders_do_not_alias_the_fixed_default_policy(self):
        profile, _address = OBSERVER.inactive_profile("sit0", 3)
        profile["linkinfo"]["info_data"]["ttl"] = 1
        self.assertEqual(OBSERVER.INACTIVE_DEFAULTS["sit0"]["info_data"]["ttl"], 64)
        self.assertEqual(len(OBSERVER.network_none_interfaces(native_observation())), 3)

    def test_orders_do_not_affect_classification_or_canonical_receipt(self):
        value = native_observation()
        expected = [{"index": 1, "name": "lo"}, {"index": 2, "name": "ip_vti0"}, {"index": 3, "name": "sit0"}]
        value["socket_interfaces"].reverse()
        value["sys_interfaces"]["names"].reverse()
        value["sys_interfaces"]["interfaces"].reverse()
        value["ip"]["link"].reverse()
        value["ip"]["address"].reverse()
        self.assertEqual(OBSERVER.network_none_interfaces(value), expected)

    def test_lower_link_absent_or_null_is_the_only_optional_field(self):
        for view in ("link", "address"):
            for name in ("lo", "ip_vti0", "sit0"):
                value = native_observation()
                native_interface(value, view, name).pop("link", None)
                self.assertEqual(len(OBSERVER.network_none_interfaces(value)), 3)
                native_interface(value, view, name)["link"] = None
                self.assertEqual(len(OBSERVER.network_none_interfaces(value)), 3)

    def test_only_lo_index_is_fixed_but_all_maps_must_agree(self):
        value = native_observation(("lo", "sit0"))
        for item in value["socket_interfaces"]:
            if item["name"] == "sit0":
                item["index"] = 2
        native_interface(value, "sys", "sit0")["index"] = 2
        for view in ("link", "address"):
            native_interface(value, view, "sit0")["ifindex"] = 2
        self.assertEqual(OBSERVER.network_none_interfaces(value), [{"index": 1, "name": "lo"}, {"index": 2, "name": "sit0"}])
        self.assert_rejected(native_observation(("sit0", "ip_vti0")))
        value = native_observation()
        value["socket_interfaces"][0]["index"] = 9
        native_interface(value, "sys", "lo")["index"] = 9
        for view in ("link", "address"):
            native_interface(value, view, "lo")["ifindex"] = 9
        self.assert_rejected(value)

    def test_unknown_names_are_not_admitted_by_matching_safe_metadata(self):
        for name in ("eth0", "veth0", "tunl0", "gre0", "ip6tnl0", "ip6_vti0", "sit1", "ip_vti1"):
            value = native_observation()
            for item in value["socket_interfaces"] + value["sys_interfaces"]["interfaces"]:
                if item["name"] == "ip_vti0":
                    item["name"] = name
            value["sys_interfaces"]["names"] = [name if old == "ip_vti0" else old for old in value["sys_interfaces"]["names"]]
            for view in ("link", "address"):
                native_interface(value, view, "ip_vti0")["ifname"] = name
            OBSERVER.matching_interfaces(value)
            with self.subTest(name=name):
                self.assert_rejected(value)

    def test_wrong_names_types_kinds_and_any_active_flag_are_rejected(self):
        for name in ("lo", "ip_vti0", "sit0"):
            for field, bad_values in (("type", (1, 772, 768, 776, True)),
                                      ("flags", (0, 1, 8, 128, 129, 256, 65664, True))):
                original = native_interface(native_observation(), "sys", name)[field]
                for bad in bad_values:
                    if type(bad) is int and bad == original:
                        continue
                    value = native_observation()
                    native_interface(value, "sys", name)[field] = bad
                    with self.subTest(name=name, field=field, bad=bad):
                        self.assert_rejected(value)
            for view in ("link", "address"):
                for field, bad in (("flags", []), ("flags", ["NOARP", "UP"]),
                                   ("flags", ["NOARP", "LOWER_UP"]), ("flags", ["POINTOPOINT"]),
                                   ("flags", ["NOARP", "RUNNING"]), ("operstate", "UP"),
                                   ("link_type", "ether"), ("mtu", True)):
                    value = native_observation()
                    native_interface(value, view, name)[field] = bad
                    with self.subTest(name=name, view=view, field=field, bad=bad):
                        self.assert_rejected(value)
        for name, kind in (("ip_vti0", "sit"), ("sit0", "vti"), ("sit0", "gre")):
            value = native_observation()
            native_interface(value, "link", name)["linkinfo"]["info_kind"] = kind
            self.assert_rejected(value)

    def test_addresses_and_routes_in_any_table_reject_every_device(self):
        for name in ("lo", "ip_vti0", "sit0"):
            value = native_observation()
            native_interface(value, "address", name)["addr_info"] = [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}]
            self.assert_rejected(value)
        for view, route in (("route4", {"dst": "default", "dev": "ip_vti0"}),
                            ("route4", {"dst": "127.0.0.1", "dev": "lo", "table": "local"}),
                            ("route6", {"dst": "::1", "dev": "lo", "table": 999}),
                            ("route6", {"dst": "default", "type": "unreachable", "table": "default"})):
            value = native_observation()
            value["ip"][view] = [route]
            self.assert_rejected(value)

    def test_parent_master_peer_and_link_fields_fail_even_when_null(self):
        for name in ("lo", "ip_vti0", "sit0"):
            for view in ("link", "address"):
                for field in ("master", "parent", "peer", "link_index", "link_netnsid", "link_netns", "ifalias"):
                    for bad in (None, 0, "lo", {"ifindex": 9}):
                        value = native_observation()
                        native_interface(value, view, name)[field] = bad
                        with self.subTest(name=name, view=view, field=field, bad=bad):
                            self.assert_rejected(value)
                for bad in (0, False, "lo", 1):
                    value = native_observation()
                    native_interface(value, view, name)["link"] = bad
                    self.assert_rejected(value)

    def test_tunnel_keys_marks_metadata_encapsulation_and_endpoints_fail(self):
        for name in ("ip_vti0", "sit0"):
            for field in ("ikey", "okey", "fwmark", "collect_metadata", "metadata", "encap", "encap_type", "dev",
                          "6rd_prefix", "6rd_relay_prefix", "isatap", "tos"):
                for bad in (0, False, "0", {"type": "fou"}):
                    value = native_observation()
                    native_interface(value, "link", name)["linkinfo"]["info_data"][field] = bad
                    with self.subTest(name=name, field=field, bad=bad):
                        self.assert_rejected(value)
            for field in ("local", "remote"):
                for bad in ("0.0.0.0", "192.0.2.1", "::", None):
                    value = native_observation()
                    native_interface(value, "link", name)["linkinfo"]["info_data"][field] = bad
                    self.assert_rejected(value)
        for field, bad in (("proto", "ipip"), ("proto", 41), ("ttl", 0), ("ttl", 63), ("ttl", True),
                           ("pmtudisc", 0), ("pmtudisc", True), ("pmtudisc", "false")):
            value = native_observation()
            native_interface(value, "link", "sit0")["linkinfo"]["info_data"][field] = bad
            with self.subTest(field=field, bad=bad):
                self.assert_rejected(value)

    def test_missing_or_unknown_metadata_and_incomplete_views_fail(self):
        for name in ("lo", "ip_vti0", "sit0"):
            for view in ("link", "address"):
                record = native_interface(native_observation(), view, name)
                for field in set(record) - {"link"}:
                    value = native_observation()
                    del native_interface(value, view, name)[field]
                    with self.subTest(name=name, view=view, missing=field):
                        self.assert_rejected(value)
                value = native_observation()
                native_interface(value, view, name)["unknown_metadata"] = False
                self.assert_rejected(value)
            if name != "lo":
                for field in native_interface(native_observation(), "link", name)["linkinfo"]["info_data"]:
                    value = native_observation()
                    del native_interface(value, "link", name)["linkinfo"]["info_data"][field]
                    self.assert_rejected(value)
                for field in ("info_kind", "info_data"):
                    value = native_observation()
                    del native_interface(value, "link", name)["linkinfo"][field]
                    self.assert_rejected(value)
                value = native_observation()
                native_interface(value, "link", name)["linkinfo"]["info_slave_kind"] = "bridge"
                self.assert_rejected(value)
        for view in OBSERVER.VIEWS:
            value = native_observation()
            value["ip"][view] = None
            self.assert_rejected(value)
        value = native_observation()
        value["errors"]["route4"] = "network-observation-timeout"
        self.assert_rejected(value)
        value = native_observation()
        native_interface(value, "address", "ip_vti0")["ifindex"] = 9
        self.assert_rejected(value)


if __name__ == "__main__":
    unittest.main()
