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


if __name__ == "__main__":
    unittest.main()
