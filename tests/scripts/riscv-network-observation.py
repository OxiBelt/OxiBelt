#!/usr/bin/env python3
"""Bounded, read-only network evidence in an already isolated probe child."""
from __future__ import annotations

import json
import os
import re
import selectors
import socket
import subprocess
import time
from pathlib import Path

IP = "/usr/sbin/ip"
MAX_INTERFACES, MAX_ROUTES, MAX_BYTES = 32, 128, 12288
MAX_OBSERVATION = 49152
TIMEOUT = 3
VIEWS = {"link": ["-j", "-details", "link", "show"],
         "address": ["-j", "addr", "show"],
         "route4": ["-j", "-4", "route", "show", "table", "all"],
         "route6": ["-j", "-6", "route", "show", "table", "all"]}
ERRORS = {"network-observation-unavailable", "network-observation-invalid",
          "network-observation-timeout", "network-observation-too-large",
          "network-observation-command-failed"}


class ObservationError(ValueError):
    pass


def empty() -> dict:
    return {"schema_version": 1, "socket_interfaces": None, "sys_interfaces": None,
            "ip": {key: None for key in VIEWS}, "errors": {}}


def valid_index(value) -> bool:
    return type(value) is int and 0 < value <= 2147483647


def valid_name(value) -> bool:
    return (isinstance(value, str) and re.fullmatch(r"[!-~]{1,15}", value) is not None
            and "/" not in value and value not in (".", ".."))


def pairs(items: list, *, sysfs: bool = False, partial: bool = False) -> dict:
    if not isinstance(items, list) or len(items) > MAX_INTERFACES:
        raise ObservationError("network-observation-invalid")
    result, indices = {}, set()
    fields = {"name", "index", "type", "flags"} if sysfs else {"name", "index"}
    for item in items:
        if (not isinstance(item, dict) or set(item) != fields or not valid_name(item["name"])
            or item["name"] in result or (not (partial and item["index"] is None) and not valid_index(item["index"]))
            or (item["index"] is not None and item["index"] in indices)):
            raise ObservationError("network-observation-invalid")
        if sysfs and any(not (partial and item[key] is None)
                         and (type(item[key]) is not int or not 0 <= item[key] <= 4294967295)
                         for key in ("type", "flags")):
            raise ObservationError("network-observation-invalid")
        result[item["name"]] = item["index"]
        if item["index"] is not None:
            indices.add(item["index"])
    return result


def json_shape(value, depth=0, budget=None) -> None:
    """Retain CLI metadata only when every value has bounded safe JSON shape."""
    if budget is None:
        budget = [1024]
    budget[0] -= 1
    if depth > 6 or budget[0] < 0:
        raise ObservationError("network-observation-invalid")
    if value is None or type(value) is bool or (type(value) is int and abs(value) <= 2**63):
        return
    if isinstance(value, str) and len(value) <= 256 and all(32 <= ord(c) <= 126 for c in value):
        return
    if isinstance(value, list) and len(value) <= MAX_ROUTES:
        for item in value:
            json_shape(item, depth + 1, budget)
        return
    if isinstance(value, dict) and len(value) <= 64:
        for key, item in value.items():
            if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", key):
                raise ObservationError("network-observation-invalid")
            json_shape(item, depth + 1, budget)
        return
    raise ObservationError("network-observation-invalid")


def ip_shape(view: str, value) -> dict | None:
    json_shape(value)
    if len(json.dumps(value, separators=(",", ":")).encode()) > MAX_BYTES:
        raise ObservationError("network-observation-too-large")
    if (not isinstance(value, list) or len(value) > (MAX_INTERFACES if view in ("link", "address") else MAX_ROUTES)
        or any(not isinstance(item, dict) for item in value)):
        raise ObservationError("network-observation-invalid")
    if view in ("link", "address"):
        mapping = pairs([{"name": item.get("ifname"), "index": item.get("ifindex")} for item in value])
        for item in value:
            if view == "link" and (not isinstance(item.get("flags"), list)
                or len(item["flags"]) > 32 or any(not isinstance(flag, str) for flag in item["flags"])):
                raise ObservationError("network-observation-invalid")
            if view == "address" and (not isinstance(item.get("addr_info"), list)
                or len(item["addr_info"]) > 32 or any(not isinstance(addr, dict) for addr in item["addr_info"])):
                raise ObservationError("network-observation-invalid")
        return mapping
    if any("dev" in item and not valid_name(item["dev"]) for item in value):
        raise ObservationError("network-observation-invalid")
    return None


def unique_object(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ObservationError("network-observation-invalid")
        result[key] = value
    return result


def ip_snapshot(view: str) -> list:
    """No shell, credentials, stdin, or new session outside the parent's group."""
    deadline = time.monotonic() + TIMEOUT
    try:
        process = subprocess.Popen([IP, *VIEWS[view]], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=False,
            env={"LANG": "C", "LC_ALL": "C"})
    except OSError as error:
        raise ObservationError("network-observation-unavailable") from error
    raw = bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not (events := selector.select(remaining)):
                    raise ObservationError("network-observation-timeout")
                for key, _mask in events:
                    block = os.read(key.fd, MAX_BYTES + 1 - len(raw))
                    if not block:
                        selector.unregister(key.fileobj)
                    else:
                        raw.extend(block)
                        if len(raw) > MAX_BYTES:
                            raise ObservationError("network-observation-too-large")
        try:
            code = process.wait(timeout=max(.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as error:
            raise ObservationError("network-observation-timeout") from error
        if code:
            raise ObservationError("network-observation-command-failed")
        try:
            value = json.loads(raw, object_pairs_hook=unique_object)
        except (ValueError, UnicodeDecodeError, RecursionError) as error:
            raise ObservationError("network-observation-invalid") from error
        ip_shape(view, value)
        return value
    finally:
        try:
            if process.poll() is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired as error:
                raise ObservationError("network-observation-timeout") from error
        finally:
            process.stdout.close()


def validate(value: dict, *, complete=False) -> None:
    if (not isinstance(value, dict) or set(value) != set(empty())
        or type(value["schema_version"]) is not int or value["schema_version"] != 1
        or not isinstance(value["ip"], dict) or set(value["ip"]) != set(VIEWS)
        or not isinstance(value["errors"], dict) or not set(value["errors"]) <= {"socket", "sys", *VIEWS}
        or any(not isinstance(error, str) or error not in ERRORS for error in value["errors"].values())):
        raise ObservationError("network-observation-invalid")
    if value["socket_interfaces"] is not None:
        pairs(value["socket_interfaces"])
    sysfs = value["sys_interfaces"]
    if sysfs is not None:
        if (not isinstance(sysfs, dict) or set(sysfs) != {"names", "interfaces"}
            or not isinstance(sysfs["names"], list) or len(sysfs["names"]) > MAX_INTERFACES
            or any(not valid_name(name) for name in sysfs["names"])
            or len(set(sysfs["names"])) != len(sysfs["names"])
            or set(pairs(sysfs["interfaces"], sysfs=True, partial=not complete)) != set(sysfs["names"])):
            raise ObservationError("network-observation-invalid")
    for view, snapshot in value["ip"].items():
        if snapshot is not None:
            ip_shape(view, snapshot)
    if len(json.dumps(value, separators=(",", ":")).encode()) > MAX_OBSERVATION:
        raise ObservationError("network-observation-too-large")
    if complete and (value["errors"] or value["socket_interfaces"] is None or sysfs is None
                     or any(snapshot is None for snapshot in value["ip"].values())):
        raise ObservationError("network-observation-invalid")


def collect(target: Path, output: dict, read_file) -> None:
    """Attempt every independent view and retain partial evidence on failure."""
    def capture(view, action):
        try:
            action()
        except (OSError, ValueError, UnicodeDecodeError) as error:
            output["errors"][view] = str(error) if isinstance(error, ObservationError) else "network-observation-unavailable"

    def sockets():
        value = [{"index": index, "name": name} for index, name in socket.if_nameindex()]
        pairs(value)
        output["socket_interfaces"] = value

    def sysfs():
        with os.scandir(target / "class/net") as entries:
            names = []
            for entry in entries:
                if len(names) == MAX_INTERFACES:
                    raise ObservationError("network-observation-too-large")
                names.append(entry.name)
        if any(not valid_name(name) for name in names) or len(set(names)) != len(names):
            raise ObservationError("network-observation-invalid")
        value = {"names": sorted(names), "interfaces": [{"name": name, "index": None, "type": None, "flags": None}
                                                        for name in sorted(names)]}
        output["sys_interfaces"] = value
        failure = None
        indices = set()
        for item in value["interfaces"]:
            for field, filename in (("index", "ifindex"), ("type", "type"), ("flags", "flags")):
                try:
                    raw = read_file(target / "class/net" / item["name"] / filename, 32).strip()
                    pattern = rb"0x[0-9a-fA-F]{1,8}" if field == "flags" else rb"[0-9]{1,10}"
                    if not re.fullmatch(pattern, raw):
                        raise ObservationError("network-observation-invalid")
                    number = int(raw, 16 if field == "flags" else 10)
                    if ((field == "index" and (not valid_index(number) or number in indices))
                        or number > 4294967295):
                        raise ObservationError("network-observation-invalid")
                    item[field] = number
                    if field == "index":
                        indices.add(number)
                except (OSError, ValueError, UnicodeDecodeError) as error:
                    failure = failure or (error if isinstance(error, ObservationError)
                                          else ObservationError("network-observation-unavailable"))
        if failure:
            raise failure
        pairs(value["interfaces"], sysfs=True)

    capture("socket", sockets)
    capture("sys", sysfs)
    def cli(view):
        snapshot = ip_snapshot(view)
        output["ip"][view] = snapshot
        # Reserve space for fixed errors in every view and the enclosing receipt.
        if len(json.dumps(output, separators=(",", ":")).encode()) > MAX_OBSERVATION - 512:
            output["ip"][view] = None
            raise ObservationError("network-observation-too-large")
    for view in VIEWS:
        capture(view, lambda view=view: cli(view))
    validate(output)
    if output["errors"]:
        raise ObservationError(next(iter(output["errors"].values())))
    validate(output, complete=True)


def matching_interfaces(value: dict) -> list[dict]:
    validate(value, complete=True)
    mapping = pairs(value["socket_interfaces"])
    if (pairs(value["sys_interfaces"]["interfaces"], sysfs=True) != mapping
        or ip_shape("link", value["ip"]["link"]) != mapping
        or ip_shape("address", value["ip"]["address"]) != mapping):
        raise ObservationError("sys-network-view-mismatch")
    return value["socket_interfaces"]
