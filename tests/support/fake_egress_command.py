#!/usr/bin/env python3
"""Unprivileged fake networking commands for D1-B3 shell fault-injection tests.

This is a TEST DOUBLE. It never runs ip/wg/iptables/sysctl/ss. Every invocation
is recorded into a JSON file provided by NVL_FAKE_STATE. It must never be
installed on a server or used as a production diagnostic.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def _is(command, *prefix):
    return command[:len(prefix)] == list(prefix)


def main() -> int:
    cmd = Path(sys.argv[0]).name
    args = sys.argv[1:]
    source = os.environ.get("NVL_FAKE_STATE")
    if not source:
        print("NVL_FAKE_STATE not set", file=sys.stderr)
        return 125
    file = Path(source)
    state = json.loads(file.read_text())
    signature = " ".join([cmd] + args)

    state.setdefault("calls", []).append(signature)
    state.setdefault("links", {"wg0": "root", "eth0": "root"})
    state.setdefault("namespaces", [])
    state.setdefault("rules", ["BASELINE:wg0"])
    state.setdefault("nest_rules", [])

    failure = os.environ.get("NVL_FAKE_FAIL_CONTAINS")
    if failure and not state.get("failed_once") and failure in signature:
        state["failed_once"] = True
        file.write_text(json.dumps(state))
        print("SIMULATED FAILURE: " + signature, file=sys.stderr)
        return 70

    code = 0
    output = ""
    if cmd == "sysctl":
        if _is(args, "-n", "net.ipv4.ip_forward"):
            output = "1\n"
        else:
            code = 2
    elif cmd == "ss":
        if state.get("port_busy"):
            output = "UNCONN 0 0 0.0.0.0:51832 0.0.0.0:*\n"
    elif cmd == "wg":
        if args[:1] == ["setconf"] and len(args) == 3:
            if args[1] not in state["links"] or not Path(args[2]).is_file():
                code = 1
        else:
            code = 2
    elif cmd == "iptables":
        action = "-A" if "-A" in args else ("-D" if "-D" in args else None)
        if not action:
            code = 2
        else:
            canonical = " ".join(args).replace(" -A ", " -A ").replace(" -D ", " -A ")
            if action == "-A":
                state["rules"].append(canonical)
            elif canonical in state["rules"]:
                state["rules"].remove(canonical)
            else:
                code = 1
    elif cmd == "ip":
        if _is(args, "-o", "-4", "route", "get"):
            output = "1.1.1.1 via 10.0.0.1 dev eth0 src 172.86.94.174\n"
        elif _is(args, "netns", "list"):
            output = "".join(x + "\n" for x in state["namespaces"])
        elif _is(args, "netns", "add"):
            if args[2] in state["namespaces"]:
                code = 1
            else:
                state["namespaces"].append(args[2])
        elif _is(args, "netns", "del"):
            name = args[2]
            if name not in state["namespaces"]:
                code = 1
            else:
                state["namespaces"].remove(name)
                state["links"] = {k: v for k, v in state["links"].items() if v != name}
                state["nest_rules"] = [r for r in state["nest_rules"] if r["ns"] != name]
        elif _is(args, "netns", "exec"):
            name = args[2]
            if name not in state["namespaces"]:
                code = 1
            else:
                state["nest_rules"].append({"ns": name, "cmd": " ".join(args[3:])})
        elif _is(args, "link", "show"):
            iface = args[-1]
            if state["links"].get(iface) != "root":
                code = 1
        elif _is(args, "link", "add"):
            # ip link add dev wg-nvl-x type wireguard
            # ip link add vnh-x type veth peer name vnn-x
            iface = args[3] if "dev" in args[:3] else args[2]
            if iface in state["links"]:
                code = 1
            else:
                state["links"][iface] = "root"
                if "peer" in args:
                    peer = args[args.index("name") + 1]
                    state["links"][peer] = "root"
        elif _is(args, "link", "del"):
            iface = args[2]
            if iface not in state["links"]:
                code = 1
            else:
                del state["links"][iface]
                if iface.startswith("vnh-"):
                    state["links"].pop(iface.replace("vnh-", "vnn-", 1), None)
        elif _is(args, "link", "set"):
            # ip link set IFACE netns NS; other link-set operations are no-op
            if "netns" in args:
                iface = args[2]
                name = args[args.index("netns") + 1]
                if name not in state["namespaces"] or iface not in state["links"]:
                    code = 1
                else:
                    state["links"][iface] = name
        elif _is(args, "-4", "addr", "add"):
            if args[-1] not in state["links"]:
                code = 1
        else:
            # ip link set dev eth0 up and other safe mock operations
            if not args:
                code = 2
    else:
        code = 2

    file.write_text(json.dumps(state))
    if output:
        sys.stdout.write(output)
    return code


if __name__ == "__main__":
    sys.exit(main())
