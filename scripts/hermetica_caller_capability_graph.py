#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

REPO = Path(os.environ.get("HERMETICA_REPO", "/tmp/hermetica-contracts"))
HEAD = os.environ.get("HERMETICA_HEAD", "5e13e431f69dd840fe297791fa2a73d9993a27e0")
ROLE_LEDGER = Path("public-data/hermetica-role-ledger.json")
OUT = Path("public-data/hermetica-caller-capability-graph.json")
DEPLOYER = "SP1S1HSFH0SQQGWKB69EYFNY0B1MHRMGXR3J1FH4D"

CONTRACTS: dict[str, dict[str, str]] = {
    "hq": {"path": "mainnet/contracts/hbtc/protocol/hq-v1.clar", "id": f"{DEPLOYER}.hq-hbtc-v1"},
    "blacklist": {"path": "mainnet/contracts/hbtc/protocol/blacklist-v1.clar", "id": f"{DEPLOYER}.blacklist-hbtc-v1"},
    "token": {"path": "mainnet/contracts/hbtc/tokens/token-hbtc.clar", "id": f"{DEPLOYER}.token-hbtc"},
    "state": {"path": "mainnet/contracts/hbtc/protocol/state-v1.clar", "id": f"{DEPLOYER}.state-hbtc-v1"},
    "reserve-fund": {"path": "mainnet/contracts/hbtc/protocol/reserve-fund-v1.clar", "id": f"{DEPLOYER}.reserve-fund-hbtc-v1"},
    "reserve": {"path": "mainnet/contracts/hbtc/protocol/reserve-v1.clar", "id": f"{DEPLOYER}.reserve-hbtc-v1"},
    "controller": {"path": "mainnet/contracts/hbtc/protocol/controller-v1.clar", "id": f"{DEPLOYER}.controller-hbtc-v1"},
    "fee-collector": {"path": "mainnet/contracts/hbtc/protocol/fee-collector-v1.clar", "id": f"{DEPLOYER}.fee-collector-hbtc-v1"},
    "hermetica-interface": {"path": "mainnet/contracts/hbtc/protocol/interfaces/hermetica-interface-v1.clar", "id": f"{DEPLOYER}.hermetica-interface-hbtc-v1"},
    "zest-interface": {"path": "mainnet/contracts/hbtc/protocol/interfaces/zest-interface-v1.clar", "id": f"{DEPLOYER}.zest-interface-hbtc-v1"},
    "trading": {"path": "mainnet/contracts/hbtc/protocol/trading-v1.clar", "id": f"{DEPLOYER}.trading-hbtc-v1"},
    "vault": {"path": "mainnet/contracts/hbtc/protocol/vault-v1-2.clar", "id": f"{DEPLOYER}.vault-hbtc-v1-2"},
}

ALIASES = {
    "hq-hbtc": "hq",
    "blacklist": "blacklist",
    "token-hbtc": "token",
    "state": "state",
    "reserve-fund": "reserve-fund",
    "reserve": "reserve",
    "controller-hbtc": "controller",
    "fee-collector": "fee-collector",
    "hermetica-interface": "hermetica-interface",
    "zest-interface": "zest-interface",
    "trading": "trading",
    "vault": "vault",
}

FUNCTION_RE = re.compile(r"^\(define-(public|private|read-only)\s+\(([^\s()]+)")
STATIC_CALL_RE = re.compile(r"\(contract-call\?\s+\.([A-Za-z0-9-]+)\s+([A-Za-z0-9-]+)")
DYNAMIC_CALL_RE = re.compile(r"\(contract-call\?\s+([A-Za-z0-9-]+)\s+([A-Za-z0-9-]+)")
ROLE_RE = re.compile(
    r"check-is-(owner|guardian|trader|rewarder|manager|fee-setter|protocol)\s+contract-caller"
)


def source(path: str) -> str:
    file_path = REPO / path
    if not file_path.exists():
        raise FileNotFoundError(file_path)
    return file_path.read_text(encoding="utf-8")


def strip_comments(text: str) -> str:
    out: list[str] = []
    for line in text.splitlines():
        in_string = False
        escaped = False
        cut = len(line)
        i = 0
        while i < len(line):
            ch = line[i]
            if in_string:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_string = False
                i += 1
                continue
            if ch == '"':
                in_string = True
                i += 1
                continue
            if line.startswith(";;", i):
                cut = i
                break
            i += 1
        cleaned = line[:cut].strip()
        if cleaned:
            out.append(cleaned)
    return "\n".join(out)


def top_level_forms(text: str) -> list[str]:
    src = strip_comments(text)
    forms: list[str] = []
    depth = 0
    start: int | None = None
    in_string = False
    escaped = False
    for i, ch in enumerate(src):
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
            continue
        if ch == "(":
            if depth == 0:
                start = i
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                raise ValueError("unbalanced closing parenthesis")
            if depth == 0 and start is not None:
                forms.append(src[start : i + 1])
                start = None
    if depth != 0:
        raise ValueError("unbalanced source")
    return forms


def normalize(form: str) -> str:
    return re.sub(r"\s+", " ", form).strip()


def parse_functions(text: str) -> dict[str, dict[str, Any]]:
    functions: dict[str, dict[str, Any]] = {}
    for form in top_level_forms(text):
        norm = normalize(form)
        match = FUNCTION_RE.match(norm)
        if not match:
            continue
        kind, name = match.groups()
        functions[name] = {
            "kind": kind,
            "normalized": norm,
            "sha256": hashlib.sha256(norm.encode()).hexdigest(),
            "direct_roles": sorted(set(ROLE_RE.findall(norm))),
            "static_calls": [
                {"alias": alias, "function": fn}
                for alias, fn in STATIC_CALL_RE.findall(norm)
            ],
            "dynamic_calls": [
                {"target": target, "function": fn}
                for target, fn in DYNAMIC_CALL_RE.findall(norm)
                if not target.startswith(".")
            ],
        }
        if "check-is-protocol-two contract-caller" in norm:
            functions[name]["direct_roles"] = sorted(
                set(functions[name]["direct_roles"]) | {"protocol"}
            )
    names = set(functions)
    for name, item in functions.items():
        local_calls: list[str] = []
        norm = item["normalized"]
        for candidate in names:
            if candidate == name:
                continue
            if re.search(rf"\({re.escape(candidate)}(?:\s|\))", norm):
                local_calls.append(candidate)
        item["local_calls"] = sorted(local_calls)
        item["effective_roles"] = list(item["direct_roles"])

    changed = True
    while changed:
        changed = False
        for item in functions.values():
            roles = set(item["effective_roles"])
            for called in item["local_calls"]:
                roles.update(functions[called]["effective_roles"])
            new = sorted(roles)
            if new != item["effective_roles"]:
                item["effective_roles"] = new
                changed = True
    return functions


def main() -> None:
    ledger = json.loads(ROLE_LEDGER.read_text(encoding="utf-8"))
    roles_by_address: dict[str, list[str]] = ledger.get("roles_by_address") or {}

    parsed: dict[str, dict[str, Any]] = {}
    for label, meta in CONTRACTS.items():
        parsed[label] = parse_functions(source(meta["path"]))

    edges: list[dict[str, Any]] = []
    mismatches: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []

    for caller_label, functions in parsed.items():
        caller_id = CONTRACTS[caller_label]["id"]
        caller_roles = set(roles_by_address.get(caller_id, []))
        for caller_fn, item in functions.items():
            for call in item["static_calls"]:
                alias = call["alias"]
                callee_fn = call["function"]
                callee_label = ALIASES.get(alias)
                edge: dict[str, Any] = {
                    "caller_contract": caller_label,
                    "caller_contract_id": caller_id,
                    "caller_function": caller_fn,
                    "callee_alias": alias,
                    "callee_function": callee_fn,
                    "caller_active_roles": sorted(caller_roles),
                }
                if callee_label is None or callee_fn not in parsed.get(callee_label, {}):
                    edge["resolved"] = False
                    edges.append(edge)
                    continue
                required = set(parsed[callee_label][callee_fn]["effective_roles"])
                missing = sorted(required - caller_roles)
                edge.update(
                    {
                        "resolved": True,
                        "callee_contract": callee_label,
                        "callee_contract_id": CONTRACTS[callee_label]["id"],
                        "callee_required_immediate_caller_roles": sorted(required),
                        "missing_roles": missing,
                    }
                )
                edges.append(edge)
                # HQ check functions pass a principal argument and are not role requirements
                # on the immediate caller contract itself; their semantics are already folded
                # into direct_roles of the calling function.
                if callee_label != "hq" and missing:
                    mismatches.append(edge)
            for call in item["dynamic_calls"]:
                unresolved.append(
                    {
                        "caller_contract": caller_label,
                        "caller_contract_id": caller_id,
                        "caller_function": caller_fn,
                        "target_variable": call["target"],
                        "callee_function": call["function"],
                    }
                )

    payload = {
        "target_commit": HEAD,
        "role_ledger_sha256": hashlib.sha256(ROLE_LEDGER.read_bytes()).hexdigest(),
        "contracts": {
            label: {
                "id": meta["id"],
                "path": meta["path"],
                "active_roles": sorted(roles_by_address.get(meta["id"], [])),
                "functions": {
                    name: {
                        "kind": item["kind"],
                        "direct_roles": item["direct_roles"],
                        "effective_roles": item["effective_roles"],
                        "local_calls": item["local_calls"],
                    }
                    for name, item in parsed[label].items()
                },
            }
            for label, meta in CONTRACTS.items()
        },
        "static_edges": edges,
        "immediate_caller_role_mismatches": mismatches,
        "unresolved_dynamic_edges": unresolved,
        "summary": {
            "static_edge_count": len(edges),
            "resolved_static_edge_count": sum(bool(edge.get("resolved")) for edge in edges),
            "mismatch_count": len(mismatches),
            "dynamic_edge_count": len(unresolved),
        },
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


if __name__ == "__main__":
    main()
