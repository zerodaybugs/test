#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

if len(sys.argv) != 4:
    raise SystemExit("usage: scan.py <core> <periphery> <results>")

core, periphery, results = map(Path, sys.argv[1:])
results.mkdir(parents=True, exist_ok=True)

FUNCTION_RE = re.compile(
    r"function\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<args>.*?)\)\s*"
    r"(?P<tail>[^\{;]*)(?P<end>[\{;])",
    re.S,
)
CONTRACT_RE = re.compile(r"\b(?:abstract\s+)?(?:contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)")

suspicious_terms = {
    "delegatecall": re.compile(r"\.delegatecall\b"),
    "raw_call": re.compile(r"(?<!static)\.call\s*[\{(]"),
    "staticcall": re.compile(r"\.staticcall\b"),
    "selfdestruct": re.compile(r"\bselfdestruct\b"),
    "tx_origin": re.compile(r"\btx\.origin\b"),
    "assembly": re.compile(r"\bassembly\b"),
    "abi_decode_calldata": re.compile(r"abi\.decode\s*\(\s*(?:data|msg\.data|_data)"),
    "balance_delta": re.compile(r"balanceOf\s*\([^)]*\).*balanceOf", re.S),
    "force_approve": re.compile(r"\.forceApprove\b"),
    "unbounded_loop": re.compile(r"for\s*\([^;]*;[^;]*(?:\.length|<=)[^;]*;"),
    "timestamp_subtraction": re.compile(r"block\.timestamp\s*-"),
    "hash_only_authorization": re.compile(r"keccak256\s*\([^)]*(?:message|data)[^)]*\)"),
}

callback_names = {
    "receiveMessage", "receiveCctpV2Message", "lzCompose", "handleV3AcrossMessage",
    "receiveFlashLoan", "executeOperation", "onReport", "onERC721Received", "onERC1155Received",
    "onERC1155BatchReceived", "fallback", "receive",
}

report: dict[str, object] = {
    "roots": {},
    "public_state_changing_without_obvious_role_modifier": [],
    "callbacks": [],
    "suspicious_terms": {},
    "source_hashes": {},
}

obvious_modifiers = {
    "restricted", "onlyOperator", "onlyMechanic", "onlySecurityCouncil", "onlyRiskManager",
    "onlyRiskManagerTimelock", "onlyFactory", "onlyMachine", "onlyCaliber", "onlyController",
    "onlyFlashLoanModule", "onlyOwner", "initializer", "onlyInitializing", "nonReentrant",
    "whitelistCheck", "whenNotPaused", "notRecoveryMode", "accountingModeCheck",
}

for root_name, root in (("core", core), ("periphery", periphery)):
    files = sorted((root / "src").rglob("*.sol"))
    report["roots"][root_name] = {"solidity_files": len(files)}
    for path in files:
        text = path.read_text(errors="replace")
        rel = f"{root_name}/{path.relative_to(root).as_posix()}"
        report["source_hashes"][rel] = hashlib.sha256(text.encode()).hexdigest()
        contract_match = CONTRACT_RE.search(text)
        contract = contract_match.group(1) if contract_match else path.stem

        for term, pattern in suspicious_terms.items():
            matches = list(pattern.finditer(text))
            if matches:
                report["suspicious_terms"].setdefault(term, []).append({
                    "file": rel,
                    "count": len(matches),
                    "lines": sorted({text.count("\n", 0, m.start()) + 1 for m in matches})[:50],
                })

        for match in FUNCTION_RE.finditer(text):
            name = match.group("name")
            tail = " ".join(match.group("tail").split())
            line = text.count("\n", 0, match.start()) + 1
            is_external = re.search(r"\b(public|external)\b", tail)
            is_readonly = re.search(r"\b(view|pure)\b", tail)
            is_interface = match.group("end") == ";"
            modifiers = set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", tail))
            if name in callback_names:
                report["callbacks"].append({"file": rel, "contract": contract, "function": name, "line": line, "tail": tail})
            if is_external and not is_readonly and not is_interface:
                recognized = sorted(modifiers & obvious_modifiers)
                if not recognized:
                    report["public_state_changing_without_obvious_role_modifier"].append({
                        "file": rel,
                        "contract": contract,
                        "function": name,
                        "line": line,
                        "tail": tail,
                    })

(results / "custom_scan.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
print(json.dumps({
    "files": len(report["source_hashes"]),
    "unguarded": len(report["public_state_changing_without_obvious_role_modifier"]),
    "callbacks": len(report["callbacks"]),
    "terms": {k: sum(x["count"] for x in v) for k, v in report["suspicious_terms"].items()},
}, indent=2, sort_keys=True))
