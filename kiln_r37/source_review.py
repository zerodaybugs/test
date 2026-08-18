#!/usr/bin/env python3
"""Kiln R37: bind R33 v6 mutation evidence to source and impact class."""
from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any

NETWORKS = ["ethereum", "arbitrum", "base", "bnb", "polygon", "optimism"]
OUT = Path("r37_results")
OUT.mkdir(exist_ok=True)
DOWNLOADS = Path("r37_downloads")
MIRROR = Path("mirror")
PUBLIC = Path("r33_v6_public_gates")

ACCESS_MARKERS = [
    "onlyrole", "onlyowner", "onlyadmin", "onlymanager", "onlydelegatecall",
    "initializer", "reinitializer", "requiresauth", " auth", "hasrole",
]
INTENDED_PERMISSIONLESS_PREFIXES = ("create", "deploy", "collect")


def find_evidence(network: str) -> Path | None:
    root = DOWNLOADS / network
    candidates = sorted(root.rglob("EVIDENCE.json")) if root.exists() else []
    for path in candidates:
        try:
            data = json.loads(path.read_text())
            if str(data.get("schema", "")).startswith("kiln-r33-control-plane"):
                return path
        except Exception:
            continue
    return None


def verify_public_gate(network: str) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    root = PUBLIC / network
    gate_path = root / "PUBLIC_GATE.json"
    sums_path = root / "SHA256SUMS.txt"
    meta: dict[str, Any] = {
        "network": network,
        "gate_exists": gate_path.exists(),
        "sums_exists": sums_path.exists(),
        "hash_ok": False,
    }
    if not gate_path.exists() or not sums_path.exists():
        return None, meta
    try:
        raw = gate_path.read_bytes()
        expected = None
        for line in sums_path.read_text().splitlines():
            if line.strip().endswith("PUBLIC_GATE.json"):
                expected = line.split()[0]
                break
        actual = hashlib.sha256(raw).hexdigest()
        meta.update({"expected_sha256": expected, "actual_sha256": actual, "hash_ok": expected == actual})
        return json.loads(raw), meta
    except Exception as exc:
        meta["error"] = f"{type(exc).__name__}: {exc}"
        return None, meta


def payload_parts(label: str) -> tuple[str | None, str, str]:
    if label.startswith("abi:"):
        _, contract, signature = label.split(":", 2)
        return contract, signature.split("(", 1)[0], signature
    function_name = label.split("(", 1)[0]
    return None, function_name, label


def source_matches(function_name: str, contract_hint: str | None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    pattern = re.compile(rf"\bfunction\s+{re.escape(function_name)}\s*\(")
    for path in sorted((MIRROR / "src").rglob("*.sol")):
        if contract_hint and path.stem.lower() != contract_hint.lower():
            # Keep scanning other files only if hinted contract was not found later.
            pass
        try:
            text = path.read_text(errors="replace")
        except Exception:
            continue
        for match in pattern.finditer(text):
            start_line = text[:match.start()].count("\n") + 1
            brace = text.find("{", match.start())
            semicolon = text.find(";", match.start())
            end = min(x for x in [brace, semicolon] if x >= 0) if brace >= 0 or semicolon >= 0 else min(len(text), match.start()+1000)
            declaration = re.sub(r"\s+", " ", text[match.start():end]).strip()
            lower = declaration.lower()
            visible_guard = any(marker in lower for marker in ACCESS_MARKERS)
            lines = text.splitlines()
            context = "\n".join(lines[max(0,start_line-4):min(len(lines),start_line+12)])
            rows.append({
                "file": str(path.relative_to(MIRROR)),
                "line": start_line,
                "contract_hint_match": bool(contract_hint and path.stem.lower() == contract_hint.lower()),
                "declaration": declaration,
                "visible_access_guard": visible_guard,
                "context": context,
            })
    rows.sort(key=lambda row: (not row["contract_hint_match"], row["file"], row["line"]))
    return rows


def audit_blob() -> str:
    chunks: list[str] = []
    for base in [MIRROR / ".audit", MIRROR / "pdfextracts", MIRROR / "reports"]:
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if path.is_file() and path.suffix.lower() in {".md", ".txt", ".json"}:
                try:
                    chunks.append(path.read_text(errors="replace").lower())
                except Exception:
                    pass
    return "\n".join(chunks)


def find_target_attempt(evidence: dict[str, Any], target: str, label: str) -> dict[str, Any] | None:
    local = evidence.get("local_fork") or {}
    for row in local.get("target_results", []):
        if str(row.get("target", "")).lower() != target.lower():
            continue
        for attempt in row.get("attempts", []):
            if attempt.get("label") == label:
                return attempt
    return None


def classify(candidate: dict[str, Any], attempt: dict[str, Any] | None, source_rows: list[dict[str, Any]]) -> dict[str, Any]:
    categories = [str(item) for item in candidate.get("categories", [])]
    keys = [str(item) for item in candidate.get("sensitive_change_keys", [])]
    label = str(candidate.get("payload_label", ""))
    contract_hint, function_name, signature = payload_parts(label)
    implementation_only = bool(categories) and all(
        "getter:implementation()" in item or "implementation_logic" in item
        for item in categories
    )
    strong_prefixes = (
        "slot:eip1967_", "role:", "view:owner", "view:defaultAdmin",
        "view:pendingDefaultAdmin", "view:pendingOwner", "registry_test_entry",
        "runtime_code",
    )
    config_prefixes = ("control_view:", "control_storage_slot:")
    strong = [key for key in keys if key.startswith(strong_prefixes)]
    config = [key for key in keys if key.startswith(config_prefixes)]
    generic_only = bool(keys) and not strong and bool(config)
    all_5 = bool(candidate.get("all_5_pass"))
    source_guarded = any(row.get("visible_access_guard") for row in source_rows[:10])
    intended_permissionless = function_name.lower().startswith(INTENDED_PERMISSIONLESS_PREFIXES)

    if not all_5:
        decision = "KILL_NOT_DETERMINISTIC_5OF5"
    elif implementation_only:
        decision = "KILL_DIRECT_IMPLEMENTATION_STATE_NO_PROXY_CONTROL"
    elif generic_only and intended_permissionless:
        decision = "KILL_INTENDED_PERMISSIONLESS_CONFIG_ONLY_SIGNAL"
    elif strong:
        decision = "PROMOTE_STRONG_CONTROL_GAIN_DEPLOYED_SOURCE_IMPACT_REVIEW"
    elif config:
        decision = "PROMOTE_CONFIG_MUTATION_DEPLOYED_SOURCE_IMPACT_REVIEW"
    else:
        decision = "HOLD_UNCLASSIFIED_MUTATION_SIGNAL"
    return {
        "decision": decision,
        "implementation_only": implementation_only,
        "all_5_pass": all_5,
        "strong_change_keys": strong,
        "config_change_keys": config,
        "source_visible_guard": source_guarded,
        "intended_permissionless_name": intended_permissionless,
        "function_name": function_name,
        "signature": signature,
        "contract_hint": contract_hint,
        "attempt_found": attempt is not None,
    }


def main() -> int:
    corpus = audit_blob()
    result: dict[str, Any] = {
        "schema": "kiln-r37-source-impact-review-v1",
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "networks": [],
        "candidates": [],
        "errors": [],
        "safety": {
            "public_chain_state_changes": 0,
            "transactions_signed": 0,
            "transactions_sent": 0,
            "local_fork_transactions_in_this_stage": 0,
        },
    }

    for network in NETWORKS:
        gate, gate_meta = verify_public_gate(network)
        evidence_path = find_evidence(network)
        network_row: dict[str, Any] = {
            "network": network,
            "public_gate": gate_meta,
            "evidence_path": str(evidence_path) if evidence_path else None,
            "verified_candidate_count": 0,
        }
        if gate is None or not gate_meta.get("hash_ok"):
            network_row["error"] = "public gate missing or hash-invalid"
            result["errors"].append({"network": network, "error": network_row["error"]})
            result["networks"].append(network_row)
            continue
        if evidence_path is None:
            network_row["error"] = "private evidence unavailable"
            result["errors"].append({"network": network, "error": network_row["error"]})
            result["networks"].append(network_row)
            continue
        try:
            evidence = json.loads(evidence_path.read_text())
        except Exception as exc:
            network_row["error"] = f"evidence parse: {type(exc).__name__}: {exc}"
            result["errors"].append({"network": network, "error": network_row["error"]})
            result["networks"].append(network_row)
            continue
        verified = gate.get("verified_candidates", [])
        network_row["verified_candidate_count"] = len(verified)
        for candidate in verified:
            target = candidate["target"]
            label = candidate["payload_label"]
            contract_hint, function_name, signature = payload_parts(label)
            matches = source_matches(function_name, contract_hint)
            attempt = find_target_attempt(evidence, target, label)
            classification = classify(candidate, attempt, matches)
            mention_terms = [function_name.lower(), signature.lower(), label.lower()]
            mentions = {term: corpus.count(term) for term in mention_terms if term}
            duplicate_mentions = max(mentions.values(), default=0)
            row = {
                "network": network,
                "target": target,
                "categories": candidate.get("categories", []),
                "payload_label": label,
                "sensitive_change_keys": candidate.get("sensitive_change_keys", []),
                "classification": classification,
                "source_matches": matches[:20],
                "audit_corpus_mentions": mentions,
                "duplicate_risk": (
                    "HIGH_PUBLIC_CORPUS" if duplicate_mentions >= 5
                    else "MEDIUM_PUBLIC_CORPUS" if duplicate_mentions > 0
                    else "LOW_PUBLIC_CORPUS_NOT_PRIVATE_CLEARANCE"
                ),
                "attempt_summary": {
                    "found": attempt is not None,
                    "tx_status": (attempt or {}).get("tx", {}).get("status"),
                    "five_run": (attempt or {}).get("five_run_verification", {}),
                    "generic_slots": (attempt or {}).get("generic_storage_slots_changed", []),
                },
            }
            result["candidates"].append(row)
        result["networks"].append(network_row)

    promoted = [
        row for row in result["candidates"]
        if row["classification"]["decision"].startswith("PROMOTE_")
    ]
    holds = [
        row for row in result["candidates"]
        if row["classification"]["decision"].startswith("HOLD_")
    ]
    killed = [row for row in result["candidates"] if row not in promoted and row not in holds]
    if result["errors"]:
        decision = "INCONCLUSIVE_PRIVATE_EVIDENCE_OR_HASH_GAP"
    elif promoted:
        decision = "HOLD_PROMOTED_CONTROL_MUTATIONS_REQUIRE_EXACT_DEPLOYED_SOURCE_AND_PATCHED_CONTROL"
    elif holds:
        decision = "HOLD_UNCLASSIFIED_MUTATIONS_REQUIRE_MANUAL_SOURCE_REVIEW"
    else:
        decision = "KILL_NO_PROMOTABLE_CONTROL_PLANE_MUTATION"
    result["summary"] = {
        "decision": decision,
        "network_count": len(result["networks"]),
        "error_count": len(result["errors"]),
        "raw_verified_candidate_count": len(result["candidates"]),
        "promoted_count": len(promoted),
        "hold_count": len(holds),
        "killed_count": len(killed),
        "promoted": [
            {
                "network": row["network"],
                "target": row["target"],
                "payload_label": row["payload_label"],
                "decision": row["classification"]["decision"],
                "strong_change_keys": row["classification"]["strong_change_keys"],
                "config_change_keys": row["classification"]["config_change_keys"],
                "duplicate_risk": row["duplicate_risk"],
            }
            for row in promoted
        ],
    }
    (OUT / "EVIDENCE_REVIEW.json").write_text(json.dumps(result, indent=2, sort_keys=True))
    public_gate = {
        "schema": "kiln-r37-public-gate-v1",
        "decision": decision,
        "submit_ready": False,
        "validated_critical": 0,
        "validated_high": 0,
        "network_count": len(result["networks"]),
        "error_count": len(result["errors"]),
        "raw_verified_candidate_count": len(result["candidates"]),
        "promoted_count": len(promoted),
        "hold_count": len(holds),
        "killed_count": len(killed),
        "promoted": result["summary"]["promoted"],
        "public_chain_state_changes": 0,
        "transactions_signed": 0,
        "transactions_sent": 0,
    }
    (OUT / "PUBLIC_GATE.json").write_text(json.dumps(public_gate, indent=2, sort_keys=True))
    files = sorted(path for path in OUT.iterdir() if path.is_file() and path.name != "SHA256SUMS.txt")
    (OUT / "SHA256SUMS.txt").write_text("".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in files
    ))
    print(json.dumps(public_gate, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
