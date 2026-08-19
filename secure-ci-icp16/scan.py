#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

EXCLUDED_ROOT_CAUSES = (
    "uncertified decimals",
    "disburse maturity",
    "stale neuron",
    "stale canister details",
    "public snapshot",
    "skippedblockforcontract",
    "oversized block",
    "proposal content",
)

HIGH_VALUE_PARTS = (
    "rs/nns/cmc",
    "rs/sns/swap",
    "rs/nns/governance",
    "rs/sns/governance",
    "rs/sns/root",
    "rs/nns/handlers/root",
    "rs/nns/sns-wasm",
    "rs/bitcoin/ckbtc/minter",
    "rs/ethereum/cketh/minter",
    "rs/ledger_suite",
    "rs/execution_environment",
    "rs/cycles_account_manager",
    "rs/replicated_state",
    "rs/message_routing",
    "rs/consensus",
)

ENDPOINT_ATTR = re.compile(
    r"#\s*\[(?:ic_cdk::)?(?:update|query|heartbeat|init|pre_upgrade|post_upgrade)(?:\([^\]]*\))?\]",
    re.I,
)
FN_START = re.compile(
    r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)\s*(?:<[^>{};]*>)?\s*\("
)

AUTH_RX = re.compile(
    r"(?:authorize|authorise|permission|controller|hotkey|hot_key|is_caller|caller_is|"
    r"validate_caller|check_caller|guard_|ensure_authorized|is_authorized|is_authorised|"
    r"caller\(\)\s*==|msg_caller\(\)\s*==|caller\s*!=|msg_caller\s*!=)",
    re.I,
)
CALLER_RX = re.compile(r"\b(?:caller|msg_caller|principal|owner|sender|beneficiary|account|controller)\b", re.I)
TARGET_RX = re.compile(
    r"\b(?:target|to|recipient|beneficiary|owner|account|canister_id|ledger_id|root_canister_id|"
    r"governance_canister_id|subaccount|neuron_id|proposal_id|block_index)\b",
    re.I,
)
AWAIT_RX = re.compile(r"\.await\b")
MUTATE_RX = re.compile(
    r"\b(?:mutate_state|process_event|record_[A-Za-z0-9_]*|mark_[A-Za-z0-9_]*|"
    r"insert_[A-Za-z0-9_]*|remove_[A-Za-z0-9_]*|set_[A-Za-z0-9_]*|add_[A-Za-z0-9_]*|"
    r"burn_[A-Za-z0-9_]*|mint_[A-Za-z0-9_]*|refund_[A-Za-z0-9_]*|reimburse_[A-Za-z0-9_]*)\s*\(|"
    r"\.(?:insert|remove|push|pop|retain|clear|append)\s*\(",
    re.I,
)
READ_RX = re.compile(r"\b(?:read_state|with_state|borrow\(|get\(|contains|balance|status|lookup|find_)\b", re.I)
EXTERNAL_RX = re.compile(
    r"\b(?:icrc1_transfer|icrc2_transfer_from|transfer|transfer_funds|mint|burn|"
    r"create_canister|install_code|update_settings|set_controllers|stop_canister|start_canister|"
    r"sign_with_[A-Za-z0-9_]*|ecdsa_[A-Za-z0-9_]*|schnorr_[A-Za-z0-9_]*|"
    r"get_utxos|get_logs|get_transaction_receipt|send_raw_transaction|"
    r"call|try_send|perform_call|execute_call)\s*\(|"
    r"\.(?:transfer|transfer_from|approve|call|try_send|send|mint|burn)\s*\(",
    re.I,
)
GUARD_RX = re.compile(
    r"\b(?:Guard|ScopeGuard|scopeguard|TimerGuard|Processing|InFlight|Pending|lock|guard)\b",
    re.I,
)
ERROR_RX = re.compile(r"\b(?:Err\s*\(|return\s+Err|error|failed|reject|trap|panic!|unwrap\(|expect\()", re.I)
RETRY_RX = re.compile(r"\b(?:retry|retriable|temporarily|schedule_now|set_timer|resubmit|try_again|continue)\b", re.I)
FINANCIAL_RX = re.compile(
    r"\b(?:amount|balance|stake|maturity|cycles|fee|refund|reimburse|mint|burn|ledger|withdraw|deposit|"
    r"satoshi|e8s|wei|token|funds|allowance|reward)\b",
    re.I,
)
CURSOR_RX = re.compile(r"\b(?:last_[A-Za-z0-9_]*|next_[A-Za-z0-9_]*|cursor|height|block_number|offset|nonce|index)\b", re.I)


@dataclass
class Function:
    name: str
    start: int
    end: int
    line: int
    body: str
    attrs: str


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract_functions(text: str) -> Iterable[Function]:
    for match in FN_START.finditer(text):
        brace = text.find("{", match.end())
        if brace < 0:
            continue
        depth = 0
        in_string = False
        escaped = False
        in_char = False
        in_line_comment = False
        in_block_comment = 0
        end = None
        i = brace
        while i < len(text):
            c = text[i]
            n = text[i + 1] if i + 1 < len(text) else ""
            if in_line_comment:
                if c == "\n":
                    in_line_comment = False
                i += 1
                continue
            if in_block_comment:
                if c == "/" and n == "*":
                    in_block_comment += 1
                    i += 2
                    continue
                if c == "*" and n == "/":
                    in_block_comment -= 1
                    i += 2
                    continue
                i += 1
                continue
            if in_string:
                if escaped:
                    escaped = False
                elif c == "\\":
                    escaped = True
                elif c == '"':
                    in_string = False
                i += 1
                continue
            if in_char:
                if escaped:
                    escaped = False
                elif c == "\\":
                    escaped = True
                elif c == "'":
                    in_char = False
                i += 1
                continue
            if c == "/" and n == "/":
                in_line_comment = True
                i += 2
                continue
            if c == "/" and n == "*":
                in_block_comment = 1
                i += 2
                continue
            if c == '"':
                in_string = True
            elif c == "'" and n and n != "s":
                in_char = True
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
            i += 1
        if end is None:
            continue
        attr_start = max(0, text.rfind("\n\n", 0, match.start()))
        attrs = text[attr_start:match.start()]
        line = text.count("\n", 0, match.start()) + 1
        yield Function(match.group(1), match.start(), end, line, text[match.start():end], attrs)


def positions(rx: re.Pattern[str], text: str) -> list[int]:
    return [m.start() for m in rx.finditer(text)]


def first_pos(rx: re.Pattern[str], text: str) -> int:
    m = rx.search(text)
    return m.start() if m else 10**9


def candidate_records(label: str, snapshot: Path) -> list[dict]:
    out: list[dict] = []
    for path in snapshot.rglob("*.rs"):
        rel = path.relative_to(snapshot).as_posix()
        if not rel.startswith(HIGH_VALUE_PARTS):
            continue
        if any(part in {"target", "generated", "gen"} for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except Exception:
            continue
        for fn in extract_functions(text):
            body = fn.body
            lower = body.lower()
            if any(term in lower for term in EXCLUDED_ROOT_CAUSES):
                continue
            await_positions = positions(AWAIT_RX, body)
            mutate_positions = positions(MUTATE_RX, body)
            external_positions = positions(EXTERNAL_RX, body)
            if not (mutate_positions or external_positions or FINANCIAL_RX.search(body)):
                continue
            endpoint = bool(ENDPOINT_ATTR.search(fn.attrs))
            auth_pos = first_pos(AUTH_RX, body)
            target_pos = first_pos(TARGET_RX, body)
            first_await = await_positions[0] if await_positions else 10**9
            first_mutate = mutate_positions[0] if mutate_positions else 10**9
            guard_before_await = bool(GUARD_RX.search(body[:first_await])) if await_positions else False
            reread_after_await = bool(READ_RX.search(body[first_await:first_await + 2200])) if await_positions else False
            categories: list[str] = []
            reasons: list[str] = []
            score = 0

            if endpoint and target_pos < auth_pos and first_external < auth_pos:
                categories.append("endpoint_target_before_auth")
                reasons.append("public endpoint uses target/identity before an obvious authorization check")
                score += 13
            if endpoint and CALLER_RX.search(body) and TARGET_RX.search(body) and not AUTH_RX.search(body) and EXTERNAL_RX.search(body):
                categories.append("endpoint_identity_external_no_auth")
                reasons.append("public endpoint combines caller/target identity with an external side effect and no obvious authorization")
                score += 12
            if await_positions and first_mutate < first_await and not guard_before_await:
                categories.append("state_consumed_before_await_without_guard")
                reasons.append("state mutation/removal occurs before an await without an obvious rollback/in-flight guard")
                score += 11
            if await_positions and READ_RX.search(body[:first_await]) and mutate_positions and any(p > first_await for p in mutate_positions) and not reread_after_await and not guard_before_await:
                categories.append("async_toctou_state_commit")
                reasons.append("state is read before await and committed after await without an obvious guard or re-read")
                score += 12
            if await_positions and EXTERNAL_RX.search(body[:first_await + 1]) and ERROR_RX.search(body[first_await:]) and RETRY_RX.search(body[first_await:]):
                categories.append("ambiguous_external_error_retry")
                reasons.append("external side effect is followed by a retriable/error path that may need idempotency analysis")
                score += 9
            if re.search(r"ScopeGuard::into_inner|defuse", body) and await_positions and ERROR_RX.search(body):
                categories.append("scopeguard_defuse_error_path")
                reasons.append("scope guard is defused on an external-call error path; ambiguous outcomes need proof")
                score += 8
            if FINANCIAL_RX.search(body) and re.search(r"saturating_(?:sub|add|mul)", body):
                categories.append("saturating_financial_arithmetic")
                reasons.append("saturating arithmetic appears in a financial/state-accounting function")
                score += 7
            if ERROR_RX.search(body) and CURSOR_RX.search(body) and re.search(r"(?:advance|skip|last_[A-Za-z0-9_]*\s*=|next_[A-Za-z0-9_]*\s*=|set_last|update_last)", body, re.I):
                categories.append("cursor_progress_on_error")
                reasons.append("error handling and irreversible cursor/progress changes appear in one function")
                score += 9
            if endpoint and re.search(r"(?:refund|reimburse|transfer)", body, re.I) and TARGET_RX.search(body) and not AUTH_RX.search(body):
                categories.append("public_refund_target_no_auth")
                reasons.append("public endpoint can direct a refund/transfer without an obvious authorization check")
                score += 13
            if re.search(r"\[[ ]*0[ ]*\]|\.unwrap\(\)|\.expect\(", body) and endpoint and (CALLER_RX.search(body) or TARGET_RX.search(body)):
                categories.append("endpoint_panic_on_identity_input")
                reasons.append("public identity/target path contains index/unwrap/expect operations")
                score += 6
            if re.search(r"(?:contains_key|entry|insert)\s*\(", body) and re.search(r"(?:txid|transaction_hash|signature|block_index|log_index|nonce)", body, re.I):
                if not re.search(r"(?:chain_id|ledger_id|canister_id|log_index|vout|instruction_index)", body, re.I):
                    categories.append("possibly_incomplete_dedup_identity")
                    reasons.append("deduplication-like key may omit a domain/index dimension")
                    score += 7

            if "/tests/" in f"/{rel}/" or rel.endswith("tests.rs") or "test" in fn.attrs.lower():
                score -= 5
            if endpoint:
                score += 3
            if first_external < 10**9 and FINANCIAL_RX.search(body):
                score += 3
            if score < 9 or not categories:
                continue
            out.append({
                "label": label,
                "score": score,
                "file": rel,
                "line": fn.line,
                "function": fn.name,
                "endpoint": endpoint,
                "categories": categories,
                "reasons": reasons,
                "signals": {
                    "awaits": len(await_positions),
                    "mutations": len(mutate_positions),
                    "external_calls": len(external_positions),
                    "guard_before_first_await": guard_before_await,
                    "reread_after_first_await": reread_after_await,
                    "auth_present": auth_pos < 10**9,
                },
                "excerpt": body[:28000],
                "file_sha256": sha256_bytes(path.read_bytes()),
            })
    out.sort(key=lambda x: (-x["score"], x["file"], x["line"]))
    return out


def git_output(repo: Path, args: list[str], limit: int = 100000) -> str:
    try:
        p = subprocess.run(["git", "-C", str(repo), *args], text=True, capture_output=True, timeout=180)
        return (p.stdout + p.stderr)[-limit:]
    except Exception as exc:
        return repr(exc)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshots", type=Path)
    parser.add_argument("repo", type=Path)
    parser.add_argument("out", type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    all_candidates: list[dict] = []
    labels = []
    for snapshot in sorted(args.snapshots.iterdir()):
        if not snapshot.is_dir():
            continue
        label = snapshot.name
        labels.append(label)
        records = candidate_records(label, snapshot)
        all_candidates.extend(records)
        (args.out / f"CANDIDATES_{label}.json").write_text(json.dumps(records[:500], indent=2), encoding="utf-8")

    all_candidates.sort(key=lambda x: (-x["score"], x["label"], x["file"], x["line"]))
    (args.out / "ALL_CANDIDATES.json").write_text(json.dumps(all_candidates[:1800], indent=2), encoding="utf-8")

    clusters: dict[tuple[str, str], list[dict]] = {}
    for c in all_candidates:
        clusters.setdefault((c["file"], c["function"]), []).append(c)
    cluster_rows = []
    for (file, function), rows in clusters.items():
        labels_here = sorted({r["label"] for r in rows})
        max_score = max(r["score"] for r in rows)
        categories = sorted({cat for r in rows for cat in r["categories"]})
        cluster_rows.append({
            "max_score": max_score,
            "file": file,
            "function": function,
            "labels": labels_here,
            "categories": categories,
            "persistent_across_revisions": len(labels_here) > 1,
            "representative": max(rows, key=lambda r: r["score"]),
        })
    cluster_rows.sort(key=lambda x: (-x["max_score"], -len(x["labels"]), x["file"]))
    (args.out / "CLUSTERS.json").write_text(json.dumps(cluster_rows[:800], indent=2), encoding="utf-8")

    source_dir = args.out / "top_source_files"
    source_dir.mkdir(exist_ok=True)
    copied = set()
    for c in all_candidates:
        key = (c["label"], c["file"])
        if key in copied or len(copied) >= 80:
            continue
        src = args.snapshots / c["label"] / c["file"]
        if not src.is_file():
            continue
        dst = source_dir / c["label"] / c["file"]
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        copied.add(key)

    history_queries = {
        "security_fixes": ["log", "--all", "--oneline", "--decorate", "--regexp-ignore-case", "--grep=security|auth|authorization|double|refund|reimburse|idempot|overflow|underflow|replay|race|stale|incorrect target|wrong account|mint|burn"],
        "recent_high_value": ["log", "-n", "1200", "--oneline", "--", *HIGH_VALUE_PARTS],
    }
    history = {name: git_output(args.repo, command, 400000) for name, command in history_queries.items()}
    (args.out / "HISTORY.json").write_text(json.dumps(history, indent=2), encoding="utf-8")

    duplicate_terms = sorted({c["function"] for c in all_candidates[:120] if len(c["function"]) >= 5})
    duplicate_results = {}
    for term in duplicate_terms[:60]:
        duplicate_results[term] = git_output(args.repo, ["log", "--all", "--oneline", f"--grep={term}", "--regexp-ignore-case"], 30000)
    (args.out / "PUBLIC_DUPLICATE_HINTS.json").write_text(json.dumps(duplicate_results, indent=2), encoding="utf-8")

    summary = {
        "labels": labels,
        "candidate_count": len(all_candidates),
        "cluster_count": len(cluster_rows),
        "top": [{k: c[k] for k in ("score", "label", "file", "line", "function", "categories")} for c in all_candidates[:80]],
        "persistent_top": [
            {k: row[k] for k in ("max_score", "file", "function", "labels", "categories")}
            for row in cluster_rows if row["persistent_across_revisions"]
        ][:80],
    }
    (args.out / "SUMMARY.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    with (args.out / "TOP_CANDIDATES.txt").open("w", encoding="utf-8") as f:
        for c in all_candidates[:180]:
            f.write(f"\n=== {c['score']} {c['label']} {c['file']}:{c['line']} {c['function']} ===\n")
            f.write("CATEGORIES: " + ", ".join(c["categories"]) + "\n")
            f.write("REASONS: " + " | ".join(c["reasons"]) + "\n")
            f.write(c["excerpt"] + "\n")


if __name__ == "__main__":
    main()
