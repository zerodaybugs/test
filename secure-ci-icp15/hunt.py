from __future__ import annotations

import json
import os
import re
from pathlib import Path

repo = Path(os.environ["RUNNER_TEMP"]) / "ic"
out = Path(os.environ["RUNNER_TEMP"]) / "result"
out.mkdir(parents=True, exist_ok=True)

roots = [
    repo / "rs/bitcoin/ckbtc",
    repo / "rs/ethereum/cketh",
    repo / "rs/ledger_suite",
    repo / "rs/nns/governance",
    repo / "rs/sns/governance",
    repo / "rs/nns/cmc",
    repo / "rs/nns/handlers/root",
    repo / "rs/nns/sns-wasm",
    repo / "rs/sns/root",
    repo / "rs/sns/swap",
    repo / "rs/execution_environment",
    repo / "rs/cycles_account_manager",
    repo / "rs/consensus",
    repo / "rs/registry",
    repo / "rs/crypto",
    repo / "rs/rosetta-api",
]

files: list[Path] = []
for root in roots:
    if root.exists():
        files.extend(root.rglob("*.rs"))
files = sorted(set(files))

fn_start = re.compile(
    r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+"
    r"([A-Za-z0-9_]+)\s*(?:<[^>{}]*>)?\s*\("
)


def functions(text: str):
    for match in fn_start.finditer(text):
        brace = text.find("{", match.end())
        if brace < 0:
            continue
        depth = 0
        index = brace
        in_string = False
        escaped = False
        while index < len(text):
            char = text[index]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
            else:
                if char == '"':
                    in_string = True
                elif char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        yield (
                            match.group(1),
                            match.start(),
                            index + 1,
                            text[match.start() : index + 1],
                        )
                        break
            index += 1


signals = {
    "await": r"\.await\b",
    "mutate_state": r"\bmutate_state\s*\(",
    "read_state": r"\bread_state\s*\(",
    "remove": r"\.remove\s*\(|\bremove_[A-Za-z0-9_]*\s*\(",
    "insert": r"\.insert\s*\(|\binsert_[A-Za-z0-9_]*\s*\(",
    "record": (
        r"\b(?:record|process|apply|commit|finalize|confirm|accept|mint|burn|"
        r"transfer|reimburse|refund)_[A-Za-z0-9_]*\s*\("
    ),
    "external": (
        r"\.(?:transfer|call|try_send|send|sign_with|ecdsa_public_key|"
        r"get_utxos|get_logs|get_block_by_number|get_transaction_receipt|"
        r"icrc[0-9]?_[A-Za-z0-9_]+)\s*\("
    ),
    "guard": r"\b(?:guard|ScopeGuard|scopeguard|TimerGuard|Processing|InFlight|Pending)\b",
    "error": r"\b(?:Err|error|fail|reject|trap|panic|unwrap|expect)\b",
    "cursor": (
        r"\b(?:last_[A-Za-z0-9_]*|next_[A-Za-z0-9_]*|cursor|height|"
        r"block_number|index|nonce|offset)\b"
    ),
    "saturating": r"\bsaturating_(?:add|sub|mul)\b",
    "checked": r"\bchecked_(?:add|sub|mul)\b",
    "caller": r"\b(?:caller|controller|principal|owner|sender|source|beneficiary|account)\b",
}
compiled = {key: re.compile(value, re.I) for key, value in signals.items()}

candidates: list[dict[str, object]] = []
for path in files:
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        continue
    relative = str(path.relative_to(repo))
    for name, start, _end, body in functions(text):
        hits = {key: bool(regex.search(body)) for key, regex in compiled.items()}
        score = 0
        reasons: list[str] = []

        def add(points: int, reason: str) -> None:
            nonlocal_holder[0] += points
            reasons.append(reason)

        nonlocal_holder = [0]
        if hits["await"] and hits["mutate_state"]:
            add(9, "await+mutate_state")
        if hits["await"] and hits["remove"]:
            add(8, "await+remove")
        if hits["await"] and hits["record"]:
            add(7, "await+record/commit")
        if hits["external"] and hits["mutate_state"]:
            add(7, "external-call+state-mutation")
        if hits["cursor"] and hits["error"]:
            add(5, "cursor+error")
        if hits["saturating"] and any(
            token in relative for token in ("ledger", "minter", "governance", "cmc", "swap")
        ):
            add(5, "saturating-arithmetic-in-financial-code")
        if hits["caller"] and hits["external"]:
            add(3, "identity+external-call")
        if hits["await"] and not hits["guard"] and (
            hits["remove"] or hits["record"] or hits["mutate_state"]
        ):
            add(5, "async-state-without-obvious-guard")
        if re.search(
            r"\.await[\s\S]{0,2500}(?:mutate_state|\.insert\(|\.remove\(|process_event|record_)",
            body,
        ):
            add(6, "post-await-state-commit")
        if re.search(
            r"(?:mutate_state|\.remove\(|process_event|record_)[\s\S]{0,2500}\.await",
            body,
        ):
            add(6, "pre-await-state-commit")
        if re.search(
            r"(?:Err\(|return\s+Err|continue;|return;)[\s\S]{0,900}"
            r"(?:insert|remove|record|process_event|mutate_state)",
            body,
        ):
            add(3, "error-path-state-change")
        if re.search(r"(?:unwrap_or_else|expect\(|panic!|assert!)", body) and hits["caller"]:
            add(2, "panic/expect-near-user-identity")

        score = nonlocal_holder[0]
        if score < 8:
            continue
        line = text.count("\n", 0, start) + 1
        candidates.append(
            {
                "score": score,
                "file": relative,
                "line": line,
                "function": name,
                "reasons": reasons,
                "hits": hits,
                "excerpt": body[:16000],
            }
        )

candidates.sort(key=lambda item: (-int(item["score"]), str(item["file"]), int(item["line"])))
(out / "ASYNC_AUTHORITY_CANDIDATES.json").write_text(
    json.dumps(candidates[:700], indent=2), encoding="utf-8"
)
with (out / "ASYNC_AUTHORITY_TOP.txt").open("w", encoding="utf-8") as handle:
    for candidate in candidates[:250]:
        handle.write(
            f"\n=== SCORE {candidate['score']} {candidate['file']}:"
            f"{candidate['line']} {candidate['function']} ===\n"
        )
        handle.write("REASONS: " + ", ".join(candidate["reasons"]) + "\n")
        handle.write(str(candidate["excerpt"]) + "\n")

patterns = {
    "cursor_advance_on_error": (
        r"(?is)(?:Err\(|error|too large|reject|failed)[\s\S]{0,1800}"
        r"(?:set_last|update_last|last_[A-Za-z0-9_]*\s*=|"
        r"next_[A-Za-z0-9_]*\s*=|advance|skip)"
    ),
    "remove_before_await": r"(?is)(?:\.remove\(|remove_[A-Za-z0-9_]*\()[\s\S]{0,1600}\.await",
    "commit_before_await": r"(?is)(?:process_event|record_[A-Za-z0-9_]*|mutate_state)[\s\S]{0,1600}\.await",
    "await_then_commit": r"(?is)\.await[\s\S]{0,1600}(?:process_event|record_[A-Za-z0-9_]*|mutate_state)",
    "saturating_financial": r"(?i)saturating_(?:add|sub|mul)",
    "panic_user_path": (
        r"(?is)(?:caller|principal|owner|account|sender)[\s\S]{0,1200}"
        r"(?:expect\(|unwrap\(|panic!|assert!)"
    ),
    "dedup_incomplete_identity": (
        r"(?is)(?:contains_key|entry\(|insert\()[\s\S]{0,800}"
        r"(?:txid|transaction_hash|block_index|log_index|nonce)"
    ),
}
pattern_hits: list[dict[str, object]] = []
for path in files:
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        continue
    relative = str(path.relative_to(repo))
    for label, pattern in patterns.items():
        regex = re.compile(pattern)
        for match in regex.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            low = max(0, match.start() - 900)
            high = min(len(text), match.end() + 1400)
            pattern_hits.append(
                {
                    "type": label,
                    "file": relative,
                    "line": line,
                    "excerpt": text[low:high],
                }
            )
            if len(pattern_hits) >= 2500:
                break
        if len(pattern_hits) >= 2500:
            break
    if len(pattern_hits) >= 2500:
        break
(out / "CROSS_FUNCTION_PATTERNS.json").write_text(
    json.dumps(pattern_hits, indent=2), encoding="utf-8"
)

exclusions = [
    "snapshot",
    "SkippedBlockForContract",
    "stale_neuron",
    "CanisterDetail",
    "uncertified",
    "DisburseMaturity",
    "decimals",
]
filtered = [
    candidate
    for candidate in candidates
    if not any(
        exclusion.lower()
        in (
            str(candidate["file"])
            + " "
            + str(candidate["function"])
            + " "
            + str(candidate["excerpt"])
        ).lower()
        for exclusion in exclusions
    )
]
(out / "FILTERED_NEW_ROOT_CAUSES.json").write_text(
    json.dumps(filtered[:500], indent=2), encoding="utf-8"
)
summary = {
    "rust_files_scanned": len(files),
    "ranked_candidates": len(candidates),
    "filtered_candidates": len(filtered),
    "pattern_hits": len(pattern_hits),
    "top": [
        {key: candidate[key] for key in ("score", "file", "line", "function", "reasons")}
        for candidate in filtered[:100]
    ],
}
(out / "SUMMARY.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
