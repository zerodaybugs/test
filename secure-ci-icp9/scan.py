#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path

ROOT = Path(os.environ["SCAN_ROOT"]).resolve()
OUT = Path(os.environ["SECURE_RESULT_DIR"]).resolve()
OUT.mkdir(parents=True, exist_ok=True)

PROD_EXTS = {".rs", ".ts", ".svelte", ".js", ".tsx", ".jsx", ".mo"}
EXCLUDES = {".git", "target", "node_modules", "bazel-out", "bazel-bin", "bazel-testlogs"}

SENSITIVE = re.compile(
    r"(?i)\b(transfer|mint|burn|disburse|withdraw|delete|install|upgrade|rename|"
    r"set_?controller|set_?controllers|update_?settings|migrate|execute|submit|vote|"
    r"stake|unstake|create_canister|load_canister_snapshot|take_canister_snapshot|"
    r"upload_canister_snapshot|notify|refund|reimburse|sweep|sign_with|derive_key)\b"
)
AUTH = re.compile(
    r"(?i)(validate_(?:controller|caller|auth)|is_authori[sz]ed|caller_allowed|"
    r"assert_.*controller|contains\(&?caller|msg_caller\(\)|caller\(\)|"
    r"check_.*controller|verify_.*signature|authenticate|authorize)"
)
AWAIT = re.compile(r"\.await\b|\bawait\b")
PUBLIC = re.compile(r"#\[(?:update|query|candid_method|unsafe\(export_name\s*=\s*\"canister_(?:update|query))")
CHARGE = re.compile(r"(?i)(charge|consume_cycles|remove_cycles|withdraw_cycles|prepay|debit|fee)")
VALIDATE = re.compile(r"(?i)(validate|check_|assert_|ensure|verify|bounds?|range|offset|hash)")

PATTERNS = {
    "destination_invalid_success": re.compile(r"DestinationInvalid[\s\S]{0,450}(?:Success|Ok\(\)|return\s+Ok)"),
    "retry_after_effect": re.compile(r"(?i)(?:bounded_wait|unbounded_wait|\.await)[\s\S]{0,850}(?:or_retry\(|NoProgress|retry)"),
    "charge_before_validation": re.compile(r"(?i)(?:charge|consume_cycles|remove_cycles|withdraw_cycles)[\s\S]{0,1000}(?:validate|check_|assert_|offset|range|hash)"),
    "validation_after_await": re.compile(r"(?i)\.await[\s\S]{0,1200}(?:validate_(?:controller|caller|auth)|caller_allowed|assert_.*controller|is_authori[sz]ed)"),
    "saturating_accounting": re.compile(r"(?i)saturating_(?:sub|add)[\s\S]{0,450}(?:cycles|balance|refund|spent|fee|amount)"),
    "public_billing": re.compile(r"(?i)(?:Public|public)[\s\S]{0,1400}(?:charge|consume_cycles|fee|debit)"),
    "identity_to_action": re.compile(r"(?i)(?:route|canister_id|root_canister_id|neuron_id|proposal_id)[\s\S]{0,1500}(?:submit|execute|transfer|vote|update_settings|increase_stake)"),
    "async_state_snapshot": re.compile(r"(?i)(?:let\s+\w+\s*=.*(?:state|request|account|controller|balance))[\s\S]{0,1100}\.await[\s\S]{0,1100}(?:insert|remove|set_|update|transfer|mint|burn|delete)"),
    "unchecked_decode": re.compile(r"(?i)(?:Decode|decode|from_slice|candid|payload|request)[\s\S]{0,350}\.unwrap\(\)"),
}

@dataclass
class Candidate:
    score: int
    repo: str
    file: str
    line: int
    kind: str
    function: str
    reasons: list[str]
    snippet: str


def prod_file(p: Path) -> bool:
    if p.suffix not in PROD_EXTS:
        return False
    if set(p.parts) & EXCLUDES:
        return False
    s = "/" + str(p).replace("\\", "/").lower()
    if "/tests/" in s or "/test/" in s or s.endswith("_test.rs") or s.endswith(".spec.ts"):
        return False
    return True


def line_no(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def clean(s: str, limit: int = 2600) -> str:
    return "\n".join(x.rstrip() for x in s.splitlines())[:limit]


def rust_functions(text: str):
    pat = re.compile(
        r"(?m)^(?P<attrs>(?:\s*#\[[^\n]+\]\s*)*)"
        r"(?P<sig>\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+"
        r"(?P<name>[A-Za-z0-9_]+)[^{;]*\{)"
    )
    for m in pat.finditer(text):
        brace = text.find("{", m.start("sig"), m.end("sig"))
        if brace < 0:
            continue
        depth = 0
        i = brace
        in_string = False
        escaped = False
        quote = ""
        while i < len(text):
            ch = text[i]
            if in_string:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == quote:
                    in_string = False
            else:
                if ch == '"':
                    in_string = True
                    quote = ch
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        yield m.group("name"), m.start(), i + 1, text[m.start(): i + 1]
                        break
            i += 1


def scan_repo(name: str, repo: Path) -> list[Candidate]:
    recent: set[str] = set()
    try:
        log = subprocess.check_output(
            ["git", "-C", str(repo), "log", "--since=2026-05-01", "--name-only", "--pretty=format:"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
        recent = {x.strip() for x in log.splitlines() if x.strip()}
    except Exception:
        pass

    found: list[Candidate] = []
    for p in repo.rglob("*"):
        if not p.is_file() or not prod_file(p):
            continue
        rel = str(p.relative_to(repo))
        text = p.read_text(encoding="utf-8", errors="replace")

        if p.suffix == ".rs":
            for fn, start, _end, body in rust_functions(text):
                reasons: list[str] = []
                score = 0
                is_public = bool(PUBLIC.search(body[:900]))
                has_await = bool(AWAIT.search(body))
                has_effect = bool(SENSITIVE.search(fn + " " + body))
                auths = list(AUTH.finditer(body))
                first_await = AWAIT.search(body).start() if AWAIT.search(body) else 10**9
                first_auth = auths[0].start() if auths else 10**9

                if is_public:
                    score += 5
                    reasons.append("public endpoint")
                if has_await:
                    score += 2
                    reasons.append("async/await")
                if has_effect:
                    score += 4
                    reasons.append("sensitive effect")
                if is_public and has_effect and not auths:
                    score += 8
                    reasons.append("no explicit auth in function")
                if has_await and auths and first_await < first_auth:
                    score += 7
                    reasons.append("authorization after await")
                if rel in recent:
                    score += 2
                    reasons.append("recently changed")
                if ".or_retry()" in body or "ProcessingResult::NoProgress" in body:
                    score += 3
                    reasons.append("retry state machine")
                if "DestinationInvalid" in body and ("Success" in body or "Ok(" in body):
                    score += 5
                    reasons.append("DestinationInvalid treated as success")
                if CHARGE.search(body) and VALIDATE.search(body):
                    if CHARGE.search(body).start() < VALIDATE.search(body).start():
                        score += 5
                        reasons.append("charge before validation keyword")
                if "saturating_sub" in body and re.search(r"(?i)(cycles|balance|refund|amount|spent)", body):
                    score += 3
                    reasons.append("saturating accounting")
                if score >= 11:
                    found.append(Candidate(score, name, rel, line_no(text, start), "function", fn, reasons, clean(body)))

        for kind, pat in PATTERNS.items():
            for m in pat.finditer(text):
                a = max(0, m.start() - 650)
                b = min(len(text), m.end() + 1050)
                score = 9 + (2 if rel in recent else 0)
                if SENSITIVE.search(text[a:b]):
                    score += 3
                reasons = [kind]
                if rel in recent:
                    reasons.append("recently changed")
                found.append(Candidate(score, name, rel, line_no(text, m.start()), kind, "", reasons, clean(text[a:b])))

    best: dict[tuple, Candidate] = {}
    for c in found:
        key = (c.repo, c.file, c.line, c.kind, c.function)
        if key not in best or c.score > best[key].score:
            best[key] = c
    return sorted(best.values(), key=lambda c: (-c.score, c.repo, c.file, c.line))


repos = {"ic": ROOT / "ic", "nns-dapp": ROOT / "nns-dapp"}
all_candidates: list[Candidate] = []
for repo_name, repo_path in repos.items():
    all_candidates.extend(scan_repo(repo_name, repo_path))
all_candidates.sort(key=lambda c: (-c.score, c.repo, c.file, c.line))

(OUT / "STATIC_CANDIDATES.json").write_text(
    json.dumps([asdict(x) for x in all_candidates[:1800]], indent=2), encoding="utf-8"
)
with (OUT / "STATIC_CANDIDATES_TOP.md").open("w", encoding="utf-8") as f:
    f.write("# Static candidates\n\n")
    for i, c in enumerate(all_candidates[:220], 1):
        f.write(f"## {i}. score {c.score} — `{c.repo}/{c.file}:{c.line}` — {c.kind} {c.function}\n\n")
        f.write("Reasons: " + ", ".join(c.reasons) + "\n\n```text\n" + c.snippet + "\n```\n\n")

queries = {
    "minimum_incoming_cycles": r"minimum_incoming_canister_call_cycles|requires at least .* transferred cycles",
    "dts_resume": r"PausedExecution|AbortedExecution|clean_canister|cycles_balance|resume.*cycles|cycles.*resume",
    "migration_ready": r"ready_for_migration|rename_canister|drop_in_progress_management_calls_after_split",
    "status_visibility": r"status_visibility|validate_status_visibility|CanisterStatus",
    "snapshot_visibility": r"snapshot_visibility|validate_snapshot_visibility|ReadCanisterSnapshot",
    "http_spent": r"CanisterHttp(?:Initial|Async)Spent|initial_spent|asynchronous|unspent_allowance|spent\(",
    "retry_success": r"DestinationInvalid|\.or_retry\(\)|ProcessingResult::NoProgress",
    "caller_effect": r"msg_caller\(\)|caller\(\)|set_exclusive_controller|set_controllers|transfer|mint|burn|disburse|rename_canister",
    "certification": r"certified|certificate|uncertified|root_key|witness",
    "module_hash": r"module_hash_ref|CanisterModule|OnceLock",
    "query_limits": r"query.*limit|composite.*query|instruction_limit_per_query",
}
for q, pattern in queries.items():
    blocks = []
    for repo_name, repo_path in repos.items():
        cp = subprocess.run(
            ["rg", "-n", "--hidden", "-g", "!target/**", "-g", "!node_modules/**", pattern, str(repo_path)],
            text=True,
            capture_output=True,
            timeout=180,
        )
        blocks.append(f"### {repo_name}\n" + cp.stdout[:3_000_000])
    (OUT / f"RG_{q}.txt").write_text("\n".join(blocks), encoding="utf-8")

for repo_name, repo_path in repos.items():
    for days in (14, 60, 180):
        cp = subprocess.run(
            ["git", "-C", str(repo_path), "log", f"--since={days} days ago", "--date=iso-strict", "--pretty=format:%H%x09%cI%x09%s", "--name-status"],
            text=True,
            capture_output=True,
            timeout=180,
        )
        (OUT / f"{repo_name}_RECENT_{days}D.txt").write_text(cp.stdout, encoding="utf-8")

copy_specs = {
    "ic": [
        "rs/execution_environment/src",
        "rs/replicated_state/src",
        "rs/https_outcalls/consensus/src",
        "rs/messaging/src/canister_http_spent.rs",
        "rs/migration_canister/src",
        "rs/nns/governance/src",
        "rs/sns/governance/src",
        "rs/nns/cmc/src",
        "rs/ethereum/cketh/minter/src",
        "rs/types/wasm_types/src",
        "rs/types/types/src/batch.rs",
        "rs/types/types/src/batch/canister_http.rs",
        "rs/interfaces/src/execution_environment.rs",
        "rs/test_utilities/execution_environment/src/lib.rs",
        "rs/execution_environment/tests/canister_settings.rs",
        "rs/migration_canister/tests/tests.rs",
    ],
    "nns-dapp": [
        "frontend/src/lib",
        "rs/sns_aggregator/src",
        "frontend/src/tests/lib",
        "frontend/src/tests/page-objects",
    ],
}
source_out = OUT / "sources"
for repo_name, rels in copy_specs.items():
    for rel in rels:
        src = repos[repo_name] / rel
        if not src.exists():
            continue
        dst = source_out / repo_name / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            shutil.copytree(src, dst, dirs_exist_ok=True, ignore=shutil.ignore_patterns("target", "node_modules"))
        else:
            shutil.copy2(src, dst)

binding = {}
for repo_name, repo_path in repos.items():
    binding[repo_name] = {
        "head": subprocess.check_output(["git", "-C", str(repo_path), "rev-parse", "HEAD"], text=True).strip(),
        "status": subprocess.check_output(["git", "-C", str(repo_path), "status", "--porcelain"], text=True).strip(),
        "log": subprocess.check_output(["git", "-C", str(repo_path), "log", "-1", "--format=%H%n%cI%n%s"], text=True).strip(),
    }
(OUT / "SOURCE_BINDING.json").write_text(json.dumps(binding, indent=2), encoding="utf-8")
print(json.dumps({"candidate_count": len(all_candidates), "top": [asdict(x) for x in all_candidates[:12]], "binding": binding}, indent=2))
