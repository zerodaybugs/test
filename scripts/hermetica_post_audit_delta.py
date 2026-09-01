#!/usr/bin/env python3
from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

REPO = Path(os.environ.get("HERMETICA_REPO", "/tmp/hermetica-contracts"))
BASE = os.environ.get("HERMETICA_AUDITED_HEAD", "09393e69a57db59e071b622d3e8cb7dfb5fcc426")
HEAD = os.environ.get("HERMETICA_LATEST_HEAD", "5e13e431f69dd840fe297791fa2a73d9993a27e0")
OUT = Path("public-data/hermetica-post-audit-delta.json")

FILE_MAP = {
    "blacklist": (
        "contracts/hbtc/protocol/blacklist-v1.clar",
        "mainnet/contracts/hbtc/protocol/blacklist-v1.clar",
    ),
    "controller": (
        "contracts/hbtc/protocol/controller-v1.clar",
        "mainnet/contracts/hbtc/protocol/controller-v1.clar",
    ),
    "fee-collector": (
        "contracts/hbtc/protocol/fee-collector-v1.clar",
        "mainnet/contracts/hbtc/protocol/fee-collector-v1.clar",
    ),
    "hq": (
        "contracts/hbtc/protocol/hq-v1.clar",
        "mainnet/contracts/hbtc/protocol/hq-v1.clar",
    ),
    "hermetica-interface": (
        "contracts/hbtc/protocol/interfaces/hermetica-interface-v1.clar",
        "mainnet/contracts/hbtc/protocol/interfaces/hermetica-interface-v1.clar",
    ),
    "zest-interface": (
        "contracts/hbtc/protocol/interfaces/zest-interface-v1.clar",
        "mainnet/contracts/hbtc/protocol/interfaces/zest-interface-v1.clar",
    ),
    "reserve-fund": (
        "contracts/hbtc/protocol/reserve-fund-v1.clar",
        "mainnet/contracts/hbtc/protocol/reserve-fund-v1.clar",
    ),
    "reserve": (
        "contracts/hbtc/protocol/reserve-v1.clar",
        "mainnet/contracts/hbtc/protocol/reserve-v1.clar",
    ),
    "state": (
        "contracts/hbtc/protocol/state-v1.clar",
        "mainnet/contracts/hbtc/protocol/state-v1.clar",
    ),
    "trading": (
        "contracts/hbtc/protocol/trading-v1.clar",
        "mainnet/contracts/hbtc/protocol/trading-v1.clar",
    ),
    "vault": (
        "contracts/hbtc/protocol/vault-v1.clar",
        "mainnet/contracts/hbtc/protocol/vault-v1-2.clar",
    ),
    "token": (
        "contracts/hbtc/tokens/hbtc-token.clar",
        "mainnet/contracts/hbtc/tokens/token-hbtc.clar",
    ),
    "vault-trait": (
        "contracts/hbtc/traits/vault-trait-v1.clar",
        "mainnet/contracts/hbtc/traits/vault-trait-v1.clar",
    ),
    "zest-market-trait": (
        "contracts/hbtc/traits/zest-market-trait-v1.clar",
        "mainnet/contracts/hbtc/traits/zest-market-trait-v1.clar",
    ),
    "zest-vault-trait": (
        "contracts/hbtc/traits/zest-vault-trait-v1.clar",
        "mainnet/contracts/hbtc/traits/zest-vault-trait-v1.clar",
    ),
}

DEFINE_RE = re.compile(
    r"^\(define-(public|private|read-only|constant|data-var|map|fungible-token|trait)\s+"
    r"(?:\(([^\s()]+)|([^\s()]+))"
)


def git_show(ref: str, path: str) -> str | None:
    proc = subprocess.run(
        ["git", "-C", str(REPO), "show", f"{ref}:{path}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return proc.stdout if proc.returncode == 0 else None


def strip_comments(source: str) -> str:
    lines: list[str] = []
    for line in source.splitlines():
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
            lines.append(cleaned)
    return "\n".join(lines)


def top_level_forms(source: str) -> list[str]:
    src = strip_comments(source)
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
    # Preserve strings but remove irrelevant formatting.
    return re.sub(r"\s+", " ", form).strip()


def form_map(source: str) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    duplicate_count: dict[str, int] = {}
    for form in top_level_forms(source):
        normalized = normalize(form)
        match = DEFINE_RE.match(normalized)
        if not match:
            key = f"other:{hashlib.sha256(normalized.encode()).hexdigest()[:12]}"
            kind = "other"
        else:
            kind = match.group(1)
            name = match.group(2) or match.group(3) or "unknown"
            base_key = f"{kind}:{name}"
            duplicate_count[base_key] = duplicate_count.get(base_key, 0) + 1
            key = base_key if duplicate_count[base_key] == 1 else f"{base_key}#{duplicate_count[base_key]}"
        out[key] = {
            "kind": kind,
            "sha256": hashlib.sha256(normalized.encode()).hexdigest(),
            "normalized": normalized,
        }
    return out


def short_diff(old: str, new: str, limit: int = 100) -> list[str]:
    old_lines = old.replace(") (", ")\n(").splitlines()
    new_lines = new.replace(") (", ")\n(").splitlines()
    lines = list(
        difflib.unified_diff(old_lines, new_lines, fromfile="audited", tofile="latest", lineterm="")
    )
    if len(lines) > limit:
        return lines[:limit] + [f"... diff truncated: {len(lines) - limit} lines omitted"]
    return lines


def compare_file(label: str, old_path: str, new_path: str) -> dict[str, Any]:
    old_source = git_show(BASE, old_path)
    new_source = git_show(HEAD, new_path)
    if old_source is None or new_source is None:
        return {
            "old_path": old_path,
            "new_path": new_path,
            "old_present": old_source is not None,
            "new_present": new_source is not None,
        }
    old_forms = form_map(old_source)
    new_forms = form_map(new_source)
    old_keys = set(old_forms)
    new_keys = set(new_forms)
    changed = sorted(
        key for key in old_keys & new_keys if old_forms[key]["sha256"] != new_forms[key]["sha256"]
    )
    return {
        "old_path": old_path,
        "new_path": new_path,
        "old_bytes": len(old_source.encode()),
        "new_bytes": len(new_source.encode()),
        "added": sorted(new_keys - old_keys),
        "removed": sorted(old_keys - new_keys),
        "changed": changed,
        "unchanged_count": len(old_keys & new_keys) - len(changed),
        "changed_details": {
            key: {
                "old_sha256": old_forms[key]["sha256"],
                "new_sha256": new_forms[key]["sha256"],
                "diff": short_diff(old_forms[key]["normalized"], new_forms[key]["normalized"]),
            }
            for key in changed
        },
    }


def main() -> None:
    subprocess.run(["git", "-C", str(REPO), "cat-file", "-e", f"{BASE}^{{commit}}"], check=True)
    subprocess.run(["git", "-C", str(REPO), "cat-file", "-e", f"{HEAD}^{{commit}}"], check=True)
    files = {
        label: compare_file(label, old_path, new_path)
        for label, (old_path, new_path) in FILE_MAP.items()
    }
    payload = {
        "target_repository": "hermetica-fi/hermetica-contracts",
        "audited_head": BASE,
        "latest_head": HEAD,
        "files": files,
        "summary": {
            "files_compared": len(files),
            "added_forms": sum(len(item.get("added", [])) for item in files.values()),
            "removed_forms": sum(len(item.get("removed", [])) for item in files.values()),
            "changed_forms": sum(len(item.get("changed", [])) for item in files.values()),
            "changed_public_functions": sorted(
                f"{label}:{key.split(':', 1)[1]}"
                for label, item in files.items()
                for key in item.get("changed", [])
                if key.startswith("public:")
            ),
            "added_public_functions": sorted(
                f"{label}:{key.split(':', 1)[1]}"
                for label, item in files.items()
                for key in item.get("added", [])
                if key.startswith("public:")
            ),
            "removed_public_functions": sorted(
                f"{label}:{key.split(':', 1)[1]}"
                for label, item in files.items()
                for key in item.get("removed", [])
                if key.startswith("public:")
            ),
        },
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


if __name__ == "__main__":
    main()
