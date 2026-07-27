#!/usr/bin/env python3
"""Collect and index current public Synthetix V4 API-adjacent source.

Read-only bug-bounty research. The workflow clones public repositories, records immutable
commit SHAs, copies bounded text source, and builds keyword/context indices for offline review.
It performs no API authentication, account access, signature, transaction, or state change.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import shutil
import subprocess
from collections import defaultdict
from typing import Any

OUT = pathlib.Path("synthetix_vendored_api_review")
SRC = OUT / "source_snapshot"
TMP = pathlib.Path("/tmp/synthetix-vendored-api-review")
OUT.mkdir(parents=True, exist_ok=True)
SRC.mkdir(parents=True, exist_ok=True)
shutil.rmtree(TMP, ignore_errors=True)
TMP.mkdir(parents=True, exist_ok=True)

REPOS = (
    "Fenway-snx/synthetix-mcp",
    "Fenway-snx/synthetix-go-sdk",
)

TEXT_EXTS = {
    ".go", ".py", ".ts", ".tsx", ".js", ".jsx", ".json", ".toml", ".yaml", ".yml",
    ".md", ".txt", ".sql", ".graphql", ".proto", ".sh", ".env", ".mod", ".sum",
}
SPECIAL_NAMES = {"Dockerfile", "Makefile", "LICENSE", "README"}
SKIP_PARTS = {".git", "node_modules", "dist", "build", "vendor", "coverage", ".next"}
MAX_FILE_BYTES = 2_000_000
MAX_CONTEXT_CHARS = 1_200

TERMS = (
    "withdrawCollateral", "pendingWithdraw", "withdrawable", "reservation", "reserve",
    "transaction", "serializable", "atomic", "concurrent", "mutex", "lock",
    "addDelegatedSigner", "removeDelegatedSigner", "removeAllDelegatedSigners", "addedBy",
    "delegation", "delegate", "manager", "session", "revoke", "revocation",
    "auth cache", "authCache", "authorization", "ownership", "owner",
    "nonce", "nonce already used", "consume", "rate limit", "rateLimit",
    "getSubAccountIds", "subAccountId", "subaccountId", "CreateSubaccount",
    "ScheduleCancel", "cancelAllOrders", "VoluntaryCollateralExchange",
    "account ownership verification failed", "UNAUTHORIZED", "INVALID_FORMAT",
    "papi.synthetix.io", "api.test.synthetix.io", "api.synthetix.io",
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(cmd: list[str], cwd: pathlib.Path | None = None, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
    )


def clone(repo: str) -> tuple[pathlib.Path, dict[str, Any]]:
    dest = TMP / repo.replace("/", "__")
    proc = run(["git", "clone", "--depth", "1", "--filter=blob:none", f"https://github.com/{repo}.git", str(dest)])
    if proc.returncode != 0:
        raise RuntimeError(f"clone failed for {repo}: {proc.stderr[:500]}")
    sha = run(["git", "rev-parse", "HEAD"], cwd=dest).stdout.strip()
    branch = run(["git", "branch", "--show-current"], cwd=dest).stdout.strip()
    remote = run(["git", "remote", "get-url", "origin"], cwd=dest).stdout.strip()
    return dest, {"repository": repo, "commit": sha, "branch": branch, "remote": remote}


def is_text_candidate(path: pathlib.Path) -> bool:
    if not path.is_file() or any(part in SKIP_PARTS for part in path.parts):
        return False
    if path.stat().st_size > MAX_FILE_BYTES:
        return False
    return path.suffix.lower() in TEXT_EXTS or path.name in SPECIAL_NAMES or path.name.startswith("README")


def copy_and_index(repo: str, root: pathlib.Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    manifest: list[dict[str, Any]] = []
    hits: list[dict[str, Any]] = []
    counts: dict[str, int] = defaultdict(int)
    target_root = SRC / repo.replace("/", "__")

    for path in sorted(root.rglob("*")):
        if not is_text_candidate(path):
            continue
        rel = path.relative_to(root)
        data = path.read_bytes()
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("utf-8", errors="replace")
        out_path = target_root / rel
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text, encoding="utf-8")
        manifest.append({
            "repository": repo,
            "path": str(rel),
            "bytes": len(data),
            "sha256": sha256_bytes(data),
            "lineCount": text.count("\n") + 1,
        })

        lower = text.lower()
        lines = text.splitlines()
        for term in TERMS:
            needle = term.lower()
            if needle not in lower:
                continue
            for line_no, line in enumerate(lines, 1):
                if needle not in line.lower():
                    continue
                counts[term] += 1
                start = max(0, line_no - 4)
                end = min(len(lines), line_no + 3)
                context = "\n".join(f"{i + 1}: {lines[i]}" for i in range(start, end))
                hits.append({
                    "repository": repo,
                    "path": str(rel),
                    "term": term,
                    "line": line_no,
                    "context": context[:MAX_CONTEXT_CHARS],
                })
    return manifest, hits, dict(counts)


def main() -> None:
    repositories = []
    all_manifest: list[dict[str, Any]] = []
    all_hits: list[dict[str, Any]] = []
    term_totals: dict[str, int] = defaultdict(int)

    for repo in REPOS:
        root, meta = clone(repo)
        manifest, hits, counts = copy_and_index(repo, root)
        meta.update({"textFileCount": len(manifest), "keywordHitCount": len(hits)})
        repositories.append(meta)
        all_manifest.extend(manifest)
        all_hits.extend(hits)
        for term, count in counts.items():
            term_totals[term] += count

    summary = {
        "safety": "Public Git reads only; no auth, signer, account, transaction, or protocol mutation.",
        "repositories": repositories,
        "textFileCount": len(all_manifest),
        "keywordHitCount": len(all_hits),
        "termTotals": dict(sorted(term_totals.items())),
        "notProductionBinding": (
            "Public SDK/MCP or vendored support source is not assumed to equal the current production backend. "
            "Any candidate requires independent behavioral or byte/source binding."
        ),
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    (OUT / "manifest.json").write_text(json.dumps(all_manifest, indent=2, sort_keys=True), encoding="utf-8")
    (OUT / "keyword_hits.json").write_text(json.dumps(all_hits, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
