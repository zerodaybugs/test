#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path.cwd()
OUT = ROOT / "results" / "ms11-recent-security-scan"
WORK = ROOT / ".tmp-ms11-security-scan"
SINCE = "2026-04-01"

REPOS = [
    ("dotnet/aspnetcore", "https://github.com/dotnet/aspnetcore.git"),
    ("dotnet/runtime", "https://github.com/dotnet/runtime.git"),
    ("AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet", "https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet.git"),
    ("microsoft/reverse-proxy", "https://github.com/microsoft/reverse-proxy.git"),
    ("NuGet/NuGet.Client", "https://github.com/NuGet/NuGet.Client.git"),
    ("microsoft/msquic", "https://github.com/microsoft/msquic.git"),
]

KEYWORDS = {
    "auth": 8,
    "authentication": 10,
    "authorization": 10,
    "security": 10,
    "vulnerability": 12,
    "cve": 15,
    "bypass": 12,
    "privilege": 12,
    "permission": 8,
    "tenant": 10,
    "issuer": 9,
    "signing key": 10,
    "token": 6,
    "certificate": 8,
    "cookie": 7,
    "origin": 6,
    "host": 4,
    "header": 4,
    "cache key": 9,
    "collision": 10,
    "normalize": 7,
    "canonical": 8,
    "escape": 7,
    "validation": 6,
    "validate": 5,
    "path traversal": 14,
    "traversal": 10,
    "symlink": 10,
    "hardlink": 10,
    "extract": 5,
    "archive": 4,
    "request smuggling": 15,
    "smuggling": 13,
    "desync": 13,
    "content-length": 8,
    "chunked": 7,
    "http/1": 5,
    "proxy": 4,
    "redirect": 5,
    "ssrf": 15,
    "ldap": 8,
    "lkg": 10,
    "last known good": 10,
    "refresh": 4,
    "race": 6,
    "toctou": 12,
    "overflow": 8,
    "out of bounds": 12,
    "use-after-free": 15,
    "memory corruption": 15,
}

HIGH_SIGNAL_PATHS = [
    "auth", "security", "identity", "token", "jwt", "openid", "oauth", "cookie",
    "certificate", "cache", "proxy", "http", "kestrel", "yarp", "tar", "zip",
    "archive", "extract", "path", "header", "host", "redirect", "ldap", "negotiate",
    "quic", "tls", "crypto", "signature", "permission", "authorization",
]

@dataclass
class Hit:
    repo: str
    sha: str
    date: str
    subject: str
    score: int
    matched_keywords: list[str]
    files: list[str]
    stats: str
    patch_excerpt: str


def run(args: list[str], cwd: Path | None = None, timeout: int = 600, check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(args, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if check and proc.returncode != 0:
        raise RuntimeError(f"command failed {args}: {proc.stderr[-4000:]}")
    return proc


def score_text(text: str) -> tuple[int, list[str]]:
    lower = text.lower()
    matched: list[str] = []
    total = 0
    for word, points in KEYWORDS.items():
        if word in lower:
            matched.append(word)
            total += points
    return total, matched


def scan_repo(name: str, url: str) -> tuple[list[Hit], dict]:
    target = WORK / name.replace("/", "__")
    if target.exists():
        shutil.rmtree(target)
    clone = run(["git", "clone", "--filter=blob:none", "--no-tags", "--depth", "1600", url, str(target)], timeout=1200, check=False)
    if clone.returncode != 0:
        return [], {"repo": name, "clone_ok": False, "error": clone.stderr[-2000:]}

    head = run(["git", "rev-parse", "HEAD"], cwd=target).stdout.strip()
    log = run([
        "git", "log", f"--since={SINCE}", "--no-merges",
        "--format=%H%x1f%aI%x1f%s%x1e"
    ], cwd=target).stdout

    raw_commits = [row for row in log.split("\x1e") if row.strip()]
    prelim: list[tuple[int, str, str, str, list[str]]] = []
    for row in raw_commits:
        parts = row.strip().split("\x1f")
        if len(parts) != 3:
            continue
        sha, date, subject = parts
        score, matched = score_text(subject)
        if score:
            prelim.append((score, sha, date, subject, matched))

    # Also include commits touching high-signal paths even if the subject is bland.
    recent_shas = [x.split("\x1f", 1)[0].strip() for x in raw_commits if "\x1f" in x]
    for sha in recent_shas[:700]:
        if any(p[1] == sha for p in prelim):
            continue
        names = run(["git", "show", "--format=", "--name-only", "--diff-filter=AMDR", sha], cwd=target, timeout=60, check=False).stdout.splitlines()
        joined = " ".join(names).lower()
        path_score = sum(2 for part in HIGH_SIGNAL_PATHS if part in joined)
        if path_score >= 4:
            meta = run(["git", "show", "-s", "--format=%aI%x1f%s", sha], cwd=target).stdout.strip().split("\x1f", 1)
            if len(meta) == 2:
                prelim.append((path_score, sha, meta[0], meta[1], ["high-signal-paths"]))

    prelim.sort(key=lambda x: (x[0], x[2]), reverse=True)
    hits: list[Hit] = []
    seen: set[str] = set()
    for base_score, sha, date, subject, matched in prelim[:140]:
        if sha in seen:
            continue
        seen.add(sha)
        show_names = run(["git", "show", "--format=", "--name-only", "--diff-filter=AMDR", sha], cwd=target, timeout=90, check=False).stdout
        files = [x.strip() for x in show_names.splitlines() if x.strip()][:80]
        path_text = " ".join(files)
        path_score, path_matched = score_text(path_text)
        stats = run(["git", "show", "--stat", "--oneline", "--no-renames", sha], cwd=target, timeout=90, check=False).stdout[-6000:]
        patch = run(["git", "show", "--format=", "--unified=2", "--no-ext-diff", "--no-renames", sha], cwd=target, timeout=120, check=False).stdout
        excerpt_lines = []
        for line in patch.splitlines():
            ll = line.lower()
            if any(k in ll for k in KEYWORDS) or line.startswith("diff --git") or line.startswith("@@"):
                excerpt_lines.append(line[:500])
            if len(excerpt_lines) >= 80:
                break
        total = base_score + min(path_score, 30)
        hits.append(Hit(
            repo=name,
            sha=sha,
            date=date,
            subject=subject,
            score=total,
            matched_keywords=sorted(set(matched + path_matched)),
            files=files,
            stats=stats,
            patch_excerpt="\n".join(excerpt_lines),
        ))

    hits.sort(key=lambda h: (h.score, h.date), reverse=True)
    return hits[:80], {
        "repo": name,
        "clone_ok": True,
        "head": head,
        "commits_since": len(raw_commits),
        "hits": len(hits[:80]),
    }


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir(parents=True)

    all_hits: list[Hit] = []
    repos_meta: list[dict] = []
    for name, url in REPOS:
        hits, meta = scan_repo(name, url)
        all_hits.extend(hits)
        repos_meta.append(meta)

    all_hits.sort(key=lambda h: (h.score, h.date), reverse=True)
    result = {
        "schema": "ms11-recent-security-scan/v1",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "since": SINCE,
        "repos": repos_meta,
        "top_hits": [asdict(h) for h in all_hits[:220]],
        "verdict": "STATIC_TRIAGE_ONLY_NOT_A_VULNERABILITY",
        "submission_ready": False,
    }
    (OUT / "SCAN.json").write_text(json.dumps(result, indent=2), encoding="utf-8")

    md = [
        "# MS11 recent security-adjacent source scan",
        "",
        "This is static triage only. It is not a vulnerability report.",
        "",
        "| Score | Date | Repository | Commit | Subject |",
        "|---:|---|---|---|---|",
    ]
    for h in all_hits[:120]:
        md.append(f"| {h.score} | {h.date[:10]} | `{h.repo}` | `{h.sha[:12]}` | {h.subject.replace('|', '/')} |")
    (OUT / "SCAN.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    shutil.rmtree(WORK, ignore_errors=True)


if __name__ == "__main__":
    main()
