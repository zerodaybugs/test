#!/usr/bin/env python3
"""Security-focused semantic census for Sui's latest Move runtime vs execution v3.

This script is intentionally read-only. It compares the current mainnet execution
implementation with the immediately preceding versioned implementation and emits
ranked review targets for verifier, runtime, loader/cache, object authorization,
and gas/stack semantics.
"""

from __future__ import annotations

import argparse
import csv
import difflib
import hashlib
import json
import os
import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Iterator


RISK_TERMS: dict[str, int] = {
    "unsafe": 20,
    "transmute": 20,
    "unchecked": 18,
    "bypass": 18,
    "visibility": 12,
    "private": 7,
    "friend": 8,
    "signer": 14,
    "authorization": 16,
    "owner": 12,
    "ownership": 12,
    "receiving": 14,
    "object": 5,
    "linkage": 13,
    "type_origin": 15,
    "defining_id": 15,
    "package": 6,
    "upgrade": 12,
    "module": 4,
    "loader": 11,
    "cache": 8,
    "deserialize": 12,
    "serialization": 10,
    "bcs": 8,
    "ability": 13,
    "constraint": 13,
    "reference": 10,
    "borrow": 11,
    "alias": 12,
    "global": 7,
    "native": 8,
    "stack": 11,
    "gas": 6,
    "meter": 8,
    "vector": 5,
    "enum": 7,
    "variant": 7,
    "struct": 4,
    "invariant": 14,
    "bounds": 11,
    "index": 6,
    "length": 5,
    "arity": 13,
    "phantom": 10,
    "recursive": 8,
    "cycle": 10,
    "acquires": 8,
    "drop": 4,
    "copy": 4,
    "store": 3,
    "key": 4,
}

GUARD_RE = re.compile(
    r"\b(assert|ensure|check|verify|validate|constraint|ability|abilities|"
    r"len\s*\(|length|arity|is_empty|contains|visibility|private|friend|"
    r"type_matches|is_valid|bounds|overflow|underflow)\b",
    re.IGNORECASE,
)
PANIC_RE = re.compile(
    r"\b(unwrap|expect|panic!|unreachable!|unimplemented!|todo!|assert!|"
    r"debug_assert!|debug_assert_eq!|debug_assert_ne!)\b"
)
UNSAFE_RE = re.compile(r"\bunsafe\b|transmute|from_raw|unchecked")
INDEX_RE = re.compile(r"(?<![A-Za-z0-9_])(?:[A-Za-z_][A-Za-z0-9_\.]*|\))\s*\[[^\]]+\]")
FUNCTION_RE = re.compile(
    r"^(?P<indent>\s*)(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?fn\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
    re.MULTILINE,
)
TEST_RE = re.compile(r"#\s*\[(?:test|tokio::test|sim_test|cfg\s*\(test\))[^\]]*\]")


@dataclass
class DiffFinding:
    component: str
    relative_path: str
    score: int
    removed_guards: int
    added_panics: int
    added_unsafe: int
    added_debug_only_guards: int
    removed_tests: int
    added_tests: int
    security_terms: list[str]
    old_exists: bool
    new_exists: bool
    old_lines: int
    new_lines: int
    diff_sha256: str
    diff_file: str | None = None


@dataclass
class SurfaceFinding:
    component: str
    relative_path: str
    line: int
    kind: str
    score: int
    function: str
    text: str


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def iter_rust_files(root: Path) -> Iterator[Path]:
    if not root.exists():
        return
    for path in sorted(root.rglob("*.rs")):
        if any(part in {"target", "generated", "snapshots"} for part in path.parts):
            continue
        yield path


def function_for_line(lines: list[str], line_number: int) -> str:
    current = "<module>"
    for idx, line in enumerate(lines, start=1):
        match = FUNCTION_RE.search(line)
        if match:
            current = match.group("name")
        if idx >= line_number:
            return current
    return current


def risk_terms(text: str) -> list[str]:
    lower = text.lower()
    return sorted(term for term in RISK_TERMS if term in lower)


def line_score(text: str) -> int:
    lower = text.lower()
    score = sum(weight for term, weight in RISK_TERMS.items() if term in lower)
    if PANIC_RE.search(text):
        score += 12
    if UNSAFE_RE.search(text):
        score += 20
    if INDEX_RE.search(text):
        score += 5
    return score


def compare_file(
    component: str,
    rel: str,
    old_path: Path,
    new_path: Path,
    diff_dir: Path,
) -> tuple[DiffFinding, list[SurfaceFinding]]:
    old_lines = read_lines(old_path)
    new_lines = read_lines(new_path)
    diff_lines = list(
        difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile=f"v3/{rel}",
            tofile=f"latest/{rel}",
            lineterm="",
            n=4,
        )
    )
    diff_text = "\n".join(diff_lines) + ("\n" if diff_lines else "")

    removed = [line[1:] for line in diff_lines if line.startswith("-") and not line.startswith("---")]
    added = [line[1:] for line in diff_lines if line.startswith("+") and not line.startswith("+++")]

    removed_guards = sum(bool(GUARD_RE.search(line)) for line in removed)
    added_panics = sum(bool(PANIC_RE.search(line)) for line in added)
    added_unsafe = sum(bool(UNSAFE_RE.search(line)) for line in added)
    added_debug_only = sum("debug_assert" in line for line in added)
    removed_tests = sum(bool(TEST_RE.search(line)) for line in removed)
    added_tests = sum(bool(TEST_RE.search(line)) for line in added)

    terms = risk_terms("\n".join(removed + added))
    score = (
        removed_guards * 30
        + added_panics * 18
        + added_unsafe * 35
        + added_debug_only * 16
        + removed_tests * 20
        - added_tests * 2
        + sum(RISK_TERMS[t] for t in terms)
    )

    # A newly introduced security-sensitive file deserves review even without a matched v3 file.
    if new_path.exists() and not old_path.exists():
        score += 15 + sum(line_score(line) for line in new_lines[:400]) // 25
    if old_path.exists() and not new_path.exists():
        score += 25 + removed_guards * 10

    diff_name: str | None = None
    if diff_text and score > 0:
        safe_component = re.sub(r"[^A-Za-z0-9_.-]+", "_", component)
        safe_rel = re.sub(r"[^A-Za-z0-9_.-]+", "_", rel)
        diff_name = f"{safe_component}__{safe_rel}.diff"
        (diff_dir / diff_name).write_text(diff_text, encoding="utf-8")

    surfaces: list[SurfaceFinding] = []
    for idx, line in enumerate(new_lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        kinds: list[tuple[str, int]] = []
        if UNSAFE_RE.search(stripped):
            kinds.append(("unsafe_or_unchecked", 45))
        if "unwrap(" in stripped or ".unwrap()" in stripped:
            kinds.append(("unwrap", 20))
        if ".expect(" in stripped:
            kinds.append(("expect", 18))
        if "unreachable!(" in stripped or "panic!(" in stripped:
            kinds.append(("panic_or_unreachable", 32))
        if "debug_assert" in stripped:
            kinds.append(("debug_only_guard", 25))
        if "saturating_" in stripped:
            kinds.append(("saturating_arithmetic", 16))
        if INDEX_RE.search(stripped):
            kinds.append(("direct_index", 8))
        if ".zip(" in stripped and "zip_eq" not in stripped and "zip_debug_eq" not in stripped:
            kinds.append(("silent_zip_truncation", 24))
        for kind, base in kinds:
            terms_here = risk_terms(stripped)
            score_here = base + sum(RISK_TERMS[t] for t in terms_here)
            surfaces.append(
                SurfaceFinding(
                    component=component,
                    relative_path=rel,
                    line=idx,
                    kind=kind,
                    score=score_here,
                    function=function_for_line(new_lines, idx),
                    text=stripped[:500],
                )
            )

    return (
        DiffFinding(
            component=component,
            relative_path=rel,
            score=max(score, 0),
            removed_guards=removed_guards,
            added_panics=added_panics,
            added_unsafe=added_unsafe,
            added_debug_only_guards=added_debug_only,
            removed_tests=removed_tests,
            added_tests=added_tests,
            security_terms=terms,
            old_exists=old_path.exists(),
            new_exists=new_path.exists(),
            old_lines=len(old_lines),
            new_lines=len(new_lines),
            diff_sha256=sha256_text(diff_text),
            diff_file=diff_name,
        ),
        surfaces,
    )


def test_names(root: Path) -> dict[str, set[str]]:
    result: dict[str, set[str]] = defaultdict(set)
    for path in iter_rust_files(root):
        lines = read_lines(path)
        pending_test = False
        for line in lines:
            if TEST_RE.search(line):
                pending_test = True
                continue
            match = FUNCTION_RE.search(line)
            if match and pending_test:
                result[path.relative_to(root).as_posix()].add(match.group("name"))
                pending_test = False
            elif line.strip() and not line.strip().startswith("#") and pending_test:
                # Keep attributes/comments between #[test] and fn, but reset on other code.
                if not line.strip().startswith("//"):
                    pending_test = False
    return result


def write_tsv(path: Path, rows: Iterable[dict[str, object]], fields: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, delimiter="\t")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--top-diffs", type=int, default=120)
    args = parser.parse_args()

    repo = args.repo.resolve()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    diff_dir = out / "top_diffs"
    diff_dir.mkdir(exist_ok=True)

    components = [
        (
            "move-vm-runtime",
            repo / "external-crates/move/move-execution/v3/crates/move-vm-runtime/src",
            repo / "external-crates/move/crates/move-vm-runtime/src",
        ),
        (
            "move-bytecode-verifier",
            repo / "external-crates/move/move-execution/v3/crates/move-bytecode-verifier/src",
            repo / "external-crates/move/crates/move-bytecode-verifier/src",
        ),
        (
            "sui-adapter",
            repo / "sui-execution/v3/sui-adapter/src",
            repo / "sui-execution/latest/sui-adapter/src",
        ),
        (
            "sui-verifier",
            repo / "sui-execution/v3/sui-verifier/src",
            repo / "sui-execution/latest/sui-verifier/src",
        ),
        (
            "sui-move-natives",
            repo / "sui-execution/v3/sui-move-natives/src",
            repo / "sui-execution/latest/sui-move-natives/src",
        ),
    ]

    findings: list[DiffFinding] = []
    surfaces: list[SurfaceFinding] = []
    component_status: dict[str, dict[str, object]] = {}
    test_gaps: list[dict[str, object]] = []

    for component, old_root, new_root in components:
        old_files = {p.relative_to(old_root).as_posix(): p for p in iter_rust_files(old_root)} if old_root.exists() else {}
        new_files = {p.relative_to(new_root).as_posix(): p for p in iter_rust_files(new_root)} if new_root.exists() else {}
        component_status[component] = {
            "old_root": str(old_root.relative_to(repo)) if old_root.exists() else str(old_root),
            "new_root": str(new_root.relative_to(repo)) if new_root.exists() else str(new_root),
            "old_exists": old_root.exists(),
            "new_exists": new_root.exists(),
            "old_files": len(old_files),
            "new_files": len(new_files),
        }
        for rel in sorted(set(old_files) | set(new_files)):
            finding, file_surfaces = compare_file(
                component,
                rel,
                old_files.get(rel, old_root / rel),
                new_files.get(rel, new_root / rel),
                diff_dir,
            )
            if finding.score or finding.old_exists != finding.new_exists:
                findings.append(finding)
            surfaces.extend(file_surfaces)

        old_tests = test_names(old_root) if old_root.exists() else {}
        new_tests = test_names(new_root) if new_root.exists() else {}
        for rel in sorted(set(old_tests) | set(new_tests)):
            missing = sorted(old_tests.get(rel, set()) - new_tests.get(rel, set()))
            added = sorted(new_tests.get(rel, set()) - old_tests.get(rel, set()))
            if missing or added:
                test_gaps.append(
                    {
                        "component": component,
                        "relative_path": rel,
                        "missing_from_latest": ",".join(missing),
                        "added_in_latest": ",".join(added),
                        "missing_count": len(missing),
                        "added_count": len(added),
                    }
                )

    findings.sort(key=lambda item: (-item.score, item.component, item.relative_path))
    surfaces.sort(key=lambda item: (-item.score, item.component, item.relative_path, item.line))

    # Keep only the highest-ranked diff files to bound artifact size; delete the rest.
    keep_diff_names = {f.diff_file for f in findings[: args.top_diffs] if f.diff_file}
    for path in diff_dir.glob("*.diff"):
        if path.name not in keep_diff_names:
            path.unlink()
    for f in findings:
        if f.diff_file not in keep_diff_names:
            f.diff_file = None

    write_tsv(
        out / "RANKED_DIFFS.tsv",
        (asdict(f) for f in findings),
        [
            "component",
            "relative_path",
            "score",
            "removed_guards",
            "added_panics",
            "added_unsafe",
            "added_debug_only_guards",
            "removed_tests",
            "added_tests",
            "security_terms",
            "old_exists",
            "new_exists",
            "old_lines",
            "new_lines",
            "diff_sha256",
            "diff_file",
        ],
    )
    write_tsv(
        out / "RANKED_PANIC_UNSAFE_SURFACES.tsv",
        (asdict(s) for s in surfaces[:2000]),
        ["component", "relative_path", "line", "kind", "score", "function", "text"],
    )
    write_tsv(
        out / "TEST_COVERAGE_DELTA.tsv",
        test_gaps,
        [
            "component",
            "relative_path",
            "missing_count",
            "added_count",
            "missing_from_latest",
            "added_in_latest",
        ],
    )

    by_component = Counter(f.component for f in findings)
    by_surface = Counter(s.kind for s in surfaces)
    top_candidates = []
    for rank, f in enumerate(findings[:40], start=1):
        candidate_class = []
        terms = set(f.security_terms)
        if terms & {"visibility", "private", "friend", "signer", "authorization", "owner", "ownership", "receiving"}:
            candidate_class.append("authorization/object-auth")
        if terms & {"type_origin", "defining_id", "linkage", "package", "upgrade", "loader", "cache"}:
            candidate_class.append("package-linkage/type-identity")
        if terms & {"ability", "constraint", "reference", "borrow", "alias", "phantom", "arity"}:
            candidate_class.append("verifier/type-safety")
        if terms & {"native", "stack", "gas", "meter"}:
            candidate_class.append("native/gas-stack")
        if not candidate_class:
            candidate_class.append("runtime-semantics")
        top_candidates.append(
            {
                "rank": rank,
                "component": f.component,
                "relative_path": f.relative_path,
                "score": f.score,
                "classes": candidate_class,
                "removed_guards": f.removed_guards,
                "added_panics": f.added_panics,
                "added_unsafe": f.added_unsafe,
                "diff_file": f.diff_file,
            }
        )

    payload = {
        "repository": str(repo),
        "components": component_status,
        "summary": {
            "ranked_diff_files": len(findings),
            "panic_or_unsafe_surfaces": len(surfaces),
            "test_delta_files": len(test_gaps),
            "diffs_by_component": dict(by_component),
            "surfaces_by_kind": dict(by_surface),
        },
        "top_candidates": top_candidates,
        "top_surfaces": [asdict(s) for s in surfaces[:100]],
        "test_gaps": test_gaps[:200],
    }
    (out / "VM_SECURITY_CENSUS.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    md: list[str] = [
        "# Sui new Move VM security census",
        "",
        "This report ranks semantic deltas between execution v3 and the latest mainnet runtime.",
        "A high score is a review priority, not a vulnerability claim.",
        "",
        "## Component coverage",
        "",
        "| Component | v3 files | latest files | ranked deltas |",
        "|---|---:|---:|---:|",
    ]
    for component, status in component_status.items():
        md.append(
            f"| `{component}` | {status['old_files']} | {status['new_files']} | {by_component.get(component, 0)} |"
        )
    md.extend(
        [
            "",
            "## Highest-priority semantic deltas",
            "",
            "| Rank | Score | Component | File | Candidate class | Removed guards | Panic/unsafe additions |",
            "|---:|---:|---|---|---|---:|---:|",
        ]
    )
    for item in top_candidates:
        md.append(
            "| {rank} | {score} | `{component}` | `{relative_path}` | {classes} | {removed_guards} | {risky} |".format(
                rank=item["rank"],
                score=item["score"],
                component=item["component"],
                relative_path=item["relative_path"],
                classes=", ".join(item["classes"]),
                removed_guards=item["removed_guards"],
                risky=item["added_panics"] + item["added_unsafe"],
            )
        )
    md.extend(
        [
            "",
            "## Runtime panic/unsafe surfaces",
            "",
            "| Rank | Score | Kind | Component | File:line | Function |",
            "|---:|---:|---|---|---|---|",
        ]
    )
    for rank, s in enumerate(surfaces[:80], start=1):
        md.append(
            f"| {rank} | {s.score} | `{s.kind}` | `{s.component}` | `{s.relative_path}:{s.line}` | `{s.function}` |"
        )
    md.extend(
        [
            "",
            "## Interpretation gate",
            "",
            "Promote a candidate only if a generated module or transaction:",
            "",
            "1. passes the active mainnet verifier and transaction checks;",
            "2. reaches consensus execution without privileged access;",
            "3. produces unauthorized object use, ownership/type confusion, effects divergence, or a validator-fatal condition;",
            "4. reproduces on an exact pinned local network; and",
            "5. is not already fixed, audited, documented, or duplicated publicly.",
            "",
            "A panic reachable only through direct internal APIs, dev-inspect, malformed local state, or debug-only builds is not bounty-ready.",
        ]
    )
    (out / "VM_SECURITY_CENSUS.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    print(json.dumps(payload["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
