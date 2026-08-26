#!/usr/bin/env python3
"""Build a searchable prior-art index from public Makina audit PDFs.

Input is a directory of pdftotext outputs. The script extracts likely finding
headings, severity-bearing lines, and keyword contexts relevant to the exact
v1.2.0 bounty review. It does not modify or test any deployed system.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
from dataclasses import asdict, dataclass

SEVERITY_RE = re.compile(
    r"\b(Critical|High|Medium|Low|Informational|Info|Note|Acknowledged|Resolved|Open)\b",
    re.IGNORECASE,
)
NUMBERED_HEADING_RE = re.compile(r"^\s*(?:[A-Z]{1,4}-\d+|\d+(?:\.\d+){1,3})\s+\S")
TITLE_RE = re.compile(r"^[A-Z][A-Za-z0-9_()'’/+:,.-]*(?:\s+[A-Z0-9][A-Za-z0-9_()'’/+:,.-]*){2,}$")

KEYWORDS = [
    "AsyncRedeemer",
    "SecurityModule",
    "Watermark",
    "fee",
    "cooldown",
    "redeem",
    "claim",
    "bridge",
    "Across",
    "LayerZero",
    "Wormhole",
    "accounting",
    "share price",
    "AUM",
    "reentrancy",
    "storage",
    "initializer",
    "upgrade",
    "oracle",
    "Merkle",
    "Weiroll",
    "flashloan",
    "duplicate",
]


@dataclass(frozen=True)
class Context:
    source: str
    line: int
    keyword: str
    text: str


def normalize(line: str) -> str:
    return " ".join(line.strip().split())


def likely_heading(line: str) -> bool:
    clean = normalize(line)
    if len(clean) < 8 or len(clean) > 180:
        return False
    if NUMBERED_HEADING_RE.match(clean):
        return True
    if SEVERITY_RE.search(clean) and len(clean.split()) <= 18:
        return True
    if TITLE_RE.match(clean) and len(clean.split()) <= 16:
        return True
    return False


def context_window(lines: list[str], center: int, radius: int = 2) -> str:
    start = max(0, center - radius)
    end = min(len(lines), center + radius + 1)
    return " | ".join(normalize(lines[i]) for i in range(start, end) if normalize(lines[i]))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("text_dir", type=pathlib.Path)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args()

    headings: dict[str, list[dict[str, object]]] = {}
    contexts: list[Context] = []
    source_stats: dict[str, dict[str, int]] = {}

    for path in sorted(args.text_dir.rglob("*.txt")):
        rel = str(path.relative_to(args.text_dir))
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        source_headings: list[dict[str, object]] = []
        for idx, line in enumerate(lines, 1):
            clean = normalize(line)
            if likely_heading(line):
                source_headings.append({"line": idx, "text": clean})
            lower = clean.lower()
            for keyword in KEYWORDS:
                if keyword.lower() in lower:
                    contexts.append(
                        Context(
                            source=rel,
                            line=idx,
                            keyword=keyword,
                            text=context_window(lines, idx - 1),
                        )
                    )
        headings[rel] = source_headings
        source_stats[rel] = {
            "lines": len(lines),
            "headings": len(source_headings),
            "keyword_contexts": sum(1 for item in contexts if item.source == rel),
        }

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "audit_headings.json").write_text(
        json.dumps(headings, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (args.out / "audit_keyword_contexts.json").write_text(
        json.dumps([asdict(item) for item in contexts], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (args.out / "audit_source_stats.json").write_text(
        json.dumps(source_stats, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    lines = [
        f"sources={len(source_stats)}",
        f"headings={sum(v['headings'] for v in source_stats.values())}",
        f"keyword_contexts={len(contexts)}",
    ]
    for source, stats in sorted(source_stats.items()):
        lines.append(
            f"{source}: lines={stats['lines']} headings={stats['headings']} contexts={stats['keyword_contexts']}"
        )
    (args.out / "audit_prior_art_summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
