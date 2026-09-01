#!/usr/bin/env python3
"""Exhaustive public TermMax frontend lazy-chunk scan.

Runs the base public frontend collector, parses the Next.js webpack runtime to
recover every lazy JavaScript chunk URL, downloads those public assets, and
searches for MakerHelper order/delegation/retry semantics. Public HTTPS GET
requests only; no wallet, signer, transaction, or exploit execution.
"""
from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path
from typing import Any

BASE_PATH = Path(__file__).with_name("termmax_frontend_retry_semantics_20260728.py")
SPEC = importlib.util.spec_from_file_location("termmax_frontend_base", BASE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot import base collector: {BASE_PATH}")
base = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(base)


def parse_pairs(text: str) -> dict[int, str]:
    return {
        int(match.group(1)): match.group(2)
        for match in re.finditer(r"(\d+):\"([^\"]+)\"", text)
    }


def enumerate_runtime_chunks(runtime_url: str, runtime_text: str) -> set[str]:
    """Recover chunk URLs from the concrete `c.u` mapping in Next's runtime."""
    urls: set[str] = set()

    # Explicit ternary paths such as:
    # 164===e ? "static/chunks/164-<hash>.js" : ...
    for match in re.finditer(r'\d+===e\?\"(static/chunks/[^\"]+\.js)\"', runtime_text):
        urls.add(base.urljoin(base.ORIGIN + "/_next/", match.group(1)))

    # Generic path builder:
    # "static/chunks/" + (({id:"name"})[e] || e) + "." + ({id:"hash"})[e] + ".js"
    marker = '"static/chunks/"+'
    start = runtime_text.find(marker)
    if start >= 0:
        tail = runtime_text[start:]
        split_marker = '})[e]||e)+"."+({'
        split_at = tail.find(split_marker)
        if split_at >= 0:
            name_text = tail[: split_at + 2]
            rest = tail[split_at + len(split_marker) - 1 :]
            end_at = rest.find('})[e]+".js"')
            hash_text = rest[: end_at + 2] if end_at >= 0 else rest[:20000]
            name_map = parse_pairs(name_text)
            hash_map = parse_pairs(hash_text)
            for chunk_id, digest in hash_map.items():
                chunk_name = name_map.get(chunk_id, str(chunk_id))
                urls.add(
                    base.urljoin(
                        base.ORIGIN + "/_next/",
                        f"static/chunks/{chunk_name}.{digest}.js",
                    )
                )

    # Defensive fallback: the hash table is distinctive and can be recovered
    # even if the exact minifier punctuation changes.
    if len(urls) < 20:
        all_pairs = parse_pairs(runtime_text)
        for chunk_id, value in all_pairs.items():
            if re.fullmatch(r"[0-9a-f]{16}", value):
                urls.add(
                    base.urljoin(
                        base.ORIGIN + "/_next/",
                        f"static/chunks/{chunk_id}.{value}.js",
                    )
                )

    return urls


def high_signal_contexts(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    names = {
        "placeOrderForV2",
        "makerHelperEthereum",
        "delegateParams",
        "delegateSignature",
        "DelegationWithSig",
        "cryptoGetRandomValues",
        "randomBytes",
        "MathRandom",
        "salt",
        "retry",
        "waitForTransactionReceipt",
        "simulateContract",
        "writeContract",
        "nonce",
    }
    return [row for row in findings if row.get("pattern") in names]


def main() -> int:
    base.main()
    out = base.OUT
    asset_index_path = out / "ASSET_INDEX.json"
    asset_index = json.loads(asset_index_path.read_text(encoding="utf-8"))

    runtime_candidates = [
        (url, entry)
        for url, entry in asset_index.items()
        if "webpack-" in url and entry.get("savedAs")
    ]
    if not runtime_candidates:
        raise RuntimeError("webpack runtime asset was not captured")

    all_lazy_urls: set[str] = set()
    runtimes: list[dict[str, Any]] = []
    for runtime_url, entry in runtime_candidates:
        path = out / entry["savedAs"]
        text = path.read_text(encoding="utf-8", errors="ignore")
        urls = enumerate_runtime_chunks(runtime_url, text)
        all_lazy_urls.update(urls)
        runtimes.append(
            {
                "url": runtime_url,
                "savedAs": entry["savedAs"],
                "enumeratedChunkCount": len(urls),
            }
        )

    already_seen = set(asset_index)
    lazy_index: dict[str, dict[str, Any]] = {}
    lazy_findings: list[dict[str, Any]] = []
    map_candidates: set[str] = set()

    for number, url in enumerate(sorted(all_lazy_urls), start=1):
        if url in already_seen:
            lazy_index[url] = {"alreadyCaptured": True, **asset_index[url]}
            continue
        try:
            response = base.fetch(url)
            text = response.text
            digest = base.hashlib.sha256(response.content).hexdigest()
            destination = out / "lazy-assets" / f"{digest}.js"
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(text, encoding="utf-8")
            rows = base.scan_text("lazy-javascript", response.url, text)
            lazy_findings.extend(rows)
            map_candidates.update(base.source_map_urls(response.url, text))
            lazy_index[url] = {
                "ordinal": number,
                "finalUrl": response.url,
                "status": response.status_code,
                "bytes": len(response.content),
                "sha256": digest,
                "savedAs": str(destination.relative_to(out)),
                "findingCount": len(rows),
            }
        except Exception as exc:  # noqa: BLE001
            lazy_index[url] = {
                "ordinal": number,
                "error": f"{type(exc).__name__}: {exc}",
            }

    lazy_maps: dict[str, dict[str, Any]] = {}
    lazy_map_findings: list[dict[str, Any]] = []
    for url in sorted(map_candidates)[:1000]:
        try:
            response = base.fetch(url, attempts=2)
            if len(response.content) > 100_000_000:
                lazy_maps[url] = {"error": "source map exceeds 100 MB"}
                continue
            text = response.text
            digest = base.hashlib.sha256(response.content).hexdigest()
            destination = out / "lazy-maps" / f"{digest}.map"
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(text, encoding="utf-8")
            rows = base.scan_text("lazy-source-map", response.url, text)
            lazy_map_findings.extend(rows)
            lazy_maps[url] = {
                "finalUrl": response.url,
                "bytes": len(response.content),
                "sha256": digest,
                "savedAs": str(destination.relative_to(out)),
                "findingCount": len(rows),
            }
        except Exception as exc:  # noqa: BLE001
            lazy_maps[url] = {"error": f"{type(exc).__name__}: {exc}"}

    all_findings = lazy_findings + lazy_map_findings
    relevant_urls = sorted(
        {
            row["url"]
            for row in all_findings
            if row["pattern"]
            in {
                "placeOrderForV2",
                "makerHelperEthereum",
                "delegateParams",
                "delegateSignature",
                "DelegationWithSig",
            }
        }
    )
    summary = {
        "schema": "termmax-public-frontend-lazy-chunk-scan/v1",
        "origin": base.ORIGIN,
        "runtimes": runtimes,
        "enumeratedChunkCount": len(all_lazy_urls),
        "newChunkSuccessCount": sum("savedAs" in row for row in lazy_index.values()),
        "newChunkErrorCount": sum("error" in row for row in lazy_index.values()),
        "lazySourceMapSuccessCount": sum("savedAs" in row for row in lazy_maps.values()),
        "findingCount": len(all_findings),
        "highSignalFindingCount": len(high_signal_contexts(all_findings)),
        "relevantUrls": relevant_urls,
        "highSignalFindings": high_signal_contexts(all_findings),
    }
    (out / "LAZY_ASSET_INDEX.json").write_text(
        json.dumps(lazy_index, indent=2), encoding="utf-8"
    )
    (out / "LAZY_SOURCE_MAP_INDEX.json").write_text(
        json.dumps(lazy_maps, indent=2), encoding="utf-8"
    )
    (out / "LAZY_ALL_FINDINGS.json").write_text(
        json.dumps(all_findings, indent=2), encoding="utf-8"
    )
    (out / "LAZY_SUMMARY.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )
    print(json.dumps({
        "enumeratedChunkCount": summary["enumeratedChunkCount"],
        "newChunkSuccessCount": summary["newChunkSuccessCount"],
        "newChunkErrorCount": summary["newChunkErrorCount"],
        "highSignalFindingCount": summary["highSignalFindingCount"],
        "relevantUrls": summary["relevantUrls"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
