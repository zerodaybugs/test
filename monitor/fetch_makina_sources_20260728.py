#!/usr/bin/env python3
"""Fetch public verified sources and metadata for the TermMax–Makina DUSD oracle chain.

Public HTTPS GET requests only. No chain writes, key material, or transactions.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

import requests

OUT = Path(os.environ.get("OUT_DIR", "evidence"))
OUT.mkdir(parents=True, exist_ok=True)

ADDRESSES = {
    "makina_machine_share_oracle_impl": "0xCEC00D97aA65B12d3389518f3aD4BDF25336B25b",
    "makina_dusd_oracle_proxy": "0xFFCBc7A7eEF2796C277095C66067aC749f4cA078",
    "termmax_dusd_adapter": "0x458e718fF8687b6eBF2dE22AeBa13f2d2d50a537",
    "dusd": "0x1e33E98aF620F1D563fcD3cfd3C75acE841204ef",
}

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "ZeroDayBugs-TermMax-Makina-Public-Source/1.0"})


def get_json(url: str) -> dict[str, Any]:
    response = SESSION.get(url, timeout=90)
    response.raise_for_status()
    return response.json()


def get_text(url: str) -> str:
    response = SESSION.get(url, timeout=90)
    response.raise_for_status()
    return response.text


def write_sources(label: str, payload: dict[str, Any]) -> list[str]:
    written: list[str] = []
    candidates: list[dict[str, Any]] = []
    for key in ("sources", "compilation", "compiler"):
        value = payload.get(key)
        if isinstance(value, dict):
            candidates.append(value)
    compilation = payload.get("compilation")
    if isinstance(compilation, dict):
        for key in ("sources", "compilerOutput", "compilerInput"):
            value = compilation.get(key)
            if isinstance(value, dict):
                candidates.append(value)
    for candidate in candidates:
        sources = candidate.get("sources") if isinstance(candidate.get("sources"), dict) else candidate
        if not isinstance(sources, dict):
            continue
        for source_path, source_obj in sources.items():
            content = source_obj.get("content") if isinstance(source_obj, dict) else None
            if not isinstance(content, str):
                continue
            safe_path = re.sub(r"[^A-Za-z0-9._/-]+", "_", str(source_path)).lstrip("/")
            destination = OUT / "sources" / label / safe_path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(content, encoding="utf-8")
            written.append(str(destination.relative_to(OUT)))
    return sorted(set(written))


def main() -> int:
    summary: dict[str, Any] = {"addresses": ADDRESSES, "results": {}}
    for label, address in ADDRESSES.items():
        entry: dict[str, Any] = {"address": address}
        sourcify_url = f"https://sourcify.dev/server/v2/contract/1/{address}?fields=all"
        try:
            payload = get_json(sourcify_url)
            path = OUT / f"sourcify_{label}.json"
            path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            entry["sourcify"] = {
                "ok": True,
                "url": sourcify_url,
                "match": payload.get("match"),
                "creationMatch": payload.get("creationMatch"),
                "runtimeMatch": payload.get("runtimeMatch"),
                "contractName": payload.get("compilation", {}).get("name") if isinstance(payload.get("compilation"), dict) else None,
                "sourceFiles": write_sources(label, payload),
            }
        except Exception as exc:
            entry["sourcify"] = {"ok": False, "url": sourcify_url, "error": f"{type(exc).__name__}: {exc}"}

        etherscan_url = f"https://etherscan.io/address/{address.lower()}#code"
        try:
            html = get_text(etherscan_url)
            (OUT / f"etherscan_{label}.html").write_text(html, encoding="utf-8")
            contract_name_match = re.search(r"Contract Name.*?<div[^>]*>\s*([^<]+)", html, re.S | re.I)
            entry["etherscan"] = {
                "ok": True,
                "url": etherscan_url,
                "bytes": len(html.encode()),
                "containsMachineShareOracle": "MachineShareOracle" in html,
                "containsTermMaxDUSD": "TermMaxDUSD" in html or "DUSDPrice" in html,
                "contractNameHeuristic": contract_name_match.group(1).strip() if contract_name_match else None,
            }
        except Exception as exc:
            entry["etherscan"] = {"ok": False, "url": etherscan_url, "error": f"{type(exc).__name__}: {exc}"}
        summary["results"][label] = entry

    (OUT / "SOURCE_FETCH_SUMMARY.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
