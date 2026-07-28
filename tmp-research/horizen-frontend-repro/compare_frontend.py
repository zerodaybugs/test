#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, deque
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

SITE = "https://staking.horizen.io/"
EXPECTED_COMMIT = "e9ab9af5f9e5bb964e690878b6d41942e825991a"
EXPECTED_CHAIN = "26514"
EXPECTED_STAKER = "0x6bf7cf29a8bce11aa62cf593d165c244fa4d3e31"
EXPECTED_TOKEN = "0x57da2d504bf8b83ef304759d9f2648522d7a9280"
ASSET_RE = re.compile(r"(?:https?://[^\s\"'<>]+)?(/_next/static/[^\s\"'<>\\)]+)")
SOURCE_MAP_RE = re.compile(r"sourceMappingURL=([^\s*]+)")
EXECUTABLE_SUFFIXES = {".js", ".mjs", ".css", ".json", ".wasm"}


class GateError(RuntimeError):
    pass


class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.script_srcs: list[str] = []
        self.stylesheet_hrefs: list[str] = []
        self.inline_scripts: list[str] = []
        self._in_script = False
        self._current_script: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {k.lower(): v or "" for k, v in attrs}
        if tag.lower() == "script":
            src = values.get("src", "")
            if src:
                self.script_srcs.append(src)
            else:
                self._in_script = True
                self._current_script = []
        elif tag.lower() == "link":
            rel = values.get("rel", "").lower()
            href = values.get("href", "")
            if href and ("stylesheet" in rel or values.get("as", "").lower() in {"script", "style"}):
                self.stylesheet_hrefs.append(href)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self._in_script:
            self.inline_scripts.append("".join(self._current_script))
            self._in_script = False
            self._current_script = []

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._current_script.append(data)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch(url: str, timeout: int = 60) -> tuple[int | None, bytes, str | None, dict[str, str]]:
    req = urllib.request.Request(
        url,
        headers={
            "user-agent": "Mozilla/5.0 (compatible; Horizen-frontend-repro/1.0)",
            "accept": "text/html,application/javascript,text/css,application/json,*/*",
            "accept-encoding": "identity",
        },
    )
    last: Exception | None = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                headers = {k.lower(): v for k, v in response.headers.items()}
                return response.status, response.read(), response.geturl(), headers
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(), exc.geturl(), {k.lower(): v for k, v in exc.headers.items()}
        except Exception as exc:
            last = exc
            time.sleep(attempt + 1)
    return None, str(last).encode(), None, {}


def route_for_html(out_root: Path, html_path: Path) -> str:
    rel = html_path.relative_to(out_root).as_posix()
    if rel == "index.html":
        return "/"
    if rel.endswith("/index.html"):
        return "/" + rel[: -len("index.html")]
    if rel.endswith(".html"):
        return "/" + rel[:-5] + "/"
    return "/" + rel


def normalize_asset_path(value: str, base_url: str = SITE) -> tuple[str | None, bool]:
    absolute = urllib.parse.urljoin(base_url, value)
    parsed = urllib.parse.urlparse(absolute)
    site_host = urllib.parse.urlparse(SITE).netloc
    if parsed.netloc != site_host:
        return absolute, True
    path = urllib.parse.unquote(parsed.path)
    return path, False


def local_for_path(out_root: Path, path: str) -> Path:
    return out_root / path.lstrip("/")


def parse_page(body: bytes) -> PageParser:
    parser = PageParser()
    parser.feed(body.decode("utf-8", "ignore"))
    return parser


def inline_profile(scripts: list[str]) -> dict[str, Any]:
    cleaned = [script.strip() for script in scripts if script.strip()]
    return {
        "count": len(cleaned),
        "hashes": sorted(sha256(item.encode()) for item in cleaned),
        "next_bootstrap_count": sum("self.__next_f.push" in item for item in cleaned),
        "document_write_count": sum("document.write" in item.lower() for item in cleaned),
        "eval_count": sum(re.search(r"\beval\s*\(", item) is not None for item in cleaned),
        "wallet_rpc_count": sum("ethereum.request" in item or "eth_sendTransaction" in item for item in cleaned),
    }


def main() -> int:
    local_root = Path(os.environ["LOCAL_OUT"]).resolve()
    repo_root = Path(os.environ["SOURCE_ROOT"]).resolve()
    private = Path("private-evidence/frontend-repro")
    sanitized = Path("sanitized-frontend-repro")
    private.mkdir(parents=True, exist_ok=True)
    sanitized.mkdir(parents=True, exist_ok=True)

    head = os.popen(f"git -C {repo_root} rev-parse HEAD").read().strip()
    if head != EXPECTED_COMMIT:
        raise GateError(f"wrong source commit: {head}")
    if not local_root.is_dir():
        raise GateError(f"missing static export: {local_root}")

    local_assets: dict[str, Path] = {}
    for path in local_root.rglob("*"):
        if not path.is_file():
            continue
        rel = "/" + path.relative_to(local_root).as_posix()
        if rel.startswith("/_next/static/") and path.suffix.lower() in EXECUTABLE_SUFFIXES:
            local_assets[rel] = path

    exact_matches: list[str] = []
    missing_remote: list[dict[str, Any]] = []
    hash_mismatches: list[dict[str, Any]] = []
    remote_headers: dict[str, dict[str, str]] = {}
    remote_bodies: dict[str, bytes] = {}

    # Fetch every locally built executable asset by its content-addressed production path.
    for rel, local_path in sorted(local_assets.items()):
        status, body, final_url, headers = fetch(urllib.parse.urljoin(SITE, rel))
        remote_headers[rel] = headers
        if status != 200:
            missing_remote.append({"path": rel, "status": status, "final_url": final_url})
            continue
        local_body = local_path.read_bytes()
        remote_bodies[rel] = body
        if body == local_body:
            exact_matches.append(rel)
        else:
            hash_mismatches.append(
                {
                    "path": rel,
                    "local_bytes": len(local_body),
                    "remote_bytes": len(body),
                    "local_sha256": sha256(local_body),
                    "remote_sha256": sha256(body),
                }
            )

    # Crawl production pages and all recursively referenced Next static assets.
    html_files = sorted(local_root.rglob("*.html"))
    route_rows: list[dict[str, Any]] = []
    production_assets: set[str] = set()
    external_scripts: set[str] = set()
    external_styles: set[str] = set()
    suspicious_inline: list[dict[str, Any]] = []

    for html_path in html_files:
        route = route_for_html(local_root, html_path)
        status, body, final_url, headers = fetch(urllib.parse.urljoin(SITE, route))
        if status != 200:
            route_rows.append({"route": route, "status": status, "final_url": final_url, "reachable": False})
            continue
        parser = parse_page(body)
        local_parser = parse_page(html_path.read_bytes())
        for src in parser.script_srcs:
            normalized, external = normalize_asset_path(src, final_url or SITE)
            if external:
                external_scripts.add(normalized or src)
            elif normalized:
                production_assets.add(normalized)
        for href in parser.stylesheet_hrefs:
            normalized, external = normalize_asset_path(href, final_url or SITE)
            if external:
                external_styles.add(normalized or href)
            elif normalized and normalized.startswith("/_next/static/"):
                production_assets.add(normalized)
        remote_inline = inline_profile(parser.inline_scripts)
        local_inline = inline_profile(local_parser.inline_scripts)
        if remote_inline["document_write_count"] or remote_inline["eval_count"] or remote_inline["wallet_rpc_count"]:
            suspicious_inline.append({"route": route, "profile": remote_inline})
        route_rows.append(
            {
                "route": route,
                "status": status,
                "final_url": final_url,
                "reachable": True,
                "remote_script_src_count": len(parser.script_srcs),
                "remote_inline": remote_inline,
                "local_inline": local_inline,
                "inline_hash_multiset_equal": Counter(remote_inline["hashes"]) == Counter(local_inline["hashes"]),
                "content_security_policy": headers.get("content-security-policy", ""),
            }
        )

    queue = deque(sorted(production_assets))
    visited: set[str] = set()
    remote_only: list[dict[str, Any]] = []
    production_asset_mismatches: list[dict[str, Any]] = []
    source_map_refs: set[str] = set()
    while queue:
        rel = queue.popleft()
        if rel in visited:
            continue
        visited.add(rel)
        status, body, final_url, _ = fetch(urllib.parse.urljoin(SITE, rel))
        if status != 200:
            remote_only.append({"path": rel, "status": status, "reason": "production reference not fetchable"})
            continue
        remote_bodies.setdefault(rel, body)
        local_path = local_for_path(local_root, rel)
        if not local_path.is_file():
            remote_only.append({"path": rel, "status": status, "remote_sha256": sha256(body)})
        elif local_path.read_bytes() != body:
            production_asset_mismatches.append(
                {
                    "path": rel,
                    "local_sha256": sha256(local_path.read_bytes()),
                    "remote_sha256": sha256(body),
                    "local_bytes": local_path.stat().st_size,
                    "remote_bytes": len(body),
                }
            )
        text = body.decode("utf-8", "ignore")
        for discovered in ASSET_RE.findall(text):
            discovered_path = urllib.parse.unquote(urllib.parse.urlparse(discovered).path)
            if discovered_path not in visited:
                queue.append(discovered_path)
        for source_map in SOURCE_MAP_RE.findall(text):
            source_map_refs.add(urllib.parse.urljoin(urllib.parse.urljoin(SITE, rel), source_map))

    accessible_source_maps: list[dict[str, Any]] = []
    for url in sorted(source_map_refs):
        status, body, final_url, _ = fetch(url)
        if status == 200 and body:
            accessible_source_maps.append(
                {"url": url, "bytes": len(body), "sha256": sha256(body), "final_url": final_url}
            )

    combined_remote = b"\n".join(remote_bodies.values()).decode("utf-8", "ignore").lower()
    constants = {
        "mainnet_chain_id_present": EXPECTED_CHAIN in combined_remote,
        "mainnet_staker_present": EXPECTED_STAKER[2:] in combined_remote or EXPECTED_STAKER in combined_remote,
        "mainnet_token_present": EXPECTED_TOKEN[2:] in combined_remote or EXPECTED_TOKEN in combined_remote,
        "testnet_chain_id_present": "2651420" in combined_remote,
        "testnet_token_present": "b06ec4ce262d8dbdc24fac87479a49a7dc4cfb87" in combined_remote,
    }

    local_js = {rel for rel in local_assets if rel.endswith((".js", ".mjs"))}
    remote_js = {rel for rel in visited if rel.endswith((".js", ".mjs"))}
    remote_js_not_local = sorted(remote_js - local_js)
    referenced_local_js_missing_remote = sorted(
        rel for rel in remote_js & local_js if rel not in remote_bodies
    )

    csp_values = sorted({row.get("content_security_policy", "") for row in route_rows if row.get("reachable")})
    csp_present = any(csp_values)
    csp_has_self_script = any("script-src 'self'" in value for value in csp_values)

    critical_pass = all(
        [
            head == EXPECTED_COMMIT,
            len(local_js) > 0,
            not hash_mismatches,
            not production_asset_mismatches,
            not remote_js_not_local,
            not referenced_local_js_missing_remote,
            not external_scripts,
            not suspicious_inline,
            constants["mainnet_chain_id_present"],
            constants["mainnet_staker_present"],
            constants["mainnet_token_present"],
            not constants["testnet_token_present"],
        ]
    )

    result = {
        "source_commit": head,
        "local_static_asset_count": len(local_assets),
        "local_js_count": len(local_js),
        "local_exact_remote_matches": len(exact_matches),
        "local_assets_missing_remotely": missing_remote,
        "local_remote_hash_mismatches": hash_mismatches,
        "production_referenced_asset_count": len(visited),
        "production_referenced_js_count": len(remote_js),
        "production_asset_mismatches": production_asset_mismatches,
        "production_js_not_in_exact_build": remote_js_not_local,
        "referenced_local_js_missing_remote": referenced_local_js_missing_remote,
        "external_scripts": sorted(external_scripts),
        "external_styles": sorted(external_styles),
        "suspicious_inline": suspicious_inline,
        "routes": route_rows,
        "source_map_references": sorted(source_map_refs),
        "accessible_source_maps": accessible_source_maps,
        "constants": constants,
        "csp_values": csp_values,
        "csp_present": csp_present,
        "csp_has_self_script": csp_has_self_script,
        "pass": critical_pass,
        "security_verdict": "KILL_EXACT_PRODUCTION_FRONTEND" if critical_pass else "HOLD_PRODUCTION_FRONTEND_DELTA",
        "public_network_writes": 0,
    }
    (private / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")

    public = {
        "source_commit": head,
        "local_static_asset_count": len(local_assets),
        "local_js_count": len(local_js),
        "exact_remote_asset_matches": len(exact_matches),
        "missing_remote_asset_count": len(missing_remote),
        "hash_mismatch_count": len(hash_mismatches),
        "production_referenced_asset_count": len(visited),
        "production_referenced_js_count": len(remote_js),
        "production_asset_mismatch_count": len(production_asset_mismatches),
        "production_js_not_in_exact_build_count": len(remote_js_not_local),
        "external_script_count": len(external_scripts),
        "suspicious_inline_count": len(suspicious_inline),
        "accessible_source_map_count": len(accessible_source_maps),
        "mainnet_constants_present": all(
            [
                constants["mainnet_chain_id_present"],
                constants["mainnet_staker_present"],
                constants["mainnet_token_present"],
            ]
        ),
        "testnet_token_present": constants["testnet_token_present"],
        "csp_present": csp_present,
        "csp_has_self_script": csp_has_self_script,
        "pass": critical_pass,
        "security_verdict": result["security_verdict"],
        "public_network_writes": 0,
    }
    (sanitized / "RESULT.json").write_text(json.dumps(public, indent=2) + "\n")
    lines = [
        "# Horizen production frontend reproducibility attestation",
        "",
        f"- Exact source commit: `{head}`",
        f"- Local executable assets: `{len(local_assets)}`",
        f"- Local JavaScript chunks: `{len(local_js)}`",
        f"- Exact remote asset matches: `{len(exact_matches)}`",
        f"- Hash mismatches: `{len(hash_mismatches) + len(production_asset_mismatches)}`",
        f"- Production JS absent from exact build: `{len(remote_js_not_local)}`",
        f"- External scripts: `{len(external_scripts)}`",
        f"- Suspicious inline scripts: `{len(suspicious_inline)}`",
        f"- Accessible source maps: `{len(accessible_source_maps)}`",
        f"- Mainnet constants present: **{public['mainnet_constants_present']}**",
        f"- Testnet token present: **{public['testnet_token_present']}**",
        f"- Verdict: **{result['security_verdict']}**",
        "- Public-network writes: **0**",
    ]
    (sanitized / "RESULT.md").write_text("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
