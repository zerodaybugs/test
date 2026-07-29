#!/usr/bin/env python3
"""Public, read-only Pyth/Hiro market-window data collection.

The program downloads signed BTC/USD historical updates, ranks short-window
high-to-low movements, and records whether listed Stacks contracts are deployed.
It never signs or broadcasts a transaction.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from decimal import Decimal, getcontext
from pathlib import Path
from typing import Any

getcontext().prec = 60
FEED = "e62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43"
PYTH = "https://benchmarks.pyth.network"
HIRO = "https://api.hiro.so"
OUT = Path(os.environ.get("SCAN_OUT", "pyth-scan-output"))
UA = "authorized-read-only-market-data-scan/1.0"
WINDOWS = [
    ("oct10_2025", "2025-10-10T20:35:00Z", "2025-10-10T21:45:00Z"),
    ("dec05_2024", "2024-12-05T10:15:00Z", "2024-12-05T10:40:00Z"),
    ("feb03_2025", "2025-02-03T01:35:00Z", "2025-02-03T02:25:00Z"),
]
MAX_PAIR_SECONDS = 900
DROP_GATE_BPS = Decimal("500")
CONF_GATE_BPS = Decimal("10")


def unix(iso: str) -> int:
    return int(datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp())


def iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat().replace("+00:00", "Z")


def get_json(url: str, attempts: int = 7) -> tuple[Any, dict[str, str]]:
    last: Exception | None = None
    for n in range(attempts):
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": UA})
            with urllib.request.urlopen(req, timeout=45) as r:
                return json.loads(r.read()), {k.lower(): v for k, v in r.headers.items()}
        except urllib.error.HTTPError as e:
            last = e
            if e.code in {429, 500, 502, 503, 504} and n + 1 < attempts:
                time.sleep(min(20, 1.7 ** n))
                continue
            body = e.read().decode("utf-8", "replace")
            raise RuntimeError(f"HTTP {e.code}: {url}: {body[:400]}") from e
        except Exception as e:
            last = e
            if n + 1 < attempts:
                time.sleep(min(20, 1.7 ** n))
                continue
    raise RuntimeError(f"request failed: {url}: {last!r}")


def status(url: str) -> dict[str, Any]:
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": UA})
        with urllib.request.urlopen(req, timeout=40) as r:
            data = r.read()
            return {"url": url, "status": r.status, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "prefix": data[:160].decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        data = e.read()
        return {"url": url, "status": e.code, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "prefix": data[:160].decode("utf-8", "replace")}
    except Exception as e:
        return {"url": url, "status": 0, "error": repr(e)}


def parse_objects(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if isinstance(payload, dict):
        for key in ("data", "updates", "results"):
            value = payload.get(key)
            if isinstance(value, list):
                return [x for x in value if isinstance(x, dict)]
        if "parsed" in payload:
            return [payload]
    return []


def extract_updates(name: str, minute: int, payload: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for obj in parse_objects(payload):
        parsed = obj.get("parsed", [])
        if isinstance(parsed, dict):
            parsed = [parsed]
        binary = obj.get("binary", {})
        binaries = binary.get("data", []) if isinstance(binary, dict) else []
        if isinstance(binaries, str):
            binaries = [binaries]
        for i, feed in enumerate(parsed if isinstance(parsed, list) else []):
            if not isinstance(feed, dict) or str(feed.get("id", "")).removeprefix("0x").lower() != FEED:
                continue
            p = feed.get("price")
            if not isinstance(p, dict):
                continue
            try:
                price_i = int(p["price"]); conf_i = int(p["conf"]); expo = int(p["expo"]); ts = int(p["publish_time"])
            except (KeyError, TypeError, ValueError):
                continue
            if price_i <= 0 or conf_i < 0:
                continue
            hx = ""
            if isinstance(binaries, list) and binaries:
                raw = binaries[i] if i < len(binaries) else binaries[0]
                if isinstance(raw, str):
                    hx = raw.removeprefix("0x").lower()
            scale = Decimal(10) ** expo
            out.append({
                "window": name, "source_minute": minute, "publish_time": ts, "utc": iso(ts),
                "price_int": price_i, "conf_int": conf_i, "expo": expo,
                "price": format(Decimal(price_i) * scale, "f"),
                "conf": format(Decimal(conf_i) * scale, "f"),
                "conf_bps": format(Decimal(conf_i) * Decimal(10000) / Decimal(price_i), "f"),
                "payload_hex": hx,
                "payload_sha256": hashlib.sha256(bytes.fromhex(hx)).hexdigest() if hx else "",
            })
    return out


def scan_window(name: str, start_iso: str, end_iso: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    start, end = unix(start_iso), unix(end_iso)
    rawdir = OUT / "raw" / name
    rawdir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    diag: list[dict[str, Any]] = []
    t = start - start % 60
    while t <= end:
        q = urllib.parse.urlencode({"ids": FEED, "encoding": "hex", "parsed": "true", "unique": "false"})
        url = f"{PYTH}/v1/updates/price/{t}/60?{q}"
        try:
            payload, headers = get_json(url)
            (rawdir / f"{t}.json").write_text(json.dumps(payload, separators=(",", ":"), sort_keys=True), encoding="utf-8")
            got = extract_updates(name, t, payload)
            rows.extend(got)
            diag.append({"minute": t, "utc": iso(t), "status": "ok", "updates": len(got), "remaining": headers.get("x-ratelimit-remaining", "")})
        except Exception as e:
            diag.append({"minute": t, "utc": iso(t), "status": "error", "error": repr(e)})
        time.sleep(0.15)
        t += 60
    dedup = {(r["publish_time"], r["price_int"], r["conf_int"], r["payload_sha256"]): r for r in rows if start <= r["publish_time"] <= end}
    return sorted(dedup.values(), key=lambda r: (r["publish_time"], r["price_int"])), diag


def rank_pairs(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for i, hi in enumerate(rows):
        if Decimal(hi["conf_bps"]) > CONF_GATE_BPS:
            continue
        for lo in rows[i + 1:]:
            dt = lo["publish_time"] - hi["publish_time"]
            if dt <= 0: continue
            if dt > MAX_PAIR_SECONDS: break
            if Decimal(lo["conf_bps"]) > CONF_GATE_BPS or lo["price_int"] >= hi["price_int"]:
                continue
            drop = (Decimal(hi["price_int"]) - Decimal(lo["price_int"])) * Decimal(10000) / Decimal(hi["price_int"])
            out.append({
                "window": hi["window"], "high_time": hi["publish_time"], "high_utc": hi["utc"],
                "low_time": lo["publish_time"], "low_utc": lo["utc"], "delta_seconds": dt,
                "high_price": hi["price"], "low_price": lo["price"], "drop_bps": format(drop, "f"),
                "high_conf_bps": hi["conf_bps"], "low_conf_bps": lo["conf_bps"],
                "high_payload_sha256": hi["payload_sha256"], "low_payload_sha256": lo["payload_sha256"],
                "high_payload_hex": hi["payload_hex"], "low_payload_hex": lo["payload_hex"],
            })
    return sorted(out, key=lambda x: (Decimal(x["drop_bps"]), -x["delta_seconds"]), reverse=True)


def height_from(obj: Any) -> int | None:
    if isinstance(obj, dict):
        for k in ("height", "block_height"):
            try:
                if k in obj: return int(obj[k])
            except Exception: pass
        for k in ("results", "blocks"):
            v = obj.get(k)
            if isinstance(v, list) and v:
                h = height_from(v[0])
                if h is not None: return h
    return None


def time_from(obj: Any) -> int | None:
    if isinstance(obj, dict):
        for k in ("block_time", "burn_block_time", "block_time_iso"):
            v = obj.get(k)
            if isinstance(v, int): return v
            if isinstance(v, str):
                try: return int(v) if v.isdigit() else unix(v)
                except Exception: pass
        for k in ("results", "blocks"):
            v = obj.get(k)
            if isinstance(v, list) and v:
                t = time_from(v[0])
                if t is not None: return t
    return None


class Blocks:
    def __init__(self) -> None:
        self.cache: dict[int, dict[str, Any]] = {}
        for url in (f"{HIRO}/extended/v2/blocks?limit=1", f"{HIRO}/extended/v1/block?limit=1"):
            try:
                obj, _ = get_json(url); h = height_from(obj)
                if h is not None: self.tip = h; break
            except Exception: pass
        else: raise RuntimeError("cannot resolve Stacks tip")

    def at(self, h: int) -> dict[str, Any]:
        if h in self.cache: return self.cache[h]
        for url in (f"{HIRO}/extended/v2/blocks/{h}", f"{HIRO}/extended/v1/block/by_height/{h}"):
            try:
                obj, _ = get_json(url); t = time_from(obj)
                if t is not None:
                    self.cache[h] = {"height": h, "time": t, "utc": iso(t), "endpoint": url}
                    return self.cache[h]
            except Exception: pass
        raise RuntimeError(f"cannot fetch block {h}")

    def before(self, ts: int) -> int:
        lo, hi, best = 1, self.tip, 1
        while lo <= hi:
            mid = (lo + hi) // 2
            if self.at(mid)["time"] <= ts: best, lo = mid, mid + 1
            else: hi = mid - 1
        return best


def freshness(blocks: Blocks, pair: dict[str, Any]) -> dict[str, Any]:
    checks = []
    for lag in range(61):
        attack = pair["low_time"] + lag
        h = blocks.before(attack)
        if h <= 4: continue
        prior = blocks.at(h - 4)
        checks.append({"lag": lag, "attack_utc": iso(attack), "height": h, "height_minus_4": h - 4, "height_minus_4_utc": prior["utc"], "fresh": pair["high_time"] > prior["time"]})
    passing = [x for x in checks if x["fresh"]]
    return {"passes": bool(passing), "first": passing[0] if passing else None, "last": passing[-1] if passing else None, "checks": checks}


def deployment() -> dict[str, Any]:
    items = {
        "new_lazer_oracle": ("SPMV5HDZ4EMB8XY7HAYT3XW0DF7DZ4E8XEG2J1T8", "pyth-lazer-oracle"),
        "new_lazer_decoder": ("SPMV5HDZ4EMB8XY7HAYT3XW0DF7DZ4E8XEG2J1T8", "pyth-lazer-decoder-v1"),
        "new_staging_adapter": ("SPC626ZYQTCT5ZSDPNS9W1J172KPQ5V2NQX5K6DV", "pyth-adapter-v1"),
        "new_staging_liquidator": ("SPC626ZYQTCT5ZSDPNS9W1J172KPQ5V2NQX5K6DV", "liquidator-v1"),
        "old_core_adapter": ("SP26NGV9AFZBX7XBDBS2C7EC7FCPSAV9PKREQNMVS", "pyth-adapter-v1"),
        "old_core_liquidator": ("SP26NGV9AFZBX7XBDBS2C7EC7FCPSAV9PKREQNMVS", "liquidator-v1"),
    }
    return {k: status(f"{HIRO}/v2/contracts/source/{p}/{c}?proof=0") for k, (p, c) in items.items()}


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    updates: list[dict[str, Any]] = []
    diagnostics: dict[str, Any] = {}
    for name, start, end in WINDOWS:
        rows, diag = scan_window(name, start, end)
        updates.extend(rows); diagnostics[name] = diag
        print(name, len(rows))
    pairs: list[dict[str, Any]] = []
    for name, _, _ in WINDOWS:
        pairs.extend(rank_pairs([x for x in updates if x["window"] == name]))
    pairs.sort(key=lambda x: Decimal(x["drop_bps"]), reverse=True)
    material = [x for x in pairs if Decimal(x["drop_bps"]) > DROP_GATE_BPS]
    dep = deployment()
    detailed: list[dict[str, Any]] = []
    block_error = None
    if material:
        try:
            blocks = Blocks()
            for p in material[:20]:
                q = dict(p); q["freshness"] = freshness(blocks, p); detailed.append(q)
            (OUT / "block_cache.json").write_text(json.dumps(blocks.cache, indent=2), encoding="utf-8")
        except Exception as e: block_error = repr(e)
    qualifying = [x for x in detailed if x["freshness"]["passes"]]
    for name, value in (("updates.json", updates), ("pairs.json", pairs), ("material_pairs.json", material), ("freshness.json", detailed), ("diagnostics.json", diagnostics), ("deployment.json", dep)):
        (OUT / name).write_text(json.dumps(value, indent=2), encoding="utf-8")
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(), "total_updates": len(updates),
        "total_pairs": len(pairs), "pairs_over_500bps": len(material),
        "qualifying_four_block_pairs": len(qualifying), "best_pair": pairs[0] if pairs else None,
        "best_qualifying_pair": qualifying[0] if qualifying else None, "block_error": block_error,
        "deployment": dep, "decision": "SIGNED_PAIR_GATE_PASS" if qualifying else "SIGNED_PAIR_GATE_FAIL_OR_BLOCKED",
    }
    (OUT / "SUMMARY.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    files = []
    for p in sorted(x for x in OUT.rglob("*") if x.is_file() and x.name != "SHA256SUMS.txt"):
        files.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(OUT).as_posix()}")
    (OUT / "SHA256SUMS.txt").write_text("\n".join(files) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
