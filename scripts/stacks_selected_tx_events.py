#!/usr/bin/env python3
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

BASE = "https://api.hiro.so"
OUT = Path("public-data/selected-transactions")

TXS = {
    "2026-04-28-sweep": "0xcd7f96d9e3eb2ab04c402de41ee62eac5a312bc441a59261a93cc7d7ce73fbe5",
    "2026-04-28-deposit": "0xf00d2911f0cebf2f367cd8623d82a14f2e81ac4f55c587d70e3e4a3f350861c0",
    "2026-04-28-reward": "0xfbad904a4ee4dc02f3c56bbdf779bfdf60e746a8012256bcd7da3f049935e562",
    "2026-05-26-sweep": "0x9afc199caf6487b6fdc5eea164082ece38c8e7830b3259ed18492f012cfb00be",
    "2026-05-26-deposit": "0xeb7c5dae953c13ca1eed8616f49d7ad1e8c15802afcb6071011744dff5ed847b",
    "2026-05-26-reward": "0xe59f48fee2567d09210d1c2f3ec137bd71460f4e82b1a1816708534baf415fde",
}


def get_json(url: str, attempts: int = 6) -> dict[str, Any]:
    last: Exception | None = None
    for i in range(attempts):
        try:
            request = urllib.request.Request(
                url,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "public-stacks-history-collector/1.3",
                },
            )
            with urllib.request.urlopen(request, timeout=45) as response:
                return json.loads(response.read().decode("utf-8"))
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
            last = exc
            if isinstance(exc, urllib.error.HTTPError) and exc.code not in {
                408,
                429,
                500,
                502,
                503,
                504,
            }:
                raise
            time.sleep(min(30, 2**i))
    raise RuntimeError(f"request failed: {url}: {last!r}")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    index: dict[str, Any] = {"source": "Hiro public Stacks API", "transactions": {}}
    for label, txid in TXS.items():
        url = f"{BASE}/extended/v1/tx/{txid}?event_offset=0&event_limit=100"
        payload = get_json(url)
        filename = f"{label}.json"
        (OUT / filename).write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        index["transactions"][label] = {
            "tx_id": txid,
            "file": filename,
            "block_height": payload.get("block_height"),
            "block_time_iso": payload.get("block_time_iso"),
            "status": payload.get("tx_status"),
            "event_count": payload.get("event_count"),
        }
        time.sleep(0.15)
    (OUT / "index.json").write_text(json.dumps(index, indent=2, sort_keys=True), encoding="utf-8")


if __name__ == "__main__":
    main()
