#!/usr/bin/env python3
"""Fetch public verification artifacts for the intermediate Deposit implementation."""

from __future__ import annotations

import hashlib
import json
import pathlib
import urllib.error
import urllib.request

OUT = pathlib.Path("intermediate_impl")
OUT.mkdir(parents=True, exist_ok=True)
ADDRESS = "0x2fd250e33Bf538f5b1Af81493339B42E5C77b308"
UA = "Mozilla/5.0 (compatible; passive-security-review/1.0)"
MAX_BYTES = 40 * 1024 * 1024
URLS = {
    "sourcify_v2": f"https://sourcify.dev/server/v2/contract/1/{ADDRESS}?fields=all",
    "sourcify_full_metadata": f"https://repo.sourcify.dev/contracts/full_match/1/{ADDRESS}/metadata.json",
    "sourcify_partial_metadata": f"https://repo.sourcify.dev/contracts/partial_match/1/{ADDRESS}/metadata.json",
    "etherscan_html": f"https://etherscan.io/address/{ADDRESS}#code",
}


def main() -> None:
    manifest: list[dict[str, object]] = []
    for label, url in URLS.items():
        suffix = ".html" if label == "etherscan_html" else ".json"
        path = OUT / f"{label}{suffix}"
        record: dict[str, object] = {"label": label, "url": url, "path": str(path)}
        try:
            request = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
            with urllib.request.urlopen(request, timeout=75) as response:
                body = response.read(MAX_BYTES + 1)
                if len(body) > MAX_BYTES:
                    raise ValueError("response too large")
                path.write_bytes(body)
                record.update(
                    status=response.status,
                    bytes=len(body),
                    content_type=response.headers.get("Content-Type", ""),
                    sha256=hashlib.sha256(body).hexdigest(),
                )
        except urllib.error.HTTPError as exc:
            body = exc.read(MAX_BYTES + 1)
            path.write_bytes(body)
            record.update(status=exc.code, bytes=len(body), error=str(exc))
        except Exception as exc:  # noqa: BLE001
            record["error"] = repr(exc)
        manifest.append(record)
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
