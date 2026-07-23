#!/usr/bin/env python3
"""Fetch only public same-origin assets explicitly referenced by production pages/bundles."""

from __future__ import annotations

import hashlib
import json
import pathlib
import urllib.request

OUT = pathlib.Path("targeted_web_assets")
UA = "Mozilla/5.0 (compatible; passive-security-review/1.0)"
MAX_BYTES = 30 * 1024 * 1024

URLS = {
    "exchange_deposit_proxy": "https://exchange.synthetix.io/assets/DepositProxy-DKmIyX6Q.js",
    "exchange_deposit_modal": "https://exchange.synthetix.io/assets/DepositMarginModal-CZw7zE_R.js",
    "exchange_withdraw_modal": "https://exchange.synthetix.io/assets/WithdrawMarginModal-D5vtpQwT.js",
    "exchange_query_keys": "https://exchange.synthetix.io/assets/query-keys-BXeEGN5P.js",
    "exchange_eip712": "https://exchange.synthetix.io/assets/eip712-d_WzdABq.js",
    "exchange_transfer_modal": "https://exchange.synthetix.io/assets/TransferModal-vq_joSi2.js",
    "exchange_submission_guard": "https://exchange.synthetix.io/assets/useSubmissionGuard-aeihgeSq.js",
    "exchange_gas_settings": "https://exchange.synthetix.io/assets/gas-settings-Ce8Ak6a_.js",
    "exchange_dynamic_sdk": "https://exchange.synthetix.io/assets/DynamicSdkInner-P372lkmD.js",
    "exchange_dynamic_wagmi": "https://exchange.synthetix.io/assets/dynamic-wagmi-B2nZYcut.js",
    "exchange_collateral_exchange": "https://exchange.synthetix.io/assets/CollateralExchangeModal-BeFDwj8C.js",
    "exchange_chain_collateral": "https://exchange.synthetix.io/assets/useChainFilteredCollateralOptions-48hQrjF5.js",
    "governance_main": "https://governance.synthetix.io/main.js",
    "governance_manifest": "https://governance.synthetix.io/manifest.json",
}


def fetch(url: str) -> tuple[bytes, dict[str, str], int]:
    request = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(request, timeout=60) as response:
        body = response.read(MAX_BYTES + 1)
        if len(body) > MAX_BYTES:
            raise ValueError(f"asset exceeds {MAX_BYTES} bytes")
        return body, dict(response.headers.items()), response.status


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    manifest: list[dict[str, object]] = []
    for label, url in URLS.items():
        suffix = pathlib.PurePosixPath(url.split("?", 1)[0]).suffix or ".bin"
        path = OUT / f"{label}{suffix}"
        record: dict[str, object] = {"label": label, "url": url, "path": str(path)}
        try:
            body, headers, status = fetch(url)
            path.write_bytes(body)
            record.update(
                status=status,
                bytes=len(body),
                sha256=hashlib.sha256(body).hexdigest(),
                content_type=headers.get("Content-Type", ""),
            )
        except Exception as exc:  # noqa: BLE001
            record["error"] = repr(exc)
        manifest.append(record)
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
