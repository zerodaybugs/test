#!/usr/bin/env python3
"""Fetch only public same-origin assets explicitly referenced by production pages/bundles."""

from __future__ import annotations

import hashlib
import json
import pathlib
import urllib.request

OUT = pathlib.Path("targeted_web_assets")
UA = "Mozilla/5.0 (compatible; passive-security-review/1.0)"
MAX_BYTES = 100 * 1024 * 1024

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
    "exchange_account_mobile": "https://exchange.synthetix.io/assets/AccountPageMobile-Sptodp-s.js",
    "exchange_subaccounts": "https://exchange.synthetix.io/assets/SubAccountsPage-B4tBQXny.js",
    "exchange_cancel_all_orders": "https://exchange.synthetix.io/assets/CancelAllOrdersModal-CMJcSOXd.js",
    "exchange_chase_order": "https://exchange.synthetix.io/assets/ChaseOrderModal-p6T4UFdI.js",
    "exchange_edit_order": "https://exchange.synthetix.io/assets/EditOrderModal-GHeaUMPG.js",
    "exchange_margin_edit": "https://exchange.synthetix.io/assets/MarginEditModal-D9vxzVWn.js",
    "exchange_orders_page": "https://exchange.synthetix.io/assets/OrdersPage-CSJIYvCR.js",
    "exchange_trade_page": "https://exchange.synthetix.io/assets/TradePage-DIfy7GrB.js",
    "exchange_referral_welcome": "https://exchange.synthetix.io/assets/ReferralWelcomeModal-Ya9ya9ID.js",
    "exchange_referrals_page": "https://exchange.synthetix.io/assets/ReferralsPage-D0iGROix.js",
    "exchange_referrals_content": "https://exchange.synthetix.io/assets/ReferralsContent-DDlk8y0Z.js",
    "exchange_revoke_all_delegates": "https://exchange.synthetix.io/assets/RevokeAllDelegatesContent-kDarMhQk.js",
    "exchange_share_position_icon": "https://exchange.synthetix.io/assets/SharePositionIcon-xuMn2mon.js",
    "exchange_build_share_link": "https://exchange.synthetix.io/assets/buildShareLink-kGZlINfv.js",
    "exchange_sanitize": "https://exchange.synthetix.io/assets/sanitize-DQ4CD9oS.js",
    "exchange_shareable_position": "https://exchange.synthetix.io/assets/toShareableOpenPosition-CYf81nid.js",
    "exchange_close_all_positions": "https://exchange.synthetix.io/assets/CloseAllPositionsModal-DFTOdP1i.js",
    "exchange_close_position": "https://exchange.synthetix.io/assets/ClosePositionModal-Df0UmC4m.js",
    "exchange_reverse_position": "https://exchange.synthetix.io/assets/ReversePositionModal-CHNSMQiI.js",
    "exchange_use_submit_order": "https://exchange.synthetix.io/assets/useSubmitOrder-BspCsBTC.js",
    "exchange_use_can_trade": "https://exchange.synthetix.io/assets/useCanTrade-sDrwBRe9.js",
    "exchange_use_cancel_orders": "https://exchange.synthetix.io/assets/useCancelOrders-DqoxCRCW.js",
    "exchange_use_cancel_all_orders": "https://exchange.synthetix.io/assets/useCancelAllOrders-CB6lcOdN.js",
    "exchange_use_edit_order": "https://exchange.synthetix.io/assets/useEditOrder-D2lY9xCD.js",
    "exchange_mobile_positions": "https://exchange.synthetix.io/assets/MobilePositionsList-C1-SHwx4.js",
    "exchange_main_map": "https://exchange.synthetix.io/assets/index-BJrW6h18.js.map",
    "exchange_trade_page_map": "https://exchange.synthetix.io/assets/TradePage-DIfy7GrB.js.map",
    "governance_main": "https://governance.synthetix.io/main.js",
    "governance_main_map": "https://governance.synthetix.io/main.js.map",
    "governance_manifest": "https://governance.synthetix.io/manifest.json",
}


def fetch(url: str) -> tuple[bytes, dict[str, str], int]:
    request = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(request, timeout=90) as response:
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
