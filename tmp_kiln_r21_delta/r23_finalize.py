#!/usr/bin/env python3
"""Finalize Kiln R23 five-repeat redeem-delta evidence.

The script promotes only deterministic, material underpayment on a connector
class not already covered by the known Compound-V2/Venus or partial-share
rounding findings. Revert-only and infrastructure-only signals are held.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import time
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

OUT = Path("r23_output")
OUT.mkdir(exist_ok=True)
RUNS = Path("r23_runs")
SCANNER = json.loads(Path("r21_delta_results/EVIDENCE.json").read_text())

MARKERS = {
    "R22_REPORTED_RECEIVED_MISMATCH": "reported_received_mismatch",
    "R22_PREVIEW_RECEIVED_MISMATCH": "preview_received_mismatch",
    "R22_REDEEM_REVERT_WITH_ADVERTISED_LIQUIDITY": "advertised_liquidity_revert",
    "R22_RESIDUAL_SHARES_AFTER_FULL_REDEEM": "residual_shares",
}
KEYS = {
    "R22_AMOUNT": "amount",
    "R22_REPORTED": "reported",
    "R22_PREVIEW": "preview",
    "R22_RECEIVED": "received",
    "R22_MAX_REDEEM": "max_redeem",
    "R22_MAX_WITHDRAW": "max_withdraw",
    "R22_RESIDUAL": "residual",
}


def parse_num(text: str) -> int | None:
    m = re.search(r"(-?\d+)\s*$", text)
    return int(m.group(1)) if m else None


def parse_vault(text: str) -> str | None:
    m = re.search(r"0x[a-fA-F0-9]{40}", text)
    return m.group(0).lower() if m else None


def parse_log(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw in path.read_text(errors="replace").splitlines():
        line = raw.strip()
        marker = next((m for m in MARKERS if m in line), None)
        if marker:
            if current:
                records.append(current)
            current = {"class": MARKERS[marker], "vault": parse_vault(line)}
            continue
        if current:
            key = next((k for k in KEYS if k in line), None)
            if key:
                value = parse_num(line)
                if value is not None:
                    current[KEYS[key]] = value
    if current:
        records.append(current)
    return [r for r in records if r.get("vault")]


def normalized(record: dict[str, Any]) -> tuple[Any, ...]:
    return tuple(record.get(k) for k in (
        "class", "vault", "amount", "reported", "preview", "received",
        "max_redeem", "max_withdraw", "residual",
    ))


def vault_meta(chain: int, vault: str) -> dict[str, Any]:
    for row in SCANNER.get("vaults", []):
        if int(row.get("chain_id", -1)) == chain and str(row.get("vault", "")).lower() == vault.lower():
            src = row.get("connector_source_ref") or {}
            token = row.get("token") or {}
            decimals = ((token.get("decimals") or {}).get("value")
                        if isinstance(token.get("decimals"), dict) else None)
            symbol = ((token.get("symbol") or {}).get("value")
                      if isinstance(token.get("symbol"), dict) else None)
            ta = ((row.get("total_assets") or {}).get("value")
                  if isinstance(row.get("total_assets"), dict) else None)
            supply = ((row.get("total_supply") or {}).get("value")
                      if isinstance(row.get("total_supply"), dict) else None)
            return {
                "label": row.get("label"),
                "connector_label": row.get("connector_label"),
                "connector_contract_name": src.get("contract_name"),
                "connector_code_sha256": src.get("code_sha256"),
                "connector_source_sha256": src.get("source_sha256"),
                "asset_symbol": symbol,
                "asset_decimals": decimals,
                "total_assets": ta,
                "total_supply": supply,
            }
    return {}


def material(record: dict[str, Any], meta: dict[str, Any]) -> tuple[bool, int, str]:
    dec = int(meta.get("asset_decimals") or 18)
    unit = 10 ** dec
    amount = int(record.get("amount") or 0)
    received = int(record.get("received") or 0)
    expected = max(int(record.get("reported") or 0), int(record.get("preview") or 0))
    delta = max(0, expected - received)
    total = int(meta.get("total_assets") or 0)
    symbol = str(meta.get("asset_symbol") or "").upper()
    stable = symbol in {"USDC", "USDT", "USDT0", "USD₮0", "DAI", "USDS", "EURA", "AGEUR"}
    if record["class"] in {"reported_received_mismatch", "preview_received_mismatch"}:
        proportional = amount > 0 and delta * 100 >= amount
        protocol_material = total > 0 and delta * 10_000 >= total
        absolute = delta >= (1_000 * unit if stable else unit)
        ok = delta > 0 and proportional and (absolute or protocol_material)
        why = f"delta={delta}; amount={amount}; totalAssets={total}; stable={stable}"
        return ok, delta, why
    if record["class"] == "residual_shares":
        return False, int(record.get("residual") or 0), "partial-share/rounding overlap"
    return False, 0, "revert-only signal requires duration and root-cause proof"


def duplicate_status(record: dict[str, Any], meta: dict[str, Any]) -> tuple[str, str]:
    name = str(meta.get("connector_contract_name") or "").lower()
    label = str(meta.get("connector_label") or "").lower()
    if any(x in name or x in label for x in ("venus", "compoundv2", "compound_v2")):
        return "KNOWN_AUDIT_OVERLAP", "Spearbit documented silent Compound-V2/Venus return-code failures"
    if record["class"] == "residual_shares":
        return "KNOWN_AUDIT_OR_SCOPE_OVERLAP", "partial-share and rounding class already documented/excluded"
    if record["class"] == "advertised_liquidity_revert":
        return "HOLD_EXTERNAL_LIQUIDITY_OR_DOS", "no proof of >2-day protocol-caused freeze"
    return "NO_DIRECT_CLASS_MATCH_FOUND", "requires final manual source-level comparison"


def main() -> int:
    chain_dirs = [p for p in RUNS.iterdir() if p.is_dir()] if RUNS.exists() else []
    all_rows = []
    infra = []
    for chain_dir in sorted(chain_dirs):
        meta_file = chain_dir / "RUN_META.json"
        meta = json.loads(meta_file.read_text()) if meta_file.exists() else {}
        chain = int(meta.get("chain_id", -1))
        reps = []
        for rep in range(1, 6):
            path = chain_dir / f"rep{rep}.forge.log"
            if not path.exists():
                reps.append([])
                continue
            reps.append(parse_log(path))
        sets = [set(normalized(x) for x in rep) for rep in reps]
        stable = set.intersection(*sets) if len(sets) == 5 else set()
        union = set.union(*sets) if sets else set()
        if int(meta.get("forge_failure_count", 0)):
            infra.append(meta)
        for key in sorted(union, key=str):
            record = dict(zip(
                ("class", "vault", "amount", "reported", "preview", "received",
                 "max_redeem", "max_withdraw", "residual"), key
            ))
            record = {k: v for k, v in record.items() if v is not None}
            record["chain_id"] = chain
            record["network"] = meta.get("network")
            record["repeat_count"] = sum(key in s for s in sets)
            record["stable_5_of_5"] = key in stable
            vm = vault_meta(chain, record["vault"])
            record["vault_meta"] = vm
            mat, delta, why = material(record, vm)
            dup, dup_why = duplicate_status(record, vm)
            record["material"] = mat
            record["material_delta"] = delta
            record["materiality_reason"] = why
            record["duplicate_status"] = dup
            record["duplicate_reason"] = dup_why
            record["eligible_high_candidate"] = (
                record["stable_5_of_5"]
                and mat
                and dup == "NO_DIRECT_CLASS_MATCH_FOUND"
                and record["class"] in {"reported_received_mismatch", "preview_received_mismatch"}
            )
            all_rows.append(record)

    eligible = [x for x in all_rows if x["eligible_high_candidate"]]
    holds = [x for x in all_rows if not x["eligible_high_candidate"]]
    decision = "SUBMIT_READY_HIGH" if eligible else (
        "INCONCLUSIVE_INFRA_FAILURE" if infra and not all_rows else "NO_VALIDATED_HIGH_OR_CRITICAL"
    )
    gate = {
        "schema": "kiln-r23-public-gate-v1",
        "decision": decision,
        "submit_ready": bool(eligible),
        "validated_critical": 0,
        "validated_high": len(eligible),
        "observed_signal_count": len(all_rows),
        "eligible_high_count": len(eligible),
        "held_or_killed_count": len(holds),
        "infra_failure_count": len(infra),
        "public_chain_mutations": 0,
        "transactions_signed": 0,
        "transactions_sent": 0,
    }
    (OUT / "PUBLIC_GATE.json").write_text(json.dumps(gate, indent=2, sort_keys=True))
    evidence = {
        "schema": "kiln-r23-five-repeat-evidence-v1",
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "safety": {
            "fixed_local_forks_only": True,
            "public_chain_mutations": 0,
            "transactions_signed": 0,
            "transactions_sent": 0,
        },
        "gate": gate,
        "eligible": eligible,
        "held_or_killed": holds,
        "infra": infra,
    }
    (OUT / "EVIDENCE.json").write_text(json.dumps(evidence, indent=2, sort_keys=True, default=str))

    package = OUT / (
        "KILN_OMNIVAULT_R23_SUBMIT_READY_HIGH_2026-08-16.zip"
        if eligible else
        "KILN_OMNIVAULT_R23_5OF5_CHECKPOINT_NOT_FOR_SUBMISSION_2026-08-16.zip"
    )
    stage = OUT / "package"
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir()
    shutil.copy2(OUT / "PUBLIC_GATE.json", stage / "PUBLIC_GATE.json")
    shutil.copy2(OUT / "EVIDENCE.json", stage / "EVIDENCE.json")
    if eligible:
        first = eligible[0]
        report = f"""# Kiln OmniVault — redeem reports/previews more assets than receiver obtains

## Severity
High

## Summary
A fixed-block local-fork reproduction shows that a full ERC-4626 redeem can report or preview more underlying than the receiver actually receives. The discrepancy reproduced 5/5 times on the same block and passed the materiality gate.

## Affected deployment
- Chain: {first['network']} ({first['chain_id']})
- Vault: {first['vault']}
- Connector: {first['vault_meta'].get('connector_contract_name')}
- Asset: {first['vault_meta'].get('asset_symbol')}

## Measured impact
- Test amount: {first.get('amount')}
- Reported: {first.get('reported')}
- Previewed: {first.get('preview')}
- Actually received: {first.get('received')}
- Delta: {first.get('material_delta')}
- Reproduction: {first.get('repeat_count')}/5

## Root cause and impact
`Vault._withdraw` burns the owner's shares before delegate-calling the connector and transfers only the observed post-call asset balance delta. If the connector completes without reverting but returns less underlying than requested, the user irreversibly loses shares while receiving less than the ERC-4626 result reported by the Vault.

## Recommended fix
After the connector call, require the observed asset delta to equal the requested `assets` amount before transferring and finalizing the share burn, or make every connector prove exact-or-revert semantics.

## Safety
The PoC uses a fixed local fork only. It does not sign or broadcast a transaction.
"""
        (stage / "REPORT.md").write_text(report)
        (stage / "PROOF_CARD.json").write_text(json.dumps(first, indent=2, sort_keys=True, default=str))
        (stage / "DUPLICATE_CLEARANCE.md").write_text(
            "No direct class match was found in the known Compound-V2/Venus silent-return or partial-share rounding findings. Final triage should compare the exact connector source hash listed in PROOF_CARD.json.\n"
        )
    else:
        (stage / "READ_ME_FIRST_HU.md").write_text(
            "# NEM BEADHATÓ\n\nAz R23 ötismétléses kapu nem validált Critical vagy High findingot. A csomag kutatási checkpoint, Cantinára nem tölthető fel.\n"
        )
    # Include exact tests and logs in both cases.
    if RUNS.exists():
        shutil.copytree(RUNS, stage / "r23_runs")
    shutil.copy2(Path("tmp_kiln_r21_delta/generate_r22_redeem_delta.py"), stage / "generate_r22_redeem_delta.py")
    sums = []
    for p in sorted(stage.rglob("*")):
        if p.is_file():
            sums.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(stage).as_posix()}\n")
    (stage / "SHA256SUMS.txt").write_text("".join(sums))
    with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for p in sorted(stage.rglob("*")):
            if p.is_file():
                z.write(p, p.relative_to(stage).as_posix())
    (OUT / (package.name + ".sha256")).write_text(
        f"{hashlib.sha256(package.read_bytes()).hexdigest()}  {package.name}\n"
    )
    print(json.dumps(gate, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
