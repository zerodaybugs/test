#!/usr/bin/env python3
"""Kiln R35 fixed-block local-fork holder redemption control.

R34 is rerun first. Only its two-RPC liveness candidates are promoted into a
state-changing Anvil fork. Existing real holders are impersonated locally; no
public transaction is signed or broadcast. Five clean snapshot repetitions are
required before a liveness failure is retained, and even that remains HOLD
until a permissionless attacker trigger is demonstrated.
"""
from __future__ import annotations

import hashlib
import json
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from web3 import Web3

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "kiln_r34"))
import liveness_exact_v2 as r34  # noqa: E402

OUT = Path("r35_results")
OUT.mkdir(exist_ok=True)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def start_anvil(fork_url: str, block: int) -> tuple[subprocess.Popen[str], Web3, str]:
    port = free_port()
    process = subprocess.Popen(
        [
            "anvil", "--fork-url", fork_url, "--fork-block-number", str(block),
            "--host", "127.0.0.1", "--port", str(port), "--silent",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    url = f"http://127.0.0.1:{port}"
    w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout":30}))
    for _ in range(90):
        if process.poll() is not None:
            stderr = process.stderr.read() if process.stderr else ""
            raise RuntimeError(f"anvil exited early: {stderr[-2000:]}")
        try:
            if w3.is_connected():
                return process, w3, url
        except Exception:
            pass
        time.sleep(1)
    process.terminate()
    raise RuntimeError("anvil startup timeout")


def rpc(w3: Web3, method: str, params: list[Any]) -> Any:
    response = w3.provider.make_request(method, params)
    if response.get("error"):
        raise RuntimeError(response["error"])
    return response.get("result")


def safe_view(fn: Any) -> dict[str, Any]:
    try:
        return {"ok":True, "value":r34.normalize(fn.call())}
    except Exception as exc:
        return {"ok":False, "error":f"{type(exc).__name__}: {exc}"}


def execute_redeem_once(
    w3: Web3,
    vault_address: str,
    asset_address: str,
    holder: str,
    shares: int,
) -> dict[str, Any]:
    vault_address = Web3.to_checksum_address(vault_address)
    asset_address = Web3.to_checksum_address(asset_address)
    holder = Web3.to_checksum_address(holder)
    vault = w3.eth.contract(vault_address, abi=r34.VAULT_ABI)
    asset = w3.eth.contract(asset_address, abi=r34.ERC20_ABI)
    snapshot = rpc(w3, "evm_snapshot", [])
    rpc(w3, "anvil_impersonateAccount", [holder])
    rpc(w3, "anvil_setBalance", [holder, hex(10**20)])
    before = {
        "holder_shares": safe_view(vault.functions.balanceOf(holder)),
        "holder_assets": safe_view(asset.functions.balanceOf(holder)),
        "totalAssets": safe_view(vault.functions.totalAssets()),
        "totalSupply": safe_view(vault.functions.totalSupply()),
        "previewRedeem": safe_view(vault.functions.previewRedeem(shares)),
        "maxRedeem": safe_view(vault.functions.maxRedeem(holder)),
    }
    tx: dict[str, Any]
    try:
        fn = vault.functions.redeem(shares, holder, holder)
        tx_hash = w3.eth.send_transaction({
            "from":holder,
            "to":vault_address,
            "data":fn._encode_transaction_data(),
            "gas":30_000_000,
        })
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=90)
        tx = {
            "sent":True,
            "status":int(receipt.status),
            "gas_used":int(receipt.gasUsed),
            "tx_hash":tx_hash.hex(),
        }
    except Exception as exc:
        tx = {"sent":False, "status":0, "error":f"{type(exc).__name__}: {exc}"}
    after = {
        "holder_shares": safe_view(vault.functions.balanceOf(holder)),
        "holder_assets": safe_view(asset.functions.balanceOf(holder)),
        "totalAssets": safe_view(vault.functions.totalAssets()),
        "totalSupply": safe_view(vault.functions.totalSupply()),
    }
    share_before = int(r34.value(before["holder_shares"]) or 0)
    share_after = int(r34.value(after["holder_shares"]) or 0)
    asset_before = int(r34.value(before["holder_assets"]) or 0)
    asset_after = int(r34.value(after["holder_assets"]) or 0)
    result = {
        "before":before,
        "tx":tx,
        "after":after,
        "share_delta":share_after-share_before,
        "asset_delta":asset_after-asset_before,
        "success_with_asset_payout":bool(tx.get("status")==1 and asset_after>asset_before and share_after<share_before),
    }
    rpc(w3, "anvil_stopImpersonatingAccount", [holder])
    rpc(w3, "evm_revert", [snapshot])
    return result


def pick_holder(row: dict[str, Any]) -> tuple[str, int] | None:
    census = row.get("holder_census") or {}
    for holder in census.get("positive_holders", []):
        balance = int(holder.get("share_balance", 0) or 0)
        max_redeem = int(r34.value(holder.get("maxRedeem")) or 0)
        sample = min(balance, max_redeem)
        if sample > 0:
            return Web3.to_checksum_address(holder["holder"]), sample
    return None


def main() -> int:
    # Re-run R34 in this exact workflow instead of trusting an old public gate.
    r34_code = int(r34.main())
    r34_evidence_path = Path("r34_exact_results/EVIDENCE.json")
    if not r34_evidence_path.exists():
        raise RuntimeError("R34 evidence missing")
    r34_evidence = json.loads(r34_evidence_path.read_text())
    candidates = [row for row in r34_evidence.get("rows", []) if row.get("promotion", {}).get("candidate")]

    evidence: dict[str, Any] = {
        "schema":"kiln-r35-fixed-block-liveness-v1",
        "generated_at_utc":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
        "r34_exit_code":r34_code,
        "r34_summary":r34_evidence.get("summary", {}),
        "candidate_count":len(candidates),
        "rows":[],
        "errors":[],
        "safety":{
            "public_chain_state_changes":0,
            "transactions_signed":0,
            "transactions_sent_to_public_chain":0,
            "local_fork_transactions":0,
            "private_keys_loaded":0,
        },
    }

    for candidate in candidates:
        network = candidate["network"]
        chain = r34_evidence["chains"][network]
        fork_url = chain["rpc_urls"][0]
        block = int(chain["pinned_block"])
        holder_pick = pick_holder(candidate)
        row_result: dict[str, Any] = {
            "network":network,
            "vault":candidate["vault"],
            "label":candidate["label"],
            "preliminary_signals":candidate.get("preliminary_signals", []),
            "pinned_block":block,
            "pinned_block_hash":chain["pinned_block_hash"],
            "holder_pick":holder_pick,
            "runs":[],
        }
        if holder_pick is None:
            row_result["decision"] = "INCONCLUSIVE_NO_POSITIVE_MAX_REDEEM_HOLDER"
            evidence["rows"].append(row_result)
            continue
        asset_address = r34.checksum(r34.value(candidate.get("asset")))
        if not asset_address:
            row_result["decision"] = "INCONCLUSIVE_ASSET_BINDING"
            evidence["rows"].append(row_result)
            continue
        process: subprocess.Popen[str] | None = None
        try:
            process, local, local_url = start_anvil(fork_url, block)
            holder, shares = holder_pick
            for _ in range(5):
                run = execute_redeem_once(local,candidate["vault"],asset_address,holder,shares)
                row_result["runs"].append(run)
                if run.get("tx",{}).get("sent"):
                    evidence["safety"]["local_fork_transactions"] += 1
            success_count = sum(run["success_with_asset_payout"] for run in row_result["runs"])
            failure_count = sum(not run["success_with_asset_payout"] for run in row_result["runs"])
            row_result.update({
                "local_url":local_url,
                "success_count":success_count,
                "failure_count":failure_count,
                "all_5_success":success_count==5,
                "all_5_failure":failure_count==5,
                "decision":(
                    "KILL_REDEEM_SUCCEEDS_5OF5"
                    if success_count==5
                    else "HOLD_REDEEM_FAILURE_5OF5_REQUIRES_PERMISSIONLESS_TRIGGER"
                    if failure_count==5
                    else "INCONCLUSIVE_NONDETERMINISTIC_REDEEM_RESULT"
                ),
            })
        except Exception as exc:
            row_result["decision"] = "INCONCLUSIVE_LOCAL_FORK_ERROR"
            row_result["error"] = f"{type(exc).__name__}: {exc}"
            evidence["errors"].append({"vault":candidate["vault"],"error":row_result["error"]})
        finally:
            if process is not None:
                try:
                    process.send_signal(signal.SIGTERM)
                    process.wait(timeout=10)
                except Exception:
                    process.kill()
        evidence["rows"].append(row_result)

    failures = [row for row in evidence["rows"] if row.get("decision")=="HOLD_REDEEM_FAILURE_5OF5_REQUIRES_PERMISSIONLESS_TRIGGER"]
    nondeterministic = [row for row in evidence["rows"] if str(row.get("decision","")).startswith("INCONCLUSIVE")]
    if failures:
        decision = "HOLD_OPERATIONAL_FREEZE_REQUIRES_PERMISSIONLESS_TRIGGER_AND_SOURCE_BINDING"
    elif evidence["errors"] or nondeterministic or r34_code != 0:
        decision = "INCONCLUSIVE_FIXED_BLOCK_LIVENESS_GATE"
    else:
        decision = "KILL_NO_FIXED_BLOCK_REDEEM_FAILURE"
    public_gate = {
        "schema":"kiln-r35-public-gate-v1",
        "decision":decision,
        "submit_ready":False,
        "validated_critical":0,
        "validated_high":0,
        "r34_candidate_count":len(candidates),
        "tested_candidate_count":len(evidence["rows"]),
        "verified_redeem_failure_5of5_count":len(failures),
        "inconclusive_count":len(nondeterministic),
        "failure_rows":[
            {
                "network":row["network"],
                "vault":row["vault"],
                "signals":row["preliminary_signals"],
                "decision":row["decision"],
            }
            for row in failures
        ],
        "public_chain_state_changes":0,
        "transactions_signed":0,
        "transactions_sent":0,
        "local_fork_transactions":evidence["safety"]["local_fork_transactions"],
    }
    evidence["public_gate"] = public_gate
    (OUT/"EVIDENCE.json").write_text(json.dumps(evidence,indent=2,sort_keys=True))
    (OUT/"PUBLIC_GATE.json").write_text(json.dumps(public_gate,indent=2,sort_keys=True))
    files=sorted(path for path in OUT.iterdir() if path.is_file() and path.name!="SHA256SUMS.txt")
    (OUT/"SHA256SUMS.txt").write_text("".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in files
    ))
    print(json.dumps(public_gate,sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
