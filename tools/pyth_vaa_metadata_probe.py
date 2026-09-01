#!/usr/bin/env python3
import base64
import datetime as dt
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

EMITTER = os.environ.get(
    "EMITTER_HEX",
    "5635979a221c34931e32620b9293a463065555ea71fe97cd6237ade875b12e9e",
).lower()
OUT = Path(os.environ.get("OUT_DIR", "out"))
PAGES = OUT / "pages"
TX_DIR = OUT / "solana-transactions"
OUT.mkdir(parents=True, exist_ok=True)
PAGES.mkdir(parents=True, exist_ok=True)
TX_DIR.mkdir(parents=True, exist_ok=True)


def http_get(url: str):
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "read-only-governance-metadata-probe/3.0",
        },
    )
    with urllib.request.urlopen(req, timeout=45) as response:
        return response.status, response.read(), dict(response.headers)


def rpc_call(url: str, method: str, params):
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode()
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "read-only-governance-metadata-probe/3.0",
        },
    )
    with urllib.request.urlopen(req, timeout=45) as response:
        return json.loads(response.read())


def list_candidates(parsed):
    candidates = []
    if isinstance(parsed, list):
        candidates.append(("root", parsed))
    elif isinstance(parsed, dict):
        for key, value in parsed.items():
            if isinstance(value, list):
                candidates.append((key, value))
        data = parsed.get("data")
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, list):
                    candidates.append((f"data.{key}", value))
    return candidates


def first(obj, names):
    if not isinstance(obj, dict):
        return None
    for name in names:
        value = obj.get(name)
        if value not in (None, ""):
            return value
    for value in obj.values():
        if isinstance(value, dict):
            found = first(value, names)
            if found not in (None, ""):
                return found
    return None


def decode_vaa_base64(text: str):
    raw = base64.b64decode(text)
    if len(raw) < 6 or raw[0] != 1:
        raise ValueError("unsupported VAA")
    signature_count = raw[5]
    body = raw[6 + signature_count * 66 :]
    payload = body[51:]
    result = {
        "payload_hex": payload.hex(),
        "payload_length": len(payload),
    }
    if len(payload) >= 8 and payload[:4] == b"PTGM":
        result.update(
            {
                "magic": "PTGM",
                "module": payload[4],
                "action": payload[5],
                "target_chain": int.from_bytes(payload[6:8], "big"),
                "action_body_length": len(payload) - 8,
            }
        )
    return result


def parse_timestamp(value):
    if not value:
        return None
    return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def account_keys(tx):
    result = tx.get("result") if isinstance(tx, dict) else None
    if not result:
        return []
    keys = result.get("transaction", {}).get("message", {}).get("accountKeys", [])
    normalized = []
    for key in keys:
        if isinstance(key, str):
            normalized.append({"pubkey": key})
        elif isinstance(key, dict) and key.get("pubkey"):
            normalized.append(key)
    return normalized


base = f"https://api.wormholescan.io/api/v1/vaas/1/{EMITTER}"
page_reports = []
all_items = []
selected_key = None
for page in range(0, 20):
    params = urllib.parse.urlencode(
        {"pageSize": 100, "sortOrder": "ASC", "page": page}
    )
    url = f"{base}?{params}"
    status, body, headers = http_get(url)
    text = body.decode("utf-8", errors="replace")
    (PAGES / f"page-{page:02d}.json").write_text(text)
    parsed = json.loads(text)
    candidates = list_candidates(parsed)
    if selected_key is None and candidates:
        selected_key = max(candidates, key=lambda item: len(item[1]))[0]
    matches = [value for key, value in candidates if key == selected_key]
    items = (
        matches[0]
        if matches
        else (max(candidates, key=lambda item: len(item[1]))[1] if candidates else [])
    )
    all_items.extend(items)
    page_reports.append(
        {
            "page": page,
            "url": url,
            "status": status,
            "headers": {
                key: value
                for key, value in headers.items()
                if key.lower() in ("content-range", "link", "x-total-count")
            },
            "list_candidates": [
                {"key": key, "count": len(value)} for key, value in candidates
            ],
            "selected_key": selected_key,
            "selected_count": len(items),
        }
    )
    if page == 0:
        (OUT / "FIRST_PAGE_PRETTY.json").write_text(
            json.dumps(parsed, indent=2, default=str) + "\n"
        )
    if len(items) < 100:
        break

normalized = []
for item in all_items:
    if not isinstance(item, dict):
        continue
    vaa_meta = decode_vaa_base64(item["vaa"]) if item.get("vaa") else {}
    normalized.append(
        {
            "id": first(item, ["id", "_id", "vaaId"]),
            "sequence": first(item, ["sequence", "sequenceNumber"]),
            "tx_hash": first(
                item, ["txHash", "tx_hash", "transactionHash", "originTxHash"]
            ),
            "timestamp": first(item, ["timestamp", "indexedAt", "createdAt"]),
            "emitter_chain": first(item, ["emitterChain"]),
            "emitter_address": first(item, ["emitterAddr", "emitterAddress"]),
            "vaa": vaa_meta,
            "raw": item,
        }
    )
normalized.sort(key=lambda item: int(item["sequence"]))

bursts = []
current = []
for item in normalized:
    if not current:
        current = [item]
        continue
    previous = current[-1]
    gap = (parse_timestamp(item["timestamp"]) - parse_timestamp(previous["timestamp"])).total_seconds()
    if int(item["sequence"]) == int(previous["sequence"]) + 1 and 0 <= gap <= 10:
        current.append(item)
    else:
        if len(current) >= 2:
            bursts.append(current)
        current = [item]
if len(current) >= 2:
    bursts.append(current)

burst_summary = [
    {
        "first_sequence": int(burst[0]["sequence"]),
        "last_sequence": int(burst[-1]["sequence"]),
        "count": len(burst),
        "duration_seconds": (
            parse_timestamp(burst[-1]["timestamp"])
            - parse_timestamp(burst[0]["timestamp"])
        ).total_seconds(),
        "items": [
            {
                "sequence": int(item["sequence"]),
                "timestamp": item["timestamp"],
                "tx_hash": item["tx_hash"],
                "module": item["vaa"].get("module"),
                "action": item["vaa"].get("action"),
                "target_chain": item["vaa"].get("target_chain"),
                "action_body_length": item["vaa"].get("action_body_length"),
            }
            for item in burst
        ],
    }
    for burst in bursts
]

selected_sequences = [736, 737]
selected = {
    int(item["sequence"]): item
    for item in normalized
    if int(item["sequence"]) in selected_sequences
}
rpc_urls = [
    "https://api.mainnet-beta.solana.com",
    "https://solana-rpc.publicnode.com",
]
transactions = {}
for sequence in selected_sequences:
    signature = selected[sequence]["tx_hash"]
    errors = []
    for rpc_url in rpc_urls:
        try:
            response = rpc_call(
                rpc_url,
                "getTransaction",
                [
                    signature,
                    {
                        "encoding": "jsonParsed",
                        "commitment": "finalized",
                        "maxSupportedTransactionVersion": 0,
                    },
                ],
            )
            if response.get("result"):
                transactions[str(sequence)] = {
                    "rpc": rpc_url,
                    "signature": signature,
                    "response": response,
                }
                (TX_DIR / f"sequence-{sequence}.json").write_text(
                    json.dumps(response, indent=2, default=str) + "\n"
                )
                break
            errors.append({"rpc": rpc_url, "response": response})
        except Exception as exc:
            errors.append({"rpc": rpc_url, "error": repr(exc)})
    else:
        transactions[str(sequence)] = {
            "signature": signature,
            "errors": errors,
        }

key_sets = {
    sequence: {item["pubkey"] for item in account_keys(record.get("response", {}))}
    for sequence, record in transactions.items()
}
common_accounts = sorted(set.intersection(*key_sets.values())) if len(key_sets) == 2 else []
account_details = {}
for sequence, record in transactions.items():
    account_details[sequence] = account_keys(record.get("response", {}))

summary = {
    "mode": "public_read_only",
    "emitter": EMITTER,
    "selected_list_key": selected_key,
    "page_reports": page_reports,
    "total_items": len(normalized),
    "min_sequence": int(normalized[0]["sequence"]),
    "max_sequence": int(normalized[-1]["sequence"]),
    "items_with_tx_hash": sum(1 for item in normalized if item.get("tx_hash")),
    "rapid_consecutive_burst_count": len(burst_summary),
    "largest_burst_count": max((item["count"] for item in burst_summary), default=0),
    "selected_transactions": {
        sequence: {
            "signature": record.get("signature"),
            "rpc": record.get("rpc"),
            "has_result": bool(record.get("response", {}).get("result")),
            "errors": record.get("errors"),
        }
        for sequence, record in transactions.items()
    },
    "selected_transaction_common_accounts": common_accounts,
    "selected_transaction_account_details": account_details,
}
(OUT / "SUMMARY.json").write_text(json.dumps(summary, indent=2, default=str) + "\n")
(OUT / "NORMALIZED_ITEMS.json").write_text(
    json.dumps(normalized, indent=2, default=str) + "\n"
)
(OUT / "RAPID_CONSECUTIVE_BURSTS.json").write_text(
    json.dumps(burst_summary, indent=2, default=str) + "\n"
)
print(json.dumps(summary, indent=2, default=str))

if len(normalized) < 739:
    raise SystemExit(f"incomplete metadata inventory: {len(normalized)}")
if len(burst_summary) == 0:
    raise SystemExit("no rapid consecutive governance VAA burst found")
if not all(record.get("response", {}).get("result") for record in transactions.values()):
    raise SystemExit("selected Solana transactions could not be read")
