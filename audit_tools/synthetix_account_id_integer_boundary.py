#!/usr/bin/env python3
"""Read-only Synthetix subaccount-ID integer-boundary audit.

The production/test account IDs are around 2e18, above JavaScript Number.MAX_SAFE_INTEGER. This
workflow determines whether the official APIs serialize them as strings or JSON numbers, whether
browser JSON.parse/Number conversion preserves them exactly, whether distinct account IDs collide
under IEEE-754, and whether the current Exchange bundle contains obvious account-ID coercions.

Safety:
- public Ethereum logs and unsigned `getSubAccountIds` only;
- public Exchange GET assets only;
- no signature, credential, private account query, trade, transaction or state mutation;
- raw wallet addresses are hashed in output; account IDs are public routing identifiers.
"""
from __future__ import annotations

import collections
import hashlib
import json
import math
import pathlib
import re
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from eth_utils import to_checksum_address

OUT = pathlib.Path("synthetix_account_id_integer_boundary")
OUT.mkdir(parents=True, exist_ok=True)

PROD_INFO = "https://papi.synthetix.io/v1/info"
TEST_INFO = "https://api.test.synthetix.io/v1/info"
EXCHANGE = "https://exchange.synthetix.io/"
DEPOSIT = "0xD62595c3c23B690BAEE0935e107A209Cb1Dbd37B"
CREATION_BLOCK = 23_739_792
ASSET_DEPOSITED_TOPIC = "0x8d9f8eed9603fe0e069574aaf008e644885b52d54ba86f026277ac9db1c2d08a"
RPC_URLS = (
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://rpc.mevblocker.io",
    "https://eth.drpc.org",
)
UA = "Mozilla/5.0 (compatible; authorized-read-only-security-review/1.0)"
MAX_BODY = 12 * 1024 * 1024
MAX_PARTICIPANTS = 500
REQUEST_DELAY = 0.18
MAX_ASSETS = 400
MAX_JS_BYTES = 30 * 1024 * 1024
MAX_SINGLE_ASSET = 8 * 1024 * 1024
MAX_SAFE = 2**53 - 1

INTEGER_TOKEN_RE = re.compile(rb'(?P<quoted>"?)(?P<value>\d{12,})(?P=quoted)')
ASSET_URL_RE = re.compile(r'''(?:src|href)=["']([^"']+\.js(?:\?[^"']*)?)["']|["']([^"']*?/assets/[^"']+\.js(?:\?[^"']*)?)["']''', re.I)
JS_REF_RE = re.compile(r'''["']([^"']+\.js(?:\?[^"']*)?)["']''')
PROPERTY_RE = re.compile(r"(?:subAccountId|subaccountId|accountId)")
COERCION_RE = re.compile(r"(?:Number\s*\(|parseInt\s*\(|parseFloat\s*\(|Math\.|\|\s*0|>>>\s*0|~~)")
SAFE_RE = re.compile(r"(?:BigInt\s*\(|\.toString\s*\(|String\s*\()")


def digest(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def post(url: str, payload: dict[str, Any], timeout: int = 45) -> tuple[int, bytes, dict[str, str]]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(MAX_BODY + 1)
            status = response.status
            headers = dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_BODY + 1)
        status = exc.code
        headers = dict(exc.headers.items()) if exc.headers else {}
    if len(body) > MAX_BODY:
        raise RuntimeError("HTTP body exceeds safety cap")
    return status, body, headers


def get(url: str, timeout: int = 45) -> tuple[int, bytes, dict[str, str], str]:
    request = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"}, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(MAX_BODY + 1)
            status = response.status
            headers = dict(response.headers.items())
            final = response.url
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_BODY + 1)
        status = exc.code
        headers = dict(exc.headers.items()) if exc.headers else {}
        final = exc.url
    if len(body) > MAX_BODY:
        raise RuntimeError("GET body exceeds safety cap")
    return status, body, headers, final


def rpc(method: str, params: list[Any]) -> Any:
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    errors: list[str] = []
    for url in RPC_URLS:
        try:
            status, body, _ = post(url, payload)
            parsed = json.loads(body)
            if status >= 400 or "error" in parsed:
                errors.append(f"{status}:{str(parsed.get('error'))[:100]}")
                continue
            return parsed["result"]
        except Exception as exc:  # noqa: BLE001
            errors.append(type(exc).__name__)
    raise RuntimeError(f"RPC {method} failed: {' | '.join(errors)}")


def get_logs(start: int, end: int) -> list[dict[str, Any]]:
    try:
        return rpc(
            "eth_getLogs",
            [{"address": DEPOSIT, "fromBlock": hex(start), "toBlock": hex(end), "topics": [ASSET_DEPOSITED_TOPIC]}],
        )
    except Exception:
        if start >= end:
            raise
        middle = (start + end) // 2
        return get_logs(start, middle) + get_logs(middle + 1, end)


def beneficiaries() -> tuple[list[str], int]:
    latest = int(rpc("eth_blockNumber", []), 16)
    logs = get_logs(CREATION_BLOCK, latest)
    values: collections.Counter[str] = collections.Counter()
    for log in logs:
        topics = log.get("topics", [])
        if len(topics) >= 3:
            values[to_checksum_address("0x" + str(topics[2])[-40:])] += 1
    participants = [address for address, _ in values.most_common()]
    if len(participants) > MAX_PARTICIPANTS:
        raise RuntimeError(f"participant count {len(participants)} exceeds cap")
    return participants, latest


def raw_integer_tokens(body: bytes) -> list[dict[str, Any]]:
    output = []
    for match in INTEGER_TOKEN_RE.finditer(body):
        value = match.group("value").decode()
        # Restrict to plausible account IDs rather than timestamps and request IDs.
        integer = int(value)
        if integer < 10**15 or integer > 10**22:
            continue
        output.append(
            {
                "decimal": value,
                "quoted": bool(match.group("quoted")),
                "offset": match.start(),
                "prefixSha256": digest(body[max(0, match.start() - 60) : match.start()]),
                "suffixSha256": digest(body[match.end() : min(len(body), match.end() + 60)]),
            }
        )
    return output


def recursively_collect_ids(value: Any, path: str = "$", out: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    if out is None:
        out = []
    if isinstance(value, dict):
        for key, item in value.items():
            recursively_collect_ids(item, f"{path}.{key}", out)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            recursively_collect_ids(item, f"{path}[{index}]", out)
    elif isinstance(value, (str, int)) and not isinstance(value, bool):
        text = str(value)
        if text.isdigit() and 10**15 <= int(text) <= 10**22:
            out.append({"path": path, "pythonType": type(value).__name__, "decimal": text})
    return out


def float_ulp(integer: int) -> int:
    value = float(integer)
    if not math.isfinite(value):
        return 0
    next_value = math.nextafter(value, math.inf)
    return int(next_value - value)


def precision_record(decimal: str) -> dict[str, Any]:
    integer = int(decimal)
    as_number = float(integer)
    rounded = int(as_number)
    return {
        "decimal": decimal,
        "aboveMaxSafeInteger": integer > MAX_SAFE,
        "numberRoundTripDecimal": str(rounded),
        "numberRoundTripExact": rounded == integer,
        "numberDelta": rounded - integer,
        "floatUlp": float_ulp(integer),
        "mod256": integer % 256,
        "mod1024": integer % 1024,
    }


def parse_discovery(endpoint: str, wallet: str) -> dict[str, Any]:
    status, body, headers = post(
        endpoint,
        {"params": {"action": "getSubAccountIds", "walletAddress": wallet, "includeDelegations": True}},
    )
    try:
        parsed = json.loads(body)
    except Exception:
        parsed = None
    ids = recursively_collect_ids(parsed)
    tokens = raw_integer_tokens(body)
    token_by_decimal: dict[str, list[bool]] = collections.defaultdict(list)
    for token in tokens:
        token_by_decimal[token["decimal"]].append(token["quoted"])
    records = []
    for item in ids:
        record = {**item, **precision_record(item["decimal"])}
        quoted_flags = token_by_decimal.get(item["decimal"], [])
        record["rawTokenObserved"] = bool(quoted_flags)
        record["rawTokenQuotedFlags"] = quoted_flags
        records.append(record)
    return {
        "httpStatus": status,
        "contentType": headers.get("Content-Type"),
        "bodyBytes": len(body),
        "bodySha256": digest(body),
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "recordCount": len(records),
        "records": records,
        "rawPlausibleIntegerTokenCount": len(tokens),
        "rawTokens": tokens,
    }


def normalize_asset_url(base: str, reference: str) -> str | None:
    url = urllib.parse.urljoin(base, reference)
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "exchange.synthetix.io" or not parsed.path.endswith(".js"):
        return None
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", parsed.query, ""))


def collect_frontend_assets() -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    status, html, headers, final = get(EXCHANGE)
    text = html.decode("utf-8", errors="replace")
    queue: list[str] = []
    for match in ASSET_URL_RE.finditer(text):
        reference = match.group(1) or match.group(2)
        url = normalize_asset_url(final, reference)
        if url and url not in queue:
            queue.append(url)
    # Current deployments can inject the entry dynamically; cover literal assets in HTML as well.
    for reference in re.findall(r"[A-Za-z0-9_./-]+\.js(?:\?[A-Za-z0-9_=&.-]+)?", text):
        url = normalize_asset_url(final, reference)
        if url and url not in queue:
            queue.append(url)

    seen: set[str] = set()
    assets: list[dict[str, Any]] = []
    snippets: list[dict[str, Any]] = []
    total_bytes = 0
    while queue and len(seen) < MAX_ASSETS and total_bytes < MAX_JS_BYTES:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        try:
            asset_status, body, asset_headers, asset_final = get(url, timeout=60)
        except Exception as exc:
            assets.append({"urlSha256": digest(url), "error": type(exc).__name__})
            continue
        if len(body) > MAX_SINGLE_ASSET:
            assets.append({"urlSha256": digest(url), "httpStatus": asset_status, "bodyBytes": len(body), "skippedLarge": True})
            continue
        total_bytes += len(body)
        js = body.decode("utf-8", errors="replace")
        assets.append(
            {
                "urlSha256": digest(url),
                "path": urllib.parse.urlparse(asset_final).path,
                "httpStatus": asset_status,
                "contentType": asset_headers.get("Content-Type"),
                "bodyBytes": len(body),
                "bodySha256": digest(body),
            }
        )
        for match in PROPERTY_RE.finditer(js):
            start = max(0, match.start() - 350)
            end = min(len(js), match.end() + 350)
            window = js[start:end]
            snippets.append(
                {
                    "assetPath": urllib.parse.urlparse(asset_final).path,
                    "offset": match.start(),
                    "property": match.group(0),
                    "windowSha256": digest(window),
                    "hasUnsafeCoercionToken": bool(COERCION_RE.search(window)),
                    "hasSafeConversionToken": bool(SAFE_RE.search(window)),
                    "excerpt": window[:700],
                }
            )
        for reference in JS_REF_RE.findall(js):
            child = normalize_asset_url(asset_final, reference)
            if child and child not in seen and child not in queue:
                queue.append(child)

    return assets, snippets, {
        "exchangeHttpStatus": status,
        "exchangeContentType": headers.get("Content-Type"),
        "exchangeHtmlBytes": len(html),
        "exchangeHtmlSha256": digest(html),
        "assetCount": len(assets),
        "totalAssetBytes": total_bytes,
        "graphTruncated": bool(queue) or len(seen) >= MAX_ASSETS or total_bytes >= MAX_JS_BYTES,
    }


def main() -> None:
    participants, latest = beneficiaries()
    rows = []
    unique_ids: dict[str, dict[str, Any]] = {}
    non_ok_prod = 0
    test_positive = 0
    for index, wallet in enumerate(participants):
        prod = parse_discovery(PROD_INFO, wallet)
        if prod["httpStatus"] != 200 or prod["apiStatus"] != "ok":
            non_ok_prod += 1
        test = parse_discovery(TEST_INFO, wallet)
        if test["recordCount"]:
            test_positive += 1
        for environment, result in (("production", prod), ("test", test)):
            for record in result["records"]:
                entry = unique_ids.setdefault(record["decimal"], {**precision_record(record["decimal"]), "environments": set(), "pythonTypes": set(), "rawQuotedFlags": set(), "occurrences": 0})
                entry["environments"].add(environment)
                entry["pythonTypes"].add(record["pythonType"])
                entry["rawQuotedFlags"].update(record["rawTokenQuotedFlags"])
                entry["occurrences"] += 1
        rows.append(
            {
                "walletSha256": digest(wallet.lower()),
                "production": prod,
                "test": test,
            }
        )
        if index + 1 < len(participants):
            time.sleep(REQUEST_DELAY)

    number_buckets: dict[str, list[str]] = collections.defaultdict(list)
    for decimal, record in unique_ids.items():
        number_buckets[record["numberRoundTripDecimal"]].append(decimal)
    collisions = {rounded: values for rounded, values in number_buckets.items() if len(values) > 1}

    normalized_ids = []
    for decimal, record in sorted(unique_ids.items(), key=lambda pair: int(pair[0])):
        normalized_ids.append(
            {
                "decimal": decimal,
                **{key: value for key, value in record.items() if key not in {"environments", "pythonTypes", "rawQuotedFlags"}},
                "environments": sorted(record["environments"]),
                "pythonTypes": sorted(record["pythonTypes"]),
                "rawQuotedFlags": sorted(record["rawQuotedFlags"]),
            }
        )

    assets, snippets, frontend = collect_frontend_assets()
    unsafe_snippets = [item for item in snippets if item["hasUnsafeCoercionToken"]]

    output = {
        "safety": "Public logs, unsigned account discovery and public Exchange assets only.",
        "snapshotBlock": latest,
        "participantCount": len(participants),
        "productionDiscoveryNonOkCount": non_ok_prod,
        "walletsWithAnyTestAccount": test_positive,
        "uniqueAccountIdCount": len(normalized_ids),
        "accountIdsAboveMaxSafeInteger": sum(1 for item in normalized_ids if item["aboveMaxSafeInteger"]),
        "accountIdsNotExactlyRepresentableAsJsNumber": sum(1 for item in normalized_ids if not item["numberRoundTripExact"]),
        "accountIdsSerializedAsUnquotedJsonNumber": sum(1 for item in normalized_ids if False in item["rawQuotedFlags"]),
        "accountIdsSerializedAsQuotedString": sum(1 for item in normalized_ids if True in item["rawQuotedFlags"]),
        "jsNumberCollisionBucketCount": len(collisions),
        "jsNumberCollisions": collisions,
        "accountIds": normalized_ids,
        "frontend": frontend,
        "frontendAssets": assets,
        "accountPropertySnippetCount": len(snippets),
        "accountPropertySnippetsWithCoercionTokens": len(unsafe_snippets),
        "accountPropertySnippets": snippets,
        "walletResults": rows,
    }
    if output["accountIdsNotExactlyRepresentableAsJsNumber"] or output["jsNumberCollisionBucketCount"]:
        verdict = "MATERIAL_JS_INTEGER_PRECISION_RISK"
    elif output["accountIdsSerializedAsUnquotedJsonNumber"]:
        verdict = "UNQUOTED_BUT_CURRENT_IDS_EXACTLY_REPRESENTABLE"
    else:
        verdict = "ACCOUNT_IDS_STRING_SERIALIZED_OR_EXACTLY_PRESERVED"
    output["verdict"] = verdict

    (OUT / "summary.json").write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")
    print(
        json.dumps(
            {
                key: output[key]
                for key in (
                    "snapshotBlock",
                    "participantCount",
                    "productionDiscoveryNonOkCount",
                    "walletsWithAnyTestAccount",
                    "uniqueAccountIdCount",
                    "accountIdsAboveMaxSafeInteger",
                    "accountIdsNotExactlyRepresentableAsJsNumber",
                    "accountIdsSerializedAsUnquotedJsonNumber",
                    "accountIdsSerializedAsQuotedString",
                    "jsNumberCollisionBucketCount",
                    "accountPropertySnippetCount",
                    "accountPropertySnippetsWithCoercionTokens",
                    "verdict",
                )
            }
            | {"frontend": frontend},
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
