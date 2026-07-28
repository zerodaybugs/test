#!/usr/bin/env python3
from __future__ import annotations

import json
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

ENDPOINT = "https://hub.snapshot.org/graphql"
SPACE = "horizenfoundation.eth"
STAKER = "0x6bf7cf29a8bce11aa62cf593d165c244fa4d3e31"
CHAIN_ID = "26514"


def post(query: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
    request = urllib.request.Request(
        ENDPOINT,
        data=json.dumps({"query": query, "variables": variables or {}}).encode(),
        headers={
            "content-type": "application/json",
            "user-agent": "Horizen-Snapshot-read-only-attestation/1.1",
        },
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        obj = json.loads(response.read())
    if obj.get("errors"):
        raise RuntimeError(json.dumps(obj["errors"], indent=2))
    return obj["data"]


def walk(value: Any, path: str = "$") -> list[tuple[str, Any]]:
    out = [(path, value)]
    if isinstance(value, dict):
        for key, child in value.items():
            out.extend(walk(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            out.extend(walk(child, f"{path}[{index}]"))
    return out


def summarize_strategies(strategies: Any) -> list[dict[str, Any]]:
    if not isinstance(strategies, list):
        return []
    rows = []
    for strategy in strategies:
        if not isinstance(strategy, dict):
            continue
        params = strategy.get("params") if isinstance(strategy.get("params"), dict) else {}
        url = str(params.get("url") or "")
        parsed = urllib.parse.urlparse(url) if url else None
        rows.append(
            {
                "name": strategy.get("name"),
                "network": str(strategy.get("network")) if strategy.get("network") is not None else None,
                "params": params,
                "api_url": url or None,
                "api_host": parsed.netloc.lower() if parsed else None,
                "api_type": params.get("type"),
                "decimals": params.get("decimals"),
                "symbol": params.get("symbol"),
                "contract": params.get("address") or params.get("contractAddress"),
            }
        )
    return rows


def main() -> int:
    space_query = """
    query Space($id: String!) {
      space(id: $id) {
        id name network symbol
        strategies { name network params }
        validation { name params }
        voting { delay period type quorum }
        filters { minScore onlyMembers }
        plugins
      }
    }
    """
    proposal_query = """
    query Proposals($spaces: [String!]) {
      proposals(first: 25, where: { space_in: $spaces }, orderBy: "created", orderDirection: desc) {
        id title snapshot network state created
        strategies { name network params }
      }
    }
    """

    space = post(space_query, {"id": SPACE}).get("space") or {}
    proposals = post(proposal_query, {"spaces": [SPACE]}).get("proposals") or []
    current = summarize_strategies(space.get("strategies"))
    historical = [
        {
            "id": proposal.get("id"),
            "title": proposal.get("title"),
            "snapshot": proposal.get("snapshot"),
            "network": str(proposal.get("network")),
            "state": proposal.get("state"),
            "strategies": summarize_strategies(proposal.get("strategies")),
        }
        for proposal in proposals
    ]
    raw = {"space": space, "proposals": proposals}
    Path("snapshot-output").mkdir(exist_ok=True)
    Path("snapshot-output/raw.json").write_text(json.dumps(raw, indent=2) + "\n")

    staker_hits: list[dict[str, Any]] = []
    get_votes_hits: list[dict[str, Any]] = []
    chain_hits: list[dict[str, Any]] = []
    for path, value in walk(raw):
        if not isinstance(value, (str, int)):
            continue
        text = str(value).lower()
        if STAKER in text:
            staker_hits.append({"path": path, "value": value})
        if "getvotes" in text:
            get_votes_hits.append({"path": path, "value": value})
        if text == CHAIN_ID:
            chain_hits.append({"path": path, "value": value})

    all_strategies = current + [strategy for item in historical for strategy in item["strategies"]]
    names = sorted({str(item["name"]) for item in all_strategies if item.get("name")})
    api_hosts = sorted({str(item["api_host"]) for item in all_strategies if item.get("api_host")})
    api_urls = sorted({str(item["api_url"]) for item in all_strategies if item.get("api_url")})
    contract_call_like = [
        name for name in names
        if any(token in name.lower() for token in ("contract-call", "multicall", "delegation", "custom"))
    ]
    api_v2 = [item for item in all_strategies if item.get("name") == "api-v2"]
    uses_staker = bool(staker_hits or get_votes_hits)

    result = {
        "space_id": space.get("id"),
        "space_name": space.get("name"),
        "space_network": str(space.get("network")),
        "proposal_count_checked": len(proposals),
        "current_strategies": current,
        "proposal_strategies": historical,
        "strategy_names": names,
        "api_hosts": api_hosts,
        "api_urls": api_urls,
        "api_v2_strategies": api_v2,
        "contract_call_like_strategy_names": contract_call_like,
        "staker_address_hits": staker_hits,
        "get_votes_hits": get_votes_hits,
        "horizen_l3_chain_id_hits": chain_hits,
        "zenstaker_getvotes_consumed": uses_staker,
        "pass": not uses_staker,
        "security_verdict": "KILL_NO_ZENSTAKER_GOVERNANCE_CONSUMER" if not uses_staker else "HOLD_ZENSTAKER_GOVERNANCE_CONSUMER",
        "public_network_writes": 0,
    }
    Path("snapshot-output/RESULT.json").write_text(json.dumps(result, indent=2) + "\n")

    public = {
        "space_id": result["space_id"],
        "space_network": result["space_network"],
        "proposal_count_checked": len(proposals),
        "current_strategies": current,
        "strategy_names": names,
        "api_hosts": api_hosts,
        "api_urls": api_urls,
        "contract_call_like_strategy_names": contract_call_like,
        "staker_address_hit_count": len(staker_hits),
        "get_votes_hit_count": len(get_votes_hits),
        "horizen_l3_chain_id_hit_count": len(chain_hits),
        "zenstaker_getvotes_consumed": uses_staker,
        "pass": result["pass"],
        "security_verdict": result["security_verdict"],
        "public_network_writes": 0,
    }
    Path("sanitized-snapshot").mkdir(exist_ok=True)
    Path("sanitized-snapshot/RESULT.json").write_text(json.dumps(public, indent=2) + "\n")
    Path("sanitized-snapshot/RESULT.md").write_text(
        "# Horizen Snapshot strategy attestation\n\n"
        f"- Space: `{result['space_id']}`\n"
        f"- Space network: `{result['space_network']}`\n"
        f"- Proposals checked: `{len(proposals)}`\n"
        f"- Strategy names: `{', '.join(names)}`\n"
        f"- API hosts: `{', '.join(api_hosts) if api_hosts else 'none'}`\n"
        f"- ZenStaker address hits: `{len(staker_hits)}`\n"
        f"- `getVotes` hits: `{len(get_votes_hits)}`\n"
        f"- Horizen L3 chain-id hits: `{len(chain_hits)}`\n"
        f"- Verdict: **{result['security_verdict']}**\n"
        "- Public-network writes: **0**\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
