#!/usr/bin/env python3
from __future__ import annotations

import json
import urllib.request
from pathlib import Path
from typing import Any

ENDPOINT = "https://hub.snapshot.org/graphql"
SPACE = "horizenfoundation.eth"
STAKER = "0x6bf7cf29a8bce11aa62cf593d165c244fa4d3e31"
CHAIN_ID = "26514"


def post(query: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = json.dumps({"query": query, "variables": variables or {}}).encode()
    req = urllib.request.Request(
        ENDPOINT,
        data=payload,
        headers={
            "content-type": "application/json",
            "user-agent": "Horizen-Snapshot-read-only-attestation/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=60) as response:
        obj = json.loads(response.read())
    if obj.get("errors"):
        raise RuntimeError(json.dumps(obj["errors"], indent=2))
    return obj["data"]


def walk(value: Any, path: str = "$") -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = [(path, value)]
    if isinstance(value, dict):
        for key, child in value.items():
            out.extend(walk(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            out.extend(walk(child, f"{path}[{index}]"))
    return out


def strategy_summary(strategies: Any) -> list[dict[str, Any]]:
    result = []
    if not isinstance(strategies, list):
        return result
    for strategy in strategies:
        if not isinstance(strategy, dict):
            continue
        result.append(
            {
                "name": strategy.get("name"),
                "network": str(strategy.get("network")) if strategy.get("network") is not None else None,
                "params": strategy.get("params"),
            }
        )
    return result


def main() -> int:
    output = Path("snapshot-output")
    output.mkdir(exist_ok=True)

    space_query = """
    query Space($id: String!) {
      space(id: $id) {
        id
        name
        network
        symbol
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
      proposals(
        first: 25,
        where: { space_in: $spaces },
        orderBy: "created",
        orderDirection: desc
      ) {
        id
        title
        snapshot
        network
        state
        created
        strategies { name network params }
      }
    }
    """

    space_data = post(space_query, {"id": SPACE})
    proposal_data = post(proposal_query, {"spaces": [SPACE]})
    raw = {"space": space_data.get("space"), "proposals": proposal_data.get("proposals", [])}
    (output / "raw.json").write_text(json.dumps(raw, indent=2) + "\n")

    space = raw.get("space") or {}
    proposals = raw.get("proposals") or []
    current_strategies = strategy_summary(space.get("strategies"))
    proposal_strategies = []
    for proposal in proposals:
        proposal_strategies.append(
            {
                "id": proposal.get("id"),
                "title": proposal.get("title"),
                "snapshot": proposal.get("snapshot"),
                "network": str(proposal.get("network")),
                "state": proposal.get("state"),
                "strategies": strategy_summary(proposal.get("strategies")),
            }
        )

    flattened = walk(raw)
    staker_hits = []
    get_votes_hits = []
    chain_hits = []
    for path, value in flattened:
        if not isinstance(value, (str, int)):
            continue
        text = str(value).lower()
        if STAKER in text:
            staker_hits.append({"path": path, "value": value})
        if "getvotes" in text or "getvotes(address)" in text:
            get_votes_hits.append({"path": path, "value": value})
        if text == CHAIN_ID:
            chain_hits.append({"path": path, "value": value})

    names = sorted(
        {
            str(strategy.get("name"))
            for strategy in current_strategies
            + [item for proposal in proposal_strategies for item in proposal["strategies"]]
            if strategy.get("name")
        }
    )
    contract_call_like = [
        name
        for name in names
        if any(token in name.lower() for token in ("contract-call", "call", "multicall", "delegation", "custom"))
    ]

    current_uses_staker = bool(staker_hits or get_votes_hits)
    result = {
        "space_id": space.get("id"),
        "space_name": space.get("name"),
        "space_network": str(space.get("network")),
        "proposal_count_checked": len(proposals),
        "current_strategies": current_strategies,
        "proposal_strategies": proposal_strategies,
        "strategy_names": names,
        "contract_call_like_strategy_names": contract_call_like,
        "staker_address_hits": staker_hits,
        "get_votes_hits": get_votes_hits,
        "horizen_l3_chain_id_hits": chain_hits,
        "zenstaker_getvotes_consumed": current_uses_staker,
        "pass": not current_uses_staker,
        "security_verdict": "KILL_NO_ZENSTAKER_GOVERNANCE_CONSUMER" if not current_uses_staker else "HOLD_ZENSTAKER_GOVERNANCE_CONSUMER",
        "public_network_writes": 0,
    }
    (output / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")

    public = {
        "space_id": result["space_id"],
        "space_network": result["space_network"],
        "proposal_count_checked": len(proposals),
        "strategy_names": names,
        "contract_call_like_strategy_names": contract_call_like,
        "staker_address_hit_count": len(staker_hits),
        "get_votes_hit_count": len(get_votes_hits),
        "horizen_l3_chain_id_hit_count": len(chain_hits),
        "zenstaker_getvotes_consumed": current_uses_staker,
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
        f"- ZenStaker address hits: `{len(staker_hits)}`\n"
        f"- `getVotes` hits: `{len(get_votes_hits)}`\n"
        f"- Horizen L3 chain-id hits: `{len(chain_hits)}`\n"
        f"- Verdict: **{result['security_verdict']}**\n"
        "- Public-network writes: **0**\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
