#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, time
from pathlib import Path
NETWORKS=("ethereum","optimism","bnb","polygon","base","arbitrum")
ROOT=Path("r45_downloads"); OUT=Path("r45_aggregate"); OUT.mkdir(parents=True,exist_ok=True)
rows=[]; missing=[]
for network in NETWORKS:
    matches=[p for p in ROOT.rglob("PUBLIC_GATE.json") if p.parent.name==network]
    if not matches: missing.append(network); continue
    rows.append(json.loads(matches[0].read_text()))
selected=sum(int(r.get("selected_count",0) or 0) for r in rows)
inspected=sum(int(r.get("inspected_count",0) or 0) for r in rows)
errors=sum(int(r.get("base_error_count",0) or 0) for r in rows)
mismatches=sum(int(r.get("base_quorum_mismatch_count",0) or 0)+int(r.get("extension_quorum_mismatch_count",0) or 0) for r in rows)
candidates=sum(int(r.get("candidate_count",0) or 0) for r in rows)
inventory=sum(int(r.get("inventory_trigger_count",0) or 0) for r in rows)
coverage=not missing and len(rows)==6 and selected==inspected and all(bool(r.get("coverage_complete")) for r in rows)
if not coverage: decision="INCONCLUSIVE_R45_SHARDED_COVERAGE_FAILED_CLOSED"
elif candidates: decision="HOLD_R45_RUNTIME_CANDIDATES_REQUIRE_PRIVATE_EVIDENCE_AND_FIXED_BLOCK_POC"
elif inventory: decision="HOLD_R45_INVENTORY_DELTA_REQUIRES_SOURCE_DIFF"
else: decision="KILL_R45_NO_NEW_RUNTIME_INVARIANT_SIGNAL"
gate={"schema":"kiln-r45-aggregate-public-gate-v2","generated_at_utc":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),"decision":decision,"coverage_complete":coverage,"missing_networks":missing,"network_gate_count":len(rows),"selected_total":selected,"inspected_total":inspected,"error_total":errors,"quorum_mismatch_total":mismatches,"candidate_total":candidates,"inventory_trigger_total":inventory,"network_gates":rows,"submit_ready":False,"validated_critical":0,"validated_high":0,"public_chain_state_changes":0,"transactions_signed":0,"transactions_sent":0}
(OUT/"PUBLIC_GATE.json").write_text(json.dumps(gate,indent=2,sort_keys=True))
(OUT/"SHA256SUMS.txt").write_text(f"{hashlib.sha256((OUT/'PUBLIC_GATE.json').read_bytes()).hexdigest()}  PUBLIC_GATE.json\n")
print(json.dumps(gate,sort_keys=True)); raise SystemExit(0 if coverage else 2)
