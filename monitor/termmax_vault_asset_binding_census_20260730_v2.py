#!/usr/bin/env python3
"""Extends the read-only TermMax vault binding census with pool.asset checks."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
from typing import Any

from web3 import Web3

HERE=Path(__file__).resolve().parent
SPEC=importlib.util.spec_from_file_location("termmax_vault_binding_base",HERE/"termmax_vault_asset_binding_census_20260730.py")
if SPEC is None or SPEC.loader is None: raise RuntimeError("cannot load base scanner")
base=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(base)

POOL_ABI=[
 {"type":"function","name":"asset","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
 {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
 {"type":"function","name":"convertToAssets","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"uint256"}]},
]
base.VAULT_ABI.append({"type":"function","name":"pool","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]})
_original=base.inspect_vault

def inspect_vault(w3:Web3,config:dict[str,Any],vault_address:str,start_block:int,block:int,timestamp:int)->dict[str,Any]:
 row=_original(w3,config,vault_address,start_block,block,timestamp)
 vault=w3.eth.contract(address=Web3.to_checksum_address(vault_address),abi=base.VAULT_ABI)
 pool_r=base.safe(vault.functions.pool().call,block_identifier=block); row["pool"]=pool_r
 pool=base.val(pool_r); asset=base.val(row.get("asset",{})); zero="0x0000000000000000000000000000000000000000"
 if pool and str(pool).lower()!=zero:
  pool=Web3.to_checksum_address(pool); c=w3.eth.contract(address=pool,abi=POOL_ABI)
  pool_asset_r=base.safe(c.functions.asset().call,block_identifier=block)
  shares_r=base.safe(c.functions.balanceOf(Web3.to_checksum_address(vault_address)).call,block_identifier=block)
  shares=int(base.val(shares_r,0) or 0); assets_r=base.safe(c.functions.convertToAssets(shares).call,block_identifier=block) if shares else {"ok":True,"value":0}
  pool_asset=base.val(pool_asset_r)
  row["poolState"]={"address":pool,"asset":pool_asset_r,"sharesHeldByVault":shares_r,"assetsRepresented":assets_r}
  row["poolAssetMatch"]=bool(asset and pool_asset and str(asset).lower()==str(pool_asset).lower())
  row["dangerousCurrentPoolAssetMismatch"]=bool(shares>0 and row["poolAssetMatch"] is False)
 else:
  row["poolState"]=None; row["poolAssetMatch"]=True; row["dangerousCurrentPoolAssetMismatch"]=False
 return row

base.inspect_vault=inspect_vault
rc=base.main()
out=Path(os.environ.get("OUT_DIR","evidence"))
full_path=out/"VAULT_ASSET_BINDING_FULL.json"; compact_path=out/"VAULT_ASSET_BINDING_COMPACT.json"
full=json.loads(full_path.read_text(encoding="utf-8")); pool_mismatches=[]
for chain in full.get("chains",[]):
 for vault in chain.get("vaults",[]):
  if vault.get("dangerousCurrentPoolAssetMismatch"):
   pool_mismatches.append({"chain":chain.get("chain"),"vault":vault.get("vault"),"vaultName":base.val(vault.get("name",{})),"vaultAsset":vault.get("assetMeta"),"pool":vault.get("poolState")})
full["dangerousCurrentPoolAssetMismatchCount"]=len(pool_mismatches)
full["dangerousCurrentPoolAssetMismatches"]=pool_mismatches
if pool_mismatches or full.get("dangerousCurrentMismatchCount",0): full["nextStep"]="LOCAL_FORK_EXPLOIT"
full_path.write_text(json.dumps(full,indent=2,default=base.default),encoding="utf-8")
compact=json.loads(compact_path.read_text(encoding="utf-8")); compact["dangerousCurrentPoolAssetMismatchCount"]=len(pool_mismatches); compact["dangerousCurrentPoolAssetMismatches"]=pool_mismatches; compact["nextStep"]=full["nextStep"]
compact_path.write_text(json.dumps(compact,indent=2,default=base.default),encoding="utf-8")
print(json.dumps(compact,indent=2,default=base.default))
raise SystemExit(rc)
