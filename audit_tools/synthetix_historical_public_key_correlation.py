#!/usr/bin/env python3
"""Historical public-key correlation for live Synthetix Deposit privileges.

The current-tree scan found no match. This second pass scans every added text line in the reachable
Git history of selected public Synthetix repositories, derives Ethereum addresses from every valid
64-hex private-key-shaped literal, and compares them with live role members and Safe owners.
Raw literals are never persisted or printed.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import time
import urllib.request
from typing import Any

from eth_account import Account
from eth_utils import keccak, to_checksum_address

OUT = pathlib.Path("synthetix_historical_public_key_correlation")
OUT.mkdir(parents=True, exist_ok=True)
WORK = pathlib.Path("/tmp/synthetix-historical-key-correlation")
if WORK.exists():
    shutil.rmtree(WORK)
WORK.mkdir(parents=True)

DEPOSIT = "0xD62595c3c23B690BAEE0935e107A209Cb1Dbd37B"
RPC_URLS = (
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://rpc.mevblocker.io",
    "https://eth.drpc.org",
)
REPOSITORIES = (
    "Synthetixio/synthetix-deployments",
    "Synthetixio/synthetix-v3",
    "Synthetixio/synthetix-sdk",
    "Synthetixio/governance.synthetix.eth",
)
ROLE_NAMES = (
    "DEFAULT_ADMIN_ROLE", "OWNER_ROLE", "MANAGER_ROLE", "RELAYER_ROLE",
    "WATCHER_ROLE", "TELLER_ROLE", "GUARDIAN_ROLE", "AUTHORIZED_TRADER_ROLE",
)
HEX64_RE = re.compile(r"(?<![0-9a-fA-F])(?:0x)?([0-9a-fA-F]{64})(?![0-9a-fA-F])")
TEXT_PATH_RE = re.compile(
    r"\.(?:js|jsx|ts|tsx|py|sol|rs|go|java|kt|json|toml|ya?ml|md|txt|env|sh|bash|zsh|ini|cfg|conf|properties|csv|graphql|lock)$",
    re.I,
)


def digest(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def rpc(method: str, params: list[Any]) -> Any:
    payload = json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params}, separators=(",",":")).encode()
    errors=[]
    for url in RPC_URLS:
        try:
            req=urllib.request.Request(url,data=payload,headers={"Content-Type":"application/json","User-Agent":"authorized-read-only-review"},method="POST")
            with urllib.request.urlopen(req,timeout=45) as resp:
                parsed=json.loads(resp.read(4*1024*1024))
            if "error" not in parsed:
                return parsed["result"]
            errors.append(str(parsed["error"])[:100])
        except Exception as exc:
            errors.append(type(exc).__name__)
    raise RuntimeError(f"RPC {method} failed: {' | '.join(errors)}")


def selector(signature: str) -> str:
    return keccak(text=signature)[:4].hex()


def role_hash(name: str) -> str:
    return "0x" + ("00"*32 if name=="DEFAULT_ADMIN_ROLE" else keccak(text=name).hex())


def eth_call(to: str, data: str) -> str:
    return rpc("eth_call", [{"to":to,"data":data},"latest"])


def live_targets() -> tuple[dict[str,list[str]], dict[str,dict[str,Any]], set[str]]:
    roles={}
    targets=set()
    for name in ROLE_NAMES:
        role=role_hash(name).removeprefix("0x")
        count=int(eth_call(DEPOSIT,"0x"+selector("getRoleMemberCount(bytes32)")+role),16)
        members=[]
        for i in range(count):
            raw=eth_call(DEPOSIT,"0x"+selector("getRoleMember(bytes32,uint256)")+role+f"{i:064x}")
            address=to_checksum_address("0x"+raw[-40:])
            members.append(address); targets.add(address)
        roles[name]=members
    safes={}
    for address in list(targets):
        code=rpc("eth_getCode",[address,"latest"])
        if code=="0x":
            continue
        try:
            raw=bytes.fromhex(eth_call(address,"0x"+selector("getOwners()")).removeprefix("0x"))
            off=int.from_bytes(raw[:32],"big"); count=int.from_bytes(raw[off:off+32],"big")
            if count>100 or off+32+count*32>len(raw):
                continue
            owners=[to_checksum_address("0x"+raw[off+32+i*32:off+64+i*32][-20:].hex()) for i in range(count)]
            threshold=int(eth_call(address,"0x"+selector("getThreshold()")),16)
            safes[address]={"owners":owners,"threshold":threshold}
            targets.update(owners)
        except Exception:
            pass
    return roles,safes,targets


def derive(candidate: str) -> str | None:
    try:
        if int(candidate,16)<=0:
            return None
        return Account.from_key(bytes.fromhex(candidate)).address
    except Exception:
        return None


def clone_mirror(repo: str) -> tuple[pathlib.Path,bool,dict[str,Any]]:
    target=WORK/(repo.split("/",1)[1]+".git")
    started=time.monotonic()
    proc=subprocess.run(
        ["git","clone","--mirror","https://github.com/"+repo+".git",str(target)],
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=900,check=False,
    )
    return target,proc.returncode==0,{
        "repository":repo,"success":proc.returncode==0,"returnCode":proc.returncode,
        "elapsedSeconds":round(time.monotonic()-started,2),"stderrSha256":digest(proc.stderr),
        "stderrExcerpt":proc.stderr[-500:] if proc.returncode else None,
    }


def scan_history(repo: str, mirror: pathlib.Path, targets: set[str]) -> dict[str,Any]:
    target_lower={x.lower() for x in targets}
    cmd=[
        "git","--git-dir",str(mirror),"log","--all","--reverse",
        "--format=@@COMMIT:%H","--patch","--unified=0","--no-renames","--",
    ]
    proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,errors="ignore",bufsize=1)
    assert proc.stdout is not None
    commit=None; path=None; old_line=0; new_line=0
    occurrence_count=0; added_line_count=0
    candidate_hashes=set(); derived_addresses=set(); matches=[]
    for line in proc.stdout:
        if line.startswith("@@COMMIT:"):
            commit=line.strip().split(":",1)[1]; path=None; continue
        if line.startswith("+++ b/"):
            path=line[6:].strip(); continue
        if line.startswith("@@ "):
            m=re.search(r"\+(\d+)(?:,(\d+))?",line)
            new_line=int(m.group(1)) if m else 0
            continue
        if not line.startswith("+") or line.startswith("+++"):
            continue
        added_line_count+=1
        current_line=new_line; new_line+=1
        if path and not (TEXT_PATH_RE.search(path) or pathlib.PurePosixPath(path).name in {"Dockerfile","Makefile"}):
            continue
        content=line[1:]
        for m in HEX64_RE.finditer(content):
            occurrence_count+=1
            candidate=m.group(1).lower(); h=digest(candidate)
            if h in candidate_hashes:
                continue
            candidate_hashes.add(h)
            address=derive(candidate)
            if not address:
                continue
            derived_addresses.add(address.lower())
            if address.lower() in target_lower:
                matches.append({
                    "address":to_checksum_address(address),"repository":repo,
                    "commit":commit,"path":path,"line":current_line,
                    "publicLiteralSha256":h,"addedLineSha256":digest(content.strip()),
                })
    stderr=proc.stderr.read() if proc.stderr else ""
    code=proc.wait(timeout=120)
    return {
        "repository":repo,"gitLogReturnCode":code,"stderrSha256":digest(stderr),
        "addedLineCount":added_line_count,"literalOccurrences":occurrence_count,
        "uniquePrivateKeyShapedLiterals":len(candidate_hashes),
        "uniqueDerivedAddresses":len(derived_addresses),"matches":matches,
    }


def main() -> None:
    roles,safes,targets=live_targets()
    clone_results=[]; scans=[]
    for repo in REPOSITORIES:
        mirror,ok,meta=clone_mirror(repo); clone_results.append(meta)
        if ok:
            scans.append(scan_history(repo,mirror,targets))
        else:
            scans.append({"repository":repo,"gitLogReturnCode":None,"addedLineCount":0,"literalOccurrences":0,"uniquePrivateKeyShapedLiterals":0,"uniqueDerivedAddresses":0,"matches":[],"cloneFailed":True})
    matches=[m for s in scans for m in s["matches"]]
    output={
        "safety":"Public RPC and full public Git history only; raw candidate keys never retained.",
        "snapshotBlock":int(rpc("eth_blockNumber",[]),16),"deposit":DEPOSIT,
        "roles":roles,"safes":safes,"privilegedAddresses":sorted(targets,key=str.lower),
        "cloneResults":clone_results,"historyScans":scans,"matchCount":len(matches),"matches":matches,
        "verdict":"HISTORICAL_PUBLIC_KEY_MATCH" if matches else "NO_HISTORICAL_PUBLIC_KEY_MATCH_IN_SCANNED_REPOSITORIES",
        "limitations":["Only the selected public repositories were exhaustively scanned; private repositories and unrelated public repositories are not covered."],
    }
    (OUT/"summary.json").write_text(json.dumps(output,indent=2,sort_keys=True),encoding="utf-8")
    print(json.dumps({
        "snapshotBlock":output["snapshotBlock"],"privilegedAddressCount":len(targets),
        "scans":[{k:s.get(k) for k in ("repository","gitLogReturnCode","addedLineCount","uniquePrivateKeyShapedLiterals","uniqueDerivedAddresses")}|{"matchCount":len(s.get("matches",[]))} for s in scans],
        "matchCount":len(matches),"verdict":output["verdict"],
    },indent=2))


if __name__=="__main__":
    main()
