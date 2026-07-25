#!/usr/bin/env python3
"""Build an exact local Foundry fixture from the deployed Sourcify verification.

The script downloads only public verified source metadata. It does not query or
mutate live contract state and it creates no transaction.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import shutil
import urllib.request

ADDRESS = "0xff6611190b48Cc920EF3c5DCbD356bF2C20D731F"
SOURCE_URL = f"https://sourcify.dev/server/v2/contract/1/{ADDRESS}?fields=all"
OUT = pathlib.Path("synthetix-local-fixture")
TEST_SOURCE = pathlib.Path("audit_tools/SynthetixDepositLocal.t.sol")


def fetch_json(url: str) -> dict:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 exact-source-local-security-review/1.0", "Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=90) as response:
        return json.loads(response.read())


def main() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)

    verified = fetch_json(SOURCE_URL)
    if str(verified.get("address", "")).lower() != ADDRESS.lower():
        raise RuntimeError("Sourcify returned a different contract address")
    if verified.get("runtimeMatch") != "match":
        raise RuntimeError("Deployed runtime bytecode is not a full match")
    compilation = verified.get("compilation") or {}
    if compilation.get("compilerVersion") != "0.8.30+commit.73712a01":
        raise RuntimeError(f"Unexpected compiler version: {compilation.get('compilerVersion')}")

    sources = verified.get("sources") or {}
    if "src/SynthetixDepositContract.sol" not in sources:
        raise RuntimeError("Main verified source missing")

    manifest: list[dict[str, object]] = []
    for name, record in sorted(sources.items()):
        content = record.get("content")
        if not isinstance(content, str):
            raise RuntimeError(f"Source content missing: {name}")
        path = OUT / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        manifest.append(
            {
                "path": name,
                "bytes": len(content.encode()),
                "sha256": hashlib.sha256(content.encode()).hexdigest(),
            }
        )

    test_path = OUT / "test/SynthetixDepositLocal.t.sol"
    test_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(TEST_SOURCE, test_path)

    foundry_toml = """[profile.default]
src = "src"
test = "test"
libs = ["lib"]
solc = "0.8.30"
evm_version = "prague"
via_ir = true
optimizer = true
optimizer_runs = 200
bytecode_hash = "none"
verbosity = 3
fuzz = { runs = 1000 }
"""
    (OUT / "foundry.toml").write_text(foundry_toml, encoding="utf-8")
    (OUT / "verified-source.json").write_text(json.dumps(verified, indent=2), encoding="utf-8")
    (OUT / "source-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (OUT / "provenance.json").write_text(
        json.dumps(
            {
                "chainId": 1,
                "address": ADDRESS,
                "sourceUrl": SOURCE_URL,
                "runtimeMatch": verified.get("runtimeMatch"),
                "creationMatch": verified.get("creationMatch"),
                "compilerVersion": compilation.get("compilerVersion"),
                "verifiedAt": verified.get("verifiedAt"),
                "sourceCount": len(manifest),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(json.dumps({"sourceCount": len(manifest), "runtimeMatch": verified.get("runtimeMatch")}, indent=2))


if __name__ == "__main__":
    main()
