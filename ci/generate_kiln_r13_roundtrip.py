#!/usr/bin/env python3
from __future__ import annotations
import json, re, urllib.request
from pathlib import Path

SOURCE_URL = "https://raw.githubusercontent.com/dumebi042/kiln-vault/33359ff399fd9fbf31ca87e3671446eb37a7ee61/kiln-v2-vault.md"
NETWORKS = {
    "ethereum": (1, "https://ethereum-rpc.publicnode.com"),
    "bnb": (56, "https://bsc-rpc.publicnode.com"),
    "polygon": (137, "https://polygon-bor-rpc.publicnode.com"),
    "base": (8453, "https://base-rpc.publicnode.com"),
    "arbitrum": (42161, "https://arbitrum-one-rpc.publicnode.com"),
    "optimism": (10, "https://optimism-rpc.publicnode.com"),
    "avalanche": (43114, "https://avalanche-c-chain-rpc.publicnode.com"),
    "linea": (59144, "https://linea-rpc.publicnode.com"),
    "scroll": (534352, "https://scroll-rpc.publicnode.com"),
    "gnosis": (100, "https://gnosis-rpc.publicnode.com"),
}

text = urllib.request.urlopen(SOURCE_URL, timeout=30).read().decode()
rows = []
for line in text.splitlines():
    if not line.lstrip().startswith("|") or "0x" not in line:
        continue
    cells = [c.strip().replace("\\_", "_") for c in line.strip().strip("|").split("|")]
    if len(cells) < 5:
        continue
    address = re.search(r"0x[a-fA-F0-9]{40}", cells[1])
    network = cells[3].lower().strip()
    if not address or network not in NETWORKS:
        continue
    rows.append({
        "label": re.sub(r"\[([^]]+)\]\([^)]*\)", r"\1", cells[0]),
        "vault": address.group(0),
        "connector": cells[2],
        "network": network,
        "chain_id": NETWORKS[network][0],
        "asset_label": cells[4],
    })
seen = set()
rows = [r for r in rows if not ((r["chain_id"], r["vault"].lower()) in seen or seen.add((r["chain_id"], r["vault"].lower())))]
Path("r13_generation").mkdir(exist_ok=True)
Path("r13_generation/SCOPE.json").write_text(json.dumps(rows, indent=2))

groups = {}
for row in rows:
    groups.setdefault(row["network"], []).append(row)

header = r'''// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;
import {Test, console2} from "forge-std/Test.sol";

interface IR13Vault {
    function asset() external view returns (address);
    function totalAssets() external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function depositFee() external view returns (uint256);
    function deposit(uint256 assets, address receiver) external returns (uint256 shares);
    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets);
}

contract KilnAllActiveRoundTrip is Test {
    address internal constant ATTACKER = address(0xA77113);
'''
body = []
for network, items in sorted(groups.items()):
    rpc = NETWORKS[network][1]
    fn = re.sub(r"[^a-zA-Z0-9_]", "_", network)
    body.append(f'    function test_{fn}_active_roundtrip() external {{')
    body.append(f'        address[] memory vaults = new address[]({len(items)});')
    for i, item in enumerate(items):
        body.append(f'        vaults[{i}] = {item["vault"]};')
    body.append(f'        _scanChain("{network}", "{rpc}", vaults);')
    body.append('    }\n')

footer = r'''
    function _scanChain(string memory network, string memory rpc, address[] memory vaults) internal {
        vm.createSelectFork(rpc);
        uint256 fixedBlock = block.number;
        console2.log("R13_NETWORK", network);
        console2.log("R13_FIXED_BLOCK", fixedBlock);
        uint256 positiveProfitCandidates;
        uint256 zeroNavDeltaCandidates;
        uint256 completedRoundTrips;
        for (uint256 i; i < vaults.length; ++i) {
            (uint256 positive, uint256 zeroDelta, uint256 completed) = _scanVault(rpc, fixedBlock, vaults[i]);
            positiveProfitCandidates += positive;
            zeroNavDeltaCandidates += zeroDelta;
            completedRoundTrips += completed;
        }
        console2.log("R13_COMPLETED_ROUNDTRIPS", completedRoundTrips);
        console2.log("R13_POSITIVE_PROFIT_CANDIDATES", positiveProfitCandidates);
        console2.log("R13_ZERO_NAV_DELTA_CANDIDATES", zeroNavDeltaCandidates);
        assertEq(positiveProfitCandidates, 0, "positive full-exit roundtrip profit");
        assertEq(zeroNavDeltaCandidates, 0, "deposit credited no meaningful NAV");
    }

    function _scanVault(string memory rpc, uint256 fixedBlock, address vaultAddr)
        internal
        returns (uint256 positiveCandidates, uint256 zeroDeltaCandidates, uint256 completed)
    {
        vm.createSelectFork(rpc, fixedBlock);
        IR13Vault vault = IR13Vault(vaultAddr);
        address asset;
        uint256 total;
        uint256 feeRate;
        uint8 decimals;
        try vault.asset() returns (address a) { asset = a; } catch { return (0, 0, 0); }
        try vault.totalAssets() returns (uint256 a) { total = a; } catch { return (0, 0, 0); }
        try vault.depositFee() returns (uint256 f) { feeRate = f; } catch { return (0, 0, 0); }
        (bool decOk, bytes memory decRet) = asset.staticcall(abi.encodeWithSelector(bytes4(0x313ce567)));
        if (!decOk || decRet.length < 32) return (0, 0, 0);
        decimals = abi.decode(decRet, (uint8));
        if (decimals > 30) return (0, 0, 0);
        uint256 unit = 10 ** decimals;
        uint256[] memory amounts = new uint256[](3);
        amounts[0] = unit;
        amounts[1] = _max(unit, total / 10_000);
        amounts[2] = _max(unit, total / 100);
        console2.log("R13_VAULT", vaultAddr);
        console2.log("R13_ASSET", asset);
        console2.log("R13_TOTAL_ASSETS", total);
        console2.log("R13_TOTAL_SUPPLY", vault.totalSupply());
        console2.log("R13_DEPOSIT_FEE", feeRate);
        for (uint256 j; j < amounts.length; ++j) {
            (bool ok, int256 profit, uint256 navDelta, uint256 expectedNet, uint256 remainingShares) =
                _roundTrip(rpc, fixedBlock, vaultAddr, amounts[j]);
            console2.log("R13_AMOUNT", amounts[j]);
            console2.log("R13_OK", ok);
            console2.log("R13_PROFIT_SIGNED");
            console2.logInt(profit);
            console2.log("R13_NAV_DELTA_AFTER_DEPOSIT", navDelta);
            console2.log("R13_EXPECTED_NET_DEPOSIT", expectedNet);
            console2.log("R13_REMAINING_SHARES", remainingShares);
            if (!ok || remainingShares != 0) continue;
            ++completed;
            if (profit > int256(unit)) {
                ++positiveCandidates;
                console2.log("R13_CANDIDATE_POSITIVE_PROFIT", vaultAddr);
            }
            // A connector account-context failure commonly credits the original caller instead
            // of the Vault, leaving totalAssets almost unchanged after a successful deposit.
            uint256 tolerance = _max(uint256(100), expectedNet / 1_000_000);
            if (expectedNet > tolerance && navDelta + tolerance < expectedNet / 100) {
                ++zeroDeltaCandidates;
                console2.log("R13_CANDIDATE_ZERO_NAV_DELTA", vaultAddr);
            }
        }
    }

    function _roundTrip(string memory rpc, uint256 fixedBlock, address vaultAddr, uint256 amount)
        internal
        returns (bool ok, int256 profit, uint256 navDelta, uint256 expectedNet, uint256 remainingShares)
    {
        vm.createSelectFork(rpc, fixedBlock);
        IR13Vault vault = IR13Vault(vaultAddr);
        address asset = vault.asset();
        uint8 decimals = _decimals(asset);
        uint256 beforeTA = vault.totalAssets();
        uint256 feeRate = vault.depositFee();
        expectedNet = amount - (amount * feeRate / (100 * (10 ** decimals)));
        try this.exposedDeal(asset, ATTACKER, amount) { } catch { return (false, 0, 0, expectedNet, 0); }
        uint256 beforeBal = _balanceOf(asset, ATTACKER);
        vm.startPrank(ATTACKER);
        if (!_approve(asset, vaultAddr, type(uint256).max)) {
            vm.stopPrank();
            return (false, 0, 0, expectedNet, 0);
        }
        uint256 shares;
        try vault.deposit(amount, ATTACKER) returns (uint256 s) { shares = s; }
        catch {
            vm.stopPrank();
            return (false, 0, 0, expectedNet, 0);
        }
        uint256 afterDepositTA;
        try vault.totalAssets() returns (uint256 a) { afterDepositTA = a; }
        catch {
            vm.stopPrank();
            return (false, 0, 0, expectedNet, shares);
        }
        navDelta = afterDepositTA > beforeTA ? afterDepositTA - beforeTA : 0;
        try vault.redeem(shares, ATTACKER, ATTACKER) returns (uint256) { }
        catch {
            vm.stopPrank();
            remainingShares = _balanceOf(vaultAddr, ATTACKER);
            return (false, 0, navDelta, expectedNet, remainingShares);
        }
        vm.stopPrank();
        uint256 afterBal = _balanceOf(asset, ATTACKER);
        remainingShares = _balanceOf(vaultAddr, ATTACKER);
        ok = true;
        profit = int256(afterBal) - int256(beforeBal);
    }

    function exposedDeal(address token, address to, uint256 amount) external {
        require(msg.sender == address(this), "self only");
        deal(token, to, amount, true);
    }

    function _approve(address token, address spender, uint256 value) internal returns (bool) {
        (bool ok, bytes memory ret) = token.call(abi.encodeWithSelector(bytes4(0x095ea7b3), spender, value));
        return ok && (ret.length == 0 || (ret.length >= 32 && abi.decode(ret, (bool))));
    }

    function _balanceOf(address token, address account) internal view returns (uint256 value) {
        (bool ok, bytes memory ret) = token.staticcall(abi.encodeWithSelector(bytes4(0x70a08231), account));
        require(ok && ret.length >= 32, "balanceOf failed");
        value = abi.decode(ret, (uint256));
    }

    function _decimals(address token) internal view returns (uint8 value) {
        (bool ok, bytes memory ret) = token.staticcall(abi.encodeWithSelector(bytes4(0x313ce567)));
        require(ok && ret.length >= 32, "decimals failed");
        value = abi.decode(ret, (uint8));
    }

    function _max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a : b;
    }
}
'''
Path("test/KilnAllActiveRoundTrip.t.sol").write_text(header + "\n".join(body) + footer)
print(json.dumps({"vault_count": len(rows), "networks": {k: len(v) for k, v in groups.items()}}, indent=2))
