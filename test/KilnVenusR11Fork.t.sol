// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {Test, console2} from "forge-std/Test.sol";

interface IKilnVaultR11 {
    function asset() external view returns (address);
    function totalAssets() external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function connectorRegistry() external view returns (address);
    function connectorName() external view returns (bytes32);
    function depositFee() external view returns (uint256);
    function deposit(uint256 assets, address receiver) external returns (uint256 shares);
    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets);
    function maxRedeem(address owner) external view returns (uint256);
    function previewRedeem(uint256 shares) external view returns (uint256);
}

contract KilnVenusR11Fork is Test {
    address internal constant ATTACKER = address(0xA771);
    string internal constant ETH_RPC = "https://ethereum-rpc.publicnode.com";
    string internal constant BNB_RPC = "https://bsc-rpc.publicnode.com";

    address[] internal ethVaults;
    address[] internal bnbVaults;

    function setUp() public {
        ethVaults.push(0xCcDed4b9D47F7F248bfe3F49a9C70A5F1E6EA4c4);
        ethVaults.push(0xDa273908A3f837091774164E2821ba8Ee8238501);
        bnbVaults.push(0x290F5566a5269A52ad70D01aC860456b3B964f01);
        bnbVaults.push(0xB962E0B467E4EdA5b8df916c5756F9753d46914F);
        bnbVaults.push(0xBF45a2e9bBa728037A714380899fd7C4ee587312);
    }

    function test_ethereum_fixed_block_attack_vs_accrued_control() external {
        uint256 fork = vm.createSelectFork(ETH_RPC);
        uint256 fixedBlock = block.number;
        console2.log("R11_CHAIN ethereum");
        console2.log("R11_FIXED_BLOCK", fixedBlock);
        uint256 materialCandidates;
        for (uint256 i; i < ethVaults.length; ++i) {
            materialCandidates += _scanVault(ETH_RPC, fixedBlock, ethVaults[i]);
        }
        console2.log("R11_MATERIAL_CANDIDATES", materialCandidates);
        assertEq(materialCandidates, 0, "material positive attack/control differential");
        vm.selectFork(fork);
    }

    function test_bnb_fixed_block_attack_vs_accrued_control() external {
        uint256 fork = vm.createSelectFork(BNB_RPC);
        uint256 fixedBlock = block.number;
        console2.log("R11_CHAIN bnb");
        console2.log("R11_FIXED_BLOCK", fixedBlock);
        uint256 materialCandidates;
        for (uint256 i; i < bnbVaults.length; ++i) {
            materialCandidates += _scanVault(BNB_RPC, fixedBlock, bnbVaults[i]);
        }
        console2.log("R11_MATERIAL_CANDIDATES", materialCandidates);
        assertEq(materialCandidates, 0, "material positive attack/control differential");
        vm.selectFork(fork);
    }

    function _scanVault(string memory rpc, uint256 fixedBlock, address vaultAddr) internal returns (uint256 candidates) {
        vm.createSelectFork(rpc, fixedBlock);
        IKilnVaultR11 vault = IKilnVaultR11(vaultAddr);
        address asset = vault.asset();
        uint256 total = vault.totalAssets();
        uint8 decimals = _decimals(asset);
        address market = _resolveMarket(vaultAddr, asset);
        console2.log("R11_VAULT", vaultAddr);
        console2.log("R11_ASSET", asset);
        console2.log("R11_MARKET", market);
        console2.log("R11_TOTAL_ASSETS", total);
        console2.log("R11_TOTAL_SUPPLY", vault.totalSupply());
        console2.log("R11_DEPOSIT_FEE", vault.depositFee());

        uint256 unit = 10 ** decimals;
        uint256[] memory amounts = new uint256[](7);
        amounts[0] = unit;
        amounts[1] = _max(unit, total / 1000);
        amounts[2] = _max(unit, total / 100);
        amounts[3] = _max(unit, total / 10);
        amounts[4] = _max(unit, total);
        amounts[5] = _boundedMul(_max(unit, total), 10);
        amounts[6] = _boundedMul(_max(unit, total), 100);

        for (uint256 j; j < amounts.length; ++j) {
            uint256 amount = amounts[j];
            (bool baseOk, int256 baseProfit, uint256 baseShares, uint256 baseRemaining) =
                _roundTrip(rpc, fixedBlock, vaultAddr, amount, address(0));
            (bool controlOk, int256 controlProfit, uint256 controlShares, uint256 controlRemaining) =
                _roundTrip(rpc, fixedBlock, vaultAddr, amount, market);
            console2.log("R11_AMOUNT", amount);
            console2.log("R11_BASE_OK", baseOk);
            console2.log("R11_BASE_PROFIT_SIGNED");
            console2.logInt(baseProfit);
            console2.log("R11_BASE_SHARES", baseShares);
            console2.log("R11_BASE_REMAINING_SHARES", baseRemaining);
            console2.log("R11_CONTROL_OK", controlOk);
            console2.log("R11_CONTROL_PROFIT_SIGNED");
            console2.logInt(controlProfit);
            console2.log("R11_CONTROL_SHARES", controlShares);
            console2.log("R11_CONTROL_REMAINING_SHARES", controlRemaining);

            // Require a fully exited, reproducible, economically material differential.
            if (
                baseOk && controlOk && baseRemaining == 0 && controlRemaining == 0
                    && baseProfit > int256(unit) && controlProfit <= 0
            ) {
                ++candidates;
                console2.log("R11_CANDIDATE_MATERIAL_DIFFERENTIAL", vaultAddr);
            }
        }
    }

    function _roundTrip(
        string memory rpc,
        uint256 fixedBlock,
        address vaultAddr,
        uint256 amount,
        address accrueMarket
    ) internal returns (bool ok, int256 profit, uint256 mintedShares, uint256 remainingShares) {
        vm.createSelectFork(rpc, fixedBlock);
        IKilnVaultR11 vault = IKilnVaultR11(vaultAddr);
        address asset = vault.asset();
        if (accrueMarket != address(0)) {
            (bool accrued,) = accrueMarket.call(abi.encodeWithSignature("exchangeRateCurrent()"));
            if (!accrued) return (false, 0, 0, 0);
        }
        deal(asset, ATTACKER, amount, true);
        uint256 beforeBal = _balanceOf(asset, ATTACKER);
        vm.startPrank(ATTACKER);
        if (!_approve(asset, vaultAddr, type(uint256).max)) {
            vm.stopPrank();
            return (false, 0, 0, 0);
        }
        try vault.deposit(amount, ATTACKER) returns (uint256 shares) {
            mintedShares = shares;
        } catch {
            vm.stopPrank();
            return (false, 0, 0, 0);
        }
        try vault.redeem(mintedShares, ATTACKER, ATTACKER) returns (uint256) {
            // exact full exit succeeded
        } catch {
            vm.stopPrank();
            remainingShares = _balanceOf(vaultAddr, ATTACKER);
            return (false, 0, mintedShares, remainingShares);
        }
        vm.stopPrank();
        uint256 afterBal = _balanceOf(asset, ATTACKER);
        remainingShares = _balanceOf(vaultAddr, ATTACKER);
        ok = true;
        profit = int256(afterBal) - int256(beforeBal);
    }

    function _resolveMarket(address vaultAddr, address asset) internal view returns (address market) {
        IKilnVaultR11 vault = IKilnVaultR11(vaultAddr);
        address registry = vault.connectorRegistry();
        bytes32 name = vault.connectorName();
        address connector = _staticAddress(registry, abi.encodeWithSignature("connectorAddress(bytes32)", name));
        if (connector == address(0)) connector = _staticAddress(registry, abi.encodeWithSignature("get(bytes32)", name));
        if (connector == address(0)) return address(0);

        market = _firstAddress(
            connector,
            abi.encodeWithSignature("vToken()"),
            abi.encodeWithSignature("vtoken()"),
            abi.encodeWithSignature("venus()"),
            abi.encodeWithSignature("pool()")
        );
        if (market != address(0)) return market;

        address marketRegistry = _firstAddress(
            connector,
            abi.encodeWithSignature("venusMarketRegistry()"),
            abi.encodeWithSignature("marketRegistry()"),
            abi.encodeWithSignature("compoundMarketRegistry()"),
            bytes("")
        );
        if (marketRegistry == address(0)) return address(0);
        market = _staticAddress(marketRegistry, abi.encodeWithSignature("getMarket(address)", asset));
        if (market == address(0)) market = _staticAddress(marketRegistry, abi.encodeWithSignature("getVToken(address)", asset));
        if (market == address(0)) market = _staticAddress(marketRegistry, abi.encodeWithSignature("market(address)", asset));
    }

    function _firstAddress(address target, bytes memory a, bytes memory b, bytes memory c, bytes memory d)
        internal
        view
        returns (address out)
    {
        if (a.length != 0) out = _staticAddress(target, a);
        if (out == address(0) && b.length != 0) out = _staticAddress(target, b);
        if (out == address(0) && c.length != 0) out = _staticAddress(target, c);
        if (out == address(0) && d.length != 0) out = _staticAddress(target, d);
    }

    function _staticAddress(address target, bytes memory data) internal view returns (address out) {
        (bool ok, bytes memory ret) = target.staticcall(data);
        if (ok && ret.length >= 32) out = abi.decode(ret, (address));
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

    function _boundedMul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a > type(uint256).max / b) return type(uint256).max;
        return a * b;
    }
}
