// SPDX-License-Identifier: UNLICENSED
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
    function test_arbitrum_active_roundtrip() external {
        address[] memory vaults = new address[](23);
        vaults[0] = 0x2834704003616DAD55B5f22D3324E462E92Bad93;
        vaults[1] = 0x9Fc247b58D2d76c0231CAb96274595f59C9e4a89;
        vaults[2] = 0xE9700FD4194722eb680C57ed3e07C8Bb1933Bb98;
        vaults[3] = 0xeA8c59C737d32e0EE78dbAd35C27b142356Ea4a3;
        vaults[4] = 0xe3657dFE299393eBdFC9D5059Ed85ef67eFEEcC1;
        vaults[5] = 0xAd231a5aAc991089F1A4FEbFD95eE571A9826054;
        vaults[6] = 0xEdf257f1429a4E0efBa1019348112Ff1b6Be2231;
        vaults[7] = 0x96d6c438C704A2de8CDCE435803A10D329b72E68;
        vaults[8] = 0x15DCC1978f68c5E0D7A298A65fCc879E2D673D43;
        vaults[9] = 0x90788f682463D1Ac00Bd2230b15A4bD0D32a3E46;
        vaults[10] = 0xA7c500EB3069bAD292D9Bd57574a89Cd883118df;
        vaults[11] = 0xdB8C962e8A39d3E82d3EAA8F477bE90984C6Dfe8;
        vaults[12] = 0xdB4b6723f5659B4e78AaB29Fb1eD49Ccc18Fc5e6;
        vaults[13] = 0x19A0F016Ac3989e754ab8216810beD8503bDA37e;
        vaults[14] = 0xAB3aC228Cac84a8a1C855C3E08F869B65836c962;
        vaults[15] = 0x1C107c4233Ab3056254e717c7a67F9917079b615;
        vaults[16] = 0x552dAc42901b7559D31247B77fA550fb65688432;
        vaults[17] = 0x9b855bA95bbD19C73d931977feB5140D40bC03F6;
        vaults[18] = 0xf8df2Eee600A4Df8cc494D8B1ff34B7980AbA3aD;
        vaults[19] = 0x97901Cf9f064c40F538C5f7b53420A02Cb68c644;
        vaults[20] = 0x1eB3061F96Ff927EA7CAeF216bB5872622052C1C;
        vaults[21] = 0x8A44861320c68b87C58A35d7110fAc5615233728;
        vaults[22] = 0xBD3D2a51824784F138A333055Fa91b590CD2B2CB;
        _scanChain("arbitrum", "https://arbitrum-one-rpc.publicnode.com", vaults);
    }

    function test_base_active_roundtrip() external {
        address[] memory vaults = new address[](11);
        vaults[0] = 0xFa043C890C3C54a147E847E1C97a2C8a8115c1B3;
        vaults[1] = 0x4F7CA859a0d2dbbf774a1375CD12a34dAaff3D50;
        vaults[2] = 0xb8B455001a3A48c28D90eA29Efd9fcc74e95cFF7;
        vaults[3] = 0xddB8Ab45E253f697340a3540665733F46fD2a8fe;
        vaults[4] = 0x4b2A4368544E276780342750D6678dC30368EF35;
        vaults[5] = 0x371Ed18a2fb09a0349BA284905A4F03C98cDd9D4;
        vaults[6] = 0xd92249507B3ECe9600a3b1DaDC1e4DAc3B80128F;
        vaults[7] = 0x29Eceb50C5C1cc52FAb72Ff258B5a46324693BE7;
        vaults[8] = 0x8168AEBc65b4181F6fAAe8094Ca133a272D03CA9;
        vaults[9] = 0xEeE56Dc1fb5eD6ebC596da2ea1d1ECd83409f4e4;
        vaults[10] = 0x801ECB612d2f724dad01F22049752E9596dD3Eb1;
        _scanChain("base", "https://base-rpc.publicnode.com", vaults);
    }

    function test_bnb_active_roundtrip() external {
        address[] memory vaults = new address[](6);
        vaults[0] = 0x696b456c1c79416CCE302D09e935b3cB80d0CDC5;
        vaults[1] = 0x290F5566a5269A52ad70D01aC860456b3B964f01;
        vaults[2] = 0xB962E0B467E4EdA5b8df916c5756F9753d46914F;
        vaults[3] = 0xBF45a2e9bBa728037A714380899fd7C4ee587312;
        vaults[4] = 0x4d1806C26A728f2e1b82b4549b9E074DBE5940B9;
        vaults[5] = 0x1F7Cf59d1ABd6F03dAf7CCA7817B634251B8723C;
        _scanChain("bnb", "https://bsc-rpc.publicnode.com", vaults);
    }

    function test_ethereum_active_roundtrip() external {
        address[] memory vaults = new address[](52);
        vaults[0] = 0x8AF79Dd066d86fE6F3169c62e515D15174dc1A45;
        vaults[1] = 0x42A32606eb641BcB262b5b9F05222EdA3fC30F99;
        vaults[2] = 0xC9514F08f80d59eb0C418883092F295397b3e536;
        vaults[3] = 0xaAB9eC3c2F5F363c654a2910Dbe29aeA708C80b6;
        vaults[4] = 0xafDb696b693F38996B4fa7B839f3E9CfdD758694;
        vaults[5] = 0x7F8ca9b130ED8027a8dc2949542593Dc1a1c95DC;
        vaults[6] = 0x8b1fE482062B9B5FF40c4473d47674A886022118;
        vaults[7] = 0xCcDed4b9D47F7F248bfe3F49a9C70A5F1E6EA4c4;
        vaults[8] = 0xDa273908A3f837091774164E2821ba8Ee8238501;
        vaults[9] = 0x9e7aa7686FE1a85896d2cDcB7AFc3D01237cD276;
        vaults[10] = 0x96D595D35a0203d6e218852190b3E981ADEeab0B;
        vaults[11] = 0x91422083A9947De4f0423c6829888BE7B83f06F5;
        vaults[12] = 0x754A34e2f4582925F5E384c371f78db01A869572;
        vaults[13] = 0x5B38308f3dB29EA653f83db5E715189abCb83fd9;
        vaults[14] = 0xCB575B3de1224469B6fb4d7f03AcE1bED5C92E0b;
        vaults[15] = 0x56a5a7E7aD573ec8568727b87C881dffC30C84dA;
        vaults[16] = 0xC4C8Ffe0AFfEE49Ef5EB13c2908Ad63B359846C1;
        vaults[17] = 0xCeE637e5D129bDfac96bC72fA70ccF12D8D81856;
        vaults[18] = 0x31bcEa36c4943feB48650355dE1fB5f12DcF7674;
        vaults[19] = 0x49EC3dC668F579AC0027255D28662bb056A09b57;
        vaults[20] = 0x7DAEBa3F217614E409F85d3014D33923a6b03630;
        vaults[21] = 0x4B20748c3Dd973f1456eccDE4FF84D54792dcD3e;
        vaults[22] = 0x96B22EB7178d116797e57197e586b70FedAE8Fdd;
        vaults[23] = 0x334F5d28a71432f8fc21C7B2B6F5dBbcD8B32A7b;
        vaults[24] = 0xB9E62Cb9b4cE8ec13c886FaE67369Da417EE2714;
        vaults[25] = 0xbd08C57f7448a5794bf4faeE067EC71AA64ef26D;
        vaults[26] = 0xD88714E295da03a07BcB8aD4a4dbE87fa42d75f9;
        vaults[27] = 0x4Ef971774c77865FF8Ec35f274474CB0eD9c48FA;
        vaults[28] = 0xD2011d314aCAA68E5401E7f5AeC3Be6d2C574DCf;
        vaults[29] = 0x4D431856295413906075dD40266d83624E09C672;
        vaults[30] = 0x6C310b55D6728423B3bddB9D07A6c21Bb6eFBDCb;
        vaults[31] = 0x2Df453aA9ac59Dc05030979CA67Af4BBff424333;
        vaults[32] = 0xe7Bf38c635426caaCfa95966c4C6064e7637fE0A;
        vaults[33] = 0x2a7822d6764dFc7a945A4c38776624cB542b32f6;
        vaults[34] = 0x804EE40b227B9003BB7bf2880cF502466544F208;
        vaults[35] = 0x50913b45F278c39c8A7925b3C31DD88B95fb1AA2;
        vaults[36] = 0xF4918Ef824a242602E0d3e5DB07fFd4DaC4ad3Ea;
        vaults[37] = 0xBd01d20e6897e4A148BafFCfa9ED7aA1ac05a4B0;
        vaults[38] = 0x4bf3499072103e9A4afC2Ce4ea09afccF163CD87;
        vaults[39] = 0x6504158a43208150E5dbc0602d3F3Ac694e0158e;
        vaults[40] = 0x815d9e5A6F9c9662b07570c801131e8942587132;
        vaults[41] = 0xB59f4f16709Aa88e04B0addf15a3DF6Aa8B14524;
        vaults[42] = 0xe2F86504C610EdbaE7A788b04785395fDe781577;
        vaults[43] = 0x924e38bdFDa04990Fc78FEc258E8B83B3478B1Af;
        vaults[44] = 0x75e4cE661A49B6bfb2d5b1a8231E32aB47F8b706;
        vaults[45] = 0x2db0B0fa84C3c8B342183FD0B777C521ec054325;
        vaults[46] = 0x15BEFDB812690D02eCB4cDE372f42BF0A8c24d68;
        vaults[47] = 0x9c4E4c15D0532204186ef757b246253A65B4562D;
        vaults[48] = 0x75eE9f7aA08d20788898103f28F640FFF0fB85fC;
        vaults[49] = 0x67c18866E6F6bEE1e9B6d0BB9055a65Dba8E9348;
        vaults[50] = 0xd972f93d3F8A1B0ae072Cd21CcBb6344f3407275;
        vaults[51] = 0xc81aB5DE4871a447f1003B90c7Ff8C961702EEb2;
        _scanChain("ethereum", "https://ethereum-rpc.publicnode.com", vaults);
    }

    function test_optimism_active_roundtrip() external {
        address[] memory vaults = new address[](4);
        vaults[0] = 0xeEE5205D35747307c3650c82b86Acfd1Abc300b0;
        vaults[1] = 0x0BA60A5bA2D59B3A52C1b27cCc1C7f28213b8C9b;
        vaults[2] = 0xAEcC73782E5d6a6e9F6c1a6533bc68D90891f9b9;
        vaults[3] = 0xB9EbFF375D5EADE50Ed561F611754902f70e34CF;
        _scanChain("optimism", "https://optimism-rpc.publicnode.com", vaults);
    }

    function test_polygon_active_roundtrip() external {
        address[] memory vaults = new address[](5);
        vaults[0] = 0xE194d6De7E9499116A9E7E923696A92d6944D2B2;
        vaults[1] = 0x03441c89e7B751bb570f9Dc8C92702b127c52C51;
        vaults[2] = 0x66431b90985212D3B09E27ff9b83cb32F6dd79Dc;
        vaults[3] = 0xebA6232DC52C2548e4b4aE1d9686e8e692436bA2;
        vaults[4] = 0x6f15CDA2D68B00311614294A2b9b17400636133C;
        _scanChain("polygon", "https://polygon-bor-rpc.publicnode.com", vaults);
    }

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
