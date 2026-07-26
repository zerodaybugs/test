// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {IERC20} from "@forge-std/interfaces/IERC20.sol";
import {ISignatureTransfer} from "@permit2/interfaces/ISignatureTransfer.sol";
import {ALLOWANCE_HOLDER} from "src/allowanceholder/IAllowanceHolder.sol";
import {IBridgeSettlerActions} from "src/bridge/IBridgeSettlerActions.sol";
import {INucleusTeller} from "src/core/NucleusTeller.sol";
import {SafeTransferLib} from "src/vendor/SafeTransferLib.sol";
import {NucleusTellerMainnetTest} from "./NucleusTeller.t.sol";
import {ActionDataBuilder} from "../utils/ActionDataBuilder.sol";
import {LibBytes} from "../utils/LibBytes.sol";

/// @notice Replays the upstream public refund test and exports the resulting
///         fork state for offline regression testing. It performs no drain,
///         no mainnet transaction, and no mutation outside Foundry's local fork.
contract NucleusRefundStateExport is NucleusTellerMainnetTest {
    using SafeTransferLib for IERC20;
    using LibBytes for bytes;

    function testExportOfficialRefundState() public {
        uint256 shareAmount = 1e18;

        deal(address(WPAXG), address(this), shareAmount, true);
        WPAXG.safeApprove(address(ALLOWANCE_HOLDER), shareAmount);

        INucleusTeller.BridgeData memory data = _bridgeData();
        uint256 fee = INucleusTeller(TELLER).previewFee(shareAmount, data);
        uint256 excess = 0.1 ether;

        bytes memory bridgeCallData = abi.encodeCall(INucleusTeller.bridge, (0, data)).popSelector();
        bytes[] memory actions = ActionDataBuilder.build(
            _getDefaultTransferFrom(address(WPAXG), shareAmount),
            abi.encodeCall(IBridgeSettlerActions.BRIDGE_TO_NUCLEUS_TELLER, (bridgeCallData))
        );

        deal(address(this), fee + excess);
        ALLOWANCE_HOLDER.exec{value: fee + excess}(
            address(bridgeSettler),
            address(WPAXG),
            shareAmount,
            payable(address(bridgeSettler)),
            abi.encodeCall(bridgeSettler.execute, (actions, bytes32(0)))
        );

        assertEq(WPAXG.balanceOf(address(bridgeSettler)), 0, "bridge should consume WPAXG");
        assertEq(address(bridgeSettler).balance, excess, "official LayerZero refund must remain");

        vm.createDir("artifacts", true);
        vm.writeFile("artifacts/bridge-settler-address.txt", vm.toString(address(bridgeSettler)));
        vm.writeFile("artifacts/refund-amount.txt", vm.toString(excess));
        vm.writeFile("artifacts/fork-block.txt", vm.toString(_testBlockNumber()));
        vm.dumpState("artifacts/refund-state-alloc.json");
    }
}
