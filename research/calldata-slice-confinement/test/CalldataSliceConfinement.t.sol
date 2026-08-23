// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

struct GenericCall {
    address target;
    uint256 value;
    bytes data;
}

library SliceDecoder {
    error InvalidSlice();

    // Deliberately minimal assembly decoder used to test one language-level
    // property: whether a returned calldata view remains confined to the
    // original bytes slice after only the first relative offset is checked.
    function decode(bytes calldata slice)
        internal
        pure
        returns (GenericCall[] calldata calls)
    {
        if (slice.length < 32) revert InvalidSlice();

        uint256 relOffset;
        assembly ("memory-safe") {
            relOffset := calldataload(slice.offset)
        }

        if (relOffset > slice.length - 32) revert InvalidSlice();

        assembly ("memory-safe") {
            let dataPointer := add(slice.offset, relOffset)
            calls.offset := add(dataPointer, 32)
            calls.length := calldataload(dataPointer)
        }
    }
}

contract GenericRecorder {
    bytes32 public seen;
    uint256 public count;

    function record(bytes32 marker) external {
        seen = marker;
        count++;
    }
}

contract SliceHarness {
    using SliceDecoder for bytes;

    error ExternalCallFailed();

    function unsafeProbe(bytes calldata bounded, bytes calldata adjacent)
        external
        pure
        returns (address target, uint256 value, bytes4 selector, bytes32 argument)
    {
        adjacent;
        GenericCall[] calldata calls = bounded.decode();
        GenericCall calldata first = calls[0];
        bytes calldata payload = first.data;

        target = first.target;
        value = first.value;
        if (payload.length >= 4) selector = bytes4(payload[:4]);
        if (payload.length >= 36) argument = bytes32(payload[4:36]);
    }

    function unsafeExecute(bytes calldata bounded, bytes calldata adjacent) external {
        adjacent;
        GenericCall[] calldata calls = bounded.decode();
        for (uint256 i; i < calls.length; ++i) {
            GenericCall calldata item = calls[i];
            (bool ok,) = item.target.call{value: item.value}(item.data);
            if (!ok) revert ExternalCallFailed();
        }
    }

    function safeExecute(bytes calldata bounded, bytes calldata adjacent) external {
        adjacent;
        GenericCall[] memory calls = abi.decode(bounded, (GenericCall[]));
        for (uint256 i; i < calls.length; ++i) {
            GenericCall memory item = calls[i];
            (bool ok,) = item.target.call{value: item.value}(item.data);
            if (!ok) revert ExternalCallFailed();
        }
    }
}

contract CalldataSliceConfinementTest {
    uint256 private constant ESCAPE_TO_ADJACENT_DATA = 0x40;

    function test_crossSliceAliasExecutesAdjacentCarrier() external {
        SliceHarness harness = new SliceHarness();
        GenericRecorder recorder = new GenericRecorder();
        bytes32 marker = keccak256("native-cross-slice-positive");

        bytes memory bounded = _boundedView();
        bytes memory adjacent = _carrier(address(recorder), marker);

        (address target, uint256 value, bytes4 selector, bytes32 argument) =
            harness.unsafeProbe(bounded, adjacent);

        require(target == address(recorder), "wrong target");
        require(value == 0, "wrong value");
        require(selector == GenericRecorder.record.selector, "wrong selector");
        require(argument == marker, "wrong argument");

        harness.unsafeExecute(bounded, adjacent);
        require(recorder.seen() == marker, "carrier call not executed");
        require(recorder.count() == 1, "wrong call count");
    }

    function test_sameBoundedBytesDifferentAdjacentCarrierChangesExecution() external {
        SliceHarness harness = new SliceHarness();
        GenericRecorder first = new GenericRecorder();
        GenericRecorder second = new GenericRecorder();
        bytes32 markerA = keccak256("carrier-A");
        bytes32 markerB = keccak256("carrier-B");
        bytes memory boundedA = _boundedView();
        bytes memory boundedB = _boundedView();

        require(keccak256(boundedA) == keccak256(boundedB), "bounded bytes differ");

        (address targetA,,, bytes32 argumentA) =
            harness.unsafeProbe(boundedA, _carrier(address(first), markerA));
        (address targetB,,, bytes32 argumentB) =
            harness.unsafeProbe(boundedB, _carrier(address(second), markerB));

        require(targetA == address(first), "wrong A target");
        require(targetB == address(second), "wrong B target");
        require(argumentA == markerA, "wrong A argument");
        require(argumentB == markerB, "wrong B argument");

        harness.unsafeExecute(boundedB, _carrier(address(second), markerB));
        require(first.count() == 0, "A unexpectedly executed");
        require(second.seen() == markerB, "B not executed");
    }

    function test_canonicalAbiDecoderRejectsCrossSliceAlias() external {
        SliceHarness harness = new SliceHarness();
        GenericRecorder recorder = new GenericRecorder();
        bytes memory payload = abi.encodeWithSelector(
            SliceHarness.safeExecute.selector,
            _boundedView(),
            _carrier(address(recorder), bytes32(uint256(0xCAFE)))
        );

        (bool ok,) = address(harness).call(payload);
        require(!ok, "bounded abi.decode accepted escaped element");
        require(recorder.count() == 0, "safe path executed carrier");
    }

    function test_topLevelOffsetGuardStillRejectsInvalidRoot() external {
        SliceHarness harness = new SliceHarness();
        GenericRecorder recorder = new GenericRecorder();
        bytes memory invalid = abi.encode(
            uint256(0x61),
            uint256(1),
            uint256(ESCAPE_TO_ADJACENT_DATA)
        );
        bytes memory payload = abi.encodeWithSelector(
            SliceHarness.unsafeExecute.selector,
            invalid,
            _carrier(address(recorder), bytes32(uint256(1)))
        );

        (bool ok,) = address(harness).call(payload);
        require(!ok, "invalid root offset accepted");
        require(recorder.count() == 0, "invalid root executed");
    }

    function testFuzz_adjacentCarrierControlsDecodedArgument(bytes32 marker) external {
        SliceHarness harness = new SliceHarness();
        GenericRecorder recorder = new GenericRecorder();
        bytes memory bounded = _boundedView();
        bytes memory adjacent = _carrier(address(recorder), marker);

        (, , bytes4 selector, bytes32 decodedMarker) =
            harness.unsafeProbe(bounded, adjacent);
        require(selector == GenericRecorder.record.selector, "fuzz selector");
        require(decodedMarker == marker, "fuzz decode mismatch");

        harness.unsafeExecute(bounded, adjacent);
        require(recorder.seen() == marker, "fuzz execution mismatch");
        require(recorder.count() == 1, "fuzz call count");
    }

    function _boundedView() private pure returns (bytes memory) {
        // Canonical dynamic-array root and length, followed by an element offset
        // that is valid under the decoder's root-only check but outside this
        // 96-byte slice. In this two-bytes-argument ABI layout, 0x40 reaches the
        // beginning of the adjacent bytes argument's data.
        return abi.encode(
            uint256(0x20),
            uint256(1),
            uint256(ESCAPE_TO_ADJACENT_DATA)
        );
    }

    function _carrier(address target, bytes32 marker)
        private
        pure
        returns (bytes memory)
    {
        return abi.encode(
            target,
            uint256(0),
            abi.encodeWithSelector(GenericRecorder.record.selector, marker)
        );
    }
}
