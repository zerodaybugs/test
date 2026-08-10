"""Gas-bounded EVM reproduction for Besu's remaining Address HashDoS path."""

from hashlib import sha256

import pytest
from execution_testing import Account, Alloc, StateTestFiller, Transaction

pytestmark = pytest.mark.valid_from("Osaka")

ADDRESS_COUNT = 5_000
START_INDEX = 1_000
GAS_LIMIT = 16_700_000

# Runtime:
#   offset := 0
#   while offset < calldatasize:
#       target := shr(96, calldataload(offset))
#       pop(call(0, target, 0, 0, 0, 0, 0))
#       offset += 20
#   sstore(0, offset)
RUNTIME = bytes.fromhex(
    "5b"
    "60006000600060006000"
    "6000513560601c6000f150"
    "600051601401600052"
    "600051369010600057"
    "60005160005500"
)


def _write_zero_sum_pair(buf: bytearray, offset: int, digit: int) -> None:
    if digit == 0:
        a, b = 0, 0
    elif digit == 1:
        a, b = 1, 0xE1  # signed byte -31
    else:
        a, b = 0xFF, 31  # signed byte -1, +31
    buf[offset] = a
    buf[offset + 1] = b


def _colliding_address(index: int) -> bytes:
    buf = bytearray(20)
    remaining = index
    for pair in range(10):
        _write_zero_sum_pair(buf, pair * 2, remaining % 3)
        remaining //= 3
    return bytes(buf)


def _control_address(index: int) -> bytes:
    # Preserve the exact zero/non-zero byte pattern (and therefore calldata gas)
    # while breaking the base-31 zero-sum relation by swapping every non-zero pair.
    buf = bytearray(_colliding_address(index))
    for pair in range(10):
        off = pair * 2
        if buf[off] != 0 or buf[off + 1] != 0:
            buf[off], buf[off + 1] = buf[off + 1], buf[off]
    return bytes(buf)


def _java_bytes_hash(data: bytes) -> int:
    result = 1
    for raw in data:
        signed = raw if raw < 128 else raw - 256
        result = (31 * result + signed) & 0xFFFFFFFF
    return result - 0x100000000 if result & 0x80000000 else result


def _payload(colliding: bool) -> bytes:
    builder = _colliding_address if colliding else _control_address
    return b"".join(builder(START_INDEX + i) for i in range(ADDRESS_COUNT))


@pytest.mark.parametrize(
    "colliding",
    [pytest.param(False, id="control"), pytest.param(True, id="colliding")],
)
def test_besu_world_updater_hashdos_gas_bounded(
    state_test: StateTestFiller,
    pre: Alloc,
    colliding: bool,
) -> None:
    """Execute 5,000 zero-value CALLs under the Osaka per-transaction gas cap."""
    collision_hashes = {
        _java_bytes_hash(_colliding_address(START_INDEX + i)) for i in range(ADDRESS_COUNT)
    }
    assert len(collision_hashes) == 1

    controls = [_control_address(START_INDEX + i) for i in range(ADDRESS_COUNT)]
    assert len({_java_bytes_hash(value) for value in controls}) > ADDRESS_COUNT // 2

    collision_payload = _payload(True)
    control_payload = _payload(False)
    assert len(collision_payload) == len(control_payload) == ADDRESS_COUNT * 20
    assert sum(byte == 0 for byte in collision_payload) == sum(
        byte == 0 for byte in control_payload
    )

    sender = pre.fund_eoa()
    target = pre.deploy_contract(code=RUNTIME)
    payload = collision_payload if colliding else control_payload

    tx = Transaction(
        sender=sender,
        to=target,
        data=payload,
        gas_limit=GAS_LIMIT,
    )

    state_test(
        pre=pre,
        tx=tx,
        post={target: Account(storage={0: ADDRESS_COUNT * 20})},
    )
