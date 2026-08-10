"""EIP-7702 x EIP-8037 repeated-authorization state-gas tests."""

import pytest
from execution_testing import (
    Account,
    Alloc,
    AuthorizationTuple,
    Block,
    BlockchainTestFiller,
    Bytecode,
    Op,
    Transaction,
)

from .spec import Spec, ref_spec_7702

REFERENCE_SPEC_GIT_PATH = ref_spec_7702.git_path
REFERENCE_SPEC_VERSION = ref_spec_7702.version
pytestmark = pytest.mark.valid_from("Amsterdam")


def _suffix(kind: str) -> Bytecode:
    if kind == "stop":
        return Op.STOP
    if kind == "revert":
        return Op.REVERT(0, 0)
    if kind == "invalid":
        return Op.INVALID
    raise ValueError(kind)


SEQUENCES = [
    ("set",),
    ("clear",),
    ("set", "clear"),
    ("clear", "set"),
    ("set", "set"),
    ("clear", "clear"),
]


@pytest.mark.parametrize(
    "sequence",
    [pytest.param(s, id="-".join(s)) for s in SEQUENCES],
)
@pytest.mark.parametrize(
    "initial_state",
    [
        pytest.param("empty", id="existing_empty_authority"),
        pytest.param("balance", id="balance_only_authority"),
        pytest.param("delegated", id="predelegated_authority"),
    ],
)
@pytest.mark.parametrize(
    "outer_result",
    [
        pytest.param("stop", id="outer_success"),
        pytest.param("revert", id="outer_revert"),
        pytest.param("invalid", id="outer_halt"),
    ],
)
def test_repeated_authorization_state_gas_and_persistence(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    sequence: tuple[str, ...],
    initial_state: str,
    outer_result: str,
) -> None:
    """
    Exercise EIP-8037 account-creation and per-authorization-base refunds for
    repeated tuples from one authority. The last valid tuple controls code,
    every valid tuple increments nonce, and authorization state persists across
    success, REVERT and exceptional halt of the execution phase.
    """
    sponsor = pre.fund_eoa()
    old_target = pre.deploy_contract(Op.STOP)
    target_1 = pre.deploy_contract(Op.STOP)
    target_2 = pre.deploy_contract(Op.STOP)

    if initial_state == "empty":
        authority = pre.fund_eoa(0)
        initial_nonce = 0
        expected_balance = 0
    elif initial_state == "balance":
        authority = pre.fund_eoa(1)
        initial_nonce = 0
        expected_balance = 1
    else:
        authority = pre.fund_eoa(0, delegation=old_target)
        initial_nonce = 1
        expected_balance = 0

    authorization_list = []
    final_target = old_target if initial_state == "delegated" else None
    set_index = 0
    for offset, operation in enumerate(sequence):
        if operation == "clear":
            code_address = 0
            final_target = None
        else:
            code_address = target_1 if set_index == 0 else target_2
            final_target = code_address
            set_index += 1
        authorization_list.append(
            AuthorizationTuple(
                address=code_address,
                nonce=initial_nonce + offset,
                signer=authority,
            )
        )

    sink = pre.deploy_contract(_suffix(outer_result))
    tx = Transaction(
        sender=sponsor,
        to=sink,
        gas_limit=5_000_000,
        authorization_list=authorization_list,
    )

    final_code = (
        Spec.delegation_designation(final_target)
        if final_target is not None
        else b""
    )
    blockchain_test(
        pre=pre,
        blocks=[Block(txs=[tx])],
        post={
            authority: Account(
                nonce=initial_nonce + len(sequence),
                balance=expected_balance,
                code=final_code,
            )
        },
    )
