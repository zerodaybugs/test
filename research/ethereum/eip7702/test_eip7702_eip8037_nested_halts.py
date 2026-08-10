"""EIP-7702 x EIP-8037 nested delegated-call halt and revert tests."""

import pytest
from execution_testing import (
    Account,
    Alloc,
    AuthorizationTuple,
    Block,
    BlockchainTestFiller,
    Bytecode,
    Op,
    Storage,
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


@pytest.mark.parametrize(
    "child_result,outer_result",
    [
        pytest.param("stop", "stop", id="child_success_outer_success"),
        pytest.param("revert", "stop", id="child_revert_outer_success"),
        pytest.param("invalid", "stop", id="child_halt_outer_success"),
        pytest.param("stop", "revert", id="child_success_outer_revert"),
        pytest.param("revert", "revert", id="child_revert_outer_revert"),
        pytest.param("invalid", "invalid", id="child_halt_outer_halt"),
    ],
)
@pytest.mark.parametrize(
    "predelegated",
    [
        pytest.param(False, id="fresh_authorities"),
        pytest.param(True, id="replace_existing_delegations"),
    ],
)
def test_nested_delegated_state_gas_restoration(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    child_result: str,
    outer_result: str,
    predelegated: bool,
) -> None:
    """
    A set-code transaction delegates authority A to code which calls authority
    B, itself delegated in the same authorization list. B performs state work
    and then succeeds, reverts, or exceptionally halts. A records the child
    result, performs additional state work, and then succeeds, reverts, or
    halts. Authorization writes must persist in every branch while execution
    state follows the EIP-8037 child/top-level state-gas restoration rules.
    """
    sponsor = pre.fund_eoa()
    old_target_a = pre.deploy_contract(Op.STOP)
    old_target_b = pre.deploy_contract(Op.STOP)
    if predelegated:
        authority_a = pre.fund_eoa(0, delegation=old_target_a)
        authority_b = pre.fund_eoa(0, delegation=old_target_b)
        auth_nonce = 1
        final_nonce = 2
    else:
        authority_a = pre.fund_eoa(0)
        authority_b = pre.fund_eoa(0)
        auth_nonce = 0
        final_nonce = 1

    storage_b = Storage()
    child_write_slot = storage_b.store_next(0xBEEF, "child_state_write")
    code_b = pre.deploy_contract(
        Op.SSTORE(child_write_slot, 0xBEEF) + _suffix(child_result)
    )

    storage_a = Storage()
    child_status_slot = storage_a.store_next(
        1 if child_result == "stop" else 0,
        "child_call_status",
    )
    outer_write_slot = storage_a.store_next(0xA11CE, "outer_state_write")
    code_a = pre.deploy_contract(
        Op.SSTORE(
            child_status_slot,
            Op.CALL(gas=2_000_000, address=authority_b),
        )
        + Op.SSTORE(outer_write_slot, 0xA11CE)
        + _suffix(outer_result)
    )

    tx = Transaction(
        sender=sponsor,
        to=authority_a,
        gas_limit=10_000_000,
        authorization_list=[
            AuthorizationTuple(
                address=code_a,
                nonce=auth_nonce,
                signer=authority_a,
            ),
            AuthorizationTuple(
                address=code_b,
                nonce=auth_nonce,
                signer=authority_b,
            ),
        ],
    )

    outer_success = outer_result == "stop"
    child_success = child_result == "stop" and outer_success
    expected_a_storage = storage_a if outer_success else {}
    expected_b_storage = storage_b if child_success else {}

    blockchain_test(
        pre=pre,
        blocks=[Block(txs=[tx])],
        post={
            authority_a: Account(
                nonce=final_nonce,
                code=Spec.delegation_designation(code_a),
                storage=expected_a_storage,
            ),
            authority_b: Account(
                nonce=final_nonce,
                code=Spec.delegation_designation(code_b),
                storage=expected_b_storage,
            ),
        },
    )
