"""EIP-7702 invalid-tuple ordering and authority-warmth consensus tests."""

import pytest
from execution_testing import (
    Account,
    Alloc,
    AuthorizationTuple,
    ChainConfig,
    Op,
    StateTestFiller,
    Storage,
    Transaction,
)

from .spec import Spec, ref_spec_7702

REFERENCE_SPEC_GIT_PATH = ref_spec_7702.git_path
REFERENCE_SPEC_VERSION = ref_spec_7702.version
pytestmark = pytest.mark.valid_from("Prague")


@pytest.mark.parametrize(
    "case,expected_warm,expected_valid",
    [
        pytest.param("valid", True, True, id="valid_tuple_warms"),
        pytest.param(
            "nonce_mismatch",
            True,
            False,
            id="nonce_mismatch_still_warms",
        ),
        pytest.param(
            "chain_mismatch",
            False,
            False,
            id="chain_mismatch_stops_before_warm",
        ),
        pytest.param(
            "max_nonce",
            False,
            False,
            id="max_nonce_stops_before_warm",
        ),
    ],
)
def test_invalid_tuple_stage_controls_authority_warmth(
    state_test: StateTestFiller,
    pre: Alloc,
    chain_config: ChainConfig,
    case: str,
    expected_warm: bool,
    expected_valid: bool,
) -> None:
    """
    EIP-7702 warms the recovered authority after chain-id, max-nonce and
    signature validation, but before the authority-code and authority-nonce
    checks. A 500-gas child probe converts warm/cold BALANCE cost into a
    deterministic CALL success bit.
    """
    authority = pre.fund_eoa(0)
    sponsor = pre.fund_eoa()
    delegation_target = pre.deploy_contract(Op.STOP)

    # 500 gas is enough for a warm BALANCE plus stack operations, but not for a
    # cold BALANCE. Transaction access warmth is shared with child frames.
    probe = pre.deploy_contract(Op.POP(Op.BALANCE(authority)) + Op.STOP)
    storage = Storage()
    result_slot = storage.store_next(1 if expected_warm else 0, "probe_success")
    observer = pre.deploy_contract(
        Op.SSTORE(result_slot, Op.CALL(gas=500, address=probe)) + Op.STOP
    )

    auth_chain_id = chain_config.chain_id
    auth_nonce = 0
    if case == "nonce_mismatch":
        auth_nonce = 1
    elif case == "chain_mismatch":
        auth_chain_id += 1
    elif case == "max_nonce":
        auth_nonce = 2**64 - 1

    tx = Transaction(
        sender=sponsor,
        to=observer,
        gas_limit=200_000,
        authorization_list=[
            AuthorizationTuple(
                chain_id=auth_chain_id,
                address=delegation_target,
                nonce=auth_nonce,
                signer=authority,
            )
        ],
    )

    # The zero-balance authority only survives EIP-161 finalisation when the
    # authorization is valid and installs delegation code/nonzero nonce.
    authority_post = (
        Account(
            nonce=1,
            code=Spec.delegation_designation(delegation_target),
        )
        if expected_valid
        else Account.NONEXISTENT
    )
    observer_storage = storage if expected_warm else {}

    state_test(
        pre=pre,
        tx=tx,
        post={
            authority: authority_post,
            observer: Account(storage=observer_storage),
        },
    )
