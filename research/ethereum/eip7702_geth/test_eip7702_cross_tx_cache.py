"""Cross-transaction EIP-7702 sender-validation and code-cache consistency tests."""

from dataclasses import dataclass

import pytest
from execution_testing import (
    Account,
    Alloc,
    AuthorizationTuple,
    Block,
    BlockchainTestFiller,
    Op,
    Storage,
    Transaction,
)

from .spec import Spec, ref_spec_7702

REFERENCE_SPEC_GIT_PATH = ref_spec_7702.git_path
REFERENCE_SPEC_VERSION = ref_spec_7702.version
pytestmark = pytest.mark.valid_from("Prague")


@dataclass(frozen=True)
class SponsoredScenario:
    name: str
    initial_delegated: bool
    operations: tuple[str, ...]
    failing: str | None = None


SCENARIOS = [
    SponsoredScenario("set", False, ("set",)),
    SponsoredScenario("clear", True, ("clear",)),
    SponsoredScenario("failed_set_revert", False, ("set",), "revert"),
    SponsoredScenario("failed_set_invalid", False, ("set",), "invalid"),
    SponsoredScenario("failed_clear_revert", True, ("clear",), "revert"),
    SponsoredScenario("failed_clear_invalid", True, ("clear",), "invalid"),
    SponsoredScenario("set_clear", False, ("set", "clear")),
    SponsoredScenario("clear_set", True, ("clear", "set")),
]


def _recording_target(pre: Alloc):
    storage = Storage()
    caller_slot = storage.store_next(0, "caller")
    count_slot = storage.store_next(1, "count")
    target = pre.deploy_contract(
        Op.SSTORE(caller_slot, Op.CALLER)
        + Op.SSTORE(count_slot, Op.ADD(Op.SLOAD(count_slot), 1))
        + Op.STOP
    )
    return target, caller_slot, count_slot


def _failure_code(kind: str | None):
    if kind == "revert":
        return Op.REVERT(0, 0)
    if kind == "invalid":
        return Op.INVALID
    return Op.STOP


@pytest.mark.parametrize(
    "scenario",
    [pytest.param(s, id=s.name) for s in SCENARIOS],
)
def test_sponsored_transition_then_authority_sender_same_block(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    scenario: SponsoredScenario,
) -> None:
    """
    Apply delegation mutations from a sponsor, then originate a transaction from
    the authority later in the same block. This detects stale sender-code caches
    across set, clear, replacement and reverted/exceptional outer execution.
    """
    sponsor = pre.fund_eoa()
    old_target = pre.deploy_contract(Op.STOP)
    new_target = pre.deploy_contract(Op.STOP)
    authority = (
        pre.fund_eoa(delegation=old_target)
        if scenario.initial_delegated
        else pre.fund_eoa()
    )
    success_sink = pre.deploy_contract(Op.STOP)
    failing_sink = pre.deploy_contract(_failure_code(scenario.failing))
    target, caller_slot, count_slot = _recording_target(pre)

    sponsored_txs = []
    final_target = old_target if scenario.initial_delegated else None
    authority_nonce = 1 if scenario.initial_delegated else 0
    for sponsor_nonce, operation in enumerate(scenario.operations):
        if operation == "set":
            authorization_target = new_target
            final_target = new_target
        else:
            authorization_target = 0
            final_target = None
        sponsored_txs.append(
            Transaction(
                sender=sponsor,
                nonce=sponsor_nonce,
                to=failing_sink
                if scenario.failing is not None and sponsor_nonce == 0
                else success_sink,
                authorization_list=[
                    AuthorizationTuple(
                        address=authorization_target,
                        nonce=authority_nonce,
                        signer=authority,
                    )
                ],
            )
        )
        authority_nonce += 1

    authority_tx = Transaction(
        sender=authority,
        nonce=authority_nonce,
        to=target,
    )
    final_code = (
        Spec.delegation_designation(final_target) if final_target is not None else b""
    )

    blockchain_test(
        pre=pre,
        blocks=[Block(txs=[*sponsored_txs, authority_tx])],
        post={
            authority: Account(nonce=authority_nonce + 1, code=final_code),
            target: Account(storage={caller_slot: authority, count_slot: 1}),
        },
    )


@pytest.mark.parametrize("operation", ["clear", "replace"])
def test_self_transition_then_sender_again_same_block(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    operation: str,
) -> None:
    """A delegated sender mutates its own delegation and sends again immediately."""
    old_target = pre.deploy_contract(Op.STOP)
    new_target = pre.deploy_contract(Op.STOP)
    authority = pre.fund_eoa(delegation=old_target)
    sink = pre.deploy_contract(Op.STOP)
    target, caller_slot, count_slot = _recording_target(pre)

    authorization_target = 0 if operation == "clear" else new_target
    self_transition = Transaction(
        sender=authority,
        nonce=1,
        to=sink,
        authorization_list=[
            AuthorizationTuple(
                address=authorization_target,
                nonce=2,
                signer=authority,
            )
        ],
    )
    authority_tx = Transaction(sender=authority, nonce=3, to=target)
    final_code = (
        b"" if operation == "clear" else Spec.delegation_designation(new_target)
    )

    blockchain_test(
        pre=pre,
        blocks=[Block(txs=[self_transition, authority_tx])],
        post={
            authority: Account(nonce=4, code=final_code),
            target: Account(storage={caller_slot: authority, count_slot: 1}),
        },
    )
