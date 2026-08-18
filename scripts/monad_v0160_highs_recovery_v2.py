from __future__ import annotations

from pathlib import Path
import runpy

# Inject the original exact test, then harden its network model.
runpy.run_path("scripts/monad_v0160_highs_recovery_inject.py", run_name="__main__")
runpy.run_path("scripts/monad_v0160_highs_recovery_assignment_fix.py", run_name="__main__")

path = Path("monad-bft/monad-raptorcast/src/udp.rs")
text = path.read_text()

replacements = [
    (
        "PrimaryBroadcastGroup::of_epoch(epoch, &honest_one, &validator_map).unwrap();",
        "PrimaryBroadcastGroup::of_epoch(epoch, &honest_three, &validator_map).unwrap();",
    ),
    (
        "let recovery_packets = MessageBuilder::<SecpSignature>::new(&honest_one_key)",
        "let recovery_packets = MessageBuilder::<SecpSignature>::new(&honest_three_key)",
    ),
]
for old, new in replacements:
    if old not in text:
        raise SystemExit(f"recovery-v2 replacement not found: {old}")
    text = text.replace(old, new, 1)

# The recovery packet sender is the new honest proposer in all three receiver feeds.
old_sender = "packet.stride,\n                    honest_one,"
if text.count(old_sender) != 3:
    raise SystemExit(f"expected three recovery sender sites, found {text.count(old_sender)}")
text = text.replace(
    old_sender,
    "packet.stride,\n                    honest_three,",
    3,
)

old_assertions = """        assert_eq!(recovered_one, 1, "poisoned receiver recovers in the next round");
        assert_eq!(recovered_two, 1, "poisoned receiver recovers in the next round");
        assert_eq!(recovered_three, 1, "clean receiver remains healthy");
"""
new_assertions = """        assert_eq!(recovered_one, 1, "first poisoned receiver recovers as a network receiver");
        assert_eq!(recovered_two, 1, "second poisoned receiver recovers as a network receiver");
        assert_eq!(
            recovered_three, 0,
            "the honest proposer owns the proposal locally and is not its own first-hop receiver",
        );
"""
if old_assertions not in text:
    raise SystemExit("recovery-v2 assertion block not found")
text = text.replace(old_assertions, new_assertions, 1)

path.write_text(text)
print(f"Applied corrected recovery-v2 model to {path}")
