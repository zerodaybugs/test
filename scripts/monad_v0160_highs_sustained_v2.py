from __future__ import annotations

from pathlib import Path
import runpy

runpy.run_path("scripts/monad_v0160_highs_sustained_inject.py", run_name="__main__")

path = Path("monad-bft/monad-raptorcast/src/udp.rs")
text = path.read_text()

old = """            assert_eq!(counts[proposer_index], 1, "clean proposer-side receiver decodes");
"""
new = """            assert_eq!(
                counts[proposer_index],
                0,
                "the proposer owns its proposal locally and is not its own first-hop receiver",
            );
"""
if old not in text:
    raise SystemExit("sustained proposer assertion not found")
text = text.replace(old, new, 1)

path.write_text(text)
print(f"Applied corrected sustained-v2 proposer semantics to {path}")
