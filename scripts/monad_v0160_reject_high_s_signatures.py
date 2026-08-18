from __future__ import annotations

from pathlib import Path

TARGET = Path("monad-bft/monad-secp/src/secp.rs")

text = TARGET.read_text()
old = """        Ok(SecpSignature(
            secp256k1::ecdsa::RecoverableSignature::from_compact(sig_data, recid).map_err(Error)?,
        ))
"""
new = """        let signature =
            secp256k1::ecdsa::RecoverableSignature::from_compact(sig_data, recid).map_err(Error)?;

        // Monad's signer emits canonical low-S signatures. Reject the
        // mathematically equivalent high-S recoverable alias at the byte
        // boundary so raw signature bytes cannot become a second packet,
        // cache, or commitment identity for the same authenticated signer.
        let standard = signature.to_standard();
        let mut normalized = standard;
        normalized.normalize_s();
        if normalized != standard {
            return Err(Error(secp256k1::Error::InvalidSignature));
        }

        Ok(SecpSignature(signature))
"""
if old not in text:
    raise SystemExit("exact SecpSignature::deserialize block not found")
TARGET.write_text(text.replace(old, new, 1))
print(f"Applied canonical low-S rejection to {TARGET}")
