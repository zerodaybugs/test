#!/usr/bin/env python3
from pathlib import Path

path = Path('monad-bft/monad-secp/src/secp.rs')
text = path.read_text()
old = '''        Ok(SecpSignature(
            secp256k1::ecdsa::RecoverableSignature::from_compact(sig_data, recid).map_err(Error)?,
        ))
'''
new = '''        let mut signature =
            secp256k1::ecdsa::RecoverableSignature::from_compact(sig_data, recid).map_err(Error)?;

        // Canonicalize the mathematically equivalent high-S recoverable alias at
        // the authentication boundary.  The low-S transformation changes s to
        // n-s and therefore flips the recovery parity bit to preserve the same
        // recovered public key.
        let mut standard = signature.to_standard();
        let before = standard.serialize_compact();
        standard.normalize_s();
        let after = standard.serialize_compact();
        if after != before {
            let canonical_recid = secp256k1::ecdsa::RecoveryId::from_i32(
                recid.to_i32() ^ 1,
            )
            .map_err(Error)?;
            signature = secp256k1::ecdsa::RecoverableSignature::from_compact(
                &after,
                canonical_recid,
            )
            .map_err(Error)?;
        }

        Ok(SecpSignature(signature))
'''
if old not in text:
    raise SystemExit('target SecpSignature deserialize block not found exactly')
text = text.replace(old, new, 1)
path.write_text(text)
