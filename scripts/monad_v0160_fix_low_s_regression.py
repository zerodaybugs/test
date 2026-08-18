from __future__ import annotations

from pathlib import Path

SOURCE = Path("monad-bft/monad-secp/src/secp.rs")

text = SOURCE.read_text()

old_deserialize = '''        Ok(SecpSignature(
            secp256k1::ecdsa::RecoverableSignature::from_compact(sig_data, recid).map_err(Error)?,
        ))
'''
new_deserialize = '''        let signature =
            secp256k1::ecdsa::RecoverableSignature::from_compact(sig_data, recid).map_err(Error)?;

        // Monad's signer emits canonical low-S signatures. Reject the
        // mathematically equivalent high-S recoverable alias at the byte
        // boundary so raw signature bytes cannot become a second packet,
        // cache, or commitment identity for the same authenticated signer.
        let standard = signature.to_standard();
        let mut normalized = standard.clone();
        normalized.normalize_s();
        if normalized != standard {
            return Err(Error(secp256k1::Error::InvalidSignature));
        }

        Ok(SecpSignature(signature))
'''
if old_deserialize not in text:
    raise SystemExit("missing exact deserialize anchor")
text = text.replace(old_deserialize, new_deserialize, 1)

old_test = '''        // 4) The malleable signature must be rejected:
        let mal_sig = SecpSignature::deserialize(&mal_bytes).unwrap();
        assert!(
            pubkey.verify::<SigningDomainType>(msg, &mal_sig).is_err(),
            "High-S malleable signature successfully verified; signature is malleable"
        );
'''
new_test = '''        // 4) Canonical low-S parsing rejects the high-S representation at
        // the byte boundary, before it can acquire an independent cache or
        // transport commitment identity.
        assert!(
            SecpSignature::deserialize(&mal_bytes).is_err(),
            "High-S malleable signature parsed under canonical low-S policy"
        );
'''
if old_test not in text:
    raise SystemExit("missing exact non-malleability test anchor")
text = text.replace(old_test, new_test, 1)

SOURCE.write_text(text)
print(f"Applied canonical low-S parser and updated regression expectation in {SOURCE}")
