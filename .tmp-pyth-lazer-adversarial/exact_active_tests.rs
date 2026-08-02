
impl Setup {
    async fn verify_message_ecdsa_result(
        &mut self,
        message: &[u8],
    ) -> Result<(), BanksClientError> {
        let mut transaction_verify = Transaction::new_with_payer(
            &[Instruction::new_with_bytes(
                pyth_lazer_solana_contract::ID,
                &pyth_lazer_solana_contract::instruction::VerifyEcdsaMessage {
                    message_data: message.to_vec(),
                }
                .data(),
                vec![
                    AccountMeta::new(self.payer.pubkey(), true),
                    AccountMeta::new_readonly(pyth_lazer_solana_contract::STORAGE_ID, false),
                    AccountMeta::new(self.treasury, false),
                    AccountMeta::new_readonly(system_program::ID, false),
                ],
            )],
            Some(&self.payer.pubkey()),
        );
        transaction_verify.sign(&[&self.payer], self.recent_blockhash);
        self.banks_client.process_transaction(transaction_verify).await
    }

    async fn set_trusted_ecdsa_result(
        &mut self,
        verifying_key: EvmAddress,
    ) -> Result<(), BanksClientError> {
        let mut transaction_set_trusted = Transaction::new_with_payer(
            &[Instruction::new_with_bytes(
                pyth_lazer_solana_contract::ID,
                &pyth_lazer_solana_contract::instruction::UpdateEcdsaSigner {
                    trusted_signer: verifying_key,
                    expires_at: i64::MAX,
                }
                .data(),
                vec![
                    AccountMeta::new(self.payer.pubkey(), true),
                    AccountMeta::new(pyth_lazer_solana_contract::STORAGE_ID, false),
                ],
            )],
            Some(&self.payer.pubkey()),
        );
        transaction_set_trusted.sign(&[&self.payer], self.recent_blockhash);
        self.banks_client
            .process_transaction(transaction_set_trusted)
            .await
    }
}

fn ecdsa_test_message() -> Vec<u8> {
    hex::decode(
        "e4bd474dd4b822eca4509650613e58b21db858e60750ab3498d4a484028785981740adf42cd558bb4f9efd5157bcbb60a1939470ead091b82b63641ad962c7a537db4eb300310075d3c793c0afe900e42e060003010100000004000054e616b201000004f8ff020035dc1cb2010000010073f010b2010000",
    )
    .unwrap()
}

#[tokio::test]
async fn adversarial_ecdsa_accepts_high_s_twin() {
    let mut setup = Setup::new().await;
    setup.init_contract().await;
    let verifying_key = hex::decode("b8d50f0bae75bf6e03c104903d7c3afc4a6596da").unwrap();
    setup
        .set_trusted_ecdsa(verifying_key.try_into().unwrap())
        .await;

    let low_s = ecdsa_test_message();
    setup.verify_message_ecdsa_result(&low_s).await.unwrap();

    // ECDSA's (r, s) and (r, n-s) twins recover the same public key when
    // the recovery parity bit is flipped. This confirms whether the exact
    // active verifier enforces canonical low-S signatures.
    let high_s = hex::decode(
        "e4bd474dd4b822eca4509650613e58b21db858e60750ab3498d4a484028785981740adf4d32aa744b06102aea843449f5e6c6b8dcfde4b2e83e53c20e66f96e7985af28e01310075d3c793c0afe900e42e060003010100000004000054e616b201000004f8ff020035dc1cb2010000010073f010b2010000",
    )
    .unwrap();
    setup.verify_message_ecdsa_result(&high_s).await.unwrap();
    println!("ADVERSARIAL_ECDSA_HIGH_S_TWIN_ACCEPTED=PASS");
}

#[tokio::test]
async fn adversarial_ecdsa_accepts_unsigned_trailing_bytes() {
    let mut setup = Setup::new().await;
    setup.init_contract().await;
    let verifying_key = hex::decode("b8d50f0bae75bf6e03c104903d7c3afc4a6596da").unwrap();
    setup
        .set_trusted_ecdsa(verifying_key.try_into().unwrap())
        .await;

    let mut message = ecdsa_test_message();
    message.extend_from_slice(&hex::decode("deadbeefcafebabe").unwrap());
    setup.verify_message_ecdsa_result(&message).await.unwrap();
    println!("ADVERSARIAL_ECDSA_UNSIGNED_TRAILING_BYTES_ACCEPTED=PASS");
}

#[tokio::test]
async fn adversarial_ecdsa_rejects_payload_mutation() {
    let mut setup = Setup::new().await;
    setup.init_contract().await;
    let verifying_key = hex::decode("b8d50f0bae75bf6e03c104903d7c3afc4a6596da").unwrap();
    setup
        .set_trusted_ecdsa(verifying_key.try_into().unwrap())
        .await;

    let mut message = ecdsa_test_message();
    let last = message.len() - 1;
    message[last] ^= 1;
    assert!(setup.verify_message_ecdsa_result(&message).await.is_err());
    println!("ADVERSARIAL_ECDSA_SIGNED_PAYLOAD_MUTATION_REJECTED=PASS");
}

#[tokio::test]
async fn adversarial_ecdsa_rejects_invalid_recovery_id() {
    let mut setup = Setup::new().await;
    setup.init_contract().await;
    let verifying_key = hex::decode("b8d50f0bae75bf6e03c104903d7c3afc4a6596da").unwrap();
    setup
        .set_trusted_ecdsa(verifying_key.try_into().unwrap())
        .await;

    let mut message = ecdsa_test_message();
    message[68] = 4;
    assert!(setup.verify_message_ecdsa_result(&message).await.is_err());
    println!("ADVERSARIAL_ECDSA_INVALID_RECOVERY_ID_REJECTED=PASS");
}

#[tokio::test]
async fn adversarial_ecdsa_signer_limit_remains_enforced() {
    let mut setup = Setup::new().await;
    setup.init_contract().await;
    setup
        .set_trusted_ecdsa_result([1u8; 20])
        .await
        .unwrap();
    setup
        .set_trusted_ecdsa_result([2u8; 20])
        .await
        .unwrap();
    assert!(setup.set_trusted_ecdsa_result([3u8; 20]).await.is_err());
    println!("ADVERSARIAL_ECDSA_THIRD_SIGNER_REJECTED=PASS");
}

#[tokio::test]
async fn adversarial_ed25519_rejects_unsigned_trailing_bytes() {
    let mut setup = Setup::new().await;
    setup.init_contract().await;
    let verifying_key =
        hex::decode("74313a6525edf99936aa1477e94c72bc5cc617b21745f5f03296f3154461f214").unwrap();
    let mut message = hex::decode(
        "b9011a82e5cddee2c1bd364c8c57e1c98a6a28d194afcad410ff412226c8b2ae931ff59a57147cb47c7307afc2a0a1abec4dd7e835a5b7113cf5aeac13a745c6bed6c60074313a6525edf99936aa1477e94c72bc5cc617b21745f5f03296f3154461f2141c0075d3c7931c9773f30a240600010102000000010000e1f50500000000",
    )
    .unwrap();
    setup.set_trusted(verifying_key.try_into().unwrap()).await;
    message.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    assert!(setup.verify_message_with_offset(&message, 12).await.is_err());
    println!("ADVERSARIAL_ED25519_UNSIGNED_TRAILING_BYTES_REJECTED=PASS");
}
