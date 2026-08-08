
#[tracing_test::traced_test]
#[tokio::test]
async fn test_mvr_session_certificate_cross_package_replay() {
    use crate::mvr;
    use crate::signed_message::signed_request;
    use crate::tests::{to_sdk_address, to_sdk_ptb, SealTestCluster};
    use crate::time::current_epoch_time;
    use crate::valid_ptb::ValidPtb;
    use crate::Certificate;
    use crypto::{create_full_id, elgamal, ibe};
    use fastcrypto::ed25519::{Ed25519KeyPair, Ed25519Signature};
    use fastcrypto::traits::{KeyPair, Signer};
    use rand::thread_rng;
    use seal_sdk::signed_message;
    use shared_crypto::intent::{Intent, IntentMessage, PersonalMessage};
    use sui_sdk_types::{Address, UserSignature};
    use sui_types::base_types::{ObjectID, SuiAddress};
    use sui_types::crypto::{get_key_pair_from_rng, Signature};
    use sui_types::programmable_transaction_builder::ProgrammableTransactionBuilder;
    use sui_types::signature::GenericSignature;
    use sui_types::Identifier;

    fn account_ptb(
        package_id: ObjectID,
        user: SuiAddress,
    ) -> sui_sdk_types::ProgrammableTransaction {
        let mut builder = ProgrammableTransactionBuilder::new();
        let inner_id = bcs::to_bytes(&user).expect("address BCS");
        let id_arg = builder.pure(inner_id).expect("pure vector<u8>");
        builder.programmable_move_call(
            package_id,
            Identifier::new("account_based").unwrap(),
            Identifier::new("seal_approve").unwrap(),
            vec![],
            vec![id_arg],
        );
        to_sdk_ptb(builder.finish())
    }

    fn certificate(
        wallet: &Ed25519KeyPair,
        session: &Ed25519KeyPair,
        package_name: String,
        mvr_name: Option<String>,
        creation_time: u64,
        ttl_min: u16,
    ) -> Certificate {
        let message = signed_message(
            package_name,
            session.public(),
            creation_time,
            ttl_min,
        );
        let personal = PersonalMessage {
            message: message.as_bytes().to_vec(),
        };
        let intent = IntentMessage::new(Intent::personal_message(), personal);
        let generic = GenericSignature::Signature(Signature::new_secure(&intent, wallet));
        Certificate {
            user: Address::new(SuiAddress::from(wallet.public()).to_inner()),
            session_vk: session.public().clone(),
            creation_time,
            ttl_min,
            signature: UserSignature::from_bytes(generic.as_ref()).expect("valid user signature"),
            mvr_name,
        }
    }

    async fn checked_request(
        server: &crate::Server,
        ptb: sui_sdk_types::ProgrammableTransaction,
        certificate: &Certificate,
        session: &Ed25519KeyPair,
        mvr_name: Option<String>,
    ) -> Result<(Address, Vec<Vec<u8>>, ibe::UserSecretKey), crate::errors::InternalError> {
        let (enc_sk, enc_pk, enc_vk) = elgamal::genkey(&mut thread_rng());
        let request_signature: Ed25519Signature =
            session.sign(&signed_request(&ptb, &enc_pk, &enc_vk));
        let (first_pkg_id, ids) = server
            .check_request(
                &ValidPtb::try_from(ptb).unwrap(),
                &enc_pk,
                &enc_vk,
                &request_signature,
                certificate,
                1000,
                None,
                Some("mvr-replay-regression"),
                mvr_name,
            )
            .await?;
        let response = server.create_response(first_pkg_id, ids.clone(), &enc_pk);
        let user_secret_key = elgamal::decrypt(
            &enc_sk,
            &response.decryption_keys[0].encrypted_key,
        );
        Ok((first_pkg_id, ids, user_secret_key))
    }

    let mut tc = SealTestCluster::new(1, "seal").await;
    let (staleness_package, _) = tc.publish("seal_staleness").await;
    let (seal_package, _) = tc.publish("seal").await;
    tc.add_open_server(staleness_package).await;

    // Two independent package identities model the same MVR application name on
    // two networks. Both contain the same account-based policy and both authorize
    // the same wallet address.
    let (package_a, _) = tc
        .publish_with_deps("patterns", vec![("seal", seal_package)])
        .await;
    let (package_b, _) = tc
        .publish_with_deps("patterns", vec![("seal", seal_package)])
        .await;
    assert_ne!(package_a, package_b);

    let wallet = &tc.users[0].keypair;
    let wallet_address = tc.users[0].address;
    let (_session_address, session): (_, Ed25519KeyPair) =
        get_key_pair_from_rng(&mut thread_rng());
    let creation_time = current_epoch_time();
    let ttl_min = 10;
    let mvr_name = "@zdb/seal-cross-network-regression".to_string();

    // The wallet signs exactly once. The signed text contains only the MVR name,
    // TTL, creation time and session key; no chain ID or resolved package ID.
    let cert = certificate(
        wallet,
        &session,
        mvr_name.clone(),
        Some(mvr_name.clone()),
        creation_time,
        ttl_min,
    );

    let ptb_a = account_ptb(package_a, wallet_address);
    let ptb_b = account_ptb(package_b, wallet_address);

    // Network/package context A.
    mvr::insert_mvr_cache(&mvr_name, to_sdk_address(package_a));
    let (first_a, ids_a, usk_a) = checked_request(
        tc.server(),
        ptb_a,
        &cert,
        &session,
        Some(mvr_name.clone()),
    )
    .await
    .expect("MVR certificate must be accepted for package A");

    // Network/package context B. The certificate bytes and wallet signature are
    // unchanged; only the session-owned PTB signature is freshly produced.
    mvr::insert_mvr_cache(&mvr_name, to_sdk_address(package_b));
    let (first_b, ids_b, usk_b) = checked_request(
        tc.server(),
        ptb_b.clone(),
        &cert,
        &session,
        Some(mvr_name.clone()),
    )
    .await
    .expect("same MVR certificate is replayed for package B");

    assert_eq!(first_a, to_sdk_address(package_a));
    assert_eq!(first_b, to_sdk_address(package_b));
    assert_ne!(ids_a[0], ids_b[0]);

    // Both responses are real valid derived keys in different package namespaces.
    let service_id = tc.servers[0].0;
    let public_key = tc.get_public_keys(&[service_id]).await.remove(0);
    assert!(ibe::verify_user_secret_key(&usk_a, &ids_a[0], &public_key).is_ok());
    assert!(ibe::verify_user_secret_key(&usk_b, &ids_b[0], &public_key).is_ok());
    assert_eq!(
        ids_a[0],
        create_full_id(&package_a.into_bytes(), &bcs::to_bytes(&wallet_address).unwrap())
    );
    assert_eq!(
        ids_b[0],
        create_full_id(&package_b.into_bytes(), &bcs::to_bytes(&wallet_address).unwrap())
    );

    // Negative control: without MVR, a certificate bound to package A is rejected
    // when replayed against package B.
    let package_cert = certificate(
        wallet,
        &session,
        package_a.to_hex_uncompressed(),
        None,
        creation_time,
        ttl_min,
    );
    let package_bound_result = checked_request(
        tc.server(),
        ptb_b,
        &package_cert,
        &session,
        None,
    )
    .await;
    assert!(matches!(
        package_bound_result,
        Err(crate::errors::InternalError::InvalidSignature)
    ));

    println!(
        "SEAL_MVR_CROSS_PACKAGE_CERT_REPLAY_PASS package_a={} package_b={} cert_message_name={} derived_a={} derived_b={} negative_control=REJECTED",
        package_a,
        package_b,
        mvr_name,
        hex::encode(&ids_a[0]),
        hex::encode(&ids_b[0]),
    );
}
