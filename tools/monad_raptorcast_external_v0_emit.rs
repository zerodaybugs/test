    #[test]
    fn external_packet_v0_emit_scenario() {
        use std::{
            env,
            fs::{self, File},
            io::Write as _,
            path::PathBuf,
        };

        use monad_crypto::certificate_signature::CertificateKeyPair as _;
        use crate::util::{RaptorcastMode, Redundancy};

        fn parse_u64_list(value: &str) -> Vec<u64> {
            value
                .split(',')
                .filter(|item| !item.trim().is_empty())
                .map(|item| item.trim().parse::<u64>().expect("valid u64 list item"))
                .collect()
        }

        if env::var("MONAD_REPLAY_MODE").unwrap_or_default() != "emit-v0" {
            eprintln!("MONAD_REPLAY_MODE is not emit-v0; V0 emitter skipped");
            return;
        }

        let base = PathBuf::from(env::var("MONAD_REPLAY_DIR").expect("MONAD_REPLAY_DIR"));
        fs::create_dir_all(&base).expect("create replay directory");
        let epoch = Epoch(
            env::var("MONAD_REPLAY_EPOCH")
                .unwrap_or_else(|_| "1".to_owned())
                .parse()
                .expect("valid epoch"),
        );
        let rounds = parse_u64_list(
            &env::var("MONAD_REPLAY_ROUNDS").unwrap_or_else(|_| "42,43,44".to_owned()),
        );
        let app_size: usize = env::var("MONAD_REPLAY_APP_SIZE")
            .unwrap_or_else(|_| (128 * 1024).to_string())
            .parse()
            .expect("valid app size");
        let redundancy: u8 = env::var("MONAD_REPLAY_REDUNDANCY")
            .unwrap_or_else(|_| "2".to_owned())
            .parse()
            .expect("valid redundancy");

        let keys: Vec<KeyPairType> = (1_u8..=4).map(make_key_pair).collect();
        let node_ids: Vec<NodeId<PubKeyType>> =
            keys.iter().map(|key| NodeId::new(key.pubkey())).collect();
        let members: BTreeMap<_, _> = node_ids
            .iter()
            .copied()
            .map(|node_id| (node_id, Stake::ONE))
            .collect();
        let validators = ValidatorSet::new_unchecked(members);
        let epoch_validators: BTreeMap<_, _> = [(epoch, validators)].into();

        let mut manifest = File::create(base.join("manifest.tsv")).expect("manifest");
        writeln!(
            manifest,
            "packet_id\tpath\tstride\tround\tproposer_index\trecipient_index\tpacket_index\tpayload_len"
        )
        .unwrap();

        let mut packet_id = 0_usize;
        for round_value in rounds {
            let round = Round(round_value);
            for proposer_index in 0..keys.len() {
                let proposer = node_ids[proposer_index];
                let group = PrimaryBroadcastGroup::of_epoch(
                    epoch,
                    &proposer,
                    &epoch_validators,
                )
                .expect("primary group");
                let fill = ((round_value as usize + proposer_index) & 0xff) as u8;
                let app_message = vec![fill; app_size];
                let packets = MessageBuilder::<SignatureType>::new(&keys[proposer_index])
                    .unix_ts_ms(1_700_000_000_000_u64 + round_value)
                    .redundancy(Redundancy::from_u8(redundancy))
                    .build_vec(
                        &app_message,
                        &BuildTarget::Raptorcast {
                            group,
                            mode: RaptorcastMode::Regular,
                        },
                    )
                    .expect("regular V0 packet corpus builds");

                for (packet_index, packet) in packets.iter().enumerate() {
                    let recipient_index = node_ids
                        .iter()
                        .position(|node_id| node_id == packet.recipient.node_id())
                        .expect("packet recipient belongs to validator set");
                    let name = format!(
                        "v0_r{round_value}_p{proposer_index}_c{packet_index}.bin"
                    );
                    fs::write(base.join(&name), &packet.payload).expect("write packet");
                    writeln!(
                        manifest,
                        "{packet_id}\t{name}\t{}\t{round_value}\t{proposer_index}\t{recipient_index}\t{packet_index}\t{}",
                        packet.stride,
                        packet.payload.len(),
                    )
                    .unwrap();
                    packet_id += 1;
                }
            }
        }
        eprintln!("EMIT_V0_DONE packets={packet_id} dir={}", base.display());
    }
