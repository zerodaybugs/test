    #[test]
    fn external_packet_replay_scenario() {
        use std::{
            env,
            fs::{self, File},
            io::Write as _,
            path::{Path, PathBuf},
        };

        use monad_crypto::certificate_signature::CertificateKeyPair as _;
        use crate::util::Redundancy;

        fn parse_stage(value: &str) -> DeterministicProtocolRolloutStage {
            use DeterministicProtocolRolloutStage::*;
            match value {
                "always-v0" => AlwaysV0,
                "accept-both-publish-v0" => AcceptBothPublishV0,
                "accept-both-publish-v1" => AcceptBothPublishV1,
                "always-v1" => AlwaysV1,
                other => panic!("unknown rollout stage: {other}"),
            }
        }

        fn parse_u64_list(value: &str) -> Vec<u64> {
            value
                .split(',')
                .filter(|item| !item.trim().is_empty())
                .map(|item| item.trim().parse::<u64>().expect("valid u64 list item"))
                .collect()
        }

        fn packet_path(base: &Path, relative: &str) -> PathBuf {
            let path = PathBuf::from(relative);
            if path.is_absolute() {
                path
            } else {
                base.join(path)
            }
        }

        let mode = env::var("MONAD_REPLAY_MODE").unwrap_or_default();
        if mode.is_empty() {
            eprintln!("MONAD_REPLAY_MODE is unset; generic external replay harness skipped");
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
        let keys: Vec<KeyPairType> = (1_u8..=4).map(make_key_pair).collect();
        let node_ids: Vec<NodeId<PubKeyType>> =
            keys.iter().map(|key| NodeId::new(key.pubkey())).collect();
        let members: BTreeMap<_, _> = node_ids
            .iter()
            .copied()
            .map(|node_id| (node_id, Stake::ONE))
            .collect();
        let validators = ValidatorSet::new_unchecked(members);
        let epoch_validators: BTreeMap<_, _> = [(epoch, validators.clone())].into();
        let full_node_groups = FullNodeGroupMap::default();
        let proposer_schedule = StubProposerSchedule::VALID;

        match mode.as_str() {
            "emit" => {
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
                                &BuildTarget::deterministic_raptorcast(group, round),
                            )
                            .expect("deterministic packet corpus builds");

                        for (packet_index, packet) in packets.iter().enumerate() {
                            let recipient_index = node_ids
                                .iter()
                                .position(|node_id| node_id == packet.recipient.node_id())
                                .expect("packet recipient belongs to validator set");
                            let name = format!(
                                "r{round_value}_p{proposer_index}_c{packet_index}.bin"
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
                eprintln!("EMIT_DONE packets={packet_id} dir={}", base.display());
            }
            "replay" => {
                let default_stage = parse_stage(
                    &env::var("MONAD_REPLAY_STAGE")
                        .unwrap_or_else(|_| "accept-both-publish-v0".to_owned()),
                );
                let mut states: Vec<UdpState<SignatureType>> = node_ids
                    .iter()
                    .copied()
                    .map(|node_id| {
                        let mut state = UdpState::<SignatureType>::new(
                            node_id,
                            u64::MAX,
                            1_000_000,
                        );
                        state.set_v1_rollout(default_stage);
                        state
                    })
                    .collect();
                let mut totals = vec![0_usize; states.len()];
                let scenario = fs::read_to_string(base.join("scenario.tsv"))
                    .expect("read scenario.tsv");
                let mut output = File::create(base.join("replay_output.tsv"))
                    .expect("create replay_output.tsv");
                writeln!(
                    output,
                    "op_index\tcommand\treceiver\tdecoded_now\tdecoded_total\tdetail"
                )
                .unwrap();

                for (op_index, raw_line) in scenario.lines().enumerate() {
                    let line = raw_line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    let fields: Vec<&str> = line.split('\t').collect();
                    match fields[0] {
                        "round" => {
                            assert_eq!(fields.len(), 3, "round receiver round");
                            let receiver: usize = fields[1].parse().expect("receiver index");
                            let round: u64 = fields[2].parse().expect("round value");
                            states[receiver].update_current_round(Round(round));
                            writeln!(
                                output,
                                "{op_index}\tround\t{receiver}\t0\t{}\t{round}",
                                totals[receiver]
                            )
                            .unwrap();
                        }
                        "stage" => {
                            assert_eq!(fields.len(), 3, "stage receiver stage");
                            let receiver: usize = fields[1].parse().expect("receiver index");
                            states[receiver].set_v1_rollout(parse_stage(fields[2]));
                            writeln!(
                                output,
                                "{op_index}\tstage\t{receiver}\t0\t{}\t{}",
                                totals[receiver], fields[2]
                            )
                            .unwrap();
                        }
                        "reset" => {
                            assert_eq!(fields.len(), 2, "reset receiver");
                            let receiver: usize = fields[1].parse().expect("receiver index");
                            let mut state = UdpState::<SignatureType>::new(
                                node_ids[receiver],
                                u64::MAX,
                                1_000_000,
                            );
                            state.set_v1_rollout(default_stage);
                            states[receiver] = state;
                            totals[receiver] = 0;
                            writeln!(
                                output,
                                "{op_index}\treset\t{receiver}\t0\t0\treset"
                            )
                            .unwrap();
                        }
                        "feed" => {
                            assert_eq!(
                                fields.len(),
                                5,
                                "feed receiver sender path stride"
                            );
                            let receiver: usize = fields[1].parse().expect("receiver index");
                            let sender: usize = fields[2].parse().expect("sender index");
                            let path = packet_path(&base, fields[3]);
                            let stride: u16 = fields[4].parse().expect("stride");
                            let payload: Bytes = fs::read(&path).expect("read packet").into();
                            let decoded = states[receiver].handle_message(
                                &epoch_validators,
                                &full_node_groups,
                                &proposer_schedule,
                                |_, _, _| {},
                                AuthRecvMsg {
                                    src_addr: SocketAddr::new(
                                        IpAddr::V4(Ipv4Addr::LOCALHOST),
                                        9000_u16 + sender as u16,
                                    ),
                                    payload,
                                    stride,
                                    sender: Some(node_ids[sender]),
                                },
                            );
                            totals[receiver] += decoded.len();
                            let decoded_lengths = decoded
                                .iter()
                                .map(|(_, message)| message.len().to_string())
                                .collect::<Vec<_>>()
                                .join(",");
                            writeln!(
                                output,
                                "{op_index}\tfeed\t{receiver}\t{}\t{}\t{}:{}",
                                decoded.len(),
                                totals[receiver],
                                path.display(),
                                decoded_lengths,
                            )
                            .unwrap();
                        }
                        "snapshot" => {
                            assert_eq!(fields.len(), 2, "snapshot label");
                            writeln!(
                                output,
                                "{op_index}\tsnapshot\t-1\t0\t{}\t{}",
                                totals.iter().sum::<usize>(),
                                fields[1]
                            )
                            .unwrap();
                        }
                        other => panic!("unknown scenario command: {other}"),
                    }
                }
                eprintln!("REPLAY_DONE totals={totals:?} dir={}", base.display());
            }
            other => panic!("unknown MONAD_REPLAY_MODE: {other}"),
        }
    }
