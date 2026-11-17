//! Packet-kernel tests do not construct a TLS freeze or transferable owner.
use super::super::super::test_support::{R, raw};
use super::*;
const TX: [u8; 16] = [9; 16];
fn fixture() -> R<(GateState, PacketSealer)> {
    fixture_with_policy(PacketPolicy::new(576))
}
fn fixture_with_policy(policy: PacketPolicy) -> R<(GateState, PacketSealer)> {
    let mut state = GateState::new(
        raw(true, 0),
        policy,
        Instant::now() + Duration::from_secs(10),
    )?;
    state.client = true;
    state.active = true;
    state.transaction = TX;
    state.session = [1; 16];
    state.opener = Some(PacketOpener::new(
        policy.datagram([1; 16], 0, Direction::ServerToClient),
        &[3; 32],
    )?);
    state.fence = Some(Fence {
        local: 1000,
        peer: 2000,
        receive_prefix: 400,
        local_horizon: 32768,
        peer_horizon: 32768,
        peer_scale: 0,
        window: 32768,
        sent: 0,
        allocated: 0,
        retired: 0,
        peer_retired: 0,
    });
    let sealer = PacketSealer::new(
        policy.datagram([1; 16], 0, Direction::ServerToClient),
        &[3; 32],
    )?;
    Ok((state, sealer))
}
#[path = "candidate_tests.rs"]
mod candidates;

#[tokio::test(start_paused = true)]
async fn send_diagnostics_separate_actual_packet_io_refusal_from_local_scheduling() -> R {
    struct TestIo {
        blocked: bool,
    }
    impl PacketIo for TestIo {
        fn receive(&mut self, _: &mut [u8]) -> io::Result<Option<usize>> {
            Ok(None)
        }
        fn send(&mut self, _: &[u8]) -> io::Result<()> {
            if self.blocked {
                Err(io::ErrorKind::WouldBlock.into())
            } else {
                Ok(())
            }
        }
    }
    let (state, _) = fixture()?;
    let policy = state.policy;
    let budget = Arc::new(Mutex::new(Budget::new(policy, Instant::now())));
    let mut gate = GateIo::new(TestIo { blocked: true }, state, budget.clone());
    let origin = Instant::now();
    gate.send_timing.try_reserve_exact(1)?;
    gate.send_timing
        .push(super::super::send_timing::SendTiming::new(origin, false));
    let mut bytes = vec![0; 45];
    packet::encode(
        raw(true, 0),
        1000,
        2000,
        32768,
        &[0x80, 0, 0, 0, 0],
        &mut bytes,
    )?;
    lock(&budget)?.quota = 0;
    assert_eq!(
        gate.send(&bytes).err().ok_or("quota refusal")?.kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(gate.send_observations.turn_budget_refusals, 1);
    assert_eq!(gate.send_observations.packet_io_attempts, 0);
    {
        let mut b = lock(&budget)?;
        b.quota = 32;
        b.byte_tokens = 0;
    }
    assert_eq!(
        gate.send(&bytes).err().ok_or("pacing refusal")?.kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(gate.send_observations.pacing_refusals, 1);
    assert_eq!(gate.send_observations.would_block_episodes, 0);
    assert_eq!(
        gate.send_timing[0]
            .snapshot(Instant::now())
            .would_block_observations,
        0
    );
    assert_eq!(
        gate.send_timing[0].snapshot(Instant::now()).open_micros,
        None
    );
    lock(&budget)?.byte_tokens = u64::from(policy.burst_bytes);
    for _ in 0..2 {
        assert_eq!(
            gate.send(&bytes).err().ok_or("actual refusal")?.kind(),
            io::ErrorKind::WouldBlock
        );
    }
    assert_eq!(gate.send_observations.packet_io_attempts, 2);
    assert_eq!(gate.send_observations.would_block_observations, 2);
    assert_eq!(gate.send_observations.would_block_episodes, 1);
    assert!(gate.send_observations.blocked);
    tokio::time::advance(Duration::from_millis(10)).await;
    lock(&budget)?.quota = 0;
    assert_eq!(
        gate.send(&bytes).err().ok_or("later quota refusal")?.kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(
        gate.send_timing[0].snapshot(Instant::now()).open_micros,
        Some(10_000)
    );
    assert_eq!(
        gate.send_timing[0]
            .snapshot(Instant::now())
            .would_block_observations,
        2
    );
    lock(&budget)?.quota = 32;
    tokio::time::advance(Duration::from_millis(5)).await;
    gate.io.blocked = false;
    gate.send(&bytes)?;
    let timed = gate.send_timing[0].snapshot(Instant::now());
    assert_eq!(
        timed.completed,
        SendTimingTotal {
            episodes: 1,
            micros: 15_000
        }
    );
    assert_eq!(timed.open_micros, None);
    assert_eq!(gate.send_observations.resumed_episodes, 1);
    assert!(!gate.send_observations.blocked);
    gate.io.blocked = true;
    assert!(gate.send(&bytes).is_err());
    tokio::time::advance(Duration::from_millis(4)).await;
    gate.cancel_pending();
    gate.cancel_pending();
    let timed = gate.send_timing[0].snapshot(Instant::now());
    assert_eq!(
        timed.cancelled,
        SendTimingTotal {
            episodes: 1,
            micros: 4_000
        }
    );
    assert_eq!(timed.completed.episodes, 1);
    assert_eq!(gate.send_observations.would_block_episodes, 2);
    assert_eq!(gate.send_observations.cancelled_episodes, 1);
    assert!(!gate.send_observations.blocked);
    assert_eq!(lock(&gate.state)?.sent_packets, 1);
    Ok(())
}
fn seal(sealer: &mut PacketSealer, kind: wire::Kind, offset: u64, body: &[u8]) -> R<Vec<u8>> {
    let plain = wire::Header {
        kind,
        transaction: TX,
        offset,
        retired: 0,
        right_edge: 32768,
        body: body.len() as u16,
    }
    .encode(body)?;
    Ok(sealer.seal_vec(&plain)?.bytes)
}
fn outer(protected: &[u8], sequence: u32, ack: u32, window: u16) -> R<Vec<u8>> {
    let mut output = vec![0; 40 + protected.len()];
    packet::encode(raw(false, 0), sequence, ack, window, protected, &mut output)?;
    Ok(output)
}
#[test]
fn mirror_rejections_preserve_original_opener_replay_and_usage() -> R {
    let (mut state, mut sealer) = fixture()?;
    let protected = seal(&mut sealer, wire::Kind::Data, 0, b"kept")?;
    for (seq, ack, window) in [
        (2001, 1000, 32768),
        (2000, 1001, 32768),
        (2000, 1000, 32767),
    ] {
        state.ingest_phase(&outer(&protected, seq, ack, window)?)?;
        assert_eq!(state.opener.as_ref().ok_or("opener")?.usage().packets, 0);
        assert!(state.incoming.is_empty());
        assert_eq!(state.fence.as_ref().ok_or("fence")?.retired, 0);
    }
    state.ingest_phase(&outer(&protected, 2000, 1000, 32768)?)?;
    assert_eq!(state.opener.as_ref().ok_or("opener")?.usage().packets, 1);
    assert_eq!(state.incoming.pop_front().ok_or("cell")?.body, b"kept");
    state.ingest_phase(&outer(&protected, 2000, 1000, 32768)?)?;
    assert_eq!(state.opener.as_ref().ok_or("opener")?.usage().packets, 1);
    Ok(())
}
#[test]
fn fresh_nonce_cannot_reuse_or_overlap_any_accepted_byte_range() -> R {
    let (mut state, mut sealer) = fixture()?;
    let a = seal(&mut sealer, wire::Kind::Data, 0, b"first")?;
    state.ingest_phase(&outer(&a, 2000, 1000, 32768)?)?;
    for offset in [0, 1, a.len() as u64 - 1] {
        let b = seal(&mut sealer, wire::Kind::Data, offset, b"conflicting bytes")?;
        state.ingest_phase(&outer(&b, 2000 + offset as u32, 1000, 32768)?)?;
        assert_eq!(state.opener.as_ref().ok_or("opener")?.usage().packets, 1);
    }
    let c = seal(&mut sealer, wire::Kind::Data, a.len() as u64, b"adjacent")?;
    state.ingest_phase(&outer(&c, 2000 + a.len() as u32, 1000, 32768)?)?;
    assert_eq!(state.ranges.occupied_bytes(), (a.len() + c.len()) as u64);
    assert_eq!(state.opener.as_ref().ok_or("opener")?.usage().packets, 2);
    Ok(())
}
#[test]
fn disjoint_reorder_is_accepted() -> R {
    let (mut state, mut sealer) = fixture()?;
    let a = seal(&mut sealer, wire::Kind::Data, 500, b"later")?;
    let b = seal(&mut sealer, wire::Kind::Data, 0, b"older")?;
    state.ingest_phase(&outer(&a, 2500, 1000, 32768)?)?;
    state.ingest_phase(&outer(&b, 2000, 1000, 32768)?)?;
    assert_eq!(state.opener.as_ref().ok_or("opener")?.usage().packets, 2);
    assert_eq!(state.ranges.occupied_bytes(), (a.len() + b.len()) as u64);
    Ok(())
}
#[test]
fn authenticated_sparse_packets_do_not_exhaust_a_disjoint_range_count() -> R {
    let (mut state, mut sealer) = fixture()?;
    let capacity = state.range_capacity_bytes();
    let mut offset = 0u64;
    let mut accepted_bytes = 0u64;
    for i in 0u16..180 {
        let body = i.to_be_bytes();
        let protected = seal(&mut sealer, wire::Kind::Data, offset, &body)?;
        state.ingest_phase(&outer(&protected, 2000 + offset as u32, 1000, 32768)?)?;
        assert_eq!(state.incoming.pop_front().ok_or("cell")?.body, body);
        state.records_outstanding = 0;
        accepted_bytes += protected.len() as u64;
        offset += protected.len() as u64 + 1;
    }
    assert!(offset < 32768);
    assert_eq!(state.opener.as_ref().ok_or("opener")?.usage().packets, 180);
    assert_eq!(state.rejected_packets, 0);
    assert_eq!(state.ranges.occupied_bytes(), accepted_bytes);
    assert_eq!(state.range_capacity_bytes(), capacity);
    Ok(())
}
#[test]
fn full_delivery_slot_does_not_burn_a_valid_nonce() -> R {
    let (mut state, mut sealer) = fixture()?;
    state.policy.queue_packets = 1;
    let a = seal(&mut sealer, wire::Kind::Data, 0, b"one")?;
    state.ingest_phase(&outer(&a, 2000, 1000, 32768)?)?;
    let b = seal(&mut sealer, wire::Kind::Data, a.len() as u64, b"two")?;
    let b = outer(&b, 2000 + a.len() as u32, 1000, 32768)?;
    state.ingest_phase(&b)?;
    assert_eq!(state.opener.as_ref().ok_or("opener")?.usage().packets, 1);
    assert_eq!(state.ranges.occupied_bytes(), a.len() as u64);
    assert_eq!(state.fence.as_ref().ok_or("fence")?.retired, a.len() as u64);
    state.incoming.pop_front();
    state.records_outstanding = 0;
    state.ingest_phase(&b)?;
    assert_eq!(state.opener.as_ref().ok_or("opener")?.usage().packets, 2);
    Ok(())
}
fn hello() -> wire::Hello {
    wire::Hello {
        count: 1,
        pair: [7; 32],
        armed: [8; 32],
        lanes: [
            Some(wire::LaneProof {
                lane: 0,
                bulk: 0,
                role: 2,
                options: 0,
                session: [1; 16],
                written: 400,
                read: 500,
                una: 2000,
                next: 2000,
                receive: 1000,
                ack: 1000,
                window: 32768,
                scale: 0,
                peer_scale: 0,
                peer_window: 32768,
                mss: 536,
                available: u32::MAX - 2000,
                counters: [4; 32],
            }),
            None,
        ],
    }
}
#[test]
fn early_hello_uses_same_opener_range_table_and_one_coalesced_cell() -> R {
    let (mut state, mut sealer) = fixture()?;
    state.fence = None;
    state.active = false;
    state.hello_allowed = true;
    state.expected_pair = [7; 32];
    state.expected_armed = [8; 32];
    let body = hello().encode()?;
    let a = seal(&mut sealer, wire::Kind::Hello, 0, &body)?;
    state.ingest_phase(&outer(&a, 2000, 1000, 32768)?)?;
    assert!(state.early.is_some());
    assert_eq!(state.opener.as_ref().ok_or("opener")?.usage().packets, 1);
    let overlap = seal(&mut sealer, wire::Kind::Hello, 0, &body)?;
    state.ingest_phase(&outer(&overlap, 2000, 1000, 32768)?)?;
    assert_eq!(state.opener.as_ref().ok_or("opener")?.usage().packets, 1);
    let b = seal(&mut sealer, wire::Kind::Hello, a.len() as u64, &body)?;
    state.ingest_phase(&outer(&b, 2000 + a.len() as u32, 1000, 32768)?)?;
    assert_eq!(state.opener.as_ref().ok_or("opener")?.usage().packets, 2);
    assert_eq!(state.ranges.occupied_bytes(), (a.len() + b.len()) as u64);
    state.fence = fixture()?.0.fence;
    state.release_early()?;
    assert!(state.early.is_none());
    assert_eq!(state.incoming.len(), 1);
    assert_eq!(
        state.fence.as_ref().ok_or("fence")?.retired,
        (a.len() + b.len()) as u64
    );
    Ok(())
}
#[test]
fn early_hello_reordering_preserves_the_highest_end_and_missing_extents() -> R {
    let (mut state, mut sealer) = fixture()?;
    state.fence = None;
    state.active = false;
    state.hello_allowed = true;
    state.expected_pair = [7; 32];
    state.expected_armed = [8; 32];
    let body = hello().encode()?;
    let later = seal(&mut sealer, wire::Kind::Hello, 512, &body)?;
    state.ingest_phase(&outer(&later, 2512, 1000, 32768)?)?;
    let earlier = seal(&mut sealer, wire::Kind::Hello, 0, &body)?;
    state.ingest_phase(&outer(&earlier, 2000, 1000, 32768)?)?;
    assert_eq!(state.opener.as_ref().ok_or("opener")?.usage().packets, 2);
    assert_eq!(
        state.ranges.occupied_bytes(),
        (earlier.len() + later.len()) as u64
    );
    let duplicate = seal(&mut sealer, wire::Kind::Hello, 0, &body)?;
    state.ingest_phase(&outer(&duplicate, 2000, 1000, 32768)?)?;
    assert_eq!(state.opener.as_ref().ok_or("opener")?.usage().packets, 2);
    state.fence = fixture()?.0.fence;
    state.release_early()?;
    assert_eq!(state.incoming.len(), 1);
    assert_eq!(
        state.fence.as_ref().ok_or("fence")?.retired,
        512 + later.len() as u64
    );
    Ok(())
}
#[test]
fn compact_preflight_does_not_advance_ranges_until_explicit_commit() -> R {
    let (mut state, _) = fixture()?;
    state.final_context = Some([7; 32]);
    let body = [2, 1, 2, 3, 4];
    state.ingest_final(&outer(&body, 22000, 1000, 32768)?)?;
    assert_eq!(state.ranges.occupied_bytes(), 0);
    assert_eq!(state.fence.as_ref().ok_or("fence")?.retired, 0);
    state.incoming.pop_front().ok_or("candidate")?;
    for index in 0..180u32 {
        state.ingest_final(&outer(&body, 2000 + index * 6, 1000, 32768)?)?;
        let metadata = state
            .incoming
            .pop_front()
            .ok_or("candidate")?
            .final_metadata
            .ok_or("metadata")?;
        assert_eq!(state.ranges.occupied_bytes(), u64::from(index) * 5);
        state.commit_final(metadata)?;
        assert!(matches!(state.validate_final(metadata), Err(Error::Proof)));
    }
    assert_eq!(state.ranges.occupied_bytes(), 900);
    assert_eq!(state.fence.as_ref().ok_or("fence")?.retired, 1079);
    assert_eq!(state.rejected_packets, 0);
    Ok(())
}
#[test]
fn authenticated_hello_before_armed_is_terminal_without_usage_commit() -> R {
    let (mut state, mut sealer) = fixture()?;
    state.fence = None;
    state.expected_pair = [7; 32];
    state.expected_armed = [8; 32];
    let protected = seal(&mut sealer, wire::Kind::Hello, 0, &hello().encode()?)?;
    assert!(matches!(
        state.ingest_phase(&outer(&protected, 2000, 1000, 32768)?),
        Err(Error::Proof)
    ));
    assert_eq!(state.opener.as_ref().ok_or("opener")?.usage().packets, 0);
    assert!(state.fault.is_some());
    Ok(())
}
#[test]
fn old_prefix_responder_accepts_wrapped_consumed_bytes_but_never_crossings_or_ack_only() -> R {
    let (mut state, _) = fixture()?;
    state.fence.as_mut().ok_or("fence")?.peer = 5;
    state.fence.as_mut().ok_or("fence")?.receive_prefix = 10;
    let duplicate = outer(b"old", u32::MAX - 2, 1000, 32768)?;
    state.old(&duplicate, Instant::now())?;
    let reply = state.old_reply.take().ok_or("old reply")?;
    let inspected = packet::inspect(raw(false, 0), &reply)?;
    assert_eq!(
        (
            inspected.sequence,
            inspected.acknowledgment,
            inspected.window
        ),
        (1000, 5, 32768)
    );
    assert!(inspected.payload.is_empty());
    for bytes in [
        outer(b"crossing", 2, 1000, 32768)?,
        outer(b"too old", u32::MAX - 20, 1000, 32768)?,
        outer(b"", 3, 1000, 32768)?,
    ] {
        state.old(&bytes, Instant::now())?;
        assert!(state.old_reply.is_none());
    }
    state.old(&duplicate, state.deadline)?;
    assert!(state.old_reply.is_none());
    Ok(())
}
#[test]
fn budget_has_one_shared_turn_and_finite_held_allowance() {
    let now = Instant::now();
    let mut p = PacketPolicy::new(576);
    p.burst_bytes = 576;
    p.burst_packets = 1;
    let mut b = Budget::new(p, now);
    assert!(b.take(31));
    assert!(!b.take(2));
    assert!(b.take(1));
    assert!(!b.take(1));
    assert!(b.reserve(576, now));
    assert!(!b.reserve(40, now));
    assert!(b.reserve(40, now + Duration::from_secs(1)));
}

#[test]
fn upper_feedback_has_bounded_headroom_without_spending_internal_control_reserve() -> R {
    let (mut state, mut sealer) = fixture()?;
    let data_end = 32768 - 8 * 536;
    let offset = data_end - 10;
    let data = seal(&mut sealer, wire::Kind::Data, offset, b"bulk")?;
    state.ingest_phase(&outer(&data, 2000 + offset as u32, 1000, 32768)?)?;
    assert_eq!(state.opener.as_ref().ok_or("opener")?.usage().packets, 0);
    let feedback = seal(&mut sealer, wire::Kind::Feedback, offset, b"feedback")?;
    state.ingest_phase(&outer(&feedback, 2000 + offset as u32, 1000, 32768)?)?;
    assert_eq!(state.opener.as_ref().ok_or("opener")?.usage().packets, 1);
    // Four maximum cells remain exclusively available to internal controls.
    let offset = 32768 - 4 * 536;
    let too_far = seal(&mut sealer, wire::Kind::Feedback, offset, b"feedback")?;
    // retirement advances on accepted feedback, so freeze its prior value here
    // to exercise the exact initial-edge admission kernel rather than a new edge.
    state.fence.as_mut().ok_or("fence")?.retired = 0;
    state.ingest_phase(&outer(&too_far, 2000 + offset as u32, 1000, 32768)?)?;
    assert_eq!(state.opener.as_ref().ok_or("opener")?.usage().packets, 1);
    let ping = seal(&mut sealer, wire::Kind::Ping, offset, &[1; 8])?;
    state.ingest_phase(&outer(&ping, 2000 + offset as u32, 1000, 32768)?)?;
    assert_eq!(state.opener.as_ref().ok_or("opener")?.usage().packets, 2);
    Ok(())
}

#[test]
fn early_hello_proof_diagnostic_retains_exact_window_refusal_without_adoption() -> R {
    let (mut state, mut sealer) = fixture()?;
    state.fence = None;
    state.active = false;
    state.hello_allowed = true;
    state.expected_pair = [7; 32];
    state.expected_armed = [8; 32];
    let body = hello().encode()?;
    let protected = seal(&mut sealer, wire::Kind::Hello, 0, &body)?;
    state.ingest_phase(&outer(&protected, 2000, 1000, 32768)?)?;
    assert!(state.early.is_some());
    state.fence = fixture()?.0.fence;
    state.fence.as_mut().ok_or("fence")?.peer_horizon = 32763;
    let before = state.fence.as_ref().ok_or("fence")?.retired;
    assert!(matches!(state.release_early(), Err(Error::Proof)));
    let Some(SetupProofFailure::EarlyHelloRelease(value)) = state.proof_failure else {
        return Err("missing early release proof diagnostic".into());
    };
    assert!(value.sequence_matches && value.acknowledgment_matches);
    assert!(value.within_local_horizon && value.within_sequence_space);
    assert!(!value.window_matches && !value.right_edge_matches);
    assert_eq!(
        (value.expected_window, value.observed_window),
        (32763, 32768)
    );
    assert_eq!(
        (value.expected_right_edge, value.observed_right_edge),
        (32763, 32768)
    );
    assert_eq!(value.end, protected.len() as u64);
    assert_eq!(state.fence.as_ref().ok_or("fence")?.retired, before);
    assert_eq!(state.fence.as_ref().ok_or("fence")?.peer_horizon, 32763);
    assert!(state.incoming.is_empty());
    assert!(
        state.fault.is_none(),
        "diagnostic must not invent a gate fault"
    );
    // The original release consumed the early cell on failure. Observing that
    // absence does not replace the first retained failure with a success.
    state.release_early()?;
    assert_eq!(
        state.proof_failure,
        Some(SetupProofFailure::EarlyHelloRelease(value))
    );
    Ok(())
}

#[test]
fn complementary_diagnostic_keeps_identity_sequence_and_scale_refusals_separate() -> R {
    let peer = hello().lanes[0].ok_or("peer")?;
    let mut local = peer;
    local.role = 1;
    local.written = peer.read;
    local.read = peer.written;
    local.una = peer.receive;
    local.next = peer.receive;
    local.receive = peer.next;
    local.ack = peer.next;
    local.available = u32::MAX - local.next;
    local.complementary(peer)?;
    for variant in 0..4 {
        let mut other = peer;
        match variant {
            0 => other.session[0] ^= 1,
            1 => other.receive += 1,
            2 => other.peer_scale = 1,
            _ => other.peer_window -= 1,
        }
        assert!(matches!(local.complementary(other), Err(Error::Proof)));
        let SetupProofFailure::Hello(value) =
            SetupProofFailure::hello(SetupProofBoundary::PeerHello, local, other)
        else {
            return Err("wrong proof diagnostic".into());
        };
        assert_eq!(value.identity_matches, variant != 0);
        assert_eq!(value.sequence_matches, variant != 1);
        assert_eq!(value.scales_match, variant != 2);
        assert_eq!(value.peer_peer_window_matches, variant != 3);
        assert!(value.stream_bytes_match && value.options_match && value.local_peer_window_matches);
    }
    Ok(())
}
