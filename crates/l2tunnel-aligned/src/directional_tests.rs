use super::*;
use l2tunnel_codec::aligned_receiver::RecordId;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}
fn context(role: EndpointRole) -> RecoveryContext {
    tests::context(role)
}

fn policies() -> (Config, Config) {
    let mut a = tests::config(128);
    let mut b = tests::config(256);
    a.receiver.channels = 1;
    a.receiver.first_record = RecordId(7);
    a.recovery.outer_overhead_bytes = 17;
    b.receiver.channels = 3;
    b.receiver.first_record = RecordId(19);
    b.native_policy = NativePolicy::RawIp;
    b.receiver.body.elide_payload_length = false;
    b.receiver.body.predictive = false;
    b.receiver.body.timestamp_pair_dictionary = false;
    b.recovery.arq.ack_delay = ms(7);
    b.recovery.arq.initial_rto = ms(150);
    b.recovery.fec.block.max_sources = 2;
    b.recovery.fec.block.max_packet_bytes -= 1;
    b.max_recovery_packet_bytes -= 1;
    b.recovery.flush_after = ms(9);
    b.recovery.outer_overhead_bytes = 73;
    (a, b)
}
fn packed_policy(base: Config, units: u8, hold: u64, work: usize) -> TestResult<packed::Config> {
    let mut config = packed::Config {
        base,
        hold_micros: hold,
        max_units: units,
        work_limit: work,
    };
    let original = config.envelope().max_source_bytes()?;
    let base = &mut config.base;
    base.recovery.arq.max_source_bytes = original;
    base.recovery.arq.send_bytes = 8 * original;
    base.recovery.arq.receive_bytes = 8 * original;
    base.recovery.fec.block.max_source_bytes = 44 + original;
    base.recovery.fec.block.max_packet_bytes =
        56 + base.recovery.fec.block.max_sources + 2 + 44 + original;
    base.recovery.max_restored_bytes = 16 * (44 + original);
    base.max_recovery_packet_bytes = 8 + base.recovery.fec.block.max_packet_bytes;
    base.receiver.lookahead_records = usize::from(units);
    base.receiver.lookahead_bytes = usize::from(units) * 65535;
    base.receiver.lookahead_fragments = usize::from(units) * base.receiver.max_fragments_per_record;
    config.validate()?;
    Ok(config)
}

// These test operations use each public endpoint directly, never a runtime actor.
trait Probe {
    fn enqueue(&mut self, channel: ChannelId, bytes: &[u8]) -> Result<RecordIdentity, Error>;
    fn data(
        &mut self,
        now: Duration,
        output: &mut [u8],
        budget: &mut OutboundBudget,
    ) -> Result<Option<usize>, Error>;
    fn feedback(
        &mut self,
        now: Duration,
        output: &mut [u8],
        budget: &mut OutboundBudget,
    ) -> Result<Option<usize>, Error>;
    fn receive(&mut self, bytes: &[u8], now: Duration) -> Result<(), Error>;
    fn units(&mut self, bytes: &[u8], output: &mut [UnitWitness]) -> Result<usize, Error>;
    fn take(
        &mut self,
        channels: u16,
        now: Duration,
    ) -> Result<Vec<(RecordIdentity, Vec<u8>)>, Error>;
    fn send_max(&self) -> usize;
    fn receive_max(&self) -> usize;
    fn drained(&self) -> bool;
}
macro_rules! probe {
    ($endpoint:ty) => {
        impl Probe for $endpoint {
            fn enqueue(
                &mut self,
                channel: ChannelId,
                bytes: &[u8],
            ) -> Result<RecordIdentity, Error> {
                self.enqueue_identified(channel, bytes, Duration::ZERO)
            }
            fn data(
                &mut self,
                now: Duration,
                output: &mut [u8],
                budget: &mut OutboundBudget,
            ) -> Result<Option<usize>, Error> {
                self.poll_data(now, output, budget)
            }
            fn feedback(
                &mut self,
                now: Duration,
                output: &mut [u8],
                budget: &mut OutboundBudget,
            ) -> Result<Option<usize>, Error> {
                self.poll_feedback(now, output, budget)
            }
            fn receive(&mut self, bytes: &[u8], now: Duration) -> Result<(), Error> {
                self.receive_authenticated(bytes, now)
            }
            fn units(&mut self, bytes: &[u8], output: &mut [UnitWitness]) -> Result<usize, Error> {
                self.outgoing_units(bytes, output)
            }
            fn take(
                &mut self,
                channels: u16,
                now: Duration,
            ) -> Result<Vec<(RecordIdentity, Vec<u8>)>, Error> {
                let mut result = Vec::new();
                for _ in 0..32 {
                    let mut progress = false;
                    for channel in 0..channels {
                        let channel =
                            ChannelId(u8::try_from(channel).map_err(|_| Error::Configuration)?);
                        match self.prepare(channel, now, 8)? {
                            Prepared::Ready => {
                                let frame = self.pending().ok_or(Error::Identity)?;
                                let item = (
                                    RecordIdentity {
                                        channel: frame.channel,
                                        record: frame.record,
                                    },
                                    frame.bytes.to_vec(),
                                );
                                // Native custody remains immutable until the actual commit boundary.
                                assert_eq!(self.pending().ok_or(Error::Identity)?.bytes, item.1);
                                result.push(item);
                                self.commit_delivery(now)?;
                                progress = true;
                            }
                            Prepared::Progress => progress = true,
                            Prepared::Idle => {}
                        }
                    }
                    if !progress {
                        break;
                    }
                }
                Ok(result)
            }
            fn send_max(&self) -> usize {
                self.send_max_packet_bytes()
            }
            fn receive_max(&self) -> usize {
                self.receive_max_packet_bytes()
            }
            fn drained(&self) -> bool {
                self.drained()
            }
        }
    };
}
probe!(Endpoint);
probe!(packed::Endpoint);

fn collect<P: Probe>(
    endpoint: &mut P,
    now: Duration,
    witnesses: &mut Vec<UnitWitness>,
) -> Result<Vec<Vec<u8>>, Error> {
    let mut result = Vec::new();
    let mut budget = OutboundBudget {
        packets: 32,
        wire_bytes: 1_000_000,
    };
    for _ in 0..32 {
        let mut bytes = vec![0; endpoint.send_max()];
        if let Some(n) = endpoint.data(now, &mut bytes, &mut budget)? {
            bytes.truncate(n);
            let mut units = [UnitWitness {
                identity: RecordIdentity {
                    channel: ChannelId(0),
                    record: RecordId(0),
                },
                index: 0,
                count: 1,
            }; 4];
            let n = endpoint.units(&bytes, &mut units)?;
            witnesses.extend_from_slice(&units[..n]);
            result.push(bytes);
        }
    }
    Ok(result)
}

fn exercise<P: Probe>(mut left: P, mut right: P) -> TestResult {
    assert_eq!(left.send_max(), right.receive_max());
    assert_eq!(left.receive_max(), right.send_max());
    assert_ne!(left.send_max(), left.receive_max());
    let forward = [tests::native_frames()?.remove(0), vec![0x5a; 400]];
    let reverse = [vec![0, 255, 1, 0], (0_u8..=255).cycle().take(500).collect()];
    let mut expected_forward = Vec::new();
    let mut expected_reverse = Vec::new();
    let mut packets_a = Vec::new();
    let mut packets_b = Vec::new();
    let mut units_a = Vec::new();
    let mut units_b = Vec::new();
    for bytes in forward {
        let identity = left.enqueue(ChannelId(0), &bytes)?;
        expected_forward.push((identity, bytes));
        packets_a.extend(collect(&mut left, ms(0), &mut units_a)?);
    }
    for bytes in reverse {
        let identity = right.enqueue(ChannelId(2), &bytes)?;
        expected_reverse.push((identity, bytes));
        packets_b.extend(collect(&mut right, ms(0), &mut units_b)?);
    }
    // Service original packing and partial-FEC deadlines; no source RTO has elapsed.
    for now in [1, 5, 10, 15] {
        packets_a.extend(collect(&mut left, ms(now), &mut units_a)?);
        packets_b.extend(collect(&mut right, ms(now), &mut units_b)?);
    }
    assert!(packets_a.len() > 2 && packets_b.len() > 2);
    assert!(
        expected_forward[0].0.record.0 > 7,
        "context records retain their own IDs"
    );
    assert_eq!(expected_reverse[0].0.record, RecordId(19));
    for (expected, units) in [(&expected_forward, &units_a), (&expected_reverse, &units_b)] {
        for (identity, _) in expected {
            let witnesses: Vec<_> = units
                .iter()
                .filter(|unit| unit.identity == *identity)
                .collect();
            let count = witnesses.first().ok_or("native witness")?.count;
            let indices: std::collections::BTreeSet<_> =
                witnesses.iter().map(|unit| unit.index).collect();
            assert!(witnesses.iter().all(|unit| unit.count == count));
            assert_eq!(indices, (0..count).collect());
        }
    }
    // Lose each first systematic and reorder the remaining received equations.
    for bytes in packets_a.iter().skip(1).rev() {
        right.receive(bytes, ms(20))?;
    }
    for bytes in packets_b.iter().skip(1).rev() {
        left.receive(bytes, ms(20))?;
    }
    assert_eq!(right.take(1, ms(20))?, expected_forward);
    assert_eq!(left.take(3, ms(20))?, expected_reverse);
    transfer_feedback(&mut left, &mut right)?;
    transfer_feedback(&mut right, &mut left)?;
    assert!(left.drained() && right.drained());
    Ok(())
}

fn transfer_feedback<P: Probe>(sender: &mut P, peer: &mut P) -> TestResult {
    let mut bytes = vec![0; sender.send_max()];
    let mut budget = OutboundBudget {
        packets: 1,
        wire_bytes: 1_000_000,
    };
    let n = sender
        .feedback(ms(30), &mut bytes, &mut budget)?
        .ok_or("receipt")?;
    peer.receive(&bytes[..n], ms(30))?;
    Ok(())
}

#[test]
fn asymmetric_aligned_peers_preserve_real_native_ids_fragments_and_loss_recovery() -> TestResult {
    let (a, b) = policies();
    exercise(
        Endpoint::new_duplex(a, b, context(EndpointRole::Initiator))?,
        Endpoint::new_duplex(b, a, context(EndpointRole::Responder))?,
    )
}

#[test]
fn asymmetric_packed_peers_use_distinct_hold_work_units_and_receive_scratch() -> TestResult {
    let (a, b) = policies();
    let a = packed_policy(a, 2, 200, 1)?;
    let b = packed_policy(b, 4, 900, 3)?;
    let left = packed::Endpoint::new_duplex(a, b, context(EndpointRole::Initiator))?;
    let right = packed::Endpoint::new_duplex(b, a, context(EndpointRole::Responder))?;
    exercise(left, right)
}

#[test]
fn full_configuration_validation_precedes_context_and_keeps_receive_limits() -> TestResult {
    let (good, mut bad) = policies();
    bad.receiver.channels = 0;
    let mut invalid_context = context(EndpointRole::Initiator);
    invalid_context.session = 0;
    assert!(matches!(
        Endpoint::new_duplex(good, bad, invalid_context),
        Err(Error::Receiver(receiver::Error::Configuration))
    ));
    assert!(matches!(
        Endpoint::new_duplex(bad, good, invalid_context),
        Err(Error::Receiver(receiver::Error::Configuration))
    ));
    let (good, mut bad) = policies();
    bad.recovery.arq.max_source_bytes = 1;
    assert!(matches!(
        Endpoint::new_duplex(good, bad, context(EndpointRole::Initiator)),
        Err(Error::Configuration)
    ));
    let mut local = Endpoint::new_duplex(good, policies().1, context(EndpointRole::Initiator))?;
    assert!(matches!(
        local.enqueue_identified(ChannelId(1), &[1, 2], ms(0)),
        Err(Error::Sender(_))
    ));
    assert_eq!(local.arq_statistics().submitted, 0);
    Ok(())
}

fn compare_equal<P: Probe>(mut legacy: P, mut duplex: P) -> TestResult {
    let bytes = vec![0x87; 400];
    assert_eq!(
        legacy.enqueue(ChannelId(0), &bytes)?,
        duplex.enqueue(ChannelId(0), &bytes)?
    );
    for now in [0, 1, 5, 10, 100, 300] {
        let mut units_a = Vec::new();
        let mut units_b = Vec::new();
        assert_eq!(
            collect(&mut legacy, ms(now), &mut units_a)?,
            collect(&mut duplex, ms(now), &mut units_b)?
        );
        assert_eq!(units_a, units_b);
        assert_eq!(legacy.drained(), duplex.drained());
    }
    Ok(())
}

#[test]
fn equal_direction_aligned_and_packed_keep_legacy_output_and_original_witnesses() -> TestResult {
    let (config, _) = policies();
    let binding = context(EndpointRole::Initiator);
    compare_equal(
        Endpoint::new(config, binding)?,
        Endpoint::new_duplex(config, config, binding)?,
    )?;
    let config = packed_policy(config, 2, 500, 1)?;
    compare_equal(
        packed::Endpoint::new(config, binding)?,
        packed::Endpoint::new_duplex(config, config, binding)?,
    )
}
