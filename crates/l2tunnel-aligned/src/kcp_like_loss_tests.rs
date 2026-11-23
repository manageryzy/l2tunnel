//! Generated native access uses exact Ethernet/IPv4/TCP fixtures and physical Compact output.
use super::*;
use std::collections::VecDeque;

struct Link {
    pending: VecDeque<(u64, Vec<u8>)>,
    state: u32,
    dropped: usize,
}

impl Link {
    fn new(seed: u32) -> Self {
        Self {
            pending: VecDeque::new(),
            state: seed,
            dropped: 0,
        }
    }

    fn send(&mut self, endpoint: &mut Body, tick: u64, feedback: bool) -> TestResult {
        let now = Duration::from_millis(tick);
        let mut output = vec![0; endpoint.maximum()];
        let mut budget = OutboundBudget {
            packets: 4,
            wire_bytes: 4 * (output.len() + 100),
        };
        while let Some(length) = endpoint.poll(now, feedback, &mut output, &mut budget)? {
            endpoint.confirm(
                now,
                endpoint.token(feedback).ok_or("missing physical token")?,
            )?;
            self.state ^= self.state << 13;
            self.state ^= self.state >> 17;
            self.state ^= self.state << 5;
            if self.state % 100 < 15 {
                self.dropped += 1;
            } else {
                self.pending
                    .push_back((tick + 35, output[..length].to_vec()));
            }
        }
        Ok(())
    }

    fn arrive(&mut self, endpoint: &mut Body, tick: u64) -> TestResult {
        while self.pending.front().is_some_and(|packet| packet.0 <= tick) {
            let (_, packet) = self.pending.pop_front().ok_or("missing physical packet")?;
            endpoint.receive(Duration::from_millis(tick), &packet)?;
        }
        Ok(())
    }
}

#[test]
fn variable_tcp_frames_survive_two_lossy_lanes_without_ordering_complete_native_packets()
-> TestResult {
    let fixtures = include_str!("../../l2tunnel-codec/tests/data/aligned-sender-goldens.tsv")
        .lines()
        .filter(|r| {
            ["symbol128\t0\t", "symbol128\t2\t", "symbol128\t6\t"]
                .iter()
                .any(|prefix| r.starts_with(prefix))
        })
        .map(|r| {
            let hex = r.split('\t').nth(6).ok_or("native fixture missing")?;
            (0..hex.len())
                .step_by(2)
                .map(|i| Ok(u8::from_str_radix(&hex[i..i + 2], 16)?))
                .collect::<TestResult<Vec<_>>>()
        })
        .collect::<TestResult<Vec<_>>>()?;
    assert_eq!(
        fixtures.iter().map(Vec::len).collect::<Vec<_>>(),
        [130, 66, 566]
    );
    let frames = (0..128u8)
        .map(|id| {
            let mut frame = fixtures[usize::from(id) % fixtures.len()].clone();
            frame[5] = id; // Distinct Ethernet destination, preserving both original IP and TCP checksums.
            frame
        })
        .collect::<Vec<_>>();
    for native in stateless_profiles() {
        let config = selected(native, true)?;
        let mut a = Body::construct(config, config, EndpointRole::Initiator, true, usize::MAX)
            .map_err(|e| format!("{native:?} initiator: {e:?}"))?;
        let mut b = Body::construct(config, config, EndpointRole::Responder, true, usize::MAX)
            .map_err(|e| format!("{native:?} responder: {e:?}"))?;
        body!(&mut a, enable_compact_wire(49))?;
        body!(&mut b, enable_compact_wire(49))?;
        let mut data = Link::new(31248);
        let mut ack = Link::new(31999);
        let mut admitted = 0;
        let mut delivered = [false; 128];
        let mut out_of_order = false;
        for tick in 0..20_000 {
            let now = Duration::from_millis(tick);
            ack.arrive(&mut a, tick)?;
            data.arrive(&mut b, tick).map_err(|e| {
                format!("{native:?}: receiving at {tick} ms after {admitted} admissions: {e:?}")
            })?;
            if admitted < frames.len() {
                match body!(
                    &mut a,
                    enqueue_admitted(ChannelId((admitted % 2) as u8), &frames[admitted], now)
                ) {
                    Ok(()) => admitted += 1,
                    Err(Error::Busy) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            data.send(&mut a, tick, false)
                .map_err(|e| format!("{native:?} DATA at {tick}: {e}"))?;
            ack.send(&mut b, tick, true)
                .map_err(|e| format!("{native:?} ACK at {tick}: {e}"))?;
            for channel in 0..2 {
                for _ in 0..8 {
                    match body!(&mut b, prepare(ChannelId(channel), now, 8))? {
                        Prepared::Idle => break,
                        Prepared::Progress => {}
                        Prepared::Ready => {
                            let packet = body!(&b, pending()).ok_or("native output missing")?;
                            let id = usize::from(packet.bytes[5]);
                            assert_eq!(packet.bytes, frames[id]);
                            assert_eq!(packet.channel, ChannelId((id % 2) as u8));
                            assert!(!delivered[id]);
                            out_of_order |= packet.early;
                            delivered[id] = true;
                            body!(&mut b, commit_delivery(now))?;
                        }
                    }
                }
            }
            if tick % 10 == 0 && delivered.iter().all(|&v| v) && a.drained() && b.drained() {
                break;
            }
        }
        assert!(
            delivered.iter().all(|&v| v),
            "{native:?}, admitted={admitted}, B={:?}",
            b.status()
        );
        assert!(a.drained() && b.drained());
        assert!(
            out_of_order && data.dropped > 0 && ack.dropped > 0 && a.statistics().retry_packets > 0
        );
    }
    Ok(())
}
