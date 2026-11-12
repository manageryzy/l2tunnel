use super::*;
use std::net::{Ipv4Addr, SocketAddrV4};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn tcp(reverse: bool, seed: u64) -> TcpConfig {
    let a = SocketAddrV4::new(Ipv4Addr::new(10, 77, 0, 1), 20000);
    let b = SocketAddrV4::new(Ipv4Addr::new(10, 77, 0, 2), 20001);
    TcpConfig {
        local: if reverse { b } else { a },
        peer: if reverse { a } else { b },
        mtu: 576,
        send_bytes: 4096,
        receive_bytes: 4096,
        packet_slots: 16,
        random_seed: seed,
        ack_delay_millis: 10,
        keepalive_millis: 1000,
        idle_timeout_millis: 120_000,
    }
}
fn tcp_ip(reverse: bool, seed: u64, ipv6: bool) -> TcpIpConfig {
    let mut value = TcpIpConfig::from(tcp(reverse, seed));
    if ipv6 {
        let a = std::net::SocketAddr::from(([0xfd42, 0x77, 0, 0, 0, 0, 0, 1], 20000));
        let b = std::net::SocketAddr::from(([0xfd42, 0x77, 0, 0, 0, 0, 0, 2], 20001));
        value.local = if reverse { b } else { a };
        value.peer = if reverse { a } else { b };
        value.mtu = 1280;
    }
    value
}
fn config() -> Config {
    Config {
        scope: Scope {
            session: [7; 16],
            epoch: 1,
            flow: 1,
        },
        max_record_bytes: 512,
        maximum: Window {
            bytes: 1024,
            records: 4,
        },
        initial: Window {
            bytes: 512,
            records: 2,
        },
    }
}

struct NetworkPacket {
    due: u64,
    side: usize,
    to_app: bool,
    bytes: Vec<u8>,
}
struct Lab {
    ipv6: bool,
    apps: [TcpEngine; 2],
    legs: [Leg; 2],
    packets: Vec<NetworkPacket>,
    now: u64,
    count: usize,
    drops: usize,
    duplicates: usize,
    zero_window: [bool; 2],
    reopened: [bool; 2],
}
impl Lab {
    fn new() -> Result<Self, Error> {
        Self::new_family(false)
    }
    fn new_family(ipv6: bool) -> Result<Self, Error> {
        let native = |reverse, seed| tcp_ip(reverse, seed, ipv6);
        Ok(Self {
            ipv6,
            apps: [
                TcpEngine::new_ip(native(false, 11), Role::Client, Millis(0))?,
                TcpEngine::new_ip(native(true, 29), Role::Server, Millis(0))?,
            ],
            legs: [
                Leg::new_ip(config(), native(true, 17), Role::Server, Millis(0))?,
                Leg::new_ip(config(), native(false, 23), Role::Client, Millis(0))?,
            ],
            packets: Vec::new(),
            now: 0,
            count: 0,
            drops: 0,
            duplicates: 0,
            zero_window: [false; 2],
            reopened: [false; 2],
        })
    }
    fn step(&mut self, impaired: bool, blocked_tunnel: bool) -> TestResult {
        self.now += 1;
        for packet in self.packets.extract_if(.., |p| p.due <= self.now) {
            if packet.to_app {
                self.apps[packet.side].ingest(&packet.bytes)?;
            } else {
                self.legs[packet.side].ingest_packet(&packet.bytes)?;
            }
        }
        for app in &mut self.apps {
            app.poll(Millis(self.now), 8)?;
        }
        for leg in &mut self.legs {
            leg.poll(Millis(self.now), 8)?;
        }
        for side in 0..2 {
            if !blocked_tunnel
                && let Some(record) = self.legs[side].pending_record().map(<[u8]>::to_vec)
            {
                self.legs[1 - side].receive_authenticated(&record)?;
                self.legs[side].confirm_record_sent()?;
            }
            for to_app in [false, true] {
                loop {
                    let packet = if to_app {
                        self.legs[side].pop_packet()
                    } else {
                        self.apps[side].pop_packet()
                    };
                    let Some(bytes) = packet else {
                        break;
                    };
                    assert!(bytes.len() <= if self.ipv6 { 1280 } else { 576 });
                    assert_eq!(bytes[0] >> 4, if self.ipv6 { 6 } else { 4 });
                    if to_app {
                        let offset = if self.ipv6 { 54 } else { 34 };
                        let window = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
                        if window == 0 {
                            self.zero_window[side] = true;
                        } else if self.zero_window[side] {
                            self.reopened[side] = true;
                        }
                    }
                    self.count += 1;
                    if impaired && self.count.is_multiple_of(17) {
                        self.drops += 1;
                        continue;
                    }
                    if impaired && self.count.is_multiple_of(23) {
                        self.duplicates += 1;
                        self.packets.push(NetworkPacket {
                            due: self.now + 3,
                            side,
                            to_app,
                            bytes: bytes.clone(),
                        });
                    }
                    let delay = if impaired && self.count.is_multiple_of(7) {
                        19
                    } else {
                        1
                    };
                    self.packets.push(NetworkPacket {
                        due: self.now + delay,
                        side,
                        to_app,
                        bytes,
                    });
                }
            }
            let state = self.legs[side].status();
            assert!(state.received.bytes - state.acknowledged.bytes <= config().maximum.bytes);
            assert!(
                state.received.records - state.acknowledged.records <= config().maximum.records
            );
            assert!(state.retained_records <= config().maximum.records as usize);
            assert!(state.pending_record_bytes <= HEADER + config().max_record_bytes);
            let queued_payload: usize = self.legs[side]
                .incoming
                .iter()
                .map(|entry| entry.bytes.len())
                .sum();
            assert_eq!(
                queued_payload as u64 + state.native.send_bytes as u64,
                state.received.bytes - state.acknowledged.bytes
            );
        }
        assert!(self.packets.len() <= 256);
        Ok(())
    }
    fn connect(&mut self) -> TestResult {
        for _ in 0..2000 {
            self.step(false, false)?;
            if self.apps.iter().all(|app| app.status().established)
                && self
                    .legs
                    .iter()
                    .all(|leg| leg.status().peer_granted.bytes > 0)
            {
                return Ok(());
            }
        }
        Err("four TCP owners did not establish".into())
    }
}

mod admission;
fn drain(app: &mut TcpEngine, output: &mut Vec<u8>) -> Result<bool, l2tunnel_raw_tcp::Error> {
    let mut bytes = [0; 777];
    loop {
        match app.read(&mut bytes)? {
            ReadOutcome::Data(count) => output.extend_from_slice(&bytes[..count]),
            ReadOutcome::Pending => return Ok(false),
            ReadOutcome::Eof => return Ok(true),
        }
    }
}

#[test]
fn four_tcp_owners_transfer_opaque_bidirectional_bytes_and_half_close_under_loss() -> TestResult {
    for ipv6 in [false, true] {
        for (impaired, wait_for_eof) in [(false, false), (true, false), (false, true), (true, true)]
        {
            let mut lab = Lab::new_family(ipv6)?;
            lab.connect()?;
            let originals: [Vec<u8>; 2] = [
                (0..16391).map(|i| (i * 37 + 13) as u8).collect(),
                (0..12289).map(|i| (i * 19 + 91) as u8).collect(),
            ];
            let mut sent = [0; 2];
            let mut closed = [false; 2];
            let mut eof = [false; 2];
            let mut received = [Vec::new(), Vec::new()];
            for _ in 0..60_000 {
                for side in 0..2 {
                    // Cover simultaneous bulk and a reply that begins after the request EOF.
                    if side == 0 || !wait_for_eof || eof[1] {
                        if sent[side] < originals[side].len() {
                            sent[side] += lab.apps[side].write(&originals[side][sent[side]..])?;
                        } else if !closed[side] {
                            lab.apps[side].close();
                            closed[side] = true;
                        }
                    }
                    eof[side] |= drain(&mut lab.apps[side], &mut received[side])?;
                }
                lab.step(impaired, false)?;
                if eof == [true; 2]
                    && lab.legs.iter().all(|leg| {
                        let status = leg.status();
                        status.local_fin
                            && status.remote_fin
                            && status.acknowledged == status.received
                            && status.pending_record_bytes == 0
                    })
                {
                    break;
                }
            }
            assert_eq!(received[0], originals[1]);
            assert_eq!(received[1], originals[0]);
            assert_eq!(eof, [true; 2]);
            assert!(
                lab.legs
                    .iter()
                    .all(|leg| leg.status().acknowledged == leg.status().received)
            );
            for _ in 0..20_000 {
                lab.step(impaired, false)?;
                if lab
                    .legs
                    .iter()
                    .all(|leg| leg.status().native.state == State::Closed)
                    && lab
                        .apps
                        .iter()
                        .all(|app| app.status().state == State::Closed)
                {
                    break;
                }
            }
            assert!(
                lab.legs
                    .iter()
                    .all(|leg| leg.status().native.close_reason == Some(CloseReason::Clean))
            );
            assert!(
                lab.apps
                    .iter()
                    .all(|app| app.status().close_reason == Some(CloseReason::Clean))
            );
            if impaired {
                assert!(lab.drops > 0 && lab.duplicates > 0);
            }
        }
    }
    Ok(())
}

#[test]
fn remote_pressure_closes_actual_native_window_then_reopens_without_revoking_credit() -> TestResult
{
    for ipv6 in [false, true] {
        let mut lab = Lab::new_family(ipv6)?;
        lab.connect()?;
        lab.legs[1].set_target(config().maximum)?;
        for _ in 0..10 {
            lab.step(false, false)?;
        }
        let grant = lab.legs[1].status().granted;
        lab.legs[1].set_target(Window {
            bytes: 512,
            records: 1,
        })?;
        let original: Vec<u8> = (0..24577).map(|i| (i * 53 + 7) as u8).collect();
        let mut sent = 0;
        for _ in 0..2000 {
            sent += lab.apps[0].write(&original[sent..])?;
            lab.step(false, false)?;
        }
        assert!(
            lab.zero_window[0],
            "local proxy must advertise real zero window"
        );
        assert!(lab.legs[1].status().granted.contains(grant));
        let before = lab.legs[1].status();
        for _ in 0..500 {
            lab.step(false, false)?;
        }
        let after = lab.legs[1].status();
        assert_eq!(before.acknowledged, after.acknowledged);
        assert!(after.received.bytes > after.acknowledged.bytes);
        assert!(after.injected_bytes > after.acknowledged.bytes);
        assert!(
            after.acknowledged.bytes <= 4096,
            "native ACK is not local write progress"
        );
        lab.legs[1].set_target(config().maximum)?;
        let mut received = Vec::new();
        for _ in 0..20_000 {
            sent += lab.apps[0].write(&original[sent..])?;
            drain(&mut lab.apps[1], &mut received)?;
            lab.step(false, false)?;
            if received.len() == original.len() {
                break;
            }
        }
        assert_eq!(received, original);
        assert!(lab.reopened[0]);
    }
    Ok(())
}

#[test]
fn blocked_carrier_retains_exact_output_and_bounded_native_pressure() -> TestResult {
    for ipv6 in [false, true] {
        let mut lab = Lab::new_family(ipv6)?;
        lab.connect()?;
        lab.apps[0].write(&[31; 4096])?;
        for _ in 0..100 {
            lab.step(false, true)?;
            if lab.legs[0].pending_record().is_some() {
                break;
            }
        }
        let record = lab.legs[0]
            .pending_record()
            .ok_or("missing retained output")?
            .to_vec();
        let produced = lab.legs[0].status().produced;
        for _ in 0..2000 {
            lab.step(false, true)?;
        }
        assert_eq!(lab.legs[0].pending_record(), Some(record.as_slice()));
        assert_eq!(lab.legs[0].status().produced, produced);
        let mut received = Vec::new();
        for _ in 0..5000 {
            lab.step(false, false)?;
            drain(&mut lab.apps[1], &mut received)?;
            if received.len() == 4096 {
                break;
            }
        }
        assert_eq!(received, vec![31; 4096]);
    }
    Ok(())
}

#[test]
fn malformed_and_noncontiguous_records_reject_transactionally() -> TestResult {
    let mut lab = Lab::new()?;
    lab.connect()?;
    let scope = config().scope;
    let valid = encode(scope, 2, Window::default(), &[9; 31]);
    for index in [0, 4, 6, 8, 24, 32] {
        let mut record = valid.clone();
        record[index] ^= 1;
        let before = lab.legs[0].status();
        assert!(lab.legs[0].receive_authenticated(&record).is_err());
        assert_eq!(lab.legs[0].status(), before);
    }
    for length in 0..HEADER {
        assert!(lab.legs[0].receive_authenticated(&valid[..length]).is_err());
    }
    for record in [
        encode(
            scope,
            2,
            Window {
                bytes: 1,
                records: 0,
            },
            &[3],
        ),
        encode(scope, 2, Window::default(), &[3; 513]),
        encode(
            scope,
            3,
            Window {
                bytes: 1,
                records: 0,
            },
            &[],
        ),
        encode(
            scope,
            1,
            Window {
                bytes: 9999,
                records: 4,
            },
            &[],
        ),
        encode(scope, 1, Window::default(), &[]),
        encode(scope, 3, Window::default(), &[7]),
    ] {
        let before = lab.legs[0].status();
        assert!(lab.legs[0].receive_authenticated(&record).is_err());
        assert_eq!(lab.legs[0].status(), before);
    }
    lab.legs[0].receive_authenticated(&valid)?;
    assert_eq!(
        lab.legs[0].receive_authenticated(&valid),
        Err(Error::Sequence)
    );
    let end = Window {
        bytes: 31,
        records: 1,
    };
    let fin = encode(scope, 3, end, &[]);
    lab.legs[0].receive_authenticated(&fin)?;
    lab.legs[0].receive_authenticated(&fin)?;
    assert_eq!(
        lab.legs[0].receive_authenticated(&encode(scope, 2, end, &[3])),
        Err(Error::State)
    );
    Ok(())
}

#[test]
fn reset_does_not_turn_discarded_send_bytes_into_credit() -> TestResult {
    let mut lab = Lab::new()?;
    lab.connect()?;
    let scope = config().scope;
    lab.legs[1].receive_authenticated(&encode(scope, 2, Window::default(), &[7; 512]))?;
    lab.legs[1].poll(Millis(lab.now), 1)?;
    assert_eq!(lab.legs[1].status().injected_bytes, 512);
    let grant = lab.legs[1].status().granted;
    lab.apps[1].abort();
    let mut failed = false;
    for _ in 0..50 {
        if let Err(error) = lab.step(false, true) {
            assert!(error.to_string().contains("PeerReset"));
            failed = true;
            break;
        }
    }
    assert!(failed);
    assert_eq!(lab.legs[1].status().granted, grant);
    assert_eq!(lab.legs[1].status().acknowledged.bytes, 0);
    assert!(lab.legs[1].status().failure.is_some());
    Ok(())
}

#[test]
fn configuration_exhaustion_and_early_data_are_explicit() -> TestResult {
    let mut settings = config();
    settings.scope.epoch = 0;
    assert_eq!(settings.validate(), Err(Error::Config));
    settings = config();
    settings.initial.records = 5;
    assert_eq!(settings.validate(), Err(Error::Config));
    let mut leg = Leg::new(config(), tcp(true, 19), Role::Server, Millis(0))?;
    assert_eq!(
        leg.receive_authenticated(&encode(config().scope, 2, Window::default(), &[1])),
        Err(Error::State)
    );
    assert_eq!(leg.confirm_record_sent(), Err(Error::NoOutput));
    assert_eq!(
        leg.set_target(Window {
            bytes: 0,
            records: 1
        }),
        Err(Error::Config)
    );
    leg.produced = Window {
        bytes: u64::MAX,
        records: 0,
    };
    assert_eq!(
        leg.receive_authenticated(&encode(
            config().scope,
            1,
            Window {
                bytes: u64::MAX,
                records: 1
            },
            &[]
        )),
        Err(Error::Exhausted)
    );
    leg.abort();
    assert_eq!(leg.poll(Millis(1), 1), Err(Error::Aborted));
    Ok(())
}

#[test]
fn record_count_credit_is_independent_from_byte_credit() -> TestResult {
    let mut lab = Lab::new()?;
    lab.connect()?;
    for i in 0..2 {
        let record = encode(
            config().scope,
            2,
            Window {
                bytes: i,
                records: i,
            },
            &[3],
        );
        lab.legs[0].receive_authenticated(&record)?;
    }
    let before = lab.legs[0].status();
    let next = encode(
        config().scope,
        2,
        Window {
            bytes: 2,
            records: 2,
        },
        &[3],
    );
    assert_eq!(lab.legs[0].receive_authenticated(&next), Err(Error::Credit));
    assert_eq!(before, lab.legs[0].status());
    Ok(())
}

#[test]
fn maintained_timeout_never_releases_discarded_bytes() -> TestResult {
    let mut lab = Lab::new()?;
    lab.connect()?;
    lab.legs[1].receive_authenticated(&encode(config().scope, 2, Window::default(), &[7; 512]))?;
    lab.legs[1].poll(Millis(lab.now), 1)?;
    // The maintained timeout starts at first native transmission, not ring insertion.
    lab.legs[1].poll(Millis(lab.now + 1), 1)?;
    let before = lab.legs[1].status();
    assert_eq!(before.injected_bytes, 512);
    assert_eq!(
        lab.legs[1].poll(Millis(lab.now + 120_001), 1),
        Err(Error::Tcp(l2tunnel_raw_tcp::Error::Terminated(
            CloseReason::Timeout
        )))
    );
    let after = lab.legs[1].status();
    assert_eq!(after.granted, before.granted);
    assert_eq!(after.acknowledged, before.acknowledged);
    assert!(after.failure.is_some());
    Ok(())
}
