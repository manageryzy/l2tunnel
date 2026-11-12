use super::*;
use l2tunnel_raw_tcp::{ReadOutcome, TcpEngine};
use std::collections::VecDeque;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn validates_lifetime_and_aggregate_bounds() -> TestResult {
    let base = config(Role::Originator, false);
    base.validate()?;
    for bad in [
        Config {
            max_flows: 0,
            ..base
        },
        Config {
            max_flows: 65,
            ..base
        },
        Config {
            max_policies: 1,
            ..base
        },
        Config {
            admission_timeout_ms: 0,
            ..base
        },
        Config { epoch: 0, ..base },
        Config {
            session: [0; 16],
            ..base
        },
    ] {
        assert_eq!(bad.validate(), Err(Error::Config));
    }
    let mut table = Table::new(base, Millis(10))?;
    assert_eq!(table.poll(Millis(9), 1, 1), Err(Error::Time));
    assert_eq!(table.poll(Millis(10), 0, 1), Err(Error::Work));
    assert_eq!(table.status().flows, 0);
    Ok(())
}

fn config(role: Role, ipv6: bool) -> Config {
    let (local, peer): (SocketAddr, SocketAddr) = if ipv6 {
        (
            ([0xfd00, 0x112, 0, 0, 0, 0, 0, 1], 32001).into(),
            ([0xfd00, 0x112, 0, 0, 0, 0, 0, 2], 443).into(),
        )
    } else {
        (
            ([10, 112, 0, 1], 32001).into(),
            ([10, 112, 0, 2], 443).into(),
        )
    };
    Config {
        session: [19; 16],
        epoch: 7,
        role,
        max_flows: 4,
        max_policies: 16,
        native: TcpIpConfig {
            local,
            peer,
            mtu: 1280,
            send_bytes: 4096,
            receive_bytes: 4096,
            packet_slots: 8,
            random_seed: 17,
            ack_delay_millis: 0,
            keepalive_millis: 1000,
            idle_timeout_millis: 30000,
        },
        max_record_bytes: 512,
        maximum: Window {
            bytes: 2048,
            records: 8,
        },
        initial: Window {
            bytes: 1024,
            records: 4,
        },
        admission_timeout_ms: 3000,
        time_wait_reset_policy: TimeWaitResetPolicy::IgnoreInTimeWait,
    }
}

fn endpoint_config(ipv6: bool, reverse: bool, port: u16, seed: u64) -> TcpIpConfig {
    let mut native = config(Role::Originator, ipv6).native;
    native.local.set_port(port);
    native.random_seed = seed;
    if reverse {
        std::mem::swap(&mut native.local, &mut native.peer);
    }
    native
}
fn first_syn(ipv6: bool, port: u16) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut client = TcpEngine::new_ip(
        endpoint_config(ipv6, false, port, 51),
        super::super::Role::Client,
        Millis(0),
    )?;
    client.poll(Millis(0), 4)?;
    Ok(client.pop_packet().ok_or("initial SYN")?)
}
fn exchange(a: &mut Table, b: &mut Table, now: Millis) -> TestResult {
    for id in 1..=a.status().flows as u64 {
        if let Some(bytes) = a.pending_record(id).map(<[u8]>::to_vec) {
            a.confirm_record_sent(id, now)?;
            b.receive_authenticated(&bytes, true, now)?;
        }
    }
    Ok(())
}
fn reserved(ipv6: bool) -> Result<(Table, Table, Vec<u8>), Box<dyn std::error::Error>> {
    let mut a = Table::new(config(Role::Originator, ipv6), Millis(0))?;
    let mut b = Table::new(config(Role::Acceptor, ipv6), Millis(0))?;
    let syn = first_syn(ipv6, 32001)?;
    assert_eq!(
        a.ingest_native(&syn, true, Millis(0))?,
        Disposition::Owned(1)
    );
    exchange(&mut a, &mut b, Millis(1))?;
    exchange(&mut b, &mut a, Millis(2))?;
    exchange(&mut a, &mut b, Millis(3))?;
    assert_eq!(a.flow_status(1).ok_or("local")?.phase, FlowPhase::Active);
    assert_eq!(b.flow_status(1).ok_or("remote")?.phase, FlowPhase::Active);
    Ok((a, b, syn))
}

struct Flow {
    tuple: Tuple,
    clients: [TcpEngine; 2],
    send: [Vec<u8>; 2],
    written: [usize; 2],
    read: [Vec<u8>; 2],
    closed: [bool; 2],
    eof: [bool; 2],
}
impl Flow {
    fn new(
        ipv6: bool,
        port: u16,
        policy: TimeWaitResetPolicy,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let native = endpoint_config(ipv6, false, port, 71);
        let mut result = Self {
            tuple: Tuple::new(native.local, native.peer),
            clients: [
                TcpEngine::new_ip(native, super::super::Role::Client, Millis(0))?,
                TcpEngine::new_ip(
                    endpoint_config(ipv6, true, port, 99),
                    super::super::Role::Server,
                    Millis(0),
                )?,
            ],
            send: [
                (0..16397)
                    .map(|n| (n * 17 + usize::from(port)) as u8)
                    .collect(),
                (0..9281)
                    .map(|n| (n * 31 + usize::from(port)) as u8)
                    .collect(),
            ],
            written: [0; 2],
            read: [Vec::new(), Vec::new()],
            closed: [false; 2],
            eof: [false; 2],
        };
        for client in &mut result.clients {
            client.set_time_wait_reset_policy(policy)?;
        }
        Ok(result)
    }
    fn advance(&mut self, now: Millis) -> TestResult {
        for side in 0..2 {
            self.clients[side].poll(now, 8)?;
            if self.clients[side].status().established && !self.closed[side] {
                let remaining = &self.send[side][self.written[side]..];
                if !remaining.is_empty() {
                    self.written[side] += self.clients[side].write(remaining)?;
                }
                if self.written[side] == self.send[side].len() {
                    self.clients[side].close();
                    self.closed[side] = true;
                }
            }
            let mut bytes = [0; 257];
            match self.clients[side].read(&mut bytes).map_err(|error| {
                format!(
                    "side={side}, eof={:?}, read=[{},{}], native={:?}: {error}",
                    self.eof,
                    self.read[0].len(),
                    self.read[1].len(),
                    self.clients[side].status()
                )
            })? {
                ReadOutcome::Data(n) => self.read[side].extend_from_slice(&bytes[..n]),
                ReadOutcome::Eof => self.eof[side] = true,
                ReadOutcome::Pending => {}
            }
        }
        Ok(())
    }
}
struct Datagram {
    side: usize,
    to_table: bool,
    flow: usize,
    bytes: Vec<u8>,
    due: u64,
}
struct Network {
    queue: VecDeque<Datagram>,
    serial: u64,
    impaired: bool,
    persistent_loss: bool,
    drops: usize,
    duplicates: usize,
}
impl Network {
    fn send(&mut self, side: usize, to_table: bool, flow: usize, bytes: Vec<u8>, now: Millis) {
        self.serial += 1;
        if self.impaired
            && (self.persistent_loss || self.serial <= 80)
            && self.serial.is_multiple_of(7)
        {
            self.drops += 1;
            return;
        }
        let due = now.0
            + if self.impaired && self.serial.is_multiple_of(5) {
                35
            } else {
                0
            };
        if self.impaired && self.serial.is_multiple_of(11) {
            self.duplicates += 1;
            self.queue.push_back(Datagram {
                side,
                to_table,
                flow,
                bytes: bytes.clone(),
                due: due + 5,
            });
        }
        self.queue.push_back(Datagram {
            side,
            to_table,
            flow,
            bytes,
            due,
        });
        assert!(self.queue.len() < 1024);
    }
    fn deliver(&mut self, tables: &mut [Table; 2], flows: &mut [Flow], now: Millis) -> TestResult {
        for _ in 0..self.queue.len() {
            let item = self.queue.pop_front().ok_or("queued native")?;
            if item.due > now.0 {
                self.queue.push_back(item);
                continue;
            }
            if item.to_table {
                match tables[item.side].ingest_native(&item.bytes, true, now)? {
                    Disposition::Owned(_) => {}
                    Disposition::Backpressure(_) => self.queue.push_back(item),
                    Disposition::Transparent => {
                        return Err("test-owned native became transparent".into());
                    }
                }
            } else {
                flows[item.flow].clients[item.side].ingest(&item.bytes)?;
            }
        }
        Ok(())
    }
}

#[test]
fn concurrent_ipv4_ipv6_owners_preserve_bytes_handoffs_and_clean_retirement() -> TestResult {
    for (impaired, persistent) in [(false, false), (true, false)] {
        run_concurrent(impaired, persistent, TimeWaitResetPolicy::IgnoreInTimeWait)?;
    }
    Ok(())
}

#[test]
fn persistent_native_loss_preserves_post_eof_reset_as_an_abnormal_result() -> TestResult {
    // Preserve the original adversarial periodic-loss trace separately from the
    // finite-loss recovery qualification. Never relabel a maintained RST as clean.
    let error = run_concurrent(true, true, TimeWaitResetPolicy::Maintained)
        .err()
        .ok_or("expected recorded maintained reset")?;
    let detail = error.to_string();
    assert!(detail.contains("Millis(26350)"), "{detail}");
    assert!(
        detail.contains("side=1, eof=[false, true], read=[5632,16397]"),
        "{detail}"
    );
    assert!(detail.contains("Terminated(PeerReset)"), "{detail}");
    assert!(detail.contains("receive_bytes: 2625"), "{detail}");
    Ok(())
}

#[test]
fn opt_in_timewait_mitigation_does_not_claim_unfinished_periodic_loss_is_clean() -> TestResult {
    let error = run_concurrent(true, true, TimeWaitResetPolicy::IgnoreInTimeWait)
        .err()
        .ok_or("expected recorded finite bound")?;
    let detail = error.to_string();
    assert!(detail.contains("bounded 60000 ms"), "{detail}");
    assert!(!detail.contains("PeerReset"), "{detail}");
    assert!(detail.contains("receive_bytes: 1601"), "{detail}");
    Ok(())
}

fn run_concurrent(
    impaired: bool,
    persistent_loss: bool,
    policy: TimeWaitResetPolicy,
) -> TestResult {
    let mut tables = [
        Table::new(
            Config {
                time_wait_reset_policy: policy,
                ..config(Role::Originator, false)
            },
            Millis(0),
        )?,
        Table::new(
            Config {
                time_wait_reset_policy: policy,
                ..config(Role::Acceptor, false)
            },
            Millis(0),
        )?,
    ];
    let mut flows = [
        Flow::new(false, 32001, policy)?,
        Flow::new(true, 32002, policy)?,
    ];
    let mut net = Network {
        queue: VecDeque::new(),
        serial: 0,
        impaired,
        persistent_loss,
        drops: 0,
        duplicates: 0,
    };
    for flow in &mut flows {
        flow.clients[0].poll(Millis(0), 4)?;
        let syn = flow.clients[0].pop_packet().ok_or("original SYN")?;
        assert!(matches!(
            tables[0].ingest_native(&syn, true, Millis(0))?,
            Disposition::Owned(_)
        ));
    }
    let retained: Vec<_> = (1..=2)
        .map(|id| tables[0].pending_record(id).map(<[u8]>::to_vec))
        .collect();
    let mut held_native: Option<Vec<u8>> = None;
    let mut done = false;
    for tick in 0..12000 {
        let now = Millis(tick * 5);
        for table in &mut tables {
            table.poll(now, 4, 8)?;
        }
        for (side, table) in tables.iter().enumerate() {
            for id in 1..=table.status().flows as u64 {
                if table
                    .flow_status(id)
                    .is_some_and(|s| matches!(s.phase, FlowPhase::Stopped(_)))
                {
                    return Err(format!(
                        "table stopped at {now:?}, side={side}, id={id}, status={:?}; app={:?}",
                        table.flow_status(id),
                        flows
                            .iter()
                            .map(|f| (
                                f.eof,
                                [f.read[0].len(), f.read[1].len()],
                                f.clients.iter().map(TcpEngine::status).collect::<Vec<_>>()
                            ))
                            .collect::<Vec<_>>()
                    )
                    .into());
                }
            }
        }
        if tick < 100 {
            for id in 1..=2 {
                assert_eq!(
                    tables[0].pending_record(id),
                    retained[id as usize - 1].as_deref()
                );
                assert!(tables[0].pending_native(id).is_none());
            }
            assert!(
                flows
                    .iter()
                    .all(|flow| !flow.clients[0].status().established)
            );
        } else {
            let (left, right) = tables.split_at_mut(1);
            exchange(&mut left[0], &mut right[0], now)?;
            exchange(&mut right[0], &mut left[0], now)?;
        }
        for (side, table) in tables.iter_mut().enumerate() {
            for id in 1..=table.status().flows as u64 {
                if let Some(packet) = table.pending_native(id) {
                    if side == 0 && id == 1 && tick < 150 {
                        if let Some(previous) = &held_native {
                            assert_eq!(packet, previous);
                        } else {
                            held_native = Some(packet.to_vec());
                        }
                        continue;
                    }
                    let Packet::Tcp { tuple, .. } = inspect_packet(packet, 1280)? else {
                        return Err("native TCP".into());
                    };
                    let index = flows
                        .iter()
                        .position(|flow| flow.tuple == tuple)
                        .ok_or("tuple mapping")?;
                    net.send(side, false, index, packet.to_vec(), now);
                    table.confirm_native_written(id)?;
                }
            }
        }
        for (index, flow) in flows.iter_mut().enumerate() {
            flow.advance(now).map_err(|error| format!("native application error at {now:?}, impaired={impaired}, flow={index}: {error}; tables={:?}",tables.iter().map(|t|(t.flow_status(1),t.flow_status(2),t.relay_status(1),t.relay_status(2))).collect::<Vec<_>>()))?;
            for side in 0..2 {
                while let Some(packet) = flow.clients[side].pop_packet() {
                    net.send(side, true, index, packet, now);
                }
            }
        }
        net.deliver(&mut tables, &mut flows, now)?;
        let all_closed = flows.iter().all(|flow| {
            flow.eof == [true, true]
                && flow
                    .clients
                    .iter()
                    .all(|client| client.status().close_reason == Some(CloseReason::Clean))
        });
        if all_closed && net.queue.is_empty() {
            for table in &mut tables {
                for id in 1..=2 {
                    if table.flow_status(id).ok_or("flow")?.phase == FlowPhase::Active {
                        let _ = table.retire_clean(id);
                    }
                }
            }
            if tables.iter().all(|table| {
                (1..=2).all(|id| {
                    table
                        .flow_status(id)
                        .is_some_and(|s| s.phase == FlowPhase::Retired)
                })
            }) {
                done = true;
                break;
            }
        }
    }
    if !done {
        return Err(format!(
            "bounded 60000 ms, impaired={impaired}, flows={:?}",
            tables
                .iter()
                .map(|t| (t.flow_status(1), t.flow_status(2)))
                .collect::<Vec<_>>()
        )
        .into());
    }
    assert!(held_native.is_some());
    for flow in &flows {
        assert_eq!(flow.read[0], flow.send[1]);
        assert_eq!(flow.read[1], flow.send[0]);
    }
    assert!(tables.iter().all(|table| table.status().flows == 2));
    if impaired {
        assert!(net.drops > 0 && net.duplicates > 0);
    }
    Ok(())
}

fn checksums(packet: &mut [u8]) {
    let (src, dst, offset) = if packet[0] >> 4 == 4 {
        let mut ip = Ipv4Packet::new_unchecked(&mut *packet);
        ip.fill_checksum();
        (
            IpAddress::Ipv4(ip.src_addr()),
            IpAddress::Ipv4(ip.dst_addr()),
            20,
        )
    } else {
        let ip = Ipv6Packet::new_unchecked(&*packet);
        (
            IpAddress::Ipv6(ip.src_addr()),
            IpAddress::Ipv6(ip.dst_addr()),
            40,
        )
    };
    TcpPacket::new_unchecked(&mut packet[offset..]).fill_checksum(&src, &dst);
}

#[test]
fn bypass_is_sticky_and_capacity_cannot_migrate_a_connection() -> TestResult {
    for ipv6 in [false, true] {
        let base = config(Role::Originator, ipv6);
        let mut table = Table::new(
            Config {
                max_flows: 1,
                max_policies: 2,
                ..base
            },
            Millis(0),
        )?;
        let mut unsupported = first_syn(ipv6, 32001)?;
        let flags = if ipv6 { 53 } else { 33 };
        unsupported[flags] |= 0x40;
        checksums(&mut unsupported);
        assert_eq!(
            table.ingest_native(&unsupported, true, Millis(0))?,
            Disposition::Transparent
        );
        let supported = first_syn(ipv6, 32001)?;
        assert_eq!(
            table.ingest_native(&supported, true, Millis(1))?,
            Disposition::Transparent
        );
        let reverse = first_syn(ipv6, 32002)?;
        table.observe_transparent(&reverse, Millis(2))?;
        assert_eq!(
            table.ingest_native(&reverse, true, Millis(3))?,
            Disposition::Transparent
        );
        assert_eq!(
            table.ingest_native(&first_syn(ipv6, 32003)?, true, Millis(4))?,
            Disposition::Transparent
        );
        assert_eq!(
            table.status(),
            Status {
                flows: 0,
                policies: 2,
                admission_locked: true
            }
        );
        assert_eq!(
            table.ingest_native(&first_syn(ipv6, 32004)?, true, Millis(5))?,
            Disposition::Transparent
        );
        assert_eq!(table.status().policies, 2);

        let (mut owned, _, syn) = reserved(ipv6)?;
        assert_eq!(
            owned.observe_transparent(&syn, Millis(4)),
            Err(Error::Conflict)
        );
        let mut ambiguous = syn.clone();
        if ipv6 {
            ambiguous[6] = 44;
        } else {
            ambiguous[6] |= 0x20;
            Ipv4Packet::new_unchecked(&mut ambiguous).fill_checksum();
        }
        assert_eq!(
            owned.ingest_native(&ambiguous, true, Millis(5)),
            Err(Error::Conflict)
        );
        let mut before = Table::new(base, Millis(0))?;
        assert_eq!(
            before.ingest_native(&ambiguous, true, Millis(0))?,
            Disposition::Transparent
        );
        assert_eq!(
            before.ingest_native(&syn, true, Millis(1))?,
            Disposition::Transparent
        );
        assert_eq!(before.status().flows, 0);
    }
    Ok(())
}

#[test]
fn refusal_cancel_expiry_scope_and_replay_never_revive_native_ownership() -> TestResult {
    for ipv6 in [false, true] {
        let mut a = Table::new(config(Role::Originator, ipv6), Millis(0))?;
        let mut b = Table::new(config(Role::Acceptor, ipv6), Millis(0))?;
        let syn = first_syn(ipv6, 32001)?;
        a.ingest_native(&syn, true, Millis(0))?;
        let open = a.pending_record(1).ok_or("Open")?.to_vec();
        for cut in 0..open.len() {
            assert!(
                b.receive_authenticated(&open[..cut], true, Millis(0))
                    .is_err()
            );
        }
        assert_eq!(b.status().flows, 0);
        let mut bad = open.clone();
        bad[8] ^= 1;
        assert_eq!(
            b.receive_authenticated(&bad, true, Millis(0)),
            Err(Error::Scope)
        );
        a.confirm_record_sent(1, Millis(0))?;
        b.receive_authenticated(&open, false, Millis(0))?;
        assert_eq!(
            b.flow_status(1).ok_or("rejected")?.phase,
            FlowPhase::Stopped(StopReason::Rejected)
        );
        exchange(&mut b, &mut a, Millis(1))?;
        assert_eq!(
            a.flow_status(1).ok_or("rejected origin")?.phase,
            FlowPhase::Stopped(StopReason::Rejected)
        );
        assert!(a.pending_native(1).is_none());
        assert_eq!(
            b.receive_authenticated(&open, true, Millis(2)),
            Err(Error::Scope)
        );
        assert_eq!(
            a.ingest_native(&syn, true, Millis(2))?,
            Disposition::Owned(1)
        );
        assert_eq!(a.status().flows, 1);

        let mut unsent = Table::new(config(Role::Originator, ipv6), Millis(0))?;
        unsent.ingest_native(&syn, true, Millis(0))?;
        let fabricated = stop_record(
            config(Role::Originator, ipv6).scope(1),
            StopReason::Rejected,
        );
        assert_eq!(
            unsent.receive_authenticated(&fabricated, true, Millis(0)),
            Err(Error::State)
        );
        unsent.cancel(1, Millis(1))?;
        assert!(unsent.pending_record(1).is_none());
        assert!(unsent.pending_native(1).is_none());

        let (mut a, mut b, mut syn) = reserved(ipv6)?;
        let offset = if ipv6 { 40 } else { 20 };
        syn[offset + 13] |= 0x20;
        checksums(&mut syn);
        assert_eq!(
            a.ingest_native(&syn, true, Millis(4))?,
            Disposition::Owned(1)
        );
        assert_eq!(
            a.flow_status(1).ok_or("unsupported")?.phase,
            FlowPhase::Stopped(StopReason::UnsupportedPacket)
        );
        let terminal = a.pending_record(1).ok_or("terminal")?.to_vec();
        a.poll(Millis(5), 4, 4)?;
        assert_eq!(a.pending_record(1), Some(terminal.as_slice()));
        exchange(&mut a, &mut b, Millis(6))?;
        assert!(matches!(
            b.flow_status(1).ok_or("stopped")?.phase,
            FlowPhase::Stopped(_)
        ));
        assert_eq!(a.retire_clean(1), Err(Error::State));

        let mut late = Table::new(config(Role::Originator, ipv6), Millis(0))?;
        late.ingest_native(&first_syn(ipv6, 32001)?, true, Millis(0))?;
        late.confirm_record_sent(1, Millis(3000))?;
        assert_eq!(
            late.flow_status(1).ok_or("expired")?.phase,
            FlowPhase::Stopped(StopReason::AdmissionExpired)
        );
        assert_eq!(late.pending_record(1).ok_or("expired notification")?[5], 5);
        assert!(late.pending_native(1).is_none());
    }
    Ok(())
}

#[test]
fn bounded_ingress_and_real_native_reset_preserve_terminal_output() -> TestResult {
    for ipv6 in [false, true] {
        let (mut a, mut b, syn) = reserved(ipv6)?;
        // Commit has already queued one original SYN. Further native retransmits
        // consume the finite ingress allowance without losing caller ownership.
        for _ in 1..config(Role::Originator, ipv6).native.packet_slots {
            assert_eq!(
                a.ingest_native(&syn, true, Millis(4))?,
                Disposition::Owned(1)
            );
        }
        assert_eq!(
            a.ingest_native(&syn, true, Millis(4))?,
            Disposition::Backpressure(1)
        );
        b.poll(Millis(4), 4, 4)?;
        let far_syn = b.pending_native(1).ok_or("far actual SYN")?.to_vec();
        let mut server = TcpEngine::new_ip(
            endpoint_config(ipv6, true, 32001, 99),
            super::super::Role::Server,
            Millis(4),
        )?;
        server.ingest(&far_syn)?;
        server.poll(Millis(4), 4)?;
        let mut reset = server.pop_packet().ok_or("actual SYN ACK")?;
        let offset = if ipv6 { 40 } else { 20 };
        reset.truncate(offset + 20);
        reset[offset + 12] = 5 << 4;
        reset[offset + 13] = 0x14;
        if ipv6 {
            reset[4..6].copy_from_slice(&20u16.to_be_bytes());
        } else {
            reset[2..4].copy_from_slice(&40u16.to_be_bytes());
        }
        checksums(&mut reset);
        b.confirm_native_written(1)?;
        assert_eq!(
            b.ingest_native(&reset, true, Millis(5))?,
            Disposition::Owned(1)
        );
        b.poll(Millis(5), 4, 4)?;
        let status = b.flow_status(1).ok_or("reset owner")?;
        assert_eq!(status.phase, FlowPhase::Stopped(StopReason::NativeFailure));
        assert_eq!(
            status.native.ok_or("retained aborted leg")?.close_reason,
            Some(CloseReason::PeerReset)
        );
        let terminal = b.pending_record(1).ok_or("reset terminal")?.to_vec();
        b.poll(Millis(6), 4, 4)?;
        assert_eq!(b.pending_record(1), Some(terminal.as_slice()));
        exchange(&mut b, &mut a, Millis(7))?;
        assert_eq!(
            a.flow_status(1).ok_or("peer reset")?.phase,
            FlowPhase::Stopped(StopReason::NativeFailure)
        );
        let late = super::super::encode(
            config(Role::Originator, ipv6).scope(1),
            1,
            Window {
                bytes: 2048,
                records: 8,
            },
            &[],
        );
        a.receive_authenticated(&late, true, Millis(8))?;
        assert!(a.relay_status(1).is_none());
        assert_eq!(a.retire_clean(1), Err(Error::State));
    }
    Ok(())
}
