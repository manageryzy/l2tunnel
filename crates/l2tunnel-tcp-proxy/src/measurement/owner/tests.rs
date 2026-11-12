use super::*;
use crate::{Millis, Role, TcpEngine, TcpIpConfig, TimeWaitResetPolicy, Window};
use std::net::SocketAddr;
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn policy(limit: usize, role: session::Role) -> session::Config {
    session::Config {
        session: [91; 16],
        epoch: 4,
        role,
        max_flows: limit,
        max_policies: 128,
        native: TcpIpConfig {
            local: SocketAddr::from(([10, 38, 0, 1], 32000)),
            peer: SocketAddr::from(([10, 38, 0, 2], 443)),
            mtu: 1280,
            send_bytes: 4096,
            receive_bytes: 4096,
            packet_slots: 8,
            random_seed: 9,
            ack_delay_millis: 0,
            keepalive_millis: 1000,
            idle_timeout_millis: 30000,
        },
        max_record_bytes: 256,
        maximum: Window {
            bytes: 4096,
            records: 16,
        },
        initial: Window {
            bytes: 512,
            records: 2,
        },
        admission_timeout_ms: 3000,
        time_wait_reset_policy: TimeWaitResetPolicy::Maintained,
    }
}
fn config() -> OwnerConfig {
    OwnerConfig {
        pending_ttl_micros: 20_000,
        probe_interval_micros: 2_000,
        probe_timeout_micros: 30_000,
        handoff_timeout_micros: 50_000,
        emission_interval_micros: 10_000,
        max_records_per_interval: 8,
    }
}
fn exchange(a: &mut session::Table, b: &mut session::Table, now: Millis) -> TestResult {
    for flow in 1..=a.status().flows as u64 {
        if let Some(bytes) = a.pending_record(flow).map(<[u8]>::to_vec) {
            a.confirm_record_sent(flow, now)?;
            b.receive_authenticated(&bytes, true, now)?;
        }
    }
    Ok(())
}
struct Lab {
    a: session::Table,
    b: session::Table,
    hosts: Vec<[TcpEngine; 2]>,
    now: u64,
}
impl Lab {
    fn new(count: usize, limit: usize) -> Result<Self, Box<dyn std::error::Error>> {
        let mut a = session::Table::new(policy(limit, session::Role::Originator), Millis(0))?;
        let mut b = session::Table::new(policy(limit, session::Role::Acceptor), Millis(0))?;
        let mut hosts = Vec::new();
        for index in 0..count {
            let mut cfg = a.policy().native;
            cfg.local.set_port(32000 + u16::try_from(index)?);
            cfg.random_seed = 51 + index as u64;
            let mut client = TcpEngine::new_ip(cfg, Role::Client, Millis(0))?;
            std::mem::swap(&mut cfg.local, &mut cfg.peer);
            cfg.random_seed += 100;
            let server = TcpEngine::new_ip(cfg, Role::Server, Millis(0))?;
            client.poll(Millis(0), 4)?;
            let syn = client.pop_packet().ok_or("SYN")?;
            assert_eq!(
                a.ingest_native(&syn, true, Millis(0))?,
                session::Disposition::Owned(index as u64 + 1)
            );
            hosts.push([client, server]);
        }
        exchange(&mut a, &mut b, Millis(1))?;
        exchange(&mut b, &mut a, Millis(2))?;
        exchange(&mut a, &mut b, Millis(3))?;
        Ok(Self {
            a,
            b,
            hosts,
            now: 3,
        })
    }
    fn step(&mut self, handoff: bool) -> TestResult {
        self.now += 1;
        let now = Millis(self.now);
        for (index, pair) in self.hosts.iter_mut().enumerate() {
            for (side, host) in pair.iter_mut().enumerate() {
                host.poll(now, 8)?;
                let table = if side == 0 { &mut self.a } else { &mut self.b };
                while let Some(bytes) = host.pop_packet() {
                    assert_eq!(
                        table.ingest_native(&bytes, false, now)?,
                        session::Disposition::Owned(index as u64 + 1)
                    );
                }
            }
        }
        self.a.poll(now, 64, 8)?;
        self.b.poll(now, 64, 8)?;
        for (index, pair) in self.hosts.iter_mut().enumerate() {
            for (side, host) in pair.iter_mut().enumerate() {
                let table = if side == 0 { &mut self.a } else { &mut self.b };
                if let Some(bytes) = table.pending_native(index as u64 + 1).map(<[u8]>::to_vec) {
                    host.ingest(&bytes)?;
                    table.confirm_native_written(index as u64 + 1)?;
                }
            }
        }
        if handoff {
            exchange(&mut self.a, &mut self.b, now)?;
            exchange(&mut self.b, &mut self.a, now)?;
        }
        Ok(())
    }
    fn establish(&mut self) -> TestResult {
        for _ in 0..100 {
            self.step(true)?;
            if self.hosts.iter().flatten().all(|h| h.status().established)
                && (1..=self.hosts.len() as u64).all(|id| {
                    self.a
                        .credit_status(id)
                        .is_some_and(|s| s.granted.bytes > 0)
                        && self
                            .b
                            .credit_status(id)
                            .is_some_and(|s| s.granted.bytes > 0)
                })
            {
                return Ok(());
            }
        }
        Err("native handshake did not establish actual relay grants".into())
    }
    fn time(&self) -> Micros {
        Micros(self.now * 1000)
    }
}
fn pending(
    owner: &mut Owner,
    table: &session::Table,
    at: Micros,
) -> Result<(OutputId, Vec<u8>), Box<dyn std::error::Error>> {
    let output = owner.pending(table, at)?.ok_or("pending record")?;
    Ok((output.id, output.bytes.to_vec()))
}
fn encode(record: Record) -> Result<Vec<u8>, Error> {
    Ok(Buffer::encode(record)?.slice().to_vec())
}
fn record(owner: &Owner, flow: u64, serial: u64, body: Body) -> Record {
    Record {
        header: Header {
            scope: owner.scope(flow),
            direction: if kind(body) == 1 {
                owner.outgoing()
            } else {
                owner.incoming()
            },
            serial,
        },
        body,
    }
}
fn unchanged<T>(
    owner: &mut Owner,
    operation: impl FnOnce(&mut Owner) -> Result<T, Error>,
    error: Error,
) {
    let before = owner.state.clone();
    assert_eq!(operation(owner).err(), Some(error));
    assert_eq!(owner.state, before);
}

#[test]
fn finite_config_and_fixed_memory_geometry_match_retained_storage() -> TestResult {
    for n in [1, 2, 64] {
        let table = session::Table::new(policy(n, session::Role::Originator), Millis(0))?;
        let bound = config().validate(&table)?;
        assert_eq!(bound.output_slots, 2 * n + 1);
        assert_eq!(bound.incoming_proofs, 3 * n);
        assert_eq!(bound.buffer_bytes, (7 * n + 2) * 104);
        assert_eq!(bound.common_copy_bytes, 256 * n + 104);
        assert!(bound.metadata_bytes > 0);
        let owner = Owner::new(config(), &table, Micros(0))?;
        assert_eq!(owner.state.slots.len(), bound.output_slots);
        assert_eq!(owner.state.proofs.len() * 3, bound.incoming_proofs);
        assert_eq!(owner.next_deadline(), None);
        for duration in [0, 999, 120_000_001, u64::MAX] {
            let mut variants = [config(); 5];
            variants[0].pending_ttl_micros = duration;
            variants[1].probe_interval_micros = duration;
            variants[2].probe_timeout_micros = duration;
            variants[3].handoff_timeout_micros = duration;
            variants[4].emission_interval_micros = duration;
            for bad in variants {
                assert_eq!(bad.validate(&table), Err(Error::Configuration));
            }
        }
        for count in [0, 257, u16::MAX] {
            let bad = OwnerConfig {
                max_records_per_interval: count,
                ..config()
            };
            assert_eq!(bad.validate(&table), Err(Error::Configuration));
        }
        assert!(Owner::new(config(), &table, Micros(u64::MAX)).is_err());
    }
    Ok(())
}

#[test]
fn actual_table_identity_role_scope_and_error_atomicity() -> TestResult {
    let mut lab = Lab::new(1, 2)?;
    lab.establish()?;
    let now = lab.time();
    let mut owner = Owner::new(config(), &lab.a, now)?;
    let copy = session::Table::new(lab.a.policy(), Millis(0))?;
    unchanged(&mut owner, |o| o.stage_demand(&copy, 1, now), Error::Owner);
    unchanged(&mut owner, |o| o.stage_demand(&lab.a, 0, now), Error::Flow);
    unchanged(&mut owner, |o| o.stage_demand(&lab.a, 2, now), Error::Flow);
    unchanged(
        &mut owner,
        |o| o.tick(&lab.a, Micros(now.0 - 1)),
        Error::Time,
    );
    let valid = record(&owner, 1, 1, Body::Demand(Demand::default()));
    let mut variants = [valid; 4];
    variants[0].header.scope.session[0] ^= 1;
    variants[1].header.scope.epoch += 1;
    variants[2].header.direction = owner.outgoing();
    variants[3].header.scope.flow = 2;
    for (i, value) in variants.into_iter().enumerate() {
        let bytes = encode(value)?;
        unchanged(
            &mut owner,
            |o| o.receive_authenticated(&lab.a, &bytes, now),
            if i == 3 { Error::Flow } else { Error::Scope },
        );
    }
    let bytes = encode(valid)?;
    for len in 0..bytes.len() {
        let before = owner.state.clone();
        assert!(
            owner
                .receive_authenticated(&lab.a, &bytes[..len], now)
                .is_err()
        );
        assert_eq!(owner.state, before);
    }
    lab.a.poll(Millis(lab.now + 1), 1, 1)?;
    unchanged(&mut owner, |o| o.tick(&lab.a, now), Error::Time);
    Ok(())
}

#[test]
fn real_pending_data_and_native_unread_are_staged_without_table_mutation() -> TestResult {
    let mut lab = Lab::new(1, 2)?;
    lab.establish()?;
    let mut a = Owner::new(config(), &lab.a, lab.time())?;
    let mut b = Owner::new(config(), &lab.b, lab.time())?;
    assert_eq!(lab.hosts[0][0].write(&[7; 1024])?, 1024);
    for _ in 0..20 {
        lab.step(false)?;
        if lab
            .a
            .pending_record(1)
            .is_some_and(|p| p.get(5) == Some(&2))
        {
            break;
        }
    }
    let actual = lab.a.relay_status(1).ok_or("relay")?;
    let retained = lab.a.pending_record(1).ok_or("Data")?.to_vec();
    assert_eq!(retained[5], 2);
    assert!(actual.native.receive_bytes > 0);
    a.stage_demand(&lab.a, 1, lab.time())?;
    let (id, bytes) = pending(&mut a, &lab.a, lab.time())?;
    let decoded = wire::decode(&bytes)?;
    assert_eq!(decoded.header.direction, Direction::OriginatorToAcceptor);
    let Body::Demand(demand) = decoded.body else {
        return Err("Demand".into());
    };
    assert_eq!(demand.produced, actual.produced);
    assert_eq!(demand.observed_grant, actual.peer_granted);
    assert_eq!(
        demand.native_unread_bytes,
        actual.native.receive_bytes as u64
    );
    assert_eq!(demand.pending_data_bytes, 256);
    assert_eq!(lab.a.relay_status(1), Some(actual));
    assert_eq!(lab.a.pending_record(1), Some(retained.as_slice()));
    a.confirm_admission(id.clone(), lab.time())?;
    assert_eq!(
        b.receive_authenticated(&lab.b, &bytes, lab.time())?,
        Ingress::Accepted
    );
    a.confirm_written(id, lab.time())?;
    b.stage_demand(&lab.b, 1, lab.time())?;
    let (_, reverse) = pending(&mut b, &lab.b, lab.time())?;
    assert_eq!(
        wire::decode(&reverse)?.header.direction,
        Direction::AcceptorToOriginator
    );
    assert_eq!(
        a.receive_authenticated(&lab.a, &reverse, lab.time())?,
        Ingress::Accepted
    );
    Ok(())
}

#[test]
fn duplicate_conflict_stale_and_current_authoritative_grant_checks() -> TestResult {
    let mut lab = Lab::new(1, 2)?;
    lab.establish()?;
    let at = lab.time();
    let mut owner = Owner::new(config(), &lab.a, at)?;
    let grant = lab.a.credit_status(1).ok_or("grant")?.granted;
    let demand = Demand {
        produced: Window {
            bytes: 10,
            records: 1,
        },
        observed_grant: grant,
        ..Demand::default()
    };
    let initial = record(&owner, 1, 3, Body::Demand(demand));
    let bytes = encode(initial)?;
    assert_eq!(
        owner.receive_authenticated(&lab.a, &bytes, at)?,
        Ingress::Accepted
    );
    let before = owner.state.clone();
    assert_eq!(
        owner.receive_authenticated(&lab.a, &bytes, at)?,
        Ingress::Duplicate
    );
    assert_eq!(owner.state, before);
    let mut change = initial;
    change.body = Body::Demand(Demand {
        produced: Window {
            bytes: 11,
            records: 1,
        },
        ..demand
    });
    let conflict = encode(change)?;
    unchanged(
        &mut owner,
        |o| o.receive_authenticated(&lab.a, &conflict, at),
        Error::Conflict,
    );
    change.header.serial = 2;
    assert_eq!(
        owner.receive_authenticated(&lab.a, &encode(change)?, at)?,
        Ingress::Stale
    );
    assert_eq!(owner.state, before);
    let mut bad = [demand; 5];
    bad[0].observed_grant.bytes += 1;
    bad[1].observed_grant.records += 1;
    bad[2].native_unread_bytes = 4097;
    bad[3].pending_data_bytes = 257;
    bad[4].produced.bytes = 9;
    for demand in bad {
        let bytes = encode(record(&owner, 1, 4, Body::Demand(demand)))?;
        unchanged(
            &mut owner,
            |o| o.receive_authenticated(&lab.a, &bytes, at),
            Error::Counters,
        );
    }
    lab.a.set_target(
        1,
        Window {
            bytes: 2048,
            records: 8,
        },
    )?;
    lab.a.poll(Millis(lab.now + 1), 1, 4)?;
    let later = Micros((lab.now + 1) * 1000);
    let grown = lab.a.credit_status(1).ok_or("new grant")?.granted;
    assert!(grown.bytes > grant.bytes);
    // Old-but-monotonic grants remain valid hints; they assert no current exhaustion evidence.
    let bytes = encode(record(&owner, 1, 5, Body::Demand(demand)))?;
    assert_eq!(
        owner.receive_authenticated(&lab.a, &bytes, later)?,
        Ingress::Accepted
    );
    assert_eq!(lab.a.credit_status(1).ok_or("unchanged")?.granted, grown);
    Ok(())
}

#[test]
fn bounded_fake_mux_saturation_coalescing_generations_and_shared_cost() -> TestResult {
    let mut lab = Lab::new(2, 2)?;
    lab.establish()?;
    let at = lab.time();
    let mut owner = Owner::new(config(), &lab.a, at)?;
    owner.stage_demand(&lab.a, 1, at)?;
    let (old, first) = pending(&mut owner, &lab.a, at)?;
    let before = owner.state.clone();
    // Fake ordinary MUX capacity one byte below complete record+48-byte framing.
    let capacity = first.len() + 47;
    assert!(first.len() + 48 > capacity);
    let (again, bytes) = pending(&mut owner, &lab.a, at)?;
    assert_eq!(again, old);
    assert_eq!(bytes, first);
    assert_eq!(owner.state, before);
    owner.stage_demand(&lab.a, 1, at)?;
    unchanged(
        &mut owner,
        |o| o.confirm_admission(old.clone(), at),
        Error::Output,
    );
    let (current, admitted) = pending(&mut owner, &lab.a, at)?;
    let mut bounded_mux = Some((current.clone(), admitted));
    owner.confirm_admission(current.clone(), at)?;
    owner.stage_demand(&lab.a, 1, at)?;
    for _ in 0..256 {
        owner.stage_demand(&lab.a, 1, at)?;
    }
    assert_eq!(owner.status().pending, 1);
    assert_eq!(owner.status().admitted, 1);
    assert!(owner.pending(&lab.a, at)?.is_none());
    owner.stage_demand(&lab.a, 2, at)?;
    let next = owner.pending(&lab.a, at)?.ok_or("independent slot")?;
    assert_eq!(next.flow, 2);
    // Queue saturation neither copies nor confirms this second candidate.
    assert!(bounded_mux.is_some());
    let (written, exact) = bounded_mux.take().ok_or("retained write")?;
    assert_eq!(wire::decode(&exact)?.header.serial, current.generation);
    owner.confirm_written(written, at)?;
    unchanged(
        &mut owner,
        |o| o.confirm_written(current.clone(), at),
        Error::Output,
    );
    let other = Owner::new(config(), &lab.a, at)?;
    let foreign = OutputId {
        owner: other.identity.clone(),
        slot: 0,
        generation: current.generation,
    };
    unchanged(
        &mut owner,
        |o| o.confirm_admission(foreign, at),
        Error::Owner,
    );
    assert_eq!(owner.state.slots.len(), 5);
    assert_eq!(owner.state.proofs.len(), 2);
    Ok(())
}

#[test]
fn emission_is_finite_no_idle_catchup_and_input_burst_has_no_receiver_bucket() -> TestResult {
    let mut lab = Lab::new(2, 2)?;
    lab.establish()?;
    let at = lab.time();
    let cfg = OwnerConfig {
        max_records_per_interval: 1,
        ..config()
    };
    let mut owner = Owner::new(cfg, &lab.a, at)?;
    owner.stage_demand(&lab.a, 2, at)?;
    let (second, _) = pending(&mut owner, &lab.a, at)?;
    owner.stage_demand(&lab.a, 1, at)?;
    let (id, _) = pending(&mut owner, &lab.a, at)?;
    owner.confirm_admission(id.clone(), at)?;
    owner.confirm_written(id, at)?;
    unchanged(
        &mut owner,
        |o| o.confirm_admission(second, at),
        Error::EmissionLimited,
    );
    assert!(owner.pending(&lab.a, at)?.is_none());
    assert_eq!(
        owner.next_deadline(),
        Some(plus(at, cfg.emission_interval_micros)?)
    );
    for serial in 1..=256 {
        let bytes = encode(record(&owner, 1, serial, Body::Demand(Demand::default())))?;
        assert_eq!(
            owner.receive_authenticated(&lab.a, &bytes, at)?,
            Ingress::Accepted
        );
    }
    assert_eq!(owner.status().incoming_proofs, 1);
    let later = plus(at, 100_000)?;
    owner.tick(&lab.a, later)?;
    assert_eq!(owner.status().emission_remaining, 1);
    assert_eq!(owner.status().pending, 0);
    assert_eq!(owner.next_deadline(), None);
    owner.stage_demand(&lab.a, 1, later)?;
    let (id, _) = pending(&mut owner, &lab.a, later)?;
    owner.confirm_admission(id.clone(), later)?;
    owner.confirm_written(id, later)?;
    owner.stage_demand(&lab.a, 2, later)?;
    assert!(owner.pending(&lab.a, later)?.is_none());
    Ok(())
}

#[test]
fn echo_candidate_before_write_preserves_original_probe_and_no_public_sample() -> TestResult {
    let mut lab = Lab::new(1, 2)?;
    lab.establish()?;
    let at = lab.time();
    let mut a = Owner::new(config(), &lab.a, at)?;
    let mut b = Owner::new(config(), &lab.b, at)?;
    a.stage_probe(&lab.a, 1, at)?;
    let deadline = a.state.probe.ok_or("probe")?.deadline;
    let (request_id, request) = pending(&mut a, &lab.a, at)?;
    let req = wire::decode(&request)?;
    assert_eq!(req.header.direction, Direction::AcceptorToOriginator);
    let Body::EchoRequest { nonce } = req.body else {
        return Err("request".into());
    };
    let too_early = encode(record(&a, 1, 1, Body::EchoReply { nonce }))?;
    assert_eq!(
        a.receive_authenticated(&lab.a, &too_early, at)?,
        Ingress::Stale
    );
    let admitted = plus(at, 1000)?;
    a.confirm_admission(request_id.clone(), admitted)?;
    assert_eq!(a.state.probe.ok_or("probe")?.admitted_at, Some(admitted));
    assert_eq!(
        b.receive_authenticated(&lab.b, &request, admitted)?,
        Ingress::Accepted
    );
    let before = b.state.clone();
    assert_eq!(
        b.receive_authenticated(&lab.b, &request, admitted)?,
        Ingress::Duplicate
    );
    assert_eq!(b.state, before);
    let (reply_id, reply) = pending(&mut b, &lab.b, admitted)?;
    b.confirm_admission(reply_id.clone(), admitted)?;
    let receipt = plus(admitted, 1000)?;
    assert_eq!(
        a.receive_authenticated(&lab.a, &reply, receipt)?,
        Ingress::Accepted
    );
    let probe = a.state.probe.ok_or("early reply")?;
    assert!(!probe.written);
    assert_eq!(probe.reply_at, Some(receipt));
    assert_eq!(probe.deadline, deadline);
    assert_eq!(a.status().admitted, 1);
    a.confirm_written(request_id, plus(receipt, 1000)?)?;
    assert!(!a.status().probe_live);
    b.confirm_written(reply_id, receipt)?;
    assert_eq!(
        a.receive_authenticated(&lab.a, &reply, plus(receipt, 1000)?)?,
        Ingress::Duplicate
    );
    a.stage_probe(&lab.a, 1, plus(receipt, 1000)?)?;
    assert!(a.state.probe.ok_or("next nonce")?.nonce > nonce);
    Ok(())
}

#[test]
fn probe_and_pending_expiry_never_discard_admitted_proofs_or_renew_deadlines() -> TestResult {
    let mut lab = Lab::new(1, 2)?;
    lab.establish()?;
    let at = lab.time();
    let mut owner = Owner::new(config(), &lab.a, at)?;
    owner.stage_probe(&lab.a, 1, at)?;
    let (id, request) = pending(&mut owner, &lab.a, at)?;
    owner.confirm_admission(id.clone(), at)?;
    let Body::EchoRequest { nonce } = wire::decode(&request)?.body else {
        return Err("nonce".into());
    };
    let expired = plus(at, config().probe_timeout_micros)?;
    owner.tick(&lab.a, expired)?;
    assert!(!owner.status().probe_live);
    assert_eq!(owner.status().admitted, 1);
    let late = encode(record(&owner, 1, 1, Body::EchoReply { nonce }))?;
    assert_eq!(
        owner.receive_authenticated(&lab.a, &late, expired)?,
        Ingress::Stale
    );
    unchanged(
        &mut owner,
        |o| o.stage_probe(&lab.a, 1, expired),
        Error::ProbeBusy,
    );
    owner.confirm_written(id, expired)?;
    owner.stage_demand(&lab.a, 1, expired)?;
    let (id, _) = pending(&mut owner, &lab.a, expired)?;
    let ttl = plus(expired, config().pending_ttl_micros)?;
    unchanged(
        &mut owner,
        |o| o.confirm_admission(id, ttl),
        Error::OutputExpired,
    );
    owner.tick(&lab.a, ttl)?;
    assert_eq!(owner.status().pending, 0);
    assert_eq!(owner.next_deadline(), None);
    Ok(())
}

#[test]
fn original_handoff_deadline_is_terminal_for_every_callback() -> TestResult {
    let mut lab = Lab::new(1, 2)?;
    lab.establish()?;
    let at = lab.time();
    let mut owner = Owner::new(config(), &lab.a, at)?;
    owner.stage_demand(&lab.a, 1, at)?;
    let (id, _) = pending(&mut owner, &lab.a, at)?;
    owner.confirm_admission(id.clone(), at)?;
    let deadline = plus(at, config().handoff_timeout_micros)?;
    owner.quiesce(plus(at, 10_000)?)?;
    owner.quiesce(plus(at, 20_000)?)?;
    assert_eq!(owner.next_deadline(), Some(deadline));
    assert!(!owner.drained());
    let before = owner.state.clone();
    assert_eq!(owner.tick(&lab.a, deadline), Err(Error::HandoffExpired));
    let mut latched = before;
    latched.handoff_expired = true;
    assert_eq!(owner.state, latched);
    assert!(owner.status().handoff_expired);
    unchanged(
        &mut owner,
        |o| o.confirm_written(id, Micros(deadline.0 - 1)),
        Error::HandoffExpired,
    );
    let later = plus(deadline, 1_000)?;
    unchanged(&mut owner, |o| o.tick(&lab.a, later), Error::HandoffExpired);
    unchanged(&mut owner, |o| o.quiesce(later), Error::HandoffExpired);
    assert_eq!(owner.status().admitted, 1);
    assert_eq!(owner.next_deadline(), None);
    Ok(())
}

#[test]
fn terminal_and_quiesced_owners_drop_only_unadmitted_and_keep_duplicate_proofs() -> TestResult {
    let mut lab = Lab::new(1, 2)?;
    lab.establish()?;
    let at = lab.time();
    let mut owner = Owner::new(config(), &lab.a, at)?;
    owner.stage_demand(&lab.a, 1, at)?;
    let (id, _) = pending(&mut owner, &lab.a, at)?;
    owner.confirm_admission(id.clone(), at)?;
    owner.stage_demand(&lab.a, 1, at)?;
    let incoming = record(&owner, 1, 1, Body::Demand(Demand::default()));
    let bytes = encode(incoming)?;
    assert_eq!(
        owner.receive_authenticated(&lab.a, &bytes, at)?,
        Ingress::Accepted
    );
    lab.a.cancel(1, Millis(lab.now))?;
    owner.tick(&lab.a, at)?;
    assert_eq!(owner.status().pending, 0);
    assert_eq!(owner.status().admitted, 1);
    assert_eq!(
        owner.receive_authenticated(&lab.a, &bytes, at)?,
        Ingress::Duplicate
    );
    let mut novel = incoming;
    novel.header.serial = 2;
    assert_eq!(
        owner.receive_authenticated(&lab.a, &encode(novel)?, at)?,
        Ingress::Stale
    );
    let fresh = Owner::new(config(), &lab.a, at)?;
    assert_eq!(fresh.status().incoming_proofs, 0);
    owner.quiesce(at)?;
    assert!(!owner.drained());
    unchanged(
        &mut owner,
        |o| o.stage_demand(&lab.a, 1, at),
        Error::Quiesced,
    );
    owner.confirm_written(id, at)?;
    assert!(owner.drained());
    assert_eq!(owner.status().incoming_proofs, 1);
    assert_eq!(owner.next_deadline(), None);
    Ok(())
}

#[test]
fn checked_serial_nonce_reply_exhaustion_and_opening_flow_rejection() -> TestResult {
    let mut lab = Lab::new(1, 2)?;
    lab.establish()?;
    let at = lab.time();
    let mut owner = Owner::new(config(), &lab.a, at)?;
    owner.state.serial = u64::MAX;
    unchanged(
        &mut owner,
        |o| o.stage_demand(&lab.a, 1, at),
        Error::Exhausted,
    );
    let bytes = encode(record(&owner, 1, 1, Body::EchoRequest { nonce: 1 }))?;
    unchanged(
        &mut owner,
        |o| o.receive_authenticated(&lab.a, &bytes, at),
        Error::Exhausted,
    );
    owner.state.serial = 0;
    owner.state.nonce = u64::MAX;
    unchanged(
        &mut owner,
        |o| o.stage_probe(&lab.a, 1, at),
        Error::Exhausted,
    );
    owner.state.nonce = 0;
    assert_eq!(
        owner.receive_authenticated(&lab.a, &bytes, at)?,
        Ingress::Accepted
    );
    let reused = encode(record(&owner, 1, 2, Body::EchoRequest { nonce: 1 }))?;
    unchanged(
        &mut owner,
        |o| o.receive_authenticated(&lab.a, &reused, at),
        Error::Nonce,
    );
    // Build an actual allocated Opening, with no Ready/Commit handoff.
    let mut opening = session::Table::new(policy(2, session::Role::Originator), Millis(0))?;
    let mut host = TcpEngine::new_ip(opening.policy().native, Role::Client, Millis(0))?;
    host.poll(Millis(0), 4)?;
    opening.ingest_native(&host.pop_packet().ok_or("SYN")?, true, Millis(0))?;
    let mut waiting = Owner::new(config(), &opening, Micros(0))?;
    unchanged(
        &mut waiting,
        |o| o.stage_demand(&opening, 1, Micros(0)),
        Error::Flow,
    );
    let bytes = encode(record(&waiting, 1, 1, Body::Demand(Demand::default())))?;
    unchanged(
        &mut waiting,
        |o| o.receive_authenticated(&opening, &bytes, Micros(0)),
        Error::Flow,
    );
    waiting.quiesce(Micros(0))?;
    unchanged(
        &mut waiting,
        |o| o.receive_authenticated(&opening, &bytes, Micros(0)),
        Error::Flow,
    );
    Ok(())
}

#[test]
fn unadmitted_probe_ttl_and_creation_spacing_do_not_leave_or_renew_work() -> TestResult {
    let mut lab = Lab::new(1, 2)?;
    lab.establish()?;
    let at = lab.time();
    let cfg = OwnerConfig {
        pending_ttl_micros: 1_000,
        probe_interval_micros: 5_000,
        ..config()
    };
    let mut owner = Owner::new(cfg, &lab.a, at)?;
    owner.stage_probe(&lab.a, 1, at)?;
    let first_nonce = owner.state.probe.ok_or("probe")?.nonce;
    let (id, _) = pending(&mut owner, &lab.a, at)?;
    let expiry = plus(at, 1_000)?;
    unchanged(
        &mut owner,
        |o| o.confirm_admission(id, expiry),
        Error::OutputExpired,
    );
    owner.tick(&lab.a, expiry)?;
    assert!(!owner.status().probe_live);
    assert_eq!(owner.status().pending, 0);
    assert_eq!(owner.next_deadline(), None);
    unchanged(
        &mut owner,
        |o| o.stage_probe(&lab.a, 1, expiry),
        Error::ProbeBusy,
    );
    let later = plus(at, 5_000)?;
    owner.stage_probe(&lab.a, 1, later)?;
    assert!(owner.state.probe.ok_or("second probe")?.nonce > first_nonce);
    assert_eq!(owner.next_deadline(), Some(plus(later, 1_000)?));
    Ok(())
}

#[test]
fn reply_after_write_and_quiesce_never_create_new_response_or_samples() -> TestResult {
    let mut lab = Lab::new(1, 2)?;
    lab.establish()?;
    let at = lab.time();
    // Reverse roles exercise the complementary original-stream direction.
    let mut sender = Owner::new(config(), &lab.b, at)?;
    let mut receiver = Owner::new(config(), &lab.a, at)?;
    sender.stage_probe(&lab.b, 1, at)?;
    let (id, bytes) = pending(&mut sender, &lab.b, at)?;
    assert_eq!(
        wire::decode(&bytes)?.header.direction,
        Direction::OriginatorToAcceptor
    );
    sender.confirm_admission(id.clone(), at)?;
    sender.confirm_written(id, at)?;
    assert!(sender.status().probe_live);
    let later = plus(at, 1_000)?;
    assert_eq!(
        receiver.receive_authenticated(&lab.a, &bytes, later)?,
        Ingress::Accepted
    );
    let (_, reply) = pending(&mut receiver, &lab.a, later)?;
    assert_eq!(
        sender.receive_authenticated(&lab.b, &reply, later)?,
        Ingress::Accepted
    );
    assert!(!sender.status().probe_live);
    receiver.quiesce(later)?;
    assert!(receiver.drained());
    assert_eq!(receiver.status().pending, 0);
    assert_eq!(
        receiver.receive_authenticated(&lab.a, &bytes, later)?,
        Ingress::Duplicate
    );
    let Body::EchoRequest { nonce } = wire::decode(&bytes)?.body else {
        return Err("request".into());
    };
    let fresh = encode(record(
        &receiver,
        1,
        2,
        Body::EchoRequest { nonce: nonce + 1 },
    ))?;
    assert_eq!(
        receiver.receive_authenticated(&lab.a, &fresh, later)?,
        Ingress::Stale
    );
    assert!(receiver.pending(&lab.a, later)?.is_none());
    assert_eq!(receiver.status().incoming_proofs, 1);
    assert_eq!(receiver.next_deadline(), None);
    Ok(())
}

#[test]
fn retained_reply_coalesces_without_replacing_admitted_bytes_or_duplicate_deadline() -> TestResult {
    let mut lab = Lab::new(2, 2)?;
    lab.establish()?;
    let at = lab.time();
    let mut owner = Owner::new(config(), &lab.a, at)?;
    let request = encode(record(&owner, 1, 1, Body::EchoRequest { nonce: 1 }))?;
    assert_eq!(
        owner.receive_authenticated(&lab.a, &request, at)?,
        Ingress::Accepted
    );
    let (id, first) = pending(&mut owner, &lab.a, at)?;
    owner.confirm_admission(id.clone(), at)?;
    let deadline = owner.state.slots[id.slot]
        .admitted
        .as_ref()
        .ok_or("proof")?
        .deadline;
    for serial in 2..=256 {
        let request = encode(record(
            &owner,
            1,
            serial,
            Body::EchoRequest { nonce: serial },
        ))?;
        assert_eq!(
            owner.receive_authenticated(&lab.a, &request, at)?,
            Ingress::Accepted
        );
    }
    let slot = &owner.state.slots[id.slot];
    assert_eq!(
        slot.admitted.as_ref().ok_or("immutable")?.buffer.slice(),
        first
    );
    assert_eq!(
        slot.admitted.as_ref().ok_or("original deadline")?.deadline,
        deadline
    );
    assert_eq!(owner.status().pending, 1);
    assert_eq!(owner.status().admitted, 1);
    assert_eq!(owner.status().incoming_proofs, 1);
    let latest = encode(record(&owner, 1, 256, Body::EchoRequest { nonce: 256 }))?;
    let later = plus(at, 1_000)?;
    assert_eq!(
        owner.receive_authenticated(&lab.a, &latest, later)?,
        Ingress::Duplicate
    );
    assert_eq!(
        owner.state.slots[id.slot]
            .pending
            .as_ref()
            .ok_or("pending")?
            .deadline,
        plus(at, config().pending_ttl_micros)?
    );
    let across_flow = encode(record(&owner, 2, 1, Body::EchoRequest { nonce: 256 }))?;
    unchanged(
        &mut owner,
        |o| o.receive_authenticated(&lab.a, &across_flow, later),
        Error::Nonce,
    );
    owner.confirm_written(id, later)?;
    let (_, next) = pending(&mut owner, &lab.a, later)?;
    assert_eq!(wire::decode(&next)?.body, Body::EchoReply { nonce: 256 });
    Ok(())
}
