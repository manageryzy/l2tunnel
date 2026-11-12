use super::*;
use crate::{Millis, Role, TcpEngine, TcpIpConfig, TimeWaitResetPolicy};
use l2tunnel_flow_control::Credit;
use std::net::SocketAddr;
mod growth;
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn policy(role: session::Role) -> session::Config {
    session::Config {
        session: [31; 16],
        epoch: 3,
        role,
        max_flows: 2,
        max_policies: 16,
        native: TcpIpConfig {
            local: SocketAddr::from(([10, 43, 0, 1], 32000)),
            peer: SocketAddr::from(([10, 43, 0, 2], 443)),
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
fn config() -> MeasuredConfig {
    MeasuredConfig {
        allocation: adaptive::Config {
            minimum_per_flow: Window {
                bytes: 256,
                records: 1,
            },
            target: adaptive::TargetConfig {
                initial: Credit {
                    bytes: 512,
                    records: 2,
                },
                minimum: Credit {
                    bytes: 256,
                    records: 1,
                },
                session_cap: Credit {
                    bytes: 8192,
                    records: 32,
                },
                per_flow_cap: Credit {
                    bytes: 4096,
                    records: 16,
                },
                policy_cap: Credit {
                    bytes: 8192,
                    records: 32,
                },
                queue_allowance_bytes: 8192,
                queue_delay_target_micros: 5000,
                many_flow_step: Credit {
                    bytes: 256,
                    records: 1,
                },
                few_flow_threshold: 4,
                max_flows: 2,
                bootstrap_rtt_micros: 1000,
                recovery_rtts: 2,
            },
        },
        ownership: OwnerConfig {
            pending_ttl_micros: 20_000,
            probe_interval_micros: 2_000,
            probe_timeout_micros: 30_000,
            handoff_timeout_micros: 50_000,
            emission_interval_micros: 10_000,
            max_records_per_interval: 8,
        },
        observation: ObservationConfig {
            report_interval_micros: 2000,
            sample_ttl_micros: 40_000,
            demand_idle_micros: 10_000,
            rate_interval_micros: 10_000,
            rate_bins: 4,
        },
    }
}
fn exchange(a: &mut session::Table, b: &mut session::Table, now: Millis) -> TestResult {
    for id in 1..=a.status().flows as u64 {
        if let Some(bytes) = a.pending_record(id).map(<[u8]>::to_vec) {
            a.confirm_record_sent(id, now)?;
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
    fn new(count: usize) -> Result<Self, Box<dyn std::error::Error>> {
        let mut a = session::Table::new(policy(session::Role::Originator), Millis(0))?;
        let mut b = session::Table::new(policy(session::Role::Acceptor), Millis(0))?;
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
            assert_eq!(
                a.ingest_native(&client.pop_packet().ok_or("SYN")?, true, Millis(0))?,
                session::Disposition::Owned(index as u64 + 1)
            );
            hosts.push([client, server]);
        }
        exchange(&mut a, &mut b, Millis(1))?;
        exchange(&mut b, &mut a, Millis(2))?;
        exchange(&mut a, &mut b, Millis(3))?;
        let mut lab = Self {
            a,
            b,
            hosts,
            now: 3,
        };
        for _ in 0..100 {
            lab.step()?;
            if lab.hosts.iter().flatten().all(|h| h.status().established)
                && (1..=count as u64)
                    .all(|id| lab.b.credit_status(id).is_some_and(|c| c.granted.bytes > 0))
            {
                return Ok(lab);
            }
        }
        Err("actual native handshake did not complete".into())
    }
    fn step(&mut self) -> TestResult {
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
        exchange(&mut self.a, &mut self.b, now)?;
        exchange(&mut self.b, &mut self.a, now)?;
        Ok(())
    }
    fn at(&self) -> Micros {
        Micros(self.now * 1000)
    }
    fn transfer(&mut self, sizes: &[usize]) -> TestResult {
        for (index, size) in sizes.iter().enumerate() {
            assert_eq!(
                self.hosts[index][0].write(&vec![index as u8; *size])?,
                *size
            );
        }
        for _ in 0..100 {
            self.step()?;
            if sizes.iter().enumerate().all(|(index, size)| {
                self.b
                    .credit_status(index as u64 + 1)
                    .is_some_and(|c| c.acknowledged.bytes >= *size as u64)
            }) {
                return Ok(());
            }
        }
        Err("actual native ACK prefix did not progress".into())
    }
}
fn controller(table: &session::Table, at: Micros) -> Result<Controller, ControllerError> {
    let mut value = Controller::new(config(), table, at)?;
    for flow in 1..=table.status().flows as u64 {
        value.bind_flow(adaptive::FlowWeight { flow, weight: 1 })?;
    }
    Ok(value)
}
fn demand(
    table: &session::Table,
    serial: u64,
    value: wire::Demand,
) -> Result<Vec<u8>, wire::EncodeError> {
    let p = table.policy();
    let mut out = vec![0; wire::MAX_RECORD_BYTES];
    let size = wire::encode(
        wire::Record {
            header: wire::Header {
                scope: crate::Scope {
                    session: p.session,
                    epoch: p.epoch,
                    flow: 1,
                },
                direction: if p.role == session::Role::Acceptor {
                    wire::Direction::OriginatorToAcceptor
                } else {
                    wire::Direction::AcceptorToOriginator
                },
                serial,
            },
            body: wire::Body::Demand(value),
        },
        &mut out,
    )?;
    out.truncate(size);
    Ok(out)
}
fn empty(table: &session::Table, serial: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(demand(
        table,
        serial,
        wire::Demand {
            observed_grant: table.credit_status(1).ok_or("grant")?.granted,
            ..Default::default()
        },
    )?)
}
fn unread(table: &session::Table, serial: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(demand(
        table,
        serial,
        wire::Demand {
            observed_grant: table.credit_status(1).ok_or("grant")?.granted,
            native_unread_bytes: 1,
            ..Default::default()
        },
    )?)
}
fn request(
    c: &mut Controller,
    table: &session::Table,
    at: Micros,
) -> Result<(OutputId, Vec<u8>), Box<dyn std::error::Error>> {
    c.stage_probe(table, 1, at)?;
    let pending = c.pending(table, at)?.ok_or("request")?;
    let (id, bytes) = (pending.id, pending.bytes.to_vec());
    // One bounded fake common-MUX slot. These callbacks do not claim runtime I/O.
    let mut mux = Some((id.clone(), bytes.clone()));
    c.confirm_admission(id.clone(), at)?;
    let (_, retained) = mux.take().ok_or("bounded admission")?;
    Ok((id, retained))
}
fn reply(
    peer: &mut Owner,
    table: &session::Table,
    request: &[u8],
    at: Micros,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    assert_eq!(
        peer.receive_authenticated(table, request, at)?,
        Ingress::Accepted
    );
    let pending = peer.pending(table, at)?.ok_or("reply")?;
    let (id, bytes) = (pending.id, pending.bytes.to_vec());
    peer.confirm_admission(id.clone(), at)?;
    peer.confirm_written(id, at)?;
    Ok(bytes)
}
fn unchanged<T>(
    c: &mut Controller,
    operation: impl FnOnce(&mut Controller) -> Result<T, ControllerError>,
    expected: ControllerError,
) {
    let model = c.model.clone();
    let at = c.at;
    let revision = c.revision;
    let owner = c.owner.status();
    let planner = c.planner.status();
    assert_eq!(operation(c).err(), Some(expected));
    assert_eq!(c.model, model);
    assert_eq!(c.at, at);
    assert_eq!(c.revision, revision);
    assert_eq!(c.owner.status(), owner);
    assert_eq!(c.planner.status(), planner);
}

#[test]
fn config_and_preallocated_banks_are_finite_and_actual_table_bound() -> TestResult {
    let lab = Lab::new(1)?;
    let c = controller(&lab.b, lab.at())?;
    let memory = config().validate(&lab.b)?;
    assert_eq!(memory.flow_slots, 2);
    assert_eq!(memory.rate_bins, 4);
    assert_eq!(
        memory.scratch_bytes,
        2 * size_of::<model::Flow>() + 4 * size_of::<Option<model::Bin>>()
    );
    assert!(
        memory.retained_bytes
            > memory.record_owner.buffer_bytes + memory.record_owner.metadata_bytes
    );
    assert_eq!(c.model.flows.len(), c.scratch.flows.len());
    let mut variants = [config(); 5];
    variants[0].observation.rate_bins = 0;
    variants[1].observation.sample_ttl_micros = 29_999;
    variants[2].observation.demand_idle_micros = 1000;
    variants[3].observation.rate_interval_micros = u64::MAX;
    variants[4].observation.rate_interval_micros = 120_000_000;
    for config in variants {
        assert_eq!(
            config.validate(&lab.b).err(),
            Some(ControllerError::Configuration)
        );
    }
    assert!(Controller::new(config(), &lab.b, Micros(u64::MAX)).is_err());
    let other = session::Table::new(lab.b.policy(), Millis(0))?;
    assert_eq!(
        c.observations(&other, lab.at()).err(),
        Some(ControllerError::Owner)
    );
    Ok(())
}

#[test]
fn actual_multiflow_ack_bytes_use_one_elapsed_bin_and_first_history_is_not_rate() -> TestResult {
    let mut lab = Lab::new(2)?;
    let start = lab.at();
    let mut c = controller(&lab.b, start)?;
    c.observe_table(&lab.b, start)?;
    lab.transfer(&[128, 256])?;
    assert!(lab.at().0 <= start.0 + 20_000);
    let finish = Micros((start.0 + 10_000).max(lab.at().0));
    c.observe_table(&lab.b, finish)?;
    let rate = c
        .observations(&lab.b, finish)?
        .ack_rate
        .ok_or("completed rate")?;
    assert_eq!(rate.bytes, 384);
    assert_eq!(rate.elapsed_micros, finish.0 - start.0);
    assert_eq!(rate.bytes_per_second, 384_000_000 / rate.elapsed_micros);
    assert_eq!(rate.bins, 1);
    c.observe_table(&lab.b, finish)?;
    assert_eq!(c.observations(&lab.b, finish)?.ack_rate, Some(rate));
    let mut attached = controller(&lab.b, finish)?;
    attached.observe_table(&lab.b, finish)?;
    attached.observe_table(&lab.b, Micros(finish.0 + 10_000))?;
    let status = attached.observations(&lab.b, Micros(finish.0 + 10_000))?;
    assert!(status.zero_delivery);
    assert_eq!(status.ack_rate.ok_or("zero bin")?.bytes, 0);
    Ok(())
}

#[test]
fn both_table_roles_measure_only_their_incoming_original_ack_direction() -> TestResult {
    let mut lab = Lab::new(1)?;
    let start = lab.at();
    let mut a = controller(&lab.a, start)?;
    let mut b = controller(&lab.b, start)?;
    a.observe_table(&lab.a, start)?;
    b.observe_table(&lab.b, start)?;
    assert_eq!(lab.hosts[0][0].write(&[1; 128])?, 128);
    assert_eq!(lab.hosts[0][1].write(&[2; 256])?, 256);
    for _ in 0..10 {
        lab.step()?;
    }
    let at = lab.at();
    assert_eq!(
        lab.a.credit_status(1).ok_or("A ACK")?.acknowledged.bytes,
        256
    );
    assert_eq!(
        lab.b.credit_status(1).ok_or("B ACK")?.acknowledged.bytes,
        128
    );
    a.observe_table(&lab.a, at)?;
    b.observe_table(&lab.b, at)?;
    assert_eq!(
        a.observations(&lab.a, at)?.ack_rate.ok_or("A rate")?.bytes,
        256
    );
    assert_eq!(
        b.observations(&lab.b, at)?.ack_rate.ok_or("B rate")?.bytes,
        128
    );
    Ok(())
}

#[test]
fn zero_bins_ttl_and_large_gaps_never_invent_catchup_rate() -> TestResult {
    let lab = Lab::new(1)?;
    let start = lab.at();
    let mut c = controller(&lab.b, start)?;
    c.observe_table(&lab.b, start)?;
    c.observe_table(&lab.b, Micros(start.0 + 10_000))?;
    let zero = c.observations(&lab.b, Micros(start.0 + 10_000))?;
    assert!(zero.zero_delivery);
    assert_eq!(zero.ack_rate.ok_or("zero")?.bytes_per_second, 0);
    assert!(
        c.observations(&lab.b, Micros(start.0 + 50_000))?
            .ack_rate
            .is_none()
    );
    c.observe_table(&lab.b, Micros(start.0 + 40_001))?;
    assert!(
        c.observations(&lab.b, Micros(start.0 + 40_001))?
            .ack_rate
            .is_none()
    );
    assert_eq!(c.model.latest_bin, Some(Micros(start.0 + 10_000)));
    c.observe_table(&lab.b, Micros(start.0 + 60_001))?; // inclusive twice-interval bound
    let rate = c
        .observations(&lab.b, Micros(start.0 + 60_001))?
        .ack_rate
        .ok_or("one real bin")?;
    assert_eq!(rate.bins, 1);
    assert_eq!(rate.elapsed_micros, 20_000);
    Ok(())
}

#[test]
fn final_terminal_ack_counts_once_and_attach_after_stop_keeps_history_baseline() -> TestResult {
    let mut lab = Lab::new(1)?;
    let start = lab.at();
    let mut c = controller(&lab.b, start)?;
    c.observe_table(&lab.b, start)?;
    lab.transfer(&[256])?;
    let frozen = lab.b.credit_status(1).ok_or("credit")?;
    lab.b.cancel(1, Millis(lab.now))?;
    assert_eq!(lab.b.credit_status(1), Some(frozen));
    let at = Micros(start.0 + 10_000);
    c.observe_table(&lab.b, at)?;
    assert_eq!(
        c.observations(&lab.b, at)?
            .ack_rate
            .ok_or("terminal rate")?
            .bytes,
        256
    );
    c.observe_table(&lab.b, Micros(at.0 + 10_000))?;
    assert_eq!(
        c.observations(&lab.b, Micros(at.0 + 10_000))?
            .ack_rate
            .ok_or("retained rate")?
            .bytes,
        256
    );
    let mut after = controller(&lab.b, at)?;
    after.observe_table(&lab.b, at)?;
    after.observe_table(&lab.b, Micros(at.0 + 10_000))?;
    assert!(
        after
            .observations(&lab.b, Micros(at.0 + 10_000))?
            .zero_delivery
    );
    Ok(())
}

#[test]
fn authenticated_demand_duplicates_idle_and_stale_gap_preserve_exact_freshness() -> TestResult {
    let lab = Lab::new(1)?;
    let at = lab.at();
    let mut c = controller(&lab.b, at)?;
    assert_eq!(c.observations(&lab.b, at)?.unknown_flows, 1);
    let initial = empty(&lab.b, 1)?;
    assert_eq!(
        c.receive_authenticated(&lab.b, &initial, at)?,
        Ingress::Accepted
    );
    assert_eq!(
        c.receive_authenticated(&lab.b, &initial, Micros(at.0 + 2000))?,
        Ingress::Duplicate
    );
    assert_eq!(c.model.flows[0].report.ok_or("report")?.at, at);
    c.receive_authenticated(&lab.b, &empty(&lab.b, 2)?, Micros(at.0 + 9000))?;
    let plan = c.prepare(&lab.b, LocalPressure::default(), Micros(at.0 + 10_000))?;
    assert_eq!(plan.allocation().candidate, Window::default());
    let stale = c.observations(&lab.b, Micros(at.0 + 49_000))?;
    assert_eq!(stale.unknown_flows, 1);
    assert_eq!(stale.demanding_flows, 0);
    c.receive_authenticated(&lab.b, &empty(&lab.b, 3)?, Micros(at.0 + 50_000))?;
    assert_eq!(
        c.observations(&lab.b, Micros(at.0 + 50_000))?
            .demanding_flows,
        0
    );
    c.receive_authenticated(&lab.b, &unread(&lab.b, 4)?, Micros(at.0 + 51_000))?;
    assert_eq!(
        c.observations(&lab.b, Micros(at.0 + 51_000))?
            .demanding_flows,
        1
    );
    c.receive_authenticated(&lab.b, &empty(&lab.b, 5)?, Micros(at.0 + 52_000))?;
    let plan = c.prepare(&lab.b, LocalPressure::default(), Micros(at.0 + 61_999))?;
    assert_ne!(plan.allocation().candidate, Window::default());
    let plan = c.prepare(&lab.b, LocalPressure::default(), Micros(at.0 + 62_000))?;
    assert_eq!(plan.allocation().candidate, Window::default());
    assert!(
        c.observations(&lab.b, Micros(at.0 + 62_000))?
            .ack_rate
            .is_none()
    );
    Ok(())
}

#[test]
fn echo_early_reply_late_flush_uses_original_times_and_duplicate_never_refreshes() -> TestResult {
    let mut lab = Lab::new(1)?;
    let at = lab.at();
    let mut c = controller(&lab.b, at)?;
    let mut peer = Owner::new(config().ownership, &lab.a, at)?;
    let (id, request) = request(&mut c, &lab.b, at)?;
    let reply = reply(&mut peer, &lab.a, &request, Micros(at.0 + 1000))?;
    c.receive_authenticated(&lab.b, &reply, Micros(at.0 + 3000))?;
    assert!(
        c.observations(&lab.b, Micros(at.0 + 3000))?
            .service_latency
            .is_none()
    );
    c.confirm_written(&lab.b, id, Micros(at.0 + 9000))?;
    let sample = c
        .observations(&lab.b, Micros(at.0 + 9000))?
        .service_latency
        .ok_or("service sample")?;
    assert_eq!(sample.smoothed_micros, 3000);
    assert_eq!(sample.admitted_at, at);
    assert_eq!(sample.reply_at, Micros(at.0 + 3000));
    assert_eq!(
        c.receive_authenticated(&lab.b, &reply, Micros(at.0 + 15_000))?,
        Ingress::Duplicate
    );
    assert_eq!(
        c.observations(&lab.b, Micros(at.0 + 15_000))?
            .service_latency,
        Some(sample)
    );
    lab.b.cancel(1, Millis((at.0 + 16_000) / 1000))?;
    assert_eq!(
        c.observations(&lab.b, Micros(at.0 + 16_000))?
            .service_latency,
        Some(sample),
        "retirement after completion cannot rewrite original service evidence"
    );
    assert!(
        !c.observations(&lab.b, Micros(at.0 + 43_000))?
            .service_latency
            .ok_or("stale sample")?
            .fresh
    );
    Ok(())
}

#[test]
fn service_smoothing_restarts_after_stale_history_without_peer_timestamps() -> TestResult {
    let lab = Lab::new(1)?;
    let at = lab.at();
    let mut c = controller(&lab.b, at)?;
    let mut peer = Owner::new(config().ownership, &lab.a, at)?;
    for (created, latency, expected) in
        [(0, 3000, 3000), (50_000, 7000, 7000), (60_000, 2000, 6375)]
    {
        let start = Micros(at.0 + created);
        let (id, request) = request(&mut c, &lab.b, start)?;
        c.confirm_written(&lab.b, id, start)?;
        let response = reply(&mut peer, &lab.a, &request, Micros(start.0 + 1000))?;
        c.receive_authenticated(&lab.b, &response, Micros(start.0 + latency))?;
        assert_eq!(
            c.observations(&lab.b, Micros(start.0 + latency))?
                .service_latency
                .ok_or("sample")?
                .smoothed_micros,
            expected
        );
    }
    Ok(())
}

#[test]
fn prepare_watermark_blocks_older_callbacks_before_handoff_expiry_and_keeps_probe_deadline()
-> TestResult {
    let lab = Lab::new(1)?;
    let at = lab.at();
    let mut c = controller(&lab.b, at)?;
    let mut peer = Owner::new(config().ownership, &lab.a, at)?;
    let (id, request) = request(&mut c, &lab.b, at)?;
    let response = reply(&mut peer, &lab.a, &request, Micros(at.0 + 1000))?;
    c.receive_authenticated(&lab.b, &response, Micros(at.0 + 2000))?;
    let future = Micros(at.0 + 31_000);
    let plan = c.prepare(&lab.b, LocalPressure::default(), future)?;
    unchanged(
        &mut c,
        |c| c.confirm_written(&lab.b, id.clone(), Micros(at.0 + 29_000)),
        ControllerError::Time,
    );
    assert_eq!(
        c.next_deadline(),
        Some(Micros(at.0 + 30_000)),
        "live B deadline must not be filtered by Controller time"
    );
    c.tick(&lab.b, future)?;
    assert!(!c.owner.status().probe_live);
    assert!(c.next_deadline().is_some_and(|deadline| deadline > future));
    assert_eq!(
        c.apply(
            &mut { session::Table::new(lab.b.policy(), Millis(0))? },
            plan,
            future
        )
        .err(),
        Some(ControllerError::Owner)
    );
    c.confirm_written(&lab.b, id, Micros(at.0 + 32_000))?;
    assert!(
        c.observations(&lab.b, Micros(at.0 + 32_000))?
            .service_latency
            .is_none()
    );
    Ok(())
}

#[test]
fn recoverable_preflight_and_invalid_tokens_do_not_consume_echo_or_authority() -> TestResult {
    let lab = Lab::new(1)?;
    let at = lab.at();
    let mut c = controller(&lab.b, at)?;
    let mut peer = Owner::new(config().ownership, &lab.a, at)?;
    let (id, request_bytes) = request(&mut c, &lab.b, at)?;
    let response = reply(&mut peer, &lab.a, &request_bytes, Micros(at.0 + 1000))?;
    c.receive_authenticated(&lab.b, &response, Micros(at.0 + 2000))?;
    unchanged(
        &mut c,
        |c| {
            c.prepare(
                &lab.b,
                LocalPressure {
                    queue_delay_micros: u64::MAX,
                    ..Default::default()
                },
                Micros(at.0 + 31_000),
            )
        },
        ControllerError::Configuration,
    );
    let mut other = controller(&lab.b, at)?;
    let (foreign, _) = request(&mut other, &lab.b, at)?;
    unchanged(
        &mut c,
        |c| c.confirm_written(&lab.b, foreign, Micros(at.0 + 3000)),
        ControllerError::Record(owner::Error::Owner),
    );
    c.confirm_written(&lab.b, id, Micros(at.0 + 4000))?;
    assert_eq!(
        c.observations(&lab.b, Micros(at.0 + 4000))?
            .service_latency
            .ok_or("still eligible")?
            .smoothed_micros,
        2000
    );
    Ok(())
}

#[test]
fn quiesce_terminal_flow_and_sticky_handoff_failure_cannot_complete_candidates() -> TestResult {
    for terminal in [false, true] {
        let mut lab = Lab::new(1)?;
        let at = lab.at();
        let mut c = controller(&lab.b, at)?;
        let mut peer = Owner::new(config().ownership, &lab.a, at)?;
        let (id, request) = request(&mut c, &lab.b, at)?;
        let response = reply(&mut peer, &lab.a, &request, Micros(at.0 + 1000))?;
        c.receive_authenticated(&lab.b, &response, Micros(at.0 + 2000))?;
        if terminal {
            lab.b.cancel(1, Millis((at.0 + 3000) / 1000))?;
        } else {
            c.quiesce(Micros(at.0 + 3000))?;
        }
        c.confirm_written(&lab.b, id, Micros(at.0 + 4000))?;
        assert!(
            c.observations(&lab.b, Micros(at.0 + 4000))?
                .service_latency
                .is_none()
        );
        c.quiesce(Micros(at.0 + 4000))?;
        assert!(c.drained());
    }
    let lab = Lab::new(1)?;
    let at = lab.at();
    let mut c = controller(&lab.b, at)?;
    let (id, _) = request(&mut c, &lab.b, at)?;
    let error = ControllerError::Record(owner::Error::HandoffExpired);
    assert_eq!(
        c.prepare(&lab.b, LocalPressure::default(), Micros(at.0 + 50_000))
            .err(),
        Some(error)
    );
    assert_eq!(
        c.confirm_written(&lab.b, id, Micros(at.0 + 10_000)).err(),
        Some(error)
    );
    assert_eq!(c.owner.status().admitted, 1);
    assert!(!c.drained());
    Ok(())
}

#[test]
fn measured_plans_bind_both_revisions_time_owner_and_actual_table_snapshot() -> TestResult {
    let mut lab = Lab::new(1)?;
    let at = lab.at();
    let mut c = controller(&lab.b, at)?;
    let old = c.prepare(&lab.b, LocalPressure::default(), at)?;
    let plan = c.prepare(&lab.b, LocalPressure::default(), at)?;
    let credit = lab.b.credit_status(1);
    assert_eq!(
        c.apply(&mut lab.b, old, at).err(),
        Some(ControllerError::StalePlan)
    );
    assert_eq!(lab.b.credit_status(1), credit);
    let mut foreign = controller(&lab.b, at)?;
    assert_eq!(
        foreign.apply(&mut lab.b, plan, at).err(),
        Some(ControllerError::Owner)
    );
    let later = Micros(at.0 + 1000);
    let plan = c.prepare(&lab.b, LocalPressure::default(), later)?;
    assert_eq!(
        c.apply(&mut lab.b, plan, at).err(),
        Some(ControllerError::Time)
    );
    let plan = c.prepare(&lab.b, LocalPressure::default(), later)?;
    lab.b.set_target(
        1,
        Window {
            bytes: 1024,
            records: 4,
        },
    )?;
    let revision = c.revision;
    let planner = c.planner.status();
    assert_eq!(
        c.apply(&mut lab.b, plan, later).err(),
        Some(ControllerError::Allocation(adaptive::Error::StalePlan))
    );
    assert_eq!(c.revision, revision);
    assert_eq!(c.planner.status(), planner);
    let plan = c.prepare(
        &lab.b,
        LocalPressure {
            receiver_pressure: true,
            ..Default::default()
        },
        later,
    )?;
    let result = c.apply(&mut lab.b, plan, later)?;
    assert!(result.reserved.bytes >= credit.ok_or("grant")?.granted.bytes);
    Ok(())
}

#[test]
fn observation_overflow_and_revision_exhaustion_are_explicit_without_partial_b_mutation()
-> TestResult {
    let mut lab = Lab::new(1)?;
    let start = lab.at();
    let mut c = controller(&lab.b, start)?;
    unchanged(
        &mut c,
        |c| c.observe_table(&lab.b, Micros(u64::MAX - 100_000)),
        ControllerError::Time,
    );
    c.observe_table(&lab.b, start)?;
    lab.transfer(&[1])?;
    c.model.accumulated = u128::MAX;
    unchanged(
        &mut c,
        |c| c.observe_table(&lab.b, lab.at()),
        ControllerError::Accounting,
    );
    c.model.accumulated = 0;
    c.model.flows[0].baseline = Some(Window {
        bytes: u64::MAX,
        records: 1,
    });
    unchanged(
        &mut c,
        |c| c.observe_table(&lab.b, lab.at()),
        ControllerError::Accounting,
    );
    c.revision = u64::MAX;
    let owner = c.owner.status();
    assert_eq!(
        c.tick(&lab.b, lab.at()).err(),
        Some(ControllerError::Exhausted)
    );
    assert_eq!(c.owner.status(), owner);
    assert_eq!(
        c.bind_flow(adaptive::FlowWeight { flow: 1, weight: 1 })
            .err(),
        Some(ControllerError::Exhausted)
    );
    Ok(())
}
