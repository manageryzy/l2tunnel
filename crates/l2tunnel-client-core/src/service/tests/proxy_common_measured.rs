//! Finite measured Common slice over actual authenticated protected UDP.
//! Maintained native peers create real receive-window pressure without a kernel
//! TCP/cwnd qualification claim. Exact callback identity is tested at the bridge.
use super::*;
use crate::proxy_measured::{
    AckRate, Aggregate, AppliedTargets, Carrier, ServiceLatency, TargetPhase, UdpCover,
};
use l2tunnel_flow_control::Credit;
use l2tunnel_raw_tcp::{Error as TcpError, ReadOutcome, TcpEngine};
use l2tunnel_tcp_proxy::{Millis, Role as TcpRole, TcpIpConfig, Window, adaptive, measurement};

pub(super) fn config(
    fixed: l2tunnel_runtime::proxy::Config,
) -> io::Result<l2tunnel_runtime::proxy::measured::Config> {
    let max_flows = fixed.relay.max_flows;
    let cap = Credit {
        bytes: fixed.relay.maximum.bytes * max_flows as u64,
        records: fixed.relay.maximum.records * max_flows as u64,
    };
    let value = l2tunnel_runtime::proxy::measured::Config {
        measured: measurement::MeasuredConfig {
            allocation: adaptive::Config {
                target: adaptive::TargetConfig {
                    initial: Credit {
                        bytes: fixed.relay.initial.bytes,
                        records: fixed.relay.initial.records,
                    },
                    minimum: Credit {
                        bytes: 512,
                        records: 1,
                    },
                    session_cap: cap,
                    per_flow_cap: Credit {
                        bytes: fixed.relay.maximum.bytes,
                        records: fixed.relay.maximum.records,
                    },
                    policy_cap: cap,
                    queue_allowance_bytes: 4096,
                    queue_delay_target_micros: 5000,
                    many_flow_step: Credit {
                        bytes: 512,
                        records: 1,
                    },
                    few_flow_threshold: 4,
                    max_flows,
                    bootstrap_rtt_micros: 1000,
                    recovery_rtts: 2,
                },
                minimum_per_flow: Window {
                    bytes: 512,
                    records: 1,
                },
            },
            ownership: measurement::OwnerConfig {
                pending_ttl_micros: 20000,
                probe_interval_micros: 10000,
                probe_timeout_micros: 30000,
                handoff_timeout_micros: 50000,
                emission_interval_micros: 10000,
                max_records_per_interval: 8,
            },
            observation: measurement::ObservationConfig {
                report_interval_micros: 10000,
                sample_ttl_micros: 40000,
                demand_idle_micros: 20000,
                rate_interval_micros: 10000,
                rate_bins: 4,
            },
        },
        service: l2tunnel_runtime::proxy::measured::ServicePolicy {
            report_work_per_turn: 4,
            admission_work_per_turn: 4,
            callback_work_per_turn: 4,
            plan_interval_micros: 10000,
            status_interval_micros: 1000,
        },
        fixed,
    };
    value.validate()?;
    Ok(value)
}

#[derive(Default, Debug)]
struct Evidence {
    ack: [bool; 2],
    echo: [bool; 2],
    kinds: [[u64; 3]; 2],
    physical_packets: [u64; 2],
    physical_bytes: [u64; 2],
    initial_packets: [u64; 2],
    initial_bytes: [u64; 2],
    revisions: [u64; 2],
    observed_at: [u64; 2],
    ack_sample: [Option<AckRate>; 2],
    echo_sample: [Option<ServiceLatency>; 2],
    framed_bytes: [u64; 2],
    pressure_target: Option<AppliedTargets>,
    cleared_target: Option<AppliedTargets>,
    growth_after_pressure: Option<AppliedTargets>,
    pressure: bool,
    reduced: bool,
    cleared: bool,
}
impl Evidence {
    fn observe(&mut self, handles: &[Handle; 2]) -> Result<[Aggregate; 2]> {
        let mut observations = Vec::with_capacity(2);
        for (side, handle) in handles.iter().enumerate() {
            let frame = proxy_frame(handle)?;
            if frame
                .runtime
                .as_ref()
                .is_some_and(|s| s.phase == l2tunnel_runtime::proxy::Phase::Failed)
            {
                return Err(format!("measured Common actor failed: {frame:?}").into());
            }
            assert!(frame.common_record_composition && !frame.exact_tcp_rwnd_control);
            assert_eq!(frame.requested_profile, ProxyProfile::MeasuredRelay);
            assert_eq!(frame.effective_profile, ProxyProfile::MeasuredRelay);
            assert_eq!(frame.requested_digest, frame.effective_digest);
            let common = frame.common.ok_or("actual Common status")?;
            assert!(common.installed && common.running && common.graceful_close);
            assert!(!common.hot_switch);
            assert_eq!(
                common.requested_configuration,
                common.effective_configuration
            );
            assert_eq!(common.requested_carrier, common.effective_carrier);
            assert_eq!(Some(common.requested_cover), common.effective_cover);
            assert!(common.socket_accepted_packets >= self.physical_packets[side]);
            assert!(common.socket_accepted_ip_bytes >= self.physical_bytes[side]);
            self.physical_packets[side] = common.socket_accepted_packets;
            self.physical_bytes[side] = common.socket_accepted_ip_bytes;
            let snapshot = frame.measured.ok_or("actual measured status")?;
            let capabilities = snapshot.capabilities;
            assert_eq!(capabilities.requested_carrier, Carrier::CommonUdp);
            assert_eq!(capabilities.effective_carrier, Some(Carrier::CommonUdp));
            assert_eq!(capabilities.requested_udp_cover, UdpCover::QuicLike);
            assert_eq!(capabilities.effective_udp_cover, Some(UdpCover::QuicLike));
            assert!(capabilities.measured_relay_targets);
            assert!(!capabilities.exact_tcp_rwnd_control && !capabilities.native_tcp_cwnd);
            assert!(!capabilities.native_tcp_rtt && !capabilities.native_window_qualified);
            let aggregate = snapshot.aggregate.ok_or("actual Controller aggregate")?;
            assert!(!aggregate.failed && !aggregate.quiescing);
            assert!(aggregate.authoritative_at_micros <= aggregate.at_micros);
            if let Some(rate) = &aggregate.ack_rate {
                assert!(rate.elapsed_micros > 0 && rate.bins > 0);
                assert!(rate.latest_at_micros <= aggregate.at_micros);
                if rate.bytes > 0 && rate.bytes_per_second > 0 {
                    self.ack[side] = true;
                    self.ack_sample[side] = Some(rate.clone());
                }
            }
            if let Some(latency) = &aggregate.service_latency {
                assert!(latency.admitted_at_micros <= latency.reply_at_micros);
                assert!(latency.reply_at_micros <= aggregate.at_micros);
                if latency.fresh && latency.smoothed_micros > 0 {
                    self.echo[side] = true;
                    self.echo_sample[side] = Some(latency.clone());
                }
            }
            for kind in 0..3 {
                assert!(aggregate.admitted_by_kind[kind] >= self.kinds[side][kind]);
            }
            self.kinds[side] = aggregate.admitted_by_kind;
            self.framed_bytes[side] = aggregate.admitted_framed_bytes;
            self.observed_at[side] = aggregate.at_micros;
            if let Some(applied) = &aggregate.applied {
                assert!(applied.revision >= self.revisions[side]);
                self.revisions[side] = applied.revision;
                // Probing is emitted only for an actual measured, utilized,
                // quiet-interval target increase; revision alone is not growth.
                if side == 1
                    && self.cleared
                    && applied.phase == TargetPhase::Probing
                    && self
                        .pressure_target
                        .as_ref()
                        .is_some_and(|pressure| applied.candidate_bytes > pressure.candidate_bytes)
                {
                    self.growth_after_pressure = Some(applied.clone());
                }
            }
            observations.push(aggregate);
        }
        observations
            .try_into()
            .map_err(|_| "two actual observations required".into())
    }
    fn measurements(&self) -> bool {
        self.ack == [true; 2]
            && self.echo == [true; 2]
            && self
                .kinds
                .iter()
                .all(|kinds| kinds.iter().all(|count| *count > 0))
            && (0..2).all(|side| {
                self.physical_packets[side] > self.initial_packets[side]
                    && self.physical_bytes[side] > self.initial_bytes[side]
                    && self.revisions[side] > 1
            })
    }
}

fn native_peers() -> Result<[TcpEngine; 2]> {
    let local: std::net::SocketAddr = ([10, 112, 0, 1], 32001).into();
    let peer: std::net::SocketAddr = ([10, 112, 0, 2], 443).into();
    let make = |server| -> Result<TcpEngine> {
        Ok(TcpEngine::new_ip(
            TcpIpConfig {
                local: if server { peer } else { local },
                peer: if server { local } else { peer },
                mtu: 1280,
                send_bytes: 4096,
                receive_bytes: 4096,
                packet_slots: 8,
                random_seed: if server { 59 } else { 37 },
                ack_delay_millis: 0,
                keepalive_millis: 1000,
                idle_timeout_millis: 30000,
            },
            if server {
                TcpRole::Server
            } else {
                TcpRole::Client
            },
            Millis(0),
        )?)
    };
    Ok([make(false)?, make(true)?])
}
fn pump(engine: &mut TcpEngine, host: &Host, start: Instant) -> Result {
    engine.poll(Millis(start.elapsed().as_millis().try_into()?), 16)?;
    while let Some(packet) = engine.pop_packet() {
        host.send(&packet)?;
    }
    let mut packet = [0; 2048];
    let application = host
        .application
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let socket = application.as_ref().ok_or("actual native attachment")?;
    for _ in 0..4 {
        match socket.recv(&mut packet) {
            Ok(bytes) => engine.ingest(&packet[..bytes])?,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

async fn measured_pressure(hosts: &[Arc<Host>; 2], handles: &[Handle; 2]) -> Result<Evidence> {
    let mut engines = native_peers()?;
    let inputs = [
        (0..32769).map(|i| (i % 251) as u8).collect::<Vec<_>>(),
        (0..16387).map(|i| (i % 239) as u8).collect::<Vec<_>>(),
    ];
    let start = Instant::now();
    let mut sent = [0; 2];
    let mut got = [Vec::new(), Vec::new()];
    let mut closed = [false; 2];
    let mut eof = [false; 2];
    let mut evidence = Evidence::default();
    evidence.observe(handles)?;
    evidence.initial_packets = evidence.physical_packets;
    evidence.initial_bytes = evidence.physical_bytes;
    let mut pressure_since = None;
    let mut pressure_progress = None;
    let mut resume = false;
    timeout(Duration::from_secs(15), async {
        loop {
            for side in 0..2 {
                let engine = &mut engines[side];
                if sent[side] < inputs[side].len() {
                    match engine.write(&inputs[side][sent[side]..]) {
                        Ok(bytes) => sent[side] += bytes,
                        Err(TcpError::NotConnected) => {}
                        Err(error) => return Err(Error::from(error)),
                    }
                }
                // Withhold only the destination application's reads. All packet
                // ingress, ACK/window processing and Common management stay live.
                if side == 0 || resume {
                    let mut output = [0; 777];
                    match engine.read(&mut output)? {
                        ReadOutcome::Data(bytes) => got[side].extend_from_slice(&output[..bytes]),
                        ReadOutcome::Eof => eof[side] = true,
                        ReadOutcome::Pending => {}
                    }
                }
                if evidence.cleared && evidence.growth_after_pressure.is_some() && evidence.measurements()
                    && got[0].len() == inputs[1].len() && got[1].len() == inputs[0].len()
                    && !closed[side]
                {
                    engine.close();
                    closed[side] = true;
                }
                pump(engine, &hosts[side], start)?;
            }
            let aggregates = evidence.observe(handles)?;
            if !resume && aggregates[1].receiver_pressure {
                assert_eq!(engines[1].status().receive_bytes, 4096);
                assert!(!aggregates[0].receiver_pressure,
                    "source grant exhaustion must not become downstream pressure");
                evidence.pressure = true;
                if let Some(applied) = &aggregates[1].applied
                    && applied.phase == TargetPhase::Backpressure && applied.candidate_bytes < 1024 {
                    evidence.reduced = true;
                    evidence.pressure_target = Some(applied.clone());
                }
                pressure_since.get_or_insert_with(Instant::now);
                if pressure_progress.is_none() {
                    pressure_progress = Some((
                        evidence.physical_packets,
                        evidence.kinds,
                        aggregates.each_ref().map(|a| a.service_latency.as_ref().map_or(0, |l| l.reply_at_micros)),
                    ));
                }
            }
            if let (Some(since), Some((packets, kinds, replies))) = (pressure_since, pressure_progress) {
                let live = handles.iter().all(|handle| proxy_frame(handle).ok()
                    .and_then(|frame| frame.common)
                    .is_some_and(|common| common.liveness.last_pong_micros.is_some()));
                if since.elapsed() >= Duration::from_millis(100) && evidence.reduced && live
                    && (0..2).all(|side| evidence.physical_packets[side] > packets[side]
                        && evidence.kinds[side][1] > kinds[side][1]
                        && aggregates[side].service_latency.as_ref().is_some_and(|latency|
                            latency.fresh && latency.reply_at_micros > replies[side]))
                {
                    resume = true;
                }
            }
            if resume && !aggregates[1].receiver_pressure && got[1].len() > 4096 {
                evidence.cleared = true;
                evidence.cleared_target = aggregates[1].applied.clone();
            }
            if eof == [true; 2] {
                return Ok::<_, Error>(());
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }).await.map_err(|error| format!("native measured fixture timed out: {error}; {evidence:?}; sent={sent:?}, received={:?}, native={:?}",
        [got[0].len(), got[1].len()], engines.each_ref().map(TcpEngine::status)))??;
    assert_eq!(got[0], inputs[1]);
    assert_eq!(got[1], inputs[0]);
    assert!(evidence.pressure && evidence.reduced && evidence.cleared);
    assert!(
        evidence.growth_after_pressure.is_some(),
        "no qualified measured growth: {evidence:?}"
    );
    assert!(
        evidence.measurements(),
        "missing actual measured evidence: {evidence:?}"
    );
    Ok(evidence)
}

#[tokio::test]
async fn measured_common_real_udp_native_pressure_measurements_and_retained_close() -> Result {
    timeout(Duration::from_secs(35), async {
        let hosts = support::hosts();
        let ([a, b], profile) = fixture_profile(&hosts, true, true)?;
        assert!(profile.proxy_measured_config().is_some() && profile.proxy_retirement());
        let (client, client_run) = channel();
        let (server, server_run) = channel();
        let tasks = [tokio::spawn(client_run), tokio::spawn(server_run)];
        let accepted = [
            client.connect(a, client.next_key().map_err(submit)?).map_err(submit)?,
            server.connect(b, server.next_key().map_err(submit)?).map_err(submit)?,
        ];
        tokio::try_join!(connected(&client, accepted[0]), connected(&server, accepted[1]))?;
        let handles = [client, server];
        let generations = handles.each_ref().map(|handle| handle.snapshot().generation);
        let evidence = measured_pressure(&hosts, &handles).await?;
        let begin = Instant::now();
        let accepted = handles[0].apply(
            local::Request { version: local::VERSION, action: local::Action::DrainProxy {} },
            handles[0].next_key().map_err(submit)?,
        ).map_err(submit)?;
        assert!(matches!(handles[0].wait(accepted.operation).await.map_err(submit)?, Completed::Applied(response) if response.ok));
        tokio::time::sleep(Duration::from_millis(100)).await;
        for handle in &handles {
            let frame = proxy_frame(handle)?;
            assert!(!frame.released && frame.terminal.is_none(),
                "physical acceptance alone is not retained close: {frame:?}");
        }
        timeout(Duration::from_secs(8), async {
            while handles.iter().any(|handle| proxy_frame(handle).is_ok_and(|frame| !frame.released)) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }).await?;
        assert!(begin.elapsed() >= Duration::from_secs(2));
        for (side, handle) in handles.iter().enumerate() {
            let frame = proxy_frame(handle)?;
            assert!(frame.released && !frame.releasing);
            assert_eq!(frame.service_terminal, Some(Terminal::Closed));
            let Some(local::ProxyTerminal::Closed { report }) = frame.terminal.clone() else {
                return Err(format!("measured retained close failed: {frame:?}; {evidence:?}").into());
            };
            assert_eq!(report.tls_lanes_closed, 0);
            assert_eq!(report.clean_flows, 1);
            assert_eq!(report.stopped_flows, 0);
            let generation = generations[side].ok_or("actual connected generation")?;
            assert_eq!(handle.proxy_close_report(generation).map_err(submit)?, Some(report));
            assert_eq!(handle.snapshot().generation, Some(generation));
            let common = frame.common.ok_or("retained Common status")?;
            assert!(!common.running && common.graceful_close);
            assert!(common.socket_accepted_packets >= evidence.physical_packets[side]);
            let aggregate = frame.measured.and_then(|s| s.aggregate).ok_or("final measured status")?;
            assert!(aggregate.quiescing && !aggregate.failed);
            assert_eq!((aggregate.queued, aggregate.awaiting_callback), (0, 0));
        }
        assert!(hosts.iter().all(|host| host.live.load(Ordering::SeqCst) == 0));
        support::assert_ports_free([profile.settings().gate.path.client, profile.settings().gate.path.server])?;
        // These are actual bounded aggregate observations. Socket totals are not
        // individual token receipts, and echo latency is not native TCP RTT.
        eprintln!("measured Common finite integration evidence: {evidence:?}");
        drop(handles);
        for task in tasks {
            task.abort();
            assert!(task.await.is_err_and(|error| error.is_cancelled()));
        }
        Ok::<_, Error>(())
    }).await??;
    Ok(())
}
