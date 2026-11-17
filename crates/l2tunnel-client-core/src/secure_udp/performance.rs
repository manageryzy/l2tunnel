//! Bounded schema1 performance reports shared by embedding frontends and the CLI.
//! Reports are observations, not protocol inputs or throughput guarantees.
use super::{member, profile::Profile, status};
use l2tunnel_runtime::secure_udp::transport;
use l2tunnel_swift::{ReceiverStats, SenderStats, records};
use serde::Serialize;
use std::io;

/// Independent telemetry schema; local API version2 remains unchanged.
pub const SCHEMA: u8 = 1;
/// Hard channel bound, equal to the selected Swift wire grammar.
pub const MAX_CHANNELS: usize = 64;

/// CLI coalescing only; terminal changes and fresh generations remain visible.
#[cfg(any(target_os = "linux", test))]
#[derive(Default)]
pub(crate) struct Cursor(Option<(u64, u64, bool, Option<String>)>);
#[cfg(any(target_os = "linux", test))]
impl Cursor {
    pub(crate) fn accept(&mut self, report: &Report) -> bool {
        let identity = (
            report.status.generation,
            report.status.elapsed_micros,
            report.status.running,
            report.service_terminal.clone(),
        );
        if self.0.as_ref() == Some(&identity) {
            return false;
        }
        self.0 = Some(identity);
        true
    }
}

/// Saturating runtime counters and current bucket gauge; all fields retain runtime units.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct Driver {
    /// Same named observation and units as transport::Performance.
    pub loop_turns: u64,
    /// Same named observation and units as transport::Performance.
    pub udp_ready_events: u64,
    /// Same named observation and units as transport::Performance.
    pub native_ready_events: u64,
    /// Same named observation and units as transport::Performance.
    pub timer_events: u64,
    /// Same named observation and units as transport::Performance.
    pub request_events: u64,
    /// Same named observation and units as transport::Performance.
    pub udp_batch_packets: u64,
    /// Same named observation and units as transport::Performance.
    pub udp_batch_limit_hits: u64,
    /// Same named observation and units as transport::Performance.
    pub native_read_batch_packets: u64,
    /// Same named observation and units as transport::Performance.
    pub native_read_batch_limit_hits: u64,
    /// Same named observation and units as transport::Performance.
    pub native_write_batch_packets: u64,
    /// Same named observation and units as transport::Performance.
    pub native_write_batch_limit_hits: u64,
    /// Same named observation and units as transport::Performance.
    pub send_calls: u64,
    /// Same named observation and units as transport::Performance.
    pub send_batch_limit_hits: u64,
    /// Same named observation and units as transport::Performance.
    pub bootstrap_packets: u64,
    /// Same named observation and units as transport::Performance.
    pub bootstrap_ip_bytes: u64,
    /// Same named observation and units as transport::Performance.
    pub control_packets: u64,
    /// Same named observation and units as transport::Performance.
    pub control_ip_bytes: u64,
    /// Same named observation and units as transport::Performance.
    pub user_packets: u64,
    /// Same named observation and units as transport::Performance.
    pub user_ip_bytes: u64,
    /// Same named observation and units as transport::Performance.
    pub feedback_packets: u64,
    /// Same named observation and units as transport::Performance.
    pub feedback_ip_bytes: u64,
    /// Same named observation and units as transport::Performance.
    pub user_credit_blocked_polls: u64,
    /// Same named observation and units as transport::Performance.
    pub user_not_ready_polls: u64,
    /// Same named observation and units as transport::Performance.
    pub credit_wait_observed_micros: u64,
    /// Same named observation and units as transport::Performance.
    pub credit_ready_late_micros: u64,
    /// Same named observation and units as transport::Performance.
    pub credit_ready_late_max_micros: u64,
    /// Same named observation and units as transport::Performance.
    pub native_read_would_block: u64,
    /// Same named observation and units as transport::Performance.
    pub native_write_would_block: u64,
    /// Same named observation and units as transport::Performance.
    pub native_output_full_polls: u64,
    /// Same named observation and units as transport::Performance.
    pub native_pending_packets_high: u64,
    /// Same named observation and units as transport::Performance.
    pub native_pending_bytes_high: u64,
    /// Same named observation and units as transport::Performance.
    pub refill_generated_bytes: u64,
    /// Same named observation and units as transport::Performance.
    pub refill_discarded_bytes: u64,
    /// Same named observation and units as transport::Performance.
    pub bucket_tokens_bytes: u64,
    /// Actual maintained TLS/QUIC readiness, separate from raw UDP readiness.
    pub maintained_ready_events: u64,
    /// Complete records observed at the maintained boundary.
    pub maintained_batch_records: u64,
    /// Actual maintained receive work-bound hits.
    pub maintained_batch_limit_hits: u64,
}
impl From<transport::Performance> for Driver {
    fn from(value: transport::Performance) -> Self {
        Self {
            loop_turns: value.loop_turns,
            udp_ready_events: value.udp_ready_events,
            native_ready_events: value.native_ready_events,
            timer_events: value.timer_events,
            request_events: value.request_events,
            udp_batch_packets: value.udp_batch_packets,
            udp_batch_limit_hits: value.udp_batch_limit_hits,
            native_read_batch_packets: value.native_read_batch_packets,
            native_read_batch_limit_hits: value.native_read_batch_limit_hits,
            native_write_batch_packets: value.native_write_batch_packets,
            native_write_batch_limit_hits: value.native_write_batch_limit_hits,
            send_calls: value.send_calls,
            send_batch_limit_hits: value.send_batch_limit_hits,
            bootstrap_packets: value.bootstrap_packets,
            bootstrap_ip_bytes: value.bootstrap_ip_bytes,
            control_packets: value.control_packets,
            control_ip_bytes: value.control_ip_bytes,
            user_packets: value.user_packets,
            user_ip_bytes: value.user_ip_bytes,
            feedback_packets: value.feedback_packets,
            feedback_ip_bytes: value.feedback_ip_bytes,
            user_credit_blocked_polls: value.user_credit_blocked_polls,
            user_not_ready_polls: value.user_not_ready_polls,
            credit_wait_observed_micros: value.credit_wait_observed_micros,
            credit_ready_late_micros: value.credit_ready_late_micros,
            credit_ready_late_max_micros: value.credit_ready_late_max_micros,
            native_read_would_block: value.native_read_would_block,
            native_write_would_block: value.native_write_would_block,
            native_output_full_polls: value.native_output_full_polls,
            native_pending_packets_high: value.native_pending_packets_high,
            native_pending_bytes_high: value.native_pending_bytes_high,
            refill_generated_bytes: value.refill_generated_bytes,
            refill_discarded_bytes: value.refill_discarded_bytes,
            bucket_tokens_bytes: value.bucket_tokens_bytes,
            maintained_ready_events: value.maintained_ready_events,
            maintained_batch_records: value.maintained_batch_records,
            maintained_batch_limit_hits: value.maintained_batch_limit_hits,
        }
    }
}

/// Source, repair and RTT observations; current channels exclude retired engines.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct Sender {
    /// Same named observation and units as SenderStats.
    pub sources: u64,
    /// Same named observation and units as SenderStats.
    pub repairs: u64,
    /// Same named observation and units as SenderStats.
    pub tail_repairs: u64,
    /// Same named observation and units as SenderStats.
    pub retransmits: u64,
    /// Same named observation and units as SenderStats.
    pub packed_bytes: u64,
    /// Same named observation and units as SenderStats.
    pub packets: u64,
    /// Same named observation and units as SenderStats.
    pub smoothed_rtt_micros: u64,
}
impl From<SenderStats> for Sender {
    fn from(value: SenderStats) -> Self {
        Self {
            sources: value.sources,
            repairs: value.repairs,
            tail_repairs: value.tail_repairs,
            retransmits: value.retransmits,
            packed_bytes: value.packed_bytes,
            packets: value.packets,
            smoothed_rtt_micros: value.smoothed_rtt_micros,
        }
    }
}

/// Receive and feedback observations; these do not acknowledge native completion.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct Receiver {
    /// Same named observation and units as ReceiverStats.
    pub sources: u64,
    /// Same named observation and units as ReceiverStats.
    pub recovered: u64,
    /// Same named observation and units as ReceiverStats.
    pub useful_repairs: u64,
    /// Same named observation and units as ReceiverStats.
    pub useless_repairs: u64,
    /// Same named observation and units as ReceiverStats.
    pub duplicates: u64,
    /// Same named observation and units as ReceiverStats.
    pub packets: u64,
    /// Same named observation and units as ReceiverStats.
    pub feedback: u64,
}
impl From<ReceiverStats> for Receiver {
    fn from(value: ReceiverStats) -> Self {
        Self {
            sources: value.sources,
            recovered: value.recovered,
            useful_repairs: value.useful_repairs,
            useless_repairs: value.useless_repairs,
            duplicates: value.duplicates,
            packets: value.packets,
            feedback: value.feedback,
        }
    }
}

/// Current per-channel sending occupancy and recovery state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct Sending {
    /// Current directional engine counters.
    pub stats: Sender,
    /// Native bytes waiting for source packing.
    pub queued_bytes: u64,
    /// Sources awaiting peer confirmation.
    pub unconfirmed: u64,
    /// Current RTO estimate in microseconds.
    pub rto_micros: u64,
    /// Explicit retransmission queue entries.
    pub retransmit_pending: u64,
    /// Proportional repairs earned but not yet polled.
    pub repairs_due: u64,
}
impl From<records::SenderObservation> for Sending {
    fn from(value: records::SenderObservation) -> Self {
        Self {
            stats: value.stats.into(),
            queued_bytes: value.queued_bytes as u64,
            unconfirmed: value.unconfirmed as u64,
            rto_micros: value.rto_micros,
            retransmit_pending: value.retransmit_pending as u64,
            repairs_due: u64::from(value.repairs_due),
        }
    }
}
/// Current indexed channel; a missing direction is explicitly null.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct Channel {
    /// Zero-based index within the current bounded channel vectors.
    pub index: u64,
    /// Present only for a current sending channel.
    pub send: Option<Sending>,
    /// Present only for a current receiving channel.
    pub receive: Option<Receiver>,
    /// Known receive sources awaiting ordered delivery.
    pub receive_pending: u64,
}
fn channels(values: &[records::ChannelStats]) -> io::Result<Vec<Channel>> {
    if values.len() > MAX_CHANNELS {
        return Err(invalid("performance channel limit"));
    }
    Ok(values
        .iter()
        .enumerate()
        .map(|(index, value)| Channel {
            index: index as u64,
            send: value.send.map(Into::into),
            receive: value.receive.map(Into::into),
            receive_pending: u64::from(value.receive_pending),
        })
        .collect())
}
/// Current rates and fixed owner/resource geometry for interpreting the counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct Geometry {
    /// Actual current sending IP-byte budget per second.
    pub send_bytes_per_second: u64,
    /// Actual current incoming IP-byte budget per second.
    pub receive_bytes_per_second: u64,
    /// Fixed IP-byte token bucket capacity.
    pub wire_burst_bytes: u64,
    /// Shared control source plus feedback reservation, in IP bytes.
    pub control_reserve_bytes: u64,
    /// Current outgoing Swift body ceiling before common protection/cover.
    pub send_datagram_bytes: u64,
    /// Current incoming Swift body ceiling.
    pub receive_datagram_bytes: u64,
    /// Fixed complete native output storage slots.
    pub native_pending_packets: u64,
    /// Fixed complete native output storage bytes.
    pub native_pending_bytes: u64,
    /// Configured maximum UDP packets per receive interval.
    pub receive_packets: u64,
    /// Receive interval in microseconds.
    pub receive_interval_micros: u64,
    /// Configured maximum packet emissions per loop turn.
    pub send_batch: u64,
    /// Configured maximum native reads per readiness branch.
    pub native_read_batch: u64,
    /// Configured maximum native writes per readiness branch.
    pub native_write_batch: u64,
}
/// Complete nonsecret, bounded report; cumulative totals include retired engines.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Report {
    /// Telemetry schema version, separate from local command API versions.
    pub schema: u8,
    /// Unchanged existing status supplies generation/session/elapsed/epoch identity.
    pub status: status::Status,
    /// Actual service-owner termination; never a fabricated runtime StopReason.
    pub service_terminal: Option<String>,
    /// Current budgets and immutable resource interpretation.
    pub geometry: Geometry,
    /// Runtime work, pacing and pressure observations.
    pub performance: Driver,
    /// Aggregate current and retired sending engines.
    pub sender: Sender,
    /// Aggregate current and retired receiving engines.
    pub receiver: Receiver,
    /// Aggregate native bytes saved by exact header records.
    pub header_bytes_saved: u64,
    /// Current channel observations; at most64 and never silently truncated.
    pub channels: Vec<Channel>,
}
impl Report {
    pub(crate) fn observe(
        profile: Profile,
        info: member::Info,
        generation: u64,
        snapshot: Option<&transport::Snapshot>,
    ) -> io::Result<Option<Self>> {
        let Some(snapshot) = snapshot else {
            return Ok(None);
        };
        let status = status::Status::observe(profile, info, generation, Some(snapshot))?;
        let config = profile.runtime(info.role);
        let control_reserve = config
            .control
            .recovery
            .max_source_bytes
            .checked_add(l2tunnel_recovery::DATA_HEADER_BYTES)
            .and_then(|n| n.checked_add(l2tunnel_recovery::ACK_PACKET_BYTES))
            .and_then(|n| {
                config
                    .control
                    .wire_overhead
                    .checked_mul(2)
                    .and_then(|overhead| n.checked_add(overhead))
            })
            .ok_or_else(|| invalid("performance wire geometry overflow"))?;
        let expected = snapshot
            .send
            .records
            .channels
            .max(snapshot.receive.records.channels);
        if expected > MAX_CHANNELS || snapshot.channels.len() != expected {
            return Err(invalid("performance channel geometry"));
        }
        Ok(Some(Self {
            schema: SCHEMA,
            status,
            service_terminal: None,
            geometry: Geometry {
                send_bytes_per_second: snapshot.send.bytes_per_second,
                receive_bytes_per_second: snapshot.receive.bytes_per_second,
                wire_burst_bytes: config.wire.burst_bytes as u64,
                control_reserve_bytes: control_reserve as u64,
                send_datagram_bytes: snapshot.send.records.codec.datagram_bytes as u64,
                receive_datagram_bytes: snapshot.receive.records.codec.datagram_bytes as u64,
                native_pending_packets: config.native.pending_packets as u64,
                native_pending_bytes: config.native.pending_bytes as u64,
                receive_packets: u64::from(config.work.receive_packets),
                receive_interval_micros: u64::try_from(config.work.receive_interval.as_micros())
                    .map_err(io::Error::other)?,
                send_batch: config.work.send_batch as u64,
                native_read_batch: config.work.native_read_batch as u64,
                native_write_batch: config.work.native_write_batch as u64,
            },
            performance: snapshot.performance.into(),
            sender: snapshot.swift.sender.into(),
            receiver: snapshot.swift.receiver.into(),
            header_bytes_saved: snapshot.swift.header_bytes_saved,
            channels: channels(&snapshot.channels)?,
        }))
    }
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> io::Result<crate::service::SecureUdpFrame> {
        use crate::{Compression, ConnectionConfig, cli::secure_udp_frontend::Selection};
        use l2tunnel_runtime::secure_udp::establish;
        use l2tunnel_security as security;
        use l2tunnel_swift::{control::Policy, policy};
        use std::time::Duration;
        let local = "127.0.0.1:41021".parse().map_err(io::Error::other)?;
        let peer = "127.0.0.1:41022".parse().map_err(io::Error::other)?;
        let selection = Selection {
            appearance: l2tunnel_cover::Appearance::QuicLike,
            role: security::Role::Initiator,
            local,
            peer,
            policy: Policy {
                path_mtu: 1500,
                forward_kbit: 99_000,
                reverse_kbit: 9_900,
                channels: 16,
                window: 64,
                repair_permille: 0,
            },
            maximum_mtu: 9000,
            profile: l2tunnel_handshake::Profile::Ik,
            report: None,
        };
        let peers = establish::Peers {
            initiator: l2tunnel_handshake::LocalSecret::new(zeroize::Zeroizing::new([11; 32]))
                .public_key(),
            responder: l2tunnel_handshake::LocalSecret::new(zeroize::Zeroizing::new([22; 32]))
                .public_key(),
        };
        let member = l2tunnel_identity::MemberPublicKey([7; 32]);
        let profile = selection.build(
            ConnectionConfig {
                layer: l2tunnel_device::PacketLayer::Ip,
                duplex: l2tunnel_core::Duplex::Full,
                max_packet: 1600,
                compression: Compression::None,
                handshake_timeout: Duration::from_secs(3),
            },
            peers,
            member,
        )?;
        let info = member::Info {
            binding: security::SessionBinding {
                session: security::SessionId([1; 16]),
                transcript: [2; 32],
            },
            authenticated: l2tunnel_handshake::Binding {
                session: security::SessionId([1; 16]),
                configuration: profile.configuration(peers)?.0,
                carrier: [3; 32],
                outer: [4; 32],
                member: member.0,
            },
            member,
            peers,
            role: security::Role::Initiator,
            local_addr: local,
            peer_addr: peer,
            statistics: establish::Statistics::default(),
        };
        let config = profile.runtime(info.role);
        let engine = records::Engine::new(config.send.records).map_err(io::Error::other)?;
        let channels = (0..16)
            .map(|index| {
                engine
                    .channel_stats(index)
                    .ok_or_else(|| invalid("fixture channel"))
            })
            .collect::<io::Result<Vec<_>>>()?;
        Ok(crate::service::SecureUdpFrame {
            requested: profile,
            info,
            generation: 8,
            service_terminal: None,
            runtime: Some(transport::Snapshot {
                running: true,
                elapsed_micros: 1234,
                info,
                configuration: profile.configuration(peers)?,
                control_streams: config.streams.is_some(),
                policy_deadline_micros: None,
                policy_receipt_pending: false,
                send: config.send,
                receive: config.receive,
                committed: policy::Committed {
                    epoch: policy::Epoch(0),
                    policy: None,
                },
                pending: None,
                swift: records::Stats::default(),
                swift_unconfirmed: 0,
                channels,
                performance: transport::Performance::default(),
                control: l2tunnel_recovery::Retained::default(),
                counters: transport::Counters::default(),
                liveness: transport::Liveness::default(),
                terminal: None,
            }),
        })
    }
    #[test]
    fn shared_report_preserves_status_identity_geometry_terminal_and_channel_bounds()
    -> io::Result<()> {
        let mut frame = fixture()?;
        let before = serde_json::to_value(frame.status()?)?;
        let report = frame
            .performance()?
            .ok_or_else(|| invalid("missing report"))?;
        assert_eq!(report.schema, SCHEMA);
        assert_eq!(serde_json::to_value(&report.status)?, before);
        assert_eq!(report.status.generation, 8);
        assert_eq!(report.status.elapsed_micros, 1234);
        assert_eq!(report.geometry.wire_burst_bytes, 50_000);
        assert_eq!(report.geometry.control_reserve_bytes, 500);
        assert_eq!(report.geometry.send_datagram_bytes, 1424);
        assert_eq!(report.geometry.send_bytes_per_second, 12_375_000);
        assert_eq!(report.channels.len(), 16);
        let mut cursor = Cursor::default();
        assert!(cursor.accept(&report));
        assert!(!cursor.accept(&report));
        frame.service_terminal = Some(crate::service::Terminal::Aborted);
        let service_stopped = frame
            .performance()?
            .ok_or_else(|| invalid("missing service stop"))?;
        assert_eq!(
            service_stopped.status.elapsed_micros,
            report.status.elapsed_micros
        );
        assert_eq!(service_stopped.status.terminal, report.status.terminal);
        assert_eq!(service_stopped.performance, report.performance);
        assert_eq!(service_stopped.service_terminal.as_deref(), Some("Aborted"));
        assert!(cursor.accept(&service_stopped));
        assert!(!cursor.accept(&service_stopped));
        frame.service_terminal = None;
        let json = serde_json::to_value(&report)?;
        let object = json.as_object().ok_or_else(|| invalid("report object"))?;
        assert_eq!(object.len(), 9);
        for field in [
            "schema",
            "status",
            "service_terminal",
            "geometry",
            "performance",
            "sender",
            "receiver",
            "header_bytes_saved",
            "channels",
        ] {
            assert!(object.contains_key(field), "{field}");
        }
        let runtime = frame
            .runtime
            .as_mut()
            .ok_or_else(|| invalid("fixture runtime"))?;
        runtime.running = false;
        runtime.terminal = Some(transport::StopReason::PeerTimeout);
        let report = frame
            .performance()?
            .ok_or_else(|| invalid("missing terminal"))?;
        assert!(!report.status.running);
        assert_eq!(report.status.terminal.as_deref(), Some("PeerTimeout"));
        assert!(cursor.accept(&report));
        assert!(!cursor.accept(&report));
        frame.service_terminal = Some(crate::service::Terminal::Aborted);
        let service_stopped = frame
            .performance()?
            .ok_or_else(|| invalid("missing service stop"))?;
        assert_eq!(
            service_stopped.status.elapsed_micros,
            report.status.elapsed_micros
        );
        assert_eq!(service_stopped.status.terminal, report.status.terminal);
        assert!(cursor.accept(&service_stopped));
        assert!(!cursor.accept(&service_stopped));
        frame.service_terminal = None;
        frame.generation += 1;
        let runtime = frame
            .runtime
            .as_mut()
            .ok_or_else(|| invalid("fixture runtime"))?;
        runtime.running = true;
        runtime.elapsed_micros = 0;
        runtime.terminal = None;
        let fresh = frame
            .performance()?
            .ok_or_else(|| invalid("missing fresh generation"))?;
        assert!(cursor.accept(&fresh));
        assert!(!cursor.accept(&fresh));
        frame
            .runtime
            .as_mut()
            .ok_or_else(|| invalid("fixture runtime"))?
            .channels
            .pop();
        assert!(frame.performance().is_err());
        frame.runtime = None;
        assert!(frame.performance()?.is_none());
        Ok(())
    }
    #[test]
    fn channel_reports_preserve_sparse_directions_and_reject_excess_without_truncation()
    -> io::Result<()> {
        let observation = records::SenderObservation {
            stats: SenderStats {
                sources: 9,
                retransmits: 4,
                ..SenderStats::default()
            },
            queued_bytes: 77,
            unconfirmed: 12,
            rto_micros: 1000,
            retransmit_pending: 3,
            repairs_due: 2,
        };
        let mut values = vec![records::ChannelStats::default(); MAX_CHANNELS];
        values[0].send = Some(observation);
        values[63].receive = Some(ReceiverStats {
            sources: 8,
            recovered: 2,
            ..ReceiverStats::default()
        });
        values[63].receive_pending = 5;
        let report = channels(&values)?;
        assert_eq!(report.len(), MAX_CHANNELS);
        let first = report[0]
            .send
            .ok_or_else(|| invalid("missing sending observation"))?;
        assert_eq!(
            (
                first.stats.sources,
                first.stats.retransmits,
                first.queued_bytes,
                first.unconfirmed,
                first.rto_micros,
                first.retransmit_pending,
                first.repairs_due
            ),
            (9, 4, 77, 12, 1000, 3, 2)
        );
        assert!(report[0].receive.is_none());
        assert_eq!(report[63].index, 63);
        assert!(report[63].send.is_none());
        assert_eq!(report[63].receive_pending, 5);
        let json = serde_json::to_value(report)?;
        assert!(json[0]["receive"].is_null());
        assert!(json[63]["send"].is_null());
        assert_eq!(json[63]["receive"]["recovered"], 2);
        values.push(records::ChannelStats::default());
        assert!(channels(&values).is_err());
        assert!(channels(&[])?.is_empty());
        Ok(())
    }
    #[test]
    fn driver_report_names_and_values_preserve_every_runtime_observation() -> io::Result<()> {
        let source = transport::Performance {
            loop_turns: 1,
            udp_ready_events: 2,
            native_ready_events: 3,
            timer_events: 4,
            request_events: 5,
            udp_batch_packets: 6,
            udp_batch_limit_hits: 7,
            native_read_batch_packets: 8,
            native_read_batch_limit_hits: 9,
            native_write_batch_packets: 10,
            native_write_batch_limit_hits: 11,
            send_calls: 12,
            send_batch_limit_hits: 13,
            bootstrap_packets: 14,
            bootstrap_ip_bytes: 15,
            control_packets: 16,
            control_ip_bytes: 17,
            user_packets: 18,
            user_ip_bytes: 19,
            feedback_packets: 20,
            feedback_ip_bytes: 21,
            user_credit_blocked_polls: 22,
            user_not_ready_polls: 23,
            credit_wait_observed_micros: 24,
            credit_ready_late_micros: 25,
            credit_ready_late_max_micros: 26,
            native_read_would_block: 27,
            native_write_would_block: 28,
            native_output_full_polls: 29,
            native_pending_packets_high: 30,
            native_pending_bytes_high: 31,
            refill_generated_bytes: 32,
            refill_discarded_bytes: 33,
            bucket_tokens_bytes: 34,
            maintained_ready_events: 35,
            maintained_batch_records: 36,
            maintained_batch_limit_hits: 37,
        };
        let value = serde_json::to_value(Driver::from(source))?;
        let object = value
            .as_object()
            .ok_or_else(|| invalid("driver observation object"))?;
        let expected = [
            "loop_turns",
            "udp_ready_events",
            "native_ready_events",
            "timer_events",
            "request_events",
            "udp_batch_packets",
            "udp_batch_limit_hits",
            "native_read_batch_packets",
            "native_read_batch_limit_hits",
            "native_write_batch_packets",
            "native_write_batch_limit_hits",
            "send_calls",
            "send_batch_limit_hits",
            "bootstrap_packets",
            "bootstrap_ip_bytes",
            "control_packets",
            "control_ip_bytes",
            "user_packets",
            "user_ip_bytes",
            "feedback_packets",
            "feedback_ip_bytes",
            "user_credit_blocked_polls",
            "user_not_ready_polls",
            "credit_wait_observed_micros",
            "credit_ready_late_micros",
            "credit_ready_late_max_micros",
            "native_read_would_block",
            "native_write_would_block",
            "native_output_full_polls",
            "native_pending_packets_high",
            "native_pending_bytes_high",
            "refill_generated_bytes",
            "refill_discarded_bytes",
            "bucket_tokens_bytes",
            "maintained_ready_events",
            "maintained_batch_records",
            "maintained_batch_limit_hits",
        ];
        assert_eq!(object.len(), expected.len());
        for (index, name) in expected.iter().enumerate() {
            assert_eq!(value[*name], (index + 1) as u64, "{name}");
        }
        Ok(())
    }
}
