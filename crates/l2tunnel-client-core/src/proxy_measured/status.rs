//! Bounded aggregate DTOs; no payloads, keys or per-flow dumps.
use super::*;
use serde::Serialize;

/// Explicit measured profile; no fallback profile is inferred.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Profile {
    /// Measured relay targets with maintained, preallocated native rings.
    #[serde(rename = "measured-relay-v1")]
    MeasuredRelayV1,
}
/// Actual physical lane policy, authenticated with the profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneMode {
    /// Two retained directional TCP/TLS lanes.
    Half,
    /// One retained bidirectional TCP/TLS lane.
    Full,
}
/// Retained carrier for this explicit measured profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Carrier {
    /// Original authenticated ordinary TCP/TLS lanes.
    TcpTls,
}
/// UDP cover applicability on this TCP profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UdpCover {
    /// No UDP carrier is selected.
    NotApplicable,
}
/// Capabilities of this explicit TUN/TCP/TLS implementation, not native evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    /// Explicit operator-selected profile.
    pub requested: Profile,
    /// Absent until an actual runtime status has been published.
    pub effective: Option<Profile>,
    /// Exact retained lane topology.
    pub lanes: LaneMode,
    /// Explicit requested ordinary TCP/TLS carrier.
    pub requested_carrier: Carrier,
    /// Absent before the real runtime publishes status.
    pub effective_carrier: Option<Carrier>,
    /// Explicit absence of UDP cover on this profile.
    pub requested_udp_cover: UdpCover,
    /// Absent before the real runtime publishes status.
    pub effective_udp_cover: Option<UdpCover>,
    /// Future relay targets are derived from actual bounded observations.
    pub measured_relay_targets: bool,
    /// False: maintained TCP owns advertised windows.
    pub exact_tcp_rwnd_control: bool,
    /// False: echo samples measure authenticated tunnel service latency.
    pub native_tcp_rtt: bool,
    /// False: the maintained native stack exposes no congestion-window sample.
    pub native_tcp_cwnd: bool,
    /// False until a separate real-kernel acceptance gate is qualified.
    pub native_window_qualified: bool,
    /// False: this profile is immutable for its authenticated session.
    pub hot_reload: bool,
    /// False: this bounded DTO exposes only aggregate facts.
    pub flow_paging: bool,
}
/// Requested/effective capability separation plus one actual aggregate snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalSnapshot {
    /// Configuration capabilities; effective is never derived from a request alone.
    pub capabilities: Capabilities,
    /// None before the actual runtime publishes its first snapshot.
    pub aggregate: Option<Aggregate>,
}
/// Actual original-byte ACK rate, never packet-device writes or peer assertions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AckRate {
    /// Original bytes accumulated in eligible completed bins.
    pub bytes: u128,
    /// Actual aggregate bin time.
    pub elapsed_micros: u64,
    /// Bounded computed original-byte rate.
    pub bytes_per_second: u64,
    /// Number of eligible bins.
    pub bins: u8,
    /// Original latest bin completion time.
    pub latest_at_micros: u64,
}
/// Common-MUX echo service latency, not native TCP RTT.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceLatency {
    /// Smoothed service latency from original admission/reply timestamps.
    pub smoothed_micros: u64,
    /// Original common-MUX admission time.
    pub admitted_at_micros: u64,
    /// Original authenticated reply receipt time.
    pub reply_at_micros: u64,
    /// Freshness at the actual snapshot's query time.
    pub fresh: bool,
}
/// Policy phase; no interpretation as native TCP state is valid.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetPhase {
    /// No demanding flow.
    Idle,
    /// Waiting for qualifying observations.
    Bootstrap,
    /// Qualified target growth.
    Probing,
    /// Held or capped target.
    Steady,
    /// Future admission reduced under actual pressure.
    Backpressure,
    /// Waiting through the quiet recovery interval.
    Recovering,
}
/// Last actual atomic target apply; these values are not advertised windows.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedTargets {
    /// Actual planner revision.
    pub revision: u64,
    /// Current candidate policy phase.
    pub phase: TargetPhase,
    /// Candidate original-byte target before grant-debt reservation.
    pub candidate_bytes: u64,
    /// Candidate original-record target.
    pub candidate_records: u64,
    /// Full issued/future debt reservation, including terminal slots.
    pub reserved_bytes: u64,
    /// Full record reservation.
    pub reserved_records: u64,
}
/// Constant-size copied aggregate; individual flow/nonce/generation data is omitted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Aggregate {
    /// Actual runtime snapshot time.
    pub at_micros: u64,
    /// Last successful authoritative Controller operation.
    pub authoritative_at_micros: u64,
    /// Observation revision.
    pub revision: u64,
    /// Current active flow count.
    pub active_flows: usize,
    /// Current demand-set count.
    pub demanding_flows: usize,
    /// Active flows without fresh demand evidence.
    pub unknown_flows: usize,
    /// Current fresh exhausted-grant evidence.
    pub grant_exhausted: bool,
    /// Original received-minus-ACK bytes.
    pub in_flight_bytes: u64,
    /// Original received-minus-ACK records.
    pub in_flight_records: u64,
    /// Actual eligible ACK bins, if any.
    pub ack_rate: Option<AckRate>,
    /// Actual common-path service echo, if any.
    pub service_latency: Option<ServiceLatency>,
    /// Last actual target apply; None before the first successful apply.
    pub applied: Option<AppliedTargets>,
    /// Coalescible measurement work not yet admitted.
    pub pending: usize,
    /// Immutable admitted measurement proofs.
    pub admitted: usize,
    /// Actual measurement records in the shared arbiter.
    pub queued: usize,
    /// Writer records still awaiting exact full-flush callbacks.
    pub awaiting_callback: usize,
    /// Actual Demand, EchoRequest and EchoReply admissions.
    pub admitted_by_kind: [u64; 3],
    /// Actual common-budget measurement bytes including framing.
    pub admitted_framed_bytes: u64,
    /// Current actual shared queue/write sojourn.
    pub queue_delay_micros: u64,
    /// Actual local native receiver pressure.
    pub receiver_pressure: bool,
    /// Actual retained writer pressure.
    pub carrier_pressure: bool,
    /// Actual Controller admission has quiesced.
    pub quiescing: bool,
    /// A terminal Controller fault has been observed.
    pub failed: bool,
}
impl LocalSnapshot {
    #[cfg(any(unix, test))]
    pub(crate) fn observed(lanes: Duplex, snapshot: Option<&Snapshot>) -> Self {
        Self {
            capabilities: Capabilities {
                requested: Profile::MeasuredRelayV1,
                requested_carrier: Carrier::TcpTls,
                effective_carrier: snapshot.map(|_| Carrier::TcpTls),
                requested_udp_cover: UdpCover::NotApplicable,
                effective_udp_cover: snapshot.map(|_| UdpCover::NotApplicable),
                effective: snapshot.map(|_| Profile::MeasuredRelayV1),
                lanes: match lanes {
                    Duplex::Half => LaneMode::Half,
                    Duplex::Full => LaneMode::Full,
                },
                measured_relay_targets: true,
                exact_tcp_rwnd_control: false,
                native_tcp_rtt: false,
                native_tcp_cwnd: false,
                native_window_qualified: false,
                hot_reload: false,
                flow_paging: false,
            },
            aggregate: snapshot.map(Aggregate::from),
        }
    }
}
impl From<&Snapshot> for Aggregate {
    fn from(s: &Snapshot) -> Self {
        let o = s.observations;
        Self {
            at_micros: o.at.0,
            authoritative_at_micros: o.authoritative_at.0,
            revision: o.revision,
            active_flows: o.active_flows,
            demanding_flows: o.demanding_flows,
            unknown_flows: o.unknown_flows,
            grant_exhausted: o.grant_exhausted,
            in_flight_bytes: o.in_flight.bytes,
            in_flight_records: o.in_flight.records,
            ack_rate: o.ack_rate.map(|v| AckRate {
                bytes: v.bytes,
                elapsed_micros: v.elapsed_micros,
                bytes_per_second: v.bytes_per_second,
                bins: v.bins,
                latest_at_micros: v.latest_at.0,
            }),
            service_latency: o.service_latency.map(|v| ServiceLatency {
                smoothed_micros: v.smoothed_micros,
                admitted_at_micros: v.admitted_at.0,
                reply_at_micros: v.reply_at.0,
                fresh: v.fresh,
            }),
            applied: s.applied.as_ref().map(|v| AppliedTargets {
                revision: v.revision,
                phase: match v.state {
                    adaptive::TargetState::Idle => TargetPhase::Idle,
                    adaptive::TargetState::Bootstrap => TargetPhase::Bootstrap,
                    adaptive::TargetState::Probing => TargetPhase::Probing,
                    adaptive::TargetState::Steady => TargetPhase::Steady,
                    adaptive::TargetState::Backpressure => TargetPhase::Backpressure,
                    adaptive::TargetState::Recovering => TargetPhase::Recovering,
                },
                candidate_bytes: v.candidate.bytes,
                candidate_records: v.candidate.records,
                reserved_bytes: v.reserved.bytes,
                reserved_records: v.reserved.records,
            }),
            pending: o.owner.pending,
            admitted: o.owner.admitted,
            queued: s.queued,
            awaiting_callback: s.awaiting_callback,
            admitted_by_kind: s.admitted_by_kind,
            admitted_framed_bytes: s.admitted_framed_bytes,
            queue_delay_micros: s.pressure.queue_delay_micros,
            receiver_pressure: s.pressure.receiver_pressure,
            carrier_pressure: s.pressure.carrier_pressure,
            quiescing: o.owner.quiescing,
            failed: o.failure.is_some(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
    #[test]
    fn maximum_aggregate_response_fits_original_local_cap_and_is_strict() -> TestResult {
        let n = u64::MAX;
        let aggregate = serde_json::json!({
            "at_micros":n,"authoritative_at_micros":n,"revision":n,"active_flows":n,
            "demanding_flows":n,"unknown_flows":n,"grant_exhausted":true,"in_flight_bytes":n,
            "in_flight_records":n,"ack_rate":{"bytes":n,"elapsed_micros":n,"bytes_per_second":n,"bins":255,"latest_at_micros":n},
            "service_latency":{"smoothed_micros":n,"admitted_at_micros":n,"reply_at_micros":n,"fresh":true},
            "applied":{"revision":n,"phase":"backpressure","candidate_bytes":n,"candidate_records":n,"reserved_bytes":n,"reserved_records":n},
            "pending":n,"admitted":n,"queued":n,"awaiting_callback":n,"admitted_by_kind":[n,n,n],
            "admitted_framed_bytes":n,"queue_delay_micros":n,"receiver_pressure":true,"carrier_pressure":true,
            "quiescing":true,"failed":true
        });
        let mut measured = LocalSnapshot::observed(Duplex::Half, None);
        measured.aggregate = Some(serde_json::from_value(aggregate)?);
        measured.capabilities.effective = Some(Profile::MeasuredRelayV1);
        measured.capabilities.effective_carrier = Some(Carrier::TcpTls);
        measured.capabilities.effective_udp_cover = Some(UdpCover::NotApplicable);
        let mut response = crate::local::Response {
            version: crate::local::VERSION,
            ok: false,
            code: "already_accepted".into(),
            state: Some(crate::local::Snapshot {
                epoch: n,
                phase: "Quiescing".into(),
                compression: crate::local::Compression::Off,
                active: None,
                openvpn_drain: None,
                raw_packet: None,
                rolling: None,
                #[cfg(unix)]
                swift: None,
                #[cfg(unix)]
                secure_udp: None,
                transaction: None,
                common: None,
                proxy: Some(crate::local::ProxySnapshot {
                    digest: "ff".repeat(32),
                    drain_accepted: true,
                    runtime: Some(crate::local::ProxyStatus {
                        phase: "Quiescing".into(),
                        flows: usize::MAX,
                        active: usize::MAX,
                        stopped: usize::MAX,
                        retired: usize::MAX,
                        queued_bytes: usize::MAX,
                        queued_records: usize::MAX,
                        transparent_admitted_bytes: n,
                        transparent_admitted_packets: n,
                        native_confirmed_packets: n,
                    }),
                    terminal: Some(crate::local::ProxyTerminal::Failed {
                        error: "\0".repeat(256),
                    }),
                    measured: Some(measured),
                }),
            }),
        };
        let encoded = serde_json::to_vec(&response)?;
        assert!(encoded.len() < 8192, "{}", encoded.len());
        assert_eq!(
            serde_json::from_slice::<crate::local::Response>(&encoded)?,
            response
        );
        fn strict(value: &serde_json::Value, root: &str) -> TestResult {
            if let Some(object) = value.as_object() {
                let original = serde_json::to_string(value)?;
                if let Some((key, value)) = object.iter().next() {
                    for replacement in [
                        format!("{{\"unexpected\":0,{}", &original[1..]),
                        format!(
                            "{{{}:{},{}",
                            serde_json::to_string(key)?,
                            serde_json::to_string(value)?,
                            &original[1..]
                        ),
                    ] {
                        let changed = root.replacen(&original, &replacement, 1);
                        assert!(serde_json::from_str::<crate::local::Response>(&changed).is_err());
                    }
                }
                for child in object.values() {
                    strict(child, root)?;
                }
            }
            Ok(())
        }
        let ordered = serde_json::to_value(&response)?;
        strict(&ordered, &serde_json::to_string(&ordered)?)?;
        response
            .state
            .as_mut()
            .ok_or("state")?
            .proxy
            .as_mut()
            .ok_or("proxy")?
            .measured
            .as_mut()
            .ok_or("measured")?
            .aggregate
            .as_mut()
            .ok_or("aggregate")?
            .ack_rate
            .as_mut()
            .ok_or("rate")?
            .bytes = u128::MAX;
        let maximum = serde_json::to_vec(&response)?;
        assert!(maximum.len() < 8192);
        assert_eq!(
            serde_json::from_slice::<crate::local::Response>(&maximum)?,
            response
        );
        Ok(())
    }
    #[test]
    fn requested_profile_does_not_invent_effective_observations() {
        let value = LocalSnapshot::observed(Duplex::Full, None);
        assert_eq!(value.capabilities.requested, Profile::MeasuredRelayV1);
        assert_eq!(value.capabilities.effective, None);
        assert_eq!(value.capabilities.effective_carrier, None);
        assert_eq!(value.capabilities.effective_udp_cover, None);
        assert_eq!(value.aggregate, None);
    }
}
