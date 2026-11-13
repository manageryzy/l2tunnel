//! Bounded version2 observations; credentials and user/control bodies are absent.
use super::{member, profile::Profile};
use l2tunnel_runtime::secure_udp::transport;
use serde::{Deserialize, Serialize};

/// Global public policy values in fixed initiator/responder order.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Current selected IP path MTU.
    pub path_mtu: u64,
    /// Complete wire budgets, in global direction order.
    pub forward_kbit: u64,
    /// Complete reverse wire budget.
    pub reverse_kbit: u64,
    /// Ordering channels and bounded repair support.
    pub channels: u64,
    /// Sources in each repair support.
    pub window: u64,
    /// Repair proportion per thousand sources.
    pub repair_permille: u64,
}
impl From<l2tunnel_swift::control::Policy> for Policy {
    fn from(value: l2tunnel_swift::control::Policy) -> Self {
        Self {
            path_mtu: u64::from(value.path_mtu),
            forward_kbit: u64::from(value.forward_kbit),
            reverse_kbit: u64::from(value.reverse_kbit),
            channels: u64::from(value.channels),
            window: u64::from(value.window),
            repair_permille: u64::from(value.repair_permille),
        }
    }
}
/// Actual selected same-socket composition and explicit remaining limitations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    /// Exact service generation; reconnect creates a new one.
    pub generation: u64,
    /// Explicit selected appearance carrier.
    pub carrier: String,
    /// Swift is the data algorithm, independent of carrier selection.
    pub algorithm: String,
    /// Required Swift confidentiality and authentication.
    pub protection: String,
    /// Initial requested policy and actual currently committed policy.
    pub requested: Policy,
    /// Last reported effective policy; never copied from a pending request.
    pub effective: Policy,
    /// Authenticated storage/geometry capacity, distinct from active MTU.
    pub maximum_path_mtu: u64,
    /// Real runtime first-ready state, separate from authentication completion.
    pub running: bool,
    /// Actual public Noise session and final transcript.
    pub session: [u8; 16],
    /// Public authenticated final transcript, never used as a secret.
    pub transcript: [u8; 32],
    /// Full actual configuration bound at admission.
    pub configuration: [u8; 32],
    /// Exact authenticated outer transition binding.
    pub outer: [u8; 32],
    /// Authenticated existing Ed25519 member public identity.
    pub member: [u8; 32],
    /// Actual ordered pinned Noise public identities.
    pub initiator_noise: [u8; 32],
    /// Actual responding Noise pin.
    pub responder_noise: [u8; 32],
    /// Original kernel endpoint observations.
    pub local: String,
    /// Original fixed peer address.
    pub peer: String,
    /// Committed logical Swift policy epoch.
    pub policy_epoch: u64,
    /// Actual pending transaction epoch, not proof of application.
    pub pending_epoch: Option<u64>,
    /// Latest observation time since transport start.
    pub elapsed_micros: u64,
    /// Complete attempted wire charges, including control and cached tails.
    pub wire_packets: u64,
    /// Full selected IP-wire bytes charged.
    pub wire_bytes: u64,
    /// Actual native UDP socket acceptance.
    pub socket_accepted_packets: u64,
    /// Actual accepted socket bytes including modeled IP/UDP cost.
    pub socket_accepted_ip_bytes: u64,
    /// Classified transient send/receive observations.
    pub socket_drops: u64,
    /// Receive path errors, consuming work quota.
    pub socket_receive_errors: u64,
    /// Parsed input, invalid/replayed input and exact native completions.
    pub received_packets: u64,
    /// Authentication/parser/scope rejection count.
    pub rejected_packets: u64,
    /// Replay rejections without delivery mutation.
    pub replay_rejections: u64,
    /// Complete native packets read.
    pub native_read: u64,
    /// Complete native packets actually accepted by the device.
    pub native_written: u64,
    /// Native input rejected for negotiated size.
    pub native_oversize: u64,
    /// Ingress refused under bounded native output pressure.
    pub native_backpressure_drops: u64,
    /// Separate native local output storage.
    pub native_pending_packets: usize,
    /// Actual retained native output bytes.
    pub native_pending_bytes: usize,
    /// Algorithm retained-source domain, separate from native pending output.
    pub swift_unconfirmed: usize,
    /// Fixed reliable management records retained for peer confirmation.
    pub control_send_records: usize,
    /// Actual retained outbound management bytes.
    pub control_send_bytes: usize,
    /// Authenticated management records awaiting local delivery.
    pub control_receive_records: usize,
    /// Actual retained inbound management bytes.
    pub control_receive_bytes: usize,
    /// One outstanding authenticated liveness challenge, if present.
    pub ping: Option<u64>,
    /// Original challenge expiry in driver microseconds.
    pub ping_deadline_micros: Option<u64>,
    /// Last fresh authenticated record; cached/replayed input does not advance it.
    pub last_verified_micros: Option<u64>,
    /// Last fresh authenticated matching Pong.
    pub last_pong_micros: Option<u64>,
    /// Next/last common security identity observations, without keys.
    pub user_number: Option<u64>,
    /// Fixed-control security identity.
    pub control_number: Option<u64>,
    /// Actual ratchet generations; not a fresh handshake witness.
    pub user_generation: Option<u64>,
    /// Fixed-control key generation.
    pub control_generation: Option<u64>,
    /// Actual bounded driver terminal category.
    pub terminal: Option<String>,
    /// Real common policy controller capability for this backend.
    pub policy_change: bool,
    /// Fresh-authenticated reconnect is available through the service.
    pub reconnect: bool,
    /// These required parent features remain unimplemented in this composition.
    pub retained_state_recovery: bool,
    /// Full Swift-to-other-record-profile negotiated switching remains open.
    pub cross_profile_switching: bool,
    /// Periodic fresh-DH reauthentication remains separate from key generations.
    pub fresh_rekey: bool,
}

impl Status {
    pub(crate) fn observe(
        profile: Profile,
        info: member::Info,
        generation: u64,
        snapshot: Option<&transport::Snapshot>,
    ) -> std::io::Result<Self> {
        let initial = profile.initial_policy()?;
        let effective = snapshot
            .and_then(|snapshot| snapshot.committed.policy)
            .unwrap_or(initial);
        let selected = profile.settings();
        let ipv6 = selected.gate.path.client.is_ipv6();
        let header = match selected.cover.appearance {
            l2tunnel_cover::Appearance::QuicLike => 13,
            l2tunnel_cover::Appearance::MediaLike => 14,
        };
        let maximum_path_mtu = profile
            .runtime(info.role)
            .security
            .max_body_bytes
            .checked_add(9 + 26 + header + if ipv6 { 48 } else { 28 })
            .and_then(|value| u64::try_from(value).ok())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "admitted data capacity overflow",
                )
            })?;
        let counters = snapshot.map(|snapshot| &snapshot.counters);
        Ok(Self {
            generation,
            carrier: match selected.cover.appearance {
                l2tunnel_cover::Appearance::QuicLike => "quic-like",
                l2tunnel_cover::Appearance::MediaLike => "media-like",
            }
            .into(),
            algorithm: "swift".into(),
            protection: "chacha20-poly1305".into(),
            requested: initial.into(),
            effective: effective.into(),
            maximum_path_mtu,
            running: snapshot.is_some_and(|snapshot| snapshot.running),
            session: info.binding.session.0,
            transcript: info.binding.transcript,
            configuration: info.authenticated.configuration,
            outer: info.authenticated.outer,
            member: info.member.0,
            initiator_noise: info.peers.initiator.0,
            responder_noise: info.peers.responder.0,
            local: info.local_addr.to_string(),
            peer: info.peer_addr.to_string(),
            policy_epoch: snapshot.map_or(0, |snapshot| snapshot.committed.epoch.0),
            pending_epoch: snapshot
                .and_then(|snapshot| snapshot.pending.as_ref().map(|pending| pending.epoch.0)),
            elapsed_micros: snapshot.map_or(0, |snapshot| snapshot.elapsed_micros),
            wire_packets: counters.map_or(0, |c| c.wire_packets),
            wire_bytes: counters.map_or(0, |c| c.wire_bytes),
            socket_accepted_packets: counters.map_or(0, |c| c.socket_accepted_packets),
            socket_accepted_ip_bytes: counters.map_or(0, |c| c.socket_accepted_ip_bytes),
            socket_drops: counters.map_or(0, |c| c.socket_drops),
            socket_receive_errors: counters.map_or(0, |c| c.socket_receive_errors),
            received_packets: counters.map_or(0, |c| c.received_packets),
            rejected_packets: counters.map_or(0, |c| c.rejected_packets),
            replay_rejections: counters.map_or(0, |c| c.replay_rejections),
            native_read: counters.map_or(0, |c| c.native_read),
            native_written: counters.map_or(0, |c| c.native_written),
            native_oversize: counters.map_or(0, |c| c.native_oversize),
            native_backpressure_drops: counters.map_or(0, |c| c.native_backpressure_drops),
            native_pending_packets: counters.map_or(0, |c| c.native_pending_packets),
            native_pending_bytes: counters.map_or(0, |c| c.native_pending_bytes),
            swift_unconfirmed: snapshot.map_or(0, |snapshot| snapshot.swift_unconfirmed),
            control_send_records: snapshot.map_or(0, |snapshot| snapshot.control.send_records),
            control_send_bytes: snapshot.map_or(0, |snapshot| snapshot.control.send_bytes),
            control_receive_records: snapshot
                .map_or(0, |snapshot| snapshot.control.receive_records),
            control_receive_bytes: snapshot.map_or(0, |snapshot| snapshot.control.receive_bytes),
            ping: snapshot.and_then(|snapshot| snapshot.liveness.outstanding),
            ping_deadline_micros: snapshot.and_then(|snapshot| snapshot.liveness.deadline_micros),
            last_verified_micros: snapshot
                .and_then(|snapshot| snapshot.liveness.last_verified_micros),
            last_pong_micros: snapshot.and_then(|snapshot| snapshot.liveness.last_pong_micros),
            user_number: counters.and_then(|c| c.user_number.map(|n| n.0)),
            control_number: counters.and_then(|c| c.control_number.map(|n| n.0)),
            user_generation: counters.and_then(|c| c.user_generation.map(|n| n.0)),
            control_generation: counters.and_then(|c| c.control_generation.map(|n| n.0)),
            terminal: snapshot
                .and_then(|snapshot| snapshot.terminal.map(|reason| format!("{reason:?}"))),
            policy_change: true,
            reconnect: true,
            retained_state_recovery: false,
            cross_profile_switching: false,
            fresh_rekey: false,
        })
    }
}
