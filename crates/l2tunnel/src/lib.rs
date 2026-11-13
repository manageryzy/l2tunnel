//! Pure protocol facade. Authenticated I/O and native devices live in separate adapters.

/// Current implementation scope, also printed by scaffold entry points.
pub const IMPLEMENTATION_STATUS: &str = "Authenticated Linux TCP/TLS, TLS-bootstrapped UDP and genuine UDP-only QUIC TAP/TUN/VXLAN forwarding tested. UDP Cauchy/ARQ, measured active TUN credit/QoS with authenticated retirement, and TCP compression switching have finite native evidence. Full mode parity, broader hot switching, raw native TCP and cross-platform qualification remain in progress.";

/// Incremental codec boundary.
pub use l2tunnel_codec as codec;
/// Platform-independent mode contracts.
pub use l2tunnel_core as core;
/// Explicit QUIC-header and minimal RTP outer appearance codecs, without transport claims.
pub use l2tunnel_cover as cover;
/// Platform device boundaries.
pub use l2tunnel_device as device;
/// Bounded maintained Noise adapter with caller entropy/time and explicit own-peer trust.
pub use l2tunnel_handshake as handshake;
/// Pure existing-member identities and explicit authenticated Noise-session proofs.
pub use l2tunnel_identity as identity;
/// Bounded common traffic arbiter.
pub use l2tunnel_mux as mux;
/// Recovery-engine boundary.
pub use l2tunnel_recovery as recovery;
/// Shared opaque packet protection and explicit legacy Swift compatibility.
pub use l2tunnel_security as security;
/// Local reload safety guard.
pub use l2tunnel_session as session;
/// Planned carrier capabilities.
pub use l2tunnel_transport as transport;
/// Checked inner record framing.
pub use l2tunnel_wire as wire;

/// Common protected user/control records over explicitly selected appearance codecs.
pub mod secure_record;

/// Pure transparent-TUN packet, QoS and cumulative-credit composition.
pub use l2tunnel_active as active;
/// Authenticated aligned-symbol composition; clocks and native I/O stay external.
pub use l2tunnel_aligned as aligned;
/// Exporter-keyed authenticated datagram codecs, separate from socket transport.
pub use l2tunnel_datagram as datagram;
/// Real bounded GF(256) block payload recovery.
pub use l2tunnel_fec as fec;
/// Bounded cumulative credits and adaptive TUN targets.
pub use l2tunnel_flow_control as flow_control;
/// Internal authenticated-origin management admission.
pub use l2tunnel_management as management;
/// Bounded native Ethernet/IP classification and flow affinity.
pub use l2tunnel_packet as packet;
/// TAP system-policy and TUN weighted scheduling composition.
pub use l2tunnel_pipeline as pipeline;
/// Weighted byte scheduling.
pub use l2tunnel_qos as qos;
/// Pure maintained userspace TCP owner; raw sockets and TLS belong to separate adapters.
pub use l2tunnel_raw_tcp as raw_tcp;
/// Systematic block FEC with bounded selective-repeat fallback.
pub use l2tunnel_reliable as reliable;
/// Lean packed ordered-channel engine with requested retransmission and exact header records.
pub use l2tunnel_swift as swift;
/// Explicit maintained TCP relay primitive; native interception remains separate.
pub use l2tunnel_tcp_proxy as tcp_proxy;
/// Provisioned UDP admission and bounded reliable bootstrap, without native sockets.
pub use l2tunnel_udp_control as udp_control;
/// Base VXLAN framing and explicit VNI/domain admission.
pub use l2tunnel_vxlan as vxlan;
