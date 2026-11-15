//! Explicit same-socket carrier presentation through the shared lifecycle service.
use super::*;
use crate::secure_udp::{self, credentials, profile::Profile};
use l2tunnel_handshake as hs;
use l2tunnel_runtime::secure_udp::{establish, transport};
use l2tunnel_security as security;
use l2tunnel_swift::{policy, records};
use l2tunnel_udp_control as gate;
#[path = "common_cli.rs"]
mod common_cli;
#[path = "common_cli_output.rs"]
mod common_cli_output;
#[path = "setup_output.rs"]
mod setup_output;
#[path = "transaction_cli.rs"]
mod transaction_cli;
#[path = "transaction_cli_output.rs"]
mod transaction_cli_output;

pub(super) const OPTIONS: &[&str] = &[
    "--noise-profile",
    "--noise-private-key-file",
    "--noise-peer-key-file",
    "--noise-psk-file",
    "--session-admission-key-file",
    "--session-cookie-key-file",
    "--max-path-mtu",
    "--swift-transaction-plan",
    "--common-transaction-plan",
];
pub(super) const HELP: &str = "Common secure UDP (implementation draft): explicitly select --carrier quic-like|media-like --record-profile swift --duplex full, --udp-bind IP:PORT --udp-peer IP:PORT, --noise-profile ik|ikpsk2, --noise-private-key-file RAW32 --noise-peer-key-file RAW32 --session-admission-key-file RAW32; ikpsk2 additionally requires --noise-psk-file RAW32. Connect retains --identity PKCS8; serve requires --allow-key Ed25519_RAW32 and --session-cookie-key-file RAW32. Private files must be owned/private regular files. No TCP/TLS side connection or automatic credential generation. Without --swift-transaction-plan PATH, legacy Swift forward/reverse rates are mandatory; current --path-mtu defaults to 1500, --max-path-mtu capacity defaults to 9000 (576..9000). Cover IDs derive from ordered public Noise pins, without identification guarantees. Optional --control-socket exposes explicit local API version 2; external status/disconnect/reconnect/set-swift require --api-version 2. Fresh reconnect does not preserve old-session delivery state. Explicit --swift-transaction-plan PATH instead supplies a strict complete catalog/runtime plan, exposes API version 3 and excludes legacy mutable/report flags. switch-swift-configuration --control-socket PATH --api-version 3 --configuration EXACT608_LOWERCASE_HEX sends one complete change. inspect-swift-transaction-plan --role connect|serve with the same plan/carrier/native/public-trust inputs reads existing Noise/member credentials but requires no device, control socket, admission or cookie; it validates without authentication or runtime effects. Full recovery, cross-profile switching, other carrier/platform qualification remain open. Explicit --record-profile common --common-transaction-plan PATH selects the full Common catalog/backend and local API4. inspect-common-transaction-plan validates that full plan without startup; switch-common-configuration requires --api-version4 --request-key N and exact2608 lowercase hex; common-catalog pages the exact generation/catalog set with limit1..4. Common plans require explicit rolling_work:null or positive field/copies/metadata limits; the actual runtime contract decides support. Native production CLI qualification remains separate. Explicit --carrier openvpn-like --record-profile common --common-transaction-plan PATH additionally requires --udp-cover quic-like|media-like and a complete outer_carrier version1/openvpn_wire_common object in the plan. Connect uses the existing --ca DER --server-name DNS trust inputs; serve uses --cert DER --key PKCS8, with the same member identity/pin as the inner session. The actual raw TLS/member carrier has no standalone RAW64 gate: --admission-key-file/--cookie-key-file and standalone protection/drain/stats flags are refused; inner --session-admission-key-file and server-only --session-cookie-key-file remain required. Offline inspection reports requested E0 and binding required; only actual outer authentication supplies effective E1/H0/catalog. No default or fallback changes.";

#[derive(Clone, Copy)]
pub(crate) struct Selection {
    pub(crate) appearance: l2tunnel_cover::Appearance,
    pub(crate) role: security::Role,
    pub(crate) local: SocketAddr,
    pub(crate) peer: SocketAddr,
    pub(crate) policy: l2tunnel_swift::control::Policy,
    pub(crate) maximum_mtu: usize,
    pub(crate) profile: hs::Profile,
    pub(crate) report: Option<Duration>,
}
#[derive(Clone, Copy)]
struct Common {
    appearance: l2tunnel_cover::Appearance,
    role: security::Role,
    local: SocketAddr,
    peer: SocketAddr,
    maximum_mtu: usize,
    profile: hs::Profile,
}
impl From<Selection> for Common {
    fn from(value: Selection) -> Self {
        Self {
            appearance: value.appearance,
            role: value.role,
            local: value.local,
            peer: value.peer,
            maximum_mtu: value.maximum_mtu,
            profile: value.profile,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Carrier {
    OriginalUdp,
    OpenVpn,
}
pub(super) struct Selected(Choice, Carrier);
enum Choice {
    Legacy(Selection),
    Transaction(Common, Box<transaction_cli::Plan>),
    Records(Common, Box<common_cli::Plan>),
}
enum Built {
    Legacy(Box<Profile>),
    Transaction(Box<secure_udp::transaction_profile::Profile>),
    Records(Box<secure_udp::common_transaction_profile::Profile>),
}
impl Selected {
    fn common(&self) -> Common {
        match &self.0 {
            Choice::Legacy(value) => (*value).into(),
            Choice::Transaction(common, _) | Choice::Records(common, _) => *common,
        }
    }
    fn transaction(&self) -> bool {
        matches!(self.0, Choice::Transaction(_, _) | Choice::Records(_, _))
    }
    fn report_interval(&self) -> Option<Duration> {
        match &self.0 {
            Choice::Legacy(value) => Some(value.report.unwrap_or(Duration::from_secs(1))),
            Choice::Transaction(_, plan) => plan.report_interval(),
            Choice::Records(_, plan) => plan.report_interval(),
        }
    }
    fn build(
        &self,
        connection: ConnectionConfig,
        peers: establish::Peers,
        member: l2tunnel_identity::MemberPublicKey,
    ) -> io::Result<Built> {
        match &self.0 {
            Choice::Legacy(value) => value
                .build(connection, peers, member)
                .map(Box::new)
                .map(Built::Legacy),
            Choice::Transaction(common, plan) => {
                let (overhead, maximum_body) = common.geometry()?;
                let raw = common.raw(
                    plan.initial().path_mtu(),
                    connection.handshake_timeout,
                    peers,
                    member,
                )?;
                plan.build(connection, raw, peers, maximum_body, overhead)
                    .map(Box::new)
                    .map(Built::Transaction)
            }
            Choice::Records(common, plan) => {
                let mut raw = common.raw(
                    plan.initial().path_mtu(),
                    connection.handshake_timeout,
                    peers,
                    member,
                )?;
                let (overhead, maximum_body) = if self.1 == Carrier::OpenVpn {
                    common.carrier_geometry(&mut raw, plan.outer_capacity()?)?
                } else {
                    common.geometry()?
                };
                plan.build(connection, raw, peers, maximum_body, overhead)
                    .map(Box::new)
                    .map(Built::Records)
            }
        }
    }
    fn outer_config(
        &self,
        profile: &secure_udp::common_transaction_profile::Profile,
    ) -> io::Result<Option<l2tunnel_openvpn::wire_carrier::common::Config>> {
        if self.1 == Carrier::OriginalUdp {
            return Ok(None);
        }
        match &self.0 {
            Choice::Records(_, plan) => plan.outer_config(profile).map(Some),
            _ => Err(input(
                "OpenVPN carrier requires the complete Common record plan",
            )),
        }
    }
}

pub(super) fn selection(
    command: &str,
    options: &BTreeMap<String, String>,
    config: ConnectionConfig,
) -> io::Result<Option<Selected>> {
    selection_for(command, options, config, false)
}
fn selection_for(
    command: &str,
    options: &BTreeMap<String, String>,
    config: ConnectionConfig,
    inspection: bool,
) -> io::Result<Option<Selected>> {
    tls_frontend::preflight(command, options)?;
    let records_plan = options.contains_key("--common-transaction-plan");
    let carrier = if options.get("--carrier").map(String::as_str) == Some("openvpn-like")
        && (records_plan || options.get("--record-profile").map(String::as_str) == Some("common"))
    {
        if !records_plan {
            return Err(input(
                "OpenVPN Common selection requires its complete transaction plan",
            ));
        }
        Carrier::OpenVpn
    } else {
        Carrier::OriginalUdp
    };
    let appearance = match options.get("--carrier").map(String::as_str) {
        Some("quic-like") => l2tunnel_cover::Appearance::QuicLike,
        Some("media-like") => l2tunnel_cover::Appearance::MediaLike,
        Some("openvpn-like") if carrier == Carrier::OpenVpn => {
            match required(options, "--udp-cover")? {
                "quic-like" => l2tunnel_cover::Appearance::QuicLike,
                "media-like" => l2tunnel_cover::Appearance::MediaLike,
                _ => {
                    return Err(input(
                        "OpenVPN Common requires explicit inner cover quic-like or media-like",
                    ));
                }
            }
        }
        _ => {
            if OPTIONS.iter().any(|key| options.contains_key(*key)) {
                return Err(input(
                    "secure session options require explicit carrier quic-like or media-like",
                ));
            }
            return Ok(None);
        }
    };
    let allowed = [
        "--carrier",
        "--record-profile",
        "--duplex",
        "--compression",
        "--layer",
        "--max-packet",
        "--device",
        "--udp-bind",
        "--udp-peer",
        "--path-mtu",
        "--control-socket",
        "--identity",
        "--allow-key",
        "--swift-forward-kbit",
        "--swift-reverse-kbit",
        "--swift-channels",
        "--swift-window",
        "--swift-repair-permille",
        "--swift-report-ms",
    ];
    let carrier_options = [
        "--udp-cover",
        "--ca",
        "--server-name",
        "--sni",
        "--cert",
        "--key",
    ];
    if records_plan && options.contains_key("--swift-transaction-plan") {
        return Err(input(
            "Common and Swift transaction plans are mutually exclusive",
        ));
    }
    if options.get("--record-profile").map(String::as_str)
        != Some(if records_plan { "common" } else { "swift" })
        || config.duplex != Duplex::Full
        || config.compression != Compression::None
        || options.keys().any(|key| {
            !(allowed.contains(&key.as_str())
                || OPTIONS.contains(&key.as_str())
                || carrier == Carrier::OpenVpn && carrier_options.contains(&key.as_str())
                || inspection && key == "--role")
        })
    {
        return Err(input(
            "secure UDP requires its explicit matching record profile/full/no-compression and only documented options",
        ));
    }
    if inspection {
        if !(options.contains_key("--swift-transaction-plan") || records_plan)
            || [
                "--device",
                "--control-socket",
                "--session-admission-key-file",
                "--session-cookie-key-file",
                "--runtime-model",
            ]
            .iter()
            .any(|key| options.contains_key(*key))
        {
            return Err(input(
                "inspection requires a transaction plan and excludes runtime-only options",
            ));
        }
    } else {
        required(options, "--device")?;
        required(options, "--session-admission-key-file")?;
    }
    for key in ["--noise-private-key-file", "--noise-peer-key-file"] {
        required(options, key)?;
    }
    let role = match command {
        "connect"
            if !options.contains_key("--allow-key")
                && !options.contains_key("--session-cookie-key-file") =>
        {
            required(options, "--identity")?;
            security::Role::Initiator
        }
        "serve" if !options.contains_key("--identity") => {
            required(options, "--allow-key")?;
            if !inspection {
                required(options, "--session-cookie-key-file")?;
            }
            security::Role::Responder
        }
        _ => {
            return Err(input(
                "member and server-only cookie inputs differ between connect and serve",
            ));
        }
    };
    if carrier == Carrier::OpenVpn {
        match command {
            "connect"
                if !["--cert", "--key"]
                    .iter()
                    .any(|key| options.contains_key(*key)) =>
            {
                required(options, "--ca")?;
                required(options, "--server-name")?;
            }
            "serve"
                if !["--ca", "--server-name", "--sni"]
                    .iter()
                    .any(|key| options.contains_key(*key)) =>
            {
                required(options, "--cert")?;
                required(options, "--key")?;
            }
            _ => {
                return Err(input(
                    "OpenVPN outer TLS inputs differ between connect and serve",
                ));
            }
        }
    }
    let profile = match required(options, "--noise-profile")? {
        "ik" if !options.contains_key("--noise-psk-file") => hs::Profile::Ik,
        "ikpsk2" if options.contains_key("--noise-psk-file") => hs::Profile::IkPsk2,
        _ => return Err(input("explicit Noise profile and PSK input do not match")),
    };
    let address = |key| {
        required(options, key)?
            .parse::<SocketAddr>()
            .map_err(|_| input("secure UDP endpoint requires IP:PORT"))
    };
    let local = address("--udp-bind")?;
    let peer = address("--udp-peer")?;
    if local.port() == 0
        || peer.port() == 0
        || local.ip().is_unspecified()
        || peer.ip().is_unspecified()
        || local.is_ipv4() != peer.is_ipv4()
        || local == peer
    {
        return Err(input(
            "secure UDP requires a fixed distinct nonzero endpoint pair",
        ));
    }
    let maximum_mtu = number(options, "--max-path-mtu", 9000)?;
    if let Some(path) = options.get("--common-transaction-plan") {
        if [
            "--path-mtu",
            "--swift-forward-kbit",
            "--swift-reverse-kbit",
            "--swift-channels",
            "--swift-window",
            "--swift-repair-permille",
            "--swift-report-ms",
        ]
        .iter()
        .any(|key| options.contains_key(*key))
        {
            return Err(input(
                "transaction plan conflicts with legacy Swift mutable/report options",
            ));
        }
        let plan = common_cli::Plan::read(std::path::Path::new(path))?;
        plan.validate_carrier(carrier == Carrier::OpenVpn)?;
        let initial = plan.initial().path_mtu();
        if !(576..=9000).contains(&maximum_mtu) || !(576..=maximum_mtu).contains(&initial) {
            return Err(input("transaction initial MTU/capacity is out of range"));
        }
        return Ok(Some(Selected(
            Choice::Records(
                Common {
                    appearance,
                    role,
                    local,
                    peer,
                    maximum_mtu,
                    profile,
                },
                Box::new(plan),
            ),
            carrier,
        )));
    }
    if let Some(path) = options.get("--swift-transaction-plan") {
        if [
            "--path-mtu",
            "--swift-forward-kbit",
            "--swift-reverse-kbit",
            "--swift-channels",
            "--swift-window",
            "--swift-repair-permille",
            "--swift-report-ms",
        ]
        .iter()
        .any(|key| options.contains_key(*key))
        {
            return Err(input(
                "transaction plan conflicts with legacy Swift mutable/report options",
            ));
        }
        let plan = transaction_cli::Plan::read(std::path::Path::new(path))?;
        let initial = plan.initial().path_mtu();
        if !(576..=9000).contains(&maximum_mtu) || !(576..=maximum_mtu).contains(&initial) {
            return Err(input("transaction initial MTU/capacity is out of range"));
        }
        return Ok(Some(Selected(
            Choice::Transaction(
                Common {
                    appearance,
                    role,
                    local,
                    peer,
                    maximum_mtu,
                    profile,
                },
                Box::new(plan),
            ),
            carrier,
        )));
    }
    let forward_kbit = required(options, "--swift-forward-kbit")?
        .parse()
        .map_err(|_| input("invalid forward budget"))?;
    let reverse_kbit = required(options, "--swift-reverse-kbit")?
        .parse()
        .map_err(|_| input("invalid reverse budget"))?;
    let policy = l2tunnel_swift::control::Policy {
        path_mtu: number(options, "--path-mtu", 1500)?,
        forward_kbit,
        reverse_kbit,
        channels: number(options, "--swift-channels", 16)?,
        window: number(options, "--swift-window", 64)?,
        repair_permille: number(options, "--swift-repair-permille", 0)?,
    };

    if !(576..=9000).contains(&policy.path_mtu)
        || !(usize::from(policy.path_mtu)..=9000).contains(&maximum_mtu)
        || !(64..=10_000_000).contains(&policy.forward_kbit)
        || !(64..=10_000_000).contains(&policy.reverse_kbit)
        || !(1..=64).contains(&policy.channels)
        || policy.window == 0
        || policy.repair_permille > 1000
    {
        return Err(input("secure UDP Swift policy/capacity is out of range"));
    }
    let report = match number(options, "--swift-report-ms", 0u64)? {
        0 => None,
        value @ 100..=60_000 => Some(Duration::from_millis(value)),
        _ => return Err(input("report interval must be0 or100..60000ms")),
    };
    Ok(Some(Selected(
        Choice::Legacy(Selection {
            appearance,
            role,
            local,
            peer,
            policy,
            maximum_mtu,
            profile,
            report,
        }),
        carrier,
    )))
}

fn public_digest(domain: &[u8], peers: establish::Peers) -> [u8; 32] {
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    context.update(domain);
    context.update(&peers.initiator.0);
    context.update(&peers.responder.0);
    let mut result = [0; 32];
    result.copy_from_slice(context.finish().as_ref());
    result
}
impl Common {
    fn carrier_geometry(
        self,
        settings: &mut secure_udp::Settings,
        capacity: usize,
    ) -> io::Result<(usize, usize)> {
        let cover = settings.cover;
        let prototype = l2tunnel_cover::Config::new(
            cover.appearance,
            l2tunnel_cover::ConnectionIds {
                local: cover.initiator_connection,
                peer: cover.responder_connection,
            },
            l2tunnel_cover::MediaConfig {
                local_ssrc: cover.initiator_ssrc,
                peer_ssrc: cover.responder_ssrc,
                payload_type: cover.payload_type,
            },
            l2tunnel_cover::Limits {
                max_packet_bytes: cover.max_packet_bytes,
                max_protected_bytes: cover.max_protected_bytes,
            },
        )
        .map_err(io::Error::other)?;
        // Derive this new carrier's requested capacity with the maintained codec.
        // Existing descriptors and source/native/MTU values are never rewritten.
        let mut low = 0;
        let mut high = capacity.min(cover.max_protected_bytes);
        while low < high {
            let middle = low + (high - low).div_ceil(2);
            if prototype
                .overhead(l2tunnel_cover::Phase::Handshake, middle)
                .map_err(io::Error::other)?
                .checked_add(middle)
                .ok_or_else(|| input("carrier cover length overflow"))?
                <= capacity
            {
                low = middle;
            } else {
                high = middle - 1;
            }
        }
        settings.cover.max_packet_bytes = capacity;
        settings.cover.max_protected_bytes = low;
        settings.cover.bootstrap_overhead(self.local.is_ipv6())?;
        let maximum_body = low
            .checked_sub(9 + security::COMMON_PREFIX_BYTES + 16)
            .ok_or_else(|| input("outer carrier cannot fit common protection"))?;
        Ok((self.geometry()?.0, maximum_body))
    }
    fn geometry(self) -> io::Result<(usize, usize)> {
        let ip = if self.local.is_ipv6() { 48 } else { 28 };
        let header = if self.appearance == l2tunnel_cover::Appearance::QuicLike {
            13
        } else {
            14
        };
        let overhead = ip + header + 9 + security::COMMON_PREFIX_BYTES + 16;
        let maximum_body = self
            .maximum_mtu
            .checked_sub(overhead)
            .ok_or_else(|| input("capacity below secure framing"))?;
        Ok((overhead, maximum_body))
    }
    fn raw(
        self,
        path_mtu: usize,
        handshake_timeout: Duration,
        peers: establish::Peers,
        member: l2tunnel_identity::MemberPublicKey,
    ) -> io::Result<secure_udp::Settings> {
        let ip = if self.local.is_ipv6() { 48 } else { 28 };
        let header = if self.appearance == l2tunnel_cover::Appearance::QuicLike {
            13
        } else {
            14
        };
        let handshake_header = if self.appearance == l2tunnel_cover::Appearance::QuicLike {
            30
        } else {
            14
        };
        let ids = |domain: &[u8]| -> io::Result<[u8; 8]> {
            public_digest(domain, peers)[..8]
                .try_into()
                .map_err(|_| input("public CID derivation bound"))
        };
        let ssrc = |domain: &[u8]| {
            public_digest(domain, peers)[..4]
                .try_into()
                .map(u32::from_be_bytes)
                .map_err(|_| input("public SSRC derivation bound"))
        };
        let cover = secure_udp::Cover {
            appearance: self.appearance,
            initiator_connection: l2tunnel_cover::ConnectionId(ids(
                b"l2tunnel/service/CID/initiator/v1\0",
            )?),
            responder_connection: l2tunnel_cover::ConnectionId(ids(
                b"l2tunnel/service/CID/responder/v1\0",
            )?),
            initiator_ssrc: l2tunnel_cover::Ssrc(ssrc(b"l2tunnel/service/SSRC/initiator/v1\0")?),
            responder_ssrc: l2tunnel_cover::Ssrc(ssrc(b"l2tunnel/service/SSRC/responder/v1\0")?),
            payload_type: 96,
            max_packet_bytes: self
                .maximum_mtu
                .checked_sub(ip + header)
                .and_then(|value| value.checked_add(handshake_header))
                .ok_or_else(|| input("cover capacity overflow"))?,
            max_protected_bytes: self
                .maximum_mtu
                .checked_sub(ip + header)
                .ok_or_else(|| input("capacity below cover framing"))?,
        };
        let path = match self.role {
            security::Role::Initiator => gate::Path {
                client: self.local,
                server: self.peer,
            },
            security::Role::Responder => gate::Path {
                client: self.peer,
                server: self.local,
            },
        };
        let mut gate = gate::Config::new(
            path,
            public_digest(b"l2tunnel/service/bootstrap-profile/v1\0", peers),
            1,
        )
        .map_err(io::Error::other)?;
        gate.path_mtu = path_mtu;
        gate.outer_overhead = cover.bootstrap_overhead(self.local.is_ipv6())?;
        gate.arq.max_source_bytes = gate
            .path_mtu
            .checked_sub(
                gate.outer_overhead + gate::CONTROL_OVERHEAD + l2tunnel_recovery::DATA_HEADER_BYTES,
            )
            .ok_or_else(|| input("bootstrap MTU cannot hold ARQ framing"))?
            .min(1200);
        gate.arq.send_bytes = gate
            .arq
            .max_source_bytes
            .checked_mul(gate.arq.send_records)
            .ok_or_else(|| input("bootstrap send capacity overflow"))?;
        gate.arq.receive_bytes = gate
            .arq
            .max_source_bytes
            .checked_mul(gate.arq.receive_records)
            .ok_or_else(|| input("bootstrap receive capacity overflow"))?;
        gate.handshake_timeout = handshake_timeout;
        gate.cookie_ttl = gate.cookie_ttl.min(handshake_timeout);
        gate.maximum_rto = gate.maximum_rto.min(handshake_timeout);
        gate.initial_rto = gate.initial_rto.min(gate.maximum_rto);
        Ok(secure_udp::Settings {
            gate,
            cover,
            profile: self.profile,
            application: l2tunnel_core::ConfigDigest(public_digest(
                b"l2tunnel/service/application/v1\0",
                peers,
            )),
            outer: public_digest(b"l2tunnel/service/outer/v1\0", peers),
            member,
            membership: secure_udp::Membership {
                retry_interval: Duration::from_millis(100),
                max_attempts: 128,
                receive_interval: Duration::from_millis(10),
                receive_packets_per_interval: 128,
            },
            bootstrap_receive_packets_per_interval: 128,
        })
    }
}
impl Selection {
    pub(crate) fn build(
        self,
        connection: ConnectionConfig,
        peers: establish::Peers,
        member: l2tunnel_identity::MemberPublicKey,
    ) -> io::Result<Profile> {
        let common = Common::from(self);
        let (overhead, maximum_body) = common.geometry()?;
        let body = usize::from(self.policy.path_mtu)
            .checked_sub(overhead)
            .ok_or_else(|| input("path MTU below secure framing"))?;
        let selected = common.raw(
            usize::from(self.policy.path_mtu),
            connection.handshake_timeout,
            peers,
            member,
        )?;
        let direction = |forward: bool| -> policy::Direction {
            let rate = u64::from(if forward {
                self.policy.forward_kbit
            } else {
                self.policy.reverse_kbit
            }) * 125;
            policy::Direction {
                records: records::Config {
                    channels: usize::from(self.policy.channels),
                    layer: match connection.layer {
                        PacketLayer::Ethernet => records::Layer::Ethernet,
                        PacketLayer::Ip => records::Layer::Ip,
                    },
                    max_native: connection.max_packet,
                    codec: l2tunnel_swift::Config {
                        datagram_bytes: body,
                        window: usize::from(self.policy.window),
                        repair_numerator: u32::from(self.policy.repair_permille),
                        repair_denominator: 1000,
                        flow_sources: 4096,
                        queue_bytes: usize::try_from(rate / 50)
                            .unwrap_or(usize::MAX)
                            .clamp(2 * (connection.max_packet + 3), 1 << 20),
                        max_packet: connection.max_packet + l2tunnel_swift::header::MAX_EXPANSION,
                        flush_micros: 1000,
                        feedback_micros: 5000,
                        tail_micros: 10000,
                        min_rto_micros: 20000,
                        max_rto_micros: 1000000,
                    },
                },
                bytes_per_second: rate,
            }
        };
        let recovery = l2tunnel_recovery::ArqConfig {
            max_source_bytes: 256,
            send_records: 32,
            receive_records: 32,
            send_bytes: 8192,
            receive_bytes: 8192,
            ..l2tunnel_recovery::ArqConfig::default()
        };
        let pair_cost = recovery.max_source_bytes
            + l2tunnel_recovery::DATA_HEADER_BYTES
            + l2tunnel_recovery::ACK_PACKET_BYTES
            + 2 * overhead;
        // Fixed per-role credit headroom absorbs timer granularity. This is
        // authenticated geometry, not a change to either wire-rate budget.
        let burst = |rate: u64| -> io::Result<transport::WireBudget> {
            let credit = usize::try_from(rate / 250).map_err(io::Error::other)?;
            Ok(transport::WireBudget {
                burst_bytes: self
                    .maximum_mtu
                    .max(credit)
                    .checked_add(pair_cost)
                    .ok_or_else(|| input("wire burst geometry overflow"))?,
            })
        };
        let send = direction(true);
        let receive = direction(false);
        let initiator = transport::Config {
            path_mtu: usize::from(self.policy.path_mtu),
            send,
            receive,
            policy: policy::Settings {
                transaction_micros: 10_000_000,
                max_outbound: 32,
            },
            security: security::Limits {
                max_body_bytes: maximum_body,
                packets_per_key: security::MAX_PACKETS_PER_KEY,
                max_body_bytes_per_key: security::MAX_BODY_BYTES_PER_KEY,
            },
            control: l2tunnel_management::delivery::Settings {
                recovery,
                interval: Duration::from_millis(10),
                packets_per_interval: 4,
                bytes_per_interval: pair_cost * 2,
                wire_overhead: overhead,
            },
            control_epoch: security::Epoch(1),
            streams: None,
            data_epoch: security::Epoch(1),
            wire: burst(send.bytes_per_second)?,
            work: transport::WorkBudget {
                receive_interval: Duration::from_millis(1),
                receive_packets: 256,
                send_batch: 64,
                native_read_batch: 64,
                native_write_batch: 64,
            },
            native: transport::NativeBudget {
                pending_packets: 64,
                pending_bytes: connection.max_packet * 64,
                stall_timeout: Duration::from_secs(10),
            },
            lifetime: transport::Lifetime {
                lease: Duration::from_secs(3600),
                ping_interval: Duration::from_secs(1),
                pong_timeout: Duration::from_secs(5),
            },
            rolling_work: None,
            report_interval: Some(self.report.unwrap_or(Duration::from_secs(1))),
        };
        let responder = transport::Config {
            send: initiator.receive,
            receive: initiator.send,
            wire: burst(receive.bytes_per_second)?,
            ..initiator
        };
        Profile::new(connection, selected, initiator, responder)
    }
}

pub(super) fn inspect(options: &BTreeMap<String, String>) -> io::Result<()> {
    let role = required(options, "--role")?;
    if !matches!(role, "connect" | "serve") {
        return Err(input("role must be connect or serve"));
    }
    let connection = configuration(options)?;
    let selected = selection_for(role, options, connection, true)?
        .ok_or_else(|| input("inspection requires explicit secure UDP carrier"))?;
    let common = selected.common();
    let noise = credentials::NoiseIdentity::new(
        credentials::read_secret(std::path::Path::new(required(
            options,
            "--noise-private-key-file",
        )?))?,
        hs::PeerKey(credentials::read_public(std::path::Path::new(required(
            options,
            "--noise-peer-key-file",
        )?))?),
        common.profile,
        options
            .get("--noise-psk-file")
            .map(|path| credentials::read_secret(std::path::Path::new(path)))
            .transpose()?,
    )?;
    let peers = noise.peers(common.role);
    let member = if role == "connect" {
        credentials::read_member(std::path::Path::new(required(options, "--identity")?))?
            .public_key()
    } else {
        l2tunnel_identity::MemberPublicKey(credentials::read_public(std::path::Path::new(
            required(options, "--allow-key")?,
        ))?)
    };
    let values = match selected.build(connection, peers, member)? {
        Built::Transaction(profile) => {
            vec![transaction_cli_output::inspection(&profile, common.role)?]
        }
        Built::Records(profile) => match selected.outer_config(&profile)? {
            Some(outer) => common_cli_output::carrier_inspection(&profile, common.role, outer)?,
            None => common_cli_output::inspection(&profile, common.role)?,
        },
        Built::Legacy(_) => return Err(input("inspection requires explicit transaction plan")),
    };
    let values = common_cli_output::requested_tls(values, tls_frontend::requested(options)?)?;
    let mut stdout = io::stdout().lock();
    for value in values {
        serde_json::to_writer(&mut stdout, &value).map_err(io::Error::other)?;
        writeln!(stdout)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) async fn execute(
    command: &str,
    options: &BTreeMap<String, String>,
    config: ConnectionConfig,
    selected: Selected,
) -> io::Result<()> {
    use crate::service::{self, Completed, Terminal};
    use std::path::Path;
    let report_interval = selected.report_interval();
    let generic = selected.transaction();
    let common = selected.common();
    let noise = credentials::NoiseIdentity::new(
        credentials::read_secret(Path::new(required(options, "--noise-private-key-file")?))?,
        hs::PeerKey(credentials::read_public(Path::new(required(
            options,
            "--noise-peer-key-file",
        )?))?),
        common.profile,
        options
            .get("--noise-psk-file")
            .map(|path| credentials::read_secret(Path::new(path)))
            .transpose()?,
    )?;
    let peers = noise.peers(common.role);
    let admission = credentials::Secret32::new(credentials::read_secret(Path::new(required(
        options,
        "--session-admission-key-file",
    )?))?)?;
    let name = required(options, "--device")?.to_owned();
    let attachment = service::Attachment::readable(config.layer, move || {
        Ok(crate::swift::Native::new(
            l2tunnel_platform_linux::TunTap::attach(&name, config.layer)?,
        ))
    });
    let plan = match command {
        "connect" => {
            let member_der =
                credentials::read_member_der(Path::new(required(options, "--identity")?))?;
            let member = l2tunnel_identity::IdentityKey::from_pkcs8(&member_der)
                .map_err(io::Error::other)?;
            let profile = selected.build(config, peers, member.public_key())?;
            let credentials = credentials::Client::new(noise, member, admission)?;
            match profile {
                Built::Legacy(profile) => {
                    service::Prepared::secure_udp_client(*profile, credentials, attachment)?
                }
                Built::Transaction(profile) => service::Prepared::secure_udp_transaction_client(
                    *profile,
                    credentials,
                    attachment,
                )?,
                Built::Records(profile) => match selected.outer_config(&profile)? {
                    Some(outer) => {
                        let tls = tls_frontend::client(options)?;
                        let member = MemberKey::from_pkcs8(&member_der).map_err(auth_error)?;
                        let outer_credentials = service::Client {
                            remote: common.peer,
                            tls,
                            server_name: required(options, "--server-name")?.to_owned(),
                            member: std::sync::Arc::new(member),
                        };
                        service::Prepared::secure_udp_common_carrier_client(
                            *profile,
                            outer,
                            outer_credentials,
                            credentials,
                            attachment,
                        )?
                    }
                    None => service::Prepared::secure_udp_common_client(
                        *profile,
                        credentials,
                        attachment,
                    )?,
                },
            }
        }
        "serve" => {
            let member = l2tunnel_identity::MemberPublicKey(credentials::read_public(Path::new(
                required(options, "--allow-key")?,
            ))?);
            let cookie = credentials::Secret32::new(credentials::read_secret(Path::new(
                required(options, "--session-cookie-key-file")?,
            ))?)?;
            let profile = selected.build(config, peers, member)?;
            let credentials = credentials::Server::new(noise, admission, cookie)?;
            match profile {
                Built::Legacy(profile) => {
                    service::Prepared::secure_udp_server(*profile, credentials, attachment)?
                }
                Built::Transaction(profile) => service::Prepared::secure_udp_transaction_server(
                    *profile,
                    credentials,
                    attachment,
                )?,
                Built::Records(profile) => match selected.outer_config(&profile)? {
                    Some(outer) => {
                        let tls = ServerTls::from_der(
                            &[bounded_file(required(options, "--cert")?, 65536)?],
                            &bounded_file(required(options, "--key")?, 65536)?,
                        )
                        .map_err(auth_error)?;
                        let members = MemberAllowlist::new(&[auth::MemberPublicKey(member.0)])
                            .map_err(auth_error)?;
                        let outer_credentials = service::Server {
                            listen: common.local,
                            tls,
                            members,
                        };
                        service::Prepared::secure_udp_common_carrier_server(
                            *profile,
                            outer,
                            outer_credentials,
                            credentials,
                            attachment,
                        )?
                    }
                    None => service::Prepared::secure_udp_common_server(
                        *profile,
                        credentials,
                        attachment,
                    )?,
                },
            }
        }
        _ => return Err(input("unsupported secure UDP command")),
    };
    let api = options
        .get("--control-socket")
        .map(crate::local::Server::bind)
        .transpose()?;
    // Keep this shared API for explicit lower-layer reconnect after a connected
    // generation fails. This neither retries automatically nor resets Records.
    let local_control = api.is_some();
    let (handle, run) = service::channel();
    let submit = |error| io::Error::other(format!("service request: {error:?}"));
    let accepted = handle
        .connect(plan, handle.next_key().map_err(submit)?)
        .map_err(submit)?;
    let life = handle.clone();
    let lifecycle = async move {
        let mut cursor = accepted.operation.value().saturating_sub(1);
        let mut live = None;
        let mut connected = false;
        let mut last_performance = secure_udp::performance::Cursor::default();
        let mut report_tick =
            tokio::time::interval(report_interval.unwrap_or(Duration::from_secs(1)));
        report_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut output = output::Sink::stdout();
        let mut output_tick = tokio::time::interval(Duration::from_millis(5));
        output_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let stopped = async {
                match live {
                    Some(generation) => life.wait_stopped(generation).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                terminal = stopped => {
                    let generation = live;
                    live = None;
                    let terminal = terminal.map_err(submit)?;
                    if generic {
                        emit_transaction(life.snapshot().runtime.as_ref(), generation, TransactionEvent::Terminal(terminal), &mut output);
                    } else {
                        emit_performance(life.snapshot().runtime.as_ref().and_then(service::Observation::secure_udp), &mut last_performance, &mut output);
                        output.emit(serde_json::json!({"event":"secure_udp_terminal","outcome":format!("{terminal:?}")}));
                    }
                    if let Terminal::Failed(failure) = terminal && !local_control {
                        output.flush_turn();
                        return Err(io::Error::new(failure.kind, "secure UDP runtime failed"));
                    }
                }
                result = life.wait_next(cursor) => {
                    let (operation, result) = result.map_err(submit)?;
                    cursor = operation.value();
                    match result {
                        Completed::Connected { generation } => {
                            connected = true;
                            if generic && let Some(previous) = live.take() {
                                let terminal = life.wait_stopped(previous).await.map_err(submit)?;
                                emit_transaction(life.snapshot().runtime.as_ref(), Some(previous), TransactionEvent::Terminal(terminal), &mut output);
                            }
                            live = Some(generation);
                            let snapshot = life.snapshot();
                            if generic {
                                emit_transaction(snapshot.runtime.as_ref(), Some(generation), TransactionEvent::Ready, &mut output);
                            } else {
                                let frame = snapshot.runtime.as_ref().and_then(service::Observation::secure_udp);
                                match frame.map(service::SecureUdpFrame::status).transpose() {
                                    Ok(Some(status)) => output.emit(serde_json::json!({"event":"secure_udp_ready","status":status})),
                                    _ => output.projection_error(),
                                }
                                emit_performance(frame, &mut last_performance, &mut output);
                            }
                        }
                        Completed::Failed(failure) => {
                            let mut diagnostic = output::Sink::stderr();
                            match life.setup_observation(operation) {
                                Ok(Some(observation)) => setup_output::failed(observation, &mut diagnostic),
                                _ => diagnostic.projection_error(),
                            }
                            if !local_control || !connected {
                                return Err(io::Error::new(failure.kind, "secure UDP setup failed"));
                            }
                        },
                        Completed::Cancelled => {
                            if !local_control || !connected {
                                return Err(io::Error::new(io::ErrorKind::Interrupted, "secure UDP setup cancelled"));
                            }
                        },
                        Completed::Aborted => {
                            if generic && let Some(generation) = live.take() {
                                // Completion may win select before wait_stopped. Observe
                                // the real release before forgetting its generation.
                                let terminal = life.wait_stopped(generation).await.map_err(submit)?;
                                emit_transaction(life.snapshot().runtime.as_ref(), Some(generation), TransactionEvent::Terminal(terminal), &mut output);
                            }
                            live = None;
                        }
                        Completed::Applied(_) | Completed::Rejected(_) | Completed::Common { .. } | Completed::OutcomeUnknown => {}
                    }
                }
                _ = report_tick.tick(), if report_interval.is_some() => {
                    if generic {
                        if live.is_some() { emit_transaction(life.snapshot().runtime.as_ref(), live, TransactionEvent::Status, &mut output); }
                    } else {
                        emit_performance(life.snapshot().runtime.as_ref().and_then(service::Observation::secure_udp), &mut last_performance, &mut output);
                    }
                }
                _ = output_tick.tick(), if output.has_pending() => {},
            }
            output.flush_turn();
        }
    };
    let local = async {
        match api {
            Some(api) => {
                api.serve(move |request| {
                    let handle = handle.clone();
                    async move { handle.lifecycle_request(request).await }
                })
                .await
            }
            None => std::future::pending::<io::Result<()>>().await,
        }
    };
    tokio::select! { result = run => result, result = lifecycle => result, result = local => result }
}

#[cfg(target_os = "linux")]
fn emit_transaction(
    observation: Option<&crate::service::Observation>,
    generation: Option<crate::service::OperationId>,
    event: TransactionEvent,
    output: &mut output::Sink,
) {
    if observation
        .and_then(crate::service::Observation::secure_udp_common)
        .is_some()
    {
        let value = match (
            observation.and_then(crate::service::Observation::secure_udp_common),
            generation,
        ) {
            (Some(frame), Some(generation)) => {
                common_cli_output::event(frame, generation.value(), event)
            }
            _ => Err(input("missing matching Common observation")),
        };
        match value {
            Ok(value) => output.emit(value),
            Err(_) => output.projection_error(),
        }
        return;
    }
    let value = match (
        observation.and_then(crate::service::Observation::secure_udp_transaction),
        generation,
    ) {
        (Some(frame), Some(generation)) => match event {
            TransactionEvent::Ready => transaction_cli_output::ready(frame, generation.value()),
            TransactionEvent::Status => transaction_cli_output::status(frame, generation.value()),
            TransactionEvent::Terminal(terminal) => {
                transaction_cli_output::terminal(frame, generation.value(), terminal)
            }
        },
        _ => Err(input("missing matching generic transaction observation")),
    };
    match value {
        Ok(value) => output.emit(value),
        Err(_) => output.projection_error(),
    }
}
#[cfg(target_os = "linux")]
enum TransactionEvent {
    Ready,
    Status,
    Terminal(crate::service::Terminal),
}

#[cfg(target_os = "linux")]
fn emit_performance(
    frame: Option<&crate::service::SecureUdpFrame>,
    last: &mut secure_udp::performance::Cursor,
    output: &mut output::Sink,
) {
    let report = match frame
        .map(crate::service::SecureUdpFrame::performance)
        .transpose()
    {
        Ok(Some(Some(report))) => report,
        Ok(_) => return,
        Err(_) => {
            output.projection_error();
            return;
        }
    };
    if last.accept(&report) {
        output.emit(serde_json::json!({"event":"secure_udp_performance","report":report}));
    }
}

#[cfg(target_os = "linux")]
mod output {
    use std::{
        collections::VecDeque,
        fs::{File, OpenOptions},
        io::{self, Write},
        os::fd::{AsFd, AsRawFd, BorrowedFd},
        os::unix::fs::OpenOptionsExt,
        path::Path,
    };
    pub(super) const MAX_LINE: usize = 128 * 1024;
    pub(super) const MAX_LINES: usize = 4;
    const MAX_BYTES: usize = MAX_LINE * MAX_LINES;
    pub(super) const WRITE_BYTES: usize = 64 * 1024;
    const WRITE_CALLS: usize = 4;
    /// Local logger health; observations never become protocol inputs.
    #[derive(Clone, Copy, Debug, Default, serde::Serialize)]
    pub(super) struct Health {
        pub disabled: bool,
        pub write_errors: u64,
        pub broken_pipe: u64,
        pub would_block: u64,
        pub projection_errors: u64,
        pub dropped_lines: u64,
        pub dropped_bytes: u64,
        pub written_bytes: u64,
        pub queue_bytes_high: u64,
    }
    pub(super) struct Sink {
        file: Option<File>,
        pending: VecDeque<Vec<u8>>,
        offset: usize,
        bytes: usize,
        pub(super) health: Health,
    }
    impl Sink {
        pub(super) fn stdout() -> Self {
            Self::from_stdio(std::io::stdout().as_fd()).unwrap_or_else(|_| Self {
                file: None,
                pending: VecDeque::new(),
                offset: 0,
                bytes: 0,
                health: Health {
                    disabled: true,
                    write_errors: 1,
                    ..Health::default()
                },
            })
        }
        pub(super) fn stderr() -> Self {
            Self::from_stdio(std::io::stderr().as_fd()).unwrap_or_else(|_| Self {
                file: None,
                pending: VecDeque::new(),
                offset: 0,
                bytes: 0,
                health: Health {
                    disabled: true,
                    write_errors: 1,
                    ..Health::default()
                },
            })
        }
        fn from_stdio(original: BorrowedFd<'_>) -> io::Result<Self> {
            let duplicate = File::from(original.try_clone_to_owned()?);
            if duplicate.metadata()?.is_file() {
                // Stdout and stderr may alias this same open-file description.
                // Preserve their shared offset: a separate APPEND description
                // would leave stderr's old offset able to overwrite telemetry.
                // Regular-file writes have byte/call bounds, not a nonblocking
                // disk-latency guarantee; never alter the inherited flags.
                return Ok(Self::with_file(duplicate));
            }
            // Pipes/terminals need their own nonblocking description; changing
            // the duplicate's status flags would also change inherited stdio.
            Self::reopen(Path::new(&format!(
                "/proc/self/fd/{}",
                original.as_raw_fd()
            )))
        }
        fn with_file(file: File) -> Self {
            Self {
                file: Some(file),
                pending: VecDeque::with_capacity(MAX_LINES),
                offset: 0,
                bytes: 0,
                health: Health::default(),
            }
        }
        pub(super) fn reopen(path: &Path) -> io::Result<Self> {
            // Opening procfs creates a distinct open-file description. Never set
            // O_NONBLOCK/O_APPEND on the inherited stdout description. APPEND is
            // required because this new description has an independent offset.
            let flags = rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC;
            let file = OpenOptions::new()
                .append(true)
                .custom_flags(i32::try_from(flags.bits()).map_err(io::Error::other)?)
                .open(path)?;
            Ok(Self::with_file(file))
        }
        pub(super) fn has_pending(&self) -> bool {
            !self.pending.is_empty()
        }
        pub(super) fn projection_error(&mut self) {
            self.health.projection_errors = self.health.projection_errors.saturating_add(1);
        }
        pub(super) fn emit(&mut self, mut value: serde_json::Value) {
            if self.file.is_none() {
                self.health.dropped_lines = self.health.dropped_lines.saturating_add(1);
                return;
            }
            if let Some(object) = value.as_object_mut() {
                match serde_json::to_value(self.health) {
                    Ok(health) => {
                        object.insert("log_health".into(), health);
                    }
                    Err(_) => {
                        self.projection_error();
                        return;
                    }
                }
            }
            let mut encoded = Limited(Vec::new());
            if serde_json::to_writer(&mut encoded, &value).is_err() {
                self.projection_error();
                self.health.dropped_lines = self.health.dropped_lines.saturating_add(1);
                return;
            }
            encoded.0.push(b'\n');
            if self.pending.len() == MAX_LINES
                || self.bytes.saturating_add(encoded.0.len()) > MAX_BYTES
            {
                self.health.dropped_lines = self.health.dropped_lines.saturating_add(1);
                self.health.dropped_bytes = self
                    .health
                    .dropped_bytes
                    .saturating_add(encoded.0.len() as u64);
                return;
            }
            self.bytes += encoded.0.len();
            self.health.queue_bytes_high = self.health.queue_bytes_high.max(self.bytes as u64);
            self.pending.push_back(encoded.0);
        }
        pub(super) fn flush_turn(&mut self) {
            let mut budget = WRITE_BYTES;
            for _ in 0..WRITE_CALLS {
                let (Some(file), Some(line)) = (&mut self.file, self.pending.front()) else {
                    break;
                };
                if budget == 0 {
                    break;
                }
                let end = line.len().min(self.offset.saturating_add(budget));
                match file.write(&line[self.offset..end]) {
                    Ok(0) => {
                        self.fail(io::ErrorKind::WriteZero);
                        break;
                    }
                    Ok(written) => {
                        self.offset += written;
                        self.bytes -= written;
                        budget -= written;
                        self.health.written_bytes =
                            self.health.written_bytes.saturating_add(written as u64);
                        if self.offset == line.len() {
                            self.pending.pop_front();
                            self.offset = 0;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        self.health.would_block = self.health.would_block.saturating_add(1);
                        break;
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => {
                        self.fail(error.kind());
                        break;
                    }
                }
            }
        }
        fn fail(&mut self, kind: io::ErrorKind) {
            self.health.disabled = true;
            self.health.write_errors = self.health.write_errors.saturating_add(1);
            if kind == io::ErrorKind::BrokenPipe {
                self.health.broken_pipe = self.health.broken_pipe.saturating_add(1);
            }
            self.health.dropped_lines = self
                .health
                .dropped_lines
                .saturating_add(self.pending.len() as u64);
            self.health.dropped_bytes = self.health.dropped_bytes.saturating_add(self.bytes as u64);
            self.pending.clear();
            self.bytes = 0;
            self.offset = 0;
            self.file = None;
        }
    }
    struct Limited(Vec<u8>);
    impl Write for Limited {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > (MAX_LINE - 1).saturating_sub(self.0.len()) {
                return Err(io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "bounded JSON line",
                ));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{
            io::{Read, Seek},
            os::fd::AsRawFd,
            sync::atomic::{AtomicUsize, Ordering},
        };
        fn pipe() -> io::Result<(std::io::PipeReader, std::io::PipeWriter, Sink)> {
            let (reader, writer) = std::io::pipe()?;
            let before = rustix::fs::fcntl_getfl(&writer)?;
            let sink = Sink::from_stdio(writer.as_fd())?;
            assert_eq!(
                rustix::fs::fcntl_getfl(&writer)?,
                before,
                "inherited pipe flags changed"
            );
            let flags = rustix::fs::fcntl_getfl(
                sink.file
                    .as_ref()
                    .ok_or_else(|| io::Error::other("sink file"))?,
            )?;
            assert!(flags.contains(rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::APPEND));
            Ok((reader, writer, sink))
        }
        #[test]
        fn real_full_pipe_retains_exact_partial_lines_with_bounded_queue_and_turns()
        -> io::Result<()> {
            let (mut reader, _writer, mut sink) = pipe()?;
            // Fill this actual pipe nonblockingly, then expose only a bounded
            // free prefix. This does not assume a kernel pipe capacity/page size.
            let mut filled = 0;
            let mut blocked = false;
            for _ in 0..4096 {
                match sink
                    .file
                    .as_mut()
                    .ok_or_else(|| io::Error::other("sink file"))?
                    .write(&[b'P'; 4096])
                {
                    Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "pipe prefill")),
                    Ok(bytes) => filled += bytes,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        blocked = true;
                        break;
                    }
                    Err(error) => return Err(error),
                }
            }
            assert!(
                blocked && filled > 0,
                "actual pipe did not fill within the finite fixture bound"
            );
            let free = filled.min(8192);
            reader.read_exact(&mut vec![0; free])?;
            for index in 0..MAX_LINES {
                sink.emit(serde_json::json!({"index":index,"body":"x".repeat(MAX_LINE / 2)}));
            }
            assert_eq!(sink.pending.len(), MAX_LINES);
            sink.flush_turn();
            assert!(sink.health.would_block > 0);
            assert!(sink.health.written_bytes <= WRITE_BYTES as u64);
            assert!(sink.offset > 0 && sink.has_pending());
            let bytes = sink.bytes;
            sink.emit(serde_json::json!({"discarded":"bounded"}));
            assert_eq!(sink.pending.len(), MAX_LINES);
            assert_eq!(sink.bytes, bytes);
            assert_eq!(sink.health.dropped_lines, 1);
            reader.read_exact(&mut vec![0; filled - free])?;
            let mut received = Vec::new();
            let mut read = 0;
            for _ in 0..128 {
                let produced = sink.health.written_bytes as usize - read;
                if produced > 0 {
                    let mut chunk = vec![0; produced];
                    reader.read_exact(&mut chunk)?;
                    received.extend_from_slice(&chunk);
                    read += produced;
                }
                if !sink.has_pending() {
                    break;
                }
                let before = sink.health.written_bytes;
                sink.flush_turn();
                assert!(sink.health.written_bytes - before <= WRITE_BYTES as u64);
            }
            assert!(!sink.has_pending());
            assert_eq!(sink.bytes, 0);
            let lines = received
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .collect::<Vec<_>>();
            assert_eq!(lines.len(), MAX_LINES);
            for (index, line) in lines.iter().enumerate() {
                let value: serde_json::Value = serde_json::from_slice(line)?;
                assert_eq!(value["index"], index);
                assert_eq!(value["body"].as_str().map(str::len), Some(MAX_LINE / 2));
            }
            Ok(())
        }
        #[test]
        fn broken_pipe_and_projection_failures_are_nonfatal_and_bounded() -> io::Result<()> {
            let (reader, _writer, mut sink) = pipe()?;
            sink.projection_error();
            sink.emit(serde_json::json!({"too_large":"x".repeat(MAX_LINE * 2)}));
            assert!(sink.pending.is_empty());
            assert_eq!(sink.health.projection_errors, 2);
            drop(reader);
            sink.emit(serde_json::json!({"event":"terminal"}));
            sink.flush_turn();
            assert!(sink.health.disabled);
            assert_eq!(sink.health.broken_pipe, 1);
            assert_eq!(sink.health.write_errors, 1);
            assert!(!sink.has_pending());
            assert_eq!(sink.bytes, 0);
            assert!(sink.file.is_none());
            let dropped = sink.health.dropped_lines;
            sink.emit(serde_json::json!({"event":"still_nonfatal"}));
            sink.flush_turn();
            assert_eq!(sink.health.dropped_lines, dropped + 1);
            Ok(())
        }
        #[test]
        fn regular_file_sink_appends_without_changing_inherited_offset_or_flags() -> io::Result<()>
        {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "l2tunnel-log-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let mut original = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)?;
            std::fs::remove_file(&path)?;
            original.write_all(b"original\n")?;
            original.rewind()?;
            let flags = rustix::fs::fcntl_getfl(&original)?;
            let mut sink = Sink::reopen(Path::new(&format!(
                "/proc/self/fd/{}",
                original.as_raw_fd()
            )))?;
            sink.emit(serde_json::json!({"event":"appended"}));
            sink.flush_turn();
            assert_eq!(rustix::fs::fcntl_getfl(&original)?, flags);
            assert_eq!(original.stream_position()?, 0);
            let mut bytes = String::new();
            original.read_to_string(&mut bytes)?;
            assert!(bytes.starts_with("original\n"));
            let value: serde_json::Value = serde_json::from_str(
                bytes
                    .strip_prefix("original\n")
                    .ok_or_else(|| io::Error::other("prefix"))?
                    .trim(),
            )?;
            assert_eq!(value["event"], "appended");
            assert!(value["log_health"].is_object());
            assert!(!sink.has_pending());
            Ok(())
        }
        #[test]
        fn stdio_regular_file_and_aliased_stderr_preserve_each_others_lines() -> io::Result<()> {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "l2tunnel-shared-log-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let mut original = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)?;
            std::fs::remove_file(&path)?;
            let mut stderr = original.try_clone()?;
            original.write_all(b"original prefix\n")?;
            let flags = rustix::fs::fcntl_getfl(&original)?;
            assert!(!flags.intersects(rustix::fs::OFlags::APPEND | rustix::fs::OFlags::NONBLOCK));
            let mut sink = Sink::from_stdio(original.as_fd())?;
            sink.emit(serde_json::json!({"event":"first telemetry"}));
            sink.flush_turn();
            assert_eq!(
                original.stream_position()?,
                b"original prefix\n".len() as u64 + sink.health.written_bytes
            );
            stderr.write_all(b"final error\n")?;
            sink.emit(serde_json::json!({"event":"second telemetry"}));
            sink.flush_turn();
            assert_eq!(rustix::fs::fcntl_getfl(&original)?, flags);
            assert_eq!(rustix::fs::fcntl_getfl(&stderr)?, flags);
            assert!(!sink.has_pending());
            original.rewind()?;
            let mut bytes = String::new();
            original.read_to_string(&mut bytes)?;
            let lines = bytes.lines().collect::<Vec<_>>();
            assert_eq!(lines.len(), 4);
            assert_eq!(lines[0], "original prefix");
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(lines[1])?["event"],
                "first telemetry"
            );
            assert_eq!(lines[2], "final error");
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(lines[3])?["event"],
                "second telemetry"
            );
            Ok(())
        }
    }
}

#[cfg(test)]
#[path = "cli_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "transaction_cli_integration_tests.rs"]
mod transaction_integration_tests;
