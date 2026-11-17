//! Explicit same-socket carrier presentation through the shared lifecycle service.
use super::*;
#[cfg(test)]
use crate::secure_udp::common_fixture::Resources;
use crate::secure_udp::{self, credentials};
use l2tunnel_handshake as hs;
use l2tunnel_runtime::secure_udp::establish;
#[cfg(test)]
use l2tunnel_runtime::secure_udp::transport;
use l2tunnel_security as security;
#[cfg(test)]
use l2tunnel_swift::{policy, records};
use l2tunnel_udp_control as gate;
#[path = "common_cli.rs"]
mod common_cli;
#[path = "common_cli_output.rs"]
mod common_cli_output;
#[path = "common_proxy_cli.rs"]
mod common_proxy_cli;
#[path = "maintained_cli.rs"]
mod maintained_cli;
#[cfg(all(test, target_os = "linux"))]
pub(crate) use common_proxy_cli::event as proxy_event_for_test;
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn proxy_inspection_for_test(
    profile: &secure_udp::common_transaction_profile::Profile,
    role: security::Role,
) -> io::Result<Vec<serde_json::Value>> {
    common_proxy_cli::inspection(profile, role)
}
#[cfg(test)]
#[path = "common_plan_fixture.rs"]
mod common_plan_fixture;
#[path = "common_runtime_cli.rs"]
mod common_runtime_cli;
#[path = "setup_output.rs"]
mod setup_output;

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
    "--proxy-close",
    "--maintained-policy",
];
pub(super) const HELP: &str = "Common tunnel: --record-profile common --common-transaction-plan PATH selects the complete authenticated catalog and local API4. Select --carrier quic-like|media-like for one UDP socket, openvpn-like for the actual original UDP handshake, raw-packet for original raw TCP, or tcp|quic for retained TLS/QUIC. Carrier-specific plans, pinned own server trust, member credentials and Noise credentials remain explicit. Swift is a catalog algorithm and has no standalone connection mode. Appearance is limited to bootstrap; all data, recovery feedback and management use final compact Records. Omitting compact_wire selects full-tag ChaCha20-Poly1305; explicit aes-ccm-4 or chacha20-crc32c retain their documented data guarantees. inspect-common-transaction-plan validates the entire requested plan without starting a device. common-catalog and switch-common-configuration use API4 and exact complete configurations. Explicit fixed/measured proxy uses the shared proxy service and API1; unsupported carrier/duplex/channel combinations are refused before startup. Native and platform qualification remain separate from plan inspection.";

#[cfg(test)]
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
#[cfg(test)]
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

#[derive(Clone, Eq, PartialEq)]
enum Carrier {
    OriginalUdp,
    OpenVpn,
    RawPacket,
    Maintained(Box<secure_udp::maintained::Settings>),
}
struct RawSelected {
    settings: crate::raw_packet::common::Settings,
    mark: Option<u32>,
}
pub(super) struct Selected(Choice, Carrier, Option<Box<RawSelected>>);
enum Choice {
    Records(Common, Box<common_cli::Plan>),
    Proxy(
        Common,
        Box<common_cli::Plan>,
        common_proxy_cli::Policy,
        bool,
    ),
}
enum Built {
    Records(Box<secure_udp::common_transaction_profile::Profile>),
    Proxy(Box<secure_udp::common_transaction_profile::Profile>),
}
impl Selected {
    fn common(&self) -> Common {
        match &self.0 {
            Choice::Records(common, _) | Choice::Proxy(common, _, _, _) => *common,
        }
    }
    #[cfg(test)]
    fn transaction(&self) -> bool {
        matches!(self.0, Choice::Records(_, _))
    }
    fn report_interval(&self) -> Option<Duration> {
        match &self.0 {
            Choice::Records(_, plan) | Choice::Proxy(_, plan, _, _) => plan.report_interval(),
        }
    }
    fn build(
        &self,
        connection: ConnectionConfig,
        peers: establish::Peers,
        member: l2tunnel_identity::MemberPublicKey,
    ) -> io::Result<Built> {
        match &self.0 {
            Choice::Records(common, plan) => {
                let mut raw = common.raw(
                    plan.initial().path_mtu(),
                    connection.handshake_timeout,
                    peers,
                    member,
                )?;
                if let Carrier::Maintained(settings) = &self.1 {
                    common.carrier_geometry(&mut raw, settings.geometry.max_bootstrap_bytes)?;
                    common.bootstrap_arq_geometry(&mut raw)?;
                    // Share final Records backing capacity while keeping actual setup
                    // protected bytes and ARQ packets within the bootstrap maximum.
                    raw.cover.max_packet_bytes = settings.geometry.max_record_bytes;
                    let maximum_body =
                        plan.protected_body_capacity(settings.geometry.max_record_bytes)?;
                    return plan
                        .build_maintained(connection, raw, peers, maximum_body, **settings)
                        .map(Box::new)
                        .map(Built::Records);
                }
                if let Some(selected) = &self.2 {
                    let policy = selected.settings.packet_policy();
                    let geometry = policy.record_geometry().map_err(io::Error::other)?;
                    let (overhead, _) = common.raw_geometry(
                        &mut raw,
                        geometry,
                        policy.final_record_geometry().map_err(io::Error::other)?,
                    )?;
                    let maximum_body = plan.protected_body_capacity(
                        policy
                            .final_record_geometry()
                            .map_err(io::Error::other)?
                            .max_record_bytes,
                    )?;
                    return plan
                        .build_raw(connection, raw, peers, maximum_body, overhead, policy)
                        .map(Box::new)
                        .map(Built::Records);
                }
                let (overhead, maximum_body) = if self.1 == Carrier::OpenVpn {
                    let capacity = plan.outer_capacity()?;
                    let (overhead, _) = common.carrier_geometry(&mut raw, capacity)?;
                    (overhead, plan.protected_body_capacity(capacity)?)
                } else {
                    common.plan_geometry(plan)?
                };
                plan.build(connection, raw, peers, maximum_body, overhead)
                    .map(Box::new)
                    .map(Built::Records)
            }
            Choice::Proxy(common, plan, settings, retained) => {
                let mut raw = common.raw(
                    plan.initial().path_mtu(),
                    connection.handshake_timeout,
                    peers,
                    member,
                )?;
                let maintained = match &self.1 {
                    Carrier::Maintained(value) => Some(**value),
                    _ => None,
                };
                let packet = self.2.as_ref().map(|value| value.settings.packet_policy());
                let (overhead, maximum_body) = if let Some(value) = maintained {
                    common.carrier_geometry(&mut raw, value.geometry.max_bootstrap_bytes)?;
                    common.bootstrap_arq_geometry(&mut raw)?;
                    raw.cover.max_packet_bytes = value.geometry.max_record_bytes;
                    (
                        value.geometry.charged_overhead_bytes,
                        plan.protected_body_capacity(value.geometry.max_record_bytes)?,
                    )
                } else if let Some(value) = packet {
                    let geometry = value.record_geometry().map_err(io::Error::other)?;
                    let final_geometry = value.final_record_geometry().map_err(io::Error::other)?;
                    let (overhead, _) = common.raw_geometry(&mut raw, geometry, final_geometry)?;
                    (
                        overhead,
                        plan.protected_body_capacity(final_geometry.max_record_bytes)?,
                    )
                } else {
                    common.plan_geometry(plan)?
                };
                let (proxy, measured) = match settings {
                    common_proxy_cli::Policy::Fixed(settings) => (
                        Some((
                            crate::proxy::runtime_config(connection, settings)?,
                            *retained,
                        )),
                        None,
                    ),
                    common_proxy_cli::Policy::Measured(settings) => {
                        if !*retained {
                            return Err(input(
                                "Common measured proxy requires explicit retained close",
                            ));
                        }
                        (
                            None,
                            Some(crate::proxy_measured::runtime_config(connection, settings)?),
                        )
                    }
                };
                plan.build_selected_on(
                    connection,
                    raw,
                    peers,
                    maximum_body,
                    overhead,
                    packet,
                    proxy,
                    measured,
                    maintained,
                )
                .map(Box::new)
                .map(Built::Proxy)
            }
        }
    }
    fn outer_config(
        &self,
        profile: &secure_udp::common_transaction_profile::Profile,
    ) -> io::Result<Option<l2tunnel_openvpn::wire_carrier::common::Config>> {
        if self.1 != Carrier::OpenVpn {
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
    if options.contains_key("--swift-transaction-plan") {
        return Err(input(
            "the Swift-only plan is retired; use --record-profile common --common-transaction-plan PATH and local API4",
        ));
    }
    let records_plan = options.contains_key("--common-transaction-plan");
    let raw_selected = options.get("--carrier").map(String::as_str) == Some("raw-packet")
        && (records_plan || options.get("--record-profile").map(String::as_str) == Some("common"));
    let maintained_selected = matches!(
        options.get("--carrier").map(String::as_str),
        Some("tcp" | "quic")
    ) && (records_plan
        || options.get("--record-profile").map(String::as_str) == Some("common"));
    let carrier = if maintained_selected {
        if !records_plan {
            return Err(input(
                "maintained Common requires its complete transaction plan",
            ));
        }
        let settings = maintained_cli::read(
            &bounded_file(required(options, "--maintained-policy")?, 16 * 1024)?,
            config,
        )?;
        let expected = if matches!(
            settings.transport,
            secure_udp::maintained::Transport::Tls(_)
        ) {
            "tcp"
        } else {
            "quic"
        };
        if options.get("--carrier").map(String::as_str) != Some(expected) {
            return Err(input(
                "maintained policy transport differs from explicit carrier",
            ));
        }
        Carrier::Maintained(Box::new(settings))
    } else if raw_selected {
        if !records_plan {
            return Err(input("raw Common requires its complete transaction plan"));
        }
        Carrier::RawPacket
    } else if options.get("--carrier").map(String::as_str) == Some("openvpn-like")
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
    if options.contains_key("--maintained-policy") && !maintained_selected {
        return Err(input(
            "maintained policy requires explicit TCP/QUIC Common selection",
        ));
    }
    let appearance = match options.get("--carrier").map(String::as_str) {
        Some("quic-like") => l2tunnel_cover::Appearance::QuicLike,
        Some("media-like") => l2tunnel_cover::Appearance::MediaLike,
        Some("tcp" | "quic") if maintained_selected => match required(options, "--udp-cover")? {
            "quic-like" => l2tunnel_cover::Appearance::QuicLike,
            "media-like" => l2tunnel_cover::Appearance::MediaLike,
            _ => return Err(input("maintained Common requires explicit bootstrap cover")),
        },
        Some("raw-packet") if carrier == Carrier::RawPacket => {
            match required(options, "--udp-cover")? {
                "quic-like" => l2tunnel_cover::Appearance::QuicLike,
                "media-like" => l2tunnel_cover::Appearance::MediaLike,
                _ => {
                    return Err(input(
                        "raw Common requires explicit inner quic-like or media-like cover",
                    ));
                }
            }
        }
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
    let proxy = common_proxy_cli::selection(options, config, records_plan, &carrier)?;
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
    if options.get("--record-profile").map(String::as_str) != Some("common")
        || !matches!(carrier, Carrier::RawPacket | Carrier::Maintained(_))
            && config.duplex != Duplex::Full
        || options.keys().any(|key| {
            !(allowed.contains(&key.as_str())
                || OPTIONS.contains(&key.as_str())
                || carrier != Carrier::OriginalUdp && carrier_options.contains(&key.as_str())
                || matches!(carrier, Carrier::Maintained(_))
                    && ["--remote", "--listen"].contains(&key.as_str())
                || carrier == Carrier::RawPacket
                    && ["--raw-policy", "--raw-mark", "--remote", "--listen"]
                        .contains(&key.as_str())
                || proxy
                    && ["--traffic", "--proxy-policy", "--proxy-close"].contains(&key.as_str())
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
    if carrier != Carrier::OriginalUdp {
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
    let raw = if carrier == Carrier::RawPacket {
        required(options, "--duplex")?;
        if options.contains_key("--udp-bind") || options.contains_key("--udp-peer") {
            return Err(input(
                "raw Common tuples come only from the explicit raw policy",
            ));
        }
        let settings = crate::raw_packet::common::Settings::from_json(&bounded_file(
            required(options, "--raw-policy")?,
            crate::raw_packet::MAX_POLICY_BYTES,
        )?)?;
        if settings.duplex() != config.duplex {
            return Err(input("raw policy shape differs from explicit duplex"));
        }
        let mark = if inspection {
            if options.contains_key("--raw-mark") {
                return Err(input(
                    "offline raw inspection excludes the privileged runtime mark",
                ));
            }
            None
        } else {
            let value = required(options, "--raw-mark")?
                .parse::<u32>()
                .map_err(|_| input("raw mark must be nonzero u32"))?;
            if value == 0 {
                return Err(input("raw mark must be nonzero u32"));
            }
            Some(value)
        };
        let (local, peer) = settings.forward();
        if !inspection {
            let key = if command == "connect" {
                "--remote"
            } else {
                "--listen"
            };
            let declared: SocketAddr = required(options, key)?
                .parse()
                .map_err(|_| input("raw original tuple requires IPv4:PORT"))?;
            if declared != SocketAddr::V4(if command == "connect" { peer } else { local }) {
                return Err(input("raw remote/listen differs from first actual tuple"));
            }
        }
        Some(Box::new(RawSelected { settings, mark }))
    } else {
        None
    };
    let (local, peer) = if let Carrier::Maintained(settings) = &carrier {
        if ["--udp-bind", "--udp-peer"]
            .iter()
            .any(|key| options.contains_key(*key))
        {
            return Err(input(
                "maintained tuples come only from --maintained-policy",
            ));
        }
        let pair = if role == security::Role::Initiator {
            (settings.first.client, settings.first.server)
        } else {
            (settings.first.server, settings.first.client)
        };
        if !inspection {
            let key = if command == "connect" {
                "--remote"
            } else {
                "--listen"
            };
            if address(key)? != settings.first.server {
                return Err(input(
                    "maintained remote/listen differs from first actual tuple",
                ));
            }
        }
        pair
    } else if let Some(raw) = &raw {
        let (local, peer) = raw.settings.forward();
        (SocketAddr::V4(local), SocketAddr::V4(peer))
    } else {
        (address("--udp-bind")?, address("--udp-peer")?)
    };
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
        let proxy = if proxy {
            Some(common_proxy_cli::settings(options, config)?)
        } else {
            None
        };
        let plan = common_cli::Plan::read(std::path::Path::new(path))?;
        plan.validate_carrier(carrier == Carrier::OpenVpn)?;
        if let Some(raw) = &raw {
            let geometry = raw
                .settings
                .packet_policy()
                .record_geometry()
                .map_err(io::Error::other)?;
            if plan.initial().path_mtu() != geometry.path_mtu {
                return Err(input("raw policy MTU differs from complete catalog"));
            }
        }
        let initial = plan.initial().path_mtu();
        if !(576..=9000).contains(&maximum_mtu) || !(576..=maximum_mtu).contains(&initial) {
            return Err(input("transaction initial MTU/capacity is out of range"));
        }
        return Ok(Some(Selected(
            match proxy {
                Some(settings) => Choice::Proxy(
                    Common {
                        appearance,
                        role,
                        local,
                        peer,
                        maximum_mtu,
                        profile,
                    },
                    Box::new(plan),
                    settings,
                    common_proxy_cli::retained(options)?,
                ),
                None => Choice::Records(
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
            },
            carrier,
            raw,
        )));
    }
    Err(input(
        "use --record-profile common --common-transaction-plan PATH; Swift is a catalog algorithm, not a connection mode",
    ))
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
    fn plan_geometry(self, plan: &common_cli::Plan) -> io::Result<(usize, usize)> {
        let ip = if self.local.is_ipv6() { 48 } else { 28 };
        let packet = self
            .maximum_mtu
            .checked_sub(ip)
            .ok_or_else(|| input("path capacity below IP framing"))?;
        Ok((
            self.final_geometry()?.0,
            plan.protected_body_capacity(packet)?,
        ))
    }
    fn raw_geometry(
        self,
        settings: &mut secure_udp::Settings,
        geometry: l2tunnel_raw_io::handoff::pairing::packet::RecordGeometry,
        final_geometry: l2tunnel_raw_io::handoff::pairing::packet::RecordGeometry,
    ) -> io::Result<(usize, usize)> {
        self.carrier_geometry(settings, geometry.max_record_bytes)?;
        // Bootstrap ARQ geometry derives from the selected real covered record;
        // no explicit catalog source, native, body or channel value is rewritten.
        self.bootstrap_arq_geometry(settings)?;
        // Final Records omit the bootstrap wrapper and require the corresponding
        // larger backing buffer. Keep bootstrap protected bytes and ARQ limits.
        settings.cover.max_packet_bytes = final_geometry.max_record_bytes;
        let overhead = final_geometry
            .ip_tcp_bytes
            .checked_add(l2tunnel::secure_record::compact::AUTHENTICATED_OVERHEAD)
            .ok_or_else(|| input("raw final control overhead overflow"))?;
        let maximum_body = final_geometry
            .max_record_bytes
            .checked_sub(l2tunnel::secure_record::compact::AUTHENTICATED_OVERHEAD)
            .ok_or_else(|| input("raw final capacity below authenticated framing"))?;
        Ok((overhead, maximum_body))
    }
    fn bootstrap_arq_geometry(self, settings: &mut secure_udp::Settings) -> io::Result<()> {
        settings.gate.arq.max_source_bytes = settings
            .cover
            .max_protected_bytes
            .checked_sub(gate::CONTROL_OVERHEAD + l2tunnel_recovery::DATA_HEADER_BYTES + 1)
            .ok_or_else(|| input("carrier bootstrap cannot hold maintained control framing"))?
            .min(1200);
        settings.gate.arq.send_bytes = settings
            .gate
            .arq
            .max_source_bytes
            .checked_mul(settings.gate.arq.send_records)
            .ok_or_else(|| input("carrier bootstrap send geometry overflow"))?;
        settings.gate.arq.receive_bytes = settings
            .gate
            .arq
            .max_source_bytes
            .checked_mul(settings.gate.arq.receive_records)
            .ok_or_else(|| input("carrier bootstrap receive geometry overflow"))?;
        Ok(())
    }
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
        let maximum_body = capacity
            .checked_sub(l2tunnel::secure_record::compact::AUTHENTICATED_OVERHEAD)
            .ok_or_else(|| input("outer carrier cannot fit common protection"))?;
        Ok((self.final_geometry()?.0, maximum_body))
    }
    fn final_geometry(self) -> io::Result<(usize, usize)> {
        let ip: usize = if self.local.is_ipv6() { 48 } else { 28 };
        let overhead = ip
            .checked_add(l2tunnel::secure_record::compact::AUTHENTICATED_OVERHEAD)
            .ok_or_else(|| input("final control overhead overflow"))?;
        let maximum_body = self
            .maximum_mtu
            .checked_sub(overhead)
            .ok_or_else(|| input("final capacity below authenticated framing"))?;
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
#[cfg(test)]
impl Selection {
    pub(crate) fn build(
        self,
        connection: ConnectionConfig,
        peers: establish::Peers,
        member: l2tunnel_identity::MemberPublicKey,
    ) -> io::Result<Resources> {
        let common = Common::from(self);
        let (overhead, maximum_body) = common.final_geometry()?;
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
            ack_coalescing: None,
            connection_ingress: None,
            rolling_fragments: None,
            rolling_ingress: None,
            report_interval: Some(self.report.unwrap_or(Duration::from_secs(1))),
        };
        let responder = transport::Config {
            send: initiator.receive,
            receive: initiator.send,
            wire: burst(receive.bytes_per_second)?,
            ..initiator
        };
        Ok(Resources::new(connection, selected, initiator, responder))
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
        Built::Records(profile) => {
            if let Some(raw) = &selected.2 {
                common_cli_output::raw_inspection(&profile, common.role, &raw.settings)?
            } else {
                match selected.outer_config(&profile)? {
                    Some(outer) => {
                        common_cli_output::carrier_inspection(&profile, common.role, outer)?
                    }
                    None => common_cli_output::inspection(&profile, common.role)?,
                }
            }
        }
        Built::Proxy(profile) => common_proxy_cli::inspection(&profile, common.role)?,
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
        Ok(crate::native::Native::new(
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
                Built::Proxy(profile) | Built::Records(profile) => {
                    if let Carrier::Maintained(settings) = &selected.1 {
                        let member = std::sync::Arc::new(
                            MemberKey::from_pkcs8(&member_der).map_err(auth_error)?,
                        );
                        let name = required(options, "--server-name")?.to_owned();
                        let outer = match settings.transport {
                            secure_udp::maintained::Transport::Tls(_) => {
                                secure_udp::maintained::Client::Tls(service::Client {
                                    remote: settings.first.server,
                                    tls: tls_frontend::client(options)?,
                                    server_name: name,
                                    member,
                                })
                            }
                            secure_udp::maintained::Transport::Quic(_) => {
                                secure_udp::maintained::Client::Quic {
                                    roots: vec![bounded_file(required(options, "--ca")?, 65536)?],
                                    server_name: name,
                                    member,
                                }
                            }
                        };
                        (if matches!(&selected.0, Choice::Proxy(..)) {
                            service::Prepared::proxy_common_maintained_client
                        } else {
                            service::Prepared::secure_udp_common_maintained_client
                        })(*profile, outer, credentials, attachment)?
                    } else if let Some(raw) = &selected.2 {
                        let mark = raw.mark.ok_or_else(|| input("runtime raw mark absent"))?;
                        let opener =
                            crate::raw_packet::common::PacketOpener::new(move |config, role| {
                                l2tunnel_raw_io::open_packet_marked(config, role, mark)
                            });
                        let tls = tls_frontend::client(options)?;
                        let member = MemberKey::from_pkcs8(&member_der).map_err(auth_error)?;
                        (if matches!(&selected.0, Choice::Proxy(..)) {
                            service::Prepared::proxy_common_raw_client
                        } else {
                            service::Prepared::secure_udp_common_raw_client
                        })(
                            *profile,
                            raw.settings.clone(),
                            service::Client {
                                remote: common.peer,
                                tls,
                                server_name: required(options, "--server-name")?.to_owned(),
                                member: std::sync::Arc::new(member),
                            },
                            credentials,
                            opener,
                            attachment,
                        )?
                    } else {
                        match selected.outer_config(&profile)? {
                            Some(outer) => {
                                let tls = tls_frontend::client(options)?;
                                let member =
                                    MemberKey::from_pkcs8(&member_der).map_err(auth_error)?;
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
                            None => (if matches!(&selected.0, Choice::Proxy(..)) {
                                service::Prepared::proxy_common_client
                            } else {
                                service::Prepared::secure_udp_common_client
                            })(
                                *profile, credentials, attachment
                            )?,
                        }
                    }
                }
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
                Built::Proxy(profile) | Built::Records(profile) => {
                    if let Carrier::Maintained(settings) = &selected.1 {
                        let certs = vec![bounded_file(required(options, "--cert")?, 65536)?];
                        let key = bounded_file(required(options, "--key")?, 65536)?;
                        let members = MemberAllowlist::new(&[auth::MemberPublicKey(member.0)])
                            .map_err(auth_error)?;
                        let outer = match settings.transport {
                            secure_udp::maintained::Transport::Tls(_) => {
                                secure_udp::maintained::Server::Tls(service::Server {
                                    listen: settings.first.server,
                                    tls: ServerTls::from_der(&certs, &key).map_err(auth_error)?,
                                    members,
                                })
                            }
                            secure_udp::maintained::Transport::Quic(_) => {
                                secure_udp::maintained::Server::Quic {
                                    certs,
                                    key: zeroize::Zeroizing::new(key),
                                    members,
                                }
                            }
                        };
                        (if matches!(&selected.0, Choice::Proxy(..)) {
                            service::Prepared::proxy_common_maintained_server
                        } else {
                            service::Prepared::secure_udp_common_maintained_server
                        })(*profile, outer, credentials, attachment)?
                    } else if let Some(raw) = &selected.2 {
                        let mark = raw.mark.ok_or_else(|| input("runtime raw mark absent"))?;
                        let opener =
                            crate::raw_packet::common::PacketOpener::new(move |config, role| {
                                l2tunnel_raw_io::open_packet_marked(config, role, mark)
                            });
                        let tls = ServerTls::from_der(
                            &[bounded_file(required(options, "--cert")?, 65536)?],
                            &bounded_file(required(options, "--key")?, 65536)?,
                        )
                        .map_err(auth_error)?;
                        let members = MemberAllowlist::new(&[auth::MemberPublicKey(member.0)])
                            .map_err(auth_error)?;
                        (if matches!(&selected.0, Choice::Proxy(..)) {
                            service::Prepared::proxy_common_raw_server
                        } else {
                            service::Prepared::secure_udp_common_raw_server
                        })(
                            *profile,
                            raw.settings.clone(),
                            service::Server {
                                listen: common.local,
                                tls,
                                members,
                            },
                            credentials,
                            opener,
                            attachment,
                        )?
                    } else {
                        match selected.outer_config(&profile)? {
                            Some(outer) => {
                                let tls = ServerTls::from_der(
                                    &[bounded_file(required(options, "--cert")?, 65536)?],
                                    &bounded_file(required(options, "--key")?, 65536)?,
                                )
                                .map_err(auth_error)?;
                                let members =
                                    MemberAllowlist::new(&[auth::MemberPublicKey(member.0)])
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
                            None => (if matches!(&selected.0, Choice::Proxy(..)) {
                                service::Prepared::proxy_common_server
                            } else {
                                service::Prepared::secure_udp_common_server
                            })(
                                *profile, credentials, attachment
                            )?,
                        }
                    }
                }
            }
        }
        _ => return Err(input("unsupported secure UDP command")),
    };
    if matches!(&selected.0, Choice::Proxy(..)) {
        return common_proxy_cli::serve_prepared(plan, options, config).await;
    }
    let api = options
        .get("--control-socket")
        .map(crate::local::Server::bind)
        .transpose()?;
    // Keep this shared API for explicit lower-layer reconnect after a connected
    // generation fails. This neither retries automatically nor resets Records.
    let local_control = api.is_some();
    let (handle, run) = service::channel();
    let submit = |error| io::Error::other(format!("service request: {error:?}"));
    // Prepare persistent output owners before any protocol operation starts.
    // Regular descriptions retain their original shared offset and flags.
    let mut output = output::Sink::stdout();
    let mut diagnostic = output::Sink::stderr();
    let accepted = handle
        .connect(plan, handle.next_key().map_err(submit)?)
        .map_err(submit)?;
    let life = handle.clone();
    let lifecycle = async {
        let mut cursor = accepted.operation.value().saturating_sub(1);
        let mut live = None;
        let mut connected = false;
        let mut report_tick =
            tokio::time::interval(report_interval.unwrap_or(Duration::from_secs(1)));
        report_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
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
                    emit_transaction(life.snapshot().runtime.as_ref(), generation, TransactionEvent::Terminal(terminal), &mut output);
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
                            if let Some(previous) = live.take() {
                                let terminal = life.wait_stopped(previous).await.map_err(submit)?;
                                emit_transaction(life.snapshot().runtime.as_ref(), Some(previous), TransactionEvent::Terminal(terminal), &mut output);
                            }
                            live = Some(generation);
                            let snapshot = life.snapshot();
                            emit_transaction(snapshot.runtime.as_ref(), Some(generation), TransactionEvent::Ready, &mut output);
                        }
                        Completed::Failed(failure) => {
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
                            if let Some(generation) = live.take() {
                                // Completion may win select before wait_stopped. Observe
                                // the real release before forgetting its generation.
                                let terminal = life.wait_stopped(generation).await.map_err(submit)?;
                                emit_transaction(life.snapshot().runtime.as_ref(), Some(generation), TransactionEvent::Terminal(terminal), &mut output);
                            }
                            live = None;
                        }
                        Completed::Applied(_) | Completed::Rejected(_) | Completed::Common { .. } | Completed::ConnectionReuse { .. } | Completed::OutcomeUnknown => {}
                    }
                }
                _ = report_tick.tick(), if report_interval.is_some() => {
                    if live.is_some() { emit_transaction(life.snapshot().runtime.as_ref(), live, TransactionEvent::Status, &mut output); }
                }
                _ = output_tick.tick(), if output.has_pending() || diagnostic.has_pending() => {},
            }
            output.flush_turn();
            if output.take_failure() {
                diagnostic.emit(serde_json::json!({
                    "event": "cli_output_failure", "output_health": output.health
                }));
            }
            diagnostic.flush_turn();
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
    let result = tokio::select! { result = run => result, result = lifecycle => result, result = local => result };
    // This is local diagnostic cleanup after the protocol outcome. Its one
    // absolute cap never renews or extends any protocol deadline. Eight existing
    // 64KiB grants at the 5ms cadence give a 40ms implementation cleanup bound.
    let now = tokio::time::Instant::now();
    let deadline = now.checked_add(output::DRAIN_CAP).unwrap_or(now);
    let stdout = output.finish_until(deadline).await;
    diagnostic.emit(serde_json::json!({"event":"cli_output_finish", "stdout":stdout}));
    let _stderr = diagnostic.finish_until(deadline).await;
    result
}

#[cfg(target_os = "linux")]
fn emit_transaction(
    observation: Option<&crate::service::Observation>,
    generation: Option<crate::service::OperationId>,
    event: TransactionEvent,
    output: &mut output::Sink,
) {
    let projection_started = output.timing.start();
    let value = match (
        observation.and_then(crate::service::Observation::secure_udp_common),
        generation,
    ) {
        (Some(frame), Some(generation)) => {
            common_cli_output::event(frame, generation.value(), event)
        }
        _ => Err(input("missing matching Common observation")),
    };
    output.timing.record_since(
        l2tunnel_runtime::initialization_timing::Stage::CliProjection,
        projection_started,
        if value.is_ok() {
            l2tunnel_runtime::initialization_timing::Outcome::Complete
        } else {
            l2tunnel_runtime::initialization_timing::Outcome::Failed
        },
    );
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
#[path = "output_writer.rs"]
mod output_writer;

#[cfg(all(test, target_os = "linux"))]
#[path = "output_sink_tests.rs"]
mod output_sink_tests;

#[cfg(target_os = "linux")]
mod output {
    use super::output_writer as writer;
    use l2tunnel_runtime::initialization_timing::{Outcome, Owner, Stage, Timing};
    use std::{
        collections::VecDeque,
        fs::{File, OpenOptions},
        io::{self, Write},
        os::fd::{AsFd, AsRawFd, BorrowedFd},
        os::unix::fs::OpenOptionsExt,
        path::Path,
        time::Duration,
    };
    pub(super) const DRAIN_CAP: Duration = Duration::from_millis(40);
    use tokio::time::Instant;
    pub(super) const MAX_LINE: usize = 128 * 1024;
    pub(super) const MAX_LINES: usize = 4;
    pub(super) const MAX_BYTES: usize = MAX_LINE * MAX_LINES;
    pub(super) const WRITE_BYTES: usize = 64 * 1024;
    pub(super) const WRITE_CALLS: usize = 4;
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
        pub unresolved_lines: u64,
        pub unresolved_bytes: u64,
        pub shutdown_timeouts: u64,
    }
    /// Completion means observed write acceptance, never durable storage.
    #[derive(Clone, Copy, Debug, serde::Serialize)]
    pub(super) struct Finish {
        pub completed: bool,
        pub failed: bool,
        pub timed_out: bool,
        pub unresolved_lines: u64,
        pub unresolved_bytes: u64,
    }
    pub(super) struct Sink {
        file: Option<File>,
        worker: Option<writer::Handle>,
        observed: writer::Snapshot,
        closed: bool,
        failure_reported: bool,
        finished: Option<Finish>,
        pending: VecDeque<Vec<u8>>,
        offset: usize,
        bytes: usize,
        pub(super) health: Health,
        // Off-inline and optional; this owner never writes diagnostics on Drop.
        pub(super) timing: Timing,
    }
    impl Sink {
        pub(super) fn stdout() -> Self {
            Self::from_stdio(std::io::stdout().as_fd()).unwrap_or_else(|_| {
                Self {
                    file: None,
                    worker: None,
                    observed: writer::Snapshot::default(),
                    closed: false,
                    failure_reported: false,
                    finished: None,
                    pending: VecDeque::new(),
                    offset: 0,
                    bytes: 0,
                    timing: Timing::disabled(),
                    health: Health {
                        disabled: true,
                        write_errors: 1,
                        ..Health::default()
                    },
                }
                .observe_timing()
            })
        }
        pub(super) fn stderr() -> Self {
            Self::from_stdio(std::io::stderr().as_fd()).unwrap_or_else(|_| {
                Self {
                    file: None,
                    worker: None,
                    observed: writer::Snapshot::default(),
                    closed: false,
                    failure_reported: false,
                    finished: None,
                    pending: VecDeque::new(),
                    offset: 0,
                    bytes: 0,
                    timing: Timing::disabled(),
                    health: Health {
                        disabled: true,
                        write_errors: 1,
                        ..Health::default()
                    },
                }
                .observe_timing()
            })
        }
        fn from_stdio(original: BorrowedFd<'_>) -> io::Result<Self> {
            let duplicate = File::from(original.try_clone_to_owned()?);
            if duplicate.metadata()?.is_file() {
                // Stdout and stderr may alias this same open-file description.
                // Preserve their shared offset: a separate APPEND description
                // would leave stderr's old offset able to overwrite telemetry.
                // Only the persistent worker may perform regular-file writes.
                // Never alter inherited flags or replace the shared description.
                return Self::with_worker(duplicate);
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
                worker: None,
                observed: writer::Snapshot::default(),
                closed: false,
                failure_reported: false,
                finished: None,
                pending: VecDeque::with_capacity(MAX_LINES),
                offset: 0,
                bytes: 0,
                health: Health::default(),
                timing: Timing::disabled(),
            }
            .observe_timing()
        }
        pub(super) fn with_worker<W: Write + Send + 'static>(file: W) -> io::Result<Self> {
            Ok(Self {
                file: None,
                worker: Some(writer::Handle::new(file)?),
                timing: Timing::disabled(),
                observed: writer::Snapshot::default(),
                closed: false,
                failure_reported: false,
                finished: None,
                pending: VecDeque::new(),
                offset: 0,
                bytes: 0,
                health: Health::default(),
            }
            .observe_timing())
        }
        fn observe_timing(mut self) -> Self {
            match Timing::try_from_environment(Owner::CliOutput, Instant::now()) {
                Ok(timing) => self.timing = timing,
                Err(_) => self.projection_error(),
            }
            self
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
            self.worker.as_ref().map_or_else(
                || !self.pending.is_empty(),
                |worker| worker.snapshot().pending_lines != 0,
            )
        }
        pub(super) fn projection_error(&mut self) {
            self.health.projection_errors = self.health.projection_errors.saturating_add(1);
        }
        pub(super) fn emit(&mut self, mut value: serde_json::Value) {
            self.refresh();
            if self.closed || self.health.disabled || self.file.is_none() && self.worker.is_none() {
                self.health.dropped_lines = self.health.dropped_lines.saturating_add(1);
                return;
            }
            if let Some(object) = value.as_object_mut() {
                if let Some(now) = self.timing.start() {
                    let mut diagnostic = Limited(Vec::new());
                    match self
                        .timing
                        .write_snapshot_at(now, &mut diagnostic)
                        .and_then(|_| {
                            serde_json::from_slice(&diagnostic.0).map_err(io::Error::other)
                        }) {
                        Ok(snapshot) => {
                            object.insert("execution_wall".into(), snapshot);
                        }
                        Err(_) => {
                            self.health.projection_errors =
                                self.health.projection_errors.saturating_add(1);
                        }
                    }
                }
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
            if self
                .timing
                .measure_result(Stage::CliEncoding, || {
                    serde_json::to_writer(&mut encoded, &value)
                })
                .is_err()
            {
                self.projection_error();
                self.health.dropped_lines = self.health.dropped_lines.saturating_add(1);
                return;
            }
            encoded.0.push(b'\n');
            if let Some(worker) = &mut self.worker {
                match worker.enqueue(encoded.0) {
                    writer::Admission::Accepted => {}
                    writer::Admission::Full(line) | writer::Admission::Closed(line) => {
                        self.health.dropped_lines = self.health.dropped_lines.saturating_add(1);
                        self.health.dropped_bytes =
                            self.health.dropped_bytes.saturating_add(line.len() as u64);
                    }
                }
                self.refresh();
                return;
            }
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
            let started = self.timing.start();
            self.flush_turn_inner();
            // A flush returning normally is not proof every queued line drained.
            self.timing
                .record_since(Stage::CliFlush, started, Outcome::Complete);
        }
        fn flush_turn_inner(&mut self) {
            self.refresh();
            if let Some(worker) = &self.worker {
                worker.grant();
                return;
            }
            let mut budget = WRITE_BYTES;
            for _ in 0..WRITE_CALLS {
                let (Some(file), Some(line)) = (&mut self.file, self.pending.front()) else {
                    break;
                };
                if budget == 0 {
                    break;
                }
                let end = line.len().min(self.offset.saturating_add(budget));
                match self
                    .timing
                    .measure_result(Stage::CliFileWrite, || file.write(&line[self.offset..end]))
                {
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
        fn refresh(&mut self) {
            let Some(worker) = &self.worker else {
                return;
            };
            let current = worker.snapshot();
            self.merge_worker_snapshot(current);
        }
        fn merge_worker_snapshot(&mut self, current: writer::Snapshot) {
            macro_rules! merge {
                ($field:ident) => {
                    self.health.$field = self
                        .health
                        .$field
                        .saturating_add(current.$field.saturating_sub(self.observed.$field));
                };
            }
            merge!(written_bytes);
            merge!(write_errors);
            merge!(broken_pipe);
            merge!(would_block);
            merge!(dropped_lines);
            merge!(dropped_bytes);
            self.health.queue_bytes_high =
                self.health.queue_bytes_high.max(current.queue_bytes_high);
            self.health.disabled |= current.disabled;
            self.observed = current;
        }
        pub(super) fn take_failure(&mut self) -> bool {
            self.refresh();
            if self.health.disabled && !self.failure_reported {
                self.failure_reported = true;
                true
            } else {
                false
            }
        }
        fn report(&mut self, timed_out: bool) -> Finish {
            if let Some(report) = self.finished {
                return report;
            }
            let observed = self.worker.as_ref().map(|worker| worker.snapshot());
            self.report_observed(timed_out, observed)
        }
        fn report_observed(
            &mut self,
            timed_out: bool,
            observed: Option<writer::Snapshot>,
        ) -> Finish {
            if let Some(report) = self.finished {
                return report;
            }
            // Failure and pending custody must come from the same observation.
            // A second worker read could otherwise see an empty failed queue
            // while retaining the first read's successful health state.
            let (lines, bytes) = if let Some(snapshot) = observed {
                self.merge_worker_snapshot(snapshot);
                (snapshot.pending_lines, snapshot.pending_bytes)
            } else {
                (self.pending.len(), self.bytes)
            };
            self.health.unresolved_lines = lines as u64;
            self.health.unresolved_bytes = bytes as u64;
            let report = Finish {
                completed: lines == 0 && !self.health.disabled,
                failed: self.health.disabled,
                timed_out,
                unresolved_lines: lines as u64,
                unresolved_bytes: bytes as u64,
            };
            self.finished = Some(report);
            report
        }
        fn stop(&mut self, timed_out: bool) -> Finish {
            self.closed = true;
            // Snapshot first: after stop a returning worker may conclusively
            // discard queued tails; at this boundary they were still unresolved.
            let report = self.report(timed_out);
            if timed_out {
                self.health.shutdown_timeouts = self.health.shutdown_timeouts.saturating_add(1);
            }
            if let Some(worker) = &self.worker {
                worker.stop();
            }
            report
        }
        pub(super) async fn finish_until(&mut self, deadline: Instant) -> Finish {
            if let Some(report) = self.finished {
                return report;
            }
            if !self.closed {
                self.emit_terminal_timing();
            }
            self.closed = true;
            let mut guard = Finishing {
                sink: self,
                complete: false,
            };
            if Instant::now() < deadline
                && let Some(worker) = &guard.sink.worker
            {
                worker.close();
            }
            loop {
                guard.sink.refresh();
                if guard.sink.health.disabled {
                    let report = guard.sink.stop(false);
                    guard.complete = true;
                    return report;
                }
                if !guard.sink.has_pending() {
                    let report = guard.sink.report(false);
                    guard.complete = true;
                    return report;
                }
                if Instant::now() >= deadline {
                    let report = guard.sink.stop(true);
                    guard.complete = true;
                    return report;
                }
                guard.sink.flush_turn();
                if !guard.sink.has_pending() {
                    let report = guard.sink.report(false);
                    guard.complete = true;
                    return report;
                }
                let now = Instant::now();
                let next = now
                    .checked_add(Duration::from_millis(5))
                    .unwrap_or(deadline)
                    .min(deadline);
                tokio::time::sleep_until(next).await;
            }
        }
        fn emit_terminal_timing(&mut self) {
            let mut encoded = Limited(Vec::new());
            match self.timing.write_terminal_at(Instant::now(), &mut encoded) {
                Ok(true) => match serde_json::from_slice(&encoded.0) {
                    Ok(value) => self.emit(value),
                    Err(_) => self.projection_error(),
                },
                Ok(false) => {}
                Err(_) => self.projection_error(),
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
    impl Drop for Sink {
        fn drop(&mut self) {
            if !self.closed {
                let _unresolved = self.stop(false);
            }
        }
    }
    struct Finishing<'a> {
        sink: &'a mut Sink,
        complete: bool,
    }
    impl Drop for Finishing<'_> {
        fn drop(&mut self) {
            if !self.complete {
                // Cancellation never starts async cleanup or waits on the writer.
                let _unresolved = self.sink.stop(false);
            }
        }
    }
    #[cfg(test)]
    pub(super) fn test_health(sink: &mut Sink) -> Health {
        sink.refresh();
        sink.health
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
        #[tokio::test(flavor = "current_thread")]
        async fn terminal_snapshot_cannot_combine_pre_failure_health_with_post_failure_empty_queue()
        -> io::Result<()> {
            struct FailingWriter {
                started: Option<tokio::sync::oneshot::Sender<()>>,
                release: std::sync::mpsc::Receiver<()>,
            }
            impl Write for FailingWriter {
                fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
                    if let Some(started) = self.started.take() {
                        let _sent = started.send(());
                    }
                    self.release.recv().map_err(io::Error::other)?;
                    Err(io::Error::new(io::ErrorKind::BrokenPipe, "fixture failure"))
                }
                fn flush(&mut self) -> io::Result<()> {
                    Ok(())
                }
            }
            let (release, wait) = std::sync::mpsc::sync_channel(1);
            let (started, entered) = tokio::sync::oneshot::channel();
            let mut sink = Sink::with_worker(FailingWriter {
                started: Some(started),
                release: wait,
            })?;
            sink.emit(serde_json::json!({"event":"pending failure"}));
            sink.flush_turn();
            tokio::time::timeout(Duration::from_secs(1), entered)
                .await
                .map_err(|_| io::Error::other("worker write not entered"))?
                .map_err(io::Error::other)?;
            let before = sink
                .worker
                .as_ref()
                .ok_or_else(|| io::Error::other("worker"))?
                .snapshot();
            assert!(!before.disabled && before.pending_lines == 1);
            release.try_send(()).map_err(io::Error::other)?;
            let failed = tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    let value = sink
                        .worker
                        .as_ref()
                        .ok_or_else(|| io::Error::other("worker"))?
                        .snapshot();
                    if value.disabled && value.pending_lines == 0 {
                        break Ok::<_, io::Error>(value);
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .map_err(|_| io::Error::other("worker failure not observed"))??;
            assert_eq!(failed.written_bytes, 0);
            assert_eq!(
                (
                    failed.write_errors,
                    failed.broken_pipe,
                    failed.dropped_lines
                ),
                (1, 1, 1)
            );
            // Actual failure occurred between capture and terminal projection.
            // Freeze that capture, never combine it with the now-empty queue.
            let report = sink.report_observed(false, Some(before));
            assert!(!report.completed && !report.failed);
            assert_eq!(report.unresolved_lines, 1);
            assert_eq!(report.unresolved_bytes, before.pending_bytes as u64);
            let repeated = sink.report(false);
            assert!(!repeated.completed && !repeated.failed);
            assert_eq!(repeated.unresolved_lines, 1);
            // The independent failure observation still carries its own exact
            // empty/failed boundary; no successful progress can be inferred.
            sink.merge_worker_snapshot(failed);
            assert!(sink.health.disabled);
            assert_eq!(sink.health.write_errors, 1);
            assert_eq!(sink.health.unresolved_lines, 1);
            Ok(())
        }
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
        fn execution_timing_counts_actual_successful_direct_file_write() -> io::Result<()> {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "l2tunnel-log-timing-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)?;
            std::fs::remove_file(&path)?;
            let mut sink = Sink::with_file(file.try_clone()?);
            sink.timing = Timing::try_new(Owner::CliOutput, Instant::now())?;
            sink.emit(serde_json::json!({"event":"timed-success"}));
            sink.flush_turn();
            assert!(!sink.has_pending());
            assert!(sink.health.written_bytes > 0);
            assert_eq!(sink.health.would_block, 0);
            let writes = sink
                .timing
                .snapshot(Stage::CliFileWrite)
                .ok_or_else(|| io::Error::other("explicit observation"))?;
            assert_eq!(writes.samples, 1);
            assert_eq!(writes.failed, 0);
            assert!(writes.maximum_start_us.is_some() && writes.maximum_end_us.is_some());
            assert_eq!(
                sink.timing
                    .snapshot(Stage::CliEncoding)
                    .ok_or_else(|| io::Error::other("encoding"))?
                    .samples,
                1
            );
            assert_eq!(
                sink.timing
                    .snapshot(Stage::CliFlush)
                    .ok_or_else(|| io::Error::other("flush"))?
                    .samples,
                1
            );
            file.rewind()?;
            let mut bytes = String::new();
            file.read_to_string(&mut bytes)?;
            let value: serde_json::Value = serde_json::from_str(bytes.trim())?;
            assert_eq!(value["event"], "timed-success");
            assert_eq!(value["execution_wall"]["event"], "execution_timing");
            // The published snapshot preceded this write; it is not a later final observation.
            let written_before = value["execution_wall"]["stages"]
                .as_array()
                .ok_or_else(|| io::Error::other("stages"))?
                .iter()
                .find(|stage| stage["stage"] == "CliFileWrite")
                .ok_or_else(|| io::Error::other("write stage"))?;
            assert_eq!(written_before["samples"], 0);
            Ok(())
        }
        #[tokio::test]
        async fn stdio_regular_file_and_aliased_stderr_preserve_each_others_lines() -> io::Result<()>
        {
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
            tokio::time::timeout(Duration::from_secs(1), async {
                while sink.has_pending() {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .map_err(|_| io::Error::other("regular writer acceptance"))?;
            sink.refresh();
            assert_eq!(
                original.stream_position()?,
                b"original prefix\n".len() as u64 + sink.health.written_bytes
            );
            stderr.write_all(b"final error\n")?;
            sink.emit(serde_json::json!({"event":"second telemetry"}));
            sink.flush_turn();
            tokio::time::timeout(Duration::from_secs(1), async {
                while sink.has_pending() {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .map_err(|_| io::Error::other("regular writer acceptance"))?;
            sink.refresh();
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
