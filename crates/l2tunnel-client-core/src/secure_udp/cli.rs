//! Explicit same-socket carrier presentation through the shared lifecycle service.
use super::*;
use crate::secure_udp::{self, credentials, profile::Profile};
use l2tunnel_handshake as hs;
use l2tunnel_runtime::secure_udp::{establish, transport};
use l2tunnel_security as security;
use l2tunnel_swift::{policy, records};
use l2tunnel_udp_control as gate;

pub(super) const OPTIONS: &[&str] = &[
    "--noise-profile",
    "--noise-private-key-file",
    "--noise-peer-key-file",
    "--noise-psk-file",
    "--session-admission-key-file",
    "--session-cookie-key-file",
    "--max-path-mtu",
];
pub(super) const HELP: &str = "Common secure UDP (implementation draft): explicitly select --carrier quic-like|media-like --record-profile swift --duplex full, --udp-bind IP:PORT --udp-peer IP:PORT, --noise-profile ik|ikpsk2, --noise-private-key-file RAW32 --noise-peer-key-file RAW32 --session-admission-key-file RAW32; ikpsk2 additionally requires --noise-psk-file RAW32. Connect retains --identity PKCS8; serve requires --allow-key Ed25519_RAW32 and --session-cookie-key-file RAW32. Private files must be owned/private regular files. No TCP/TLS side connection or automatic credential generation. Swift forward/reverse rates are mandatory; current --path-mtu defaults to 1500, --max-path-mtu capacity defaults to 9000 (576..9000). Cover IDs derive from ordered public Noise pins, without identification guarantees. Optional --control-socket exposes explicit local API version 2; external status/disconnect/reconnect/set-swift require --api-version 2. Fresh reconnect does not preserve old-session delivery state. Full recovery, cross-profile switching, other carrier/platform qualification remain open.";

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
pub(super) fn selection(
    command: &str,
    options: &BTreeMap<String, String>,
    config: ConnectionConfig,
) -> io::Result<Option<Selection>> {
    let appearance = match options.get("--carrier").map(String::as_str) {
        Some("quic-like") => l2tunnel_cover::Appearance::QuicLike,
        Some("media-like") => l2tunnel_cover::Appearance::MediaLike,
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
    if options.get("--record-profile").map(String::as_str) != Some("swift")
        || config.duplex != Duplex::Full
        || config.compression != Compression::None
        || options
            .keys()
            .any(|key| !allowed.contains(&key.as_str()) && !OPTIONS.contains(&key.as_str()))
    {
        return Err(input(
            "secure UDP requires explicit Swift/full/no-compression and only its documented options",
        ));
    }
    required(options, "--device")?;
    for key in [
        "--noise-private-key-file",
        "--noise-peer-key-file",
        "--session-admission-key-file",
    ] {
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
            required(options, "--session-cookie-key-file")?;
            security::Role::Responder
        }
        _ => {
            return Err(input(
                "member and server-only cookie inputs differ between connect and serve",
            ));
        }
    };
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
    let maximum_mtu = number(options, "--max-path-mtu", 9000)?;
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
    Ok(Some(Selection {
        appearance,
        role,
        local,
        peer,
        policy,
        maximum_mtu,
        profile,
        report,
    }))
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
impl Selection {
    pub(crate) fn build(
        self,
        connection: ConnectionConfig,
        peers: establish::Peers,
        member: l2tunnel_identity::MemberPublicKey,
    ) -> io::Result<Profile> {
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
        let overhead = ip + header + 9 + security::COMMON_PREFIX_BYTES + 16;
        let body = usize::from(self.policy.path_mtu)
            .checked_sub(overhead)
            .ok_or_else(|| input("path MTU below secure framing"))?;
        let maximum_body = self
            .maximum_mtu
            .checked_sub(overhead)
            .ok_or_else(|| input("capacity below secure framing"))?;
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
            max_packet_bytes: self.maximum_mtu - ip - header + handshake_header,
            max_protected_bytes: self.maximum_mtu - ip - header,
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
        gate.path_mtu = usize::from(self.policy.path_mtu);
        gate.outer_overhead = cover.bootstrap_overhead(self.local.is_ipv6())?;
        gate.arq.max_source_bytes = gate
            .path_mtu
            .checked_sub(
                gate.outer_overhead + gate::CONTROL_OVERHEAD + l2tunnel_recovery::DATA_HEADER_BYTES,
            )
            .ok_or_else(|| input("bootstrap MTU cannot hold ARQ framing"))?
            .min(1200);
        gate.arq.send_bytes = gate.arq.max_source_bytes * gate.arq.send_records;
        gate.arq.receive_bytes = gate.arq.max_source_bytes * gate.arq.receive_records;
        gate.handshake_timeout = connection.handshake_timeout;
        gate.cookie_ttl = gate.cookie_ttl.min(connection.handshake_timeout);
        gate.maximum_rto = gate.maximum_rto.min(connection.handshake_timeout);
        gate.initial_rto = gate.initial_rto.min(gate.maximum_rto);
        let selected = secure_udp::Settings {
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
        };
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
        let initiator = transport::Config {
            path_mtu: usize::from(self.policy.path_mtu),
            send: direction(true),
            receive: direction(false),
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
            data_epoch: security::Epoch(1),
            wire: transport::WireBudget {
                burst_bytes: self.maximum_mtu + pair_cost,
            },
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
            report_interval: Some(self.report.unwrap_or(Duration::from_secs(1))),
        };
        let responder = transport::Config {
            send: initiator.receive,
            receive: initiator.send,
            ..initiator
        };
        Profile::new(connection, selected, initiator, responder)
    }
}

#[cfg(target_os = "linux")]
pub(super) async fn execute(
    command: &str,
    options: &BTreeMap<String, String>,
    config: ConnectionConfig,
    selected: Selection,
) -> io::Result<()> {
    use crate::service::{self, Completed, Terminal};
    use std::path::Path;
    let noise = credentials::NoiseIdentity::new(
        credentials::read_secret(Path::new(required(options, "--noise-private-key-file")?))?,
        hs::PeerKey(credentials::read_public(Path::new(required(
            options,
            "--noise-peer-key-file",
        )?))?),
        selected.profile,
        options
            .get("--noise-psk-file")
            .map(|path| credentials::read_secret(Path::new(path)))
            .transpose()?,
    )?;
    let peers = noise.peers(selected.role);
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
            let member = credentials::read_member(Path::new(required(options, "--identity")?))?;
            let profile = selected.build(config, peers, member.public_key())?;
            service::Prepared::secure_udp_client(
                profile,
                credentials::Client::new(noise, member, admission)?,
                attachment,
            )?
        }
        "serve" => {
            let member = l2tunnel_identity::MemberPublicKey(credentials::read_public(Path::new(
                required(options, "--allow-key")?,
            ))?);
            let cookie = credentials::Secret32::new(credentials::read_secret(Path::new(
                required(options, "--session-cookie-key-file")?,
            ))?)?;
            service::Prepared::secure_udp_server(
                selected.build(config, peers, member)?,
                credentials::Server::new(noise, admission, cookie)?,
                attachment,
            )?
        }
        _ => return Err(input("unsupported secure UDP command")),
    };
    let api = options
        .get("--control-socket")
        .map(crate::local::Server::bind)
        .transpose()?;
    let (handle, run) = service::channel();
    let submit = |error| io::Error::other(format!("service request: {error:?}"));
    let accepted = handle
        .connect(plan, handle.next_key().map_err(submit)?)
        .map_err(submit)?;
    let life = handle.clone();
    let lifecycle = async move {
        let mut cursor = accepted.operation.value().saturating_sub(1);
        let mut live = None;
        loop {
            let stopped = async {
                match live {
                    Some(generation) => life.wait_stopped(generation).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                terminal = stopped => {
                    live = None;
                    let terminal = terminal.map_err(submit)?;
                    println!("{}", serde_json::json!({"event":"secure_udp_terminal","outcome":format!("{terminal:?}")}));
                    if let Terminal::Failed(failure) = terminal {
                        return Err(io::Error::new(failure.kind, "secure UDP runtime failed"));
                    }
                }
                result = life.wait_next(cursor) => {
                    let (operation, result) = result.map_err(submit)?;
                    cursor = operation.value();
                    match result {
                        Completed::Connected { generation } => {
                            live = Some(generation);
                            let snapshot = life.snapshot();
                            let status = snapshot.runtime.as_ref().and_then(service::Observation::secure_udp)
                                .ok_or_else(|| io::Error::other("selected secure UDP observation absent"))?.status()?;
                            println!("{}", serde_json::json!({"event":"secure_udp_ready","status":status}));
                        }
                        Completed::Failed(failure) => return Err(io::Error::new(failure.kind, "secure UDP setup failed")),
                        Completed::Cancelled => return Err(io::Error::new(io::ErrorKind::Interrupted, "secure UDP setup cancelled")),
                        Completed::Aborted => live = None,
                        Completed::Applied(_) | Completed::Rejected(_) | Completed::OutcomeUnknown => {}
                    }
                }
            }
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

#[cfg(test)]
#[path = "cli_tests.rs"]
mod tests;
