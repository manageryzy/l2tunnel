//! Labeled fields of the profile editor (usability review 2026-11-24). A
//! profile stays the validated run options (owner decision 2026-11-23); this
//! table gives the common options a label, a group, a kind of input, carrier
//! visibility, and help. Options not listed here stay editable as raw rows
//! under "Other". The service remains the authority: Save is refused for an
//! unrunnable plan.

/// How a field is entered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// One of fixed values.
    Choice(&'static [&'static str]),
    /// A file path, chosen with the file chooser.
    File,
    /// `IP:PORT`.
    Address,
    /// A whole number (`u64`).
    Number,
    /// A network device name (offered from the device list).
    Device,
    /// Free text the service checks on save (lists, rates, ranges).
    Text,
}

/// Which profile role shows the field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Roles {
    /// Client and server.
    Both,
    /// Client (`connect`) only.
    Client,
    /// Server (`serve`) only.
    Server,
}

/// Which `--carrier` selections show the field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Carriers {
    /// Every carrier.
    All,
    /// UDP-endpoint carriers (`quic-like`, `media-like`, `openvpn-like`).
    UdpEndpoints,
    /// Carriers with `--remote`/`--listen` endpoints (`raw-packet`, `tcp`, `quic`).
    RemoteListen,
    /// Carriers with outer TLS + explicit `--udp-cover` (`openvpn-like`, `raw-packet`, `tcp`, `quic`).
    OuterTls,
    /// `raw-packet` only (`--raw-policy`, `--raw-mark`).
    RawPacket,
    /// Maintained `tcp` or `quic` (`--maintained-policy`).
    Maintained,
}
impl Carriers {
    /// Whether `carrier` (trimmed) matches this group.
    pub fn matches(self, carrier: &str) -> bool {
        let carrier = carrier.trim();
        match self {
            Self::All => true,
            Self::UdpEndpoints => {
                matches!(carrier, "" | "quic-like" | "media-like" | "openvpn-like")
            }
            Self::RemoteListen => matches!(carrier, "raw-packet" | "tcp" | "quic"),
            Self::OuterTls => matches!(carrier, "openvpn-like" | "raw-packet" | "tcp" | "quic"),
            Self::RawPacket => carrier == "raw-packet",
            Self::Maintained => matches!(carrier, "tcp" | "quic"),
        }
    }
}

/// One labeled option.
#[derive(Clone, Copy, Debug)]
pub struct Field {
    /// Run option, e.g. `--carrier`.
    pub option: &'static str,
    /// Label on a client profile.
    pub label: &'static str,
    /// Label on a server profile, when it differs.
    pub server_label: Option<&'static str>,
    /// Group heading.
    pub group: &'static str,
    /// Input kind.
    pub kind: Kind,
    /// Roles showing it.
    pub roles: Roles,
    /// Carriers showing it.
    pub carriers: Carriers,
    /// Needed for a runnable profile of this role and carrier.
    pub required: bool,
    /// Placeholder.
    pub hint: &'static str,
    /// One-line help.
    pub help: &'static str,
}
impl Field {
    /// Label for the role.
    pub fn label(&self, serve: bool) -> &'static str {
        match (serve, self.server_label) {
            (true, Some(label)) => label,
            _ => self.label,
        }
    }
    /// Shown for the role and carrier.
    pub fn shown(&self, serve: bool, carrier: &str) -> bool {
        let role_ok = match self.roles {
            Roles::Both => true,
            Roles::Client => !serve,
            Roles::Server => serve,
        };
        role_ok && self.carriers.matches(carrier)
    }
}

/// Group headings in display order.
pub const GROUPS: [&str; 5] = [
    "Connection",
    "Security and keys",
    "Tunnel device",
    "Protocol",
    "Live tuning",
];

const fn field(
    option: &'static str,
    label: &'static str,
    group: &'static str,
    kind: Kind,
    help: &'static str,
) -> Field {
    Field {
        option,
        label,
        server_label: None,
        group,
        kind,
        roles: Roles::Both,
        carriers: Carriers::All,
        required: true,
        hint: "",
        help,
    }
}

/// The labeled options, in display order within each group.
pub const FIELDS: &[Field] = &[
    field(
        "--carrier",
        "Carrier",
        "Connection",
        Kind::Choice(&[
            "quic-like",
            "media-like",
            "openvpn-like",
            "raw-packet",
            "tcp",
            "quic",
        ]),
        "How the tunnel travels: quic-like and media-like are UDP that looks like QUIC or media.",
    ),
    Field {
        server_label: Some("Expected client address"),
        carriers: Carriers::UdpEndpoints,
        hint: "203.0.113.7:4433",
        ..field(
            "--udp-peer",
            "Server address",
            "Connection",
            Kind::Address,
            "IP:port of the other side.",
        )
    },
    Field {
        server_label: Some("Listen address"),
        carriers: Carriers::UdpEndpoints,
        hint: "0.0.0.0:4433",
        ..field(
            "--udp-bind",
            "Local address",
            "Connection",
            Kind::Address,
            "IP:port this side uses (a server listens here).",
        )
    },
    Field {
        roles: Roles::Client,
        carriers: Carriers::RemoteListen,
        hint: "203.0.113.7:443",
        ..field(
            "--remote",
            "Server address",
            "Connection",
            Kind::Address,
            "IP:port of the server (must match the policy's first tuple).",
        )
    },
    Field {
        roles: Roles::Server,
        carriers: Carriers::RemoteListen,
        hint: "0.0.0.0:443",
        ..field(
            "--listen",
            "Listen address",
            "Connection",
            Kind::Address,
            "IP:port this server listens on (must match the policy's first tuple).",
        )
    },
    Field {
        carriers: Carriers::OuterTls,
        ..field(
            "--udp-cover",
            "Bootstrap cover",
            "Connection",
            Kind::Choice(&["quic-like", "media-like", "tls-like"]),
            "Explicit bootstrap cover required by OpenVPN, raw-packet, TCP, and QUIC carriers.",
        )
    },
    Field {
        carriers: Carriers::Maintained,
        ..field(
            "--maintained-policy",
            "Maintained policy file",
            "Connection",
            Kind::File,
            "TCP/QUIC maintained carrier policy JSON.",
        )
    },
    Field {
        carriers: Carriers::RawPacket,
        ..field(
            "--raw-policy",
            "Raw packet policy file",
            "Connection",
            Kind::File,
            "Explicit raw-packet carrier tuple and policy JSON.",
        )
    },
    Field {
        carriers: Carriers::RawPacket,
        hint: "1",
        ..field(
            "--raw-mark",
            "Raw socket mark",
            "Connection",
            Kind::Number,
            "Nonzero Linux fwmark (u32) isolating raw carrier packets.",
        )
    },
    field(
        "--common-transaction-plan",
        "Transaction plan file",
        "Connection",
        Kind::File,
        "The complete plan both sides share (JSON).",
    ),
    field(
        "--noise-profile",
        "Handshake",
        "Security and keys",
        Kind::Choice(&["ik", "ikpsk2"]),
        "Noise IK; ikpsk2 also needs a pre-shared key file.",
    ),
    field(
        "--noise-private-key-file",
        "Own Noise private key",
        "Security and keys",
        Kind::File,
        "This side's X25519 private key (32 bytes).",
    ),
    field(
        "--noise-peer-key-file",
        "Peer Noise public key",
        "Security and keys",
        Kind::File,
        "The other side's X25519 public key (pinned).",
    ),
    Field {
        roles: Roles::Client,
        ..field(
            "--identity",
            "Member identity",
            "Security and keys",
            Kind::File,
            "This client's member identity (private key file).",
        )
    },
    Field {
        roles: Roles::Server,
        ..field(
            "--allow-key",
            "Trusted member public key",
            "Security and keys",
            Kind::File,
            "The one client member this server admits.",
        )
    },
    field(
        "--session-admission-key-file",
        "Admission secret",
        "Security and keys",
        Kind::File,
        "32-byte secret shared by both sides.",
    ),
    Field {
        roles: Roles::Server,
        ..field(
            "--session-cookie-key-file",
            "Cookie secret",
            "Security and keys",
            Kind::File,
            "32-byte server secret for stateless admission cookies.",
        )
    },
    Field {
        required: false,
        ..field(
            "--noise-psk-file",
            "Pre-shared key",
            "Security and keys",
            Kind::File,
            "Only with the ikpsk2 handshake.",
        )
    },
    Field {
        roles: Roles::Client,
        carriers: Carriers::OuterTls,
        ..field(
            "--ca",
            "Outer TLS CA certificate",
            "Security and keys",
            Kind::File,
            "Pinned CA certificate verifying the server's outer TLS identity.",
        )
    },
    Field {
        roles: Roles::Client,
        carriers: Carriers::OuterTls,
        hint: "tunnel.example.test",
        ..field(
            "--server-name",
            "Outer TLS server name",
            "Security and keys",
            Kind::Text,
            "Expected DNS/host name verified against the server certificate.",
        )
    },
    Field {
        roles: Roles::Client,
        carriers: Carriers::OuterTls,
        required: false,
        hint: "optional",
        ..field(
            "--sni",
            "Outer TLS SNI",
            "Security and keys",
            Kind::Text,
            "Optional SNI override when different from server name.",
        )
    },
    Field {
        roles: Roles::Client,
        carriers: Carriers::OuterTls,
        required: false,
        hint: "64 hex SHA-256 (optional)",
        ..field(
            "--server-pin",
            "Server cert SHA-256 pin",
            "Security and keys",
            Kind::Text,
            "Optional 64-hex SHA-256 digest of the server leaf DER certificate (verified alongside CA & server name).",
        )
    },
    Field {
        roles: Roles::Server,
        carriers: Carriers::OuterTls,
        ..field(
            "--cert",
            "Outer TLS server certificate",
            "Security and keys",
            Kind::File,
            "PEM certificate chain presented on the outer TLS carrier.",
        )
    },
    Field {
        roles: Roles::Server,
        carriers: Carriers::OuterTls,
        ..field(
            "--key",
            "Outer TLS server key",
            "Security and keys",
            Kind::File,
            "Private key matching the outer TLS server certificate.",
        )
    },
    Field {
        hint: "l2t0",
        ..field(
            "--device",
            "Tunnel device",
            "Tunnel device",
            Kind::Device,
            "The TUN/TAP interface the tunnel uses.",
        )
    },
    field(
        "--layer",
        "Layer",
        "Tunnel device",
        Kind::Choice(&["tun", "tap"]),
        "tun carries IP packets, tap carries Ethernet frames.",
    ),
    Field {
        required: false,
        hint: "02:aa:bb:cc:dd:ee",
        ..field(
            "--tap-mac",
            "TAP MAC address",
            "Tunnel device",
            Kind::Text,
            "Optional unicast Ethernet MAC address for TAP L2 adapters.",
        )
    },
    Field {
        required: false,
        hint: "0.0.0.0:4789",
        ..field(
            "--vxlan-bind",
            "VXLAN local UDP bind",
            "Tunnel device",
            Kind::Address,
            "Optional VXLAN L2 UDP bind IP:port (replaces --device; requires --layer tap).",
        )
    },
    Field {
        required: false,
        hint: "127.0.0.1:4790",
        ..field(
            "--vxlan-peer",
            "VXLAN peer UDP address",
            "Tunnel device",
            Kind::Address,
            "Optional VXLAN L2 remote VTEP IP:port (requires --layer tap).",
        )
    },
    Field {
        required: false,
        hint: "42",
        ..field(
            "--vni",
            "VXLAN VNI",
            "Tunnel device",
            Kind::Number,
            "Optional 24-bit VXLAN Network Identifier (0..=16777215; requires --layer tap).",
        )
    },
    Field {
        required: false,
        hint: "1600",
        ..field(
            "--max-packet",
            "Largest packet (bytes)",
            "Tunnel device",
            Kind::Number,
            "Largest user packet; default 1600.",
        )
    },
    Field {
        required: false,
        hint: "1500",
        ..field(
            "--max-path-mtu",
            "Path MTU (bytes)",
            "Tunnel device",
            Kind::Number,
            "Largest datagram the network path carries.",
        )
    },
    field(
        "--record-profile",
        "Record profile",
        "Protocol",
        Kind::Choice(&["common"]),
        "Common compact records (the current protocol).",
    ),
    Field {
        required: false,
        ..field(
            "--duplex",
            "Duplex",
            "Protocol",
            Kind::Choice(&["full", "half"]),
            "full sends both ways at once; default half.",
        )
    },
    Field {
        required: false,
        ..field(
            "--compression",
            "Compression",
            "Protocol",
            Kind::Choice(&["off", "lz4"]),
            "lz4 compresses when it makes packets smaller.",
        )
    },
    // Live tuning (docs/modules/live-tuning.md): the client's switchable
    // choices, proposed at connect; the server's limits on them.
    Field {
        roles: Roles::Client,
        required: false,
        hint: "off,1/8,1/4",
        ..field(
            "--tune-repair",
            "Switchable FEC repair rates",
            "Live tuning",
            Kind::Text,
            "Comma list of repair rates to switch between live; off turns FEC off.",
        )
    },
    Field {
        roles: Roles::Client,
        required: false,
        hint: "1280,1400",
        ..field(
            "--tune-device-mtu",
            "Switchable device MTUs",
            "Live tuning",
            Kind::Text,
            "Comma list of inner packet sizes (bytes); also sets the TUN device MTU.",
        )
    },
    Field {
        roles: Roles::Client,
        required: false,
        hint: "1350",
        ..field(
            "--tune-path-mtu",
            "Switchable path MTUs",
            "Live tuning",
            Kind::Text,
            "Comma list of outer packet sizes (bytes) for paths that drop large packets.",
        )
    },
    Field {
        roles: Roles::Server,
        required: false,
        hint: "1/4",
        ..field(
            "--tune-max-repair",
            "Highest repair rate",
            "Live tuning",
            Kind::Text,
            "Largest FEC repair rate a client may propose; default any.",
        )
    },
    Field {
        roles: Roles::Server,
        required: false,
        hint: "1280-1500",
        ..field(
            "--tune-device-mtu-range",
            "Device MTU range",
            "Live tuning",
            Kind::Text,
            "Inner packet sizes a client may propose; default 68-65535.",
        )
    },
    Field {
        roles: Roles::Server,
        required: false,
        hint: "1200-1500",
        ..field(
            "--tune-path-mtu-range",
            "Path MTU range",
            "Live tuning",
            Kind::Text,
            "Outer packet sizes a client may propose; default 256-65535.",
        )
    },
    Field {
        roles: Roles::Server,
        required: false,
        hint: "64",
        ..field(
            "--tune-max-entries",
            "Most switchable settings",
            "Live tuning",
            Kind::Number,
            "Largest combined catalog a client may propose (1-64).",
        )
    },
    Field {
        roles: Roles::Server,
        required: false,
        hint: "8388608",
        ..field(
            "--tune-memory-cap",
            "Memory cap (bytes)",
            "Live tuning",
            Kind::Number,
            "Largest memory one switchable setting may reserve; default the plan's budget.",
        )
    },
];

/// Validation result split into hard errors (block Save) and non-blocking
/// warnings (such as files unreadable by the unprivileged GUI process).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Validation {
    /// Problems that must be fixed before saving.
    pub errors: Vec<String>,
    /// Advisory checks that do not prevent saving (the service verifies them).
    pub warnings: Vec<String>,
}

/// The labeled field for `option`.
pub fn find(option: &str) -> Option<&'static Field> {
    FIELDS.iter().find(|field| field.option == option)
}

/// Validate fields for `serve` and the currently selected `--carrier`.
///
/// Missing files on the unprivileged GUI side are reported as `warnings`
/// rather than hard `errors`, because key files may live in a directory
/// readable only by the service.
pub fn validate(
    serve: bool,
    value: impl Fn(&str) -> Option<String>,
    exists: impl Fn(&str) -> bool,
) -> Validation {
    let carrier = value("--carrier").unwrap_or_default();
    let mut out = Validation::default();
    let has_vxlan = ["--vxlan-bind", "--vxlan-peer", "--vni"]
        .iter()
        .any(|opt| value(opt).is_some_and(|text| !text.trim().is_empty()));
    for field in FIELDS.iter().filter(|field| field.shown(serve, &carrier)) {
        let label = field.label(serve);
        let Some(text) = value(field.option).filter(|text| !text.trim().is_empty()) else {
            if field.required && !(field.option == "--device" && has_vxlan) {
                out.errors.push(format!("{label} is required"));
            }
            continue;
        };
        let text = text.trim();
        match field.kind {
            Kind::Choice(values) if !values.contains(&text) => {
                out.errors
                    .push(format!("{label} must be one of {}", values.join(", ")));
            }
            Kind::Address if text.parse::<std::net::SocketAddr>().is_err() => {
                out.errors
                    .push(format!("{label} must be IP:port, e.g. {}", field.hint));
            }
            Kind::Number => {
                if field.option == "--raw-mark" {
                    if text
                        .parse::<u32>()
                        .ok()
                        .filter(|value| *value > 0)
                        .is_none()
                    {
                        out.errors
                            .push(format!("{label} must be a nonzero whole number"));
                    }
                } else if field.option == "--vni" {
                    if text
                        .parse::<u32>()
                        .ok()
                        .filter(|value| *value <= 0x00ff_ffff)
                        .is_none()
                    {
                        out.errors
                            .push(format!("{label} must be between 0 and 16777215"));
                    }
                } else if text.parse::<u64>().is_err() {
                    out.errors.push(format!("{label} must be a whole number"));
                }
            }
            Kind::Text if field.option == "--server-pin" => {
                if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
                    out.errors.push(format!(
                        "{label} must be 64 hexadecimal characters (SHA-256)"
                    ));
                }
            }
            Kind::File if !exists(text) => {
                out.warnings.push(format!(
                    "{label}: {text} is not readable by this window (the service will verify it on save)"
                ));
            }
            _ => {}
        }
    }
    let psk = value("--noise-psk-file").is_some_and(|text| !text.trim().is_empty());
    match value("--noise-profile").as_deref().map(str::trim) {
        Some("ikpsk2") if !psk => {
            out.errors
                .push("The ikpsk2 handshake needs a pre-shared key".into());
        }
        Some("ik") if psk => out
            .errors
            .push("A pre-shared key needs the ikpsk2 handshake".into()),
        _ => {}
    }
    out
}

/// Hard problems a person can fix before saving (compatibility wrapper).
pub fn problems(
    serve: bool,
    value: impl Fn(&str) -> Option<String>,
    exists: impl Fn(&str) -> bool,
) -> Vec<String> {
    validate(serve, value, exists).errors
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn fields_are_unique_grouped_and_role_and_carrier_aware() {
        let mut seen = std::collections::BTreeSet::new();
        for field in FIELDS {
            assert!(seen.insert(field.option), "{} twice", field.option);
            assert!(GROUPS.contains(&field.group), "{}", field.option);
            assert!(field.option.starts_with("--"));
        }
        let peer = find("--udp-peer").map(|field| (field.label(false), field.label(true)));
        assert_eq!(peer, Some(("Server address", "Expected client address")));
        assert!(find("--identity").is_some_and(|field| {
            field.shown(false, "quic-like") && !field.shown(true, "quic-like")
        }));
        assert!(find("--allow-key").is_some_and(|field| {
            field.shown(true, "quic-like") && !field.shown(false, "quic-like")
        }));
        assert!(find("--udp-peer").is_some_and(|field| {
            field.shown(false, "quic-like") && !field.shown(false, "tcp")
        }));
        assert!(find("--remote").is_some_and(|field| {
            field.shown(false, "tcp") && !field.shown(false, "quic-like")
        }));
        assert!(find("--maintained-policy").is_some_and(|field| {
            field.shown(false, "quic") && !field.shown(false, "raw-packet")
        }));
        assert!(find("--raw-policy").is_some_and(|field| {
            field.shown(false, "raw-packet") && !field.shown(false, "tcp")
        }));
    }

    #[test]
    fn validate_handles_udp_tcp_raw_and_non_blocking_file_warnings() {
        let mut values: BTreeMap<&str, &str> = BTreeMap::new();
        let check = |serve: bool, values: &BTreeMap<&str, &str>| {
            validate(
                serve,
                |option| values.get(option).map(|value| (*value).to_owned()),
                |path| path.starts_with("/ok"),
            )
        };
        let all = check(false, &values);
        assert!(
            all.errors
                .contains(&"Server address is required".to_owned())
        );
        assert!(
            !all.errors
                .iter()
                .any(|problem| problem.contains("Trusted member"))
        );
        for (option, value) in [
            ("--udp-peer", "127.0.0.1:24441"),
            ("--udp-bind", "127.0.0.1:24440"),
            ("--carrier", "quic-like"),
            ("--common-transaction-plan", "/ok/plan.json"),
            ("--noise-profile", "ik"),
            ("--noise-private-key-file", "/ok/a.key"),
            ("--noise-peer-key-file", "/ok/b.pub"),
            ("--identity", "/ok/member.der"),
            ("--session-admission-key-file", "/ok/admission.key"),
            ("--device", "l2t0"),
            ("--layer", "tun"),
            ("--record-profile", "common"),
        ] {
            values.insert(option, value);
        }
        assert_eq!(check(false, &values), Validation::default());

        // Unreadable file in the GUI produces a warning, not a blocking error.
        values.insert("--identity", "/etc/l2tunnel/root-only.der");
        let with_warning = check(false, &values);
        assert!(with_warning.errors.is_empty(), "{with_warning:?}");
        assert_eq!(with_warning.warnings.len(), 1);

        // Switching to TCP hides UDP fields and validates TCP/TLS fields instead.
        let mut tcp = BTreeMap::new();
        for (option, value) in [
            ("--carrier", "tcp"),
            ("--remote", "127.0.0.1:443"),
            ("--udp-cover", "tls-like"),
            ("--maintained-policy", "/ok/maintained.json"),
            ("--common-transaction-plan", "/ok/plan.json"),
            ("--noise-profile", "ik"),
            ("--noise-private-key-file", "/ok/a.key"),
            ("--noise-peer-key-file", "/ok/b.pub"),
            ("--identity", "/ok/member.der"),
            ("--session-admission-key-file", "/ok/admission.key"),
            ("--ca", "/ok/ca.pem"),
            ("--server-name", "tunnel.example.test"),
            ("--device", "l2t0"),
            ("--layer", "tun"),
            ("--record-profile", "common"),
        ] {
            tcp.insert(option, value);
        }
        assert_eq!(check(false, &tcp), Validation::default());

        // Raw-packet requires nonzero u32 raw-mark.
        let mut raw = tcp.clone();
        raw.insert("--carrier", "raw-packet");
        raw.insert("--raw-policy", "/ok/raw.json");
        raw.insert("--raw-mark", "0");
        assert!(
            check(false, &raw)
                .errors
                .iter()
                .any(|error| error.contains("Raw socket mark"))
        );
        raw.insert("--raw-mark", "7");
        assert_eq!(check(false, &raw), Validation::default());

        // Server cert SHA-256 pin validation on outer TLS carriers.
        let mut pinned = tcp.clone();
        pinned.insert("--server-pin", "bad-pin");
        assert!(
            check(false, &pinned)
                .errors
                .iter()
                .any(|e| e.contains("64 hexadecimal"))
        );
        let good_pin = "a".repeat(64);
        pinned.insert("--server-pin", good_pin.as_str());
        assert_eq!(check(false, &pinned), Validation::default());

        // VXLAN L2 profile omits --device and validates VNI range.
        let mut vxlan = tcp;
        vxlan.remove("--device");
        vxlan.insert("--layer", "tap");
        vxlan.insert("--vxlan-bind", "0.0.0.0:4789");
        vxlan.insert("--vxlan-peer", "127.0.0.1:4790");
        vxlan.insert("--vni", "16777216");
        assert!(
            check(false, &vxlan)
                .errors
                .iter()
                .any(|e| e.contains("16777215"))
        );
        vxlan.insert("--vni", "42");
        assert_eq!(check(false, &vxlan), Validation::default());
    }
}
