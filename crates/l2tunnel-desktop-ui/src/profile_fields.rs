//! Labeled fields of the profile editor (usability review 2026-11-24). A
//! profile stays the validated run options (owner decision 2026-11-23); this
//! table only gives the common options a label, a group, a kind of input and
//! help. Options not listed here stay editable as raw rows under "Other".
//! The service remains the authority: Save is refused for an unrunnable plan.

/// How a field is entered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// One of fixed values.
    Choice(&'static [&'static str]),
    /// A file path, chosen with the file chooser.
    File,
    /// `IP:PORT`.
    Address,
    /// A whole number.
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
    /// Needed for a runnable profile of this role.
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
    /// Shown for the role.
    pub fn shown(&self, serve: bool) -> bool {
        match self.roles {
            Roles::Both => true,
            Roles::Client => !serve,
            Roles::Server => serve,
        }
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
        required: true,
        hint: "",
        help,
    }
}

/// The labeled options, in display order within each group.
pub const FIELDS: &[Field] = &[
    Field {
        server_label: Some("Expected client address"),
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
        hint: "0.0.0.0:4433",
        ..field(
            "--udp-bind",
            "Local address",
            "Connection",
            Kind::Address,
            "IP:port this side uses (a server listens here).",
        )
    },
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
        required: false,
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

/// The labeled field for `option`.
pub fn find(option: &str) -> Option<&'static Field> {
    FIELDS.iter().find(|field| field.option == option)
}

/// Problems a person can fix before saving: missing required values, values
/// outside a choice, malformed addresses or numbers, and missing files.
pub fn problems(
    serve: bool,
    value: impl Fn(&str) -> Option<String>,
    exists: impl Fn(&str) -> bool,
) -> Vec<String> {
    let mut problems = Vec::new();
    for field in FIELDS.iter().filter(|field| field.shown(serve)) {
        let label = field.label(serve);
        let Some(text) = value(field.option).filter(|text| !text.trim().is_empty()) else {
            if field.required {
                problems.push(format!("{label} is required"));
            }
            continue;
        };
        let text = text.trim();
        match field.kind {
            Kind::Choice(values) if !values.contains(&text) => {
                problems.push(format!("{label} must be one of {}", values.join(", ")));
            }
            Kind::Address if text.parse::<std::net::SocketAddr>().is_err() => {
                problems.push(format!("{label} must be IP:port, e.g. {}", field.hint));
            }
            Kind::Number if text.parse::<u32>().is_err() => {
                problems.push(format!("{label} must be a whole number"));
            }
            Kind::File if !exists(text) => {
                problems.push(format!("{label}: {text} does not exist"));
            }
            _ => {}
        }
    }
    let psk = value("--noise-psk-file").is_some_and(|text| !text.trim().is_empty());
    match value("--noise-profile").as_deref().map(str::trim) {
        Some("ikpsk2") if !psk => {
            problems.push("The ikpsk2 handshake needs a pre-shared key".into())
        }
        Some("ik") if psk => problems.push("A pre-shared key needs the ikpsk2 handshake".into()),
        _ => {}
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn fields_are_unique_grouped_and_role_aware() {
        let mut seen = std::collections::BTreeSet::new();
        for field in FIELDS {
            assert!(seen.insert(field.option), "{} twice", field.option);
            assert!(GROUPS.contains(&field.group), "{}", field.option);
            assert!(field.option.starts_with("--"));
        }
        let peer = find("--udp-peer").map(|field| (field.label(false), field.label(true)));
        assert_eq!(peer, Some(("Server address", "Expected client address")));
        assert!(find("--identity").is_some_and(|field| field.shown(false) && !field.shown(true)));
        assert!(find("--allow-key").is_some_and(|field| field.shown(true) && !field.shown(false)));
    }

    #[test]
    fn problems_name_what_to_fix() {
        let mut values: BTreeMap<&str, &str> = BTreeMap::new();
        let check = |values: &BTreeMap<&str, &str>| {
            problems(
                false,
                |option| values.get(option).map(|value| (*value).to_owned()),
                |path| path.starts_with("/ok"),
            )
        };
        let all = check(&values);
        assert!(all.contains(&"Server address is required".to_owned()));
        assert!(!all.iter().any(|problem| problem.contains("Trusted member")));
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
        assert_eq!(check(&values), Vec::<String>::new());
        values.insert("--udp-peer", "example.org");
        values.insert("--carrier", "pigeon");
        values.insert("--identity", "/missing/member.der");
        values.insert("--noise-profile", "ikpsk2");
        let found = check(&values);
        assert_eq!(found.len(), 4, "{found:?}");
        assert!(
            found
                .iter()
                .any(|problem| problem.starts_with("Server address must be IP:port"))
        );
        assert!(
            found
                .iter()
                .any(|problem| problem.contains("pre-shared key"))
        );
    }
}
