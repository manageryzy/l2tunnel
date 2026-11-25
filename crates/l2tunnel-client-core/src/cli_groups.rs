//! Grouped `l2tunnelctl` commands over local API version 5
//! (`docs/modules/local-operations.md`). Flat legacy commands are unchanged.
use super::local::{
    self, Digest, EventBody, EventState, OperationAction, OperationReply, OperationRequest,
    OperationResult, OperationState, ServiceId, ServiceStatus, TerminalState,
};
use crate::secure_udp::common_status::{CANONICAL_CHARACTERS, CanonicalConfiguration};
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

/// Command groups handled here.
pub(super) const GROUPS: &[&str] = &[
    "service",
    "operation",
    "events",
    "config",
    "profile",
    "key",
    "stats",
    "meters",
    "device",
    "route",
    "diagnostics",
    "session",
    "member",
    "test",
    "tune",
];
/// Default and maximum client-side watch bound for submissions, in seconds.
const DEFAULT_WATCH_SECONDS: u64 = 120;
const MAXIMUM_WATCH_SECONDS: u64 = 86_400;

pub(super) const HELP: &str =
    "Grouped commands (local API v5; add --json for one JSON reply per line):
  service status
  service info              (version, role, uptime, per-feature capabilities)
  service connect|reconnect|disconnect|drain-proxy [--request-key K] [--watch SECONDS | --detach]
  session list                          (server: the live session, at most one)
  session kick [--request-key K] [--watch SECONDS | --detach]
      (end the live session and listen again with the same plan)
  member revoke --allow-key FILE [--watch SECONDS]
      (daemon server: save the running profile with FILE as its only trusted member key,
       then replace the session; FILE must be an absolute path the service can read)
  service stop [--request-key K] [--watch SECONDS | --detach]   (daemon: disconnect, remove
      session routes, exit; start it again with service start)
  service start [--program PATH] [--wait SECONDS] [--install]
      (administrator prompt, then wait until the service answers. Linux: pkexec installs
       or starts l2tunnel-UID.service, which runs as you with only CAP_NET_ADMIN and serves
       /run/l2tunnel-UID/api.sock; --install reinstalls PATH. Windows: UAC starts the
       service; --install --profile-dir DIR --wintun-dll DLL --wintun-sha256 HEX
       --address A/L registers it first. --control-socket is optional here)
  service connect|reconnect --profile NAME ...   (daemon: run a stored profile; reconnect
      replaces a live session, a controlled reconnect, never a hot switch)
  operation show|watch|cancel ID [--service HEX] [--timeout SECONDS]
  events [--after N] [--limit 1..32] [--timeout SECONDS] [--follow]
  stats show                (one counter snapshot)
  stats watch [--interval 1..60] [--count N]   (rates per interval)
  meters read [PREFIX] [--remote] [--limit 1..256] [--all]
      (meter CSR registers under a whole-segment prefix, e.g. runtime.native_ingress;
       --remote reads the authenticated peer over the in-band Meters stream)
  meters catalog [PREFIX] [--limit 1..256] [--all]   (path patterns, kinds and units)
  meters watch [PREFIX] [--remote] [--interval 1..60] [--count N]
      (rates per second and p50/p99 of waits completed in each interval)
  device list
  device create NAME --layer tun|tap [--mtu N] [--addresses A/L,...] [--down]
  device configure NAME [--mtu N] [--add A/L,...] [--remove A/L,...] [--up|--down]
  device delete NAME
  route list
  route add DEST/LEN --device DEV [--gateway IP] [--metric N]
  route remove DEST/LEN --device DEV
  route default on|off --device DEV   (all traffic via DEV; peer keeps its path)
  test speed [--download] [--streams 1..8] [--seconds 1..30] [--detach]
  test ping [--count 1..100] [--interval-ms 100..1000] [--detach]
  test status [ID] | test cancel ID
      (in-process TCP/ICMP through the tunnel's own path, never the host
      network stack; the peer answers while connected)
  diagnostics export --output FILE [--include-addresses]
      (status, info, metrics, devices, routes, events and recent operation
      results as JSON; IP addresses are redacted unless included; FILE must
      not exist and is created readable by its owner only)
  Device and route changes take [--request-key K] [--watch SECONDS | --detach]. They
  need a service started with --state-dir DIR; routes need a running session and
  are removed when it ends. Only service-created devices and routes can change.
  tune show                 (live tuning: current FEC repair, device and path MTU, the
                             choices of each control and every reachable setting)
  tune set [--repair off|N/D] [--device-mtu N] [--path-mtu N] [--request-key K]
           [--watch SECONDS | --detach]
      (hot switch to the setting; controls not given keep their current value)
  tune budget --symmetric MBPS | --upload MBPS --download MBPS   (1..=10000 Mbit/s;
      live authenticated wire speed-budget update on both peers without reconnecting)
  config switch --configuration HEX [--request-key K] [--watch SECONDS | --detach]
  config catalog --generation G --catalog HEX --offset O --limit 1..4
  profile inspect OPTIONS   (same as inspect-common-transaction-plan)
  profile list | show NAME | validate NAME
  profile export NAME --output FILE      (importable JSON document; FILE must not exist)
  profile import NAME --file FILE [--revision N]   (create, or replace revision N)
  profile delete NAME --revision N
  profile default NAME | --clear         (connected when the daemon starts)
      Profiles need the daemon (`daemon --control-socket P --state-dir D`). A profile is
      {\"version\":1,\"role\":\"connect\"|\"serve\",\"options\":{\"--carrier\":\"quic-like\",...}}:
      the run options without --control-socket/--state-dir/--runtime-model; keys stay
      files the options name. Saving requires a runnable plan.
  key generate OPTIONS      (same as keygen: member identity --private F --public F)
  key generate-noise --private FILE --public FILE   (Noise X25519 pair; public goes to the peer)
  key generate-secret --output FILE                 (32 random bytes: admission, cookie or PSK)
      Key generation is local and needs no service; files must not exist (mode 0600).
  profile keys NAME         (key files the profile names: role, usable, public key or
                             certificate SHA-256; private material is never shown)
Online commands need --control-socket PATH (on Windows the service pipe, by default
\\\\.\\pipe\\l2tunnel). Exit codes: 0 completed (or accepted with
--detach), 1 rejected/failed, 2 usage, 3 service unreachable, 4 still running at the
watch deadline, 5 outcome unknown, 6 unsupported.";

/// Grouped-command exit contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Exit {
    Completed = 0,
    Failed = 1,
    Usage = 2,
    Unreachable = 3,
    Running = 4,
    Unknown = 5,
    Unsupported = 6,
}
impl From<Exit> for ExitCode {
    fn from(value: Exit) -> Self {
        ExitCode::from(value as u8)
    }
}
/// A refusal code's exit class.
pub(super) fn refusal_exit(code: &str) -> Exit {
    match code {
        "unsupported" | "unsupported_version" | "cancel_unsupported" => Exit::Unsupported,
        "service_restarted" | "outcome_unknown" | "expired" => Exit::Unknown,
        "closed" => Exit::Unreachable,
        _ => Exit::Failed,
    }
}
/// A completion's exit class.
pub(super) fn result_exit(result: &OperationResult) -> Exit {
    if result.succeeded() {
        Exit::Completed
    } else if matches!(result, OperationResult::OutcomeUnknown) {
        Exit::Unknown
    } else {
        Exit::Failed
    }
}

#[derive(Debug)]
struct Usage(String);
fn usage(message: impl Into<String>) -> Usage {
    Usage(message.into())
}

/// Parsed grouped invocation.
#[derive(Debug, Eq, PartialEq)]
enum Command {
    Status,
    /// Elevated install/start of the platform service.
    Start(Box<local::elevate::StartRequest>),
    Submit {
        action: Submission,
        key: Option<u64>,
        watch: Option<u64>,
    },
    Show(u64, Option<ServiceId>),
    Watch(u64, Option<ServiceId>, u64),
    Cancel(u64, Option<ServiceId>),
    Events {
        after: u64,
        limit: u16,
        timeout: u64,
        follow: bool,
        service: Option<ServiceId>,
    },
    Catalog {
        generation: u64,
        catalog: Digest,
        offset: u16,
        limit: u16,
    },
    Delegate(&'static str),
    KeyGenerate(local::keys::KeyGeneration),
    Info,
    Sessions,
    Revoke {
        allow_key: PathBuf,
        watch: u64,
    },
    Profile(profile::Query),
    Diagnostics {
        output: PathBuf,
        include_addresses: bool,
    },
    DeviceList,
    RouteList,
    Stats {
        watch: bool,
        interval: u64,
        count: Option<u64>,
    },
    Test(test::Query),
    Meters(meters::Query),
    TuneShow,
    TuneBudget(tune::Budget),
    TuneSet {
        partial: tune::Partial,
        key: Option<u64>,
        watch: Option<u64>,
    },
}
#[derive(Debug, Eq, PartialEq)]
enum Submission {
    Connect,
    Reconnect,
    Disconnect,
    DrainProxy,
    Switch(CanonicalConfiguration),
    Profile(crate::local::ProfileChange),
    ProfileConnect { name: String, replace: bool },
    Stop,
    Kick,
    Device(crate::local::DeviceChange),
    Route(crate::local::RouteChange),
    Tune(crate::local::TuningSetting),
}
impl Submission {
    fn action(&self, request_key: u64) -> OperationAction {
        match self {
            Self::Connect => OperationAction::Connect { request_key },
            Self::Reconnect => OperationAction::Reconnect { request_key },
            Self::Disconnect => OperationAction::Disconnect { request_key },
            Self::DrainProxy => OperationAction::DrainProxy { request_key },
            Self::Switch(configuration) => OperationAction::SwitchCommonConfiguration {
                configuration: configuration.clone(),
                request_key,
            },
            Self::Stop => OperationAction::ServiceStop { request_key },
            Self::Kick => OperationAction::SessionKick { request_key },
            Self::Profile(change) => OperationAction::Profile {
                request_key,
                change: change.clone(),
            },
            Self::ProfileConnect { name, replace } => OperationAction::ProfileConnect {
                request_key,
                name: name.clone(),
                replace: *replace,
            },
            Self::Device(change) => OperationAction::Device {
                request_key,
                change: change.clone(),
            },
            Self::Route(change) => OperationAction::Route {
                request_key,
                change: change.clone(),
            },
            Self::Tune(setting) => OperationAction::TuningSwitch {
                request_key,
                setting: setting.clone(),
            },
        }
    }
}
#[derive(Debug)]
struct Parsed {
    command: Command,
    socket: Option<PathBuf>,
    json: bool,
}

/// Options with values, set boolean flags and positional arguments.
struct Split {
    options: BTreeMap<String, String>,
    flags: Vec<String>,
    positional: Vec<String>,
}
/// Split `--name value` options, boolean flags and positionals.
fn split(args: &[String], values: &[&str], flags: &[&str]) -> Result<Split, Usage> {
    let mut options = BTreeMap::new();
    let mut set = Vec::new();
    let mut positional = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if flags.contains(&arg.as_str()) {
            if set.contains(arg) {
                return Err(usage(format!("duplicate {arg}")));
            }
            set.push(arg.clone());
        } else if values.contains(&arg.as_str()) {
            let value = iter
                .next()
                .filter(|value| !value.starts_with("--"))
                .ok_or_else(|| usage(format!("{arg} needs a value")))?;
            if arg == "--configuration" && value.len() > CANONICAL_CHARACTERS {
                return Err(usage("configuration exceeds the canonical length"));
            }
            if options.insert(arg.clone(), value.clone()).is_some() {
                return Err(usage(format!("duplicate {arg}")));
            }
        } else if arg.starts_with("--") {
            return Err(usage(format!("unknown option {arg}")));
        } else {
            positional.push(arg.clone());
        }
    }
    Ok(Split {
        options,
        flags: set,
        positional,
    })
}
fn number<T: std::str::FromStr>(
    options: &BTreeMap<String, String>,
    key: &str,
) -> Result<Option<T>, Usage> {
    options
        .get(key)
        .map(|value| value.parse().map_err(|_| usage(format!("invalid {key}"))))
        .transpose()
}
fn required<T: std::str::FromStr>(
    options: &BTreeMap<String, String>,
    key: &str,
) -> Result<T, Usage> {
    number(options, key)?.ok_or_else(|| usage(format!("missing {key}")))
}
fn nonzero(value: Option<u64>, name: &str) -> Result<Option<u64>, Usage> {
    match value {
        Some(0) => Err(usage(format!("{name} must be nonzero"))),
        other => Ok(other),
    }
}
fn seconds(options: &BTreeMap<String, String>, key: &str, default: u64) -> Result<u64, Usage> {
    let value = number(options, key)?.unwrap_or(default);
    if value > MAXIMUM_WATCH_SECONDS {
        return Err(usage(format!(
            "{key} exceeds {MAXIMUM_WATCH_SECONDS} seconds"
        )));
    }
    Ok(value)
}
fn service(options: &BTreeMap<String, String>) -> Result<Option<ServiceId>, Usage> {
    options
        .get("--service")
        .map(|text| {
            ServiceId::parse(text).ok_or_else(|| usage("--service must be 16 lowercase hex"))
        })
        .transpose()
}
fn operation_id(positional: &[String]) -> Result<u64, Usage> {
    match positional {
        [id] => nonzero(
            Some(id.parse().map_err(|_| usage("invalid operation ID"))?),
            "operation ID",
        )?
        .ok_or_else(|| usage("missing operation ID")),
        _ => Err(usage("expected exactly one operation ID")),
    }
}

fn parse(args: &[String]) -> Result<Parsed, Usage> {
    let group = args.first().map(String::as_str).unwrap_or_default();
    let (verb, rest) = if group == "events" {
        ("", args.get(1..).unwrap_or_default())
    } else {
        (
            args.get(1).map(String::as_str).unwrap_or_default(),
            args.get(2..).unwrap_or_default(),
        )
    };
    if matches!((group, verb), ("profile", "inspect") | ("key", "generate")) {
        let target = if group == "profile" {
            "inspect-common-transaction-plan"
        } else {
            "keygen"
        };
        return Ok(Parsed {
            command: Command::Delegate(target),
            socket: None,
            json: false,
        });
    }
    if group == "key" && matches!(verb, "generate-noise" | "generate-secret") {
        // Local and unprivileged: keys stay files the profiles name.
        let values: &[&str] = if verb == "generate-noise" {
            &["--private", "--public"]
        } else {
            &["--output"]
        };
        let Split {
            options,
            flags: set,
            positional,
        } = split(rest, values, &["--json"])?;
        if let Some(extra) = positional.first() {
            return Err(usage(format!("unexpected argument {extra}")));
        }
        let path = |key: &str| {
            options
                .get(key)
                .map(PathBuf::from)
                .ok_or_else(|| usage(format!("missing {key} FILE")))
        };
        let generation = if verb == "generate-noise" {
            local::keys::KeyGeneration::Noise {
                private: path("--private")?,
                public: path("--public")?,
            }
        } else {
            local::keys::KeyGeneration::Secret {
                output: path("--output")?,
            }
        };
        return Ok(Parsed {
            command: Command::KeyGenerate(generation),
            socket: None,
            json: set.iter().any(|flag| flag == "--json"),
        });
    }
    let mut values = vec!["--control-socket"];
    let mut flags = vec!["--json"];
    match (group, verb) {
        ("service", "connect" | "reconnect" | "disconnect" | "drain-proxy" | "stop") => {
            values.extend(["--request-key", "--watch"]);
            flags.push("--detach");
        }
        ("config", "switch") => {
            values.extend(["--configuration", "--request-key", "--watch"]);
            flags.push("--detach");
        }
        ("config", "catalog") => {
            values.extend(["--generation", "--catalog", "--offset", "--limit"])
        }
        ("operation", "show" | "cancel") => values.push("--service"),
        ("operation", "watch") => values.extend(["--service", "--timeout"]),
        ("events", _) => {
            values.extend(["--after", "--limit", "--timeout", "--service"]);
            flags.push("--follow");
        }
        ("service", "status" | "info") | ("stats", "show") => {}
        ("service", "start") => {
            values.extend(start::VALUES);
            flags.push("--install");
        }
        ("stats", "watch") => values.extend(["--interval", "--count"]),
        ("profile", _) if profile::accepted(verb).is_some() => {
            if let Some((more_values, more_flags)) = profile::accepted(verb) {
                values.extend(more_values);
                flags.extend(more_flags);
            }
            if profile::submits(verb) {
                values.extend(["--request-key", "--watch"]);
                flags.push("--detach");
            }
        }
        ("session", "list") => {}
        ("session", "kick") => {
            values.extend(["--request-key", "--watch"]);
            flags.push("--detach");
        }
        ("member", "revoke") => values.extend(["--allow-key", "--watch"]),
        ("tune", "show") => {}
        ("tune", "budget") => values.extend(tune::BUDGET_VALUES),
        ("tune", "set") => {
            values.extend(tune::SET_VALUES);
            values.extend(["--request-key", "--watch"]);
            flags.push("--detach");
        }
        ("meters", _) if meters::accepted(verb).is_some() => {
            if let Some((more_values, more_flags)) = meters::accepted(verb) {
                values.extend(more_values);
                flags.extend(more_flags);
            }
        }
        ("test", _) if test::accepted(verb).is_some() => {
            if let Some((more_values, more_flags)) = test::accepted(verb) {
                values.extend(more_values);
                flags.extend(more_flags);
            }
        }
        ("diagnostics", "export") => {
            values.push("--output");
            flags.push("--include-addresses");
        }
        ("device" | "route", _) if host::accepted(group, verb).is_some() => {
            if let Some((more_values, more_flags)) = host::accepted(group, verb) {
                values.extend(more_values);
                flags.extend(more_flags);
            }
            if verb != "list" {
                values.extend(["--request-key", "--watch"]);
                flags.push("--detach");
            }
        }
        _ => return Err(usage(format!("unknown command {group} {verb}"))),
    }
    if group == "service" && matches!(verb, "connect" | "reconnect") {
        values.push("--profile");
    }
    let Split {
        options,
        flags: set,
        positional,
    } = split(rest, &values, &flags)?;
    let flag = |name: &str| set.iter().any(|value| value == name);
    if (!matches!(
        group,
        "operation" | "device" | "route" | "profile" | "test" | "meters"
    ) || verb == "list")
        && !positional.is_empty()
    {
        return Err(usage(format!("unexpected argument {}", positional[0])));
    }
    let submit = |action: Submission| -> Result<Command, Usage> {
        if flag("--detach") && options.contains_key("--watch") {
            return Err(usage("--watch and --detach are exclusive"));
        }
        Ok(Command::Submit {
            action,
            key: nonzero(number(&options, "--request-key")?, "--request-key")?,
            watch: if flag("--detach") {
                None
            } else {
                Some(seconds(&options, "--watch", DEFAULT_WATCH_SECONDS)?)
            },
        })
    };
    let command = match (group, verb) {
        ("service", "status") => Command::Status,
        ("service", "info") => Command::Info,
        ("session", "list") => Command::Sessions,
        ("session", _) => submit(Submission::Kick)?,
        ("member", _) => {
            let allow_key = options
                .get("--allow-key")
                .map(PathBuf::from)
                .ok_or_else(|| usage("missing --allow-key FILE"))?;
            if !allow_key.is_absolute() {
                return Err(usage(
                    "--allow-key must be an absolute path the service can read",
                ));
            }
            Command::Revoke {
                allow_key,
                watch: seconds(&options, "--watch", DEFAULT_WATCH_SECONDS)?,
            }
        }
        ("diagnostics", _) => Command::Diagnostics {
            output: options
                .get("--output")
                .map(PathBuf::from)
                .ok_or_else(|| usage("missing --output FILE"))?,
            include_addresses: flag("--include-addresses"),
        },
        ("test", _) => Command::Test(test::parse(verb, &positional, &options, flag)?),
        ("tune", "show") => Command::TuneShow,
        ("tune", "budget") => Command::TuneBudget(tune::budget(&options)?),
        ("tune", _) => {
            let partial = tune::partial(&options)?;
            let Command::Submit { key, watch, .. } =
                submit(Submission::Tune(crate::local::TuningSetting {
                    repair: String::new(),
                    device_mtu: 0,
                    path_mtu: 0,
                }))?
            else {
                return Err(usage("tune set"));
            };
            Command::TuneSet {
                partial,
                key,
                watch,
            }
        }
        ("meters", _) => Command::Meters(meters::parse(verb, &positional, &options, flag)?),
        ("device", "list") => Command::DeviceList,
        ("route", "list") => Command::RouteList,
        ("device", _) => submit(Submission::Device(host::device_change(
            verb,
            &positional,
            &options,
            flag,
        )?))?,
        ("route", _) => submit(Submission::Route(host::route_change(
            verb,
            &positional,
            &options,
        )?))?,
        ("stats", "show") => Command::Stats {
            watch: false,
            interval: 1,
            count: Some(1),
        },
        ("stats", "watch") => {
            let interval = number(&options, "--interval")?.unwrap_or(1);
            if !(1..=60).contains(&interval) {
                return Err(usage("--interval must be 1..60"));
            }
            Command::Stats {
                watch: true,
                interval,
                count: nonzero(number(&options, "--count")?, "--count")?,
            }
        }
        ("service", "connect" | "reconnect") if options.contains_key("--profile") => {
            let name: String = required(&options, "--profile")?;
            crate::local::validate_profile_name(&name).map_err(usage)?;
            submit(Submission::ProfileConnect {
                name,
                replace: verb == "reconnect",
            })?
        }
        ("service", "connect") => submit(Submission::Connect)?,
        ("service", "reconnect") => submit(Submission::Reconnect)?,
        ("profile", _) => match profile::parse(verb, &positional, &options, flag)? {
            Ok(query) => Command::Profile(query),
            Err(change) => submit(Submission::Profile(change))?,
        },
        ("service", "disconnect") => submit(Submission::Disconnect)?,
        ("service", "stop") => submit(Submission::Stop)?,
        ("service", "start") => Command::Start(Box::new(start::request(
            &options,
            options.get("--control-socket").map(PathBuf::from).as_ref(),
            flag("--install"),
        )?)),
        ("service", "drain-proxy") => submit(Submission::DrainProxy)?,
        ("config", "switch") => {
            let text: String = required(&options, "--configuration")?;
            let configuration = CanonicalConfiguration::parse(&text)
                .map_err(|_| usage("invalid complete configuration"))?;
            submit(Submission::Switch(configuration))?
        }
        ("config", "catalog") => {
            let text: String = required(&options, "--catalog")?;
            let limit = required(&options, "--limit")?;
            if !(1..=local::CATALOG_LIMIT).contains(&limit) {
                return Err(usage("--limit must be 1..4"));
            }
            Command::Catalog {
                generation: required(&options, "--generation")?,
                catalog: Digest::parse(&text)
                    .ok_or_else(|| usage("--catalog must be 64 lowercase hex"))?,
                offset: required(&options, "--offset")?,
                limit,
            }
        }
        ("operation", "show") => Command::Show(operation_id(&positional)?, service(&options)?),
        ("operation", "cancel") => Command::Cancel(operation_id(&positional)?, service(&options)?),
        ("operation", "watch") => Command::Watch(
            operation_id(&positional)?,
            service(&options)?,
            seconds(&options, "--timeout", DEFAULT_WATCH_SECONDS)?,
        ),
        ("events", _) => {
            let limit = number(&options, "--limit")?.unwrap_or(local::EVENTS_LIMIT);
            if !(1..=local::EVENTS_LIMIT).contains(&limit) {
                return Err(usage("--limit must be 1..32"));
            }
            Command::Events {
                after: number(&options, "--after")?.unwrap_or(0),
                limit,
                timeout: seconds(&options, "--timeout", 0)?,
                follow: flag("--follow"),
                service: service(&options)?,
            }
        }
        _ => return Err(usage(format!("unknown command {group} {verb}"))),
    };
    Ok(Parsed {
        command,
        socket: options.get("--control-socket").map(PathBuf::from),
        json: flag("--json"),
    })
}

/// Output sink: human text or one JSON reply per line.
struct Output {
    json: bool,
}
impl Output {
    fn reply(&self, reply: &OperationReply, human: impl FnOnce(&mut dyn Write) -> io::Result<()>) {
        let mut out = io::stdout().lock();
        let _written = if self.json {
            serde_json::to_string(reply)
                .map_err(io::Error::other)
                .and_then(|line| writeln!(out, "{line}"))
        } else {
            human(&mut out)
        };
        let _flushed = out.flush();
    }
}
fn note(message: impl std::fmt::Display) {
    let _written = writeln!(io::stderr().lock(), "l2tunnelctl: {message}");
}
fn dash<T: std::fmt::Display>(value: Option<T>) -> String {
    value.map_or_else(|| "-".to_owned(), |value| value.to_string())
}
fn terminal_text(terminal: &TerminalState) -> String {
    match terminal {
        TerminalState::Aborted => "aborted".into(),
        TerminalState::Closed => "closed".into(),
        TerminalState::Failed { error_kind } => format!("failed ({error_kind})"),
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn write_status(
    out: &mut dyn Write,
    service: Option<ServiceId>,
    status: &ServiceStatus,
) -> io::Result<()> {
    writeln!(
        out,
        "service       {}",
        dash(service.map(|id| format!("{:016x}", id.0)))
    )?;
    writeln!(out, "phase         {}", status.phase)?;
    writeln!(out, "operation     {}", dash(status.operation))?;
    writeln!(out, "generation    {}", dash(status.generation))?;
    writeln!(
        out,
        "terminal      {}",
        dash(status.terminal.as_ref().map(terminal_text))
    )?;
    writeln!(out, "next key      {}", dash(status.next_request_key))?;
    writeln!(out, "event cursor  {}", status.event_cursor)?;
    writeln!(out, "listening     {}", dash(status.listening.as_ref()))?;
    let observation = status.observation.as_ref();
    if let Some(common) = observation.and_then(|value| value.common.as_ref()) {
        writeln!(out, "backend       common (running: {})", common.running)?;
        writeln!(out, "carrier       {}", common.carrier)?;
        writeln!(out, "algorithm     {}", common.algorithm)?;
        writeln!(out, "peer          {}", common.peer)?;
        writeln!(out, "epoch         {}", dash(common.epoch))?;
        writeln!(
            out,
            "catalog       {} ({} members, generation {})",
            hex(&common.catalog),
            common.catalog_members,
            common.generation
        )?;
    } else if let Some(proxy) = observation.and_then(|value| value.proxy.as_ref()) {
        writeln!(out, "backend       proxy {}", proxy.digest)?;
        writeln!(
            out,
            "drain         {}",
            if proxy.drain_accepted {
                "accepted"
            } else {
                "-"
            }
        )?;
    } else {
        writeln!(out, "backend       -")?;
    }
    Ok(())
}
fn result_text(result: &OperationResult) -> String {
    match result {
        OperationResult::Connected { generation } => format!("connected (generation {generation})"),
        OperationResult::Aborted => "aborted".into(),
        OperationResult::Applied { code } => format!("applied ({code})"),
        OperationResult::Rejected { code } => format!("rejected ({code})"),
        OperationResult::CommonCommitted { epoch, .. } => format!("committed (epoch {epoch})"),
        OperationResult::CommonRefused { reason, .. } => format!("refused ({reason})"),
        OperationResult::ReuseConfirmed { generation } => {
            format!("reuse confirmed (generation {generation})")
        }
        OperationResult::ReuseRefused { reason, .. } => format!("reuse refused ({reason})"),
        OperationResult::Cancelled => "cancelled".into(),
        OperationResult::OutcomeUnknown => "outcome unknown".into(),
        OperationResult::Failed { error_kind } => format!("failed ({error_kind})"),
        OperationResult::HostApplied { summary } => format!("applied ({summary})"),
        OperationResult::HostRefused { reason } => format!("refused ({reason})"),
        OperationResult::ProfileApplied { summary } => format!("applied ({summary})"),
        OperationResult::ProfileRefused { reason } => format!("refused ({reason})"),
    }
}
fn write_operation(out: &mut dyn Write, operation: &OperationState) -> io::Result<()> {
    write!(
        out,
        "operation {} ({}): {}",
        operation.id, operation.kind, operation.state
    )?;
    if let Some(result) = &operation.result {
        write!(out, ", {}", result_text(result))?;
    }
    if let Some(setup) = &operation.setup {
        write!(out, ", setup {} {}", setup.stage, setup.outcome)?;
        if let Some(failure) = &setup.failure {
            write!(out, " [{failure}]")?;
        }
    }
    if operation.result.is_none()
        && let Some(deadline) = operation.deadline_ms
    {
        write!(out, ", deadline in {deadline} ms")?;
    }
    if operation.cancel_requested {
        write!(out, ", cancel requested")?;
    }
    writeln!(out)
}
fn write_event(out: &mut dyn Write, event: &EventState) -> io::Result<()> {
    match &event.event {
        EventBody::OperationAccepted { operation, kind } => {
            writeln!(
                out,
                "#{} operation {operation} accepted ({kind})",
                event.sequence
            )
        }
        EventBody::OperationProgress { operation, stage } => {
            writeln!(
                out,
                "#{} operation {operation} reached {stage}",
                event.sequence
            )
        }
        EventBody::OperationCompleted { operation, outcome } => {
            writeln!(
                out,
                "#{} operation {operation} completed: {outcome}",
                event.sequence
            )
        }
        EventBody::Lifecycle {
            phase,
            operation,
            generation,
            terminal,
        } => writeln!(
            out,
            "#{} phase {phase}, operation {}, generation {}, terminal {}",
            event.sequence,
            dash(*operation),
            dash(*generation),
            dash(terminal.as_ref().map(terminal_text))
        ),
    }
}

type ExchangeFuture<'a> = std::pin::Pin<
    Box<
        dyn std::future::Future<Output = Result<Box<OperationReply>, (Exit, io::Error)>>
            + Send
            + 'a,
    >,
>;

/// One exchange; connection failures are reported as unreachable.
/// Boxed so `execute`'s debug future does not inline a copy of `request_operation`
/// and `OperationReply` at every command arm.
fn exchange<'a>(socket: &'a PathBuf, action: OperationAction) -> ExchangeFuture<'a> {
    Box::pin(async move {
        let submits = action.submits();
        local::request_operation(socket, &OperationRequest::new(action))
            .await
            .map(Box::new)
            .map_err(|error| {
                (
                    if submits && !local::client::unsent(&error) {
                        Exit::Unknown
                    } else {
                        Exit::Unreachable
                    },
                    error,
                )
            })
    })
}
fn refused(output: &Output, reply: &OperationReply) -> Exit {
    output.reply(reply, |out| writeln!(out, "refused: {}", reply.code));
    refusal_exit(&reply.code)
}

async fn watch(
    output: &Output,
    socket: &PathBuf,
    id: u64,
    service: Option<ServiceId>,
    seconds: u64,
) -> Exit {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let hint = || {
        note(format!(
            "reattach with: l2tunnelctl operation watch {id} --control-socket {}{}",
            socket.display(),
            service
                .map(|id| format!(" --service {:016x}", id.0))
                .unwrap_or_default()
        ))
    };
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            note(format!(
                "operation {id} is still running at the watch deadline"
            ));
            hint();
            return Exit::Running;
        }
        let timeout_ms = u32::try_from(remaining.as_millis())
            .unwrap_or(u32::MAX)
            .clamp(1, local::WAIT_LIMIT_MS);
        let reply = match exchange(
            socket,
            OperationAction::OperationWait {
                operation: id,
                timeout_ms,
                service,
            },
        )
        .await
        {
            Ok(reply) => reply,
            Err((_, error)) => {
                note(format!(
                    "lost contact while watching: {error}; outcome unknown"
                ));
                hint();
                return Exit::Unknown;
            }
        };
        let operation = reply.operation.as_ref();
        match (
            reply.code.as_str(),
            operation.and_then(|state| state.result.as_ref()),
        ) {
            ("running", _) => {
                if output.json {
                    output.reply(&reply, |_| Ok(()));
                }
            }
            (_, Some(result)) => {
                output.reply(&reply, |out| {
                    operation.map_or(Ok(()), |state| write_operation(out, state))
                });
                return result_exit(result);
            }
            ("closed", None) => {
                output.reply(&reply, |out| {
                    writeln!(out, "service closed; operation {id} outcome unknown")
                });
                return Exit::Unknown;
            }
            // `expired` (left the retained history) maps to outcome unknown.
            _ => return refused(output, &reply),
        }
    }
}

/// Run one grouped command. The command state machine holds whole replies
/// (including Common observations) across awaits, so it lives on the heap
/// rather than on the caller's stack.
fn run(parsed: Parsed) -> std::pin::Pin<Box<dyn std::future::Future<Output = Exit> + Send>> {
    Box::pin(execute(parsed))
}
async fn execute(parsed: Parsed) -> Exit {
    let output = Output { json: parsed.json };
    // `service start` needs no running service and no socket.
    if let Command::Start(request) = parsed.command {
        return start::run(*request, parsed.json).await;
    }
    let Some(socket) = parsed.socket else {
        note("missing --control-socket");
        return Exit::Usage;
    };
    let failed = |exit: Exit, error: io::Error| {
        note(format!("service unavailable: {error}"));
        exit
    };
    // `tune set` fills the controls it does not change from the session.
    let command = match parsed.command {
        Command::TuneSet {
            partial,
            key,
            watch,
        } => match tune::resolve(&socket, partial).await {
            Ok(setting) => Command::Submit {
                action: Submission::Tune(setting),
                key,
                watch,
            },
            Err(exit) => return exit,
        },
        other => other,
    };
    match command {
        Command::TuneSet { .. } => Exit::Usage,
        Command::TuneBudget(budget) => match exchange(
            &socket,
            OperationAction::RateBudgetSet {
                send_rate: budget.send_rate,
                receive_rate: budget.receive_rate,
            },
        )
        .await
        {
            Ok(reply) if reply.ok => {
                output.reply(&reply, |out| {
                    writeln!(
                        out,
                        "speed budget updated: up {} Mbit/s, down {} Mbit/s",
                        budget.send_rate / 125_000,
                        budget.receive_rate / 125_000
                    )
                });
                Exit::Completed
            }
            Ok(reply) => refused(&output, &reply),
            Err((exit, error)) => failed(exit, error),
        },
        Command::TuneShow => match exchange(&socket, OperationAction::TuningGet {}).await {
            Ok(reply) if reply.ok => {
                output.reply(&reply, |out| {
                    reply
                        .tuning
                        .as_deref()
                        .map_or(Ok(()), |view| tune::write_view(out, view))
                });
                Exit::Completed
            }
            Ok(reply) => refused(&output, &reply),
            Err((exit, error)) => failed(exit, error),
        },
        Command::Start(request) => start::run(*request, output.json).await,
        Command::Diagnostics {
            output: file,
            include_addresses,
        } => match Box::pin(local::diagnostics::collect(&socket, include_addresses)).await {
            Ok(report) => match local::diagnostics::write_new(&file, &report) {
                Ok(()) => {
                    let _written = if output.json {
                        writeln!(
                            io::stdout().lock(),
                            "{}",
                            serde_json::json!({"written": file})
                        )
                    } else {
                        writeln!(io::stdout().lock(), "wrote {}", file.display())
                    };
                    Exit::Completed
                }
                Err(error) => {
                    note(format!("cannot write {}: {error}", file.display()));
                    Exit::Failed
                }
            },
            Err(error) => failed(Exit::Unreachable, error),
        },
        Command::Sessions => match exchange(&socket, OperationAction::SessionList {}).await {
            Ok(reply) if reply.ok => {
                output.reply(&reply, |out| {
                    sessions::write_sessions(out, reply.sessions.as_deref().unwrap_or_default())
                });
                Exit::Completed
            }
            Ok(reply) => refused(&output, &reply),
            Err((exit, error)) => failed(exit, error),
        },
        Command::Revoke { allow_key, watch } => {
            Box::pin(sessions::revoke(&socket, &allow_key, watch, output.json)).await
        }
        Command::Profile(query) => {
            let action = match &query {
                profile::Query::List => OperationAction::ProfileList {},
                profile::Query::Show(name) | profile::Query::Export { name, .. } => {
                    OperationAction::ProfileGet { name: name.clone() }
                }
                profile::Query::Validate(name) => {
                    OperationAction::ProfileValidate { name: name.clone() }
                }
                profile::Query::Keys(name) => OperationAction::ProfileKeys { name: name.clone() },
            };
            match exchange(&socket, action).await {
                Ok(reply) if reply.ok => match &query {
                    profile::Query::List => {
                        output.reply(&reply, |out| {
                            profile::write_list(out, reply.profiles.as_deref().unwrap_or_default())
                        });
                        Exit::Completed
                    }
                    profile::Query::Show(_) => {
                        output.reply(&reply, |out| {
                            reply
                                .profile
                                .as_ref()
                                .map_or(Ok(()), |entry| profile::write_entry(out, entry))
                        });
                        Exit::Completed
                    }
                    profile::Query::Keys(_) => {
                        output.reply(&reply, |out| {
                            profile::write_keys(out, reply.keys.as_deref().unwrap_or_default())
                        });
                        if reply
                            .keys
                            .as_deref()
                            .unwrap_or_default()
                            .iter()
                            .all(|key| key.usable)
                        {
                            Exit::Completed
                        } else {
                            Exit::Failed
                        }
                    }
                    profile::Query::Validate(_) => {
                        output.reply(&reply, |out| {
                            reply
                                .check
                                .as_ref()
                                .map_or(Ok(()), |check| profile::write_check(out, check))
                        });
                        if reply.check.as_ref().is_some_and(|check| check.valid) {
                            Exit::Completed
                        } else {
                            Exit::Failed
                        }
                    }
                    profile::Query::Export { output: file, .. } => {
                        let written = reply
                            .profile
                            .as_ref()
                            .ok_or_else(|| io::Error::other("service replied without a profile"))
                            .and_then(profile::export_value)
                            .and_then(|value| local::diagnostics::write_new(file, &value));
                        match written {
                            Ok(()) => {
                                let _written = if output.json {
                                    writeln!(
                                        io::stdout().lock(),
                                        "{}",
                                        serde_json::json!({"written": file})
                                    )
                                } else {
                                    writeln!(io::stdout().lock(), "wrote {}", file.display())
                                };
                                Exit::Completed
                            }
                            Err(error) => {
                                note(format!("cannot write {}: {error}", file.display()));
                                Exit::Failed
                            }
                        }
                    }
                },
                Ok(reply) => {
                    if let Some(check) = &reply.check {
                        let _written = profile::write_check(&mut io::stderr().lock(), check);
                    }
                    refused(&output, &reply)
                }
                Err((exit, error)) => failed(exit, error),
            }
        }
        Command::DeviceList => match exchange(&socket, OperationAction::DeviceList {}).await {
            Ok(reply) if reply.ok => {
                output.reply(&reply, |out| {
                    host::write_devices(out, reply.devices.as_deref().unwrap_or_default())
                });
                Exit::Completed
            }
            Ok(reply) => refused(&output, &reply),
            Err((exit, error)) => failed(exit, error),
        },
        Command::RouteList => match exchange(&socket, OperationAction::RouteList {}).await {
            Ok(reply) if reply.ok => {
                output.reply(&reply, |out| {
                    host::write_routes(out, reply.routes.as_deref().unwrap_or_default())
                });
                Exit::Completed
            }
            Ok(reply) => refused(&output, &reply),
            Err((exit, error)) => failed(exit, error),
        },
        Command::Info => match exchange(&socket, OperationAction::ServiceInfo {}).await {
            Ok(reply) if reply.ok => {
                output.reply(&reply, |out| {
                    reply
                        .info
                        .as_ref()
                        .map_or(Ok(()), |info| stats::write_info(out, info))
                });
                Exit::Completed
            }
            Ok(reply) => refused(&output, &reply),
            Err((exit, error)) => failed(exit, error),
        },
        Command::Stats {
            watch,
            interval,
            count,
        } => {
            let mut previous: Option<crate::local::Metrics> = None;
            let mut taken = 0_u64;
            loop {
                match exchange(&socket, OperationAction::Metrics {}).await {
                    Ok(reply) if reply.ok => {
                        let Some(metrics) = reply.metrics.as_deref() else {
                            note("service replied without metrics");
                            return Exit::Failed;
                        };
                        output.reply(&reply, |out| {
                            if watch {
                                writeln!(out, "{}", stats::rate_line(previous.as_ref(), metrics))
                            } else {
                                stats::write_metrics(out, metrics)
                            }
                        });
                        previous = Some(metrics.clone());
                    }
                    Ok(reply) => return refused(&output, &reply),
                    Err((exit, error)) => return failed(exit, error),
                }
                taken += 1;
                if count.is_some_and(|count| taken >= count) {
                    return Exit::Completed;
                }
                tokio::time::sleep(Duration::from_secs(interval)).await;
            }
        }
        // Boxed: inlining this loop enlarges every command's future.
        Command::Test(query) => Box::pin(run_test(&socket, &output, query)).await,
        Command::Meters(query) => meters::boxed(&socket, &output, query).await,
        Command::Status => match exchange(&socket, OperationAction::Status {}).await {
            Ok(reply) if reply.ok => {
                output.reply(&reply, |out| {
                    reply
                        .status
                        .as_ref()
                        .map_or(Ok(()), |status| write_status(out, reply.service, status))
                });
                Exit::Completed
            }
            Ok(reply) => refused(&output, &reply),
            Err((exit, error)) => failed(exit, error),
        },
        Command::Submit {
            action,
            key,
            watch: bound,
        } => {
            // The same shared step the GUI uses: key selection and lost-reply class.
            let (key, reply) = match Box::pin(local::client::submit(&socket, key, |key| {
                action.action(key)
            }))
            .await
            {
                Ok(local::client::Submitted { key, reply }) => (key, reply),
                Err(local::client::SubmitFailure::Unreachable(error)) => {
                    return failed(Exit::Unreachable, error);
                }
                Err(local::client::SubmitFailure::Refused(reply)) => {
                    return refused(&output, &reply);
                }
                Err(local::client::SubmitFailure::NoKey) => {
                    note("service offers no request key (closed)");
                    return Exit::Unreachable;
                }
                Err(local::client::SubmitFailure::OutcomeUnknown { key, error }) => {
                    note(format!("submission failed: {error}"));
                    note(format!(
                        "outcome unknown; retry with --request-key {key} to reattach"
                    ));
                    return Exit::Unknown;
                }
            };
            if !reply.ok {
                return refused(&output, &reply);
            }
            let Some(operation) = reply.operation.as_ref() else {
                note("service accepted without an operation view");
                return Exit::Unknown;
            };
            let id = operation.id;
            output.reply(&reply, |out| {
                writeln!(out, "operation {id} accepted (request key {key})")
            });
            match bound {
                None => Exit::Completed,
                // The service exits after the stop completes: wait until it
                // stops answering instead of watching an operation that ends
                // with the process.
                Some(seconds) if action == Submission::Stop => {
                    let deadline =
                        tokio::time::Instant::now() + std::time::Duration::from_secs(seconds);
                    loop {
                        if exchange(&socket, OperationAction::Status {}).await.is_err() {
                            let _written = writeln!(io::stdout().lock(), "service stopped");
                            break Exit::Completed;
                        }
                        if tokio::time::Instant::now() >= deadline {
                            note(format!(
                                "service still answers; operation {id} may still run"
                            ));
                            break Exit::Running;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    }
                }
                Some(seconds) => {
                    Box::pin(watch(&output, &socket, id, reply.service, seconds)).await
                }
            }
        }
        Command::Show(id, service) => {
            match exchange(
                &socket,
                OperationAction::OperationGet {
                    operation: id,
                    service,
                },
            )
            .await
            {
                Ok(reply) if reply.ok => {
                    output.reply(&reply, |out| {
                        reply
                            .operation
                            .as_ref()
                            .map_or(Ok(()), |state| write_operation(out, state))
                    });
                    Exit::Completed
                }
                Ok(reply) => refused(&output, &reply),
                Err((exit, error)) => failed(exit, error),
            }
        }
        Command::Watch(id, service, seconds) => {
            Box::pin(watch(&output, &socket, id, service, seconds)).await
        }
        Command::Cancel(id, service) => {
            match exchange(
                &socket,
                OperationAction::OperationCancel {
                    operation: id,
                    service,
                },
            )
            .await
            {
                Ok(reply) if reply.ok => {
                    output.reply(&reply, |out| {
                        writeln!(
                            out,
                            "cancellation requested; watch the operation for its actual outcome"
                        )
                    });
                    Exit::Completed
                }
                Ok(reply) if reply.code == "completed" => {
                    output.reply(&reply, |out| {
                        reply
                            .operation
                            .as_ref()
                            .map_or(Ok(()), |state| write_operation(out, state))
                    });
                    Exit::Failed
                }
                Ok(reply) => refused(&output, &reply),
                Err((exit, error)) => failed(exit, error),
            }
        }
        Command::Events {
            mut after,
            limit,
            timeout,
            follow,
            service: expected,
        } => {
            // A supplied identity makes a restarted service refuse the cursor.
            let mut service = expected;
            loop {
                let timeout_ms = if follow {
                    local::WAIT_LIMIT_MS
                } else {
                    u32::try_from(timeout.saturating_mul(1000))
                        .unwrap_or(u32::MAX)
                        .min(local::WAIT_LIMIT_MS)
                };
                let reply = match exchange(
                    &socket,
                    OperationAction::Events {
                        after,
                        limit,
                        timeout_ms,
                        service,
                    },
                )
                .await
                {
                    Ok(reply) if reply.ok => reply,
                    Ok(reply) => return refused(&output, &reply),
                    Err((exit, error)) => return failed(exit, error),
                };
                service = service.or(reply.service);
                output.reply(&reply, |out| {
                    if let Some(batch) = &reply.events {
                        if batch.gap {
                            writeln!(
                                out,
                                "gap: older events were evicted; current status follows"
                            )?;
                            if let Some(status) = &reply.status {
                                write_status(out, reply.service, status)?;
                            }
                        }
                        for event in &batch.events {
                            write_event(out, event)?;
                        }
                    }
                    Ok(())
                });
                if let Some(batch) = &reply.events {
                    after = batch.next;
                }
                if !follow {
                    return Exit::Completed;
                }
            }
        }
        Command::Catalog {
            generation,
            catalog,
            offset,
            limit,
        } => {
            match exchange(
                &socket,
                OperationAction::Catalog {
                    generation,
                    catalog,
                    offset,
                    limit,
                },
            )
            .await
            {
                Ok(reply) if reply.ok => {
                    output.reply(&reply, |out| {
                        let page = reply
                            .observation
                            .as_ref()
                            .and_then(|value| value.common.as_ref())
                            .and_then(|common| common.catalog_page.as_ref());
                        if let Some(page) = page {
                            writeln!(
                                out,
                                "catalog page offset {} of {}, next {}",
                                page.offset,
                                page.total,
                                dash(page.next)
                            )?;
                            for (index, configuration) in page.configurations.iter().enumerate() {
                                writeln!(
                                    out,
                                    "{} {} {}",
                                    usize::from(page.offset) + index,
                                    crate::local::configuration_summary(configuration),
                                    configuration.as_str()
                                )?;
                            }
                        }
                        Ok(())
                    });
                    Exit::Completed
                }
                Ok(reply) => refused(&output, &reply),
                Err((exit, error)) => failed(exit, error),
            }
        }
        Command::Delegate(_) | Command::KeyGenerate(_) => Exit::Usage,
    }
}

/// Run one grouped command.
pub(super) fn main(args: &[String]) -> ExitCode {
    let parsed = match parse(args) {
        Ok(parsed) => parsed,
        Err(Usage(message)) => {
            note(format!("{message}; use --help"));
            return Exit::Usage.into();
        }
    };
    if let Command::Delegate(target) = parsed.command {
        let mut forwarded = vec![target.to_owned()];
        forwarded.extend(args.iter().skip(2).cloned());
        return super::main_entry(forwarded);
    }
    if let Command::KeyGenerate(generation) = &parsed.command {
        return match local::keys::generate(generation) {
            Ok(public) => {
                let _written = if parsed.json {
                    writeln!(
                        io::stdout().lock(),
                        "{}",
                        serde_json::json!({ "public": public })
                    )
                } else {
                    match public {
                        Some(public) => writeln!(io::stdout().lock(), "public key {public}"),
                        None => writeln!(io::stdout().lock(), "wrote 32 random bytes"),
                    }
                };
                Exit::Completed.into()
            }
            Err(error) => {
                note(format!("key generation failed: {error}"));
                Exit::Failed.into()
            }
        };
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();
    match runtime {
        Ok(runtime) => runtime.block_on(run(parsed)).into(),
        Err(error) => {
            note(format!("cannot start the local runtime: {error}"));
            Exit::Unreachable.into()
        }
    }
}

#[path = "cli_groups_host.rs"]
mod host;
#[path = "cli_groups_meters.rs"]
mod meters;
#[path = "cli_groups_profile.rs"]
mod profile;
#[path = "cli_groups_sessions.rs"]
mod sessions;
#[path = "cli_groups_start.rs"]
mod start;
#[path = "cli_groups_stats.rs"]
mod stats;
#[path = "cli_groups_test.rs"]
mod test;
#[path = "cli_groups_tune.rs"]
mod tune;

fn unavailable(exit: Exit, error: io::Error) -> Exit {
    note(format!("service unavailable: {error}"));
    exit
}

/// Start, follow, read or cancel a tunnel test.
async fn run_test(socket: &PathBuf, output: &Output, query: test::Query) -> Exit {
    let (action, follow) = match query {
        test::Query::Start { test, follow } => (OperationAction::TestStart { test }, follow),
        test::Query::Status(id) => (OperationAction::TestGet { id, timeout_ms: 0 }, false),
        test::Query::Cancel(id) => (OperationAction::TestCancel { id }, false),
    };
    let cancelling = matches!(action, OperationAction::TestCancel { .. });
    let mut reply = match exchange(socket, action).await {
        Ok(reply) if reply.ok => reply,
        Ok(reply) => return refused(output, &reply),
        Err((exit, error)) => return unavailable(exit, error),
    };
    loop {
        let Some(state) = reply.test.as_ref().and_then(|test| test.test.clone()) else {
            note("no test has run on this service");
            return Exit::Failed;
        };
        output.reply(&reply, |out| writeln!(out, "{}", test::line(&state)));
        if cancelling {
            return Exit::Completed;
        }
        if !follow || test::finished(&state) {
            return match state.state {
                crate::local::tunnel_test::TestPhase::Completed
                | crate::local::tunnel_test::TestPhase::Running => Exit::Completed,
                _ => Exit::Failed,
            };
        }
        // One line per second while it runs.
        tokio::time::sleep(Duration::from_secs(1)).await;
        reply = match exchange(
            socket,
            OperationAction::TestGet {
                id: Some(state.id),
                timeout_ms: 0,
            },
        )
        .await
        {
            Ok(reply) if reply.ok => reply,
            Ok(reply) => return refused(output, &reply),
            Err((exit, error)) => return unavailable(exit, error),
        };
    }
}

// The tests bind private Unix sockets; Windows pipe behavior is covered in
// docs/modules/windows-local-service.md (cross-compiled, not executed here).
#[cfg(all(test, unix))]
#[path = "cli_groups_tests.rs"]
mod tests;
