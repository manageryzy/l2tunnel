//! `l2tunnelctl socks show|set|flows`: SOCKS5 entry controls over local API v5
//! (`docs/modules/desktop-gui.md`, `DGUI-08`).
use super::{Exit, Output, Usage, exchange, note, refused, unavailable, usage};
use crate::local::{
    OperationAction, SOCKS_MAX_FLOWS_LIMIT, SocksAuthMode, SocksCidr, SocksFlows, SocksSettings,
    SocksStatus,
};
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::PathBuf;

/// Value options accepted by `socks set`.
const SET_VALUES: &[&str] = &[
    "--listen",
    "--auth",
    "--username",
    "--password-file",
    "--allow",
    "--max-flows",
];
/// Boolean flags accepted by `socks set`.
const SET_FLAGS: &[&str] = &["--enable", "--disable"];

/// Accepted `(value_options, flags)` for `socks <verb>`.
pub(super) fn accepted(verb: &str) -> Option<(&'static [&'static str], &'static [&'static str])> {
    match verb {
        "show" | "flows" => Some((&[], &[])),
        "set" => Some((SET_VALUES, SET_FLAGS)),
        _ => None,
    }
}

/// Parsed `l2tunnelctl socks` command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Query {
    Show,
    Flows,
    Set(Partial),
}

/// Partial `socks set` changes merged onto the service's current settings.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct Partial {
    pub(super) enabled: Option<bool>,
    pub(super) listen_host: Option<String>,
    pub(super) listen_port: Option<u16>,
    pub(super) auth_mode: Option<SocksAuthMode>,
    pub(super) username: Option<String>,
    pub(super) password: Option<String>,
    pub(super) allowed_clients: Option<Vec<String>>,
    pub(super) max_flows: Option<u16>,
}

fn parse_listen(text: &str) -> Result<(String, u16), Usage> {
    let (host, port_text) = if let Some(rest) = text.strip_prefix('[') {
        let Some((host, tail)) = rest.split_once("]:") else {
            return Err(usage("--listen IPv6 must be [ADDR]:PORT"));
        };
        (host, tail)
    } else {
        let Some((host, port_text)) = text.rsplit_once(':') else {
            return Err(usage("--listen must be HOST:PORT"));
        };
        (host, port_text)
    };
    let ip: IpAddr = host
        .parse()
        .map_err(|_| usage("--listen host must be a literal IP address"))?;
    let port: u16 = port_text
        .parse()
        .map_err(|_| usage("--listen port must be 1..=65535"))?;
    if port == 0 {
        return Err(usage("--listen port must be 1..=65535"));
    }
    Ok((ip.to_string(), port))
}

pub(super) fn parse(
    verb: &str,
    options: &BTreeMap<String, String>,
    flag: impl Fn(&str) -> bool,
) -> Result<Query, Usage> {
    match verb {
        "show" => Ok(Query::Show),
        "flows" => Ok(Query::Flows),
        "set" => {
            let enable = flag("--enable");
            let disable = flag("--disable");
            if enable && disable {
                return Err(usage("--enable and --disable are exclusive"));
            }
            let (listen_host, listen_port) = match options.get("--listen") {
                Some(text) => {
                    let (host, port) = parse_listen(text)?;
                    (Some(host), Some(port))
                }
                None => (None, None),
            };
            let auth_mode = match options.get("--auth").map(String::as_str) {
                None => None,
                Some("none") => Some(SocksAuthMode::None),
                Some("userpass") => Some(SocksAuthMode::UserPass),
                Some(_) => return Err(usage("--auth must be none or userpass")),
            };
            let username = options.get("--username").cloned();
            let password = match options.get("--password-file") {
                Some(path) => {
                    let text = std::fs::read_to_string(path).map_err(|error| {
                        usage(format!("cannot read --password-file {path}: {error}"))
                    })?;
                    let trimmed = text.trim_end_matches(['\r', '\n']).to_owned();
                    if trimmed.is_empty() {
                        return Err(usage("--password-file is empty"));
                    }
                    Some(trimmed)
                }
                None => None,
            };
            let allowed_clients = match options.get("--allow") {
                Some(text) => {
                    let list: Vec<String> = text
                        .split(',')
                        .map(str::trim)
                        .filter(|entry| !entry.is_empty())
                        .map(str::to_owned)
                        .collect();
                    for entry in &list {
                        SocksCidr::parse(entry).map_err(usage)?;
                    }
                    Some(list)
                }
                None => None,
            };
            let max_flows = match options.get("--max-flows") {
                Some(text) => {
                    let value: u16 = text.parse().map_err(|_| {
                        usage(format!("--max-flows must be 1..={SOCKS_MAX_FLOWS_LIMIT}"))
                    })?;
                    if !(1..=SOCKS_MAX_FLOWS_LIMIT).contains(&value) {
                        return Err(usage(format!(
                            "--max-flows must be 1..={SOCKS_MAX_FLOWS_LIMIT}"
                        )));
                    }
                    Some(value)
                }
                None => None,
            };
            let partial = Partial {
                enabled: enable.then_some(true).or(disable.then_some(false)),
                listen_host,
                listen_port,
                auth_mode,
                username,
                password,
                allowed_clients,
                max_flows,
            };
            if partial == Partial::default() {
                return Err(usage(
                    "socks set needs at least one option (--enable, --disable, --listen, --auth, --allow, --max-flows)",
                ));
            }
            Ok(Query::Set(partial))
        }
        _ => Err(usage(format!("unknown socks command {verb}"))),
    }
}

pub(super) async fn run(socket: &PathBuf, output: &Output, query: Query) -> Exit {
    match query {
        Query::Show => match exchange(socket, OperationAction::SocksGet {}).await {
            Ok(reply) if reply.ok => {
                output.reply(&reply, |out| {
                    reply
                        .socks
                        .as_deref()
                        .map_or(Ok(()), |status| write_status(out, status))
                });
                Exit::Completed
            }
            Ok(reply) => refused(output, &reply),
            Err((exit, error)) => unavailable(exit, error),
        },
        Query::Flows => match exchange(socket, OperationAction::SocksFlows {}).await {
            Ok(reply) if reply.ok => {
                output.reply(&reply, |out| {
                    reply
                        .socks_flows
                        .as_deref()
                        .map_or(Ok(()), |flows| write_flows(out, flows))
                });
                Exit::Completed
            }
            Ok(reply) => refused(output, &reply),
            Err((exit, error)) => unavailable(exit, error),
        },
        Query::Set(partial) => {
            let current = match exchange(socket, OperationAction::SocksGet {}).await {
                Ok(reply) if reply.ok => reply
                    .socks
                    .map(|status| status.settings)
                    .unwrap_or_default(),
                Ok(reply) => return refused(output, &reply),
                Err((exit, error)) => return unavailable(exit, error),
            };
            let settings = SocksSettings {
                enabled: partial.enabled.unwrap_or(current.enabled),
                listen_host: partial.listen_host.unwrap_or(current.listen_host),
                listen_port: partial.listen_port.unwrap_or(current.listen_port),
                auth_mode: partial.auth_mode.unwrap_or(current.auth_mode),
                username: partial.username.or(current.username),
                password: partial.password,
                password_set: current.password_set,
                allowed_clients: partial.allowed_clients.unwrap_or(current.allowed_clients),
                max_flows: partial.max_flows.unwrap_or(current.max_flows),
            };
            if let Err(reason) = settings.validate(current.password_set, false) {
                note(reason);
                return Exit::Usage;
            }
            match exchange(socket, OperationAction::SocksSet { settings }).await {
                Ok(reply) if reply.ok => {
                    output.reply(&reply, |out| {
                        reply
                            .socks
                            .as_deref()
                            .map_or(Ok(()), |status| write_status(out, status))
                    });
                    Exit::Completed
                }
                Ok(reply) => refused(output, &reply),
                Err((exit, error)) => unavailable(exit, error),
            }
        }
    }
}

/// Human-readable rendering of `socks show` / `socks set`.
pub(super) fn write_status(out: &mut dyn Write, status: &SocksStatus) -> io::Result<()> {
    let state = match &status.listening {
        Some(addr) => format!("listening {addr}"),
        None => "stopped".into(),
    };
    writeln!(out, "status           {state}")?;
    writeln!(
        out,
        "tcp-proxy        {}",
        if status.proxy_active {
            "active"
        } else {
            "inactive (needs a connected TCP-proxy profile)"
        }
    )?;
    writeln!(
        out,
        "configured       {}:{} (enabled: {})",
        status.settings.listen_host, status.settings.listen_port, status.settings.enabled
    )?;
    let auth = match status.settings.auth_mode {
        SocksAuthMode::None => "none".to_owned(),
        SocksAuthMode::UserPass => format!(
            "userpass (user {}, password {})",
            status.settings.username.as_deref().unwrap_or("-"),
            if status.settings.password_set {
                "set"
            } else {
                "unset"
            }
        ),
    };
    writeln!(out, "auth             {auth}")?;
    writeln!(
        out,
        "allowed clients  {}",
        if status.settings.allowed_clients.is_empty() {
            "-".to_owned()
        } else {
            status.settings.allowed_clients.join(", ")
        }
    )?;
    writeln!(
        out,
        "flows            {} active / {} max ({} total, {} refused, {} rejected clients)",
        status.active_flows,
        status.settings.max_flows,
        status.total_flows,
        status.failed_connects,
        status.rejected_clients
    )?;
    if let Some(error) = &status.last_error {
        writeln!(out, "last error       {error}")?;
    }
    Ok(())
}

/// Human-readable rendering of `socks flows`.
pub(super) fn write_flows(out: &mut dyn Write, table: &SocksFlows) -> io::Result<()> {
    writeln!(
        out,
        "active flows: {} (showing {})",
        table.total_active,
        table.flows.len()
    )?;
    for flow in &table.flows {
        write!(
            out,
            "  #{:<4} {} -> {}  tx={}B rx={}B  {} ({} ms)",
            flow.id,
            flow.client,
            flow.target,
            flow.sent_bytes,
            flow.received_bytes,
            flow.state,
            flow.age_ms
        )?;
        if let Some(error) = &flow.error {
            write!(out, "  [{error}]")?;
        }
        writeln!(out)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks_commands_parse_strictly() {
        let parse_cli = |text: &str| {
            super::super::parse(
                &text
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect::<Vec<_>>(),
            )
            .map(|parsed| parsed.command)
            .map_err(|super::super::Usage(message)| message)
        };
        assert_eq!(
            parse_cli("socks show --control-socket /s"),
            Ok(super::super::Command::Socks(Query::Show))
        );
        assert_eq!(
            parse_cli("socks flows --control-socket /s"),
            Ok(super::super::Command::Socks(Query::Flows))
        );
        assert_eq!(
            parse_cli(
                "socks set --control-socket /s --enable --listen 127.0.0.1:1081 --allow 127.0.0.1/32,::1/128 --max-flows 64"
            ),
            Ok(super::super::Command::Socks(Query::Set(Partial {
                enabled: Some(true),
                listen_host: Some("127.0.0.1".into()),
                listen_port: Some(1081),
                auth_mode: None,
                username: None,
                password: None,
                allowed_clients: Some(vec!["127.0.0.1/32".into(), "::1/128".into()]),
                max_flows: Some(64),
            })))
        );
        assert!(parse_cli("socks set --control-socket /s").is_err());
        assert!(parse_cli("socks set --control-socket /s --enable --disable").is_err());
        assert!(parse_cli("socks set --control-socket /s --listen bad").is_err());
        assert!(parse_cli("socks set --control-socket /s --allow 127.0.0.1").is_err());
        assert!(parse_cli("socks set --control-socket /s --max-flows 0").is_err());
    }
}
