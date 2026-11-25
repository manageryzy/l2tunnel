//! `l2tunnelctl carrier show|switch`: live in-session carrier / UDP cover
//! switching over local API v5 (`docs/modules/desktop-gui.md`, `DGUI-14`).
use super::{Exit, Output, Usage, exchange, refused, unavailable, usage};
use crate::local::{CarrierSwitchView, OperationAction};
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::PathBuf;

/// Value options accepted by `carrier switch`.
const SWITCH_VALUES: &[&str] = &["--target"];

/// Accepted `(value_options, flags)` for `carrier <verb>`.
pub(super) fn accepted(verb: &str) -> Option<(&'static [&'static str], &'static [&'static str])> {
    match verb {
        "show" => Some((&[], &[])),
        "switch" => Some((SWITCH_VALUES, &[])),
        _ => None,
    }
}

/// Parsed `l2tunnelctl carrier` command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Query {
    Show,
    Switch { target: String },
}

pub(super) fn parse(verb: &str, options: &BTreeMap<String, String>) -> Result<Query, Usage> {
    match verb {
        "show" => Ok(Query::Show),
        "switch" => {
            let target = options
                .get("--target")
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    usage("carrier switch needs --target quic-like|media-like|tls-like")
                })?;
            Ok(Query::Switch { target })
        }
        _ => Err(usage(format!("unknown carrier command {verb}"))),
    }
}

pub(super) async fn run(socket: &PathBuf, output: &Output, query: Query) -> Exit {
    let action = match query {
        Query::Show => OperationAction::CarrierSwitchGet {},
        Query::Switch { target } => OperationAction::CarrierSwitch { target },
    };
    match exchange(socket, action).await {
        Ok(reply) if reply.ok => {
            output.reply(&reply, |out| {
                reply
                    .carrier_switch
                    .as_deref()
                    .map_or(Ok(()), |view| write_view(out, view))
            });
            Exit::Completed
        }
        Ok(reply) => refused(output, &reply),
        Err((exit, error)) => unavailable(exit, error),
    }
}

/// Human-readable rendering of `carrier show` / `carrier switch`.
pub(super) fn write_view(out: &mut dyn Write, view: &CarrierSwitchView) -> io::Result<()> {
    writeln!(
        out,
        "carrier          {}{}",
        view.current_carrier,
        view.current_cover
            .as_ref()
            .map_or_else(String::new, |cover| format!(" / {cover}"))
    )?;
    writeln!(out, "endpoints        {} -> {}", view.local, view.peer)?;
    writeln!(out, "live switches    {}", view.switches)?;
    writeln!(out, "targets ({}):", view.choices.len())?;
    for choice in &view.choices {
        let current = view.current_cover.as_deref() == Some(choice.id.as_str())
            || view.current_carrier == choice.id;
        let mark = if current { "*" } else { " " };
        if choice.available {
            writeln!(out, " {mark} {:<12} {} (live)", choice.id, choice.label)?;
        } else {
            let reason = choice.reason.as_deref().unwrap_or("unavailable");
            writeln!(out, " {mark} {:<12} {} [{reason}]", choice.id, choice.label)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carrier_commands_parse_strictly() {
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
            parse_cli("carrier show --control-socket /s"),
            Ok(super::super::Command::Carrier(Query::Show))
        );
        assert_eq!(
            parse_cli("carrier switch --control-socket /s --target media-like"),
            Ok(super::super::Command::Carrier(Query::Switch {
                target: "media-like".into(),
            }))
        );
        assert!(parse_cli("carrier switch --control-socket /s").is_err());
        assert!(parse_cli("carrier bogus --control-socket /s").is_err());
    }
}
