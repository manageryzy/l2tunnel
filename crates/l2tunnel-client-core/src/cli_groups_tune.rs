//! `l2tunnelctl tune show|set`: live-tuning controls of the connected
//! session (docs/modules/live-tuning.md, decision 10), the same service
//! actions the desktop Connection page uses.
use super::{Exit, Usage, exchange, note, usage};
use crate::local::{OperationAction, TuningSetting, TuningView};
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::PathBuf;

/// Value options of `tune set` besides the submission options.
pub(super) const SET_VALUES: [&str; 3] = ["--repair", "--device-mtu", "--path-mtu"];

/// The controls `tune set` changes; unset ones keep the current value.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct Partial {
    repair: Option<String>,
    device_mtu: Option<u16>,
    path_mtu: Option<u16>,
}

fn size(options: &BTreeMap<String, String>, name: &str) -> Result<Option<u16>, Usage> {
    options
        .get(name)
        .map(|text| {
            text.parse()
                .map_err(|_| usage(format!("{name} must be a size in bytes")))
        })
        .transpose()
}

pub(super) fn partial(options: &BTreeMap<String, String>) -> Result<Partial, Usage> {
    let repair = options
        .get("--repair")
        .map(|text| {
            crate::secure_udp::live_tuning::parse_repair("--repair", text)
                .map(crate::secure_udp::live_tuning::repair_text)
                .map_err(|error| usage(error.to_string()))
        })
        .transpose()?;
    let partial = Partial {
        repair,
        device_mtu: size(options, "--device-mtu")?,
        path_mtu: size(options, "--path-mtu")?,
    };
    if partial == Partial::default() {
        return Err(usage("tune set needs --repair, --device-mtu or --path-mtu"));
    }
    Ok(partial)
}

/// The full setting: the given controls over the session's current one.
pub(super) async fn resolve(socket: &PathBuf, partial: Partial) -> Result<TuningSetting, Exit> {
    let current = match exchange(socket, OperationAction::TuningGet {}).await {
        Ok(reply) if reply.ok => reply.tuning.and_then(|view| view.current),
        Ok(reply) => {
            note(format!("refused: {}", reply.code));
            return Err(super::refusal_exit(&reply.code));
        }
        Err((exit, error)) => {
            note(format!("service unavailable: {error}"));
            return Err(exit);
        }
    };
    let Some(current) = current else {
        note("the session reports no tunable setting");
        return Err(Exit::Failed);
    };
    Ok(TuningSetting {
        repair: partial.repair.unwrap_or(current.repair),
        device_mtu: partial.device_mtu.unwrap_or(current.device_mtu),
        path_mtu: partial.path_mtu.unwrap_or(current.path_mtu),
    })
}

fn setting_text(setting: &TuningSetting) -> String {
    format!(
        "repair {}, device MTU {}, path MTU {}",
        setting.repair, setting.device_mtu, setting.path_mtu
    )
}

/// Human form of `tune show`.
pub(super) fn write_view(out: &mut dyn Write, view: &TuningView) -> io::Result<()> {
    writeln!(
        out,
        "catalog: {}",
        if view.live {
            "generated from this client's live-tuning choices"
        } else {
            "the plan's own entries"
        }
    )?;
    match &view.current {
        Some(current) => writeln!(out, "current: {}", setting_text(current))?,
        None => writeln!(out, "current: -")?,
    }
    writeln!(out, "repair choices: {}", view.repair.join(", "))?;
    let list = |values: &[u16]| {
        values
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    writeln!(out, "device MTU choices: {}", list(&view.device_mtu))?;
    writeln!(out, "path MTU choices: {}", list(&view.path_mtu))?;
    writeln!(out, "reachable settings ({}):", view.entries.len())?;
    for entry in &view.entries {
        let mark = if view.current.as_ref() == Some(entry) {
            "*"
        } else {
            " "
        };
        writeln!(out, " {mark} {}", setting_text(entry))?;
    }
    if let Some(device) = &view.device {
        let value = |mtu: Option<u32>| mtu.map_or_else(|| "-".to_owned(), |mtu| mtu.to_string());
        writeln!(
            out,
            "device MTU: set {}, wanted {}, failures {}{}",
            value(device.applied),
            value(device.wanted),
            device.failures,
            device
                .last_error
                .as_ref()
                .map_or_else(String::new, |error| format!(" (last: {error})"))
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_needs_a_control_and_checks_each_value() {
        let options = |pairs: &[(&str, &str)]| {
            pairs
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect::<BTreeMap<_, _>>()
        };
        assert!(partial(&options(&[])).is_err());
        assert!(partial(&options(&[("--repair", "half")])).is_err());
        assert!(partial(&options(&[("--device-mtu", "big")])).is_err());
        assert_eq!(
            partial(&options(&[("--repair", "OFF"), ("--path-mtu", "1350")])).ok(),
            Some(Partial {
                repair: Some("off".into()),
                device_mtu: None,
                path_mtu: Some(1350),
            })
        );
    }

    #[test]
    fn tune_commands_parse_strictly() {
        let parse = |text: &str| {
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
            parse("tune show --control-socket /s"),
            Ok(super::super::Command::TuneShow)
        );
        assert_eq!(
            parse("tune set --control-socket /s --repair 1/4 --request-key 9 --detach"),
            Ok(super::super::Command::TuneSet {
                partial: Partial {
                    repair: Some("1/4".into()),
                    device_mtu: None,
                    path_mtu: None,
                },
                key: Some(9),
                watch: None,
            })
        );
        assert!(parse("tune set --control-socket /s").is_err());
        assert!(parse("tune set --control-socket /s --repair off --watch 5 --detach").is_err());
        assert!(parse("tune show --control-socket /s --repair off").is_err());
    }

    #[test]
    fn show_marks_the_current_setting() -> io::Result<()> {
        let current = l2tunnel::live_tuning::Setting {
            repair: l2tunnel::live_tuning::Repair::Off,
            device_mtu: 1400,
            path_mtu: 1500,
        };
        let other = l2tunnel::live_tuning::Setting {
            device_mtu: 1280,
            ..current
        };
        let view = TuningView::new(true, Some(current), [current, other], None);
        let mut out = Vec::new();
        write_view(&mut out, &view)?;
        let text = String::from_utf8_lossy(&out);
        assert!(
            text.contains(" * repair off, device MTU 1400, path MTU 1500"),
            "{text}"
        );
        assert!(
            text.contains("   repair off, device MTU 1280, path MTU 1500"),
            "{text}"
        );
        assert!(text.contains("device MTU choices: 1280, 1400"), "{text}");
        Ok(())
    }
}
