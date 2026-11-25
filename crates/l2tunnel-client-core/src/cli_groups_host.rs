//! `device` and `route` commands of the grouped CLI (service-owned devices
//! and session routes; docs/modules/desktop-gui.md DGUI-06/07).
use super::{Usage, usage};
use crate::local::{DeviceChange, DeviceLayer, DeviceState, RouteChange, RouteState};
use std::collections::BTreeMap;
use std::io::{self, Write};

/// Value options and flags a device/route verb accepts (besides the shared ones).
pub(super) fn accepted(
    group: &str,
    verb: &str,
) -> Option<(&'static [&'static str], &'static [&'static str])> {
    Some(match (group, verb) {
        ("device" | "route", "list") => (&[], &[]),
        ("device", "create") => (&["--layer", "--mtu", "--addresses"], &["--down"]),
        ("device", "configure") => (&["--mtu", "--add", "--remove"], &["--up", "--down"]),
        ("device", "delete") => (&[], &[]),
        ("route", "add") => (&["--device", "--gateway", "--metric"], &[]),
        ("route", "remove" | "default") => (&["--device"], &[]),
        _ => return None,
    })
}

fn list(options: &BTreeMap<String, String>, key: &str) -> Vec<String> {
    options
        .get(key)
        .map(|text| {
            text.split(',')
                .filter(|item| !item.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}
fn number(options: &BTreeMap<String, String>, key: &str) -> Result<Option<u32>, Usage> {
    options
        .get(key)
        .map(|text| {
            text.parse()
                .map_err(|_| usage(format!("{key} must be a number")))
        })
        .transpose()
}
fn single<'a>(positional: &'a [String], what: &str) -> Result<&'a str, Usage> {
    match positional {
        [value] => Ok(value),
        [] => Err(usage(format!("missing {what}"))),
        [_, extra, ..] => Err(usage(format!("unexpected argument {extra}"))),
    }
}
fn required<'a>(options: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, Usage> {
    options
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| usage(format!("missing {key}")))
}

/// The change a submitting device verb requests.
pub(super) fn device_change(
    verb: &str,
    positional: &[String],
    options: &BTreeMap<String, String>,
    flag: impl Fn(&str) -> bool,
) -> Result<DeviceChange, Usage> {
    let name = single(positional, "device name")?.to_owned();
    let change = match verb {
        "create" => DeviceChange::Create {
            name,
            layer: match required(options, "--layer")? {
                "tun" => DeviceLayer::Tun,
                "tap" => DeviceLayer::Tap,
                _ => return Err(usage("--layer must be tun or tap")),
            },
            mtu: number(options, "--mtu")?,
            addresses: list(options, "--addresses"),
            up: !flag("--down"),
        },
        "configure" => {
            if flag("--up") && flag("--down") {
                return Err(usage("--up and --down are exclusive"));
            }
            DeviceChange::Configure {
                name,
                mtu: number(options, "--mtu")?,
                add: list(options, "--add"),
                remove: list(options, "--remove"),
                up: if flag("--up") {
                    Some(true)
                } else if flag("--down") {
                    Some(false)
                } else {
                    None
                },
            }
        }
        _ => DeviceChange::Delete { name },
    };
    change.validate().map_err(usage)?;
    Ok(change)
}

/// The change a submitting route verb requests.
pub(super) fn route_change(
    verb: &str,
    positional: &[String],
    options: &BTreeMap<String, String>,
) -> Result<RouteChange, Usage> {
    let device = required(options, "--device")?.to_owned();
    let change = match verb {
        "add" => RouteChange::Add {
            destination: single(positional, "destination")?.to_owned(),
            device,
            gateway: options.get("--gateway").cloned(),
            metric: number(options, "--metric")?,
        },
        "remove" => RouteChange::Remove {
            destination: single(positional, "destination")?.to_owned(),
            device,
        },
        _ => RouteChange::Default {
            enabled: match single(positional, "on or off")? {
                "on" => true,
                "off" => false,
                _ => return Err(usage("route default takes on or off")),
            },
            device,
        },
    };
    change.validate().map_err(usage)?;
    Ok(change)
}

/// Human device listing.
pub(super) fn write_devices(out: &mut dyn Write, devices: &[DeviceState]) -> io::Result<()> {
    writeln!(
        out,
        "{:<16}{:<6}{:<7}{:<6}{:<12}addresses",
        "name", "layer", "mtu", "up", "owner"
    )?;
    for device in devices {
        writeln!(
            out,
            "{:<16}{:<6}{:<7}{:<6}{:<12}{}",
            device.name,
            match device.layer {
                Some(DeviceLayer::Tun) => "tun",
                Some(DeviceLayer::Tap) => "tap",
                None => "-",
            },
            device.mtu.map_or("-".into(), |mtu| mtu.to_string()),
            if device.up { "yes" } else { "no" },
            if device.owned {
                "service"
            } else {
                "preexisting"
            },
            if device.addresses.is_empty() {
                "-".to_owned()
            } else {
                device.addresses.join(",")
            }
        )?;
    }
    Ok(())
}

/// Human route listing.
pub(super) fn write_routes(out: &mut dyn Write, routes: &[RouteState]) -> io::Result<()> {
    writeln!(
        out,
        "{:<24}{:<18}{:<12}{:<8}owner",
        "destination", "gateway", "device", "metric"
    )?;
    for route in routes {
        writeln!(
            out,
            "{:<24}{:<18}{:<12}{:<8}{}",
            route.destination,
            route.gateway.as_deref().unwrap_or("-"),
            route.device.as_deref().unwrap_or("-"),
            route.metric.map_or("-".into(), |metric| metric.to_string()),
            match (&route.owned, &route.purpose) {
                (true, Some(purpose)) => format!("service ({purpose})"),
                (true, None) => "service".into(),
                (false, _) => "preexisting".into(),
            }
        )?;
    }
    Ok(())
}
