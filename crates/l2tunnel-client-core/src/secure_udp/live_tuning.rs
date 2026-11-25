//! Live protocol tuning at connect (docs/modules/live-tuning.md): the
//! client's proposal, the server's judgment and the run options that set
//! them. Both ends generate the same catalog with `l2tunnel::live_tuning`.

use super::common_transaction_profile::Profile;
use l2tunnel::live_tuning::{self as tuning, Choices, Limits, Refusal, Repair};
use l2tunnel::record_configuration::Catalog;
use l2tunnel_security::Role;
use std::collections::BTreeMap;
use std::io;

/// Live-tuning policy of one profile: the client's switchable choices, and
/// the server's limits on what it accepts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Policy {
    /// Client: the choices proposed at connect; `None` proposes nothing.
    pub choices: Option<Choices>,
    /// Server: what a proposal may contain (decision 5).
    pub limits: Limits,
    /// Server: largest record-engine heap a switch target may reserve; `None`
    /// uses the plan's retained-memory budget.
    pub memory_cap: Option<usize>,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            choices: None,
            limits: Limits::PROTOCOL,
            memory_cap: None,
        }
    }
}

/// Run options a client profile may set.
pub const CLIENT_OPTIONS: [&str; 3] = ["--tune-repair", "--tune-device-mtu", "--tune-path-mtu"];
/// Run options a server profile may set.
pub const SERVER_OPTIONS: [&str; 5] = [
    "--tune-max-repair",
    "--tune-device-mtu-range",
    "--tune-path-mtu-range",
    "--tune-max-entries",
    "--tune-memory-cap",
];

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn parse_rate(option: &str, text: &str) -> io::Result<(u32, u32)> {
    let parsed = text
        .split_once('/')
        .and_then(|(n, d)| Some((n.trim().parse().ok()?, d.trim().parse().ok()?)));
    match parsed {
        Some((numerator, denominator)) if denominator != 0 => Ok((numerator, denominator)),
        _ => Err(invalid(format!(
            "{option}: {text:?} is not a rate like 1/4"
        ))),
    }
}

/// A repair choice as text: `off` or a rate like `1/4`.
pub fn repair_text(repair: Repair) -> String {
    match repair {
        Repair::Off => "off".to_owned(),
        Repair::Rate {
            numerator,
            denominator,
        } => format!("{numerator}/{denominator}"),
    }
}

/// Parse a repair choice written as [`repair_text`] does.
pub fn parse_repair(option: &str, text: &str) -> io::Result<Repair> {
    if text.trim().eq_ignore_ascii_case("off") {
        return Ok(Repair::Off);
    }
    let (numerator, denominator) = parse_rate(option, text)?;
    Ok(Repair::Rate {
        numerator,
        denominator,
    })
}

fn parse_mtu(option: &str, text: &str) -> io::Result<u16> {
    text.trim()
        .parse()
        .map_err(|_| invalid(format!("{option}: {text:?} is not a size in bytes")))
}

fn parse_list<T>(
    option: &str,
    text: &str,
    one: impl Fn(&str, &str) -> io::Result<T>,
) -> io::Result<Vec<T>> {
    text.split(',').map(|item| one(option, item)).collect()
}

fn parse_range(option: &str, text: &str) -> io::Result<(u16, u16)> {
    let (low, high) = text
        .split_once('-')
        .ok_or_else(|| invalid(format!("{option}: {text:?} is not a range like 1280-1500")))?;
    let range = (parse_mtu(option, low)?, parse_mtu(option, high)?);
    if range.0 > range.1 {
        return Err(invalid(format!("{option}: {text:?} is an empty range")));
    }
    Ok(range)
}

/// Read the live-tuning run options of `command` (`connect` or `serve`).
/// The other role's options are refused, so a profile cannot silently carry
/// settings that do nothing.
pub fn policy(command: &str, options: &BTreeMap<String, String>) -> io::Result<Policy> {
    let (own, other): (&[&str], &[&str]) = if command == "connect" {
        (&CLIENT_OPTIONS, &SERVER_OPTIONS)
    } else {
        (&SERVER_OPTIONS, &CLIENT_OPTIONS)
    };
    if let Some(option) = other.iter().find(|option| options.contains_key(**option)) {
        return Err(invalid(format!("{option} does not apply to {command}")));
    }
    let mut policy = Policy::default();
    if own.iter().any(|option| options.contains_key(*option)) && command == "connect" {
        let get = |option: &str| options.get(option).map(String::as_str);
        let choices = Choices {
            repair: get("--tune-repair")
                .map(|text| parse_list("--tune-repair", text, parse_repair))
                .transpose()?
                .unwrap_or_default(),
            device_mtu: get("--tune-device-mtu")
                .map(|text| parse_list("--tune-device-mtu", text, parse_mtu))
                .transpose()?
                .unwrap_or_default(),
            path_mtu: get("--tune-path-mtu")
                .map(|text| parse_list("--tune-path-mtu", text, parse_mtu))
                .transpose()?
                .unwrap_or_default(),
        };
        choices
            .check(&Limits::PROTOCOL)
            .map_err(|error| invalid(format!("live-tuning choices: {error}")))?;
        policy.choices = Some(choices);
    }
    if command != "connect" {
        if let Some(text) = options.get("--tune-max-repair") {
            policy.limits.max_repair = parse_rate("--tune-max-repair", text)?;
        }
        if let Some(text) = options.get("--tune-device-mtu-range") {
            policy.limits.device_mtu = parse_range("--tune-device-mtu-range", text)?;
        }
        if let Some(text) = options.get("--tune-path-mtu-range") {
            policy.limits.path_mtu = parse_range("--tune-path-mtu-range", text)?;
        }
        if let Some(text) = options.get("--tune-max-entries") {
            policy.limits.max_entries = text
                .parse()
                .ok()
                .filter(|count| (1..=tuning::MAX_ENTRIES).contains(count))
                .ok_or_else(|| {
                    invalid(format!(
                        "--tune-max-entries: {text:?} is not 1..={}",
                        tuning::MAX_ENTRIES
                    ))
                })?;
        }
        if let Some(text) = options.get("--tune-memory-cap") {
            policy.memory_cap = Some(text.parse().map_err(|_| {
                invalid(format!("--tune-memory-cap: {text:?} is not a byte count"))
            })?);
        }
    }
    Ok(policy)
}

/// What the client sends and binds at connect.
pub(crate) struct Proposal {
    /// Encoded choices, carried in handshake message 1.
    pub bytes: Vec<u8>,
    /// The catalog both ends will generate.
    pub catalog: Catalog,
    /// Its root, bound into both key confirmations.
    pub root: [u8; 32],
}

/// The client's proposal, when its profile has choices. Fails before any
/// I/O when the plan cannot be tuned with them, with the exact reason.
pub(crate) fn proposal(profile: &Profile) -> io::Result<Option<Proposal>> {
    let Some(choices) = &profile.tuning().choices else {
        return Ok(None);
    };
    let catalog = tuning::extend(profile.plan_catalog(), choices, &Limits::PROTOCOL)
        .map_err(|error| invalid(format!("live tuning: {error}")))?;
    let bytes = choices
        .encode()
        .map_err(|error| invalid(format!("live tuning: {error}")))?;
    let root = *catalog.root().as_bytes();
    Ok(Some(Proposal {
        bytes,
        catalog,
        root,
    }))
}

/// The server's judgment of a carried proposal: the generated catalog and
/// its root, or the exact refusal. The runtime contract is built for the
/// generated catalog, so every entry is checked as the runtime will use it.
pub(crate) fn judge(
    profile: &Profile,
    role: Role,
    proposal: &[u8],
) -> Result<(Catalog, [u8; 32]), Refusal> {
    let policy = profile.tuning();
    let choices = Choices::decode(proposal).map_err(|error| Refusal::from(&error))?;
    let catalog = tuning::extend(profile.plan_catalog(), &choices, &policy.limits)
        .map_err(|error| Refusal::from(&error))?;
    let contract = profile
        .with_live_catalog(catalog.clone())
        .and_then(|tuned| tuned.runtime_contract(role))
        .map_err(|_| Refusal::Configuration)?;
    let cap = policy
        .memory_cap
        .unwrap_or(profile.parameters().retained_bytes);
    if contract
        .largest_entry_bytes()
        .map_or(true, |bytes| bytes > cap)
    {
        return Err(Refusal::Memory);
    }
    let root = *catalog.root().as_bytes();
    Ok((catalog, root))
}

#[cfg(test)]
#[path = "live_tuning_tests.rs"]
mod tests;
