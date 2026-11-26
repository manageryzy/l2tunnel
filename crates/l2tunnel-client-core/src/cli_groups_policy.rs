//! `policy` and `plan` local CLI command groups:
//! - `l2tunnelctl policy presets|lookup|test|compile` (CIDR / ASN / GeoIP / Continent redirect rules)
//! - `l2tunnelctl plan tune` (generate a Common plan with custom Internal/Device MTU and Capsule/Path MTU,
//!   including Internal MTU > Capsule MTU segmentation configurations).
use super::{Exit, Usage, usage};
use crate::local::redirect_policy::{
    IpGeoAsnDatabase, MmdbReader, RedirectAction, RedirectPolicy, RedirectRule, RuleMatcher,
};
use l2tunnel::live_tuning::{self, Repair, Setting};
use l2tunnel::record_configuration::{DESCRIPTOR_BYTES, Descriptor, Profile};
use l2tunnel_management::Role;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;

/// Value options and flags accepted by `policy` and `plan` subcommands.
pub(super) fn accepted(
    group: &str,
    verb: &str,
) -> Option<(&'static [&'static str], &'static [&'static str])> {
    Some(match (group, verb) {
        ("policy", "presets") => (&[], &[]),
        ("policy", "lookup") => (&["--db", "--mmdb"], &[]),
        ("policy", "test") => (
            &[
                "--preset",
                "--rules",
                "--rule",
                "--default",
                "--db",
                "--mmdb",
            ],
            &[],
        ),
        ("policy", "compile") => (
            &[
                "--preset",
                "--rules",
                "--rule",
                "--default",
                "--peer",
                "--db",
                "--mmdb",
            ],
            &[],
        ),
        ("plan", "tune") => (
            &[
                "--input",
                "--output",
                "--device-mtu",
                "--path-mtu",
                "--repair",
                "--overhead-bytes",
            ],
            &["--force"],
        ),
        _ => return None,
    })
}

/// Parsed local `policy` / `plan` command (runs offline with no daemon required).
#[derive(Debug, Eq, PartialEq)]
pub(super) enum LocalToolCommand {
    PolicyPresets,
    PolicyLookup {
        ip: IpAddr,
        db: Option<String>,
        mmdb: Option<String>,
    },
    PolicyTest {
        ip: IpAddr,
        policy: RedirectPolicy,
        db: Option<String>,
        mmdb: Option<String>,
    },
    PolicyCompile {
        policy: RedirectPolicy,
        peer: Option<IpAddr>,
        db: Option<String>,
        mmdb: Option<String>,
    },
    PlanTune {
        input: String,
        output: String,
        device_mtu: u16,
        path_mtu: u16,
        repair: Option<Repair>,
        overhead_bytes: Option<u16>,
        force: bool,
    },
}

pub(super) fn parse(
    group: &str,
    verb: &str,
    positional: &[String],
    options: &BTreeMap<String, String>,
    flag: impl Fn(&str) -> bool,
) -> Result<LocalToolCommand, Usage> {
    match (group, verb) {
        ("policy", "presets") => {
            if !positional.is_empty() {
                return Err(usage("policy presets takes no positional arguments"));
            }
            Ok(LocalToolCommand::PolicyPresets)
        }
        ("policy", "lookup") => {
            let [raw_ip] = positional else {
                return Err(usage("usage: policy lookup <IP> [--db CSV] [--mmdb FILE]"));
            };
            let ip: IpAddr = raw_ip
                .parse()
                .map_err(|_| usage(format!("invalid IP address {raw_ip:?}")))?;
            Ok(LocalToolCommand::PolicyLookup {
                ip,
                db: options.get("--db").cloned(),
                mmdb: options.get("--mmdb").cloned(),
            })
        }
        ("policy", "test") => {
            let [raw_ip] = positional else {
                return Err(usage(
                    "usage: policy test <IP> [--preset NAME | --rules FILE | --rule MATCH=ACTION,...]",
                ));
            };
            let ip: IpAddr = raw_ip
                .parse()
                .map_err(|_| usage(format!("invalid IP address {raw_ip:?}")))?;
            let policy = load_policy_from_options(options)?;
            Ok(LocalToolCommand::PolicyTest {
                ip,
                policy,
                db: options.get("--db").cloned(),
                mmdb: options.get("--mmdb").cloned(),
            })
        }
        ("policy", "compile") => {
            if !positional.is_empty() {
                return Err(usage("policy compile takes no positional arguments"));
            }
            let policy = load_policy_from_options(options)?;
            let peer = match options.get("--peer") {
                Some(raw) => Some(
                    raw.parse::<IpAddr>()
                        .map_err(|_| usage(format!("invalid --peer IP {raw:?}")))?,
                ),
                None => None,
            };
            Ok(LocalToolCommand::PolicyCompile {
                policy,
                peer,
                db: options.get("--db").cloned(),
                mmdb: options.get("--mmdb").cloned(),
            })
        }
        ("plan", "tune") => {
            if !positional.is_empty() {
                return Err(usage("plan tune takes options only"));
            }
            let input = options
                .get("--input")
                .cloned()
                .ok_or_else(|| usage("plan tune requires --input BASE_PLAN.json"))?;
            let output = options
                .get("--output")
                .cloned()
                .ok_or_else(|| usage("plan tune requires --output OUT_PLAN.json"))?;
            let device_mtu: u16 = options
                .get("--device-mtu")
                .ok_or_else(|| usage("plan tune requires --device-mtu N"))?
                .parse()
                .map_err(|_| usage("--device-mtu must be a u16 MTU (68..=65519)"))?;
            let path_mtu: u16 = options
                .get("--path-mtu")
                .ok_or_else(|| usage("plan tune requires --path-mtu N"))?
                .parse()
                .map_err(|_| usage("--path-mtu must be a u16 MTU (256..=65535)"))?;
            let repair = match options.get("--repair") {
                Some(raw) => Some(
                    crate::secure_udp::live_tuning::parse_repair("--repair", raw)
                        .map_err(|e| usage(e.to_string()))?,
                ),
                None => None,
            };
            let overhead_bytes = match options.get("--overhead-bytes") {
                Some(raw) => Some(
                    raw.parse::<u16>()
                        .map_err(|_| usage("--overhead-bytes must be a u16 byte count"))?,
                ),
                None => None,
            };
            Ok(LocalToolCommand::PlanTune {
                input,
                output,
                device_mtu,
                path_mtu,
                repair,
                overhead_bytes,
                force: flag("--force"),
            })
        }
        _ => Err(usage(format!("unknown {group} command {verb:?}"))),
    }
}

fn load_policy_from_options(options: &BTreeMap<String, String>) -> Result<RedirectPolicy, Usage> {
    let mut policy = if let Some(path) = options.get("--rules") {
        let text = fs::read_to_string(path)
            .map_err(|e| usage(format!("failed to read --rules {path:?}: {e}")))?;
        serde_json::from_str::<RedirectPolicy>(&text)
            .map_err(|e| usage(format!("invalid --rules JSON: {e}")))?
    } else if let Some(preset) = options.get("--preset") {
        RedirectPolicy::preset(preset).ok_or_else(|| {
            usage(format!(
                "unknown preset {preset:?}; run `policy presets` to list available presets"
            ))
        })?
    } else {
        RedirectPolicy::default()
    };

    if let Some(def) = options.get("--default") {
        policy.default_action = parse_action(def)?;
    }

    if let Some(inline) = options.get("--rule") {
        let mut custom = Vec::new();
        for (idx, item) in inline.split(',').enumerate() {
            let trimmed = item.trim();
            if trimmed.is_empty() {
                continue;
            }
            let (m_str, a_str) = trimmed
                .split_once('=')
                .ok_or_else(|| usage(format!("--rule item {trimmed:?} must be MATCH=ACTION")))?;
            let matcher = RuleMatcher::parse_shorthand(m_str).map_err(usage)?;
            let action = parse_action(a_str)?;
            custom.push(RedirectRule {
                id: format!("cli-{}", idx + 1),
                enabled: true,
                matcher,
                action,
                comment: None,
            });
        }
        custom.extend(policy.rules);
        policy.rules = custom;
    }

    policy.validate().map_err(usage)?;
    Ok(policy)
}

fn parse_action(raw: &str) -> Result<RedirectAction, Usage> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "tunnel" | "vpn" | "proxy" => Ok(RedirectAction::Tunnel),
        "direct" | "bypass" => Ok(RedirectAction::Direct),
        "reject" | "drop" | "block" => Ok(RedirectAction::Reject),
        _ => Err(usage(format!(
            "unsupported action {raw:?} (expected tunnel, direct, or reject)"
        ))),
    }
}

fn load_db(csv_path: Option<&str>) -> Result<IpGeoAsnDatabase, String> {
    let mut db = IpGeoAsnDatabase::builtin();
    if let Some(path) = csv_path {
        let text = fs::read_to_string(path).map_err(|e| format!("failed to read {path:?}: {e}"))?;
        db.load_csv_str(&text)?;
    }
    Ok(db)
}

pub(super) fn run(
    command: LocalToolCommand,
    json: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Exit {
    match run_inner(command, json, out) {
        Ok(()) => Exit::Completed,
        Err(msg) => {
            let _ = writeln!(err, "{msg}");
            Exit::Failed
        }
    }
}

fn run_inner(command: LocalToolCommand, json: bool, out: &mut dyn Write) -> Result<(), String> {
    match command {
        LocalToolCommand::PolicyPresets => {
            let presets: Vec<serde_json::Value> = RedirectPolicy::preset_catalog()
                .iter()
                .map(|(name, desc)| serde_json::json!({ "name": name, "description": desc }))
                .collect();
            if json {
                write_json(out, &serde_json::json!({ "ok": true, "presets": presets }))
            } else {
                for (name, desc) in RedirectPolicy::preset_catalog() {
                    writeln!(out, "{name:<26} {desc}").map_err(|e| e.to_string())?;
                }
                Ok(())
            }
        }
        LocalToolCommand::PolicyLookup { ip, db, mmdb } => {
            let geo = if let Some(mmdb_path) = mmdb {
                let bytes = fs::read(&mmdb_path)
                    .map_err(|e| format!("failed to read MMDB {mmdb_path:?}: {e}"))?;
                let reader = MmdbReader::from_bytes(bytes)?;
                reader.lookup(ip)?
            } else {
                load_db(db.as_deref())?.lookup(ip)
            };
            if json {
                write_json(
                    out,
                    &serde_json::json!({ "ok": true, "ip": ip.to_string(), "geo": geo }),
                )
            } else {
                match geo {
                    Some(g) => writeln!(
                        out,
                        "ip={} prefix={} country={} region={} continent={} asn=AS{} org={}",
                        ip,
                        g.matched_prefix,
                        g.country,
                        g.region.as_deref().unwrap_or("-"),
                        g.continent,
                        g.asn,
                        g.org
                    )
                    .map_err(|e| e.to_string()),
                    None => writeln!(out, "ip={ip} no matching GeoIP/ASN record")
                        .map_err(|e| e.to_string()),
                }
            }
        }
        LocalToolCommand::PolicyTest {
            ip,
            policy,
            db,
            mmdb,
        } => {
            let mut decision = if let Some(mmdb_path) = mmdb {
                let bytes = fs::read(&mmdb_path)
                    .map_err(|e| format!("failed to read MMDB {mmdb_path:?}: {e}"))?;
                let reader = MmdbReader::from_bytes(bytes)?;
                let mut temp_db = load_db(db.as_deref())?;
                if let Some(info) = reader.lookup(ip)? {
                    let line = format!(
                        "{},{},{},{},{},{}",
                        info.matched_prefix,
                        info.country,
                        info.region.unwrap_or_default(),
                        info.continent,
                        info.asn,
                        info.org
                    );
                    let _ = temp_db.load_csv_str(&line);
                }
                policy.evaluate(ip, &temp_db)
            } else {
                let database = load_db(db.as_deref())?;
                policy.evaluate(ip, &database)
            };
            if decision.geo.is_none() {
                decision.geo = load_db(db.as_deref())?.lookup(ip);
            }
            if json {
                write_json(
                    out,
                    &serde_json::json!({ "ok": true, "decision": decision }),
                )
            } else {
                writeln!(
                    out,
                    "ip={} action={} rule={} matched_by={}",
                    decision.ip, decision.action, decision.matched_rule_id, decision.matched_by
                )
                .map_err(|e| e.to_string())?;
                if let Some(g) = &decision.geo {
                    writeln!(
                        out,
                        "  geo: prefix={} country={} region={} continent={} asn=AS{} org={}",
                        g.matched_prefix,
                        g.country,
                        g.region.as_deref().unwrap_or("-"),
                        g.continent,
                        g.asn,
                        g.org
                    )
                    .map_err(|e| e.to_string())?;
                }
                Ok(())
            }
        }
        LocalToolCommand::PolicyCompile {
            policy,
            peer,
            db,
            mmdb: _,
        } => {
            let database = load_db(db.as_deref())?;
            let compiled = policy.compile_tun_routes(&database, peer);
            if json {
                write_json(
                    out,
                    &serde_json::json!({ "ok": true, "compiled": compiled }),
                )
            } else {
                writeln!(
                    out,
                    "active_rules={} expanded_prefixes={} include_v4={} exclude_v4={} include_v6={} exclude_v6={} reject={}",
                    compiled.active_rules,
                    compiled.expanded_prefixes,
                    compiled.include_v4.len(),
                    compiled.exclude_v4.len(),
                    compiled.include_v6.len(),
                    compiled.exclude_v6.len(),
                    compiled.reject_cidrs.len()
                )
                .map_err(|e| e.to_string())?;
                for cidr in &compiled.include_v4 {
                    writeln!(out, "  include_v4 {cidr}").map_err(|e| e.to_string())?;
                }
                for cidr in &compiled.exclude_v4 {
                    writeln!(out, "  exclude_v4 {cidr}").map_err(|e| e.to_string())?;
                }
                Ok(())
            }
        }
        LocalToolCommand::PlanTune {
            input,
            output,
            device_mtu,
            path_mtu,
            repair,
            overhead_bytes,
            force,
        } => tune_common_plan_file(
            Path::new(&input),
            Path::new(&output),
            device_mtu,
            path_mtu,
            repair,
            overhead_bytes,
            force,
            json,
            out,
        ),
    }
}

/// Generate a valid `common_records_v2` plan JSON whose initial descriptor uses
/// the requested `device_mtu` (Internal MTU) and `path_mtu` (Capsule/Path MTU),
/// supporting `device_mtu > path_mtu` (Internal MTU larger than Capsule MTU).
#[allow(clippy::too_many_arguments)]
pub fn tune_common_plan_file(
    input: &Path,
    output: &Path,
    device_mtu: u16,
    path_mtu: u16,
    repair: Option<Repair>,
    overhead_bytes: Option<u16>,
    force: bool,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), String> {
    if output.exists() && !force {
        return Err(format!(
            "output file {} already exists (pass --force to overwrite)",
            output.display()
        ));
    }
    let raw = fs::read_to_string(input)
        .map_err(|e| format!("failed to read {}: {e}", input.display()))?;
    let mut doc: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("invalid plan JSON: {e}"))?;
    let initial_idx = doc
        .get("initial_index")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let catalog = doc
        .get("catalog")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "plan JSON missing catalog array".to_owned())?;
    let hex_str = catalog
        .get(initial_idx)
        .and_then(|v| v.as_str())
        .ok_or_else(|| "initial_index out of bounds in catalog".to_owned())?;
    let base_bytes = decode_hex(hex_str)?;
    let base =
        Descriptor::decode(&base_bytes).map_err(|e| format!("invalid base descriptor: {e}"))?;
    let base_setting = live_tuning::setting(&base).map_err(|e| e.to_string())?;
    let target = Setting {
        repair: repair.unwrap_or(base_setting.repair),
        device_mtu,
        path_mtu,
    };
    let mut tuned =
        live_tuning::tune(&base, target).map_err(|e| format!("plan tune failed: {e}"))?;
    if let Some(ovh) = overhead_bytes {
        let datagram = usize::from(path_mtu)
            .checked_sub(usize::from(ovh))
            .ok_or_else(|| "path_mtu smaller than --overhead-bytes".to_owned())?;
        if let Profile::Swift {
            mut forward,
            mut reverse,
        } = *tuned.profile()
        {
            forward.codec.datagram_bytes = datagram;
            reverse.codec.datagram_bytes = datagram;
            tuned = Descriptor::new(
                tuned.path_mtu(),
                tuned.duplex(),
                *tuned.direction(Role::Client).common(),
                *tuned.direction(Role::Server).common(),
                Profile::Swift { forward, reverse },
            )
            .map_err(|e| format!("overhead adjustment failed: {e}"))?;
        }
    }
    let mut tuned_bytes = [0u8; DESCRIPTOR_BYTES];
    tuned
        .encode_into(&mut tuned_bytes)
        .map_err(|e| format!("encode failed: {e}"))?;
    let tuned_hex = encode_hex(&tuned_bytes);

    doc["catalog"] = serde_json::json!([tuned_hex]);
    doc["initial_index"] = serde_json::json!(0);

    // Ensure native.pending_bytes can comfortably hold multiple jumbo packets if device_mtu > 1500.
    if let Some(native) = doc.get_mut("runtime").and_then(|r| r.get_mut("native")) {
        let min_pending = u64::from(device_mtu) * 1024;
        let cur = native
            .get("pending_bytes")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if cur < min_pending {
            native["pending_bytes"] = serde_json::json!(min_pending);
        }
    }

    let formatted = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?;
    fs::write(output, format!("{formatted}\n"))
        .map_err(|e| format!("failed to write {}: {e}", output.display()))?;

    let segmented = device_mtu > path_mtu;
    if json {
        write_json(
            out,
            &serde_json::json!({
                "ok": true,
                "output": output.display().to_string(),
                "device_mtu": device_mtu,
                "path_mtu": path_mtu,
                "internal_gt_capsule": segmented,
                "repair": crate::secure_udp::live_tuning::repair_text(target.repair),
            }),
        )
    } else {
        writeln!(
            out,
            "wrote {} (internal device_mtu={} B, capsule path_mtu={} B, repair={}, internal>capsule={})",
            output.display(),
            device_mtu,
            path_mtu,
            crate::secure_udp::live_tuning::repair_text(target.repair),
            segmented
        )
        .map_err(|e| e.to_string())
    }
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let trimmed = s.trim();
    if !trimmed.len().is_multiple_of(2) {
        return Err("odd hex length in descriptor".to_owned());
    }
    let mut out = Vec::with_capacity(trimmed.len() / 2);
    for pair in trimmed.as_bytes().chunks_exact(2) {
        let hi = hex_nibble(pair[0]).ok_or_else(|| "invalid hex char".to_owned())?;
        let lo = hex_nibble(pair[1]).ok_or_else(|| "invalid hex char".to_owned())?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[usize::from(b >> 4)] as char);
        out.push(DIGITS[usize::from(b & 0x0f)] as char);
    }
    out
}

fn write_json(out: &mut dyn Write, value: &serde_json::Value) -> Result<(), String> {
    let line = serde_json::to_string(value).map_err(|e| e.to_string())?;
    writeln!(out, "{line}").map_err(|e| e.to_string())
}
