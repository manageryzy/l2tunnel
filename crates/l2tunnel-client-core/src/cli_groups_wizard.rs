//! `wizard` local CLI command group:
//! - `l2tunnelctl wizard crawl <DOMAIN[:PORT]> [--json]`
//! - `l2tunnelctl wizard init --carrier quic-like|tls-like|media-like|openvpn-like|tcp|quic
//!       --server IP:PORT --output DIR [--look-like DOMAIN] [--name NAME]
//!       [--noise ik|ikpsk2] [--layer tun|tap] [--device-mtu N] [--path-mtu N]
//!       [--tun-server CIDR] [--tun-client CIDR] [--server-bind IP:PORT]
//!       [--client-bind IP:PORT] [--offline] [--json]`
use super::{Exit, Usage, usage};
use crate::local::wizard::{self, WizardCarrier, WizardRequest};
use std::collections::BTreeMap;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// Value options and flags accepted by `wizard` subcommands.
pub(super) fn accepted(verb: &str) -> Option<(&'static [&'static str], &'static [&'static str])> {
    Some(match verb {
        "crawl" => (&["--timeout"], &[]),
        "init" => (
            &[
                "--carrier",
                "--server",
                "--output",
                "--look-like",
                "--name",
                "--noise",
                "--layer",
                "--device-mtu",
                "--path-mtu",
                "--tun-server",
                "--tun-client",
                "--server-bind",
                "--client-bind",
            ],
            &["--offline"],
        ),
        _ => return None,
    })
}

/// Parsed `wizard` command (runs locally with no daemon required).
#[derive(Debug, Eq, PartialEq)]
pub(super) enum WizardCommand {
    Crawl { target: String, timeout_secs: u64 },
    Init(Box<WizardRequest>),
}

/// Parse `l2tunnelctl wizard ...`.
pub(super) fn parse(
    verb: &str,
    positional: &[String],
    options: &BTreeMap<String, String>,
    flag: impl Fn(&str) -> bool,
) -> Result<WizardCommand, Usage> {
    match verb {
        "crawl" => {
            if positional.len() != 1 {
                return Err(usage(
                    "wizard crawl requires a target domain (e.g. google.com)",
                ));
            }
            let target = positional[0].clone();
            wizard::parse_cover_target(&target).map_err(|e| usage(e.to_string()))?;
            let timeout_secs: u64 = match options.get("--timeout") {
                Some(raw) => raw
                    .parse()
                    .ok()
                    .filter(|&v| (1..=15).contains(&v))
                    .ok_or_else(|| usage("--timeout must be 1..=15 seconds"))?,
                None => 5,
            };
            Ok(WizardCommand::Crawl {
                target,
                timeout_secs,
            })
        }
        "init" => {
            if !positional.is_empty() {
                return Err(usage(format!(
                    "unexpected positional argument {}",
                    positional[0]
                )));
            }
            let carrier_str = options
                .get("--carrier")
                .map(String::as_str)
                .unwrap_or("quic-like");
            let carrier = WizardCarrier::parse(carrier_str).map_err(|e| usage(e.to_string()))?;
            let server_raw = options
                .get("--server")
                .ok_or_else(|| usage("wizard init requires --server IP:PORT"))?;
            let server_endpoint: SocketAddr = server_raw
                .parse()
                .map_err(|_| usage("invalid --server (expected IP:PORT)"))?;
            let output_dir = PathBuf::from(
                options
                    .get("--output")
                    .ok_or_else(|| usage("wizard init requires --output DIR"))?,
            );
            let look_like = options
                .get("--look-like")
                .cloned()
                .filter(|s| !s.trim().is_empty());
            if let Some(domain) = &look_like {
                wizard::parse_cover_target(domain).map_err(|e| usage(e.to_string()))?;
            }
            let default_name = look_like
                .as_deref()
                .and_then(|d| wizard::parse_cover_target(d).ok())
                .map(|(dom, _)| {
                    let clean: String = dom
                        .split('.')
                        .next()
                        .unwrap_or("tunnel")
                        .chars()
                        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
                        .collect();
                    format!(
                        "{}-{}",
                        if clean.is_empty() { "l2t" } else { &clean },
                        carrier.as_str()
                    )
                })
                .unwrap_or_else(|| format!("l2t-{}", carrier.as_str()));
            let name = options.get("--name").cloned().unwrap_or(default_name);
            let mut req =
                WizardRequest::simple(name, carrier, server_endpoint, look_like, output_dir);
            req.crawl = !flag("--offline");
            if let Some(noise) = options.get("--noise") {
                req.noise = noise.clone();
            }
            if let Some(layer) = options.get("--layer") {
                req.layer = layer.clone();
            }
            if let Some(v) = options.get("--device-mtu") {
                req.device_mtu = v.parse().map_err(|_| usage("invalid --device-mtu"))?;
            }
            if let Some(v) = options.get("--path-mtu") {
                req.path_mtu = v.parse().map_err(|_| usage("invalid --path-mtu"))?;
            }
            if let Some(v) = options.get("--tun-server") {
                req.tun_server_cidr = v.clone();
            }
            if let Some(v) = options.get("--tun-client") {
                req.tun_client_cidr = v.clone();
            }
            if let Some(v) = options.get("--server-bind") {
                req.server_bind = Some(
                    v.parse()
                        .map_err(|_| usage("invalid --server-bind (expected IP:PORT)"))?,
                );
            }
            if let Some(v) = options.get("--client-bind") {
                req.client_bind = Some(
                    v.parse()
                        .map_err(|_| usage("invalid --client-bind (expected IP:PORT)"))?,
                );
            }
            Ok(WizardCommand::Init(Box::new(req)))
        }
        _ => Err(usage(format!("unknown wizard verb {verb}"))),
    }
}

/// Execute a parsed `wizard` command and write human-readable or `--json` output.
pub(super) fn run(
    command: WizardCommand,
    json: bool,
    out: &mut impl Write,
    err: &mut impl Write,
) -> Exit {
    match command {
        WizardCommand::Crawl {
            target,
            timeout_secs,
        } => {
            match wizard::crawl_cover_domain_blocking(&target, Duration::from_secs(timeout_secs)) {
                Ok(report) => {
                    let res = if json {
                        serde_json::to_writer_pretty(&mut *out, &report)
                            .and_then(|()| writeln!(out).map_err(serde_json::Error::io))
                            .map_err(std::io::Error::other)
                    } else {
                        writeln!(
                            out,
                            "Cover domain:      {}:{} ({})\nTLS version:       {}\nALPN:              {}\nCipher suite:      {}\nUDP QUIC probe:    {}\nObserved leaf:     {} bytes (SHA-256: {})\nRecommended SNI:   {}\nRecommended cover: {}",
                            report.domain,
                            report.port,
                            report.resolved_addr,
                            report.tls_version,
                            report.alpn.as_deref().unwrap_or("none"),
                            report.cipher_suite,
                            if report.udp_quic_observed {
                                "responded (QUIC active)"
                            } else {
                                "no reply"
                            },
                            report.observed_leaf_bytes,
                            report.observed_leaf_sha256.as_deref().unwrap_or("none"),
                            report.recommended_sni,
                            report.recommended_cover,
                        )
                    };
                    if res.is_ok() {
                        Exit::Completed
                    } else {
                        Exit::Failed
                    }
                }
                Err(error) => {
                    let _ = writeln!(err, "wizard crawl failed: {error}");
                    Exit::Failed
                }
            }
        }
        WizardCommand::Init(req) => match wizard::generate_pair(&req) {
            Ok(result) => {
                let res = if json {
                    serde_json::to_writer_pretty(&mut *out, &result)
                        .and_then(|()| writeln!(out).map_err(serde_json::Error::io))
                        .map_err(std::io::Error::other)
                } else {
                    let mut text = String::new();
                    use std::fmt::Write as _;
                    let _ = writeln!(text, "Profile:       {}", result.name);
                    let _ = writeln!(
                        text,
                        "Carrier:       {} (cover: {})",
                        result.carrier, result.cover
                    );
                    if let Some(sni) = &result.sni {
                        let _ = writeln!(text, "Cover SNI:     {sni}");
                    }
                    if let Some(sn) = &result.server_name {
                        let _ = writeln!(text, "Server Name:   {sn} (own-server trust)");
                    }
                    if let Some(pin) = &result.server_pin {
                        let _ = writeln!(text, "Server Pin:    {pin}");
                    }
                    if let Some(crawl) = &result.crawl {
                        let _ = writeln!(
                            text,
                            "Crawled:       {}:{} -> {} ALPN={} QUIC={}",
                            crawl.domain,
                            crawl.port,
                            crawl.tls_version,
                            crawl.alpn.as_deref().unwrap_or("none"),
                            crawl.udp_quic_observed
                        );
                    } else if let Some(note) = &result.crawl_note {
                        let _ = writeln!(text, "Crawl note:    {note}");
                    }
                    let _ = writeln!(text, "\nServer bundle: {}", result.server_dir.display());
                    let _ = writeln!(
                        text,
                        "Server profile: {}",
                        result.server_profile_path.display()
                    );
                    let _ = writeln!(text, "Server command:\n  {}", result.server_command);
                    let _ = writeln!(text, "\nClient bundle: {}", result.client_dir.display());
                    let _ = writeln!(
                        text,
                        "Client Share URI (paste in GUI / Android / l2tunnelctl):\n  {}",
                        result.share_uri
                    );
                    out.write_all(text.as_bytes())
                };
                if res.is_ok() {
                    Exit::Completed
                } else {
                    Exit::Failed
                }
            }
            Err(error) => {
                let _ = writeln!(err, "wizard init failed: {error}");
                Exit::Failed
            }
        },
    }
}
