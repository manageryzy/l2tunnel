//! `profile` commands of the grouped CLI (stored profiles, DGUI-10).
//! `profile inspect` stays the offline plan inspection.
use super::{Usage, usage};
use crate::local::{
    PROFILE_VERSION, ProfileChange, ProfileCheck, ProfileDocument, ProfileEntry, ProfileSummary,
};
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::PathBuf;

/// Largest importable document (a save request must fit 4096 bytes).
const IMPORT_LIMIT: u64 = 4096;

/// What a profile verb needs besides positionals.
pub(super) fn accepted(verb: &str) -> Option<(&'static [&'static str], &'static [&'static str])> {
    Some(match verb {
        "list" | "show" | "validate" | "keys" => (&[], &[]),
        "export" => (&["--output"], &[]),
        "share" => (&["--tun", "--routes", "--dns"], &["--include-secrets"]),
        "import" => (&["--file", "--uri", "--key-dir", "--revision"], &[]),
        "delete" => (&["--revision"], &[]),
        "default" => (&[], &["--clear"]),
        _ => return None,
    })
}
/// Whether the verb submits a keyed change.
pub(super) fn submits(verb: &str) -> bool {
    matches!(verb, "import" | "delete" | "default")
}

fn name(positional: &[String]) -> Result<String, Usage> {
    match positional {
        [name] => {
            crate::local::validate_profile_name(name).map_err(usage)?;
            Ok(name.clone())
        }
        [] => Err(usage("missing profile name")),
        [_, extra, ..] => Err(usage(format!("unexpected argument {extra}"))),
    }
}
fn revision(options: &BTreeMap<String, String>) -> Result<Option<u64>, Usage> {
    options
        .get("--revision")
        .map(|text| {
            text.parse()
                .map_err(|_| usage("--revision must be a number"))
        })
        .transpose()
}

/// Read a document file for `import`.
fn read_document(path: &str) -> Result<ProfileDocument, Usage> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|error| usage(format!("{path}: {error}")))?;
    let mut text = String::new();
    file.take(IMPORT_LIMIT + 1)
        .read_to_string(&mut text)
        .map_err(|error| usage(format!("{path}: {error}")))?;
    if text.len() as u64 > IMPORT_LIMIT {
        return Err(usage(format!("{path} is larger than {IMPORT_LIMIT} bytes")));
    }
    let document: ProfileDocument =
        serde_json::from_str(&text).map_err(|error| usage(format!("{path}: {error}")))?;
    document.validate().map_err(usage)?;
    Ok(document)
}

/// Read a share URI from `--uri` (use `--uri -` to read from stdin so secrets avoid shell history).
fn read_share_uri_document(
    uri_arg: &str,
    profile_name: &str,
    key_dir: Option<&str>,
) -> Result<ProfileDocument, Usage> {
    use std::io::Read;
    let raw = if uri_arg == "-" {
        let mut buf = String::new();
        io::stdin()
            .take(crate::local::share_uri::MAX_SHARE_URI_BYTES as u64 + 1)
            .read_to_string(&mut buf)
            .map_err(|e| usage(format!("cannot read URI from stdin: {e}")))?;
        buf
    } else {
        uri_arg.to_owned()
    };
    let parsed = crate::local::share_uri::ShareProfile::decode(&raw)
        .map_err(|e| usage(format!("invalid share URI: {e}")))?;
    let default_dir = key_dir.map(PathBuf::from).or_else(|| {
        let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
            .map(PathBuf::from)?;
        Some(
            home.join(".local/share/l2tunnel/shared-keys")
                .join(profile_name),
        )
    });
    parsed
        .to_profile_document(default_dir.as_deref())
        .map_err(|e| usage(format!("cannot materialize shared profile: {e}")))
}

/// Read-only profile command.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum Query {
    List,
    Show(String),
    Validate(String),
    Keys(String),
    Export {
        name: String,
        output: PathBuf,
    },
    Share {
        name: String,
        include_secrets: bool,
        tun: Option<String>,
        routes: Vec<String>,
        dns: Vec<String>,
    },
}

/// Parse a profile verb: a query, or the change it submits.
pub(super) fn parse(
    verb: &str,
    positional: &[String],
    options: &BTreeMap<String, String>,
    flag: impl Fn(&str) -> bool,
) -> Result<Result<Query, ProfileChange>, Usage> {
    Ok(match verb {
        "list" => Ok(Query::List),
        "show" => Ok(Query::Show(name(positional)?)),
        "validate" => Ok(Query::Validate(name(positional)?)),
        "keys" => Ok(Query::Keys(name(positional)?)),
        "export" => Ok(Query::Export {
            name: name(positional)?,
            output: options
                .get("--output")
                .map(PathBuf::from)
                .ok_or_else(|| usage("missing --output FILE"))?,
        }),
        "share" => Ok(Query::Share {
            name: name(positional)?,
            include_secrets: flag("--include-secrets"),
            tun: options.get("--tun").cloned(),
            routes: options
                .get("--routes")
                .map(|s| {
                    s.split(',')
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
            dns: options
                .get("--dns")
                .map(|s| {
                    s.split(',')
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
        }),
        "import" => {
            let profile_name = name(positional)?;
            let document = match (options.get("--file"), options.get("--uri")) {
                (Some(file), None) => read_document(file)?,
                (None, Some(uri)) => read_share_uri_document(
                    uri,
                    &profile_name,
                    options.get("--key-dir").map(String::as_str),
                )?,
                (Some(_), Some(_)) => {
                    return Err(usage("pass either --file FILE or --uri URI, not both"));
                }
                (None, None) => return Err(usage("missing --file FILE or --uri URI")),
            };
            Err(ProfileChange::Save {
                name: profile_name,
                document,
                expected_revision: revision(options)?,
            })
        }
        "delete" => Err(ProfileChange::Delete {
            name: name(positional)?,
            expected_revision: revision(options)?
                .ok_or_else(|| usage("missing --revision N (see profile list)"))?,
        }),
        _ => Err(ProfileChange::Default {
            name: match (flag("--clear"), positional) {
                (true, []) => None,
                (false, _) => Some(name(positional)?),
                (true, _) => return Err(usage("--clear takes no profile name")),
            },
        }),
    })
}

/// Human profile listing.
pub(super) fn write_list(out: &mut dyn Write, profiles: &[ProfileSummary]) -> io::Result<()> {
    writeln!(
        out,
        "{:<20}{:<10}{:<9}{:<9}summary",
        "name", "revision", "role", "default"
    )?;
    for profile in profiles {
        writeln!(
            out,
            "{:<20}{:<10}{:<9}{:<9}{}",
            profile.name,
            profile.revision,
            match profile.role {
                Some(crate::local::ProfileRole::Connect) => "client",
                Some(crate::local::ProfileRole::Serve) => "server",
                None => "-",
            },
            if profile.default { "yes" } else { "" },
            profile.summary
        )?;
    }
    Ok(())
}
/// Human document view: one `--option value` per line.
pub(super) fn write_entry(out: &mut dyn Write, entry: &ProfileEntry) -> io::Result<()> {
    writeln!(
        out,
        "{} revision {} ({} version {})",
        entry.name,
        entry.revision,
        entry.document.role.command(),
        entry.document.version
    )?;
    for (key, value) in &entry.document.options {
        writeln!(out, "  {key} {value}")?;
    }
    Ok(())
}
/// Human check line.
pub(super) fn write_check(out: &mut dyn Write, check: &ProfileCheck) -> io::Result<()> {
    if check.valid {
        writeln!(out, "valid: {}", check.summary)
    } else {
        writeln!(
            out,
            "invalid: {}",
            check.reason.as_deref().unwrap_or("unknown reason")
        )
    }
}

/// Human key reference table.
pub(super) fn write_keys(
    out: &mut dyn Write,
    keys: &[crate::local::keys::KeyReference],
) -> io::Result<()> {
    for key in keys {
        writeln!(
            out,
            "{} {} — {}{}",
            key.option,
            key.path,
            key.role.text(),
            if key.usable { "" } else { " (unusable)" }
        )?;
        if let Some(public) = &key.public {
            writeln!(out, "    public {public}")?;
        }
        if let Some(reason) = &key.reason {
            writeln!(out, "    {reason}")?;
        }
    }
    Ok(())
}

/// Exported document: the importable form.
pub(super) fn export_value(entry: &ProfileEntry) -> io::Result<serde_json::Value> {
    if entry.document.version != PROFILE_VERSION {
        return Err(io::Error::other("unsupported profile version"));
    }
    serde_json::to_value(&entry.document).map_err(io::Error::other)
}
