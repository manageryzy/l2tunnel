//! Stored profiles (CL-12, CL-24; owner decision 2026-11-23): a profile is a
//! named, versioned set of the same `connect`/`serve` options the service
//! already validates. The service owns the store; credentials stay files that
//! options reference, so a profile never contains private key material.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Profile document version this service writes and edits.
pub const PROFILE_VERSION: u16 = 1;
/// Longest profile name.
pub const PROFILE_NAME_LIMIT: usize = 64;
/// Most options in one profile.
pub const PROFILE_OPTION_LIMIT: usize = 48;
/// Longest option value (a path, address or small policy value).
pub const PROFILE_VALUE_LIMIT: usize = 512;
/// Most stored profiles.
pub const PROFILE_LIMIT: usize = 64;
/// Longest summary or refusal text.
pub const PROFILE_TEXT_LIMIT: usize = 240;
/// Options that belong to the service process, never to a profile.
pub const SERVICE_OPTIONS: &[&str] = &[
    "--control-socket",
    "--state-dir",
    "--runtime-model",
    "--api-version",
];

/// What the profile runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileRole {
    /// Client: `connect` options.
    Connect,
    /// Server: `serve` options.
    Serve,
}
impl ProfileRole {
    /// The run command this role uses.
    pub fn command(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Serve => "serve",
        }
    }
}

/// One stored profile document.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileDocument {
    /// Document version; only [`PROFILE_VERSION`] is edited.
    pub version: u16,
    /// Client or server.
    pub role: ProfileRole,
    /// Run options without the leading command, e.g. `--carrier` → `quic-like`.
    pub options: BTreeMap<String, String>,
}
impl ProfileDocument {
    /// Structural checks shared by every frontend and the store. Whether the
    /// options form a runnable plan is checked by the service (`profile_validate`).
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version != PROFILE_VERSION {
            return Err("unsupported profile version");
        }
        if self.options.len() > PROFILE_OPTION_LIMIT {
            return Err("too many options");
        }
        for (key, value) in &self.options {
            let name = key.strip_prefix("--").unwrap_or_default();
            if name.is_empty()
                || name.len() > 40
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            {
                return Err("option names look like --name");
            }
            if SERVICE_OPTIONS.contains(&key.as_str()) {
                return Err(
                    "service options (--control-socket, --state-dir, --runtime-model) are not profile options",
                );
            }
            if value.is_empty()
                || value.len() > PROFILE_VALUE_LIMIT
                || value.chars().any(char::is_control)
            {
                return Err("option values must be 1..512 printable characters");
            }
        }
        Ok(())
    }
}

/// Check a profile name: 1..64 of `A-Z a-z 0-9 . _ -`, not starting with `.`.
pub fn validate_profile_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty()
        || name.len() > PROFILE_NAME_LIMIT
        || name.starts_with('.')
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        Err("profile names are 1..64 of A-Z a-z 0-9 . _ - and do not start with .")
    } else {
        Ok(())
    }
}

/// One row of `profile_list`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSummary {
    /// Name.
    pub name: String,
    /// Store revision; changes need it.
    pub revision: u64,
    /// Stored document version.
    pub version: u16,
    /// Role, when the version is understood.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<ProfileRole>,
    /// Short description, e.g. `quic-like · device l2t0 · 203.0.113.7:443`.
    pub summary: String,
    /// Tunnel device the profile names (`--device`), when understood.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// Connected on service start.
    pub default: bool,
    /// False for a newer document version this service does not rewrite.
    pub editable: bool,
}

/// `profile_get` result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileEntry {
    /// Name.
    pub name: String,
    /// Store revision.
    pub revision: u64,
    /// The document.
    pub document: ProfileDocument,
}

/// `profile_validate` result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileCheck {
    /// The service could build a runnable plan (credentials, trust and the
    /// transaction plan were read and accepted; nothing was opened).
    pub valid: bool,
    /// Role and carrier when valid.
    pub summary: String,
    /// Why not, when invalid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A keyed store change.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProfileChange {
    /// Create (no expected revision) or replace (exact expected revision).
    /// The service refuses documents it cannot turn into a runnable plan.
    Save {
        /// Name.
        name: String,
        /// Complete document.
        document: ProfileDocument,
        /// Current revision when replacing.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expected_revision: Option<u64>,
    },
    /// Delete at the exact revision.
    Delete {
        /// Name.
        name: String,
        /// Current revision.
        expected_revision: u64,
    },
    /// Choose the profile connected on service start, or none.
    Default {
        /// Name, or none to clear.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },
}
impl ProfileChange {
    /// Name this change concerns.
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Save { name, .. } | Self::Delete { name, .. } => Some(name),
            Self::Default { name } => name.as_deref(),
        }
    }
    /// Structural checks before a key is consumed.
    pub fn validate(&self) -> Result<(), &'static str> {
        if let Some(name) = self.name() {
            validate_profile_name(name)?;
        }
        if let Self::Save { document, .. } = self {
            document.validate()?;
        }
        Ok(())
    }
}

/// Bound a text for a summary or refusal reason at a character boundary.
pub fn bounded_text(text: &str) -> String {
    if text.len() <= PROFILE_TEXT_LIMIT {
        return text.to_owned();
    }
    let mut end = PROFILE_TEXT_LIMIT;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

/// Short description from well-known options.
pub fn describe(document: &ProfileDocument) -> String {
    let get = |key: &str| document.options.get(key).map(String::as_str);
    let mut parts = vec![get("--carrier").unwrap_or("no carrier").to_owned()];
    if let Some(traffic) = get("--traffic") {
        parts.push(traffic.to_owned());
    }
    if let Some(device) = get("--device") {
        parts.push(format!("device {device}"));
    }
    if let Some(endpoint) = get("--remote")
        .or_else(|| get("--udp-peer"))
        .or_else(|| get("--listen"))
    {
        parts.push(endpoint.to_owned());
    }
    bounded_text(&parts.join(" · "))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(options: &[(&str, &str)]) -> ProfileDocument {
        ProfileDocument {
            version: PROFILE_VERSION,
            role: ProfileRole::Connect,
            options: options
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect(),
        }
    }

    #[test]
    fn documents_names_and_changes_are_checked_strictly() {
        let good = document(&[("--carrier", "quic-like"), ("--device", "l2t0")]);
        assert_eq!(good.validate(), Ok(()));
        assert_eq!(describe(&good), "quic-like · device l2t0");
        for bad in [
            document(&[("carrier", "x")]),
            document(&[("--Carrier", "x")]),
            document(&[("--control-socket", "/s")]),
            document(&[("--state-dir", "/d")]),
            document(&[("--device", "")]),
            document(&[("--device", "a\nb")]),
            ProfileDocument {
                version: 2,
                ..good.clone()
            },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
        for name in ["office", "home-2", "a.b_c"] {
            assert_eq!(validate_profile_name(name), Ok(()));
        }
        for name in ["", ".hidden", "a/b", "sp ace", &"x".repeat(65)] {
            assert!(validate_profile_name(name).is_err(), "{name}");
        }
        let save = ProfileChange::Save {
            name: "office".into(),
            document: good,
            expected_revision: None,
        };
        let text = serde_json::to_string(&save).unwrap_or_default();
        assert_eq!(
            serde_json::from_str::<ProfileChange>(&text).ok(),
            Some(save)
        );
        assert!(
            serde_json::from_str::<ProfileChange>(r#"{"op":"delete","name":"a"}"#).is_err(),
            "deletes need the revision"
        );
        assert_eq!(
            ProfileChange::Default { name: None }.validate(),
            Ok(()),
            "clearing the default"
        );
        assert_eq!(bounded_text(&"é".repeat(200)).len(), 240);
    }
}
