//! Meter CSR reads over the local API (`docs/modules/meter-csr.md`).
//!
//! A register is a u64 at a named path such as
//! `runtime.native_ingress.lane0.user.occupancy_bytes`. Reads page through a
//! whole-segment prefix with a cursor (the last path of the previous page).
//! An absent path means the running profile does not report that meter.
use serde::{Deserialize, Serialize};

/// Most entries in one page (the remote wire limit as well).
pub const METER_PAGE_LIMIT: u16 = l2tunnel_meters::wire::MAX_PAGE_ENTRIES;
/// Estimated JSON bytes allowed in one page, inside the local reply limit.
pub const METER_PAGE_BYTES: usize = 24 * 1024;
/// Longest prefix.
pub const METER_PREFIX_BYTES: usize = l2tunnel_meters::path::MAX_PREFIX_BYTES;

/// Which side's CSR to read.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeterSide {
    /// This service's running session.
    Local,
    /// The authenticated peer, over the in-band `Meters` control stream.
    Remote,
}

/// One register.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeterEntry {
    /// Register path.
    pub path: String,
    /// Register value.
    pub value: u64,
}

/// One page of a meter read.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeterPage {
    /// Side the values come from.
    pub side: MeterSide,
    /// Session generation of the values; a change restarts every series.
    pub generation: u64,
    /// Service-monotonic time of this read (milliseconds since start).
    pub sampled_ms: u64,
    /// Age of the runtime table when read, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub age_ms: Option<u64>,
    /// Registers in path order.
    pub entries: Vec<MeterEntry>,
    /// Cursor for the next page, when more registers match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
}

/// One catalog pattern.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeterDescriptor {
    /// Path pattern with placeholders such as `{lane}`.
    pub pattern: String,
    /// `gauge`, `capacity`, `high_water`, `counter`, `duration`, `bucket` or `state`.
    pub kind: String,
    /// Value unit.
    pub unit: String,
    /// `buffer`, `recovery`, `carrier`, `mux` or `meta`.
    pub family: String,
    /// Buffer-inventory row or ledger reference.
    pub row: String,
    /// `reported` or `unavailable`.
    pub state: String,
    /// Why an unavailable meter is never reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// One page of the catalog.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeterCatalogPage {
    /// Catalog version.
    pub version: u64,
    /// Patterns in catalog order.
    pub entries: Vec<MeterDescriptor>,
    /// Cursor (the next pattern index) when more patterns match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<u32>,
}

impl MeterDescriptor {
    /// Local view of one catalog entry.
    pub fn of(descriptor: &l2tunnel_meters::catalog::Descriptor) -> Self {
        let (state, reason) = match descriptor.state {
            l2tunnel_meters::catalog::State::Reported => ("reported", None),
            l2tunnel_meters::catalog::State::Unavailable(reason) => {
                ("unavailable", Some(reason.to_owned()))
            }
        };
        Self {
            pattern: descriptor.pattern.clone(),
            kind: descriptor.kind.as_str().to_owned(),
            unit: descriptor.unit.as_str().to_owned(),
            family: descriptor.family.as_str().to_owned(),
            row: descriptor.row.to_owned(),
            state: state.to_owned(),
            reason,
        }
    }
}

/// Estimated JSON size of one entry in a page.
pub fn entry_bytes(path: &str) -> usize {
    path.len() + 40
}

/// Check a request's prefix, cursor and limit; returns the refusal code.
pub fn check_request(prefix: &str, cursor: Option<&str>, limit: u16) -> Result<(), &'static str> {
    if limit == 0 || limit > METER_PAGE_LIMIT {
        return Err("invalid_limit");
    }
    if l2tunnel_meters::path::validate_prefix(prefix).is_err() {
        return Err("invalid_prefix");
    }
    if let Some(cursor) = cursor
        && (l2tunnel_meters::path::validate(cursor).is_err()
            || !l2tunnel_meters::path::under(prefix, cursor))
    {
        return Err("invalid_cursor");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_checked() {
        assert_eq!(check_request("", None, 1), Ok(()));
        assert_eq!(check_request("", None, 0), Err("invalid_limit"));
        assert_eq!(check_request("", None, 257), Err("invalid_limit"));
        assert_eq!(check_request("Bad", None, 1), Err("invalid_prefix"));
        assert_eq!(
            check_request("mux", Some("quic.connection"), 1),
            Err("invalid_cursor")
        );
        assert_eq!(check_request("mux", Some("mux.channel.ch0"), 1), Ok(()));
    }

    #[test]
    fn pages_round_trip_strictly() -> Result<(), serde_json::Error> {
        let page = MeterPage {
            side: MeterSide::Remote,
            generation: 2,
            sampled_ms: 10,
            age_ms: Some(3),
            entries: vec![MeterEntry {
                path: "meta.version".into(),
                value: 1,
            }],
            next: None,
        };
        let text = serde_json::to_string(&page)?;
        assert_eq!(
            text,
            r#"{"side":"remote","generation":2,"sampled_ms":10,"age_ms":3,"entries":[{"path":"meta.version","value":1}]}"#
        );
        assert_eq!(serde_json::from_str::<MeterPage>(&text)?, page);
        assert!(serde_json::from_str::<MeterPage>(&text.replace("}]}", "}],\"x\":1}")).is_err());
        Ok(())
    }
}
