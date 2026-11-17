//! Portable explicit compact-wire request and actual installed observations.
use l2tunnel::secure_record::compact;
use serde::{Deserialize, Serialize};
use std::io;

/// Selected data protection, independent of the management authentication domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CompactDataProtection {
    /// Native four-byte AES-128-CCM authentication tag.
    #[serde(rename = "aes-ccm-4")]
    AesCcm4,
    /// Encrypted unkeyed CRC32C with ChaCha20; not authenticated data.
    #[serde(rename = "chacha20-crc32c")]
    ChaCha20Crc32c,
    /// ChaCha20-Poly1305 with its full sixteen-byte authentication tag.
    #[serde(rename = "chacha20-poly1305")]
    ChaCha20Poly1305,
    /// Full HMAC-SHA256 authentication without payload confidentiality.
    #[serde(rename = "hmac-sha256")]
    HmacSha256,
}
impl CompactDataProtection {
    /// Stable explicit CLI/API name, without a fallback/default.
    pub const fn name(self) -> &'static str {
        match self {
            Self::AesCcm4 => "aes-ccm-4",
            Self::ChaCha20Crc32c => "chacha20-crc32c",
            Self::ChaCha20Poly1305 => "chacha20-poly1305",
            Self::HmacSha256 => "hmac-sha256",
        }
    }
}

/// Complete strict establishment-bound compact v3 selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactWireSelection {
    /// Explicit format version; only v3 is supported by this selection.
    pub version: u8,
    /// Selected data protection, independent of strong retiring feedback.
    pub data_protection: CompactDataProtection,
    /// Positive bounded full-counter reconstruction gap, also capped by key interval.
    pub max_forward_packets: u32,
    /// Original receiving-owner lifetime failed-check cap; success does not reset it.
    pub max_failed_checks: u32,
}
impl CompactWireSelection {
    /// Validate and construct the actual facade selection, without I/O or authority.
    pub fn build(self) -> io::Result<compact::Selection> {
        if self.version != 3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "compact wire requires explicit version3",
            ));
        }
        let value = compact::Selection {
            protection: match self.data_protection {
                CompactDataProtection::AesCcm4 => {
                    l2tunnel_security::compact::Protection::Aes128Ccm4
                }
                CompactDataProtection::ChaCha20Crc32c => {
                    l2tunnel_security::compact::Protection::ChaCha20Crc32c
                }
                CompactDataProtection::ChaCha20Poly1305 => {
                    l2tunnel_security::compact::Protection::ChaCha20Poly1305
                }
                CompactDataProtection::HmacSha256 => {
                    l2tunnel_security::compact::Protection::HmacSha256
                }
            },
            limits: l2tunnel_security::compact::Selection {
                max_forward_packets: self.max_forward_packets,
                max_failed_checks: self.max_failed_checks,
            },
        };
        value.validate().map_err(io::Error::other)?;
        Ok(value)
    }
    /// Project the retained actual typed selection without manufacturing readiness.
    pub fn from_selection(value: compact::Selection) -> io::Result<Self> {
        value.validate().map_err(io::Error::other)?;
        let data_protection = match value.protection {
            l2tunnel_security::compact::Protection::Aes128Ccm4 => CompactDataProtection::AesCcm4,
            l2tunnel_security::compact::Protection::ChaCha20Crc32c => {
                CompactDataProtection::ChaCha20Crc32c
            }
            l2tunnel_security::compact::Protection::ChaCha20Poly1305 => {
                CompactDataProtection::ChaCha20Poly1305
            }
            l2tunnel_security::compact::Protection::HmacSha256 => CompactDataProtection::HmacSha256,
        };
        Ok(Self {
            version: 3,
            data_protection,
            max_forward_packets: value.limits.max_forward_packets,
            max_failed_checks: value.limits.max_failed_checks,
        })
    }
}

/// Actual failed checks from the three independent receiving purpose owners.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactCheckCounts {
    /// Actual selected data-owner failed checks; CRC checks are not authentication.
    pub data: u32,
    /// Actual strong retiring-feedback authentication failures.
    pub feedback: u32,
    /// Actual strong management/liveness authentication failures.
    pub control: u32,
    /// Negotiated lifetime cap per receiving purpose owner.
    pub limit: u32,
}

/// Requested policy and actual runtime installation, never an authentication proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactWireStatus {
    /// Complete retained establishment-bound request.
    pub requested: CompactWireSelection,
    /// Actual matching installed selection; absent until a runtime sample exists.
    pub effective: Option<CompactWireSelection>,
    /// Actual current failed-check facts, absent without a runtime sample.
    pub checks: Option<CompactCheckCounts>,
    /// Actual separate retiring-feedback packet identity; not the user counter.
    pub feedback_packet_number: Option<u64>,
    /// Actual proxy records use strong authentication even for a short-data request.
    pub authenticated_proxy_records: Option<bool>,
    /// Actual final data framing/protection bytes, excluding carrier cost.
    pub effective_data_overhead_bytes: Option<u64>,
}
impl CompactWireStatus {
    pub(crate) fn observe(
        requested: compact::Selection,
        snapshot: Option<&l2tunnel_runtime::secure_udp::transport::CommonSnapshot>,
    ) -> io::Result<Self> {
        if snapshot.is_some_and(|actual| {
            actual.compact_wire != Some(requested)
                || actual
                    .compact_check_status
                    .is_none_or(|checks| checks.limit != requested.limits.max_failed_checks)
        }) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "compact runtime selection/check limits differ from authenticated request",
            ));
        }
        Ok(Self {
            requested: CompactWireSelection::from_selection(requested)?,
            effective: snapshot
                .and_then(|actual| actual.compact_wire)
                .map(CompactWireSelection::from_selection)
                .transpose()?,
            checks: snapshot
                .and_then(|actual| actual.compact_check_status)
                .map(|checks| CompactCheckCounts {
                    data: checks.data,
                    feedback: checks.feedback,
                    control: checks.control,
                    limit: checks.limit,
                }),
            feedback_packet_number: snapshot
                .and_then(|actual| actual.compact_feedback_number)
                .map(|number| number.0),
            authenticated_proxy_records: snapshot.map(|actual| actual.authenticated_proxy_records),
            effective_data_overhead_bytes: snapshot
                .map(|actual| actual.effective_data_overhead_bytes as u64),
        })
    }
}
