//! Authenticated native body selection shared by aligned and packed owners.

use l2tunnel_codec::{aligned_receiver as receiver, aligned_storage as storage};

/// Explicit authenticated native interpretation; never inferred from packet bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativePolicy {
    /// Ethernet eligibility checks select header compression or exact raw fallback.
    EthernetHeaders,
    /// Native IP is an exact kind-2 raw body, including fragmented packets.
    RawIp,
    /// Native IP TCP uses explicit contexts/deltas, with exact raw fallback.
    IpHeaders,
    /// Complete Ethernet bytes without header or payload compression.
    RawEthernet,
    /// Complete Ethernet bytes with stateless LZ4 only when smaller than raw.
    Lz4Ethernet,
    /// Complete native IP bytes with stateless LZ4 only when smaller than raw.
    Lz4Ip,
    /// Native IP deltas reference an explicit full context on the same channel.
    FixedAnchorIpHeaders,
}

impl NativePolicy {
    /// Stable complete configuration discriminant, independent of body tags.
    pub const fn wire(self) -> u8 {
        match self {
            Self::EthernetHeaders => 1,
            Self::RawIp => 2,
            Self::IpHeaders => 3,
            Self::RawEthernet => 4,
            Self::Lz4Ethernet => 5,
            Self::Lz4Ip => 6,
            Self::FixedAnchorIpHeaders => 7,
        }
    }
    /// Decode only current explicit configuration selections.
    pub const fn from_wire(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::EthernetHeaders),
            2 => Some(Self::RawIp),
            3 => Some(Self::IpHeaders),
            4 => Some(Self::RawEthernet),
            5 => Some(Self::Lz4Ethernet),
            6 => Some(Self::Lz4Ip),
            7 => Some(Self::FixedAnchorIpHeaders),
            _ => None,
        }
    }
    /// Whether packet bodies require no prior header context.
    pub const fn is_stateless(self) -> bool {
        !self.uses_ip_headers() && !matches!(self, Self::EthernetHeaders)
    }
    /// Whether the codec requires a native-IP header encoder.
    pub const fn uses_ip_headers(self) -> bool {
        matches!(self, Self::IpHeaders | Self::FixedAnchorIpHeaders)
    }
    /// Whether a lost record leaves every later record decodable: stateless
    /// bodies, or deltas that name an explicit anchor (a delta whose anchor
    /// was lost is discarded). Chained header contexts do not survive loss.
    pub const fn survives_record_loss(self) -> bool {
        !matches!(self, Self::EthernetHeaders | Self::IpHeaders)
    }
    /// Whether the native device supplies IP packets rather than Ethernet frames.
    pub const fn is_ip(self) -> bool {
        self.uses_ip_headers() || matches!(self, Self::RawIp | Self::Lz4Ip)
    }
    /// Whether the selected policy enables bounded LZ4-or-raw body selection.
    pub const fn uses_lz4(self) -> bool {
        matches!(self, Self::Lz4Ethernet | Self::Lz4Ip)
    }
    /// Build capability, checked before owner construction or packet ingress.
    pub const fn available(self) -> bool {
        !self.uses_lz4() || l2tunnel_codec::aligned_body::lz4_available()
    }
    /// Select the receiver's exact backing from the authenticated native policy.
    pub fn receiver_plan(
        self,
        limits: receiver::Limits,
    ) -> Result<storage::ReceiverPlan, storage::Error> {
        match self {
            Self::FixedAnchorIpHeaders => storage::ReceiverPlan::for_fixed_anchor_ip_limits(limits),
            Self::IpHeaders => storage::ReceiverPlan::for_ip_limits(limits),
            _ => storage::ReceiverPlan::for_limits(limits),
        }
    }
    /// Construct a receiver with its original fixed allocation allowance.
    pub fn reserved_receiver(
        self,
        scope: receiver::Scope,
        limits: receiver::Limits,
        capacity: storage::Limits,
    ) -> Result<receiver::Receiver, storage::Error> {
        match self {
            Self::FixedAnchorIpHeaders => {
                receiver::Receiver::new_reserved_ip_with_fixed_anchors(scope, limits, capacity)
            }
            Self::IpHeaders => receiver::Receiver::new_reserved_ip(scope, limits, capacity),
            _ => receiver::Receiver::new_reserved(scope, limits, capacity),
        }
    }
    /// Check a body tag under the negotiated policy before codec admission.
    /// Fragment continuation syntax is validated by the existing unit parser.
    /// This provides no authentication, geometry or ownership authority.
    pub fn accepts_unit(self, unit: &[u8]) -> bool {
        let Some(mut tag) = unit.get(3).copied() else {
            return false;
        };
        if tag == 4 {
            let Some(offset) = unit.get(6..8) else {
                return false;
            };
            if offset != [0, 0] {
                return true;
            }
            let Some(first) = unit.get(8).copied() else {
                return false;
            };
            tag = first;
        }
        if self == Self::FixedAnchorIpHeaders {
            matches!(tag, 2 | 8 | l2tunnel_codec::aligned_body::FIXED_ANCHOR_TAG)
        } else if self.uses_lz4() {
            matches!(tag, 2 | l2tunnel_codec::aligned_body::LZ4_TAG)
        } else if self.is_stateless() {
            tag == 2
        } else {
            !matches!(
                tag,
                l2tunnel_codec::aligned_body::LZ4_TAG
                    | l2tunnel_codec::aligned_body::FIXED_ANCHOR_TAG
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::NativePolicy;

    #[test]
    fn negotiated_body_tag_is_checked_on_complete_units_and_first_fragments() {
        let anchored = NativePolicy::FixedAnchorIpHeaders;
        assert_eq!(NativePolicy::from_wire(7), Some(anchored));
        assert_eq!(NativePolicy::from_wire(8), None);
        for tag in [2, 8, 9, 10, 11] {
            for unit in [&[0, 0, 1, tag][..], &[0, 0, 1, 4, 0, 50, 0, 0, tag][..]] {
                assert_eq!(anchored.accepts_unit(unit), matches!(tag, 2 | 8 | 11));
                assert_eq!(
                    NativePolicy::IpHeaders.accepts_unit(unit),
                    matches!(tag, 2 | 8 | 9)
                );
            }
        }
    }
}
