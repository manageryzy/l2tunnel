//! Authenticated native body selection shared by aligned and packed owners.

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
            _ => None,
        }
    }
    /// Whether packet bodies require no prior header context.
    pub const fn is_stateless(self) -> bool {
        !matches!(self, Self::EthernetHeaders | Self::IpHeaders)
    }
    /// Whether the native device supplies IP packets rather than Ethernet frames.
    pub const fn is_ip(self) -> bool {
        matches!(self, Self::RawIp | Self::IpHeaders | Self::Lz4Ip)
    }
    /// Whether the selected policy enables bounded LZ4-or-raw body selection.
    pub const fn uses_lz4(self) -> bool {
        matches!(self, Self::Lz4Ethernet | Self::Lz4Ip)
    }
    /// Build capability, checked before owner construction or packet ingress.
    pub const fn available(self) -> bool {
        !self.uses_lz4() || l2tunnel_codec::aligned_body::lz4_available()
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
        if self.uses_lz4() {
            matches!(tag, 2 | l2tunnel_codec::aligned_body::LZ4_TAG)
        } else if self.is_stateless() {
            tag == 2
        } else {
            tag != l2tunnel_codec::aligned_body::LZ4_TAG
        }
    }
}
