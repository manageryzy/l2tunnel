//! Pure carrier selection contracts; actual sockets live in separate runtime adapters.
use l2tunnel_core::Recovery;

/// Selectable carrier identities; runtime capability checks determine availability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Backend {
    /// Experimental privileged packet engine with qualified semantics.
    RawTcp,
    /// Retained kernel TCP socket and TLS connection after authentication.
    TcpTls,
    /// Authenticated UDP packets with optional payload confidentiality.
    UdpAuthenticated,
}

/// Explicit backend selection or capability-aware automatic fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Selection {
    /// Use the negotiated preference order, subject to required semantics.
    Auto,
    /// Use exactly this backend; absence or incompatibility is an error.
    Only(Backend),
}

/// UDP header/handshake appearance, independent of transport reliability.
/// These identities do not claim OpenVPN or QUIC interoperability or path availability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpCover {
    /// Custom OpenVPN-like envelope and handshake profile.
    OpenVpnLike,
    /// Custom QUIC-like envelope and handshake profile.
    QuicLike,
}

/// Requested carrier and its mandatory UDP profile when UDP is explicitly selected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CarrierConfig {
    /// Explicit backend or automatic preference.
    pub selection: Selection,
    /// Required if automatic selection may fall back to UDP.
    pub udp_cover: Option<UdpCover>,
}

impl CarrierConfig {
    /// Select without silently replacing an explicitly requested backend.
    /// Missing UDP cover removes UDP from auto fallback and rejects explicit UDP.
    pub fn resolve(
        self,
        mut available: Availability,
        required: Requirement,
    ) -> Result<Backend, &'static str> {
        if self.udp_cover.is_none() {
            available.udp_authenticated = false;
        }
        match self.selection {
            Selection::Auto => select(available, required),
            Selection::Only(backend) => {
                let restricted = Availability {
                    raw_tcp: backend == Backend::RawTcp && available.raw_tcp,
                    tcp_tls: backend == Backend::TcpTls && available.tcp_tls,
                    udp_authenticated: backend == Backend::UdpAuthenticated
                        && available.udp_authenticated,
                };
                select(restricted, required)
            }
        }
    }
}

/// Upper-layer delivery requirement; explicit to prevent silent semantic downgrade.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Requirement {
    /// Carrier must supply reliable in-order delivery.
    ReliableStream,
    /// Expose datagram loss/reordering to custom recovery.
    Datagrams,
    /// Caller provides independent recovery and permits either carrier semantic.
    EitherWithOverlayRecovery,
}
impl Requirement {
    /// Default capability required for a configured recovery engine.
    pub fn for_recovery(recovery: Recovery) -> Self {
        if recovery == Recovery::CarrierOnly {
            Self::ReliableStream
        } else {
            Self::Datagrams
        }
    }
}

/// Capability probe results supplied by the embedding runtime, not only OS checks.
#[derive(Clone, Copy, Debug, Default)]
pub struct Availability {
    /// Raw implementation, permission and path qualification all passed.
    pub raw_tcp: bool,
    /// TCP/TLS implementation and peer connectivity passed.
    pub tcp_tls: bool,
    /// UDP implementation and peer connectivity passed.
    pub udp_authenticated: bool,
}

/// Prefer TCP to UDP when negotiated semantics permit.
pub const PREFERENCE: [Backend; 3] = [Backend::RawTcp, Backend::TcpTls, Backend::UdpAuthenticated];

/// Choose a compatible available backend; permission absence alone is not fatal.
pub fn select(available: Availability, required: Requirement) -> Result<Backend, &'static str> {
    for backend in PREFERENCE {
        let ready = match backend {
            Backend::RawTcp => available.raw_tcp,
            Backend::TcpTls => available.tcp_tls,
            Backend::UdpAuthenticated => available.udp_authenticated,
        };
        let compatible = match required {
            Requirement::ReliableStream => backend == Backend::TcpTls,
            Requirement::Datagrams => backend != Backend::TcpTls,
            Requirement::EitherWithOverlayRecovery => true,
        };
        if ready && compatible {
            return Ok(backend);
        }
    }
    Err("no compatible authenticated carrier available")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tcp_precedes_udp_without_changing_required_semantics() {
        let a = Availability {
            raw_tcp: false,
            tcp_tls: true,
            udp_authenticated: true,
        };
        assert_eq!(
            select(a, Requirement::EitherWithOverlayRecovery),
            Ok(Backend::TcpTls)
        );
        assert_eq!(
            select(a, Requirement::Datagrams),
            Ok(Backend::UdpAuthenticated)
        );
        assert!(
            select(
                Availability {
                    tcp_tls: true,
                    ..Availability::default()
                },
                Requirement::Datagrams
            )
            .is_err()
        );
        assert!(
            select(
                Availability {
                    raw_tcp: true,
                    udp_authenticated: true,
                    tcp_tls: false
                },
                Requirement::ReliableStream
            )
            .is_err()
        );
        assert_eq!(
            Requirement::for_recovery(Recovery::CarrierOnly),
            Requirement::ReliableStream
        );
        assert!(select(Availability::default(), Requirement::ReliableStream).is_err());
    }
    #[test]
    fn explicit_backend_and_udp_cover_are_not_silently_replaced() {
        let all = Availability {
            raw_tcp: true,
            tcp_tls: true,
            udp_authenticated: true,
        };
        let udp = CarrierConfig {
            selection: Selection::Only(Backend::UdpAuthenticated),
            udp_cover: Some(UdpCover::QuicLike),
        };
        assert_eq!(
            udp.resolve(all, Requirement::Datagrams),
            Ok(Backend::UdpAuthenticated)
        );
        assert!(udp.resolve(all, Requirement::ReliableStream).is_err());
        assert!(
            CarrierConfig {
                udp_cover: None,
                ..udp
            }
            .resolve(all, Requirement::Datagrams)
            .is_err()
        );
        let tcp = CarrierConfig {
            selection: Selection::Only(Backend::TcpTls),
            udp_cover: None,
        };
        assert_eq!(
            tcp.resolve(all, Requirement::ReliableStream),
            Ok(Backend::TcpTls)
        );
        assert!(
            tcp.resolve(
                Availability {
                    tcp_tls: false,
                    ..all
                },
                Requirement::EitherWithOverlayRecovery
            )
            .is_err()
        );
        let auto = CarrierConfig {
            selection: Selection::Auto,
            udp_cover: None,
        };
        let only_udp = Availability {
            udp_authenticated: true,
            ..Availability::default()
        };
        assert!(auto.resolve(only_udp, Requirement::Datagrams).is_err());
        assert_eq!(
            CarrierConfig {
                udp_cover: Some(UdpCover::OpenVpnLike),
                ..auto
            }
            .resolve(only_udp, Requirement::Datagrams),
            Ok(Backend::UdpAuthenticated)
        );
    }
}
