//! Planned TUN/TAP policy contracts; no TCP proxy or QoS scheduler is implemented.

/// Native device service selected by a client profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkLayer {
    /// Ethernet frames; preserve host TCP behavior.
    Tap,
    /// Routed IP packets, optionally handled by an explicitly selected TCP proxy.
    Tun,
}

/// Ownership boundary for TCP and flow-window decisions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpControl {
    /// Preserve endpoint TCP and use system flow/congestion control.
    System,
    /// Control only tunnel credits, pacing and queues; endpoint TCP stays unchanged.
    TunnelCredits,
    /// Explicitly terminate TCP legs; changes end-to-end TCP semantics.
    SplitTcpProxy,
}

/// Planned cross-flow service policy, separate from MUX channel placement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Qos {
    /// Use the platform queueing policy without a custom active scheduler.
    System,
    /// Hierarchical weighted deficit scheduling with bounded queue management.
    WeightedDeficit,
}

/// Traffic service selection. Constructors express intent, not implementation availability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrafficPolicy {
    /// Native interface packet layer.
    pub layer: NetworkLayer,
    /// TCP/window ownership contract.
    pub tcp: TcpControl,
    /// Cross-flow scheduler ownership.
    pub qos: Qos,
}

impl TrafficPolicy {
    /// Transparent TAP uses system algorithms.
    pub fn tap() -> Self {
        Self {
            layer: NetworkLayer::Tap,
            tcp: TcpControl::System,
            qos: Qos::System,
        }
    }

    /// Active TUN without altering endpoint TCP semantics.
    pub fn tun_active() -> Self {
        Self {
            layer: NetworkLayer::Tun,
            tcp: TcpControl::TunnelCredits,
            qos: Qos::WeightedDeficit,
        }
    }

    /// Explicit TUN TCP acceleration profile with owned TCP legs.
    pub fn tun_tcp_proxy() -> Self {
        Self {
            layer: NetworkLayer::Tun,
            tcp: TcpControl::SplitTcpProxy,
            qos: Qos::WeightedDeficit,
        }
    }

    /// Reject an active TCP/scheduler profile accidentally attached to TAP.
    pub fn validate(self) -> Result<(), &'static str> {
        if self.layer == NetworkLayer::Tap
            && (self.tcp != TcpControl::System || self.qos != Qos::System)
        {
            return Err("TAP preserves system TCP and QoS algorithms");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tap_cannot_silently_enable_active_tcp_or_custom_qos() {
        for policy in [
            TrafficPolicy::tap(),
            TrafficPolicy::tun_active(),
            TrafficPolicy::tun_tcp_proxy(),
        ] {
            assert!(policy.validate().is_ok());
        }
        assert!(
            TrafficPolicy {
                tcp: TcpControl::SplitTcpProxy,
                ..TrafficPolicy::tap()
            }
            .validate()
            .is_err()
        );
        assert!(
            TrafficPolicy {
                qos: Qos::WeightedDeficit,
                ..TrafficPolicy::tap()
            }
            .validate()
            .is_err()
        );
    }
}
