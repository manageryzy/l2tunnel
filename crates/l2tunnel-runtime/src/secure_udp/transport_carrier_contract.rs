//! Genuine initial carrier proof checks for current Common records.
use super::*;
use crate::secure_udp::establish::carrier::AuthenticatedOuter;

impl CommonTransactionContract {
    /// Compare the actual handoff proof; copied observations cannot create the
    /// original Parts or the confirmed initial authority consumed by runtime.
    pub fn validate_outer(&self, actual: Option<AuthenticatedOuter>) -> io::Result<()> {
        if actual != self.outer {
            return Err(invalid("original outer proof differs from Common contract"));
        }
        Ok(())
    }
}

pub(super) fn validate_carrier(
    outer: AuthenticatedOuter,
    role: security::Role,
    resources: Config,
    ipv6: bool,
    descriptor: common::Descriptor,
) -> io::Result<()> {
    let requested = outer.requested();
    if requested.path_mtu != resources.path_mtu
        || requested.outer_overhead_bytes != if ipv6 { 49 } else { 29 }
        || outer.endpoints().0.is_ipv6() != ipv6
        || outer.endpoints().1.is_ipv6() != ipv6
        || outer.info().config != requested.session_config().map_err(invalid)?
        || match role {
            security::Role::Initiator => outer.info().peer_member.is_some(),
            security::Role::Responder => outer.info().peer_member != Some(outer.info().member),
        }
        || outer.info().config.layer
            != match descriptor
                .direction(mg::Role::Client)
                .common()
                .traffic()
                .layer
            {
                core::traffic::NetworkLayer::Tap => PacketLayer::Ethernet,
                core::traffic::NetworkLayer::Tun => PacketLayer::Ip,
            }
    {
        return Err(invalid("selected original outer policy/geometry differs"));
    }
    Ok(())
}
