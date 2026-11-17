//! Bounded test resource templates for current Common fixtures.
//! This module has no profile resolver, wire parser or runtime entry.
use super::{Settings, establish, security};
use crate::cli::secure_udp_frontend::Selection;
use crate::{Compression, ConnectionConfig};
use l2tunnel_core::Duplex;
use l2tunnel_device::PacketLayer;
use l2tunnel_handshake as hs;
use l2tunnel_identity as identity;
use l2tunnel_runtime::secure_udp::transport;
use l2tunnel_swift::control::Policy;
use std::{io, time::Duration};
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
pub(crate) struct Resources {
    connection: ConnectionConfig,
    settings: Settings,
    initiator: transport::Config,
    responder: transport::Config,
}
impl Resources {
    pub(crate) fn new(
        connection: ConnectionConfig,
        settings: Settings,
        initiator: transport::Config,
        responder: transport::Config,
    ) -> Self {
        Self {
            connection,
            settings,
            initiator,
            responder,
        }
    }
    pub(crate) fn connection(&self) -> ConnectionConfig {
        self.connection
    }
    pub(crate) fn settings(&self) -> Settings {
        self.settings
    }
    pub(crate) fn runtime(&self, role: security::Role) -> transport::Config {
        match role {
            security::Role::Initiator => self.initiator,
            security::Role::Responder => self.responder,
        }
    }
}

pub(crate) fn fixture(
    path: l2tunnel_udp_control::Path,
    appearance: l2tunnel_cover::Appearance,
    member: identity::MemberPublicKey,
) -> io::Result<(Resources, establish::Peers)> {
    let peers = establish::Peers {
        initiator: hs::LocalSecret::new(Zeroizing::new([11; 32])).public_key(),
        responder: hs::LocalSecret::new(Zeroizing::new([22; 32])).public_key(),
    };
    let selection = Selection {
        appearance,
        role: security::Role::Initiator,
        local: path.client,
        peer: path.server,
        policy: Policy {
            path_mtu: 1500,
            forward_kbit: 10_000,
            reverse_kbit: 5_000,
            channels: 4,
            window: 32,
            repair_permille: 0,
        },
        maximum_mtu: 2000,
        profile: hs::Profile::Ik,
        report: Some(Duration::from_millis(100)),
    };
    let connection = ConnectionConfig {
        layer: PacketLayer::Ip,
        duplex: Duplex::Full,
        max_packet: 1600,
        compression: Compression::None,
        handshake_timeout: Duration::from_secs(3),
    };
    Ok((selection.build(connection, peers, member)?, peers))
}
