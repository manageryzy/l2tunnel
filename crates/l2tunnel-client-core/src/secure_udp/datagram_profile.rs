//! Shared datagram addressing, authentication geometry and public peer bindings.
use crate::secure_udp::{self, common_cli};
use l2tunnel_handshake as hs;
use l2tunnel_runtime::secure_udp::establish;
use l2tunnel_security as security;
use l2tunnel_udp_control as gate;
use std::{io, net::SocketAddr, time::Duration};

fn input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[derive(Clone, Copy)]
pub(crate) struct Common {
    pub(crate) appearance: l2tunnel_cover::Appearance,
    pub(crate) role: security::Role,
    pub(crate) local: SocketAddr,
    pub(crate) peer: SocketAddr,
    pub(crate) maximum_mtu: usize,
    pub(crate) profile: hs::Profile,
}
pub(crate) fn public_digest(domain: &[u8], peers: establish::Peers) -> [u8; 32] {
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    context.update(domain);
    context.update(&peers.initiator.0);
    context.update(&peers.responder.0);
    let mut result = [0; 32];
    result.copy_from_slice(context.finish().as_ref());
    result
}
impl Common {
    pub(crate) fn plan_geometry(self, plan: &common_cli::Plan) -> io::Result<(usize, usize)> {
        let ip = if self.local.is_ipv6() { 48 } else { 28 };
        let packet = self
            .maximum_mtu
            .checked_sub(ip)
            .ok_or_else(|| input("path capacity below IP framing"))?;
        Ok((
            self.final_geometry()?.0,
            plan.protected_body_capacity(packet)?,
        ))
    }
    #[cfg(unix)]
    pub(crate) fn raw_geometry(
        self,
        settings: &mut secure_udp::Settings,
        geometry: l2tunnel_raw_io::handoff::pairing::packet::RecordGeometry,
        final_geometry: l2tunnel_raw_io::handoff::pairing::packet::RecordGeometry,
    ) -> io::Result<(usize, usize)> {
        self.carrier_geometry(settings, geometry.max_record_bytes)?;
        // Bootstrap ARQ geometry derives from the selected real covered record;
        // no explicit catalog source, native, body or channel value is rewritten.
        self.bootstrap_arq_geometry(settings)?;
        // Final Records omit the bootstrap wrapper and require the corresponding
        // larger backing buffer. Keep bootstrap protected bytes and ARQ limits.
        settings.cover.max_packet_bytes = final_geometry.max_record_bytes;
        let overhead = final_geometry
            .ip_tcp_bytes
            .checked_add(l2tunnel::secure_record::compact::AUTHENTICATED_OVERHEAD)
            .ok_or_else(|| input("raw final control overhead overflow"))?;
        let maximum_body = final_geometry
            .max_record_bytes
            .checked_sub(l2tunnel::secure_record::compact::AUTHENTICATED_OVERHEAD)
            .ok_or_else(|| input("raw final capacity below authenticated framing"))?;
        Ok((overhead, maximum_body))
    }
    #[cfg(unix)]
    pub(crate) fn bootstrap_arq_geometry(
        self,
        settings: &mut secure_udp::Settings,
    ) -> io::Result<()> {
        settings.gate.arq.max_source_bytes = settings
            .cover
            .max_protected_bytes
            .checked_sub(gate::CONTROL_OVERHEAD + l2tunnel_recovery::DATA_HEADER_BYTES + 1)
            .ok_or_else(|| input("carrier bootstrap cannot hold maintained control framing"))?
            .min(1200);
        settings.gate.arq.send_bytes = settings
            .gate
            .arq
            .max_source_bytes
            .checked_mul(settings.gate.arq.send_records)
            .ok_or_else(|| input("carrier bootstrap send geometry overflow"))?;
        settings.gate.arq.receive_bytes = settings
            .gate
            .arq
            .max_source_bytes
            .checked_mul(settings.gate.arq.receive_records)
            .ok_or_else(|| input("carrier bootstrap receive geometry overflow"))?;
        Ok(())
    }
    #[cfg(unix)]
    pub(crate) fn carrier_geometry(
        self,
        settings: &mut secure_udp::Settings,
        capacity: usize,
    ) -> io::Result<(usize, usize)> {
        let cover = settings.cover;
        let prototype = l2tunnel_cover::Config::new(
            cover.appearance,
            l2tunnel_cover::ConnectionIds {
                local: cover.initiator_connection,
                peer: cover.responder_connection,
            },
            l2tunnel_cover::MediaConfig {
                local_ssrc: cover.initiator_ssrc,
                peer_ssrc: cover.responder_ssrc,
                payload_type: cover.payload_type,
            },
            l2tunnel_cover::Limits {
                max_packet_bytes: cover.max_packet_bytes,
                max_protected_bytes: cover.max_protected_bytes,
            },
        )
        .map_err(io::Error::other)?;
        // Derive this new carrier's requested capacity with the maintained codec.
        // Existing descriptors and source/native/MTU values are never rewritten.
        let mut low = 0;
        let mut high = capacity.min(cover.max_protected_bytes);
        while low < high {
            let middle = low + (high - low).div_ceil(2);
            if prototype
                .overhead(l2tunnel_cover::Phase::Handshake, middle)
                .map_err(io::Error::other)?
                .checked_add(middle)
                .ok_or_else(|| input("carrier cover length overflow"))?
                <= capacity
            {
                low = middle;
            } else {
                high = middle - 1;
            }
        }
        settings.cover.max_packet_bytes = capacity;
        settings.cover.max_protected_bytes = low;
        settings.cover.bootstrap_overhead(self.local.is_ipv6())?;
        let maximum_body = capacity
            .checked_sub(l2tunnel::secure_record::compact::AUTHENTICATED_OVERHEAD)
            .ok_or_else(|| input("outer carrier cannot fit common protection"))?;
        Ok((self.final_geometry()?.0, maximum_body))
    }
    pub(crate) fn final_geometry(self) -> io::Result<(usize, usize)> {
        let ip: usize = if self.local.is_ipv6() { 48 } else { 28 };
        let overhead = ip
            .checked_add(l2tunnel::secure_record::compact::AUTHENTICATED_OVERHEAD)
            .ok_or_else(|| input("final control overhead overflow"))?;
        let maximum_body = self
            .maximum_mtu
            .checked_sub(overhead)
            .ok_or_else(|| input("final capacity below authenticated framing"))?;
        Ok((overhead, maximum_body))
    }
    pub(crate) fn raw(
        self,
        path_mtu: usize,
        handshake_timeout: Duration,
        peers: establish::Peers,
        member: l2tunnel_identity::MemberPublicKey,
    ) -> io::Result<secure_udp::Settings> {
        let ip = if self.local.is_ipv6() { 48 } else { 28 };
        let header = if self.appearance == l2tunnel_cover::Appearance::QuicLike {
            13
        } else {
            14
        };
        let handshake_header = if self.appearance == l2tunnel_cover::Appearance::QuicLike {
            30
        } else {
            14
        };
        let ids = |domain: &[u8]| -> io::Result<[u8; 8]> {
            public_digest(domain, peers)[..8]
                .try_into()
                .map_err(|_| input("public CID derivation bound"))
        };
        let ssrc = |domain: &[u8]| {
            public_digest(domain, peers)[..4]
                .try_into()
                .map(u32::from_be_bytes)
                .map_err(|_| input("public SSRC derivation bound"))
        };
        let cover = secure_udp::Cover {
            appearance: self.appearance,
            initiator_connection: l2tunnel_cover::ConnectionId(ids(
                b"l2tunnel/service/CID/initiator/v1\0",
            )?),
            responder_connection: l2tunnel_cover::ConnectionId(ids(
                b"l2tunnel/service/CID/responder/v1\0",
            )?),
            initiator_ssrc: l2tunnel_cover::Ssrc(ssrc(b"l2tunnel/service/SSRC/initiator/v1\0")?),
            responder_ssrc: l2tunnel_cover::Ssrc(ssrc(b"l2tunnel/service/SSRC/responder/v1\0")?),
            payload_type: 96,
            max_packet_bytes: self
                .maximum_mtu
                .checked_sub(ip + header)
                .and_then(|value| value.checked_add(handshake_header))
                .ok_or_else(|| input("cover capacity overflow"))?,
            max_protected_bytes: self
                .maximum_mtu
                .checked_sub(ip + header)
                .ok_or_else(|| input("capacity below cover framing"))?,
        };
        let path = match self.role {
            security::Role::Initiator => gate::Path {
                client: self.local,
                server: self.peer,
            },
            security::Role::Responder => gate::Path {
                client: self.peer,
                server: self.local,
            },
        };
        let mut gate = gate::Config::new(
            path,
            public_digest(b"l2tunnel/service/bootstrap-profile/v1\0", peers),
            1,
        )
        .map_err(io::Error::other)?;
        gate.path_mtu = path_mtu;
        gate.outer_overhead = cover.bootstrap_overhead(self.local.is_ipv6())?;
        gate.arq.max_source_bytes = gate
            .path_mtu
            .checked_sub(
                gate.outer_overhead + gate::CONTROL_OVERHEAD + l2tunnel_recovery::DATA_HEADER_BYTES,
            )
            .ok_or_else(|| input("bootstrap MTU cannot hold ARQ framing"))?
            .min(1200);
        gate.arq.send_bytes = gate
            .arq
            .max_source_bytes
            .checked_mul(gate.arq.send_records)
            .ok_or_else(|| input("bootstrap send capacity overflow"))?;
        gate.arq.receive_bytes = gate
            .arq
            .max_source_bytes
            .checked_mul(gate.arq.receive_records)
            .ok_or_else(|| input("bootstrap receive capacity overflow"))?;
        gate.handshake_timeout = handshake_timeout;
        gate.cookie_ttl = gate.cookie_ttl.min(handshake_timeout);
        gate.maximum_rto = gate.maximum_rto.min(handshake_timeout);
        gate.initial_rto = gate.initial_rto.min(gate.maximum_rto);
        Ok(secure_udp::Settings {
            gate,
            cover,
            profile: self.profile,
            application: l2tunnel_core::ConfigDigest(public_digest(
                b"l2tunnel/service/application/v1\0",
                peers,
            )),
            outer: public_digest(b"l2tunnel/service/outer/v1\0", peers),
            member,
            membership: secure_udp::Membership {
                retry_interval: Duration::from_millis(100),
                max_attempts: 128,
                receive_interval: Duration::from_millis(10),
                receive_packets_per_interval: 128,
            },
            bootstrap_receive_packets_per_interval: 128,
        })
    }
}
