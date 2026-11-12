use crate::{
    Carrier, ClientCredentials, CloseReceipt, Config, Control, Error, PacketReceiver, PacketSender,
    ServerCredentials, Status, Traffic, WireStatus,
};
use crate::{
    budget::Budget,
    runtime::{Prepared, enable_native, nonce, prepare_client, prepare_server},
};
use l2tunnel_auth::{
    ClientTls, Direction, KeyPurpose, MemberAllowlist, MemberKey, ServerTls, SessionInfo,
};
use l2tunnel_datagram::Direction as DataDirection;
use l2tunnel_udp_control::Secret;
use ring::{digest, hmac};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UdpSocket,
    time::{Instant, timeout},
};

/// One global client identity with separately provisioned lane admission keys.
pub struct ClientPairCredentials<'a> {
    /// Certificate verification policy for both actual TLS connections.
    pub tls: &'a ClientTls,
    /// Certificate verification name, never sent as SNI.
    pub server_name: &'a str,
    /// The same actual member must authenticate on both lanes.
    pub member: &'a MemberKey,
    /// Forward then reverse lane bootstrap keys.
    pub admissions: [Secret; 2],
}
/// One global server identity with separately provisioned per-lane gate keys.
pub struct ServerPairCredentials<'a> {
    /// The actual certificate identity for both lanes.
    pub tls: &'a ServerTls,
    /// Final member authorization, separate from admission.
    pub members: &'a MemberAllowlist,
    /// Forward then reverse lane admission keys.
    pub admissions: [Secret; 2],
    /// Independent server-only cookie keys in the same order.
    pub cookies: [Secret; 2],
}
/// Non-secret identity of an actually joined pair, in canonical bulk direction order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairInfo {
    /// Hash binding both actual sessions, identities, lane IDs and accepted configs.
    pub digest: [u8; 32],
    /// Client-to-server then server-to-client physical session metadata.
    pub lanes: [SessionInfo; 2],
}
/// Counters from both owned actors and their one shared wire admission ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairStatus {
    /// Individual physical lane snapshots, not instantaneous across actors.
    pub lanes: [Status; 2],
    /// Atomic aggregate snapshot including both gates and all retries.
    pub wire: WireStatus,
}
/// Both physical owners plus otherwise inactive handles needed to retain their queues.
pub struct PairControl {
    controls: [Control; 2],
    inactive_sender: PacketSender,
    inactive_receiver: PacketReceiver,
    budget: Budget,
}
impl PairControl {
    /// Snapshot both lane states and the single aggregate allowance.
    pub fn status(&self) -> Result<PairStatus, Error> {
        Ok(PairStatus {
            lanes: [self.controls[0].status()?, self.controls[1].status()?],
            wire: self.budget.status()?,
        })
    }
    /// Require explicit complete drain on both lanes; drop cancels both owners.
    pub async fn close(self) -> Result<[CloseReceipt; 2], Error> {
        let Self {
            controls: [a, b],
            inactive_sender,
            inactive_receiver,
            budget: _,
        } = self;
        let result = tokio::try_join!(a.close(), b.close());
        drop((inactive_sender, inactive_receiver));
        let (a, b) = result?;
        Ok([a, b])
    }
}
/// Bidirectional packet capability composed of two authenticated one-direction lanes.
pub struct PairedCarrier {
    info: PairInfo,
    control: PairControl,
    sender: PacketSender,
    receiver: PacketReceiver,
}
impl PairedCarrier {
    /// Actual joined metadata, never caller-asserted exporters.
    pub fn info(&self) -> &PairInfo {
        &self.info
    }
    /// Transfer both supervised owners and the locally usable data direction handles.
    pub fn split(self) -> (PairControl, PacketSender, PacketReceiver) {
        (self.control, self.sender, self.receiver)
    }
}

/// Authenticate and join two complementary standalone UDP lanes before enabling data.
pub async fn client_pair(
    sockets: [UdpSocket; 2],
    configs: [Config; 2],
    credentials: ClientPairCredentials<'_>,
) -> Result<PairedCarrier, Error> {
    Ok(client_pair_profile(sockets, configs, credentials, None)
        .await?
        .0)
}
pub(crate) async fn client_pair_profile(
    sockets: [UdpSocket; 2],
    configs: [Config; 2],
    credentials: ClientPairCredentials<'_>,
    native: Option<std::time::Duration>,
) -> Result<(PairedCarrier, Option<std::sync::Arc<crate::native::Domain>>), Error> {
    validate(configs)?;
    let started = Instant::now();
    let budget = Budget::new(configs[0].wire_budget, started);
    let [a, b] = sockets;
    let [ak, bk] = credentials.admissions;
    timeout(configs[0].pairing_timeout, async {
        let (a, b) = tokio::try_join!(
            prepare_client(
                a,
                configs[0],
                ClientCredentials {
                    tls: credentials.tls,
                    server_name: credentials.server_name,
                    member: credentials.member,
                    admission: ak
                },
                started,
                budget.clone()
            ),
            prepare_client(
                b,
                configs[1],
                ClientCredentials {
                    tls: credentials.tls,
                    server_name: credentials.server_name,
                    member: credentials.member,
                    admission: bk
                },
                started,
                budget.second()
            ),
        )?;
        finish_pair(a, b, false, budget, native).await
    })
    .await
    .map_err(|_| Error::Timeout)?
}
/// Accept one configured two-lane peer; failed/cancelled factories retain no drivers.
pub async fn server_pair(
    sockets: [UdpSocket; 2],
    configs: [Config; 2],
    credentials: ServerPairCredentials<'_>,
) -> Result<PairedCarrier, Error> {
    Ok(server_pair_profile(sockets, configs, credentials, None)
        .await?
        .0)
}
pub(crate) async fn server_pair_profile(
    sockets: [UdpSocket; 2],
    configs: [Config; 2],
    credentials: ServerPairCredentials<'_>,
    native: Option<std::time::Duration>,
) -> Result<(PairedCarrier, Option<std::sync::Arc<crate::native::Domain>>), Error> {
    validate(configs)?;
    let started = Instant::now();
    let budget = Budget::new(configs[0].wire_budget, started);
    let [a, b] = sockets;
    let [ak, bk] = credentials.admissions;
    let [ac, bc] = credentials.cookies;
    timeout(configs[0].pairing_timeout, async {
        let (a, b) = tokio::try_join!(
            prepare_server(
                a,
                configs[0],
                ServerCredentials {
                    tls: credentials.tls,
                    members: credentials.members,
                    admission: ak,
                    cookie: ac
                },
                started,
                budget.clone()
            ),
            prepare_server(
                b,
                configs[1],
                ServerCredentials {
                    tls: credentials.tls,
                    members: credentials.members,
                    admission: bk,
                    cookie: bc
                },
                started,
                budget.second()
            ),
        )?;
        finish_pair(a, b, true, budget, native).await
    })
    .await
    .map_err(|_| Error::Timeout)?
}
fn validate(configs: [Config; 2]) -> Result<(), Error> {
    for config in configs {
        config.validate()?;
    }
    if configs[0].base != configs[1].base
        || configs[0].wire_budget != configs[1].wire_budget
        || configs[0].pairing_timeout != configs[1].pairing_timeout
        || configs[0].profile.protection != configs[1].profile.protection
        || configs[0].profile.lane == configs[1].profile.lane
        || configs[0].bootstrap.path.client == configs[1].bootstrap.path.client
        || configs[0].bootstrap.path.server == configs[1].bootstrap.path.server
        || configs[0].profile.traffic
            != (Traffic::HalfDuplex {
                sender: DataDirection::ClientToServer,
            })
        || configs[1].profile.traffic
            != (Traffic::HalfDuplex {
                sender: DataDirection::ServerToClient,
            })
    {
        return Err(Error::Configuration("incompatible directional pair"));
    }
    Ok(())
}
fn binding(infos: [SessionInfo; 2], configs: [Config; 2], server: bool) -> Result<[u8; 32], Error> {
    validate(configs)?;
    if infos[0].session_id == infos[1].session_id
        || infos[0].member != infos[1].member
        || infos[0].server != infos[1].server
    {
        return Err(Error::Configuration(
            "pair actual identity or session mismatch",
        ));
    }
    let mut hash = digest::Context::new(&digest::SHA256);
    hash.update(b"l2tunnel/openvpn-like/pair/v1\0");
    for (index, (info, config)) in infos.iter().zip(configs).enumerate() {
        if info.config != config.session_config()?
            || info.peer_member != server.then_some(info.member)
        {
            return Err(Error::Configuration("pair actual config or role mismatch"));
        }
        hash.update(&[index as u8]);
        hash.update(&info.session_id);
        hash.update(&info.member.0);
        hash.update(&info.server.0);
        hash.update(&info.config.digest.0);
        hash.update(
            &config
                .profile
                .canonical()
                .map_err(|_| Error::Configuration("pair profile"))?,
        );
    }
    let mut result = [0; 32];
    result.copy_from_slice(hash.finish().as_ref());
    Ok(result)
}
async fn finish_pair(
    mut a: Prepared,
    b: Prepared,
    server: bool,
    budget: Budget,
    native: Option<std::time::Duration>,
) -> Result<(PairedCarrier, Option<std::sync::Arc<crate::native::Domain>>), Error> {
    let info = PairInfo {
        lanes: [*a.connection.info(), *b.connection.info()],
        digest: binding(
            [*a.connection.info(), *b.connection.info()],
            [a.config, b.config],
            server,
        )?,
    };
    let keys = Keys::actual(&a, &b)?;
    join(&mut a.connection, info.digest, keys, server, nonce()?).await?;
    let domain = native.map(|timeout| {
        let (send, receive, slots) = if server {
            (
                b.control.shared.clone(),
                a.control.shared.clone(),
                b.config.packet_slots,
            )
        } else {
            (
                a.control.shared.clone(),
                b.control.shared.clone(),
                a.config.packet_slots,
            )
        };
        crate::native::Domain::new(info.digest, send, receive, slots, timeout)
    });
    let first = domain.as_ref().map(|domain| crate::native::Attachment {
        domain: domain.clone(),
        management: true,
    });
    let second = domain.as_ref().map(|domain| crate::native::Attachment {
        domain: domain.clone(),
        management: false,
    });
    let (a, b) = tokio::try_join!(enable_native(a, first), enable_native(b, second))?;
    Ok((assemble(a, b, info, server, budget), domain))
}
fn assemble(a: Carrier, b: Carrier, info: PairInfo, server: bool, budget: Budget) -> PairedCarrier {
    let (mut ac, at, ar) = a.split();
    let (bc, bt, br) = b.split();
    ac.supervise_pair(&bc);
    let (sender, receiver, inactive_sender, inactive_receiver) = if server {
        (bt, ar, at, br)
    } else {
        (at, br, bt, ar)
    };
    PairedCarrier {
        info,
        control: PairControl {
            controls: [ac, bc],
            inactive_sender,
            inactive_receiver,
            budget,
        },
        sender,
        receiver,
    }
}
struct Keys {
    forward: [hmac::Key; 2],
    reverse: [hmac::Key; 2],
}
impl Keys {
    fn actual(a: &Prepared, b: &Prepared) -> Result<Self, Error> {
        let export = |p: &Prepared, direction| -> Result<hmac::Key, Error> {
            let secret = p.connection.export_key(
                KeyPurpose::LaneJoin,
                direction,
                p.config.profile.lane.0,
            )?;
            Ok(hmac::Key::new(hmac::HMAC_SHA256, secret.expose_bytes()))
        };
        Ok(Self {
            forward: [
                export(a, Direction::ClientToServer)?,
                export(a, Direction::ServerToClient)?,
            ],
            reverse: [
                export(b, Direction::ClientToServer)?,
                export(b, Direction::ServerToClient)?,
            ],
        })
    }
    fn transcript(
        &self,
        group: &[u8; 32],
        challenges: &[[u8; 16]; 2],
        role: u8,
        phase: u8,
    ) -> Vec<u8> {
        // Fixed bounded transcript, never peer-sized allocation.
        let mut bytes = Vec::with_capacity(160);
        bytes.extend_from_slice(b"l2tunnel/openvpn-like/pair/forward/v1\0");
        bytes.extend_from_slice(group);
        bytes.extend_from_slice(&challenges[0]);
        bytes.extend_from_slice(&challenges[1]);
        bytes.extend_from_slice(&[role, phase]);
        let forward = hmac::sign(&self.forward[usize::from(role - 1)], &bytes);
        bytes.clear();
        bytes.extend_from_slice(b"l2tunnel/openvpn-like/pair/reverse/v1\0");
        bytes.extend_from_slice(group);
        bytes.extend_from_slice(&challenges[0]);
        bytes.extend_from_slice(&challenges[1]);
        bytes.extend_from_slice(&[role, phase]);
        bytes.extend_from_slice(forward.as_ref());
        bytes
    }
    fn sign(&self, group: &[u8; 32], challenges: &[[u8; 16]; 2], role: u8, phase: u8) -> [u8; 32] {
        let bytes = self.transcript(group, challenges, role, phase);
        let mut tag = [0; 32];
        tag.copy_from_slice(hmac::sign(&self.reverse[usize::from(role - 1)], &bytes).as_ref());
        tag
    }
    fn verify(
        &self,
        group: &[u8; 32],
        challenges: &[[u8; 16]; 2],
        role: u8,
        phase: u8,
        tag: &[u8],
    ) -> Result<(), Error> {
        hmac::verify(
            &self.reverse[usize::from(role - 1)],
            &self.transcript(group, challenges, role, phase),
            tag,
        )
        .map_err(|_| Error::Configuration("pair exporter proof"))
    }
}
const JOIN_BYTES: usize = 96;
fn frame(
    group: [u8; 32],
    challenge: [u8; 16],
    role: u8,
    phase: u8,
    tag: [u8; 32],
) -> [u8; JOIN_BYTES] {
    let mut bytes = [0; JOIN_BYTES];
    bytes[..4].copy_from_slice(b"OVJ1");
    bytes[4] = phase;
    bytes[5] = role;
    bytes[8..40].copy_from_slice(&group);
    bytes[40..56].copy_from_slice(&challenge);
    bytes[56..88].copy_from_slice(&tag);
    bytes
}
async fn send<S: AsyncWrite + Unpin>(io: &mut S, bytes: [u8; JOIN_BYTES]) -> Result<(), Error> {
    io.write_all(&bytes).await?;
    io.flush().await?;
    Ok(())
}
async fn receive<S: AsyncRead + Unpin>(
    io: &mut S,
    group: [u8; 32],
    role: u8,
    phase: u8,
) -> Result<([u8; 16], [u8; 32]), Error> {
    let mut bytes = [0; JOIN_BYTES];
    io.read_exact(&mut bytes).await?;
    if bytes[..4] != *b"OVJ1"
        || bytes[4] != phase
        || bytes[5] != role
        || bytes[6..8] != [0; 2]
        || bytes[8..40] != group
        || bytes[88..] != [0; 8]
    {
        return Err(Error::Configuration("pair frame scope/state"));
    }
    let mut challenge = [0; 16];
    challenge.copy_from_slice(&bytes[40..56]);
    let mut tag = [0; 32];
    tag.copy_from_slice(&bytes[56..88]);
    Ok((challenge, tag))
}
async fn join<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    group: [u8; 32],
    keys: Keys,
    server: bool,
    challenge: [u8; 16],
) -> Result<(), Error> {
    let role = if server { 2 } else { 1 };
    let peer = 3 - role;
    let mut challenges = [[0; 16]; 2];
    challenges[usize::from(role - 1)] = challenge;
    if !server {
        send(io, frame(group, challenge, role, 1, [0; 32])).await?;
    }
    let (other, tag) = receive(io, group, peer, 1).await?;
    if other == [0; 16] || tag != [0; 32] {
        return Err(Error::Configuration("pair challenge"));
    }
    challenges[usize::from(peer - 1)] = other;
    if server {
        send(io, frame(group, challenge, role, 1, [0; 32])).await?;
    }
    for phase in [2, 3] {
        if !server {
            send(
                io,
                frame(
                    group,
                    challenge,
                    role,
                    phase,
                    keys.sign(&group, &challenges, role, phase),
                ),
            )
            .await?;
        }
        let (observed, tag) = receive(io, group, peer, phase).await?;
        if observed != other {
            return Err(Error::Configuration("pair changed challenge"));
        }
        keys.verify(&group, &challenges, peer, phase, &tag)?;
        if server {
            send(
                io,
                frame(
                    group,
                    challenge,
                    role,
                    phase,
                    keys.sign(&group, &challenges, role, phase),
                ),
            )
            .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
