//! Current Common native/device and original-carrier fixtures, without privileges.

#[path = "transport_common_carrier_tests.rs"]
mod common_carrier;
#[path = "transport_common_tests.rs"]
mod common_selected;
#[path = "transport_envelope_tests.rs"]
mod envelope;

use super::*;
use l2tunnel_handshake as hs;
use l2tunnel_identity as identity;
use l2tunnel_udp_control as gate;
use std::{
    net::{SocketAddr, UdpSocket as StdUdp},
    os::unix::net::UnixDatagram,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use zeroize::Zeroizing;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct Entropy(u8);
impl hs::Entropy for Entropy {
    fn fill(&mut self, output: &mut [u8; 32]) -> std::result::Result<(), hs::EntropyError> {
        output.fill(self.0);
        self.0 = self.0.wrapping_add(1);
        Ok(())
    }
}
fn key() -> Result<identity::IdentityKey> {
    // Public RFC8032 vector only, never deployed provisioning material.
    let text = "3051020101300506032b6570042204209d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60812100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    let bytes = text
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect::<Result<Vec<u8>>>()?;
    Ok(identity::IdentityKey::from_pkcs8(&bytes)?)
}
fn appearance(kind: cover::Appearance, client: bool) -> Result<cover::Config> {
    let (local, peer) = if client { (1, 2) } else { (2, 1) };
    Ok(cover::Config::new(
        kind,
        cover::ConnectionIds {
            local: cover::ConnectionId([local; 8]),
            peer: cover::ConnectionId([peer; 8]),
        },
        cover::MediaConfig {
            local_ssrc: cover::Ssrc(u32::from(local)),
            peer_ssrc: cover::Ssrc(u32::from(peer)),
            payload_type: 96,
        },
        cover::Limits {
            max_packet_bytes: 1500,
            max_protected_bytes: 1400,
        },
    )?)
}
fn config(_kind: cover::Appearance) -> Config {
    let codec = swift::Config {
        datagram_bytes: 512,
        window: 8,
        repair_numerator: 1,
        repair_denominator: 4,
        flow_sources: 64,
        queue_bytes: 65536,
        max_packet: 513,
        flush_micros: 0,
        feedback_micros: 1000,
        tail_micros: 10000,
        min_rto_micros: 10000,
        max_rto_micros: 100000,
    };
    let direction = policy::Direction {
        records: records::Config {
            codec,
            channels: 2,
            layer: records::Layer::Ethernet,
            max_native: 512,
        },
        bytes_per_second: 1_000_000,
    };
    let overhead = 28 + record::compact::AUTHENTICATED_OVERHEAD;
    Config {
        path_mtu: 1500,
        send: direction,
        receive: direction,
        policy: policy::Settings {
            transaction_micros: 1_000_000,
            max_outbound: 8,
        },
        security: security::Limits {
            max_body_bytes: 1300,
            // Four credit window ceilings (MOD-RCREDIT-09); shorter key
            // rotation is covered by l2tunnel-security's own tests.
            packets_per_key: 8192,
            // Room for 8,192 maximum bodies, so keys rotate by packet count.
            max_body_bytes_per_key: 16 << 20,
        },
        control: delivery::Settings {
            recovery: recovery::ArqConfig {
                max_source_bytes: 192,
                send_bytes: 6144,
                receive_bytes: 6144,
                send_records: 32,
                receive_records: 32,
                initial_rto: Duration::from_millis(10),
                maximum_rto: Duration::from_millis(100),
                ack_delay: Duration::from_millis(1),
                max_retries: 16,
            },
            interval: Duration::from_millis(1),
            packets_per_interval: 16,
            bytes_per_interval: 65536,
            wire_overhead: overhead,
        },
        control_epoch: security::Epoch(1),
        streams: None,
        data_epoch: security::Epoch(1),
        wire: WireBudget { burst_bytes: 4096 },
        work: WorkBudget {
            receive_interval: Duration::from_millis(1),
            receive_packets: 64,
            send_batch: 16,
            native_read_batch: 16,
            native_write_batch: 16,
        },
        rolling_work: None,
        ack_coalescing: None,
        connection_ingress: None,
        rolling_fragments: None,
        rolling_ingress: None,
        credit: Some(l2tunnel_flow_control::session_credit::Config {
            floor_datagrams: 64,
            ceiling_datagrams: 2048,
            floor_bytes: 102_400,
            ceiling_bytes: 16 << 20,
            period: Duration::from_millis(10),
            idle_period: Duration::from_millis(250),
        }),
        native: NativeBudget {
            pending_packets: 16,
            pending_bytes: 8192,
            stall_timeout: Duration::from_secs(1),
        },
        lifetime: Lifetime {
            lease: Duration::from_secs(5),
            ping_interval: Duration::from_millis(20),
            pong_timeout: Duration::from_millis(500),
        },
        report_interval: Some(Duration::from_millis(5)),
    }
}
struct Device {
    socket: UnixDatagram,
    blocked: bool,
    wouldblock: Option<Arc<AtomicUsize>>,
}
impl AsRawFd for Device {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.socket.as_raw_fd()
    }
}
impl PacketDevice for Device {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ethernet
    }
    fn receive(&mut self, output: &mut [u8]) -> io::Result<Option<usize>> {
        match self.socket.recv(output) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error),
        }
    }
    fn transmit(&mut self, packet: &[u8]) -> io::Result<()> {
        if self.blocked {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        let length = match self.socket.send(packet) {
            Ok(length) => length,
            Err(error) => {
                if error.kind() == io::ErrorKind::WouldBlock
                    && let Some(counter) = &self.wouldblock
                {
                    counter.fetch_add(1, Ordering::Relaxed);
                }
                return Err(error);
            }
        };
        if length == packet.len() {
            Ok(())
        } else {
            Err(io::Error::from(io::ErrorKind::WriteZero))
        }
    }
}
fn context(established: &establish::Established) -> member::Settings {
    member::Settings {
        context: identity::Context {
            session: established.binding.session,
            transcript: established.binding.transcript,
            configuration: established.authenticated.configuration,
            carrier: established.authenticated.carrier,
            outer: established.authenticated.outer,
            initiator_noise: identity::NoisePublicKey(established.peers.initiator.0),
            responder_noise: identity::NoisePublicKey(established.peers.responder.0),
        },
        retry_interval: Duration::from_millis(10),
        max_attempts: 32,
        receive_interval: Duration::from_millis(1),
        receive_packets_per_interval: 64,
    }
}
async fn authenticated_for_configuration(
    socket: StdUdp,
    path: gate::Path,
    kind: cover::Appearance,
    client: bool,
    selected_cover: Option<cover::Config>,
    configuration: security::ConfigDigest,
) -> Result<member::Parts> {
    let local = hs::LocalSecret::new(Zeroizing::new(if client { [11; 32] } else { [22; 32] }));
    let initiator = hs::LocalSecret::new(Zeroizing::new([11; 32])).public_key();
    let responder = hs::LocalSecret::new(Zeroizing::new([22; 32])).public_key();
    let peers = establish::Peers {
        initiator,
        responder,
    };
    let mut gate = gate::Config::new(path, [30; 32], 1)?;
    gate.outer_overhead = 28
        + 1
        + if kind == cover::Appearance::QuicLike {
            30
        } else {
            14
        };
    gate.arq.max_source_bytes = 100;
    gate.arq.send_bytes = 3200;
    gate.arq.receive_bytes = 3200;
    gate.arq.initial_rto = Duration::from_millis(10);
    gate.arq.maximum_rto = Duration::from_millis(100);
    gate.arq.ack_delay = Duration::from_millis(1);
    gate.arq.max_retries = 32;
    gate.cookie_ttl = Duration::from_secs(2);
    gate.handshake_timeout = Duration::from_secs(2);
    gate.initial_rto = Duration::from_millis(10);
    gate.maximum_rto = Duration::from_millis(100);
    gate.gate_attempts = 32;
    let setup = establish::Config {
        gate,
        cover: match selected_cover {
            Some(selected) => selected,
            None => appearance(kind, client)?,
        },
        profile: hs::Profile::Ik,
        binding: establish::Binding {
            configuration: configuration.0,
            carrier: [4; 32],
            outer: [5; 32],
            member: [6; 32],
        },
        receive_packets_per_interval: 64,
    };
    let member_key = key()?;
    let allowlist = identity::Allowlist::new(&[member_key.public_key()])?;
    let identity = establish::Identity {
        local,
        peer: if client { responder } else { initiator },
        psk: None,
    };
    let now = Instant::now();
    let deadline = now + Duration::from_secs(2);
    let socket = tokio::net::UdpSocket::from_std(socket)?;
    let mut entropy = Entropy(if client { 40 } else { 60 });
    let established = if client {
        establish::connect(
            socket,
            setup,
            identity,
            gate::Secret::new([7; 32]),
            deadline,
            &mut entropy,
        )
        .await?
    } else {
        let mut admission = establish::ServerAdmission::new(
            setup,
            peers,
            gate::Secret::new([7; 32]),
            gate::Secret::new([8; 32]),
            now,
        )?;
        establish::accept(socket, identity, &mut admission, deadline, &mut entropy).await?
    };
    let settings = context(&established);
    Ok(if client {
        member::connect(established, &member_key, settings).await?
    } else {
        member::accept(established, allowlist, settings).await?
    }
    .into_parts())
}
fn ethernet(number: u8) -> Vec<u8> {
    let mut packet = vec![0; 256];
    packet[0..6].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
    packet[6..12].copy_from_slice(&[7, 8, 9, 10, 11, 12]);
    packet[12..14].copy_from_slice(&[0x88, 0xb5]);
    packet[14..].fill(number);
    packet
}

#[test]
fn canonical_contract_changes_for_every_runtime_class_but_not_local_reporting() -> Result {
    let initial = config(cover::Appearance::QuicLike);
    let digest = initial.canonical_digest()?;
    let mut changed = initial;
    changed.report_interval = Some(Duration::from_millis(17));
    assert_eq!(changed.canonical_digest()?, digest);
    for change in [0, 1, 2, 3, 4, 5, 6, 7, 8] {
        let mut value = initial;
        match change {
            0 => value.send.bytes_per_second += 1,
            1 => value.receive.records.codec.tail_micros += 1,
            2 => value.native.pending_bytes += 1,
            3 => value.work.receive_packets += 1,
            4 => value.security.packets_per_key += 1,
            5 => value.control.recovery.max_retries += 1,
            6 => value.data_epoch.0 += 1,
            7 => value.lifetime.lease += Duration::from_nanos(1),
            _ => value.policy.transaction_micros += 1,
        };
        assert_ne!(value.canonical_digest()?, digest);
    }
    Ok(())
}
#[test]
fn bucket_is_exact_bounded_and_does_not_reset_credit_when_rate_changes() -> Result {
    let mut bucket = Bucket::new(8000, 2000);
    bucket.charge(2000)?;
    assert_eq!(bucket.allowance(), 0);
    assert_eq!(bucket.ready_at(80)?, 10000);
    bucket.refill(5000)?;
    assert_eq!(bucket.allowance(), 40);
    bucket.rate = 16000;
    bucket.refill(10000)?;
    assert_eq!(bucket.allowance(), 120);
    assert!(bucket.charge(121).is_err());
    assert_eq!(bucket.allowance(), 120);
    assert!(bucket.refill(9999).is_err());
    assert!(bucket.ready_at(2001).is_err());
    Ok(())
}

#[test]
fn fixed_resource_control_and_feedback_minima_are_not_silently_relaxed() -> Result {
    let initial = config(cover::Appearance::MediaLike);
    initial.validate()?;
    for case in 0..6 {
        let mut value = initial;
        match case {
            0 => value.control_epoch.0 = 0,
            1 => value.data_epoch.0 = 0,
            2 => value.send.records.codec.datagram_bytes = 139,
            3 => value.control.recovery.max_source_bytes = 191,
            4 => value.work.receive_interval = Duration::ZERO,
            _ => value.native.pending_bytes = 511,
        };
        assert!(value.validate().is_err());
    }
    Ok(())
}

#[test]
fn submicrosecond_runtime_deadlines_never_become_zero_quota_or_lease() -> Result {
    for case in 0..6 {
        let mut value = config(cover::Appearance::QuicLike);
        match case {
            0 => value.lifetime.lease = Duration::from_nanos(999),
            1 => value.lifetime.ping_interval = Duration::from_nanos(1),
            2 => value.lifetime.pong_timeout = Duration::from_nanos(999),
            3 => value.native.stall_timeout = Duration::from_nanos(999),
            4 => value.work.receive_interval = Duration::from_nanos(999),
            _ => value.report_interval = Some(Duration::from_nanos(999)),
        };
        assert!(value.validate().is_err());
    }
    let mut value = config(cover::Appearance::QuicLike);
    value.work.receive_interval = Duration::from_micros(1);
    value.validate()?;
    Ok(())
}

async fn parts_pair_with_configuration(
    kind: cover::Appearance,
    selected: Option<[cover::Config; 2]>,
    configuration: security::ConfigDigest,
) -> Result<(member::Parts, member::Parts)> {
    let a = StdUdp::bind("127.0.0.1:0")?;
    let b = StdUdp::bind("127.0.0.1:0")?;
    let path = gate::Path {
        client: a.local_addr()?,
        server: b.local_addr()?,
    };
    a.connect(path.server)?;
    b.connect(path.client)?;
    a.set_nonblocking(true)?;
    b.set_nonblocking(true)?;
    let [client_cover, server_cover] = selected.map_or([None, None], |[client, server]| {
        [Some(client), Some(server)]
    });
    tokio::try_join!(
        authenticated_for_configuration(a, path, kind, true, client_cover, configuration),
        authenticated_for_configuration(b, path, kind, false, server_cover, configuration)
    )
}
