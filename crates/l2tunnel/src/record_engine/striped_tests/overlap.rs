use super::*;
use crate::{
    cover,
    secure_record::{
        Class, Opened, Records, Scope,
        compact::{AUTHENTICATED_OVERHEAD, Kind, Layout, Selection},
    },
    security,
};
use std::{net::UdpSocket, time::Duration};
use zeroize::Zeroizing;

const IP_UDP: usize = 20 + 8;
const OVERHEAD: usize = IP_UDP + AUTHENTICATED_OVERHEAD;

struct Peer {
    socket: UdpSocket,
    records: Records,
    engine: Engine,
    scope: Scope,
}

impl Peer {
    fn new(config: configuration::Configuration, role: Role) -> TestResult<Self> {
        let ctx = context(role);
        let scope = Scope {
            epoch: security::Epoch(ctx.epoch),
            configuration: security::ConfigDigest(config.digest()?.0),
        };
        let (local, remote, protocol_role) = match role {
            Role::Client => (1, 2, security::Role::Initiator),
            Role::Server => (2, 1, security::Role::Responder),
        };
        let root = security::SessionRoot::from_split_keys(
            Zeroizing::new([1; 32]),
            Zeroizing::new([2; 32]),
            security::SessionBinding {
                session: security::SessionId(ctx.session.to_be_bytes()),
                transcript: [5; 32],
            },
            protocol_role,
        )?;
        let records = Records::new_compact_with_layout(
            root,
            security::LaneId(7),
            security::Limits {
                max_body_bytes: 1024,
                packets_per_key: 1024,
                max_body_bytes_per_key: 1 << 20,
            },
            cover::Config::new(
                cover::Appearance::QuicLike,
                cover::ConnectionIds {
                    local: cover::ConnectionId([local; 8]),
                    peer: cover::ConnectionId([remote; 8]),
                },
                cover::MediaConfig {
                    local_ssrc: cover::Ssrc(local.into()),
                    peer_ssrc: cover::Ssrc(remote.into()),
                    payload_type: 96,
                },
                cover::Limits {
                    max_packet_bytes: 1500,
                    max_protected_bytes: 1400,
                },
            )?,
            Scope {
                epoch: security::Epoch(1),
                configuration: security::ConfigDigest([7; 32]),
            },
            scope,
            Selection {
                protection: security::compact::Protection::ChaCha20Poly1305,
                limits: security::compact::Selection {
                    max_forward_packets: 4096,
                    max_failed_checks: 128,
                },
            },
            Layout::Carrier,
        )?;
        let mut engine = Engine::new_functional(
            config,
            ctx,
            Geometry {
                forward_overhead_bytes: OVERHEAD,
                reverse_overhead_bytes: OVERHEAD,
            },
            NativeLimits {
                stall_micros: 50_000,
            },
        )?;
        engine.enable_compact_wire(OVERHEAD)?;
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.set_read_timeout(Some(Duration::from_secs(2)))?;
        Ok(Self {
            records,
            engine,
            scope,
            socket,
        })
    }

    fn output(
        &mut self,
        now: Tick,
        data: bool,
    ) -> TestResult<(Emission, Vec<u8>, CarrierOutputToken)> {
        let mut bytes = [0; 1500];
        let mut budget = OutboundBudget {
            packets: 1,
            wire_bytes: 1500,
        };
        let mut units = [receiver::UnitWitness {
            identity: receiver::RecordIdentity {
                channel: receiver::ChannelId(0),
                record: receiver::RecordId(0),
            },
            index: 0,
            count: 1,
        }; 4];
        let number = if data {
            self.records.next_number(Class::User)
        } else {
            self.records.next_feedback_number()
        };
        let e = self
            .engine
            .poll(now, number.0, data, &mut bytes, &mut budget, &mut units)?
            .ok_or("missing striped output")?;
        Ok((
            e,
            bytes[..e.bytes].to_vec(),
            self.engine
                .pending_carrier_output()
                .ok_or("missing carrier token")?,
        ))
    }

    // Seal and open exactly one packet on the same connected socket pair.
    fn send(&mut self, peer: &mut Self, kind: Kind, body: &[u8]) -> TestResult<(Opened, Vec<u8>)> {
        let mut packet = [0; 1500];
        let meta = cover::PacketMeta {
            phase: cover::Phase::Established,
            packet_number: cover::PacketNumber(0),
            media_timestamp: cover::MediaTimestamp(0),
        };
        let s = self.records.seal_compact_with_carrier(
            kind,
            self.scope,
            meta,
            body,
            &[],
            &mut [0; 1500],
            &mut packet,
        )?;
        assert_eq!(self.socket.send(&packet[..s.bytes])?, s.bytes);
        let n = peer.socket.recv(&mut packet)?;
        assert_eq!(n + IP_UDP, body.len() + OVERHEAD);
        let mut plaintext = [0; 1024];
        let opened = peer.records.open_compact_with_carrier(
            &packet[..n],
            &[],
            &mut [0; 1500],
            &mut plaintext,
        )?;
        assert_eq!(opened.scope, peer.scope);
        assert!(opened.strongly_authenticated);
        assert_eq!(opened.feedback, kind == Kind::Feedback);
        assert_eq!(&plaintext[..opened.bytes], body);
        Ok((opened, plaintext[..opened.bytes].to_vec()))
    }
}

#[test]
fn same_tag_real_udp_class_and_delayed_feedback_receipt_preserve_native_debt() -> TestResult {
    const N: u8 = 18;
    let original = fixture()?;
    let desc = original.descriptor();
    let configuration::Profile::Striped {
        mut forward,
        mut reverse,
    } = *desc.profile()
    else {
        return Err("expected striped".into());
    };
    forward.profile.data_cells = 17;
    forward.overhead_bytes = OVERHEAD;
    reverse.overhead_bytes = OVERHEAD;
    forward.source_limit = 40;
    forward.expanded_limit = 200_000;
    forward.hold_micros = 30_000;
    let config = configuration::Configuration::new(
        original.envelope(),
        configuration::Descriptor::new(
            desc.path_mtu(),
            desc.duplex(),
            *desc.direction(Role::Client).common(),
            *desc.direction(Role::Server).common(),
            configuration::Profile::Striped { forward, reverse },
        )?,
    )?;
    let mut a = Peer::new(config, Role::Client)?;
    let mut b = Peer::new(config, Role::Server)?;
    a.socket.connect(b.socket.local_addr()?)?;
    b.socket.connect(a.socket.local_addr()?)?;
    let mut frames = Vec::new();
    for i in 0..N {
        let at = 1000 * u64::from(i);
        let frame = packet(true, 5100, 54, i + 1);
        a.engine.enqueue_borrowed(Tick(at), &frame)?;
        assert!(a.engine.admit_borrowed(Tick(at))?.is_some());
        a.engine.tick(Tick(at))?;
        // Force one normal Packed source per native, before group hold expires.
        a.engine.tick(Tick(at + 600))?;
        frames.push(frame);
    }
    let time = Tick(18_000);
    let mut wire = Vec::new();
    for ordinal in 0..N {
        let (meta, bytes, token) = a.output(time, true)?;
        assert_eq!(meta.kind, EmissionKind::Source(SourceForm::SystematicFec));
        assert_eq!(bytes[0], 0x11);
        assert_eq!(forward.profile.inspect(&bytes)?.1.index(), ordinal);
        if ordinal == 0 {
            let (wrong, plain) = a.send(&mut b, Kind::Feedback, &bytes)?;
            assert!(b.engine.inspect_peer_class(&plain, wrong.feedback).is_err());
            assert!(b.engine.drained()?);
        }
        let record = a.send(&mut b, Kind::Data, &bytes)?;
        assert_eq!(meta.wire_bytes, bytes.len() + OVERHEAD);
        assert_eq!(meta.security_number, record.0.number.0);
        a.engine.confirm_carrier_output(time, token)?;
        wire.push(record);
    }
    let mut held = None;
    let mut at = time;
    for (i, (opened, mut plain)) in wire.into_iter().enumerate() {
        let kind = b.engine.inspect_peer_class(&plain, opened.feedback)?;
        b.engine
            .accept_authenticated(at, opened.number.0, kind, &mut plain)?;
        let mut out = [0; 1024];
        let native = (0..8)
            .find_map(
                |_| match b.engine.prepare_native(at, 8, Tick(100_000), &mut out) {
                    Ok(NativePreparation::Ready(p)) => Some(Ok(p)),
                    Ok(_) => None,
                    Err(e) => Some(Err(e)),
                },
            )
            .ok_or("expected native delivery")??;
        assert_eq!(&out[..native.bytes()], frames[i].as_slice());
        b.engine.commit_native(at, native.token())?;
        if i == 0 {
            at = Tick(at.0 + forward.timing.ack_delay);
            let (emission, body, token) = b.output(at, false)?;
            assert_eq!(body[0], 0x11);
            let record = b.send(&mut a, Kind::Feedback, &body)?;
            assert_eq!(emission.wire_bytes, body.len() + OVERHEAD);
            assert_eq!(emission.security_number, record.0.number.0);
            held = Some((at, token, record));
        }
        at.0 += 1;
    }
    let (accepted, token, (opened, mut first)) = held.ok_or("held first-prefix feedback")?;
    let sending = a.engine.striped_sources().ok_or("mixed producer")?;
    let receiving = b.engine.striped_sources().ok_or("mixed consumer")?;
    assert_eq!(sending.send_outstanding, usize::from(N));
    assert_eq!(receiving.receive_uncommitted_in_groups, 0);
    assert_eq!(receiving.receive_uncommitted_through_sealed, 0);
    assert_eq!(receiving.receive_sealed, receiving.receive_confirmed);
    // The socket completed the first prefix earlier. All remaining members
    // reached native commit before the local callback consumed that token.
    b.engine.confirm_carrier_output_at(at, accepted, token)?;
    let due = Tick(at.0 + forward.timing.ack_delay);
    let (emission, body, token) = b.output(due, false)?;
    assert_eq!(body[0], 0x11);
    assert_ne!(body, first);
    let (wrong, plain) = b.send(&mut a, Kind::Data, &body)?;
    assert!(a.engine.inspect_peer_class(&plain, wrong.feedback).is_err());
    assert!(!a.engine.drained()?);
    let (final_meta, mut final_plain) = b.send(&mut a, Kind::Feedback, &body)?;
    assert_eq!(emission.wire_bytes, body.len() + OVERHEAD);
    assert_eq!(emission.security_number, final_meta.number.0);
    b.engine.confirm_carrier_output(due, token)?;
    let kind = a
        .engine
        .inspect_peer_class(&final_plain, final_meta.feedback)?;
    a.engine
        .accept_authenticated(due, final_meta.number.0, kind, &mut final_plain)?;
    assert!(a.engine.drained()?);
    let cleared = a.engine.striped_sources().ok_or("mixed final producer")?;
    assert_eq!(cleared.send_outstanding, 0);
    assert_eq!(cleared.send_confirmed, receiving.receive_confirmed);
    // Delayed older logical evidence cannot recreate debt or regress the prefix.
    let kind = a.engine.inspect_peer_class(&first, opened.feedback)?;
    a.engine
        .accept_authenticated(due, opened.number.0, kind, &mut first)?;
    assert!(a.engine.drained()?);
    assert_eq!(
        b.engine.native_counts()?.committed.iter().sum::<u64>(),
        u64::from(N)
    );
    Ok(())
}
