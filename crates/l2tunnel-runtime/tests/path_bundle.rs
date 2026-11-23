//! Six connected loopback UDP paths carrying captured native frames under one established key binding.
use l2tunnel_fec::path_shards::{Profile, RecordReceiver};
use l2tunnel_fec::{ChannelId, Direction, Epoch, FecContext, GenerationId, SessionId};
use l2tunnel_pipeline::path_ack::{AckBatch, AckReceiver, Observation, Opportunity};
use l2tunnel_pipeline::path_batch::{BatchId, PathBatcher, PathConfig, PathId, Shard};
use l2tunnel_pipeline::path_request::ShardRequest;
use l2tunnel_security as sec;
use std::collections::{BTreeMap, BTreeSet};
use std::net::UdpSocket;
use std::time::Duration;
use zeroize::Zeroizing;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const PATHS: [u8; 6] = [0, 1, 2, 3, 4, 5];
const BASE: u64 = 300;
const UDP_IP: usize = 28;
// The geometry-07 synthetic Linux lab's a-native capture, packet indices 18, 19 and 24.
const FRAMES: &[u8; 4500] = include_bytes!("fixtures/path-bundle-ipv4-tcp.bin");
const CTX: FecContext = FecContext {
    session: SessionId([7; 16]),
    epoch: Epoch(42),
    channel: ChannelId(0),
    direction: Direction::ClientToServer,
};

fn connected() -> Test<Vec<(UdpSocket, UdpSocket)>> {
    let mut addresses = BTreeSet::new();
    let mut pairs = Vec::new();
    for _ in PATHS {
        let a = UdpSocket::bind(("127.0.0.1", 0))?;
        let b = UdpSocket::bind(("127.0.0.1", 0))?;
        a.connect(b.local_addr()?)?;
        b.connect(a.local_addr()?)?;
        for (s, other) in [(&a, &b), (&b, &a)] {
            s.set_read_timeout(Some(Duration::from_secs(2)))?;
            assert_eq!(s.peer_addr()?, other.local_addr()?);
            assert!(addresses.insert(s.local_addr()?));
        }
        pairs.push((a, b));
    }
    Ok(pairs)
}

struct Endpoint {
    tx: sec::Sender,
    rx: sec::Receiver,
}

fn endpoint(role: sec::Role) -> Test<Endpoint> {
    let mut root = sec::SessionRoot::from_split_keys(
        Zeroizing::new([1; 32]),
        Zeroizing::new([2; 32]),
        sec::SessionBinding {
            session: sec::SessionId(CTX.session.0),
            transcript: [8; 32],
        },
        role,
    )?;
    let limits = sec::Limits {
        max_body_bytes: 1500,
        packets_per_key: 8192,
        max_body_bytes_per_key: 1 << 30,
    };
    let protection = sec::Protection::ChaCha20Poly1305;
    Ok(Endpoint {
        tx: root.sender(sec::Purpose::Data, sec::LaneId(0), limits, protection)?,
        rx: root.receiver(sec::Purpose::Data, sec::LaneId(0), limits, protection)?,
    })
}

fn metadata(extra: &[u8]) -> sec::Metadata<'_> {
    sec::Metadata {
        epoch: sec::Epoch(CTX.epoch.0),
        configuration: sec::ConfigDigest([9; 32]),
        extra,
    }
}

fn seal(tx: &mut sec::Sender, path: u8, body: &[u8]) -> Test<(sec::PacketNumber, Vec<u8>)> {
    let mut wire = vec![0; body.len() + tx.overhead()];
    let packet = tx.seal(metadata(&[path]), body, &mut wire)?;
    assert_eq!(wire.len(), packet.bytes);
    Ok((packet.number, wire))
}

fn open(rx: &mut sec::Receiver, path: u8, wire: &[u8]) -> Test<Vec<u8>> {
    let mut out = vec![0; wire.len()];
    let message = rx.open(metadata(&[path]), wire, &mut out)?;
    out.truncate(message.bytes);
    Ok(out)
}

fn datagram(send: &UdpSocket, recv: &UdpSocket, wire: &[u8]) -> Test<Vec<u8>> {
    assert_eq!(send.send(wire)?, wire.len());
    let mut buf = [0; 1600];
    let n = recv.recv(&mut buf)?;
    assert_eq!(&buf[..n], wire);
    Ok(buf[..n].to_vec())
}

fn enqueue(
    batch: &mut PathBatcher,
    slot: u8,
    at: u64,
    id: GenerationId,
    ordinal: u8,
    body: &[u8],
) -> Test {
    batch.enqueue(
        PathId::new(slot)?,
        Duration::from_micros(at),
        None,
        Shard {
            generation: id.0,
            ordinal,
            bytes: body,
        },
    )?;
    Ok(())
}

struct Inbox {
    profile: Profile,
    groups: BTreeMap<GenerationId, RecordReceiver>,
    receipts: AckReceiver,
}

impl Inbox {
    fn data(&mut self, config: PathConfig, slot: u8, seq: u64, now: u64, body: &[u8]) -> Test {
        let packet = config.decode(PathId::new(slot)?, body)?;
        assert_eq!((packet.sequence, packet.count, packet.ack), (seq, 3, None));
        assert_eq!(
            self.receipts.observe_data(slot, seq, now)?,
            Observation::New
        );
        for shard in packet.entries() {
            let group = GenerationId(shard.generation);
            let row = match self.groups.entry(group) {
                std::collections::btree_map::Entry::Occupied(row) => row.into_mut(),
                std::collections::btree_map::Entry::Vacant(row) => row.insert(RecordReceiver::new(
                    self.profile,
                    CTX,
                    group,
                    RecordReceiver::original_length(shard.bytes)?,
                )?),
            };
            row.accept_authenticated(CTX, group, shard.ordinal, shard.bytes)?;
        }
        Ok(())
    }

    fn missing(&mut self) -> Test<u64> {
        let mut mask = 0u64;
        let mut out = [0; 1500];
        assert_eq!(self.groups.len(), 3);
        for (i, frame) in FRAMES.chunks_exact(1500).enumerate() {
            let row = self
                .groups
                .get_mut(&GenerationId(BASE + i as u64))
                .ok_or("unknown group")?;
            match row.recover_into(&mut out) {
                Ok(len) => assert_eq!(&out[..len], frame),
                Err(l2tunnel_fec::Error::InsufficientRank) => mask |= 1 << i,
                Err(other) => return Err(other.into()),
            }
        }
        Ok(mask)
    }
}

fn run(threshold: u8, extra_loss: bool) -> Test {
    let paths = connected()?;
    let mut alice = endpoint(sec::Role::Initiator)?;
    let mut bob = endpoint(sec::Role::Responder)?;
    let configs = PATHS.map(|s| PathConfig {
        mtu: 1500 - usize::from(s) * 20,
        outer_bytes: UDP_IP + alice.tx.overhead(),
        max_hold: Duration::from_micros(u64::from(s) + 1),
        max_entries: 8,
    });
    let mut forward = PathBatcher::new(&configs)?;
    let mut reverse = PathBatcher::new(&configs)?;
    let profile = Profile::new(6, threshold, 1500, 512)?;
    let mut custody = BTreeMap::new();
    for (i, frame) in FRAMES.chunks_exact(1500).enumerate() {
        assert_eq!(&frame[12..20], &[198, 18, 0, 1, 198, 18, 0, 2]);
        assert_eq!(frame[9], 6);
        assert_eq!(&frame[20..24], &[0x98, 0x30, 0x5f, 0x83]);
        assert_eq!(
            u32::from_be_bytes(frame[24..28].try_into()?),
            961541224 + i as u32 * 1448
        );
        let id = GenerationId(BASE + i as u64);
        let members = profile.encode(frame)?;
        for slot in PATHS {
            enqueue(&mut forward, slot, 0, id, slot, &members[usize::from(slot)])?;
        }
        custody.insert(id, members);
    }
    let mut inbox = Inbox {
        profile,
        groups: BTreeMap::new(),
        receipts: AckReceiver::new(&PATHS, 64, 8, 50)?,
    };
    let first_good = 6 - threshold + u8::from(extra_loss);
    let mut blocked: Option<(BatchId, Vec<u8>, Vec<u8>)> = None;
    let mut fresh_bytes = Vec::new();
    for slot in PATHS {
        let idx = usize::from(slot);
        let id = PathId::new(slot)?;
        let due = configs[idx].max_hold;
        assert_eq!(forward.next_wake(id)?, Some(due));
        assert!(
            forward
                .prepare(id, Duration::from_micros(u64::from(slot)), None)?
                .is_none()
        );
        let ready = forward
            .prepare(id, due, None)?
            .ok_or("path missed its deadline")?;
        let (pn, wire) = seal(&mut alice.tx, slot, ready.bytes)?;
        assert_eq!(pn, sec::PacketNumber(u64::from(slot)));
        assert!(wire.len() + UDP_IP <= configs[idx].mtu);
        fresh_bytes.push(wire.len() + UDP_IP);
        if slot == 0 {
            // Inject one carrier WouldBlock before handing anything to the socket.
            // The caller owns this ciphertext until the socket accepts it.
            blocked = Some((ready.id, ready.bytes.to_vec(), wire));
            continue;
        }
        let token = ready.id;
        let received = datagram(&paths[idx].0, &paths[idx].1, &wire)?;
        forward.confirm(token)?;
        if slot >= first_good {
            inbox.data(
                configs[idx],
                slot,
                0,
                10,
                &open(&mut bob.rx, slot, &received)?,
            )?;
        }
    }
    let (token, held, wire) = blocked.ok_or("no blocked path")?;
    let ready = forward
        .prepare(PathId::new(0)?, Duration::from_micros(10), None)?
        .ok_or("lost blocked path")?;
    assert_eq!(
        (ready.id, ready.deadline, ready.bytes),
        (token, configs[0].max_hold, held.as_slice())
    );
    datagram(&paths[0].0, &paths[0].1, &wire)?;
    forward.confirm(token)?;
    // All erased packets were sent successfully and discarded at the receiving socket boundary.
    assert_eq!(inbox.missing()?, if extra_loss { 7 } else { 0 });

    let ack = inbox
        .receipts
        .prepare(11, Opportunity::Piggyback)?
        .ok_or("no ACK")?;
    let mut suffix = vec![0; ack.batch().wire_len()];
    ack.batch().encode(&mut suffix)?;
    let ack_token = ack.token();
    let echo = profile.encode(b"return path probe")?;
    enqueue(&mut reverse, 5, 11, GenerationId(1), 5, &echo[5])?;
    let p5 = PathId::new(5)?;
    let ready = reverse
        .prepare(p5, Duration::from_micros(17), Some(&suffix))?
        .ok_or("no reverse DATA")?;
    assert_eq!(ready.attached_ack, Some(suffix.as_slice()));
    let token = ready.id;
    let (_, wire) = seal(&mut bob.tx, 5, ready.bytes)?;
    let received = datagram(&paths[5].1, &paths[5].0, &wire)?;
    reverse.confirm(token)?;
    inbox.receipts.confirm_paid(ack_token, 17, 17)?;
    let returned = open(&mut alice.rx, 5, &received)?;
    let decoded = configs[5].decode(p5, &returned)?;
    assert_eq!(
        decoded.entries().next().ok_or("missing echo")?.bytes,
        echo[5]
    );
    let ack = AckBatch::decode(decoded.ack.ok_or("missing piggyback")?)?;
    assert_eq!(
        ack.blocks().iter().map(|b| b.path()).collect::<Vec<_>>(),
        (first_good..6).collect::<Vec<_>>()
    );
    assert!(ack.blocks().iter().all(|b| b.acknowledges(0)));

    if extra_loss {
        let mask = inbox.missing()?;
        let rows = (0..3)
            .filter(|i| mask & (1 << i) != 0)
            .map(|i| (BASE + i, vec![0]))
            .collect();
        let feedback = ShardRequest::new(6, rows)?;
        let mut plain = vec![0; feedback.wire_len()];
        feedback.encode(&mut plain)?;
        let (_, request) = seal(&mut bob.tx, 4, &plain)?;
        let received = datagram(&paths[4].1, &paths[4].0, &request)?;
        let named = ShardRequest::decode(6, &open(&mut alice.rx, 4, &received)?)?;
        assert_eq!(named, feedback);
        // Custody is shared between physical paths. Pay ordinal zero on healthy path five.
        for (generation, ordinals) in named.rows() {
            let id = GenerationId(*generation);
            let members = custody.get(&id).ok_or("unknown name")?;
            for &ordinal in ordinals {
                enqueue(
                    &mut forward,
                    5,
                    20,
                    id,
                    ordinal,
                    &members[usize::from(ordinal)],
                )?;
            }
        }
        let ready = forward
            .prepare(p5, Duration::from_micros(26), None)?
            .ok_or("no repair")?;
        assert_eq!(ready.id.sequence(), 1);
        let token = ready.id;
        let (pn, wire) = seal(&mut alice.tx, 5, ready.bytes)?;
        assert_eq!(pn, sec::PacketNumber(6));
        let received = datagram(&paths[5].0, &paths[5].1, &wire)?;
        forward.confirm(token)?;
        let mut corrupt = received.clone();
        corrupt[10] ^= 1;
        assert!(open(&mut bob.rx, 5, &corrupt).is_err());
        assert!(open(&mut bob.rx, 4, &received).is_err());
        inbox.data(configs[5], 5, 1, 27, &open(&mut bob.rx, 5, &received)?)?;
        assert!(open(&mut bob.rx, 5, &received).is_err());
        assert_eq!(inbox.missing()?, 0);

        assert!(
            inbox
                .receipts
                .prepare(76, Opportunity::Standalone)?
                .is_none()
        );
        let ack = inbox
            .receipts
            .prepare(77, Opportunity::Standalone)?
            .ok_or("missed ACK deadline")?;
        let token = ack.token();
        let mut body = vec![0; ack.batch().wire_len()];
        ack.batch().encode(&mut body)?;
        let (_, wire) = seal(&mut bob.tx, 3, &body)?;
        let received = datagram(&paths[3].1, &paths[3].0, &wire)?;
        inbox.receipts.confirm_paid(token, 77, 77)?;
        let parsed = AckBatch::decode(&open(&mut alice.rx, 3, &received)?)?;
        assert!(
            parsed
                .blocks()
                .iter()
                .any(|b| b.path() == 5 && b.acknowledges(1))
        );
        assert_eq!(inbox.receipts.next_deadline(), None);
    }
    assert_eq!(fresh_bytes, [if threshold == 5 { 979 } else { 1204 }; 6]);
    eprintln!(
        "6/{threshold}, extra loss {extra_loss}, protected UDP payload + IPv4/UDP header {fresh_bytes:?}"
    );
    Ok(())
}

#[test]
fn six_connected_udp_paths_preserve_thresholds_and_reroute_named_shards() -> Test {
    for k in [5, 4] {
        run(k, false)?;
        run(k, true)?;
    }
    Ok(())
}

#[test]
fn smaller_mtu_flushes_two_records_while_another_path_accumulates_three() -> Test {
    let paths = connected()?;
    let mut alice = endpoint(sec::Role::Initiator)?;
    let mut bob = endpoint(sec::Role::Responder)?;
    let configs = [1000, 1300].map(|mtu| PathConfig {
        mtu,
        outer_bytes: UDP_IP + alice.tx.overhead(),
        max_hold: Duration::from_micros(50),
        max_entries: 8,
    });
    let mut tx = PathBatcher::new(&configs)?;
    let profile = Profile::new(6, 4, 1500, 512)?;
    for (i, frame) in FRAMES.chunks_exact(1500).enumerate() {
        let members = profile.encode(frame)?;
        for s in [0, 1] {
            enqueue(
                &mut tx,
                s,
                0,
                GenerationId(BASE + i as u64),
                s,
                &members[usize::from(s)],
            )?;
        }
    }
    assert!(tx.prepare(PathId::new(1)?, Duration::ZERO, None)?.is_none());
    for (s, now, seq, groups) in [
        (0, 0, 0, &[300, 301][..]),
        (1, 50, 0, &[300, 301, 302]),
        (0, 50, 1, &[302]),
    ] {
        let i = usize::from(s);
        let p = PathId::new(s)?;
        let ready = tx
            .prepare(p, Duration::from_micros(now), None)?
            .ok_or("missing MTU packet")?;
        let (_, wire) = seal(&mut alice.tx, s, ready.bytes)?;
        assert!(wire.len() + UDP_IP <= configs[i].mtu);
        let token = ready.id;
        let received = datagram(&paths[i].0, &paths[i].1, &wire)?;
        tx.confirm(token)?;
        let plain = open(&mut bob.rx, s, &received)?;
        let actual = configs[i].decode(p, &plain)?;
        assert_eq!(actual.sequence, seq);
        assert_eq!(
            actual.entries().map(|v| v.generation).collect::<Vec<_>>(),
            groups
        );
    }
    Ok(())
}
