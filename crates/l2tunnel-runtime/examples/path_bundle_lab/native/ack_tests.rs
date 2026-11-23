use super::*;
use l2tunnel_fec::path_shards::Profile;
use l2tunnel_fec::{ChannelId, Direction, Epoch, FecContext, SessionId};
use l2tunnel_pipeline::path_batch::Shard;

const CTX: FecContext = FecContext {
    session: SessionId([1; 16]),
    epoch: Epoch(1),
    channel: ChannelId(0),
    direction: Direction::ClientToServer,
};

// Complete IPv4/IPv6 packets including IP/TCP checksums. Negative examples also
// have valid checksums so each exercises its identified structural fallback.
const ACK: &str =
    "45000028000140004006b6cbc0000201c000020201bbcb010000000500000008501020003f070000";
const V6_TS_SACK: &str = "60000000002c064020010db800000000000000000000000120010db800000000000000000000000201bbcb010000000500000008b0102000f82d00000101080a00000005000000030101050a000000140000001e";
const DATA: &str =
    "45000029000140004006b6cac0000201c000020201bbcb01000000050000000850102000340600000b";
const SYN_ACK: &str =
    "45000028000140004006b6cbc0000201c000020201bbcb010000000500000008501220003f050000";
const FIN_ACK: &str =
    "45000028000140004006b6cbc0000201c000020201bbcb010000000500000008501120003f060000";
const RST_ACK: &str =
    "45000028000140004006b6cbc0000201c000020201bbcb010000000500000008501420003f030000";
const FRAGMENT: &str =
    "45000028000120004006d6cbc0000201c000020201bbcb010000000500000008501020003f070000";
const BAD_OPTIONS: &str =
    "4500002c000140004006b6c7c0000201c000020201bbcb010000000500000008601020002701000008020000";

fn bytes(input: &str) -> Vec<u8> {
    (0..input.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&input[i..i + 2], 16).unwrap())
        .collect()
}

fn receive(q: &mut Queue, rx: &mut Receiver, gid: u64, packet: &[u8]) -> Result<()> {
    let shards = Profile::new(3, 2, 1500, 1000)?.encode(packet)?;
    for ordinal in [2, 1, 2] {
        let shard = Shard {
            generation: gid,
            ordinal,
            bytes: &shards[usize::from(ordinal)],
        };
        if rx.accept(CTX, shard)? {
            q.push(gid, 10, rx)?;
        }
    }
    Ok(())
}

#[test]
fn only_complete_recognized_tcp_acks_can_cross_a_gap() {
    assert!(ack::eligible(&bytes(ACK)));
    assert!(ack::eligible(&bytes(V6_TS_SACK)));
    for input in [DATA, SYN_ACK, FIN_ACK, RST_ACK, FRAGMENT, BAD_OPTIONS] {
        assert!(!ack::eligible(&bytes(input)));
    }
    let mut corrupted = bytes(ACK);
    corrupted[36] ^= 1;
    assert!(!ack::eligible(&corrupted));
    assert!(!ack::eligible(&bytes(ACK)[..39]));
    assert!(!ack::eligible(&[bytes(ACK), vec![0]].concat()));
}

#[test]
fn selective_ack_actual_write_preserves_older_data_and_commits_once() -> Result<()> {
    let mut rx = Receiver::new(CTX, 3, 2, 1500, 1000, 8)?;
    let mut q = Queue::new(Mode::OrderedTcpData);
    let data = bytes(DATA);
    let ack = bytes(V6_TS_SACK);
    receive(&mut q, &mut rx, 1, &data)?;
    assert!(q.next(0).is_none());
    receive(&mut q, &mut rx, 2, &ack)?;
    assert_eq!(
        q.write_next(&mut rx, |_, _| Err(io::ErrorKind::WouldBlock.into()))?,
        Handoff::WouldBlock
    );
    assert!(!rx.confirmation(0)?.0.acknowledges(2));
    let mut written = Vec::new();
    q.write_next(&mut rx, |id, packet| {
        assert_eq!(packet, ack);
        written.push(id);
        Ok(())
    })?;
    assert_eq!(rx.confirmed_prefix(), 0);
    let coverage = rx.confirmation(0)?.0;
    assert!(coverage.acknowledges(2) && !coverage.acknowledges(1) && !coverage.acknowledges(0));
    receive(&mut q, &mut rx, 2, &ack)?;
    assert!(q.next(0).is_none());
    receive(&mut q, &mut rx, 0, &data)?;
    for _ in 0..2 {
        q.write_next(&mut rx, |id, packet| {
            assert_eq!(packet, data);
            written.push(id);
            Ok(())
        })?;
    }
    assert_eq!(written, [2, 0, 1]);
    assert_eq!(rx.confirmed_prefix(), 3);
    assert_eq!(q.len(), 0);
    Ok(())
}
