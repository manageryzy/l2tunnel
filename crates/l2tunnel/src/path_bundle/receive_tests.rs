use super::*;
use l2tunnel_fec::{ChannelId, Direction, Epoch, FecContext, SessionId, path_shards::Profile};
use l2tunnel_pipeline::{path_batch::Shard, path_request::ShardRequest};

const CONTEXT: FecContext = FecContext {
    session: SessionId([2; 16]),
    channel: ChannelId(0),
    epoch: Epoch(1),
    direction: Direction::ClientToServer,
};

#[test]
fn later_records_commit_even_while_the_oldest_needs_named_shards()
-> Result<(), Box<dyn std::error::Error>> {
    let mut rx = Receiver::new(CONTEXT, 6, 5, 1500, 1451, 8)?;
    let f = Profile::new(6, 5, 1500, 1451)?;
    let first = f.encode(b"old")?;
    let later = f.encode(b"new")?;
    for (i, body) in later.iter().take(5).enumerate() {
        assert_eq!(
            rx.accept(
                CONTEXT,
                Shard {
                    generation: 1,
                    ordinal: i as u8,
                    bytes: body
                }
            )?,
            i == 4
        );
    }
    assert!(rx.ready(0).is_none());
    assert_eq!(rx.ready(1), Some(b"new".as_slice()));
    assert!(rx.commit(1)?);
    assert!(!rx.commit(1)?);
    assert_eq!(
        rx.confirmation(0)?.0.ranges(),
        std::slice::from_ref(&(1..2))
    );
    assert_eq!(rx.confirmed_prefix(), 0);
    assert_eq!(rx.missing_from(0, 4), [4, 5, 0, 1, 2]);
    for i in [5, 0, 1, 3] {
        assert!(!rx.accept(
            CONTEXT,
            Shard {
                generation: 0,
                ordinal: i,
                bytes: &first[usize::from(i)]
            }
        )?);
    }
    assert_eq!(rx.missing(0), vec![2]);
    assert_eq!(rx.missing_from(0, 3), [4]);
    assert!(rx.accept(
        CONTEXT,
        Shard {
            generation: 0,
            ordinal: 2,
            bytes: &first[2]
        }
    )?);
    assert!(rx.missing(0).is_empty());
    assert_eq!(rx.ready(0), Some(b"old".as_slice()));
    rx.commit(0)?;
    assert_eq!(rx.confirmed_prefix(), 2);
    assert_eq!(rx.retained_groups(), 0);
    assert!(!rx.accept(
        CONTEXT,
        Shard {
            generation: 0,
            ordinal: 4,
            bytes: &first[4]
        }
    )?);
    Ok(())
}

#[test]
fn selective_ack_pages_and_old_group_requests_stay_within_the_window()
-> Result<(), Box<dyn std::error::Error>> {
    let mut rx = Receiver::new(CONTEXT, 1, 1, 128, 145, 32)?;
    let bodies = Profile::new(1, 1, 128, 145)?.encode(&[5])?;
    let member = |id| Shard {
        generation: id,
        ordinal: 0,
        bytes: &bodies[0],
    };
    assert!(rx.accept(CONTEXT, member(32)).is_err());
    let mut wrong = CONTEXT;
    wrong.epoch = Epoch(2);
    assert!(rx.accept(wrong, member(0)).is_err());
    assert!(rx.commit(0).is_err());
    for id in (1..32).step_by(2) {
        rx.accept(CONTEXT, member(id))?;
        rx.commit(id)?;
    }
    let (first, cursor) = rx.confirmation(0)?;
    assert_eq!(first.ranges().len(), 8);
    assert_eq!(cursor, Some(17));
    let (second, cursor) = rx.confirmation(17)?;
    assert_eq!(second.ranges().len(), 8);
    assert_eq!(cursor, None);
    assert_eq!(rx.missing(0), vec![0]);
    assert!(rx.missing(32).is_empty());
    Ok(())
}

#[test]
fn repair_request_agrees_with_python_and_rejects_unknown_ordinals()
-> Result<(), Box<dyn std::error::Error>> {
    let request = ShardRequest::new(6, vec![(0, vec![1, 5]), (8192, vec![0, 2])])?;
    let mut encoded = vec![0; request.wire_len()];
    request.encode(&mut encoded)?;
    assert_eq!(encoded, &[0xa3, 2, 0, 0x22, 0xff, 0x3f, 0x05]);
    assert_eq!(ShardRequest::decode(6, &encoded)?, request);
    for n in 0..encoded.len() {
        assert!(ShardRequest::decode(6, &encoded[..n]).is_err());
    }
    for bad in [&[0xa3, 1, 0, 0x40][..], &[0xa3, 1, 0, 0][..]] {
        assert!(ShardRequest::decode(6, bad).is_err());
    }
    Ok(())
}
