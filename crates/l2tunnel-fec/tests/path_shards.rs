//! Cross-language vectors and bounded recovery of native records fragmented across physical paths.
use l2tunnel_fec::path_shards::{Profile, RecordReceiver};
use l2tunnel_fec::striped::Admission;
use l2tunnel_fec::{ChannelId, Direction, Epoch, Error, FecContext, GenerationId, SessionId};

const CONTEXT: FecContext = FecContext {
    session: SessionId([11; 16]),
    channel: ChannelId(5),
    epoch: Epoch(9),
    direction: Direction::ClientToServer,
};
const GROUP: GenerationId = GenerationId(17);

fn decode_hex(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    (0..s.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&s[i..i + 2], 16)?))
        .collect()
}

#[test]
fn every_threshold_subset_recovers_identical_native_bytes() -> Result<(), Box<dyn std::error::Error>>
{
    for line in include_str!("data/path-shards.tsv")
        .lines()
        .filter(|l| !l.starts_with('#'))
    {
        let cols: Vec<_> = line.split_whitespace().collect();
        let (n, k) = (cols[0].parse::<u8>()?, cols[1].parse::<u8>()?);
        let profile = Profile::new(n, k, 1500, 1451)?;
        let native = decode_hex(cols[2])?;
        let bodies = profile.encode(&native)?;
        assert_eq!(bodies.len(), cols.len() - 3);
        for (packet, expected) in bodies.iter().zip(&cols[3..]) {
            assert_eq!(*packet, decode_hex(expected)?);
        }
        for mask in 0..(1u32 << n) {
            let mut rx = RecordReceiver::new(profile, CONTEXT, GROUP, native.len() as u16)?;
            for i in (0..n).rev().filter(|i| mask & (1 << i) != 0) {
                let shard = &bodies[usize::from(i)];
                assert_eq!(
                    rx.accept_authenticated(CONTEXT, GROUP, i, shard)?,
                    Admission::Accepted
                );
                assert_eq!(
                    rx.accept_authenticated(CONTEXT, GROUP, i, shard)?,
                    Admission::Duplicate
                );
            }
            let mut out = vec![0xa6; native.len()];
            if mask.count_ones() >= u32::from(k) {
                assert_eq!(rx.recover_into(&mut out)?, native.len());
                assert_eq!(out, native);
            } else {
                assert_eq!(rx.recover_into(&mut out), Err(Error::InsufficientRank));
                assert!(out.iter().all(|b| *b == 0xa6));
            }
        }
    }
    Ok(())
}

#[test]
fn refused_inputs_preserve_admitted_shards() -> Result<(), Error> {
    let profile = Profile::new(6, 4, 1500, 1451)?;
    let original: Vec<u8> = (0..1500).map(|i| (i % 251) as u8).collect();
    let wire = profile.encode(&original)?;
    let mut rx = RecordReceiver::new(profile, CONTEXT, GROUP, 1500)?;
    assert_eq!(
        rx.accept_authenticated(CONTEXT, GenerationId(99), 0, &wire[0]),
        Err(Error::ContextMismatch)
    );
    assert_eq!(
        rx.accept_authenticated(CONTEXT, GROUP, 6, &wire[0]),
        Err(Error::Malformed)
    );
    assert_eq!(
        rx.accept_authenticated(CONTEXT, GROUP, 0, &wire[0][..4]),
        Err(Error::Malformed)
    );
    for i in [5, 1, 3, 0] {
        rx.accept_authenticated(CONTEXT, GROUP, i, &wire[usize::from(i)])?;
    }
    let mut changed = wire[1].clone();
    changed[5] ^= 1;
    assert_eq!(
        rx.accept_authenticated(CONTEXT, GROUP, 1, &changed),
        Err(Error::Conflict)
    );
    assert_eq!(
        rx.recover_into(&mut [0; 8]),
        Err(Error::OutputTooSmall { required: 1500 })
    );
    let mut out = vec![0; 1500];
    rx.recover_into(&mut out)?;
    assert_eq!(out, original);
    assert!(Profile::new(6, 4, 1500, 8).is_err());
    assert!(RecordReceiver::original_length(&[0x81, 0]).is_err());
    Ok(())
}
