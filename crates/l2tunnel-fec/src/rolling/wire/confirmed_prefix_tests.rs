use super::*;
use crate::rolling::scheduler::Output;

const SELECTED: SourceWire = SourceWire::TargetedNear8ConfirmedPrefix;
const VECTORS: &str =
    include_str!("../../../../../simulator/tests/fixtures/rolling_confirmed_prefix.txt");

fn policy() -> Config {
    Config {
        window: 8192,
        local_window: 128,
        global_every: 16,
        ..config()
    }
}

#[test]
fn shared_python_vectors_roundtrip_through_compact_and_full_grammars() -> TestResult {
    let cfg = policy();
    for line in VECTORS.lines().filter(|line| !line.starts_with('#')) {
        let values: Vec<_> = line.split_whitespace().collect();
        let [id, end, start, tail, rhs, wire] = values.as_slice() else {
            return Err("invalid test vector".into());
        };
        let id = RepairId(id.parse()?);
        let end = end.parse()?;
        let support = cfg.confirmed_prefix_support(end, id, *tail == "1", start.parse()?)?;
        assert_eq!(support.start, start.parse::<u32>()?);
        let rhs = hex(rhs)?;
        let expected = hex(wire)?;
        let repair = Repair {
            scope: scope(),
            id,
            support,
            bytes: &rhs,
        };
        let mut bytes = [0x7a; 90];
        let n = compact::encode_data_with(cfg, SELECTED, Output::Repair(repair), &mut bytes)?;
        assert_eq!(
            compact::data_len_with(cfg, SELECTED, Output::Repair(repair))?,
            n
        );
        assert_eq!(
            compact::repair_len_with(cfg, SELECTED, id, support, rhs.len())?,
            n
        );
        assert_eq!(bytes[..n], expected);
        let compact::View::Data(View::Repair(parsed)) =
            compact::inspect_with(cfg, SELECTED, scope(), &expected)?
        else {
            return Err("repair expected".into());
        };
        assert_eq!(
            (parsed.support, parsed.id, parsed.bytes),
            (support, id, &rhs[..])
        );
        if matches!(expected[0], 7 | 8) {
            for old in [
                SourceWire::Padded,
                SourceWire::Exact,
                SourceWire::TargetedExact,
                SourceWire::TargetedNear8,
                SourceWire::TargetedNear8Hold35,
            ] {
                assert!(compact::inspect_with(cfg, old, scope(), &expected).is_err());
                assert!(encode_repair_with(cfg, old, repair, &mut bytes).is_err());
                assert!(
                    compact::encode_data_with(cfg, old, Output::Repair(repair), &mut bytes)
                        .is_err()
                );
            }
        }
        let n = encode_repair_with(cfg, SELECTED, repair, &mut bytes)?;
        let View::Repair(full) = inspect_with(cfg, SELECTED, &bytes[..n])? else {
            return Err("full repair expected".into());
        };
        assert_eq!((full.support, full.id, full.bytes), (support, id, &rhs[..]));
        assert!(inspect_with(cfg, SourceWire::TargetedNear8, &bytes[..n]).is_err());
    }
    Ok(())
}

#[test]
fn malformed_suffix_counts_reject_without_overwriting_short_outputs() -> TestResult {
    let cfg = policy();
    for bytes in [
        "091003010001a5",
        "071003000001a5",
        "071003030001a5",
        "071103010001a5",
        "07100381000001a5",
        "0710030180",
        "071003ffffffff100001a5",
    ] {
        assert!(compact::inspect_with(cfg, SELECTED, scope(), &hex(bytes)?).is_err());
    }
    let row = Repair {
        scope: scope(),
        id: RepairId(16),
        support: cfg.confirmed_prefix_support(3, RepairId(16), false, 1)?,
        bytes: &[0, 1, 0],
    };
    let mut short = [0xee; 6];
    assert_eq!(
        compact::encode_data_with(cfg, SELECTED, Output::Repair(row), &mut short),
        Err(Error::OutputTooSmall)
    );
    assert_eq!(short, [0xee; 6]);
    Ok(())
}
