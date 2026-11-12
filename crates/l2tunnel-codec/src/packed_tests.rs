#![allow(clippy::unwrap_used)]
use super::*;

fn raw(channel: u8, size: usize) -> Vec<u8> {
    let mut unit = vec![channel, 0, 0, 2];
    unit.extend_from_slice(&(size as u16).to_be_bytes());
    unit.extend((0..size).map(|value| value as u8));
    unit
}
fn packer(symbol: usize) -> Packer {
    Packer::new(Config {
        symbol_bytes: symbol,
        hold_micros: 500,
    })
    .unwrap()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn unhex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn take(packer: &mut Packer, output: &mut Vec<String>) {
    if let Some(pending) = packer.pending() {
        let reason = match pending.reason {
            SealReason::Timer => "timer",
            SealReason::Explicit => "explicit",
            SealReason::Capacity => "capacity",
            SealReason::CopyPolicy => "copy_policy",
            SealReason::LargeUnit => "large_unit",
            SealReason::UnitLimit => "unit_limit",
        };
        output.push(format!(
            "{reason}:{}:{}",
            pending.copies,
            hex(pending.payload)
        ));
        packer.commit().unwrap();
    }
}

#[test]
fn actual_python_packing_events_and_parser_outcomes_match() {
    let mut current = String::new();
    let mut packer = packer(1460);
    let mut sources = 0;
    let mut parses = 0;
    for line in include_str!("../tests/data/packed-goldens.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let cells: Vec<_> = line.split('\t').collect();
        if cells[0] == "P" {
            let data = unhex(cells[2]);
            let result = parse(&data, 1460);
            if cells[3] == "ERR" {
                assert!(result.is_err(), "parser case {}", cells[1]);
            } else {
                let result = result.unwrap();
                let units: Vec<_> = result.units().map(hex).collect();
                assert_eq!(units.join(";"), cells[3], "parser case {}", cells[1]);
                assert_eq!(result.len(), units.len());
                assert!(!result.is_empty());
                assert_eq!(result.units().len(), units.len());
            }
            parses += 1;
            continue;
        }
        if current != cells[1] {
            current = cells[1].to_string();
            packer = super::Packer::new(Config {
                symbol_bytes: 1460,
                hold_micros: 500,
            })
            .unwrap();
        }
        let mut output = Vec::new();
        if cells[0] == "F" {
            packer.flush();
        } else if cells[5] == "-" {
            packer.tick(cells[3].parse().unwrap()).unwrap();
        } else {
            let unit = unhex(cells[5]);
            let copies = cells[4].parse().unwrap();
            let now = cells[3].parse().unwrap();
            match packer.push(&unit, copies, now).unwrap() {
                Push::Accepted => {}
                Push::FlushRequired => {
                    take(&mut packer, &mut output);
                    assert_eq!(packer.push(&unit, copies, now).unwrap(), Push::Accepted);
                }
                Push::Backpressure => unreachable!(),
            }
        }
        take(&mut packer, &mut output);
        let actual = if output.is_empty() {
            "-".to_string()
        } else {
            output.join(";")
        };
        assert_eq!(actual, cells[6], "trace {} step {}", cells[1], cells[2]);
        sources += output.len();
    }
    assert!(sources >= 10);
    assert!(parses >= 100);
}

#[test]
fn first_deadline_and_retained_handoff_never_renew_or_duplicate() {
    let mut packer = packer(1460);
    let first = raw(0, 66);
    let second = raw(1, 66);
    assert_eq!(packer.push(&first, 3, 1000).unwrap(), Push::Accepted);
    assert_eq!(packer.push(&second, 3, 1499).unwrap(), Push::Accepted);
    assert_eq!(packer.status().deadline_micros, Some(1500));
    packer.tick(1499).unwrap();
    assert!(packer.pending().is_none());
    packer.tick(1500).unwrap();
    let pending = packer.pending().unwrap();
    assert_eq!(pending.reason, SealReason::Timer);
    assert_eq!(pending.payload.len(), 150);
    assert_eq!(
        parse(pending.payload, 1460)
            .unwrap()
            .units()
            .collect::<Vec<_>>(),
        [&first[..], &second[..]]
    );
    let bytes = pending.payload.to_vec();
    for now in [1501, 2000, 3000] {
        assert_eq!(packer.push(&first, 3, now).unwrap(), Push::Backpressure);
        packer.tick(now).unwrap();
        packer.flush();
        assert_eq!(packer.pending().unwrap().payload, bytes);
        assert_eq!(packer.status().deadline_micros, Some(1500));
    }
    packer.commit().unwrap();
    assert_eq!(packer.commit(), Err(Error::NoPending));
    assert_eq!(packer.push(&first, 1, 3000).unwrap(), Push::Accepted);
    assert_eq!(packer.status().deadline_micros, Some(3500));
}

#[test]
fn due_input_policy_capacity_and_count_require_retry_without_consuming_input() {
    for (symbol, first, second, copies, now, expected) in [
        (1460, raw(0, 66), raw(1, 66), 1, 0, SealReason::CopyPolicy),
        (100, raw(0, 40), raw(1, 44), 3, 0, SealReason::Capacity),
        (1460, raw(0, 66), raw(1, 66), 3, 500, SealReason::Timer),
    ] {
        let mut packer = packer(symbol);
        assert_eq!(packer.push(&first, 3, 0).unwrap(), Push::Accepted);
        assert_eq!(
            packer.push(&second, copies, now).unwrap(),
            Push::FlushRequired
        );
        let pending = packer.pending().unwrap();
        assert_eq!(pending.payload, first);
        assert_eq!(pending.units, 1);
        assert_eq!(pending.reason, expected);
        packer.commit().unwrap();
        assert_eq!(packer.push(&second, copies, now).unwrap(), Push::Accepted);
    }
    let mut packer = packer(65_535);
    let unit = [0, 0, 0, 5]; // Python context-dependent dictionary record.
    for _ in 0..255 {
        assert_eq!(packer.push(&unit, 1, 0).unwrap(), Push::Accepted);
    }
    assert_eq!(packer.push(&unit, 1, 0).unwrap(), Push::FlushRequired);
    assert_eq!(packer.pending().unwrap().reason, SealReason::UnitLimit);
    assert_eq!(
        parse(packer.pending().unwrap().payload, 65_535)
            .unwrap()
            .len(),
        255
    );
}

#[test]
fn validation_and_arithmetic_errors_preserve_owned_work() {
    for config in [
        Config {
            symbol_bytes: 8,
            hold_micros: 500,
        },
        Config {
            symbol_bytes: 65536,
            hold_micros: 500,
        },
        Config {
            symbol_bytes: 1460,
            hold_micros: 0,
        },
        Config {
            symbol_bytes: 1460,
            hold_micros: 1001,
        },
    ] {
        assert!(Packer::new(config).is_err());
    }
    let mut packer = packer(1460);
    let unit = raw(0, 66);
    assert_eq!(
        packer.push(&unit, 1, u64::MAX - 499),
        Err(Error::ClockExhausted)
    );
    assert_eq!(packer.status().bytes, 0);
    assert_eq!(packer.push(&unit, 1, 1000).unwrap(), Push::Accepted);
    let before = packer.status();
    assert_eq!(packer.push(&unit, 1, 999), Err(Error::ClockRegression));
    assert_eq!(packer.tick(999), Err(Error::ClockRegression));
    assert_eq!(packer.push(&unit, 0, 1001), Err(Error::Configuration));
    assert_eq!(packer.push(&[255, 0, 0, 5], 1, 1001), Err(Error::Malformed));
    assert_eq!(packer.status(), before);
    packer.flush();
    assert_eq!(packer.pending().unwrap().payload, unit);
}

#[test]
fn fragment_geometry_and_borrowed_parser_boundaries() {
    let mut fragment = vec![2, 0xff, 0xfe, 4, 0, 100, 0, 92];
    fragment.extend([1; 8]);
    assert!(validate_unit(&fragment, 100).is_ok());
    fragment[7] = 91;
    assert_eq!(validate_unit(&fragment, 100), Err(Error::Malformed));
    fragment[7] = 100;
    assert_eq!(validate_unit(&fragment, 100), Err(Error::Malformed));
    let mut packer = packer(100);
    let unit = raw(0, 40);
    packer.push(&unit, 1, 0).unwrap();
    packer.push(&unit, 1, 0).unwrap();
    packer.flush();
    let packed = packer.pending().unwrap().payload;
    assert_eq!(packed.len(), 98);
    for end in 0..packed.len() {
        assert!(parse(&packed[..end], 100).is_err());
    }
    let mut padded = packed.to_vec();
    padded.extend([0, 0]);
    assert_eq!(parse(&padded, 100).unwrap().encoded_len(), 98);
    padded[99] = 1;
    assert!(parse(&padded, 100).is_err());
}
