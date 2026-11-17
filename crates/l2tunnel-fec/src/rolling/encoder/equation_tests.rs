use super::*;
use crate::research::Profile;

fn config() -> Config {
    Config {
        window: 2048,
        local_window: 128,
        global_every: 16,
        max_payload: 19,
        max_rows: 1,
        repair_history: 1,
        handoff_sources: 1,
        job_ticks: 100,
        debt_ticks: 1_000,
        handoff_ticks: 500,
        memory_bytes: 1 << 20,
    }
}

#[test]
fn research_equation_actual_python_payload_rows() -> Result<(), Box<dyn std::error::Error>> {
    let mut profiles = Vec::new();
    let mut equations = 0;
    for line in include_str!("../../../tests/fixtures/research-policy.txt").lines() {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        if fields.is_empty() || fields[0] == "#" {
            continue;
        }
        let number = |index: usize| -> Result<u32, Box<dyn std::error::Error>> {
            Ok(fields[index].parse()?)
        };
        if fields[0] == "p" {
            let profile = if fields[2] == "r" {
                Profile::Recursive {
                    taps: number(3)? as u8,
                    width: number(4)? as u16,
                    reset: number(5)? as u16,
                    fresh_interval: number(6)? as u16,
                }
            } else {
                Profile::Accumulator {
                    lanes: number(7)? as u16,
                    window: number(8)? as u16,
                }
            };
            profiles.push(profile);
        } else if fields[0] == "e" {
            let profile = profiles[number(1)? as usize];
            let serial = number(2)?;
            let end = number(3)?;
            let confirmed = number(4)?;
            let scope = Scope {
                session: [0x59; 16],
                epoch: 1,
                stream: 5,
                direction: 0,
            };
            let mut encoder = Encoder::new(config(), scope, Tick(0))?;
            // A test-only serial jump selects the exact fixture slot; all source
            // vectors are still admitted through the real production encoder.
            encoder.next_repair = u64::from(serial);
            for source in 0..end {
                let length = 1 + source as usize % 19;
                let mut bytes = [0; 19];
                for (offset, byte) in bytes[..length].iter_mut().enumerate() {
                    *byte = (source * 29 + offset as u32 * 71 + (offset as u32 >> 1)) as u8;
                }
                if source.is_multiple_of(5) {
                    bytes[length - 1] = 0;
                }
                encoder.admit_source(&bytes[..length], Tick(0))?;
            }
            encoder.confirm_prefix(confirmed, Tick(0))?;
            let support = profile.support(end, confirmed, serial)?;
            assert_eq!(support.start, number(5)?, "{line}");
            encoder.begin_equation(support, profile, Tick(0))?;
            let budget = WorkBudget {
                field: 257,
                copies: 257,
                metadata: 257,
            };
            for _ in 0..20_000 {
                let work = encoder.step(Tick(0), budget)?;
                assert!(
                    work.field <= budget.field
                        && work.copies <= budget.copies
                        && work.metadata <= budget.metadata
                );
                if encoder.pending_repair().is_some() {
                    break;
                }
            }
            let actual = encoder.pending_repair().ok_or(Error::WorkLimit)?;
            let hex = fields[6];
            assert_eq!(hex.len(), 2 * config().width()?, "{line}");
            let expected: Result<Vec<_>, _> = (0..hex.len())
                .step_by(2)
                .map(|offset| u8::from_str_radix(&hex[offset..offset + 2], 16))
                .collect();
            let extent = 2
                + (support.start..support.end)
                    .map(|source| 1 + source as usize % 19)
                    .max()
                    .ok_or(Error::Identity)?;
            assert_eq!(actual.bytes.len(), extent, "{line}");
            let mut expanded = vec![0; config().width()?];
            expanded[..actual.bytes.len()].copy_from_slice(actual.bytes);
            assert_eq!(expanded, expected?, "{line}");
            equations += 1;
        }
    }
    assert_eq!(profiles.len(), 13);
    assert_eq!(equations, 13 * 7);
    Ok(())
}
