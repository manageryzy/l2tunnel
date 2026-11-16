use super::*;

#[test]
fn actual_python_policy_rows() -> Result<(), Box<dyn std::error::Error>> {
    let mut profiles = Vec::new();
    for line in include_str!("../../../tests/fixtures/research-policy.txt").lines() {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        if fields.is_empty() || fields[0] == "#" {
            continue;
        }
        let number = |index: usize| -> Result<u32, Box<dyn std::error::Error>> {
            Ok(fields[index].parse()?)
        };
        match fields[0] {
            "p" => {
                assert_eq!(profiles.len(), number(1)? as usize);
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
                profile.validate()?;
                profiles.push(profile);
            }
            "s" => {
                let profile = profiles[number(1)? as usize];
                let serial = number(2)?;
                let expected_start = number(5)?;
                let expected_end = number(6)?;
                let actual = profile.support(number(3)?, number(4)?, serial);
                if expected_end - expected_start > MAX_WINDOW as u32 {
                    assert_eq!(actual, Err(Error::Capacity), "{line}");
                } else {
                    assert_eq!(
                        actual?,
                        Support {
                            start: expected_start,
                            end: expected_end,
                            seed: serial.wrapping_mul(SERIAL_MULTIPLIER),
                            tail: false,
                        },
                        "{line}"
                    );
                }
                let expected_mode = match fields[7] {
                    "r" => RepairMode::Recursive,
                    "f" => RepairMode::Fallback,
                    "a" => RepairMode::Accumulator,
                    _ => RepairMode::Dense,
                };
                assert_eq!(profile.mode(serial)?, expected_mode, "{line}");
            }
            "c" => assert_eq!(
                profiles[number(1)? as usize].coefficient(number(2)?, number(3)?)?,
                number(4)? as u8,
                "{line}"
            ),
            "t" => assert_eq!(
                source_tap(number(1)?, number(3)? as u8, number(2)? as u16),
                (fields[4].parse()?, number(5)? as u8),
                "{line}"
            ),
            // Payload rows are consumed by the actual encoder differential test.
            "e" => {}
            _ => return Err(format!("Unknown oracle row: {line}").into()),
        }
    }
    assert_eq!(profiles.len(), 13);
    Ok(())
}

#[test]
fn fallback_keeps_expansion_and_acknowledged_history() -> Result<(), Error> {
    let pure = Profile::Recursive {
        taps: 4,
        width: 8,
        reset: 256,
        fresh_interval: 0,
    };
    let fallback = Profile::Recursive {
        taps: 4,
        width: 8,
        reset: 256,
        fresh_interval: 8,
    };
    for serial in [7, 9, 15, 17, 255, 257, 513] {
        let end = serial * 125 / 26 + 1;
        assert_eq!(
            fallback.support(end, end - 1, serial)?,
            pure.support(end, 0, serial)?
        );
        for source in 0..end {
            assert_eq!(
                fallback.coefficient(serial, source)?,
                pure.coefficient(serial, source)?
            );
        }
    }
    assert_eq!(fallback.mode(256)?, RepairMode::Fallback);
    assert_eq!(fallback.mode(257)?, RepairMode::Recursive);
    assert_eq!(fallback.retention_floor(256, 1231, 1200)?, 0);
    assert_eq!(fallback.retention_floor(257, 1236, 1200)?, 1076);
    assert_eq!(fallback.support(1231, 1200, 256)?.start, 1200);
    Ok(())
}

#[test]
fn validation_support_pressure_and_identity_never_wrap() -> Result<(), Error> {
    let recursive = Profile::Recursive {
        taps: 4,
        width: 8,
        reset: 256,
        fresh_interval: 16,
    };
    assert_eq!(recursive.mode(0), Err(Error::Identity));
    assert_eq!(recursive.coefficient(0, 0), Err(Error::Identity));
    assert_eq!(recursive.support(0, 0, 1), Err(Error::Identity));
    assert_eq!(recursive.support(1, 2, 1), Err(Error::Identity));
    assert_eq!(recursive.support(20, 20, 16), Err(Error::Identity));
    assert_eq!(recursive.support(8193, 0, 16), Err(Error::Capacity));
    assert_eq!(
        recursive.support(u32::MAX, 0, u32::MAX),
        Err(Error::Exhausted)
    );
    assert!(recursive.minimum_window()? <= MAX_WINDOW);
    for profile in [
        Profile::Recursive {
            taps: 0,
            width: 1,
            reset: 256,
            fresh_interval: 0,
        },
        Profile::Recursive {
            taps: 1,
            width: 0,
            reset: 256,
            fresh_interval: 0,
        },
        Profile::Recursive {
            taps: 17,
            width: 8,
            reset: 256,
            fresh_interval: 0,
        },
        Profile::Recursive {
            taps: 4,
            width: 8,
            reset: 0,
            fresh_interval: 0,
        },
        Profile::Recursive {
            taps: 4,
            width: u16::MAX,
            reset: 256,
            fresh_interval: 0,
        },
        Profile::Accumulator {
            lanes: 257,
            window: 128,
        },
        Profile::Accumulator {
            lanes: 1,
            window: 0,
        },
    ] {
        assert_eq!(profile.validate(), Err(Error::Configuration));
        assert_eq!(profile.coefficient(1, 0), Err(Error::Configuration));
    }
    Ok(())
}
