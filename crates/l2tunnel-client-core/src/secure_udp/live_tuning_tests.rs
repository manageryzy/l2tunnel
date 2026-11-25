use super::*;

fn options(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

#[test]
fn client_options_become_checked_choices() -> io::Result<()> {
    let read = policy(
        "connect",
        &options(&[
            ("--tune-repair", "off,1/8, 1/4"),
            ("--tune-device-mtu", "1280,1400"),
            ("--tune-path-mtu", "1350"),
        ]),
    )?;
    let choices = read.choices.ok_or_else(|| io::Error::other("no choices"))?;
    assert_eq!(
        choices.repair,
        [
            Repair::Off,
            Repair::Rate {
                numerator: 1,
                denominator: 8
            },
            Repair::Rate {
                numerator: 1,
                denominator: 4
            }
        ]
    );
    assert_eq!(choices.device_mtu, [1280, 1400]);
    assert_eq!(choices.path_mtu, [1350]);
    assert_eq!(policy("connect", &BTreeMap::new())?, Policy::default());
    Ok(())
}

#[test]
fn server_options_become_limits() -> io::Result<()> {
    let read = policy(
        "serve",
        &options(&[
            ("--tune-max-repair", "1/4"),
            ("--tune-device-mtu-range", "1280-1500"),
            ("--tune-path-mtu-range", "1200-1500"),
            ("--tune-max-entries", "32"),
            ("--tune-memory-cap", "8388608"),
        ]),
    )?;
    assert_eq!(
        read.limits,
        Limits {
            max_repair: (1, 4),
            device_mtu: (1280, 1500),
            path_mtu: (1200, 1500),
            max_entries: 32,
        }
    );
    assert_eq!(read.memory_cap, Some(8 << 20));
    assert!(read.choices.is_none());
    Ok(())
}

#[test]
fn malformed_or_misplaced_options_are_refused_with_the_option_name() {
    let refused = |command: &str, pairs: &[(&str, &str)]| {
        policy(command, &options(pairs))
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default()
    };
    assert!(refused("connect", &[("--tune-repair", "half")]).contains("--tune-repair"));
    assert!(refused("connect", &[("--tune-repair", "1/0")]).contains("--tune-repair"));
    assert!(refused("connect", &[("--tune-device-mtu", "big")]).contains("--tune-device-mtu"));
    assert!(refused("connect", &[("--tune-path-mtu", "1350,1350")]).contains("choices"));
    assert!(refused("connect", &[("--tune-max-repair", "1/4")]).contains("does not apply"));
    assert!(refused("serve", &[("--tune-repair", "off")]).contains("does not apply"));
    assert!(refused("serve", &[("--tune-device-mtu-range", "1500-1280")]).contains("empty"));
    assert!(refused("serve", &[("--tune-max-entries", "65")]).contains("--tune-max-entries"));
    assert!(refused("serve", &[("--tune-memory-cap", "-1")]).contains("--tune-memory-cap"));
}
