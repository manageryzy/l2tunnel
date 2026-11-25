use super::*;
use crate::record_configuration::{Catalog, CommonDirection, Descriptor, NativeWindow, Profile};
use l2tunnel_core::{Duplex, Mapping, traffic};
use l2tunnel_flow_control::delivery_window;
use l2tunnel_pipeline as pipeline;
use std::time::Duration;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

const NATIVE: usize = 1500;

fn swift(repair: u32) -> records::Config {
    records::Config {
        channels: 2,
        layer: records::Layer::Ip,
        max_native: NATIVE,
        codec: l2tunnel_swift::Config {
            datagram_bytes: 1500 - 60,
            window: 128,
            repair_numerator: repair,
            repair_denominator: 4,
            flow_sources: 1024,
            queue_bytes: 256 << 10,
            max_packet: NATIVE + l2tunnel_swift::header::MAX_EXPANSION,
            flush_micros: 500,
            feedback_micros: 1000,
            tail_micros: 10_000,
            min_rto_micros: 140_000,
            max_rto_micros: 1_000_000,
        },
    }
}

fn common(window: bool) -> Result<CommonDirection> {
    let pipeline = pipeline::PipelineConfig {
        profile: pipeline::Profile::TunDrr(pipeline::TunQosConfig {
            base_quantum_bytes: 1500,
            max_weight: 4,
            per_flow: pipeline::QueueLimits {
                bytes: 65_536,
                packets: 64,
            },
        }),
        flows: pipeline::FlowTableConfig {
            capacity: 64,
            channels: 2,
            mapping: Mapping::Crc32,
            idle_timeout: Duration::from_secs(30),
        },
        parse: pipeline::ParseLimits {
            max_packet_bytes: NATIVE,
            max_vlan_tags: 2,
            max_ipv6_extensions: 4,
            max_ipv6_extension_bytes: 128,
        },
        queue: pipeline::QueueLimits {
            bytes: 1 << 20,
            packets: 1024,
        },
    };
    let native_window = if window {
        NativeWindow::Delivery(delivery_window::Config {
            target_bandwidth_bps: 4_000_000,
            bootstrap_rtt_micros: 70_000,
            min_rtt_micros: 100,
            max_rtt_micros: 200_000,
            headroom_percent: 125,
            minimum_bytes: NATIVE as u64,
            max_inflight_bytes: 100_000,
            max_records: 17,
            max_packet_bytes: NATIVE as u64,
            metadata_limit_bytes: 10_000,
            sample_ttl_micros: 4_000_000,
            flush_timeout_micros: 2_000_000,
        })
    } else {
        NativeWindow::Disabled
    };
    Ok(CommonDirection::new(
        traffic::TrafficPolicy::tun_tcp_proxy(),
        pipeline,
        12_500_000,
        64 << 10,
        native_window,
    )?)
}

fn base(repair: u32) -> Result<Descriptor> {
    Ok(Descriptor::new(
        1500,
        Duplex::Full,
        common(false)?,
        common(true)?,
        Profile::Swift {
            forward: swift(repair),
            reverse: swift(repair),
        },
    )?)
}

fn rate(numerator: u32, denominator: u32) -> Repair {
    Repair::Rate {
        numerator,
        denominator,
    }
}

#[test]
fn generated_catalog_covers_every_combination_and_keeps_the_base() -> Result {
    let base = base(1)?;
    let choices = Choices {
        repair: vec![Repair::Off, rate(1, 8), rate(1, 2)],
        device_mtu: vec![1280, 1400],
        path_mtu: vec![1280],
    };
    let catalog = generate(&base, &choices, &Limits::PROTOCOL)?;
    // Repair {Off, 1/8, 1/4 (base), 1/2} x device {1280, 1400, 1500 (base)}
    // x path {1280, 1500 (base)}.
    assert_eq!(catalog.descriptors().len(), 4 * 3 * 2);
    assert_eq!(catalog.initial(), base);
    let mut seen: Vec<Setting> = catalog
        .descriptors()
        .iter()
        .map(setting)
        .collect::<std::result::Result<_, _>>()?;
    seen.sort_unstable();
    assert_eq!(seen, settings(&base, &choices)?);
    // A device MTU change resizes every native bound the descriptor ties
    // to it, and a path MTU change keeps the carrier overhead.
    let small = catalog
        .descriptors()
        .iter()
        .find(|d| {
            setting(d).is_ok_and(|s| {
                s.device_mtu == 1280 && s.path_mtu == 1280 && s.repair == Repair::Off
            })
        })
        .ok_or("missing entry")?;
    let Profile::Swift { forward, .. } = *small.profile() else {
        return Err("not swift".into());
    };
    assert_eq!(forward.codec.datagram_bytes, 1280 - 60);
    assert_eq!(forward.codec.max_packet, 1281);
    assert_eq!(forward.codec.repair_numerator, 0);
    assert_eq!(
        small
            .direction(Role::Server)
            .common()
            .pipeline()
            .parse
            .max_packet_bytes,
        1280
    );
    Ok(())
}

#[test]
fn generation_is_deterministic_and_order_free() -> Result {
    let base = base(0)?;
    let one = Choices {
        repair: vec![rate(1, 4), rate(1, 3)],
        device_mtu: vec![1400, 1280],
        path_mtu: vec![1400],
    };
    let two = Choices {
        repair: vec![rate(1, 3), rate(1, 4)],
        device_mtu: vec![1280, 1400],
        path_mtu: vec![1400],
    };
    let a = generate(&base, &one, &Limits::PROTOCOL)?;
    let b = generate(&base, &two, &Limits::PROTOCOL)?;
    assert_eq!(a, b);
    assert_eq!(a.root(), b.root());
    // No choices: the base alone.
    let alone = generate(&base, &Choices::default(), &Limits::PROTOCOL)?;
    assert_eq!(alone, Catalog::new(base, &[base])?);
    Ok(())
}

#[test]
fn server_limits_and_bounds_refuse_with_the_exact_reason() -> Result {
    let base = base(1)?;
    let limits = Limits {
        max_repair: (1, 4),
        device_mtu: (1280, 1500),
        path_mtu: (1280, 1500),
        max_entries: 8,
    };
    let refused = |choices: Choices| generate(&base, &choices, &limits).err();
    assert_eq!(
        refused(Choices {
            repair: vec![rate(1, 3)],
            ..Choices::default()
        }),
        Some(Error::RepairLimit)
    );
    assert_eq!(
        refused(Choices {
            device_mtu: vec![1000],
            ..Choices::default()
        }),
        Some(Error::DeviceMtuLimit)
    );
    assert_eq!(
        refused(Choices {
            path_mtu: vec![9000],
            ..Choices::default()
        }),
        Some(Error::PathMtuLimit)
    );
    assert_eq!(
        refused(Choices {
            repair: vec![Repair::Off, rate(1, 8)],
            device_mtu: vec![1280, 1400],
            ..Choices::default()
        }),
        Some(Error::Entries),
        "3 x 3 = 9 entries exceed 8"
    );
    assert_eq!(
        refused(Choices {
            repair: vec![rate(0, 4)],
            ..Choices::default()
        }),
        Some(Error::Repair)
    );
    assert_eq!(
        refused(Choices {
            device_mtu: vec![1400, 1400],
            ..Choices::default()
        }),
        Some(Error::Choices)
    );
    // Protocol bound: more than 64 combinations.
    let many = Choices {
        repair: (1..=4).map(|n| rate(n, 16)).collect(),
        device_mtu: (0..4).map(|n| 1280 + n * 10).collect(),
        path_mtu: (0..4).map(|n| 1280 + n * 10).collect(),
    };
    assert_eq!(
        generate(&base, &many, &Limits::PROTOCOL).err(),
        Some(Error::Entries)
    );
    // The smallest protocol path still fits the carrier overhead; a looser
    // server range cannot get below the descriptor's own 256-byte floor.
    let small = |path| Choices {
        path_mtu: vec![path],
        ..Choices::default()
    };
    assert!(generate(&base, &small(256), &Limits::PROTOCOL).is_ok());
    let loose = Limits {
        path_mtu: (1, u16::MAX),
        ..Limits::PROTOCOL
    };
    assert!(matches!(
        generate(&base, &small(100), &loose),
        Err(Error::Configuration(_))
    ));
    assert_eq!(
        generate(&base, &small(40), &loose).err(),
        Some(Error::Overhead)
    );
    Ok(())
}

#[test]
fn proposal_wire_round_trips_and_refuses_garbage() -> Result {
    let choices = Choices {
        repair: vec![Repair::Off, rate(26, 125)],
        device_mtu: vec![1280, 1500],
        path_mtu: vec![1350],
    };
    let bytes = choices.encode()?;
    assert!(bytes.len() <= MAX_PROPOSAL_BYTES);
    assert_eq!(Choices::decode(&bytes)?, choices);
    assert_eq!(
        Choices::decode(&Choices::default().encode()?)?,
        Choices::default()
    );
    assert_eq!(
        Choices::decode(&bytes[..bytes.len() - 1]),
        Err(Error::Encoding)
    );
    let mut longer = bytes.clone();
    longer.push(0);
    assert_eq!(Choices::decode(&longer), Err(Error::Encoding));
    for index in [0, 1, 2, 3] {
        let mut bad = bytes.clone();
        bad[index] ^= 1;
        assert_eq!(Choices::decode(&bad), Err(Error::Encoding), "byte {index}");
    }
    // A zero numerator with a nonzero denominator is not Off.
    let mut zero = bytes;
    zero[5..13].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 4]);
    assert_eq!(Choices::decode(&zero), Err(Error::Encoding));
    let full = Choices {
        repair: (1..=16).map(|n| rate(n, 16)).collect(),
        device_mtu: (0..16).map(|n| 1200 + n).collect(),
        path_mtu: (0..16).map(|n| 1300 + n).collect(),
    };
    assert_eq!(full.encode()?.len(), MAX_PROPOSAL_BYTES);
    Ok(())
}

#[test]
fn non_swift_or_asymmetric_bases_are_refused() -> Result {
    let mut reverse = swift(1);
    reverse.codec.repair_numerator = 2;
    let asymmetric = Descriptor::new(
        1500,
        Duplex::Full,
        common(false)?,
        common(true)?,
        Profile::Swift {
            forward: swift(1),
            reverse,
        },
    )?;
    assert_eq!(
        generate(&asymmetric, &Choices::default(), &Limits::PROTOCOL).err(),
        Some(Error::Base)
    );
    Ok(())
}

#[test]
fn refusal_codes_are_stable_and_round_trip_through_the_verdict() {
    let all = [
        Refusal::NotOffered,
        Refusal::Base,
        Refusal::Choices,
        Refusal::Repair,
        Refusal::RepairLimit,
        Refusal::DeviceMtuLimit,
        Refusal::PathMtuLimit,
        Refusal::Entries,
        Refusal::Overhead,
        Refusal::Encoding,
        Refusal::Configuration,
        Refusal::Memory,
    ];
    for (index, refusal) in all.into_iter().enumerate() {
        assert_eq!(usize::from(refusal.code()), index + 1);
        assert_eq!(decode_verdict(&encode_verdict(Err(refusal))), Err(refusal));
    }
    assert_eq!(decode_verdict(&encode_verdict(Ok(()))), Ok(()));
    assert_eq!(decode_verdict(&[200]), Err(Refusal::Unknown(200)));
    assert_eq!(Refusal::Unknown(200).code(), 200);
    assert_eq!(decode_verdict(&[]), Err(Refusal::Encoding));
    assert_eq!(decode_verdict(&[0, 0]), Err(Refusal::Encoding));
    assert_eq!(
        Refusal::from(&Error::RepairLimit).to_string(),
        Error::RepairLimit.to_string()
    );
}

#[test]
fn each_direction_keeps_its_own_untuned_fields() -> Result {
    let mut reverse = swift(1);
    reverse.channels = 3;
    reverse.codec.window = 64;
    let mut forward_common = common(false)?;
    let mut pipeline = forward_common.pipeline();
    pipeline.flows.channels = 2;
    forward_common = CommonDirection::new(
        forward_common.traffic(),
        pipeline,
        forward_common.bytes_per_second(),
        forward_common.burst_bytes(),
        forward_common.native_window(),
    )?;
    let reverse_common = common(true)?;
    let mut pipeline = reverse_common.pipeline();
    pipeline.flows.channels = 3;
    let reverse_common = CommonDirection::new(
        reverse_common.traffic(),
        pipeline,
        reverse_common.bytes_per_second(),
        reverse_common.burst_bytes(),
        reverse_common.native_window(),
    )?;
    let base = Descriptor::new(
        1500,
        Duplex::Full,
        forward_common,
        reverse_common,
        Profile::Swift {
            forward: swift(1),
            reverse,
        },
    )?;
    let choices = Choices {
        device_mtu: vec![1280],
        ..Choices::default()
    };
    let catalog = generate(&base, &choices, &Limits::PROTOCOL)?;
    for descriptor in catalog.descriptors() {
        let Profile::Swift { forward, reverse } = *descriptor.profile() else {
            return Err("not swift".into());
        };
        assert_eq!((forward.channels, reverse.channels), (2, 3));
        assert_eq!((forward.codec.window, reverse.codec.window), (128, 64));
        assert_eq!(forward.max_native, reverse.max_native);
    }
    Ok(())
}

#[test]
fn extend_keeps_the_plan_entries_and_adds_the_combinations() -> Result {
    let base = base(1)?;
    let other = base_with_path(1400)?;
    let plan = Catalog::new(base, &[base, other])?;
    let choices = Choices {
        repair: vec![Repair::Off],
        ..Choices::default()
    };
    let catalog = extend(&plan, &choices, &Limits::PROTOCOL)?;
    assert_eq!(catalog.initial(), base);
    // The plan's two entries plus the FEC-off variant of the initial one.
    assert_eq!(catalog.descriptors().len(), 3);
    assert!(catalog.descriptors().contains(&other));
    assert_eq!(extend(&plan, &choices, &Limits::PROTOCOL)?, catalog);
    let tight = Limits {
        max_entries: 2,
        ..Limits::PROTOCOL
    };
    assert_eq!(extend(&plan, &choices, &tight).err(), Some(Error::Entries));
    Ok(())
}

fn base_with_path(path: u16) -> Result<Descriptor> {
    let choices = Choices {
        path_mtu: vec![path],
        ..Choices::default()
    };
    let catalog = generate(&base(1)?, &choices, &Limits::PROTOCOL)?;
    catalog
        .descriptors()
        .iter()
        .copied()
        .find(|d| d.path_mtu() == usize::from(path))
        .ok_or_else(|| "missing path entry".into())
}
