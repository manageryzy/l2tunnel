//! Pure runtime-envelope classification; no authenticated setup or engine staging.

use super::*;
use mg::messages;

type Change<T> = (&'static str, fn(&mut T));

fn streamed(mut value: Config) -> Config {
    let entry = messages::Settings {
        delivery: delivery::Settings {
            wire_overhead: value.control.wire_overhead + streams::HEADER_BYTES,
            ..value.control
        },
        path_mtu: value.path_mtu,
        max_message_bytes: 4096,
        max_outbound_messages: 4,
        max_outbound_bytes: 131_072,
        max_fragments: 32,
        max_reassembly_bytes: 16_384,
        max_incomplete_messages: 2,
        message_lifetime: value.lifetime.lease,
        work_per_call: 8,
    };
    value.streams = Some(control_owner::Settings {
        streams: [entry; 3],
    });
    value
}

fn assert_bound(original: Config, changed: Config, label: &str) -> Result {
    changed.validate()?;
    assert_ne!(
        changed.immutable_contract_digest()?,
        original.immutable_contract_digest()?,
        "fixed inventory omitted {label}"
    );
    assert_ne!(
        changed.canonical_digest()?,
        original.canonical_digest()?,
        "{label}"
    );
    Ok(())
}

fn assert_refused(value: Config, label: &str) -> Result {
    let immutable = value
        .immutable_contract_digest()
        .err()
        .ok_or("invalid envelope was hashed")?;
    let canonical = value
        .canonical_digest()
        .err()
        .ok_or("invalid full contract was hashed")?;
    assert_eq!(immutable.kind(), io::ErrorKind::InvalidInput, "{label}");
    assert_eq!(canonical.kind(), io::ErrorKind::InvalidInput, "{label}");
    Ok(())
}

const MUTABLE_DIRECTION: &[Change<policy::Direction>] = &[
    ("channels", |d| d.records.channels += 1),
    ("exact byte rate", |d| d.bytes_per_second += 1),
    ("source datagram size", |d| {
        d.records.codec.datagram_bytes += 1
    }),
    ("linear repair window", |d| d.records.codec.window += 1),
    ("repair numerator", |d| {
        d.records.codec.repair_numerator += 1
    }),
    ("repair denominator", |d| {
        d.records.codec.repair_denominator += 1
    }),
    ("source flight bound", |d| d.records.codec.flow_sources += 1),
    ("packing queue", |d| d.records.codec.queue_bytes += 1),
    ("flush timer", |d| d.records.codec.flush_micros += 1),
    ("feedback timer", |d| d.records.codec.feedback_micros += 1),
    ("tail timer", |d| d.records.codec.tail_micros += 1),
    ("minimum RTO", |d| d.records.codec.min_rto_micros += 1),
    ("maximum RTO", |d| d.records.codec.max_rto_micros += 1),
];

#[test]
fn immutable_envelope_permits_each_complete_mutable_direction_field() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        for selected in [false, true] {
            let original = if selected {
                streamed(config(kind))
            } else {
                config(kind)
            };
            let envelope = original.immutable_contract_digest()?;
            let canonical = original.canonical_digest()?;
            let actual_cover = appearance(kind, true)?;
            original.validate_cover(actual_cover, false)?;
            for outgoing in [false, true] {
                for &(label, change) in MUTABLE_DIRECTION {
                    let mut value = original;
                    change(if outgoing {
                        &mut value.send
                    } else {
                        &mut value.receive
                    });
                    value.validate_cover(actual_cover, false)?;
                    assert_eq!(
                        value.immutable_contract_digest()?,
                        envelope,
                        "{label}, send={outgoing}"
                    );
                    assert_ne!(
                        value.canonical_digest()?,
                        canonical,
                        "{label}, send={outgoing}"
                    );
                }
            }
        }
    }
    Ok(())
}

#[test]
fn active_and_derived_mtu_and_asymmetric_policy_normalize_together() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        for selected in [false, true] {
            let original = if selected {
                streamed(config(kind))
            } else {
                config(kind)
            };
            let mut changed = original;
            changed.path_mtu = 1400;
            if let Some(settings) = &mut changed.streams {
                for entry in &mut settings.streams {
                    entry.path_mtu = changed.path_mtu;
                }
            }
            changed.validate_cover(appearance(kind, true)?, false)?;
            assert_eq!(
                changed.immutable_contract_digest()?,
                original.immutable_contract_digest()?
            );
            assert_ne!(changed.canonical_digest()?, original.canonical_digest()?);
            for &(_, change) in MUTABLE_DIRECTION {
                change(&mut changed.send);
                change(&mut changed.receive);
            }
            changed.receive.records.channels += 1;
            changed.receive.bytes_per_second = 750_013;
            changed.receive.records.codec.datagram_bytes = 768;
            changed.send.records.codec.datagram_bytes = 640;
            changed.validate_cover(appearance(kind, true)?, false)?;
            assert_ne!(changed.send, changed.receive);
            assert_eq!(
                changed.immutable_contract_digest()?,
                original.immutable_contract_digest()?
            );
            assert_ne!(changed.canonical_digest()?, original.canonical_digest()?);
        }
    }
    Ok(())
}

#[test]
fn native_layer_and_paired_native_encoded_limits_remain_fixed() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        for selected in [false, true] {
            let original = if selected {
                streamed(config(kind))
            } else {
                config(kind)
            };
            let mut layer = original;
            layer.send.records.layer = records::Layer::Ip;
            layer.receive.records.layer = records::Layer::Ip;
            assert_bound(original, layer, "native layer")?;
            let mut maximum = original;
            for direction in [&mut maximum.send, &mut maximum.receive] {
                direction.records.max_native += 1;
                direction.records.codec.max_packet += 1;
            }
            assert_bound(original, maximum, "native and encoded packet maxima")?;
            // An encoded maximum cannot change independently of its matching
            // original maximum; both exact codecs must refuse that value.
            let mut encoded_only = original;
            encoded_only.send.records.codec.max_packet += 1;
            assert_refused(encoded_only, "encoded maximum without native maximum")?;
            let mut one_direction = original;
            one_direction.receive.records.max_native += 1;
            one_direction.receive.records.codec.max_packet += 1;
            assert_refused(one_direction, "unequal original native maxima")?;
        }
    }
    Ok(())
}

const FIXED_RUNTIME: &[Change<Config>] = &[
    ("original policy deadline", |c| {
        c.policy.transaction_micros += 1
    }),
    ("policy output custody", |c| c.policy.max_outbound += 1),
    ("common body ceiling", |c| c.security.max_body_bytes += 1),
    ("key packet limit", |c| c.security.packets_per_key += 1),
    ("key byte limit", |c| c.security.max_body_bytes_per_key += 1),
    ("fixed control epoch", |c| c.control_epoch.0 += 1),
    ("base data epoch", |c| c.data_epoch.0 += 1),
    ("shared burst", |c| c.wire.burst_bytes += 1),
    ("receive work period", |c| {
        c.work.receive_interval += Duration::from_nanos(1)
    }),
    ("receive work quota", |c| c.work.receive_packets += 1),
    ("send work quota", |c| c.work.send_batch += 1),
    ("native read quota", |c| c.work.native_read_batch += 1),
    ("native write quota", |c| c.work.native_write_batch += 1),
    ("native packet custody", |c| c.native.pending_packets += 1),
    ("native byte custody", |c| c.native.pending_bytes += 1),
    ("native stall deadline", |c| {
        c.native.stall_timeout += Duration::from_nanos(1)
    }),
    ("established lease", |c| {
        c.lifetime.lease += Duration::from_nanos(1)
    }),
    ("ping interval", |c| {
        c.lifetime.ping_interval += Duration::from_nanos(1)
    }),
    ("original Pong bound", |c| {
        c.lifetime.pong_timeout += Duration::from_nanos(1)
    }),
    ("control source ceiling", |c| {
        c.control.recovery.max_source_bytes += 1
    }),
    ("control send bytes", |c| c.control.recovery.send_bytes += 1),
    ("control receive bytes", |c| {
        c.control.recovery.receive_bytes += 1
    }),
    ("control send records", |c| {
        c.control.recovery.send_records += 1
    }),
    ("control receive records", |c| {
        c.control.recovery.receive_records += 1
    }),
    ("control retry count", |c| {
        c.control.recovery.max_retries += 1
    }),
    ("control minimum RTO", |c| {
        c.control.recovery.initial_rto += Duration::from_nanos(1)
    }),
    ("control maximum RTO", |c| {
        c.control.recovery.maximum_rto += Duration::from_nanos(1)
    }),
    ("control ACK delay", |c| {
        c.control.recovery.ack_delay += Duration::from_nanos(1)
    }),
    ("control refill period", |c| {
        c.control.interval += Duration::from_nanos(1)
    }),
    ("shared control packet quota", |c| {
        c.control.packets_per_interval += 1
    }),
    ("shared control byte quota", |c| {
        c.control.bytes_per_interval += 1
    }),
    ("complete control wire overhead", |c| {
        c.control.wire_overhead += 1
    }),
];

#[test]
fn every_fixed_runtime_resource_and_control_field_is_bound() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        for selected in [false, true] {
            let original = if selected {
                streamed(config(kind))
            } else {
                config(kind)
            };
            for &(label, change) in FIXED_RUNTIME {
                let mut value = original;
                change(&mut value);
                if let Some(settings) = &mut value.streams {
                    // A base-service change is legal only with all three exact
                    // derived services updated; it remains immutable inventory.
                    for entry in &mut settings.streams {
                        entry.delivery = delivery::Settings {
                            wire_overhead: value.control.wire_overhead + streams::HEADER_BYTES,
                            ..value.control
                        };
                    }
                }
                assert_bound(original, value, label)?;
            }
        }
    }
    Ok(())
}

const FIXED_STREAM: &[Change<messages::Settings>] = &[
    ("whole-message ceiling", |s| s.max_message_bytes += 1),
    ("retained output entries", |s| s.max_outbound_messages += 1),
    ("retained output bytes", |s| s.max_outbound_bytes += 1),
    ("fragment bound", |s| s.max_fragments += 1),
    ("reassembly reservation", |s| s.max_reassembly_bytes += 1),
    ("incomplete-message quota", |s| {
        s.max_incomplete_messages += 1
    }),
    ("message lifetime", |s| {
        s.message_lifetime += Duration::from_nanos(1)
    }),
    ("message work budget", |s| s.work_per_call += 1),
];

#[test]
fn backend_selection_and_each_stream_resource_are_bound_in_fixed_order() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let legacy = config(kind);
        let original = streamed(legacy);
        assert_bound(legacy, original, "explicit independent-stream selection")?;
        assert_ne!(
            legacy.canonical_digest()?,
            legacy.immutable_contract_digest()?
        );
        assert_ne!(
            original.canonical_digest()?,
            original.immutable_contract_digest()?
        );
        for index in 0..3 {
            for &(label, change) in FIXED_STREAM {
                let mut value = original;
                change(
                    &mut value
                        .streams
                        .as_mut()
                        .ok_or("missing selected streams")?
                        .streams[index],
                );
                assert_bound(original, value, label)?;
            }
        }
        let mut first = original;
        first.streams.as_mut().ok_or("missing streams")?.streams[0].max_outbound_messages += 1;
        let mut second = original;
        second.streams.as_mut().ok_or("missing streams")?.streams[1].max_outbound_messages += 1;
        assert_bound(first, second, "fixed Transaction/Liveness ordering")?;
    }
    Ok(())
}

#[test]
fn local_reporting_is_excluded_without_skipping_its_validation() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        for selected in [false, true] {
            let original = if selected {
                streamed(config(kind))
            } else {
                config(kind)
            };
            for interval in [
                None,
                Some(Duration::from_micros(1)),
                Some(Duration::from_nanos(17_000_001)),
            ] {
                let mut changed = original;
                changed.report_interval = interval;
                assert_eq!(
                    changed.immutable_contract_digest()?,
                    original.immutable_contract_digest()?
                );
                assert_eq!(changed.canonical_digest()?, original.canonical_digest()?);
            }
            for interval in [Duration::ZERO, Duration::from_nanos(999)] {
                let mut invalid = original;
                invalid.report_interval = Some(interval);
                assert_refused(invalid, "unusable reporting interval")?;
            }
        }
    }
    Ok(())
}

const INVALID_RUNTIME: &[Change<Config>] = &[
    ("low active MTU", |c| c.path_mtu = 255),
    ("high active MTU", |c| c.path_mtu = 65_536),
    ("zero send channels", |c| c.send.records.channels = 0),
    ("receive channels outside bound", |c| {
        c.receive.records.channels = 65
    }),
    ("zero forward rate", |c| c.send.bytes_per_second = 0),
    ("reverse rate outside bound", |c| {
        c.receive.bytes_per_second = 1_250_000_001
    }),
    ("inconsistent repair fraction", |c| {
        c.send.records.codec.repair_numerator = 5
    }),
    ("zero repair denominator", |c| {
        c.receive.records.codec.repair_denominator = 0
    }),
    ("packing queue below one record", |c| {
        c.send.records.codec.queue_bytes = 512
    }),
    ("source flight below window", |c| {
        c.receive.records.codec.flow_sources = 7
    }),
    ("source outside common body ceiling", |c| {
        c.send.records.codec.datagram_bytes = 1301
    }),
    ("zero feedback timer", |c| {
        c.receive.records.codec.feedback_micros = 0
    }),
    ("mismatched native layer", |c| {
        c.receive.records.layer = records::Layer::Ip
    }),
    ("zero policy deadline", |c| c.policy.transaction_micros = 0),
    ("policy custody outside bound", |c| {
        c.policy.max_outbound = 65
    }),
    ("zero key packet limit", |c| c.security.packets_per_key = 0),
    ("key byte limit below packet", |c| {
        c.security.max_body_bytes_per_key = 1299
    }),
    ("zero control epoch", |c| c.control_epoch.0 = 0),
    ("zero data epoch", |c| c.data_epoch.0 = 0),
    ("burst outside bound", |c| {
        c.wire.burst_bytes = MAX_QUEUE + 1
    }),
    ("zero receive work quota", |c| c.work.receive_packets = 0),
    ("zero send work quota", |c| c.work.send_batch = 0),
    ("ineffective work timer", |c| {
        c.work.receive_interval = Duration::from_nanos(999)
    }),
    ("zero native packet custody", |c| {
        c.native.pending_packets = 0
    }),
    ("native byte custody below packet", |c| {
        c.native.pending_bytes = 511
    }),
    ("ineffective native deadline", |c| {
        c.native.stall_timeout = Duration::from_nanos(999)
    }),
    ("unrepresentable session clock", |c| {
        c.lifetime.lease = Duration::MAX
    }),
    ("zero challenge deadline", |c| {
        c.lifetime.pong_timeout = Duration::ZERO
    }),
    ("zero control packet quota", |c| {
        c.control.packets_per_interval = 0
    }),
    ("control bytes below one pair", |c| {
        c.control.bytes_per_interval = 1
    }),
    ("control source size overflow", |c| {
        c.control.recovery.max_source_bytes = usize::MAX
    }),
    ("control overhead overflow", |c| {
        c.control.wire_overhead = usize::MAX
    }),
];

#[test]
fn invalid_policy_and_fixed_resources_are_not_normalized_into_valid_envelopes() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let original = config(kind);
        for &(label, change) in INVALID_RUNTIME {
            let mut value = original;
            change(&mut value);
            assert_refused(value, label)?;
        }
    }
    Ok(())
}

#[test]
fn invalid_derived_stream_geometry_or_limits_cannot_be_masked() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let original = streamed(config(kind));
        let invalid: &[Change<messages::Settings>] = &[
            ("derived MTU mismatch", |s| s.path_mtu -= 1),
            ("derived service quota mismatch", |s| {
                s.delivery.packets_per_interval += 1
            }),
            ("missing wrapper charge", |s| {
                s.delivery.wire_overhead -= streams::HEADER_BYTES
            }),
            ("zero message size", |s| s.max_message_bytes = 0),
            ("too few fragments for full message", |s| {
                s.max_fragments = 1
            }),
            ("zero output ledger", |s| s.max_outbound_messages = 0),
            ("reassembly below full message", |s| {
                s.max_reassembly_bytes = 4095
            }),
            ("zero incomplete-message quota", |s| {
                s.max_incomplete_messages = 0
            }),
            ("zero message lifetime", |s| {
                s.message_lifetime = Duration::ZERO
            }),
            ("unrepresentable message clock", |s| {
                s.message_lifetime = Duration::MAX
            }),
            ("zero message work budget", |s| s.work_per_call = 0),
        ];
        for index in 0..3 {
            for &(label, change) in invalid {
                let mut value = original;
                change(&mut value.streams.as_mut().ok_or("missing streams")?.streams[index]);
                assert_refused(value, label)?;
            }
        }
        let mut epoch = original;
        epoch.control_epoch.0 = u64::MAX;
        assert_refused(epoch, "independent stream epoch derivation overflow")?;
        let mut unpaired_mtu = original;
        unpaired_mtu.path_mtu -= 1;
        assert_refused(
            unpaired_mtu,
            "active MTU changed without its derived stream geometry",
        )?;
    }
    Ok(())
}
