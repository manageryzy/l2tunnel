//! Pure selected policy/geometry tests; no initial authority or runtime installation.
use super::*;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Inputs {
    resources: Config,
    cover: cover::Config,
    catalog: common::Catalog,
    settings: TransactionSettings,
    streams: control_owner::SettingsV2,
}
fn inputs(kind: cover::Appearance) -> Result<Inputs> {
    let values = super::super::super::common_engines::tests::values()?;
    let descriptor = *values[0].descriptor();
    let common::Profile::Swift { forward, reverse } = *descriptor.profile() else {
        return Err("Swift fixture absent".into());
    };
    let overhead = 28
        + record::ROUTE_BYTES
        + security::refresh::PREFIX_BYTES
        + security::Protection::ChaCha20Poly1305.tag_bytes()
        + if kind == cover::Appearance::QuicLike {
            13
        } else {
            14
        };
    let base = delivery::Settings {
        recovery: recovery::ArqConfig {
            max_source_bytes: 192,
            send_bytes: 6144,
            receive_bytes: 6144,
            send_records: 32,
            receive_records: 32,
            initial_rto: Duration::from_millis(10),
            maximum_rto: Duration::from_millis(100),
            ack_delay: Duration::from_millis(1),
            max_retries: 16,
        },
        interval: Duration::from_millis(1),
        packets_per_interval: 16,
        bytes_per_interval: 65536,
        wire_overhead: overhead,
    };
    let entry = mg::messages::Settings {
        delivery: delivery::Settings {
            wire_overhead: base.wire_overhead + streams::v2::HEADER_BYTES,
            ..base
        },
        path_mtu: descriptor.path_mtu(),
        max_message_bytes: 4096,
        max_outbound_messages: 4,
        max_outbound_bytes: 131072,
        max_fragments: 32,
        max_reassembly_bytes: 16384,
        max_incomplete_messages: 2,
        message_lifetime: Duration::from_secs(5),
        work_per_call: 8,
    };
    let resources = Config {
        path_mtu: descriptor.path_mtu(),
        send: policy::Direction {
            records: forward,
            bytes_per_second: 1_000_000,
        },
        receive: policy::Direction {
            records: reverse,
            bytes_per_second: 1_000_000,
        },
        policy: policy::Settings {
            transaction_micros: 1_000_000,
            max_outbound: 8,
        },
        security: security::Limits {
            max_body_bytes: 1300,
            packets_per_key: 8,
            max_body_bytes_per_key: 100000,
        },
        control: base,
        control_epoch: security::Epoch(1),
        streams: Some(control_owner::Settings {
            streams: [entry; 3],
        }),
        data_epoch: security::Epoch(1),
        wire: WireBudget { burst_bytes: 4096 },
        work: WorkBudget {
            receive_interval: Duration::from_millis(1),
            receive_packets: 64,
            send_batch: 16,
            native_read_batch: 16,
            native_write_batch: 16,
        },
        rolling_work: None,
        ack_coalescing: None,
        connection_ingress: None,
        rolling_fragments: None,
        rolling_ingress: None,
        native: NativeBudget {
            pending_packets: 16,
            pending_bytes: 8192,
            stall_timeout: Duration::from_secs(1),
        },
        lifetime: Lifetime {
            lease: Duration::from_secs(60),
            ping_interval: Duration::from_millis(20),
            pong_timeout: Duration::from_millis(500),
        },
        report_interval: None,
    };
    Ok(Inputs {
        resources,
        cover: cover::Config::new(
            kind,
            cover::ConnectionIds {
                local: cover::ConnectionId([1; 8]),
                peer: cover::ConnectionId([2; 8]),
            },
            cover::MediaConfig {
                local_ssrc: cover::Ssrc(1),
                peer_ssrc: cover::Ssrc(2),
                payload_type: 96,
            },
            cover::Limits {
                max_packet_bytes: 1500,
                max_protected_bytes: 1400,
            },
        )?,
        catalog: common::Catalog::new(descriptor, &[descriptor])?,
        settings: TransactionSettings {
            protocol: transaction::Settings {
                retry_ms: 10,
                phase_timeout_ms: 1000,
                reconcile_timeout_ms: 2000,
            },
            max_operation_ms: 3000,
            retained_bytes: 256 << 20,
        },
        streams: control_owner::SettingsV2 {
            streams: [entry; 4],
        },
    })
}
fn policy() -> FreshKeyPolicy {
    FreshKeyPolicy {
        exchange_micros: 1_000_000,
        key_micros: 5_000_000,
        overlap_micros: 1000,
        max_flight_copies: 8,
    }
}
impl Inputs {
    fn contract(&self, fresh: FreshKeyPolicy) -> io::Result<CommonTransactionContract> {
        CommonTransactionContract::new_managed(
            security::ConfigDigest([31; 32]),
            security::Role::Initiator,
            self.resources,
            self.cover,
            false,
            common::EnvelopeDigest::new([42; 32]),
            self.catalog.clone(),
            self.settings,
            self.streams,
            fresh,
        )
    }
}
#[test]
fn managed_complete_control_selection_envelope_and_setup_are_distinct_and_sensitive() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let mut input = inputs(kind)?;
        let initial = input.contract(policy())?;
        let selection = initial
            .refresh_selection()
            .ok_or("missing managed selection")?;
        let spec = selection.spec();
        assert_eq!(spec.envelope_digest.0, *initial.envelope().as_bytes());
        assert_eq!(spec.control_epoch, input.resources.control_epoch);
        assert_eq!(selection, Selection::decode(&selection.canonical_bytes())?);
        assert_ne!(spec.control_digest.0, initial.expected_configuration().0);
        assert_ne!(spec.envelope_digest.0, initial.expected_configuration().0);
        assert_eq!(
            initial.fixed_control_scope(),
            Some(l2tunnel::secure_record::Scope {
                epoch: spec.control_epoch,
                configuration: spec.control_digest
            })
        );
        assert_eq!(initial.initial().envelope(), initial.envelope());
        assert_eq!(initial.managed_streams(), Some(input.streams));
        assert_eq!(initial.extra_wire_bytes(), 0);
        initial.validate_outer(None)?;
        // One actual Lifecycle resource changes fixed control, E1 and resulting H0.
        input.streams.streams[3].max_incomplete_messages += 1;
        let changed = input.contract(policy())?;
        assert_ne!(changed.fixed_control_scope(), initial.fixed_control_scope());
        assert_ne!(changed.envelope(), initial.envelope());
        assert_ne!(
            changed.expected_configuration(),
            initial.expected_configuration()
        );
        let mut fresh = policy();
        fresh.max_flight_copies += 1;
        let freshened = input.contract(fresh)?;
        assert_eq!(
            freshened.fixed_control_scope(),
            changed.fixed_control_scope()
        );
        assert_ne!(freshened.envelope(), changed.envelope());
        assert_ne!(
            freshened.expected_configuration(),
            changed.expected_configuration()
        );
    }
    Ok(())
}
#[test]
fn managed_refuses_first_three_mismatch_v2_map_and_prefix_geometry_without_clamping() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let mut input = inputs(kind)?;
        assert_eq!(
            input.contract(policy())?.geometry().forward_overhead_bytes,
            input.resources.control.wire_overhead
        );
        input.streams.streams[0].max_incomplete_messages += 1;
        assert!(input.contract(policy()).is_err());
        input.streams.streams[0].max_incomplete_messages -= 1;
        let original = input.resources.control_epoch;
        input.resources.control_epoch = security::Epoch(u64::MAX / 4 + 1);
        assert!(input.contract(policy()).is_err());
        input.resources.control_epoch = original;
        let mut fresh = policy();
        fresh.overlap_micros = fresh.key_micros;
        assert!(input.contract(fresh).is_err());
        // Retaining v1 cost for selected v2 must refuse instead of shrinking body.
        input.resources.control.wire_overhead -=
            security::refresh::PREFIX_BYTES - security::COMMON_PREFIX_BYTES;
        for entry in &mut input.streams.streams {
            entry.delivery.wire_overhead =
                input.resources.control.wire_overhead + streams::HEADER_BYTES;
        }
        input.resources.streams = Some(control_owner::Settings {
            streams: [input.streams.streams[0]; 3],
        });
        assert!(input.contract(policy()).is_err());
    }
    Ok(())
}
#[test]
fn unselected_constructor_retains_exact_caller_labels_and_v1_geometry() -> Result {
    let mut input = inputs(cover::Appearance::QuicLike)?;
    input.resources.control.wire_overhead -=
        security::refresh::PREFIX_BYTES - security::COMMON_PREFIX_BYTES;
    for entry in &mut input.streams.streams {
        entry.delivery.wire_overhead =
            input.resources.control.wire_overhead + streams::HEADER_BYTES;
    }
    input.resources.streams = Some(control_owner::Settings {
        streams: [input.streams.streams[0]; 3],
    });
    let max_native = input
        .catalog
        .initial()
        .direction(mg::Role::Client)
        .max_native()
        .max(
            input
                .catalog
                .initial()
                .direction(mg::Role::Server)
                .max_native(),
        );
    let before = input.resources.common_resource_digest(max_native)?;
    let old = CommonTransactionContract::new(
        security::ConfigDigest([31; 32]),
        security::Role::Initiator,
        input.resources,
        input.cover,
        false,
        common::EnvelopeDigest::new([42; 32]),
        input.catalog.clone(),
        input.settings,
    )?;
    assert_eq!(
        old.expected_configuration(),
        security::ConfigDigest([31; 32])
    );
    assert_eq!(old.envelope(), common::EnvelopeDigest::new([42; 32]));
    assert_eq!(old.resources().common_resource_digest(max_native)?, before);
    assert_eq!(old.refresh_selection(), None);
    assert_eq!(old.managed_streams(), None);
    assert_eq!(old.fixed_control_scope(), None);
    assert_eq!(old.extra_wire_bytes(), 0);
    old.validate_outer(None)?;
    Ok(())
}
