//! Genuine maintained TLS/member + initial-only Noise/member carrier handoff.
//! This finite test uses each explicit research policy in the sole existing
//! Common loop; it does not claim Python network-arrival or throughput parity.
use super::*;
use l2tunnel::{
    codec,
    fec::{research, rolling},
    record_configuration as c, record_engine as engine, research_records, rolling_records,
};

fn policies() -> [research::Profile; 3] {
    [
        research::Profile::Recursive {
            taps: 1,
            width: 1,
            reset: 1,
            fresh_interval: 0,
        },
        research::Profile::Recursive {
            taps: 1,
            width: 1,
            reset: 1,
            fresh_interval: 2,
        },
        research::Profile::Accumulator {
            lanes: 3,
            window: 16,
        },
    ]
}
fn selected_research(
    outer: &establish::carrier::AuthenticatedOuter,
    client: bool,
    policy: research::Profile,
) -> Result<(establish::Config, CommonTransactionContract)> {
    let (mut setup, template) = selected(outer, client)?;
    let mut resources = template.resources();
    resources.rolling_work = Some(rolling::WorkBudget {
        field: 4096,
        copies: 4096,
        metadata: 4096,
    });
    resources.rolling_ingress = Some(rolling_records::IngressLimits {
        slots: 16,
        capacity_bytes: 1 << 20,
    });
    let packed = super::super::super::common_engines::tests::values()
        .map_err(|error| io::Error::other(error.to_string()))?[2];
    let c::Profile::Packed { forward, reverse } = *packed.descriptor().profile() else {
        return Err("actual packed fixture".into());
    };
    let direction = |packed: l2tunnel_aligned::packed::Config| {
        let mut receiver = packed.base.receiver;
        receiver.lifetime_ticks = 5_000_000;
        research_records::DirectionConfig {
            native_policy: packed.base.native_policy,
            receiver,
            packing: codec::packed_sender::Config {
                sender: codec::aligned_sender::Config {
                    body: receiver.body,
                    channels: receiver.channels,
                    first_record: receiver.first_record,
                },
                packing: codec::packed::Config {
                    symbol_bytes: receiver.body.symbol_bytes,
                    hold_micros: packed.hold_micros,
                },
                max_units: packed.max_units,
                first_unit: receiver.first_source,
                work_limit: packed.work_limit,
            },
            codec_stage_micros: 1_000_000,
            scheduler: research::Config {
                recovery: rolling::Config {
                    window: 16,
                    local_window: 4,
                    global_every: 2,
                    max_payload: 1024,
                    max_rows: 16,
                    repair_history: 64,
                    handoff_sources: 2,
                    job_ticks: 1_000_000,
                    debt_ticks: 10_000_000,
                    handoff_ticks: 2_000_000,
                    memory_bytes: 16 << 20,
                },
                profile: policy,
                feedback_ticks: 100,
                memory_bytes: 16 << 20,
            },
        }
    };
    let old = packed.descriptor();
    let descriptor = c::Descriptor::new(
        old.path_mtu(),
        old.duplex(),
        *old.direction(mg::Role::Client).common(),
        *old.direction(mg::Role::Server).common(),
        c::Profile::Research {
            config: research_records::Config {
                forward: direction(forward),
                reverse: direction(reverse),
                geometry: engine::Geometry {
                    forward_overhead_bytes: resources.control.wire_overhead,
                    reverse_overhead_bytes: resources.control.wire_overhead,
                },
                native_stall_micros: u64::try_from(resources.native.stall_timeout.as_micros())?,
            },
            stream: 17,
        },
    )?;
    let contract = CommonTransactionContract::new_on_carrier_paired_compact(
        security::ConfigDigest([3; 32]),
        if client {
            security::Role::Initiator
        } else {
            security::Role::Responder
        },
        [resources; 2],
        setup.cover,
        false,
        EnvelopeDigest::new([0x39; 32]),
        Catalog::new(descriptor, &[descriptor])?,
        TransactionSettings {
            protocol: transaction::Settings {
                retry_ms: 10,
                phase_timeout_ms: 1000,
                reconcile_timeout_ms: 2000,
            },
            max_operation_ms: 3000,
            retained_bytes: 256 << 20,
        },
        *outer,
        template.compact_wire(),
    )?;
    assert_eq!(contract.compact_wire(), template.compact_wire());
    setup.binding.configuration = contract.expected_configuration().0;
    Ok((setup, contract))
}
fn variable_frame(marker: u8, length: usize) -> io::Result<Vec<u8>> {
    let mut bytes = ethernet(marker);
    bytes.resize(length, marker);
    Ok(bytes)
}
#[tokio::test]
async fn actual_initial_only_openvpn_research_three_policies_preserve_native_and_liveness() -> Result
{
    for policy in policies() {
        Box::pin(exercise_policy(policy)).await?;
    }
    Ok(())
}
async fn exercise_policy(policy: research::Profile) -> Result {
    let mut outer = factory_fixture::outer_config();
    outer.base.layer = PacketLayer::Ethernet;
    outer.path_mtu = 1500;
    outer.max_record_bytes = 1471;
    let [(a, a_contract), (b, b_contract)] =
        factory_fixture::initial::initial_parts(outer, |proof, client| {
            selected_research(proof, client, policy)
        })
        .await?;
    let endpoints = a.outer().endpoints();
    let cap = a.deadline.min(b.deadline);
    assert_eq!(a.datagram.addresses(), endpoints);
    assert_eq!(b.datagram.addresses(), (endpoints.1, endpoints.0));
    assert_eq!(
        a_contract.expected_configuration(),
        b_contract.expected_configuration()
    );
    let (a_device, a_host) = device()?;
    let (b_device, b_host) = device()?;
    let (a_stop, a_shutdown) = oneshot::channel::<()>();
    let (b_stop, b_shutdown) = oneshot::channel::<()>();
    let verified = Arc::new(AtomicUsize::new(0));
    let a_verified = verified.clone();
    let b_verified = verified.clone();
    let a_run = run_common_on_carrier(
        a_device,
        a,
        a_contract,
        None,
        async move {
            let _ = a_shutdown.await;
        },
        move |snapshot| {
            if snapshot.liveness.last_pong_micros.is_some() {
                a_verified.fetch_or(1, Ordering::Relaxed);
            }
        },
    );
    let b_run = run_common_on_carrier(
        b_device,
        b,
        b_contract,
        None,
        async move {
            let _ = b_shutdown.await;
        },
        move |snapshot| {
            if snapshot.liveness.last_pong_micros.is_some() {
                b_verified.fetch_or(2, Ordering::Relaxed);
            }
        },
    );
    let exercise = async move {
        let result = tokio::time::timeout_at(cap, async {
            for (marker, length) in [(31, 1024), (42, 975)] {
                let forward = variable_frame(marker, length)?;
                let reverse = variable_frame(marker + 1, length)?;
                assert_eq!(a_host.send(&forward).await?, forward.len());
                assert_eq!(b_host.send(&reverse).await?, reverse.len());
                let mut a_packet = [0; 2048];
                let mut b_packet = [0; 2048];
                let (a_bytes, b_bytes) =
                    tokio::try_join!(a_host.recv(&mut a_packet), b_host.recv(&mut b_packet))?;
                assert_eq!(&a_packet[..a_bytes], reverse);
                assert_eq!(&b_packet[..b_bytes], forward);
            }
            loop {
                if verified.load(Ordering::Relaxed) == 3 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            Ok::<_, io::Error>(())
        })
        .await;
        let _ = a_stop.send(());
        let _ = b_stop.send(());
        result??;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    };
    let (a, b, exercise) = tokio::join!(a_run, b_run, exercise);
    // Preserve the real owner failure before an exercise timeout obscures it.
    for (side, result) in [("initiator", &a), ("responder", &b)] {
        if let Err(error) = result {
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "Research {policy:?} {side} runtime failed: {error}; initiator={a:?}; responder={b:?}; exercise={exercise:?}"
                ),
            )
            .into());
        }
    }
    if let Err(error) = exercise {
        return Err(io::Error::other(format!(
            "Research {policy:?} exercise failed: {error}; initiator={a:?}; responder={b:?}"
        ))
        .into());
    }
    for (side, stopped) in [a?, b?].into_iter().enumerate() {
        assert_eq!(stopped.reason, StopReason::Cancelled);
        let expected = if side == 0 {
            endpoints
        } else {
            (endpoints.1, endpoints.0)
        };
        assert_eq!(
            (
                stopped.snapshot.info.local_addr,
                stopped.snapshot.info.peer_addr
            ),
            expected
        );
        assert_eq!(stopped.snapshot.counters.native_written, 2);
        assert!(stopped.snapshot.counters.socket_accepted_packets > 0);
        assert!(stopped.snapshot.counters.user_number.is_some());
        assert!(stopped.snapshot.counters.control_number.is_some());
        assert!(stopped.snapshot.liveness.last_pong_micros.is_some());
        assert_eq!(stopped.snapshot.counters.socket_drops, 0);
        assert!(!stopped.snapshot.running);
    }
    Ok(())
}
