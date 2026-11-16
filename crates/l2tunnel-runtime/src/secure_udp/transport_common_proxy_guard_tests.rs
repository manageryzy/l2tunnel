//! Immutable proxy boundaries use the real catalog and existing transaction owner.
use super::*;
use l2tunnel::record_configuration as c;
use l2tunnel_core::traffic;
use l2tunnel_pipeline as pipeline;

fn descriptor(proxy: bool) -> Result<c::Descriptor> {
    let original = udp_values(cover::Appearance::QuicLike)?[1];
    let old = original.descriptor();
    let c::Profile::Aligned {
        mut forward,
        mut reverse,
    } = *old.profile()
    else {
        return Err("Aligned fixture missing".into());
    };
    for value in [&mut forward, &mut reverse] {
        value.native_policy = l2tunnel_aligned::NativePolicy::RawIp;
        value.receiver.channels = 1;
        value.receiver.body.max_frame_bytes = 96;
        value.receiver.body.elide_payload_length = false;
        value.receiver.body.predictive = false;
        value.receiver.body.timestamp_pair_dictionary = false;
        value.receiver.body.independent_short_frame_bytes = 0;
        value.recovery.repair_symbols = 0;
    }
    let direction = |role| -> Result<c::CommonDirection> {
        let old = old.direction(role).common();
        let mut queues = old.pipeline();
        queues.flows.channels = 1;
        queues.parse.max_packet_bytes = 96;
        queues.profile = pipeline::Profile::TunDrr(pipeline::TunQosConfig {
            base_quantum_bytes: 1500,
            max_weight: 1,
            per_flow: queues.queue,
        });
        Ok(c::CommonDirection::new(
            traffic::TrafficPolicy {
                layer: traffic::NetworkLayer::Tun,
                tcp: if proxy {
                    traffic::TcpControl::SplitTcpProxy
                } else {
                    traffic::TcpControl::System
                },
                qos: traffic::Qos::WeightedDeficit,
            },
            queues,
            old.bytes_per_second(),
            old.burst_bytes(),
            old.native_window(),
        )?)
    };
    Ok(c::Descriptor::new(
        old.path_mtu(),
        old.duplex(),
        direction(mg::Role::Client)?,
        direction(mg::Role::Server)?,
        c::Profile::Aligned { forward, reverse },
    )?)
}

#[test]
fn native_adapter_rejects_unbound_bound_and_later_proxy_catalog_entries() -> Result {
    let native = descriptor(false)?;
    let proxy = descriptor(true)?;
    let contract = |initial, values: &[c::Descriptor]| -> Result<CommonTransactionContract> {
        Ok(contracts_with_catalog(
            cover::Appearance::QuicLike,
            Catalog::new(initial, values)?,
            16,
        )?[0]
            .clone())
    };
    contract(native, &[native])?.require_native_adapter()?;
    for value in [
        contract(proxy, &[proxy])?,
        contract(proxy, &[proxy])?.with_proxy_binding(core::ConfigDigest([0x77; 32]))?,
        contract(native, &[native, proxy])?,
    ] {
        let error = value
            .require_native_adapter()
            .err()
            .ok_or("proxy native adapter accepted")?;
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }
    Ok(())
}

#[tokio::test]
async fn proxy_local_switch_refuses_same_configuration_without_new_generation() -> Result {
    let descriptor = descriptor(true)?;
    let contracts = contracts_with_catalog(
        cover::Appearance::QuicLike,
        Catalog::new(descriptor, &[descriptor])?,
        16,
    )?;
    let contracts = [
        contracts[0]
            .clone()
            .with_proxy_binding(core::ConfigDigest([0x77; 32]))?,
        contracts[1]
            .clone()
            .with_proxy_binding(core::ConfigDigest([0x77; 32]))?,
    ];
    let mut fixture = Fixture::from_contracts(cover::Appearance::QuicLike, contracts).await?;
    let endpoint = &mut fixture.endpoints[0];
    let current = *endpoint.driver.common_state()?.current();
    let epoch = endpoint.driver.common_state()?.epoch();
    let before = endpoint.driver.common_state()?.usage();
    let (reply, mut result) = oneshot::channel();
    endpoint
        .driver
        .request_common(fixture.now, current, reply)?;
    assert_eq!(result.try_recv()?, Err(SwitchError::Invalid));
    assert_eq!(endpoint.driver.common_state()?.epoch(), epoch);
    assert_eq!(endpoint.driver.common_state()?.usage(), before);
    assert!(endpoint.driver.common_state()?.peer().operation().is_none());
    assert!(
        endpoint
            .driver
            .common
            .as_ref()
            .ok_or("Common missing")?
            .request
            .is_none()
    );
    Ok(())
}
