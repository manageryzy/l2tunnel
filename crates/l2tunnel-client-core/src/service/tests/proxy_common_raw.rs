//! Actual TLS-to-raw/Noise/member/proxy composition on owned injected PacketIo.
//! This is not a kernel capture, native advertised-window or ISP qualification.
use super::super::super::proxy_common as fixed;
use super::*;

fn full_settings(
    local: std::net::SocketAddr,
    peer: std::net::SocketAddr,
    p: PacketPolicy,
) -> Result<RawSettings> {
    let packet = serde_json::json!({"mtu":p.mtu,"protection":"aead","queue_packets":p.queue_packets,
        "horizon_bytes":p.horizon_bytes,"minimum_transfer_bytes":p.minimum_transfer_bytes,
        "bytes_per_second":p.bytes_per_second,"packets_per_second":p.packets_per_second,
        "burst_bytes":p.burst_bytes,"burst_packets":p.burst_packets,
        "max_key_packets":p.max_key_packets,"max_key_bytes":p.max_key_bytes});
    Ok(RawSettings::from_json(&serde_json::to_vec(
        &serde_json::json!({
            "version":1,"profile":"raw-common-carrier-v1",
            "forward":{"local":local,"peer":peer},"reverse":null,"packet":packet,
        }),
    )?)?)
}

fn plans(hosts: &[Arc<Host>; 2]) -> Result<(CarrierPlans, Vec<Arc<Probe>>)> {
    let CarrierPlans {
        plans: [left, right],
        addresses,
        requested: trust,
    } = carrier_plans(l2tunnel_cover::Appearance::QuicLike, hosts, false)?;
    let (unused, base) = fixed::fixture_selected(hosts, true)?;
    drop(unused); // Neither helper has started I/O or opened an attachment.
    let policy = PacketPolicy::new(1500);
    let geometry = policy.record_geometry()?;
    let physical = geometry
        .ip_tcp_bytes
        .checked_add(geometry.record_overhead_bytes)
        .ok_or("raw physical overhead")?;
    let mut resources = [
        base.requested_resources(Role::Initiator),
        base.requested_resources(Role::Responder),
    ];
    let delta = physical
        .checked_sub(28)
        .ok_or("raw fixture overhead order")?;
    for resource in &mut resources {
        resource.path_mtu = usize::from(policy.mtu);
        resource.security.max_body_bytes = 1260;
        resource.control.wire_overhead = resource
            .control
            .wire_overhead
            .checked_add(delta)
            .ok_or("raw control overhead")?;
        resource.report_interval = Some(Duration::from_millis(1));
        for stream in &mut resource
            .streams
            .as_mut()
            .ok_or("actual stream policies")?
            .streams
        {
            stream.path_mtu = usize::from(policy.mtu);
            stream.delivery.wire_overhead = stream
                .delivery
                .wire_overhead
                .checked_add(delta)
                .ok_or("raw stream overhead")?;
        }
    }
    // Native IPv4/IPv6 MTU1280 retains the existing proxy guard. Opaque frames
    // use the existing Aligned unit fragmentation within raw physical MTU1500.
    let direction = |resource: transport::Config| -> Result<common::CommonDirection> {
        let original = common_direction(1, 1600, resource.send.bytes_per_second)?;
        Ok(common::CommonDirection::new(
            traffic::TrafficPolicy {
                tcp: traffic::TcpControl::SplitTcpProxy,
                ..original.traffic()
            },
            original.pipeline(),
            original.bytes_per_second(),
            original.burst_bytes(),
            common::NativeWindow::Disabled,
        )?)
    };
    let mut forward = aligned_direction(1600, 1, resources[0].control.wire_overhead, false);
    let mut reverse = aligned_direction(1600, 1, resources[1].control.wire_overhead, false);
    for value in [&mut forward, &mut reverse] {
        value.receiver.body.symbol_bytes = 1024;
        let original = 48 + value.receiver.body.symbol_bytes;
        let wrapped = 44 + original;
        value.recovery.arq.max_source_bytes = original;
        value.recovery.arq.send_bytes = 8 * original;
        value.recovery.arq.receive_bytes = 8 * original;
        value.recovery.fec.block.max_source_bytes = wrapped;
        value.recovery.fec.block.max_packet_bytes = 56 + 2 + 2 + wrapped;
        value.recovery.repair_symbols = 0;
        value.recovery.max_restored_bytes = value.recovery.max_restored_packets * wrapped;
        value.max_recovery_packet_bytes = value.recovery.maximum_packet_bytes()?;
    }
    let descriptor = common::Descriptor::new(
        usize::from(policy.mtu),
        l2tunnel_core::Duplex::Full,
        direction(resources[0])?,
        direction(resources[1])?,
        common::Profile::Aligned { forward, reverse },
    )?;
    let mut settings = trust.settings();
    // Explicit new finite geometry, never a clamp of an accepted descriptor.
    settings.cover.max_packet_bytes = geometry.max_record_bytes;
    settings.cover.max_protected_bytes = 1300;
    settings.gate.arq.max_source_bytes = 1024;
    let mut connection = base.connection();
    connection.max_packet = 1280;
    let mut proxy = base
        .proxy_config()
        .cloned()
        .ok_or("explicit fixed proxy policy")?;
    proxy.runtime.max_packet = 1280;
    proxy.native.mtu = 1280;
    let requested = common_transaction_profile::Profile::new_proxy_raw_retained(
        connection,
        settings,
        trust.peers(),
        resources[0],
        resources[1],
        common::Catalog::new(descriptor, &[descriptor])?,
        base.parameters(),
        proxy,
        policy,
    )?;
    assert!(requested.raw_binding().is_none() && requested.carrier_binding().is_none());
    let (_, [left_open, right_open], probes) = raw_originals(addresses, policy, 1)?;
    let local = [
        full_settings(addresses[0], addresses[1], policy)?,
        full_settings(addresses[1], addresses[0], policy)?,
    ];
    let convert = |plan: Prepared, raw, opener| -> Result<Prepared> {
        let data = Arc::try_unwrap(plan.data)
            .map_err(|_| "unstarted actual credentials unexpectedly shared")?;
        match data.endpoint {
            prepared::Endpoint::CommonCarrierClient { outer, inner } => {
                Ok(Prepared::proxy_common_raw_client(
                    requested.clone(),
                    raw,
                    outer,
                    inner,
                    opener,
                    data.attachment,
                )?)
            }
            prepared::Endpoint::CommonCarrierServer(server) => {
                let prepared::CommonCarrierServer {
                    outer,
                    inner,
                    admission,
                } = *server;
                assert!(admission.into_inner().is_none());
                Ok(Prepared::proxy_common_raw_server(
                    requested.clone(),
                    raw,
                    outer,
                    inner,
                    opener,
                    data.attachment,
                )?)
            }
            _ => Err("unstarted actual original carrier credential variant".into()),
        }
    };
    let [a, b] = local;
    let plans = [convert(left, a, left_open)?, convert(right, b, right_open)?];
    assert!(probes.iter().all(|p| p.opened.load(Ordering::SeqCst) == 0));
    assert!(hosts.iter().all(|h| h.opened.load(Ordering::SeqCst) == 0));
    Ok((
        CarrierPlans {
            plans,
            addresses,
            requested,
        },
        probes,
    ))
}

#[tokio::test]
async fn actual_raw_full_common_proxy_preserves_physical_custody_tcp_bytes_liveness_retirement_and_release()
-> Result {
    timeout(Duration::from_secs(35),async {
        let hosts=support::hosts();
        let (CarrierPlans{plans:[a,b],addresses,requested},probes)=plans(&hosts)?;
        let (client,run)=channel();let (server,peer)=channel();
        let tasks=[tokio::spawn(run),tokio::spawn(peer)];
        let handles=[client,server];
        let accepted=[handles[0].connect(a,handles[0].next_key().map_err(submit)?).map_err(submit)?,
            handles[1].connect(b,handles[1].next_key().map_err(submit)?).map_err(submit)?];
        tokio::try_join!(connected(&handles[0],accepted[0]),connected(&handles[1],accepted[1]))?;
        let generations=handles.each_ref().map(|h|h.snapshot().generation);
        let syns:Vec<_>=probes.iter().map(|p|p.syns.load(Ordering::SeqCst)).collect();
        for (side,handle) in handles.iter().enumerate() {
            let frame=fixed::proxy_frame(handle)?;
            let common=frame.common.ok_or("actual raw proxy/Common observation")?;
            assert!(frame.common_record_composition && common.running && common.installed && common.graceful_close);
            assert_eq!(common.requested_configuration,requested.requested_configuration()?);
            assert_ne!(common.requested_configuration,common.effective_configuration,"genuine outer proof changes effective H1");
            assert_eq!(common.local_addr,addresses[side]);assert_eq!(common.peer_addr,addresses[1-side]);
            assert_eq!(common.requested_carrier,common.effective_carrier);
            assert!(!frame.released && !frame.releasing);
        }
        assert_eq!(probes[0].opened.load(Ordering::SeqCst),1);
        assert_eq!(probes[1].opened.load(Ordering::SeqCst),1);
        assert!(probes[2].opened.load(Ordering::SeqCst)==0 && probes[3].opened.load(Ordering::SeqCst)==0,
            "Full selection must not acquire a second original");
        // Same maintained native TCP endpoints, literal 7001/4099 bytes and FIN.
        fixed::exchange_native_tcp_mtu(&hosts,&handles,1280).await?;
        timeout(Duration::from_secs(3),async {
            while handles.iter().any(|h|fixed::proxy_frame(h).ok().and_then(|f|f.common)
                .is_none_or(|f|f.liveness.last_pong_micros.is_none())) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }).await?;
        for handle in &handles {
            let common=fixed::proxy_frame(handle)?.common.ok_or("actual raw Common counters")?;
            assert!(common.socket_accepted_packets>0 && common.socket_accepted_ip_bytes>0);
            assert_eq!(handle.apply_common(requested.initial(),handle.next_key().map_err(submit)?),Err(SubmitError::Unsupported));
        }
        let key=handles[0].next_key().map_err(submit)?;
        let request=local::Request{version:local::VERSION,action:local::Action::DrainProxy{}};
        let stop=handles[0].apply(request.clone(),key).map_err(submit)?;
        let result=handles[0].wait(stop.operation).await.map_err(submit)?;
        assert!(matches!(&result,Completed::Applied(response) if response.ok && response.code=="accepted"));
        assert_eq!(handles[0].apply(request,key),Ok(stop));
        assert_eq!(handles[0].wait(stop.operation).await.map_err(submit)?,result);
        timeout(Duration::from_secs(8),async {
            while handles.iter().any(|h|fixed::proxy_frame(h).is_ok_and(|f|!f.released)) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }).await?;
        for (side,handle) in handles.iter().enumerate() {
            let frame=fixed::proxy_frame(handle)?;
            assert!(frame.released && !frame.releasing);
            assert_eq!(frame.service_terminal,Some(Terminal::Closed));
            let Some(local::ProxyTerminal::Closed{report})=frame.terminal else {return Err("actual retained raw proxy close failed".into());};
            assert_eq!(report.tls_lanes_closed,0,"no fabricated ordinary TLS close");
            assert!(report.local_user_records>0 && report.peer_user_records>0);
            assert_eq!(report.clean_flows,1);assert_eq!(report.stopped_flows,0);
            assert_eq!(handle.proxy_close_report(generations[side].ok_or("actual generation")?).map_err(submit)?,Some(report));
            assert_eq!(hosts[side].live.load(Ordering::SeqCst),0);
        }
        for index in [0,1] {
            assert_eq!(probes[index].opened.load(Ordering::SeqCst),1);
            assert_eq!(probes[index].dropped.load(Ordering::SeqCst),1);
            assert_eq!(probes[index].syns.load(Ordering::SeqCst),syns[index],"no new raw original during proxy data/drain");
            assert!(probes[index].sent.load(Ordering::SeqCst)>0);
        }
        drop(handles);
        for task in tasks {task.abort();let _=task.await;}
        Ok::<_,Error>(())
    }).await??;
    Ok(())
}
