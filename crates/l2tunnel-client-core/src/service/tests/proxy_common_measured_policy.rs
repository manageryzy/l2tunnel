//! Authenticated family boundaries and observed capabilities of real Common owners.
use super::*;
use l2tunnel_runtime::proxy::{self as runtime, measured};

fn selected(
    seed: &common_transaction_profile::Profile,
    config: measured::Config,
) -> Result<common_transaction_profile::Profile> {
    Ok(
        common_transaction_profile::Profile::new_proxy_measured_retained(
            seed.connection(),
            seed.settings(),
            seed.peers(),
            seed.runtime_contract(Role::Initiator)?.resources(),
            seed.runtime_contract(Role::Responder)?.resources(),
            seed.catalog().clone(),
            seed.parameters(),
            config,
        )?,
    )
}

#[test]
fn measured_common_binding_refuses_cross_family_and_unselected_retirement() -> Result {
    let hosts = support::hosts();
    let ([client, _], legacy) = fixture(&hosts)?;
    let fixed = legacy.proxy_config().ok_or("fixed policy")?.clone();
    let measured = measured_common::config(fixed.clone())?;
    let retained = common_transaction_profile::Profile::new_proxy_retained(
        legacy.connection(),
        legacy.settings(),
        legacy.peers(),
        legacy.runtime_contract(Role::Initiator)?.resources(),
        legacy.runtime_contract(Role::Responder)?.resources(),
        legacy.catalog().clone(),
        legacy.parameters(),
        fixed.clone(),
    )?;
    let profile = selected(&legacy, measured.clone())?;
    assert!(!legacy.proxy_retirement() && legacy.proxy_measured_config().is_none());
    assert!(retained.proxy_retirement() && retained.proxy_measured_config().is_none());
    assert!(profile.proxy_retirement() && profile.proxy_measured_config().is_some());
    assert_ne!(profile.configuration()?, retained.configuration()?);
    let binding = measured::session_config(&measured)?.digest;
    assert_ne!(binding, runtime::session_config(&fixed)?.digest);
    for role in [Role::Initiator, Role::Responder] {
        for fixed_profile in [&legacy, &retained] {
            let contract = fixed_profile.runtime_contract(role)?;
            runtime::common::validate(&fixed, &contract)?;
            assert_eq!(
                runtime::common::validate_measured(&measured, &contract)
                    .err()
                    .map(|error| error.kind()),
                Some(io::ErrorKind::Unsupported),
                "fixed contract must not authorize a measured controller",
            );
        }
        let contract = profile.runtime_contract(role)?;
        assert_eq!(contract.proxy_binding(), Some(binding));
        assert_eq!(contract.expected_configuration(), profile.configuration()?);
        runtime::common::validate_measured(&measured, &contract)?;
        assert_eq!(
            runtime::common::validate(&fixed, &contract)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::Unsupported),
            "measured contract must not authorize fixed user framing",
        );
    }
    let mut changed = [measured.clone(), measured.clone(), measured.clone()];
    changed[0]
        .measured
        .allocation
        .target
        .queue_delay_target_micros += 1;
    changed[1].measured.ownership.probe_interval_micros += 1000;
    changed[2].service.status_interval_micros += 1000;
    for config in changed {
        let alternate = selected(&legacy, config.clone())?;
        assert_ne!(alternate.configuration()?, profile.configuration()?);
        assert_ne!(
            alternate
                .establish_config(Role::Initiator)?
                .binding
                .configuration,
            profile
                .establish_config(Role::Initiator)?
                .binding
                .configuration,
        );
        assert!(
            runtime::common::validate_measured(
                &config,
                &profile.runtime_contract(Role::Initiator)?
            )
            .is_err(),
            "a stale authenticated contract cannot accept changed measured policy"
        );
    }
    // Trusted runtime metadata cannot opt a measured policy into legacy close.
    let settings = profile.settings();
    let actual = profile.runtime_contract(Role::Initiator)?;
    let nonretained = transport::CommonTransactionContract::new_compact_wire(
        profile.configuration()?,
        Role::Initiator,
        [
            actual.resources(),
            profile.runtime_contract(Role::Responder)?.resources(),
        ],
        actual.cover(),
        settings.gate.path.client.is_ipv6(),
        profile.envelope(),
        profile.catalog().clone(),
        profile.parameters(),
        profile.compact_wire(),
    )?
    .with_proxy_binding(binding)?;
    assert_eq!(
        runtime::common::validate_measured(&measured, &nonretained)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::Unsupported),
        "measured Common needs explicitly bound retirement",
    );
    let data = Arc::try_unwrap(client.data).map_err(|_| "unstarted plan unexpectedly shared")?;
    let prepared::Endpoint::SecureClient(credentials) = data.endpoint else {
        return Err("original secure client credentials".into());
    };
    assert!(Prepared::secure_udp_common_client(profile, credentials, data.attachment).is_err());
    support::assert_unopened(&hosts);
    Ok(())
}

#[tokio::test]
async fn only_selected_measured_common_publishes_actual_carrier_capabilities() -> Result {
    timeout(Duration::from_secs(12), async {
        for measured in [false, true] {
            let hosts = support::hosts();
            let ([a, b], profile) = fixture_profile(&hosts, true, measured)?;
            let (client, client_run) = channel();
            let (server, server_run) = channel();
            let tasks = [tokio::spawn(client_run), tokio::spawn(server_run)];
            let accepted = [
                client
                    .connect(a, client.next_key().map_err(submit)?)
                    .map_err(submit)?,
                server
                    .connect(b, server.next_key().map_err(submit)?)
                    .map_err(submit)?,
            ];
            tokio::try_join!(
                connected(&client, accepted[0]),
                connected(&server, accepted[1])
            )?;
            let handles = [client, server];
            for handle in &handles {
                let frame = proxy_frame(handle)?;
                assert!(frame.common_record_composition && !frame.exact_tcp_rwnd_control);
                assert!(
                    frame
                        .common
                        .is_some_and(|c| c.installed && c.running && c.graceful_close)
                );
                assert_eq!(frame.measured.is_some(), measured);
                assert_eq!(
                    frame.effective_profile,
                    if measured {
                        ProxyProfile::MeasuredRelay
                    } else {
                        ProxyProfile::FixedCredit
                    }
                );
                if let Some(snapshot) = frame.measured {
                    use crate::proxy_measured::{Carrier, UdpCover};
                    let c = snapshot.capabilities;
                    assert_eq!(c.requested_carrier, Carrier::CommonUdp);
                    assert_eq!(c.effective_carrier, Some(Carrier::CommonUdp));
                    assert_eq!(c.requested_udp_cover, UdpCover::QuicLike);
                    assert_eq!(c.effective_udp_cover, Some(UdpCover::QuicLike));
                    assert!(c.measured_relay_targets && c.effective.is_some());
                    assert!(!c.exact_tcp_rwnd_control && !c.native_tcp_rtt && !c.native_tcp_cwnd);
                    assert!(!c.native_window_qualified && !c.hot_reload && !c.flow_paging);
                    assert!(snapshot.aggregate.is_some());
                }
            }
            for handle in &handles {
                let accepted = handle
                    .disconnect(handle.next_key().map_err(submit)?)
                    .map_err(submit)?;
                assert_eq!(
                    handle.wait(accepted.operation).await.map_err(submit)?,
                    Completed::Aborted
                );
                assert!(proxy_frame(handle)?.released);
            }
            assert!(
                hosts
                    .iter()
                    .all(|host| host.live.load(Ordering::SeqCst) == 0)
            );
            support::assert_ports_free([
                profile.settings().gate.path.client,
                profile.settings().gate.path.server,
            ])?;
            drop(handles);
            for task in tasks {
                task.abort();
                assert!(task.await.is_err_and(|error| error.is_cancelled()));
            }
        }
        Ok::<_, Error>(())
    })
    .await??;
    Ok(())
}
