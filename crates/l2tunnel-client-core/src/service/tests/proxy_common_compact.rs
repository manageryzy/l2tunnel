//! Actual original UDP, proxy TCP bytes and retained close under compact v3.
use super::*;
use crate::secure_udp::common_status::{CompactWireSelection, CompactWireStatus};

#[tokio::test]
async fn compact_wire_proxy_fixed_and_measured_keep_actual_tcp_and_retirement_for_both_suites()
-> Result {
    for measured in [false, true] {
        for protection in [
            l2tunnel_security::compact::Protection::Aes128Ccm4,
            l2tunnel_security::compact::Protection::ChaCha20Crc32c,
        ] {
            let selection = l2tunnel::secure_record::compact::Selection {
                protection,
                limits: l2tunnel_security::compact::Selection {
                    max_forward_packets: 32_768,
                    max_failed_checks: 64,
                },
            };
            exercise(measured, selection, 1).await?;
        }
    }
    Ok(())
}
#[tokio::test]
async fn compact_hmac_proxy_preserves_four_channel_actor_and_actual_tcp_close() -> Result {
    exercise(
        false,
        l2tunnel::secure_record::compact::Selection {
            protection: l2tunnel_security::compact::Protection::HmacSha256,
            limits: l2tunnel_security::compact::Selection {
                max_forward_packets: 32_768,
                max_failed_checks: 64,
            },
        },
        4,
    )
    .await
}
async fn exercise(
    measured: bool,
    selection: l2tunnel::secure_record::compact::Selection,
    channels: u16,
) -> Result {
    timeout(Duration::from_secs(35), async {
        let hosts = support::hosts();
        let ([a, b], profile) =
            fixture_wire_channels(&hosts, true, measured, Some(selection), channels)?;
        assert_eq!(
            profile.proxy_config().ok_or("proxy policy")?.mux.channels,
            channels
        );
        let requested = CompactWireSelection::from_selection(selection)?;
        let inspected =
            crate::cli::secure_udp_frontend::proxy_inspection_for_test(&profile, Role::Initiator)?;
        assert_eq!(
            inspected[0]["compact_wire"]["requested"],
            serde_json::to_value(requested)?
        );
        assert!(inspected[0]["compact_wire"]["effective"].is_null());
        let repeated = profile.clone().with_compact_wire(selection)?;
        assert_eq!(repeated.compact_wire(), profile.compact_wire());
        assert_eq!(repeated.configuration()?, profile.configuration()?);
        assert_eq!(repeated.envelope(), profile.envelope());
        assert_eq!(repeated.data_digest(), profile.data_digest());
        assert_eq!(profile.proxy_measured_config().is_some(), measured);
        for role in [Role::Initiator, Role::Responder] {
            let contract = profile.runtime_contract(role)?;
            assert_eq!(contract.compact_wire(), selection);
            assert!(contract.proxy_retirement());
            assert_eq!(
                contract.proxy_binding(),
                Some(match profile.proxy_measured_config() {
                    Some(config) =>
                        l2tunnel_runtime::proxy::measured::session_config(config)?.digest,
                    None =>
                        l2tunnel_runtime::proxy::session_config(
                            profile.proxy_config().ok_or("proxy")?
                        )?
                        .digest,
                })
            );
            assert_eq!(contract.expected_configuration(), profile.configuration()?);
        }
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
        // The retained existing fixture exchanges 7001/4099 exact TCP bytes and FIN
        // through actual packet devices, proxy actors, Common records and UDP.
        exchange_native_tcp(&hosts, &handles).await?;
        timeout(Duration::from_secs(3), async {
            while handles.iter().any(|handle| {
                proxy_frame(handle)
                    .ok()
                    .and_then(|frame| frame.common)
                    .is_none_or(|common| common.liveness.last_pong_micros.is_none())
            }) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await?;
        for handle in &handles {
            let frame = proxy_frame(handle)?;
            let common = frame
                .common_status()
                .ok_or("actual Common proxy observation")?;
            assert!(common.installed && common.running && common.graceful_close);
            assert_eq!(common.effective_configuration, profile.configuration()?.0);
            assert!(!common.hot_switch && !common.exact_tcp_rwnd_control);
            let status = common
                .compact_wire
                .ok_or("selected final wire observation absent")?;
            assert_eq!(
                (status.requested, status.effective),
                (requested, Some(requested))
            );
            assert!(
                status
                    .feedback_packet_number
                    .is_some_and(|number| number > 0)
            );
            assert!(status.checks.is_some_and(|checks| checks.limit == 64));
            let portable = serde_json::to_vec(&common)?;
            assert_eq!(
                serde_json::from_slice::<local::ProxyCommonStatus>(&portable)?,
                common
            );
            if measured {
                assert!(
                    frame
                        .measured
                        .as_ref()
                        .is_some_and(|status| status.aggregate.is_some())
                );
            }
            assert_eq!(
                handle.apply_common(profile.initial(), handle.next_key().map_err(submit)?),
                Err(SubmitError::Unsupported)
            );
        }
        let accepted = handles[0]
            .apply(
                local::Request {
                    version: local::VERSION,
                    action: local::Action::DrainProxy {},
                },
                handles[0].next_key().map_err(submit)?,
            )
            .map_err(submit)?;
        assert!(matches!(
            handles[0].wait(accepted.operation).await.map_err(submit)?,
            Completed::Applied(_)
        ));
        timeout(Duration::from_secs(8), async {
            while handles
                .iter()
                .any(|handle| proxy_frame(handle).is_ok_and(|frame| !frame.released))
            {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await?;
        for handle in &handles {
            let frame = proxy_frame(handle)?;
            assert!(frame.released && !frame.releasing);
            assert_eq!(frame.service_terminal, Some(Terminal::Closed));
            let Some(local::ProxyTerminal::Closed { report }) = frame.terminal else {
                return Err(format!("compact proxy did not close cleanly: {frame:?}").into());
            };
            assert_eq!(report.clean_flows, 1);
            assert_eq!(report.stopped_flows, 0);
            assert!(report.local_user_records > 0 && report.peer_user_records > 0);
        }
        assert!(
            hosts
                .iter()
                .all(|host| host.live.load(Ordering::SeqCst) == 0)
        );
        drop(handles);
        for task in tasks {
            task.abort();
            assert!(task.await.is_err_and(|error| error.is_cancelled()));
        }
        Ok::<(), Error>(())
    })
    .await?
}

#[test]
fn compact_wire_proxy_observation_is_pending_until_actual_driver_report() -> Result {
    let hosts = support::hosts();
    let (_, profile) = fixture(&hosts)?;
    let selection = l2tunnel::secure_record::compact::Selection {
        protection: l2tunnel_security::compact::Protection::Aes128Ccm4,
        limits: l2tunnel_security::compact::Selection {
            max_forward_packets: 32_768,
            max_failed_checks: 64,
        },
    };
    let original = profile.configuration()?;
    let selected = profile.clone().with_compact_wire(selection)?;
    assert_ne!(selected.configuration()?, original);
    // Proxy records always have strong authentication. Switching from the
    // default full tag to a short data suite changes the authenticated selection,
    // while the effective proxy geometry and algorithm descriptor stay equal.
    assert_eq!(selected.envelope(), profile.envelope());
    assert_eq!(selected.data_digest(), profile.data_digest());
    let mut changed = selection;
    changed.limits.max_failed_checks += 1;
    assert_ne!(
        selected.configuration()?,
        profile.with_compact_wire(changed)?.configuration()?
    );
    let pending = CompactWireStatus::observe(selection, None)?;
    assert!(
        pending.effective.is_none()
            && pending.checks.is_none()
            && pending.feedback_packet_number.is_none()
    );
    support::assert_unopened(&hosts);
    Ok(())
}
