//! Actual retained TLS/QUIC proxy ownership, native TCP bytes and retained close.
use super::*;

#[tokio::test]
async fn retained_tls_full_fixed_proxy_preserves_tcp_and_retirement() -> Result {
    exercise(false, false).await
}
#[tokio::test]
async fn retained_tls_full_measured_proxy_preserves_tcp_and_retirement() -> Result {
    exercise(false, true).await
}
#[tokio::test]
async fn genuine_quic_half_fixed_proxy_preserves_tcp_and_retirement() -> Result {
    exercise(true, false).await
}
#[tokio::test]
async fn genuine_quic_half_measured_proxy_preserves_tcp_and_retirement() -> Result {
    exercise(true, true).await
}

fn exercise(
    half: bool,
    measured: bool,
) -> Pin<Box<dyn std::future::Future<Output = Result> + Send>> {
    Box::pin(async move {
        timeout(Duration::from_secs(35), async {
            let hosts = support::hosts();
            let selection = l2tunnel::secure_record::compact::Selection {
                protection: l2tunnel_security::compact::Protection::ChaCha20Crc32c,
                limits: l2tunnel_security::compact::Selection {
                    max_forward_packets: 8192,
                    max_failed_checks: 64,
                },
            };
            let (unused, profile) =
                fixture_wire_channels(&hosts, true, measured, Some(selection), 4)?;
            drop(unused);
            let ([a, b], requested, addresses) =
                super::super::maintained_carrier::maintained_plans(profile, half, &hosts)?;
            let (client, run) = channel();
            let (server, peer) = channel();
            let tasks = [tokio::spawn(run), tokio::spawn(peer)];
            let accepted_server = server
                .connect(b, server.next_key().map_err(submit)?)
                .map_err(submit)?;
            timeout(Duration::from_secs(2), async {
                while server.snapshot().listening.is_none() {
                    tokio::task::yield_now().await;
                }
            })
            .await?;
            let accepted_client = client
                .connect(a, client.next_key().map_err(submit)?)
                .map_err(submit)?;
            let accepted = [accepted_client, accepted_server];
            tokio::try_join!(
                connected(&client, accepted[0]),
                connected(&server, accepted[1])
            )?;
            let handles = [client, server];
            exchange_native_tcp(&hosts, &handles).await?;
            for (index, handle) in handles.iter().enumerate() {
                let frame = proxy_frame(handle)?;
                let common = frame.common_status().ok_or("Common proxy status")?;
                assert!(common.installed && common.running && common.graceful_close);
                let wire = common.compact_wire.ok_or("actual protection")?;
                assert_eq!(wire.effective, Some(wire.requested));
                assert_eq!(wire.authenticated_proxy_records, Some(true));
                assert_eq!(wire.effective_data_overhead_bytes, Some(21));
                let carrier = common
                    .maintained_carrier
                    .as_ref()
                    .ok_or("maintained status")?;
                assert_eq!(carrier.effective.as_ref(), Some(&carrier.requested));
                assert_eq!(
                    carrier.lanes.iter().flatten().count(),
                    if half { 2 } else { 1 }
                );
                assert!(carrier.binding.is_some() && carrier.send_boundary.is_some());
                assert_eq!(carrier.requested.carrier, if half { "quic" } else { "tcp" });
                assert_eq!(requested.proxy_config().ok_or("proxy")?.mux.channels, 4);
                assert_eq!(frame.measured.is_some(), measured);
                crate::cli::secure_udp_frontend::proxy_event_for_test(
                    &handle.snapshot(),
                    &crate::cli::ProxyServiceEvent::Ready {
                        generation: accepted[index].operation,
                        profile: frame.requested_profile,
                        duplex: requested.connection().duplex,
                    },
                )?;
            }
            let drain = handles[0]
                .apply(
                    local::Request {
                        version: local::VERSION,
                        action: local::Action::DrainProxy {},
                    },
                    handles[0].next_key().map_err(submit)?,
                )
                .map_err(submit)?;
            assert!(matches!(
                handles[0].wait(drain.operation).await.map_err(submit)?,
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
                assert_eq!(
                    frame.service_terminal,
                    Some(Terminal::Closed),
                    "actual maintained proxy terminal: {frame:?}",
                );
                let Some(local::ProxyTerminal::Closed { report }) = frame.terminal else {
                    return Err("proxy did not close cleanly".into());
                };
                assert_eq!((report.clean_flows, report.stopped_flows), (1, 0));
            }
            assert!(
                hosts
                    .iter()
                    .all(|host| host.live.load(Ordering::SeqCst) == 0)
            );
            for pair in addresses.chunks_exact(2) {
                support::assert_ports_free([pair[0], pair[1]])?;
            }
            drop(handles);
            for task in tasks {
                task.abort();
                let _ = task.await;
            }
            Ok::<(), Error>(())
        })
        .await?
    })
}
