//! The same actual authenticated UDP/actor/service path with selected retained EOF.
//! Component loss tests separately exercise final ARQ/feedback loss and held retry.
use super::*;

#[tokio::test]
async fn selected_retained_common_proxy_publishes_close_after_actual_actor_and_driver_retirement()
-> Result {
    timeout(Duration::from_secs(35), async {
        let hosts = support::hosts();
        let ([a, b], profile) = fixture_selected(&hosts, true)?;
        let inspected=crate::cli::secure_udp_frontend::proxy_inspection_for_test(&profile,Role::Initiator)?;
        assert_eq!(inspected[0]["backend"],"common_proxy_fixed_retained_v1");
        assert_eq!(inspected[0]["capabilities"]["graceful_close"],true);
        assert_eq!(inspected[0]["proxy_requested"]["retained_close"],true);
        assert_eq!(inspected[0]["authenticated"],false);
        let (client, client_run) = channel();
        let (server, server_run) = channel();
        let tasks = [tokio::spawn(client_run), tokio::spawn(server_run)];
        let accepted = [
            client.connect(a, client.next_key().map_err(submit)?).map_err(submit)?,
            server.connect(b, server.next_key().map_err(submit)?).map_err(submit)?,
        ];
        tokio::try_join!(connected(&client, accepted[0]), connected(&server, accepted[1]))?;
        let handles = [client, server];
        let generations = handles.each_ref().map(|handle| handle.snapshot().generation);
        for handle in &handles {
            let frame = proxy_frame(handle)?;
            let common = frame.common.ok_or("actual selected Common composition")?;
            assert!(common.installed && common.running && common.graceful_close);
            assert_eq!(common.effective_configuration, profile.configuration()?);
            assert!(!frame.released);
        }
        // Maintained TCP peers, exact 7001/4099 opaque bytes and actual native FIN.
        // This is the original packet attachment/actor, not injected table state.
        exchange_native_tcp(&hosts, &handles).await?;
        let begin = Instant::now();
        let request = local::Request { version: local::VERSION, action: local::Action::DrainProxy {} };
        let key = handles[0].next_key().map_err(submit)?;
        let accepted = handles[0].apply(request.clone(), key).map_err(submit)?;
        let result = handles[0].wait(accepted.operation).await.map_err(submit)?;
        assert!(matches!(&result, Completed::Applied(response) if response.ok && response.code == "accepted"));
        assert_eq!(handles[0].apply(request, key), Ok(accepted));
        assert_eq!(handles[0].wait(accepted.operation).await.map_err(submit)?, result);
        tokio::time::sleep(Duration::from_millis(100)).await;
        for handle in &handles {
            let frame = proxy_frame(handle)?;
            assert!(!frame.released && frame.terminal.is_none(),
                "physical EOF/fence acceptance alone must not publish clean close: {frame:?}");
            assert!(handle.proxy_close_report(handle.snapshot().generation.ok_or("generation")?)
                .map_err(submit)?.is_none());
        }
        timeout(Duration::from_secs(8), async {
            while handles.iter().any(|handle| proxy_frame(handle).is_ok_and(|frame| !frame.released)) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }).await?;
        assert!(begin.elapsed() >= Duration::from_secs(2), "the original retained interval is not shortened");
        for (side, handle) in handles.iter().enumerate() {
            let frame = proxy_frame(handle)?;
            assert!(frame.released && !frame.releasing);
            assert_eq!(frame.service_terminal, Some(Terminal::Closed));
            assert_eq!(frame.runtime.as_ref().map(|status| status.phase),
                Some(l2tunnel_runtime::proxy::Phase::Closed));
            let Some(local::ProxyTerminal::Closed { report }) = frame.terminal.clone() else {
                return Err(format!("selected retained close failed: {frame:?}").into());
            };
            assert_eq!(report.tls_lanes_closed, 0, "Common must not fabricate TLS lane closure");
            assert!(report.local_user_records > 0 && report.peer_user_records > 0);
            assert_eq!(report.clean_flows, 1);
            assert_eq!(report.stopped_flows, 0);
            let generation = generations[side].ok_or("actual connected generation")?;
            assert_eq!(handle.proxy_close_report(generation).map_err(submit)?, Some(report));
            assert_eq!(handle.snapshot().generation, Some(generation));
            assert!(frame.common.is_some_and(|common| !common.running && common.graceful_close));
        }
        assert!(hosts.iter().all(|host| host.live.load(Ordering::SeqCst) == 0));
        drop(handles);
        for task in tasks {
            task.abort();
            assert!(task.await.is_err_and(|error| error.is_cancelled()));
        }
        Ok::<_, Error>(())
    }).await??;
    Ok(())
}
