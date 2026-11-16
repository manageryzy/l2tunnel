//! Real shared owners through the production proxy presenter, not native API4.
use super::*;

#[tokio::test]
async fn common_proxy_cli_presenter_uses_actual_proxy_status_and_observed_release() -> Result {
    timeout(Duration::from_secs(15), async {
        let hosts = support::hosts();
        let ([a, b], profile) = fixture(&hosts)?;
        let inspected =
            crate::cli::secure_udp_frontend::proxy_inspection_for_test(&profile, Role::Initiator)?;
        assert_eq!(inspected[0]["event"], "secure_udp_common_proxy_plan");
        assert_eq!(inspected[0]["api_version"], local::VERSION);
        assert_eq!(inspected[0]["capabilities"]["graceful_close"], false);
        assert_eq!(inspected[0]["capabilities"]["native_common_api4"], false);
        assert!(inspected[0]["proxy_effective"].is_null());
        assert_eq!(inspected[0]["authenticated"], false);
        let (client, client_run) = channel();
        let (server, server_run) = channel();
        let accepted = [
            client
                .connect(a, client.next_key().map_err(submit)?)
                .map_err(submit)?,
            server
                .connect(b, server.next_key().map_err(submit)?)
                .map_err(submit)?,
        ];
        let (events, mut received) = tokio::sync::mpsc::channel(4);
        let overflow = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let output_failed = overflow.clone();
        let observed = client.clone();
        let presented = client.clone();
        let presentation = tokio::spawn(async move {
            crate::cli::serve_shared_proxy_for_test(
                presented,
                client_run,
                accepted[0],
                None,
                crate::cli::ProxyServicePresentation {
                    duplex: Duplex::Full,
                    profile: ProxyProfile::FixedCredit,
                    grace: Duration::ZERO,
                },
                move |event| {
                    let value = crate::cli::secure_udp_frontend::proxy_event_for_test(
                        &observed.snapshot(),
                        &event,
                    );
                    if events.try_send(value).is_err() {
                        output_failed.store(true, Ordering::SeqCst);
                    }
                },
            )
            .await
        });
        let server_task = tokio::spawn(server_run);
        tokio::try_join!(
            connected(&client, accepted[0]),
            connected(&server, accepted[1])
        )?;
        let ready = timeout(Duration::from_secs(3), received.recv())
            .await?
            .ok_or("presenter readiness absent")??;
        assert_eq!(ready["event"], "secure_udp_common_proxy_ready");
        assert_eq!(ready["api_version"], local::VERSION);
        assert_eq!(ready["proxy"]["common"]["installed"], true);
        assert_eq!(ready["proxy"]["common"]["running"], true);
        assert_eq!(ready["proxy"]["common"]["graceful_close"], false);
        let handles = [client, server];
        for handle in &handles {
            assert!(
                handle
                    .snapshot()
                    .runtime
                    .as_ref()
                    .and_then(Observation::secure_udp_common)
                    .is_none()
            );
            let status = handle
                .lifecycle_request(local::Request {
                    version: local::VERSION,
                    action: local::Action::Status {},
                })
                .await;
            assert!(status.ok);
            let portable = status
                .state
                .as_ref()
                .and_then(|state| state.proxy.as_ref())
                .and_then(|proxy| proxy.common.as_ref())
                .ok_or("actual local Common proxy facts absent")?;
            assert_eq!(portable.requested_configuration, profile.configuration()?.0);
            assert_eq!(
                portable.requested_configuration,
                portable.effective_configuration
            );
            assert_eq!(portable.requested_carrier, portable.effective_carrier);
            assert!(
                portable.installed
                    && portable.running
                    && !portable.hot_switch
                    && !portable.graceful_close
                    && !portable.exact_tcp_rwnd_control
            );
            let unsupported = handle
                .lifecycle_request(local::Request {
                    version: local::COMMON_VERSION,
                    action: local::Action::Status {},
                })
                .await;
            assert!(
                !unsupported.ok,
                "immutable proxy cannot acquire native-Common API4"
            );
        }
        let stopped = [
            handles[0]
                .disconnect(handles[0].next_key().map_err(submit)?)
                .map_err(submit)?,
            handles[1]
                .disconnect(handles[1].next_key().map_err(submit)?)
                .map_err(submit)?,
        ];
        let (left, right) = tokio::join!(
            handles[0].wait(stopped[0].operation),
            handles[1].wait(stopped[1].operation)
        );
        assert_eq!(left.map_err(submit)?, Completed::Aborted);
        assert_eq!(right.map_err(submit)?, Completed::Aborted);
        let terminal = timeout(Duration::from_secs(3), received.recv())
            .await?
            .ok_or("presenter terminal absent")??;
        assert_eq!(terminal["event"], "secure_udp_common_proxy_terminal");
        assert_eq!(terminal["proxy"]["common"]["released"], true);
        assert_eq!(terminal["proxy"]["common"]["releasing"], false);
        assert_eq!(terminal["proxy"]["common"]["running"], false);
        assert!(!overflow.load(Ordering::SeqCst));
        assert_eq!(
            presentation.await?.err().map(|error| error.kind()),
            Some(io::ErrorKind::Interrupted)
        );
        assert!(
            hosts
                .iter()
                .all(|host| host.live.load(Ordering::SeqCst) == 0)
        );
        drop(handles);
        server_task.abort();
        assert!(server_task.await.is_err());
        Ok(())
    })
    .await?
}
