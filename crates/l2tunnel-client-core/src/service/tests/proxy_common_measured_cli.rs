//! Actual external measured Common fixture through the maintained CLI presenter.
use super::*;
#[tokio::test]
async fn measured_common_cli_presenter_uses_actual_api1_controller_cover_and_release() -> Result {
    timeout(Duration::from_secs(15), async {
        let hosts = support::hosts();
        // Explicit dependency helper constructs real maintained measured owners;
        // no imported root, fake backend or duplicate native/recovery algorithm.
        let ([a, b], profile) = fixture_profile(&hosts, true, true)?;
        let inspected =
            crate::cli::secure_udp_frontend::proxy_inspection_for_test(&profile, Role::Initiator)?;
        assert_eq!(inspected[0]["backend"], "common_proxy_measured_retained_v1");
        assert_eq!(inspected[0]["traffic"], "proxy-measured");
        assert_eq!(
            inspected[0]["proxy_requested"]["profile"],
            crate::proxy_measured::PROFILE
        );
        assert_eq!(inspected[0]["proxy_requested"]["retained_close"], true);
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
        let failed = overflow.clone();
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
                    profile: ProxyProfile::MeasuredRelay,
                    grace: Duration::ZERO,
                },
                move |event| {
                    let value = crate::cli::secure_udp_frontend::proxy_event_for_test(
                        &observed.snapshot(),
                        &event,
                    );
                    if events.try_send(value).is_err() {
                        failed.store(true, Ordering::SeqCst);
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
            .ok_or("actual measured presenter readiness absent")??;
        assert_eq!(ready["event"], "secure_udp_common_proxy_ready");
        assert_eq!(ready["backend"], "common_proxy_measured_retained_v1");
        assert_eq!(ready["api_version"], local::VERSION);
        assert_eq!(ready["proxy"]["common"]["installed"], true);
        assert_eq!(ready["proxy"]["common"]["graceful_close"], true);
        assert_eq!(
            ready["proxy"]["measured"]["capabilities"]["effective_carrier"],
            "common_udp"
        );
        let handles = [client, server];
        for handle in &handles {
            let snapshot = handle.snapshot();
            assert!(
                snapshot
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
            let proxy = status
                .state
                .as_ref()
                .and_then(|value| value.proxy.as_ref())
                .ok_or("actual measured proxy status absent")?;
            let measured = proxy
                .measured
                .as_ref()
                .ok_or("actual measured controller facts absent")?;
            assert_eq!(
                measured.capabilities.effective,
                Some(crate::proxy_measured::Profile::MeasuredRelayV1)
            );
            assert_eq!(
                measured.capabilities.effective_carrier,
                Some(crate::proxy_measured::Carrier::CommonUdp)
            );
            assert_eq!(
                measured.capabilities.effective_udp_cover,
                Some(crate::proxy_measured::UdpCover::QuicLike)
            );
            let common = proxy
                .common
                .as_ref()
                .ok_or("actual embedded Common status absent")?;
            assert!(
                common.installed && common.running && common.graceful_close && !common.hot_switch
            );
            assert_eq!(common.requested_configuration, profile.configuration()?.0);
            assert_eq!(
                common.requested_configuration,
                common.effective_configuration
            );
            assert!(
                !measured.capabilities.exact_tcp_rwnd_control
                    && !measured.capabilities.native_tcp_rtt
                    && !measured.capabilities.native_tcp_cwnd
            );
            let refused = handle
                .lifecycle_request(local::Request {
                    version: local::COMMON_VERSION,
                    action: local::Action::Status {},
                })
                .await;
            assert!(!refused.ok);
        }
        let stopped = [
            handles[0]
                .disconnect(handles[0].next_key().map_err(submit)?)
                .map_err(submit)?,
            handles[1]
                .disconnect(handles[1].next_key().map_err(submit)?)
                .map_err(submit)?,
        ];
        let (a, b) = tokio::join!(
            handles[0].wait(stopped[0].operation),
            handles[1].wait(stopped[1].operation)
        );
        assert_eq!(a.map_err(submit)?, Completed::Aborted);
        assert_eq!(b.map_err(submit)?, Completed::Aborted);
        let terminal = timeout(Duration::from_secs(3), received.recv())
            .await?
            .ok_or("actual measured presenter terminal absent")??;
        assert_eq!(terminal["event"], "secure_udp_common_proxy_terminal");
        assert_eq!(terminal["backend"], "common_proxy_measured_retained_v1");
        assert_eq!(terminal["proxy"]["common"]["released"], true);
        assert_eq!(terminal["proxy"]["common"]["running"], false);
        assert!(!overflow.load(Ordering::SeqCst));
        assert_eq!(
            presentation.await?.err().map(|value| value.kind()),
            Some(io::ErrorKind::Interrupted)
        );
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
        server_task.abort();
        let _ = server_task.await;
        Ok::<(), Error>(())
    })
    .await?
}
