use super::*;
use std::future::Future;
use tokio::time::sleep;

fn fixed() -> io::Result<crate::proxy::Settings> {
    Ok(crate::proxy::Settings::new(crate::proxy::RoutePolicy::new(
        Vec::new(),
    )?))
}
fn measured() -> Result<crate::proxy_measured::Settings> {
    let document = serde_json::json!({
        "version":1,"profile":"measured-relay-v1",
        "fixed":{"version":1,"channels":16,"time_wait_reset":"maintained","routes":[]},
        "allocation":{"target":{
            "initial":{"bytes":32768,"records":32},"minimum":{"bytes":2048,"records":1},
            "session_cap":{"bytes":1048576,"records":1024},"per_flow_cap":{"bytes":65536,"records":64},
            "policy_cap":{"bytes":1048576,"records":1024},"queue_allowance_bytes":65536,
            "queue_delay_target_micros":5000,"many_flow_step":{"bytes":2048,"records":1},
            "few_flow_threshold":4,"max_flows":16,"bootstrap_rtt_micros":1000,"recovery_rtts":2
        },"minimum_per_flow":{"bytes":2048,"records":1}},
        "ownership":{"pending_ttl_micros":20000,"probe_interval_micros":10000,"probe_timeout_micros":30000,
            "handoff_timeout_micros":50000,"emission_interval_micros":10000,"max_records_per_interval":8},
        "observation":{"report_interval_micros":10000,"sample_ttl_micros":40000,"demand_idle_micros":20000,
            "rate_interval_micros":10000,"rate_bins":4},
        "service":{"report_work_per_turn":4,"admission_work_per_turn":4,"callback_work_per_turn":4,
            "plan_interval_micros":10000,"status_interval_micros":20000}
    });
    Ok(crate::proxy_measured::Settings::from_json(
        &serde_json::to_vec(&document)?,
    )?)
}
fn server(c: &Credentials, native: Arc<Native>, measured_profile: bool) -> Result<Prepared> {
    let credentials = Server {
        listen: "127.0.0.1:0".parse()?,
        tls: c.server.clone(),
        members: c.members.clone(),
    };
    Ok(if measured_profile {
        Prepared::proxy_measured_server(
            cfg(Duplex::Full),
            credentials,
            measured()?,
            attachment(native),
        )?
    } else {
        Prepared::proxy_server(cfg(Duplex::Full), credentials, fixed()?, attachment(native))?
    })
}
fn client(
    c: &Credentials,
    address: std::net::SocketAddr,
    native: Arc<Native>,
    measured_profile: bool,
) -> Result<Prepared> {
    let credentials = Client {
        remote: address,
        tls: c.client.clone(),
        server_name: "service-client.test".into(),
        member: c.member.clone(),
    };
    Ok(if measured_profile {
        Prepared::proxy_measured_client(
            cfg(Duplex::Full),
            credentials,
            measured()?,
            attachment(native),
        )?
    } else {
        Prepared::proxy_client(cfg(Duplex::Full), credentials, fixed()?, attachment(native))?
    })
}
async fn wait_for(mut predicate: impl FnMut() -> bool) -> Result {
    timeout(Duration::from_secs(3), async {
        while !predicate() {
            sleep(Duration::from_millis(1)).await;
        }
    })
    .await?;
    Ok(())
}
async fn drive<T>(
    a: &mut Pin<Box<Run>>,
    b: &mut Pin<Box<Run>>,
    action: impl Future<Output = Result<T>>,
) -> Result<T> {
    tokio::select! {
        result = action => result,
        result = a.as_mut() => Err(format!("client service unexpectedly returned: {result:?}").into()),
        result = b.as_mut() => Err(format!("server service unexpectedly returned: {result:?}").into()),
    }
}
fn frame(handle: &Handle) -> Result<ProxyFrame> {
    handle
        .snapshot()
        .runtime
        .and_then(|observation| observation.proxy().cloned())
        .ok_or_else(|| "missing actual proxy frame".into())
}
fn packet(value: u8) -> Vec<u8> {
    let mut bytes = vec![value; 1600];
    bytes[..40].fill(0);
    bytes[0] = 0x60;
    bytes[4..6].copy_from_slice(&1560_u16.to_be_bytes());
    bytes[6] = 253;
    bytes[7] = 64;
    bytes[8] = 0xfd;
    bytes[23] = 1;
    bytes[24] = 0xfd;
    bytes[39] = 2;
    bytes
}
struct Pair {
    c: Credentials,
    a: Handle,
    b: Handle,
    arun: Pin<Box<Run>>,
    brun: Pin<Box<Run>>,
    an: Arc<Native>,
    bn: Arc<Native>,
    server: Prepared,
    client: Prepared,
}
async fn pair(measured_profile: bool) -> Result<Pair> {
    let c = credentials()?;
    let an = Arc::new(Native::default());
    let bn = Arc::new(Native::default());
    let server = server(&c, bn.clone(), measured_profile)?;
    let (a, arun) = channel();
    let (b, brun) = channel();
    let mut arun = Box::pin(arun);
    let mut brun = Box::pin(brun);
    let accepted = b
        .connect(server.clone(), b.next_key().map_err(submit)?)
        .map_err(submit)?;
    let client = drive(&mut arun, &mut brun, async {
        wait_for(|| b.snapshot().listening.is_some()).await?;
        let address = b.snapshot().listening.ok_or("actual listener")?.address;
        let plan = client(&c, address, an.clone(), measured_profile)?;
        let ca = a
            .connect(plan.clone(), a.next_key().map_err(submit)?)
            .map_err(submit)?;
        assert_eq!(
            a.wait(ca.operation).await.map_err(submit)?,
            Completed::Connected {
                generation: ca.operation
            }
        );
        assert_eq!(
            b.wait(accepted.operation).await.map_err(submit)?,
            Completed::Connected {
                generation: accepted.operation
            }
        );
        Ok(plan)
    })
    .await?;
    Ok(Pair {
        c,
        a,
        b,
        arun,
        brun,
        an,
        bn,
        server,
        client,
    })
}

#[tokio::test]
async fn fixed_and_measured_share_actual_ready_bytes_clean_drain_and_fresh_reconnect() -> Result {
    for measured_profile in [false, true] {
        let mut pair = pair(measured_profile).await?;
        let mut expected_a = Vec::new();
        let mut expected_b = Vec::new();
        for round in 0..2 {
            if round == 1 {
                assert_eq!(pair.an.live.load(Ordering::SeqCst), 0);
                assert_eq!(pair.bn.live.load(Ordering::SeqCst), 0);
                let sa = pair
                    .b
                    .reconnect(pair.server.clone(), pair.b.next_key().map_err(submit)?)
                    .map_err(submit)?;
                pair.client = drive(&mut pair.arun, &mut pair.brun, async {
                    wait_for(|| pair.b.snapshot().listening.is_some()).await?;
                    let address = pair
                        .b
                        .snapshot()
                        .listening
                        .ok_or("replacement listener")?
                        .address;
                    let plan = client(&pair.c, address, pair.an.clone(), measured_profile)?;
                    let ca = pair
                        .a
                        .reconnect(plan.clone(), pair.a.next_key().map_err(submit)?)
                        .map_err(submit)?;
                    assert_eq!(
                        pair.a.wait(ca.operation).await.map_err(submit)?,
                        Completed::Connected {
                            generation: ca.operation
                        }
                    );
                    assert_eq!(
                        pair.b.wait(sa.operation).await.map_err(submit)?,
                        Completed::Connected {
                            generation: sa.operation
                        }
                    );
                    Ok(plan)
                })
                .await?;
            }
            let af = frame(&pair.a)?;
            let bf = frame(&pair.b)?;
            let profile = if measured_profile {
                ProxyProfile::MeasuredRelay
            } else {
                ProxyProfile::FixedCredit
            };
            assert_eq!(af.requested_profile, profile);
            assert_eq!(af.effective_profile, profile);
            assert_eq!(af.requested_digest, af.effective_digest);
            assert_eq!(af.effective_digest, bf.effective_digest);
            assert_ne!(af.effective_digest, cfg(Duplex::Full).session()?.digest);
            assert_eq!(
                af.runtime.ok_or("actual Forwarding")?.phase,
                l2tunnel_runtime::proxy::Phase::Forwarding
            );
            assert_eq!(
                bf.runtime.ok_or("peer Forwarding")?.phase,
                l2tunnel_runtime::proxy::Phase::Forwarding
            );
            assert!(!af.released && !af.exact_tcp_rwnd_control && !af.common_record_composition);
            let request = local::Request {
                version: local::VERSION,
                action: local::Action::SwitchCompression {
                    compression: local::Compression::Off,
                },
            };
            let key = pair.a.next_key().map_err(submit)?;
            assert_eq!(pair.a.apply(request, key), Err(SubmitError::Unsupported));
            assert_eq!(pair.a.next_key().map_err(submit)?, key);
            let av = packet(10 + round);
            let bv = packet(20 + round);
            expected_a.push(bv.clone());
            expected_b.push(av.clone());
            pair.an
                .incoming
                .lock()
                .map_err(|_| "native lock")?
                .push_back(av);
            pair.bn
                .incoming
                .lock()
                .map_err(|_| "native lock")?
                .push_back(bv);
            drive(&mut pair.arun, &mut pair.brun, async {
                received(&pair.an, &expected_a).await?;
                received(&pair.bn, &expected_b).await?;
                let request = local::Request { version: local::VERSION, action: local::Action::DrainProxy {} };
                let key = pair.a.next_key().map_err(submit)?;
                let admitted = pair.a.apply(request.clone(), key).map_err(submit)?;
                let result = pair.a.wait(admitted.operation).await.map_err(submit)?;
                assert!(matches!(&result, Completed::Applied(response) if response.ok && response.code == "accepted"));
                assert_eq!(pair.a.apply(request, key), Ok(admitted));
                assert_eq!(pair.a.wait(admitted.operation).await.map_err(submit)?, result);
                wait_for(|| frame(&pair.a).is_ok_and(|frame| frame.released)
                    && frame(&pair.b).is_ok_and(|frame| frame.released)).await?;
                assert_eq!(pair.an.live.load(Ordering::SeqCst), 0);
                assert_eq!(pair.bn.live.load(Ordering::SeqCst), 0);
                for handle in [&pair.a, &pair.b] {
                    let actual = frame(handle)?;
                    assert_eq!(actual.service_terminal, Some(Terminal::Closed));
                    assert!(matches!(actual.terminal, Some(local::ProxyTerminal::Closed { .. })));
                    assert!(!actual.releasing);
                    let status = handle.request(local::Request { version: local::VERSION,
                        action: local::Action::Status {} }).await;
                    assert!(serde_json::to_vec(&status)?.len() <= 8192);
                    assert!(status.state.and_then(|state| state.proxy).is_some());
                }
                Ok(())
            }).await?;
        }
        assert_eq!(pair.an.opened.load(Ordering::SeqCst), 2);
        assert_eq!(pair.bn.opened.load(Ordering::SeqCst), 2);
    }
    Ok(())
}

#[tokio::test]
async fn cancelled_actor_readiness_joins_real_tls_children_before_completion() -> Result {
    let c = credentials()?;
    let native = Arc::new(Native::default());
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let plan = client(&c, listener.local_addr()?, native.clone(), false)?;
    let (handle, run) = channel();
    let mut run = Box::pin(run);
    let accepted = handle
        .connect(plan, handle.next_key().map_err(submit)?)
        .map_err(submit)?;
    let action = async {
        // Hold the genuine authenticated peer Session without running its actor:
        // TLS is complete, while the client's real Start/Ready remains blocked.
        let policy = fixed()?;
        let peer =
            crate::proxy::accept(&listener, &c.server, &c.members, cfg(Duplex::Full), &policy)
                .await?;
        wait_for(|| native.live.load(Ordering::SeqCst) == 1).await?;
        assert_ne!(handle.snapshot().phase, Phase::Connected);
        handle.cancel(accepted.operation).map_err(submit)?;
        assert_eq!(
            handle.wait(accepted.operation).await.map_err(submit)?,
            Completed::Cancelled
        );
        assert_eq!(native.live.load(Ordering::SeqCst), 0);
        let actual = frame(&handle)?;
        assert!(actual.released);
        assert!(matches!(
            actual.terminal,
            Some(local::ProxyTerminal::Failed { .. })
        ));
        drop(peer);
        Ok(())
    };
    tokio::select! {
        result = action => result,
        result = run.as_mut() => Err(format!("service stopped: {result:?}").into()),
    }
}

#[tokio::test]
async fn expired_disconnect_retains_joining_owner_and_refuses_replacement_until_release() -> Result
{
    let mut pair = pair(false).await?;
    let key = pair.a.next_key().map_err(submit)?;
    let accepted = pair.a.disconnect(key).map_err(submit)?;
    let cap = accepted
        .deadline
        .ok_or("proxy disconnect must retain accepted cap")?;
    tokio::time::pause();
    tokio::time::advance(cap.saturating_duration_since(Instant::now())).await;
    drive_once(&mut pair.arun).await;
    assert_eq!(
        pair.a.wait(accepted.operation).await.map_err(submit)?,
        Completed::Failed(Failure {
            kind: io::ErrorKind::TimedOut
        })
    );
    let retained = frame(&pair.a)?;
    assert!(retained.releasing && !retained.released);
    assert_eq!(retained.release_deadline, Some(cap));
    let next = pair.a.next_key().map_err(submit)?;
    assert_eq!(
        pair.a.reconnect(pair.client.clone(), next),
        Err(SubmitError::Busy)
    );
    assert_eq!(pair.a.next_key().map_err(submit)?, next);
    assert_eq!(pair.a.disconnect(key), Ok(accepted));
    tokio::time::resume();
    drive(&mut pair.arun, &mut pair.brun, async {
        wait_for(|| {
            frame(&pair.a).is_ok_and(|frame| frame.released)
                && frame(&pair.b).is_ok_and(|frame| frame.released)
        })
        .await?;
        assert_eq!(pair.an.live.load(Ordering::SeqCst), 0);
        assert_eq!(frame(&pair.a)?.release_deadline, Some(cap));
        assert_eq!(
            pair.a.wait(accepted.operation).await.map_err(submit)?,
            Completed::Failed(Failure {
                kind: io::ErrorKind::TimedOut
            })
        );
        // The original listener is gone. Admission after actual release starts
        // a fresh setup, whose real refusal cannot resurrect or reuse the owner.
        let retry = pair
            .a
            .reconnect(pair.client.clone(), next)
            .map_err(submit)?;
        assert!(matches!(
            pair.a.wait(retry.operation).await.map_err(submit)?,
            Completed::Failed(_)
        ));
        assert_eq!(pair.an.opened.load(Ordering::SeqCst), 1);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn dropping_live_proxy_service_never_claims_joined_release_or_clean_close() -> Result {
    let mut pair = pair(false).await?;
    let key = pair.a.next_key().map_err(submit)?;
    drop(pair.arun);
    let snapshot = pair.a.snapshot();
    assert_eq!(snapshot.phase, Phase::Closed);
    let terminal = Terminal::Failed(Failure {
        kind: io::ErrorKind::Interrupted,
    });
    assert_eq!(snapshot.terminal, Some(terminal));
    let observation = frame(&pair.a)?;
    assert!(!observation.released);
    assert_eq!(observation.service_terminal, Some(terminal));
    assert!(!matches!(
        observation.terminal,
        Some(local::ProxyTerminal::Closed { .. })
    ));
    assert_eq!(pair.a.reconnect(pair.client, key), Err(SubmitError::Closed));
    tokio::select! {
        result = wait_for(|| frame(&pair.b).is_ok_and(|frame| frame.released)) => result,
        result = pair.brun.as_mut() => Err(format!("peer service stopped: {result:?}").into()),
    }
}

#[cfg(target_os = "linux")]
mod cli;
