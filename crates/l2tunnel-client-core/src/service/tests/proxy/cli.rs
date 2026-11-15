//! Actual shared CLI presentation, TLS/member and v1 local-socket acceptance.
use super::*;
use crate::cli::{
    ProxyServiceEvent as Event, ProxyServicePresentation as Presentation,
    serve_shared_proxy_for_test as serve,
};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use tokio::task::JoinHandle;

struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "l2p-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
struct Task(Option<JoinHandle<io::Result<()>>>);
impl Task {
    fn finished(&self) -> bool {
        self.0.as_ref().is_none_or(JoinHandle::is_finished)
    }
    async fn finish(&mut self) -> Result<io::Result<()>> {
        let result = timeout(
            Duration::from_secs(3),
            self.0.as_mut().ok_or("task absent")?,
        )
        .await??;
        self.0.take();
        Ok(result)
    }
}
impl Drop for Task {
    fn drop(&mut self) {
        if let Some(task) = &self.0 {
            task.abort();
        }
    }
}
fn action(action: local::Action) -> local::Request {
    local::Request {
        version: local::VERSION,
        action,
    }
}
async fn rpc(path: &Path, action_value: local::Action) -> Result<local::Response> {
    Ok(timeout(
        Duration::from_secs(3),
        local::request(path, &action(action_value)),
    )
    .await??)
}
fn check_phase(response: &local::Response, expected: &str) -> Result {
    assert_eq!(response.version, local::VERSION);
    let state = response.state.as_ref().ok_or("proxy local state absent")?;
    let runtime = state
        .proxy
        .as_ref()
        .and_then(|proxy| proxy.runtime.as_ref())
        .ok_or("actual proxy runtime absent")?;
    assert_eq!(
        state.phase, runtime.phase,
        "v1 state/runtime phase compatibility"
    );
    assert_eq!(state.phase, expected);
    assert!(serde_json::to_vec(response)?.len() <= 8192);
    Ok(())
}
fn start(
    handle: Handle,
    run: Run,
    accepted: Accepted,
    api: local::Server,
    presentation: Presentation,
    events: Arc<Mutex<Vec<Event>>>,
) -> Task {
    Task(Some(tokio::spawn(serve(
        handle,
        run,
        accepted,
        Some(api),
        presentation,
        move |event| {
            events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(event);
        },
    ))))
}
fn count_ready(events: &Mutex<Vec<Event>>) -> usize {
    events
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .filter(|event| matches!(event, Event::Ready { .. }))
        .count()
}

#[tokio::test]
async fn fixed_and_measured_production_presentation_uses_shared_local_lifecycle_and_retains_pending_setup()
-> Result {
    for measured_profile in [false, true] {
        let c = credentials()?;
        let native_a = Arc::new(Native::default());
        let native_b = Arc::new(Native::default());
        let directory = Directory::new()?;
        let apath = directory.0.join("a");
        let bpath = directory.0.join("b");
        // A fixed explicit endpoint is retained by the same Prepared on fresh reconnect.
        let reservation = TcpListener::bind("127.0.0.1:0").await?;
        let address = reservation.local_addr()?;
        drop(reservation);
        let credentials = Server {
            listen: address,
            tls: c.server.clone(),
            members: c.members.clone(),
        };
        let server = if measured_profile {
            Prepared::proxy_measured_server(
                cfg(Duplex::Full),
                credentials,
                measured()?,
                attachment(native_b.clone()),
            )?
        } else {
            Prepared::proxy_server(
                cfg(Duplex::Full),
                credentials,
                fixed()?,
                attachment(native_b.clone()),
            )?
        };
        let (a, arun) = channel();
        let (b, brun) = channel();
        let ae = Arc::new(Mutex::new(Vec::new()));
        let be = Arc::new(Mutex::new(Vec::new()));
        let grace = Duration::from_millis(500);
        let presentation = Presentation {
            duplex: Duplex::Full,
            profile: if measured_profile {
                ProxyProfile::MeasuredRelay
            } else {
                ProxyProfile::FixedCredit
            },
            grace,
        };
        let bs = b
            .connect(server, b.next_key().map_err(submit)?)
            .map_err(submit)?;
        let mut bt = start(
            b.clone(),
            brun,
            bs,
            local::Server::bind(&bpath)?,
            presentation,
            be.clone(),
        );
        wait_for(|| b.snapshot().listening.is_some()).await?;
        let plan = client(&c, address, native_a.clone(), measured_profile)?;
        let initial = a
            .connect(plan, a.next_key().map_err(submit)?)
            .map_err(submit)?;
        let mut at = start(
            a.clone(),
            arun,
            initial,
            local::Server::bind(&apath)?,
            presentation,
            ae.clone(),
        );
        wait_for(|| count_ready(&ae) == 1 && count_ready(&be) == 1).await?;
        let old_a = a.snapshot().generation.ok_or("actual first generation")?;
        let old_b = b.snapshot().generation.ok_or("actual peer generation")?;
        for path in [&apath, &bpath] {
            let response = rpc(path, local::Action::Status {}).await?;
            assert!(response.ok);
            check_phase(&response, "Forwarding")?;
        }
        let av = packet(61);
        let bv = packet(93);
        native_a
            .incoming
            .lock()
            .map_err(|_| "native lock")?
            .push_back(av.clone());
        native_b
            .incoming
            .lock()
            .map_err(|_| "native lock")?
            .push_back(bv.clone());
        received(&native_a, &[bv]).await?;
        received(&native_b, &[av]).await?;
        let accepted = rpc(&apath, local::Action::DrainProxy {}).await?;
        assert!(accepted.ok);
        assert_eq!(accepted.code, "accepted");
        wait_for(|| {
            frame(&a).is_ok_and(|frame| frame.released)
                && frame(&b).is_ok_and(|frame| frame.released)
        })
        .await?;
        // The actual generation report remains available after replacement readiness.
        let replacement_b = tokio::spawn({
            let path = bpath.clone();
            async move { rpc(&path, local::Action::Reconnect {}).await }
        });
        wait_for(|| b.snapshot().listening.is_some()).await?;
        let replacement_a = rpc(&apath, local::Action::Reconnect {}).await?;
        assert!(replacement_a.ok);
        assert!(replacement_b.await??.ok);
        wait_for(|| count_ready(&ae) == 2 && count_ready(&be) == 2).await?;
        assert_ne!(a.snapshot().generation, Some(old_a));
        assert_ne!(b.snapshot().generation, Some(old_b));
        for (handle, old) in [(&a, old_a), (&b, old_b)] {
            assert_eq!(
                handle.wait_stopped(old).await.map_err(submit)?,
                Terminal::Closed
            );
            let report = handle
                .proxy_close_report(old)
                .map_err(submit)?
                .ok_or("retained real close report")?;
            assert_eq!(report.local_transparent_packets, 1);
            assert_eq!(report.native_confirmed_packets, 1);
            assert_eq!(report.tls_lanes_closed, 1);
            assert_eq!(report.clean_flows, 0);
            assert_eq!(report.stopped_flows, 0);
        }
        for (events, old) in [(&ae, old_a), (&be, old_b)] {
            let events = events.lock().map_err(|_| "events lock")?;
            let closed = events.iter().position(|event| matches!(event, Event::Terminal { generation, outcome: local::ProxyTerminal::Closed { .. } } if *generation == old)).ok_or("old actual terminal event absent")?;
            let replacement = events
                .iter()
                .position(
                    |event| matches!(event, Event::Ready { generation, .. } if *generation != old),
                )
                .ok_or("new actual readiness event absent")?;
            assert!(
                closed < replacement,
                "old terminal must precede replacement readiness"
            );
            assert_eq!(
                events
                    .iter()
                    .filter(|event| matches!(
                        event,
                        Event::Terminal {
                            outcome: local::ProxyTerminal::Closed { .. },
                            ..
                        }
                    ))
                    .count(),
                1
            );
            for event in events.iter() {
                if let Event::Ready {
                    generation,
                    duplex,
                    profile,
                } = event
                {
                    assert!(generation.value() > 0);
                    assert_eq!(*duplex, Duplex::Full);
                    assert_eq!(
                        *profile,
                        if measured_profile {
                            ProxyProfile::MeasuredRelay
                        } else {
                            ProxyProfile::FixedCredit
                        }
                    );
                }
            }
        }
        let current_a = a.snapshot().generation.ok_or("new generation")?;
        let disconnected = rpc(&apath, local::Action::Disconnect {}).await?;
        assert!(disconnected.ok);
        assert_eq!(
            a.wait_stopped(current_a).await.map_err(submit)?,
            Terminal::Aborted
        );
        let observed = frame(&a)?;
        assert!(observed.released && !observed.releasing);
        assert_eq!(native_a.live.load(Ordering::SeqCst), 0);
        assert!(a.proxy_close_report(current_a).map_err(submit)?.is_none());
        let response = rpc(&apath, local::Action::Status {}).await?;
        let phase = format!(
            "{:?}",
            frame(&a)?.runtime.ok_or("terminal actual runtime")?.phase
        );
        check_phase(&response, &phase)?;
        // Hold genuine replacement TCP/TLS setup beyond the old local grace.
        // It is not an authenticated readiness event and must retain the same Run.
        let hold = TcpListener::bind("127.0.0.1:0").await?;
        let plan = client(&c, hold.local_addr()?, native_a.clone(), measured_profile)?;
        let pending = a
            .reconnect(plan, a.next_key().map_err(submit)?)
            .map_err(submit)?;
        let (mut socket, _) = timeout(Duration::from_secs(3), hold.accept()).await??;
        let _tls_client_hello = timeout(Duration::from_secs(3), socket.read_u8()).await??;
        sleep(grace + Duration::from_millis(100)).await;
        assert!(
            !at.finished(),
            "expired observation grace dropped pending genuine setup"
        );
        assert_eq!(a.snapshot().operation, Some(pending.operation));
        assert_eq!(
            native_a.opened.load(Ordering::SeqCst),
            2,
            "pending TLS cannot reopen device"
        );
        a.cancel(pending.operation).map_err(submit)?;
        assert_eq!(
            a.wait(pending.operation).await.map_err(submit)?,
            Completed::Cancelled
        );
        drop(socket);
        drop(hold);
        assert!(at.finish().await?.is_err());
        assert!(frame(&a)?.released);
        wait_for(|| frame(&b).is_ok_and(|frame| frame.released)).await?;
        let _actual_peer_result = bt.finish().await?;
        assert_eq!(native_b.live.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[tokio::test]
async fn unobserved_actual_proxy_close_report_is_retained_after_fresh_reconnect_without_an_owner_clone()
-> Result {
    let mut pair = pair(false).await?;
    let old_a = pair
        .a
        .snapshot()
        .generation
        .ok_or("actual client generation")?;
    let old_b = pair
        .b
        .snapshot()
        .generation
        .ok_or("actual server generation")?;
    drive(&mut pair.arun, &mut pair.brun, async {
        let drain = pair.a.apply(action(local::Action::DrainProxy {}), pair.a.next_key().map_err(submit)?).map_err(submit)?;
        assert!(matches!(pair.a.wait(drain.operation).await.map_err(submit)?, Completed::Applied(response) if response.ok));
        assert_eq!(pair.a.wait_stopped(old_a).await.map_err(submit)?, Terminal::Closed);
        assert_eq!(pair.b.wait_stopped(old_b).await.map_err(submit)?, Terminal::Closed);
        Ok(())
    }).await?;
    assert_eq!(pair.an.live.load(Ordering::SeqCst), 0);
    assert_eq!(pair.bn.live.load(Ordering::SeqCst), 0);
    let sb = pair
        .b
        .reconnect(pair.server.clone(), pair.b.next_key().map_err(submit)?)
        .map_err(submit)?;
    drive(&mut pair.arun, &mut pair.brun, async {
        wait_for(|| pair.b.snapshot().listening.is_some()).await?;
        let address = pair
            .b
            .snapshot()
            .listening
            .ok_or("actual replacement listener")?
            .address;
        let plan = client(&pair.c, address, pair.an.clone(), false)?;
        let sa = pair
            .a
            .reconnect(plan, pair.a.next_key().map_err(submit)?)
            .map_err(submit)?;
        assert_eq!(
            pair.a.wait(sa.operation).await.map_err(submit)?,
            Completed::Connected {
                generation: sa.operation
            }
        );
        assert_eq!(
            pair.b.wait(sb.operation).await.map_err(submit)?,
            Completed::Connected {
                generation: sb.operation
            }
        );
        Ok(())
    })
    .await?;
    // The first close-body lookup occurs after both original backend owners were
    // released and replaced. Only bounded inline terminal metadata survived.
    for (handle, old) in [(&pair.a, old_a), (&pair.b, old_b)] {
        let report = handle
            .proxy_close_report(old)
            .map_err(submit)?
            .ok_or("actual retained close body")?;
        assert_eq!(
            report,
            local::ProxyCloseReport {
                local_user_records: 0,
                peer_user_records: 0,
                local_transparent_packets: 0,
                native_confirmed_packets: 0,
                clean_flows: 0,
                stopped_flows: 0,
                tls_lanes_closed: 1,
            }
        );
        assert_ne!(handle.snapshot().generation, Some(old));
        assert!(
            handle
                .proxy_close_report(handle.snapshot().generation.ok_or("new generation")?)
                .map_err(submit)?
                .is_none()
        );
    }
    let new_b = pair
        .b
        .snapshot()
        .generation
        .ok_or("replacement server generation")?;
    drive(&mut pair.arun, &mut pair.brun, async {
        let stop = pair
            .a
            .disconnect(pair.a.next_key().map_err(submit)?)
            .map_err(submit)?;
        assert_eq!(
            pair.a.wait(stop.operation).await.map_err(submit)?,
            Completed::Aborted
        );
        assert!(matches!(
            pair.b.wait_stopped(new_b).await.map_err(submit)?,
            Terminal::Failed(_)
        ));
        Ok(())
    })
    .await?;
    assert_eq!(pair.an.live.load(Ordering::SeqCst), 0);
    assert_eq!(pair.bn.live.load(Ordering::SeqCst), 0);
    Ok(())
}
