//! Bounded tests drive the real service Runs without installing backend state.

use super::*;

pub(super) fn appearances() -> [l2tunnel_cover::Appearance; 2] {
    [
        l2tunnel_cover::Appearance::QuicLike,
        l2tunnel_cover::Appearance::MediaLike,
    ]
}

pub(super) fn hosts() -> [Arc<Host>; 2] {
    [Arc::new(Host::default()), Arc::new(Host::default())]
}

pub(super) fn observation(handle: &Handle, operation: OperationId) -> Result<SetupObservation> {
    handle
        .setup_observation(operation)
        .map_err(submit)?
        .ok_or_else(|| "missing actual generic setup observation".into())
}

pub(super) fn completed(handle: &Handle, operation: OperationId) -> Option<Completed> {
    handle
        .0
        .lock()
        .entries
        .iter()
        .find(|entry| entry.accepted.operation == operation)
        .and_then(|entry| entry.result.clone())
}

/// Never await an admission guard held by a manually polled service Run.
pub(super) fn admission_identity_now(plan: &Prepared) -> io::Result<usize> {
    let prepared::Endpoint::SecureServer(server) = &plan.data.endpoint else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not secure server",
        ));
    };
    let guard = server
        .admission
        .try_lock()
        .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
    let admission = guard
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no retained admission"))?;
    Ok(std::ptr::from_ref(admission) as usize)
}

pub(super) fn assert_unopened(hosts: &[Arc<Host>; 2]) {
    for host in hosts {
        assert_eq!(host.opened.load(Ordering::SeqCst), 0);
        assert_eq!(host.live.load(Ordering::SeqCst), 0);
    }
}

pub(super) fn assert_ports_free(addresses: [std::net::SocketAddr; 2]) -> Result {
    let _held = [
        std::net::UdpSocket::bind(addresses[0])?,
        std::net::UdpSocket::bind(addresses[1])?,
    ];
    Ok(())
}

pub(super) fn history(handle: &Handle) -> (u64, usize, bool, Option<OperationId>) {
    let state = handle.0.lock();
    (
        state.last_key,
        state.entries.len(),
        state.queued.is_some(),
        state.snapshot.operation,
    )
}

pub(super) async fn single_result(
    run: &mut Pin<Box<Run>>,
    handle: &Handle,
    operation: OperationId,
) -> Result<Completed> {
    timeout(Duration::from_secs(4), async {
        loop {
            drive_once(run).await;
            if let Some(result) = completed(handle, operation) {
                return Ok::<_, Error>(result);
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await?
}

pub(super) struct Pair {
    pub(super) handles: [Handle; 2],
    pub(super) runs: [Option<Pin<Box<Run>>>; 2],
    pub(super) accepted: [Accepted; 2],
    pub(super) fixture: TransactionPlans,
    pub(super) hosts: [Arc<Host>; 2],
}

impl Pair {
    pub(super) fn new(fixture: TransactionPlans, hosts: [Arc<Host>; 2]) -> Result<Self> {
        for plan in &fixture.plans {
            assert!(plan.secure_udp_transaction());
        }
        let (a, run_a) = channel();
        let (b, run_b) = channel();
        let left = a
            .connect(fixture.plans[0].clone(), a.next_key().map_err(submit)?)
            .map_err(submit)?;
        let right = b
            .connect(fixture.plans[1].clone(), b.next_key().map_err(submit)?)
            .map_err(submit)?;
        Ok(Self {
            handles: [a, b],
            runs: [Some(Box::pin(run_a)), Some(Box::pin(run_b))],
            accepted: [left, right],
            fixture,
            hosts,
        })
    }

    pub(super) async fn drive_side(&mut self, side: usize) -> Result {
        if let Some(run) = &mut self.runs[side] {
            std::future::poll_fn(|cx| {
                if let Poll::Ready(result) = run.as_mut().poll(cx) {
                    return Poll::Ready(Err(io::Error::other(format!(
                        "service Run ended: {result:?}"
                    ))));
                }
                Poll::Ready(Ok(()))
            })
            .await?;
        }
        Ok(())
    }

    pub(super) async fn drive(&mut self) -> Result {
        self.drive_side(0).await?;
        self.drive_side(1).await?;
        Ok(())
    }

    pub(super) async fn until(&mut self, mut ready: impl FnMut(&Self) -> Result<bool>) -> Result {
        timeout(Duration::from_secs(4), async {
            loop {
                self.drive().await?;
                if ready(self)? {
                    return Ok::<(), Error>(());
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await?
    }

    pub(super) async fn ready(&mut self) -> Result {
        self.until(|pair| {
            Ok((0..2).all(|side| {
                completed(&pair.handles[side], pair.accepted[side].operation).is_some()
            }))
        })
        .await?;
        for side in 0..2 {
            assert_eq!(
                completed(&self.handles[side], self.accepted[side].operation),
                Some(Completed::Connected {
                    generation: self.accepted[side].operation
                })
            );
            assert!(status(&self.handles[side])?.running);
            assert_eq!(
                observation(&self.handles[side], self.accepted[side].operation)?.outcome,
                SetupOutcome::Ready
            );
        }
        Ok(())
    }

    pub(super) async fn result(
        &mut self,
        side: usize,
        operation: OperationId,
    ) -> Result<Completed> {
        self.until(|pair| Ok(completed(&pair.handles[side], operation).is_some()))
            .await?;
        completed(&self.handles[side], operation).ok_or_else(|| "lost actual completion".into())
    }

    pub(super) async fn exchange(&mut self, side: usize, marker: u8) -> Result {
        let bytes = packet(marker, 512);
        self.hosts[side].send(&bytes)?;
        self.until(|pair| {
            let mut output = [0; 1601];
            let application = pair.hosts[1 - side]
                .application
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match application
                .as_ref()
                .ok_or("generic packet device not opened")?
                .recv(&mut output)
            {
                Ok(length) => {
                    assert_eq!(&output[..length], bytes);
                    Ok(true)
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
                Err(error) => Err(error.into()),
            }
        })
        .await
    }

    pub(super) fn close(&mut self) -> Result {
        drop(self.runs[0].take());
        drop(self.runs[1].take());
        for host in &self.hosts {
            assert_eq!(host.live.load(Ordering::SeqCst), 0);
        }
        assert_ports_free(self.fixture.addresses)
    }
}
