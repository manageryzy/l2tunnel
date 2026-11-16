//! Worker ownership contracts using synchronized fake resources, without drivers.
use super::*;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    time::Duration,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct Owner(Arc<AtomicUsize>);

impl Owner {
    fn new(live: Arc<AtomicUsize>) -> Self {
        live.fetch_add(1, Ordering::SeqCst);
        Self(live)
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn cancellation_wait_does_not_detach_delayed_setup_owner() -> TestResult {
    let live = Arc::new(AtomicUsize::new(0));
    let (started, starting) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let worker_live = live.clone();
    let mut setup = Setup::spawn(move || {
        let owner = Owner::new(worker_live);
        started
            .send(())
            .map_err(|_| io::Error::other("test start"))?;
        released
            .recv()
            .map_err(|_| io::Error::other("test release"))?;
        Ok(owner)
    })?;
    starting.recv_timeout(Duration::from_secs(5))?;
    tokio::select! {
        _ = setup.wait() => return Err("blocked setup reported ready".into()),
        _ = std::future::ready(()) => {},
    }
    assert_eq!(live.load(Ordering::SeqCst), 1);
    release.send(())?;
    let owner = setup.finish().await?;
    assert_eq!(live.load(Ordering::SeqCst), 1);
    drop(owner);
    assert_eq!(live.load(Ordering::SeqCst), 0);
    assert!(setup.finish().await.is_err());
    Ok(())
}

#[test]
fn dropping_foreground_future_joins_delayed_worker_and_releases_unclaimed_owner() -> TestResult {
    let live = Arc::new(AtomicUsize::new(0));
    let (started, starting) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let worker_live = live.clone();
    let setup = Setup::spawn(move || {
        let owner = Owner::new(worker_live);
        started
            .send(())
            .map_err(|_| io::Error::other("test start"))?;
        released
            .recv()
            .map_err(|_| io::Error::other("test release"))?;
        Ok(owner)
    })?;
    starting.recv_timeout(Duration::from_secs(5))?;
    let mut foreground = Box::pin(async move {
        std::future::pending::<()>().await;
        drop(setup);
    });
    use std::{
        future::Future,
        task::{Context, Poll, Waker},
    };
    assert!(matches!(
        foreground
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
    let (dropping, drop_started) = mpsc::channel();
    let (finished, drop_finished) = mpsc::channel();
    let dropper = thread::spawn(move || {
        let _ = dropping.send(());
        drop(foreground);
        let _ = finished.send(());
    });
    drop_started.recv_timeout(Duration::from_secs(5))?;
    // The channels hold the actual worker before return. This bounded negative
    // check verifies that Drop cannot report completion while the owner is held.
    let returned_early = drop_finished
        .recv_timeout(Duration::from_millis(50))
        .is_ok();
    release.send(())?;
    if !returned_early {
        drop_finished.recv_timeout(Duration::from_secs(5))?;
    }
    dropper.join().map_err(|_| "test dropper panicked")?;
    assert!(!returned_early);
    assert_eq!(live.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn setup_error_is_joined_and_retains_actual_error_kind() -> TestResult {
    let mut setup = Setup::<()>::spawn(|| {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "test access denied",
        ))
    })?;
    setup.wait().await?;
    setup.wait().await?;
    let result = setup.finish().await;
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    Ok(())
}
