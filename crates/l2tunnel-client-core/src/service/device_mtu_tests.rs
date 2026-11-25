use super::*;
use transport::DeviceMtu as _;

#[derive(Default)]
struct Fake {
    mtu: Mutex<u32>,
    sets: Mutex<Vec<u32>>,
}
impl DeviceMtuHost for Fake {
    fn get(&self) -> MtuFuture<'_, u32> {
        let mtu = *self.mtu.lock().unwrap_or_else(PoisonError::into_inner);
        Box::pin(async move { Ok(mtu) })
    }
    fn set(&self, mtu: u32) -> MtuFuture<'_, ()> {
        *self.mtu.lock().unwrap_or_else(PoisonError::into_inner) = mtu;
        self.sets
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(mtu);
        Box::pin(async { Ok(()) })
    }
}

#[tokio::test]
async fn the_mtu_from_before_the_session_is_restored_when_it_ends() -> io::Result<()> {
    let fake = Arc::new(Fake {
        mtu: Mutex::new(9000),
        ..Fake::default()
    });
    let session = SessionMtu {
        host: fake.clone(),
        original: Mutex::new(None),
    };
    session.set(1400).await?;
    session.set(1200).await?;
    drop(session);
    for _ in 0..100 {
        if *fake.mtu.lock().unwrap_or_else(PoisonError::into_inner) == 9000 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        *fake.sets.lock().unwrap_or_else(PoisonError::into_inner),
        [1400, 1200, 9000]
    );
    // A session that never changed the device leaves it alone.
    let untouched = SessionMtu {
        host: fake.clone(),
        original: Mutex::new(None),
    };
    drop(untouched);
    tokio::task::yield_now().await;
    assert_eq!(
        fake.sets
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len(),
        3
    );
    Ok(())
}
