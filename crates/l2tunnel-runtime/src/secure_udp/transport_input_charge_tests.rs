//! Actual constructor admission and sole-loop input ownership, not full reservation.

use super::*;

fn with_budget(
    contract: &TransactionContract,
    retained_bytes: usize,
) -> io::Result<TransactionContract> {
    let mut settings = contract.settings();
    settings.retained_bytes = retained_bytes;
    TransactionContract::new(
        contract.expected_configuration(),
        contract.role(),
        contract.config(),
        contract.cover(),
        contract.ipv6(),
        contract.envelope(),
        contract.catalog().clone(),
        settings,
    )
}

#[tokio::test]
async fn actual_input_charge_rejects_the_omitted_budget_and_one_short() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let fixture = Fixture::new(kind).await?;
        let driver = &fixture.endpoints[0].driver;
        let snapshot = driver.snapshot_transaction(fixture.now, false)?;
        let required = snapshot.storage.peak_bytes;
        let input_capacity = driver
            .inputs
            .as_ref()
            .ok_or("generic constructor did not retain its real inputs")?
            .capacity_bytes();
        assert_eq!(input_capacity, READ_BUFFER_BYTES + 1501);
        assert_eq!(snapshot.counters.loop_input_capacity_bytes, input_capacity);
        assert!(!snapshot.resource_preallocation_complete);
        drop(fixture);

        let [contract, _] = contracts(kind)?;
        for (budget, succeeds) in [
            (required - input_capacity, false),
            (required - 1, false),
            (required, true),
        ] {
            let checked = with_budget(&contract, budget)?;
            let (parts, _) = parts_pair(kind).await?;
            let original = (parts.socket.local_addr()?, parts.socket.peer_addr()?);
            match Driver::new_transaction(parts, checked, Instant::now()) {
                Ok((socket, driver)) => {
                    assert!(succeeds, "insufficient actual input budget was admitted");
                    assert_eq!((socket.local_addr()?, socket.peer_addr()?), original);
                    let snapshot = driver.snapshot_transaction(0, false)?;
                    assert_eq!(snapshot.storage.limit_bytes, required);
                    assert_eq!(snapshot.storage.peak_bytes, required);
                    assert_eq!(snapshot.counters.loop_input_capacity_bytes, input_capacity);
                    assert!(!snapshot.resource_preallocation_complete);
                }
                Err(error) => {
                    assert!(!succeeds, "exact actual constructor budget failed: {error}");
                    assert_eq!(error.kind(), io::ErrorKind::Other);
                    assert!(matches!(
                        error
                            .get_ref()
                            .and_then(|cause| cause.downcast_ref::<swift::storage::Error>()),
                        Some(swift::storage::Error::Budget)
                    ));
                }
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn generic_loop_takes_the_same_input_backing_once_without_fallback() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let mut fixture = Fixture::new(kind).await?;
        for endpoint in &mut fixture.endpoints {
            let driver = &mut endpoint.driver;
            let prepared = driver.inputs.as_ref().ok_or("missing prepared inputs")?;
            let backing = (prepared.native.as_ptr(), prepared.datagram.as_ptr());
            let capacity = prepared.capacity_bytes();
            let before = driver.snapshot_transaction(fixture.now, false)?;
            let inputs = driver.take_inputs()?;
            assert_eq!((inputs.native.as_ptr(), inputs.datagram.as_ptr()), backing);
            assert_eq!(inputs.capacity_bytes(), capacity);
            assert!(driver.inputs.is_none());
            let after = driver.snapshot_transaction(fixture.now, true)?;
            assert_eq!(after.storage, before.storage);
            assert_eq!(after.counters.loop_input_capacity_bytes, capacity);
            assert!(!after.resource_preallocation_complete);
            assert!(driver.take_inputs().is_err(), "missing owner reallocated");
            assert!(driver.inputs.is_none());
            assert_eq!(inputs.capacity_bytes(), capacity);
        }
    }
    Ok(())
}
