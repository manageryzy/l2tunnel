//! A genuine retained Swift emission must not turn a paced retry into a spin.
use super::*;

#[test]
fn held_swift_ciphertext_wakes_at_retry_instead_of_expired_sender_opportunity() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let kind = cover::Appearance::QuicLike;
            let [client, server] = contracts(kind)?;
            let explicit_timing =
                |contract: CommonTransactionContract| -> Result<CommonTransactionContract> {
                    let mut resources = contract.resources();
                    // Explicit fixture geometry places the real Swift tail opportunity
                    // before the recovery cadence, independently of product defaults.
                    resources.work.receive_interval = Duration::from_millis(100);
                    resources.lifetime.ping_interval = Duration::from_secs(10);
                    Ok(CommonTransactionContract::new(
                        contract.expected_configuration(),
                        contract.role(),
                        resources,
                        contract.cover(),
                        contract.ipv6(),
                        contract.envelope(),
                        contract.catalog().clone(),
                        contract.settings(),
                    )?)
                };
            let mut fixture =
                Fixture::from_contracts(kind, [explicit_timing(client)?, explicit_timing(server)?])
                    .await?;
            fixture.admit(0, &frame(40_100, 0x93)).await?;
            let driver = &mut fixture.endpoints[0].driver;
            let epoch = core::Epoch(driver.source_scope.epoch.0);
            assert!(matches!(
                driver
                    .common_state()?
                    .engine(epoch)?
                    .configuration()
                    .descriptor()
                    .profile(),
                l2tunnel::record_configuration::Profile::Swift { .. }
            ));
            driver.bucket.refill(fixture.now)?;
            assert!(
                !driver.send_common_user_with(fixture.now, |_| Err(
                    io::ErrorKind::NetworkDown.into()
                ),)?
            );
            let runtime = driver
                .common
                .as_ref()
                .ok_or("actual Common owner missing")?;
            assert!(runtime.path.unavailable);
            let pending = runtime
                .sealed
                .as_ref()
                .ok_or("actual sealed Swift output missing")?;
            assert!(
                pending.carrier.is_none(),
                "Swift does not fabricate a Reliable token"
            );
            let identity = (
                pending.scope,
                pending.sealed,
                pending.cost,
                pending.deadline,
            );
            let bytes = runtime.wire[..pending.sealed.bytes].to_vec();
            let retry = runtime
                .path
                .retry_at_micros
                .ok_or("actual retry cadence missing")?;
            let soft = driver
                .common_state()?
                .engine(epoch)?
                .deadline()?
                .ok_or("actual emitted Swift source has no sender opportunity")?
                .0;
            let after_soft = soft.checked_add(1).ok_or("fixture clock overflow")?;
            assert!(soft > fixture.now);
            assert!(after_soft < retry);
            assert!(retry < driver.lease && retry < driver.next_ping);
            driver.progress_common(after_soft)?;
            // The direct User-send seam bypasses send_sampled's preceding
            // Control poll. Complete the real empty owners' bounded initial
            // rotations rather than excluding their legitimate immediate work.
            assert!(driver.control.deadline() <= duration(after_soft));
            assert_eq!(driver.prepare_control(after_soft)?, None);
            assert!(driver.control.deadline() > duration(retry));
            let wake = driver.wake_common(after_soft)?;
            assert_eq!(wake, driver.origin + duration(retry));
            assert!(wake > driver.origin + duration(after_soft));
            let mut premature_socket_call = false;
            assert!(!driver.flush_common_wire_with(after_soft, |_| {
                premature_socket_call = true;
                Err(io::ErrorKind::WouldBlock.into())
            })?);
            assert!(!premature_socket_call, "premature retry reached socket");
            let runtime = driver.common.as_ref().ok_or("actual Common owner lost")?;
            let pending = runtime
                .sealed
                .as_ref()
                .ok_or("actual sealed Swift output lost")?;
            assert_eq!(
                (
                    pending.scope,
                    pending.sealed,
                    pending.cost,
                    pending.deadline
                ),
                identity
            );
            assert_eq!(&runtime.wire[..pending.sealed.bytes], bytes);
            assert_eq!(runtime.path.retry_attempts, 0);
            assert_eq!(driver.counters.socket_accepted_packets, 0);
            Ok(())
        })
}
