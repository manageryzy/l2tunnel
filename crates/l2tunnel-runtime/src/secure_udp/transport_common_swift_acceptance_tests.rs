//! Actual protected UDP receipt and feedback can precede local completion observation.
use super::*;

#[tokio::test]
async fn actual_swift_receipt_survives_early_ack_and_preserves_late_success() -> Result {
    for late_observation in [false, true] {
        let kind = cover::Appearance::QuicLike;
        let fixture = Fixture::from_contracts_with_tail(kind, contracts(kind)?, false).await?;
        let [mut a, mut b] = fixture.endpoints;
        let now = clock(a.driver.origin, Instant::now())?;
        let epoch = a.driver.common_state()?.epoch();
        let active = a.driver.common_state()?.current();
        let local = active
            .descriptor()
            .local(common_contract::mg_role(a.driver.info.role));
        let l2tunnel::record_configuration::DirectionProfile::Swift(selected) =
            local.send().profile()
        else {
            return Err("actual initial Swift fixture".into());
        };
        let flush = selected.codec.flush_micros;
        let needed = common_contract::maximum_body(local.send(), local.receive())?
            .checked_add(a.driver.config.control.wire_overhead)
            .and_then(|bytes| bytes.checked_add(a.driver.reserve))
            .ok_or("actual Swift wire allowance")?;
        a.driver
            .common_state_mut()?
            .entry(epoch)?
            .enqueue_borrowed(engine::Tick(now), &frame(28_811, 17))?;
        // Commit the real Pipeline head before the existing partial-symbol delay.
        // Enqueue alone leaves native bytes in the shared MUX, outside Swift.
        a.driver
            .common_state_mut()?
            .entry(epoch)?
            .admit_borrowed(engine::Tick(now))?
            .ok_or("actual Swift native admission")?;
        a.driver.progress_common(now)?;
        let ready = a
            .driver
            .bucket
            .ready_at(needed)?
            .max(now.checked_add(flush).ok_or("flush clock")?);
        tokio::time::sleep_until(a.driver.origin + duration(ready)).await;
        let now = clock(a.driver.origin, Instant::now())?;
        a.driver.progress_common(now)?;
        assert!(
            !a.driver
                .send_common_user_with(now, |_| Err(io::ErrorKind::WouldBlock.into()))?
        );
        let (identity, wire, emission) = {
            let runtime = a.driver.common.as_deref().ok_or("Common owner")?;
            let pending = runtime.sealed.as_ref().ok_or("retained Swift ciphertext")?;
            let emission = pending
                .carrier
                .as_ref()
                .ok_or("actual Swift carrier witness")?
                .emission();
            assert_eq!(
                emission.kind,
                engine::EmissionKind::Source(engine::SourceForm::Swift)
            );
            (
                carrier::UserIdentity {
                    scope: pending.scope,
                    number: pending.sealed.number,
                    bytes: pending.sealed.bytes,
                    deadline: a.driver.origin + duration(pending.deadline),
                },
                runtime.wire[..pending.sealed.bytes].to_vec(),
                emission,
            )
        };
        let mut socket_owner: carrier::IoOwner = carrier::IoOwner::Udp(a.socket);
        let receipt = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let carrier::IoOwner::Udp(socket) = &socket_owner else {
                    return Err(io::Error::other("UDP owner changed"));
                };
                socket.writable().await?;
                match socket_owner.try_user(identity, &wire) {
                    Ok(carrier::SendProgress::Whole { receipt, late }) => {
                        assert!(!late);
                        return Ok(receipt);
                    }
                    Ok(carrier::SendProgress::Pending) => {
                        return Err(io::Error::other("UDP was not whole acceptance"));
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error),
                }
            }
        })
        .await??;
        read_one(&b.socket, &mut b.driver).await?;
        let due = b
            .driver
            .common_state()?
            .engine(epoch)?
            .feedback_opportunity()?
            .ok_or("Swift feedback due")?
            .0
            .0;
        let active = b.driver.common_state()?.current();
        let local = active
            .descriptor()
            .local(common_contract::mg_role(b.driver.info.role));
        let feedback_budget = common_contract::maximum_body(local.send(), local.receive())?
            .checked_add(b.driver.config.control.wire_overhead)
            .and_then(|bytes| bytes.checked_add(b.driver.reserve))
            .ok_or("reverse allowance")?;
        let due = due.max(b.driver.bucket.ready_at(feedback_budget)?);
        tokio::time::sleep_until(b.driver.origin + duration(due)).await;
        let now = clock(b.driver.origin, Instant::now())?;
        b.driver.progress_common(now)?;
        assert!(b.driver.send_common_user(&b.socket, now)?);
        let carrier::IoOwner::Udp(socket) = &socket_owner else {
            return Err("UDP owner changed".into());
        };
        read_one(socket, &mut a.driver).await?;
        assert_eq!(
            a.driver
                .common_state_mut()?
                .entry(epoch)?
                .pending_carrier_output()
                .ok_or("ACK cannot consume pending witness")?
                .emission(),
            emission
        );
        assert!(!a.driver.common_state()?.engine(epoch)?.drained()?);
        let before = a.driver.counters.socket_accepted_packets;
        let observed = if late_observation {
            identity.deadline
        } else {
            Instant::now()
        };
        let result = a
            .driver
            .complete_common_carrier(identity, receipt, false, || observed);
        if late_observation {
            assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::TimedOut));
        } else {
            assert!(result?);
        }
        assert_eq!(a.driver.counters.socket_accepted_packets, before + 1);
        assert!(
            a.driver
                .common
                .as_deref()
                .ok_or("Common owner")?
                .sealed
                .is_none()
        );
        assert!(
            a.driver
                .common_state_mut()?
                .entry(epoch)?
                .pending_carrier_output()
                .is_none()
        );
        assert_eq!(socket_owner.addresses()?, a.original);
    }
    Ok(())
}
