//! Actual rolling whole-write completion followed by a fresh same-batch poll.
use super::*;

#[test]
fn rolling_whole_write_resamples_before_next_same_batch_poll() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let kind = cover::Appearance::QuicLike;
            let (contracts, _) = selected(kind, rolling::wire::SourceWire::Exact, 3)?;
            let mut fixture = Fixture::from_contracts(kind, contracts).await?;
            fixture.admit(0, &frame(40_000, 95)).await?;
            let now = retain_first_source(&mut fixture)?;
            let endpoint = &mut fixture.endpoints[0];
            assert!(endpoint.driver.control.drained());
            let runtime = endpoint.driver.common.as_ref().ok_or("common runtime")?;
            let pending = runtime
                .sealed
                .as_ref()
                .ok_or("retained actual rolling source")?;
            let epoch = core::Epoch(pending.scope.epoch.0);
            let token = pending
                .carrier
                .as_ref()
                .ok_or("actual rolling carrier token")?;
            assert!(matches!(
                token.emission().kind,
                engine::EmissionKind::Source(_)
            ));
            let cap = pending.deadline;
            let original = runtime.wire[..pending.sealed.bytes].to_vec();
            let cost = pending.cost;
            let number = endpoint.driver.records.next_number(Class::User);
            let debit = endpoint.driver.bucket.tokens;
            let packets = endpoint.driver.counters.wire_packets;
            let accepted = endpoint.driver.counters.socket_accepted_packets;
            let accepted_bytes = endpoint.driver.counters.socket_accepted_ip_bytes;
            let origin = endpoint.driver.origin;
            let mut sampled = now;
            let mut samples = Vec::new();
            endpoint
                .driver
                .send_sampled(&endpoint.socket, now, origin + duration(now), || {
                    sampled += 1;
                    samples.push(sampled);
                    origin + duration(sampled)
                })?;
            // First iteration, actual post-write confirmation, then the next
            // iteration all observe distinct monotonic injected microseconds.
            assert!(samples.len() >= 3, "same-batch continuation must resample");
            assert!(samples.windows(2).all(|pair| pair[0] < pair[1]));
            assert!(samples.iter().all(|sample| *sample < cap));
            assert!(endpoint.driver.terminal.is_none());
            assert!(
                endpoint
                    .driver
                    .common
                    .as_ref()
                    .ok_or("common runtime")?
                    .sealed
                    .is_none()
            );
            assert!(
                endpoint
                    .driver
                    .common_state()?
                    .engine(epoch)?
                    .pending_carrier_output()
                    .is_none()
            );
            assert_eq!(endpoint.driver.records.next_number(Class::User), number);
            assert_eq!(endpoint.driver.bucket.tokens, debit);
            assert_eq!(endpoint.driver.counters.wire_packets, packets);
            assert_eq!(
                endpoint.driver.counters.socket_accepted_packets,
                accepted + 1
            );
            assert_eq!(
                endpoint.driver.counters.socket_accepted_ip_bytes,
                accepted_bytes + cost as u64
            );
            // The retained bytes really entered the original peer UDP socket;
            // no extra seal, policy debit or second physical source is invented.
            let mut received = [0; 1501];
            let length = tokio::time::timeout(
                Duration::from_secs(1),
                fixture.endpoints[1].socket.recv(&mut received),
            )
            .await??;
            assert_eq!(&received[..length], original);
            assert_eq!(
                fixture.endpoints[1]
                    .socket
                    .try_recv(&mut received)
                    .err()
                    .map(|error| error.kind()),
                Some(io::ErrorKind::WouldBlock)
            );
            Ok(())
        })
}
