//! Actual Common/Aligned native delivery uses one unchanged per-turn write grant.
use super::*;

fn one_channel_aligned_contracts() -> Result<[CommonTransactionContract; 2]> {
    use l2tunnel::record_configuration as c;
    let kind = cover::Appearance::QuicLike;
    let values = udp_values(kind)?;
    let descriptor = values[1].descriptor();
    let c::Profile::Aligned {
        mut forward,
        mut reverse,
    } = *descriptor.profile()
    else {
        return Err("fixture missing actual Aligned profile".into());
    };
    forward.receiver.channels = 1;
    reverse.receiver.channels = 1;
    let direction = |role| -> Result<c::CommonDirection> {
        let original = descriptor.direction(role).common();
        let mut pipeline = original.pipeline();
        pipeline.flows.channels = 1;
        Ok(c::CommonDirection::new(
            original.traffic(),
            pipeline,
            original.bytes_per_second(),
            original.burst_bytes(),
            original.native_window(),
        )?)
    };
    let descriptor = c::Descriptor::new(
        1500,
        core::Duplex::Full,
        direction(mg::Role::Client)?,
        direction(mg::Role::Server)?,
        c::Profile::Aligned { forward, reverse },
    )?;
    contracts_with_catalog(kind, Catalog::new(descriptor, &[descriptor])?, 2)
}

#[test]
fn common_native_batch_refills_actual_aligned_backlog_with_original_custody() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let mut fixture = Fixture::from_contracts(
                cover::Appearance::QuicLike,
                one_channel_aligned_contracts()?,
            )
            .await?;
            let expected: Vec<_> = (0..4).map(|id| frame(40000, id)).collect();
            for packet in &expected {
                fixture.admit(0, packet).await?;
            }
            // Send and authenticate actual recovery records while retaining the
            // receiver's first native token. No more ingress is needed below.
            for _ in 0..32 {
                fixture.turn_with_held_native(Some(1)).await?;
            }
            let endpoint = &mut fixture.endpoints[1];
            let now = fixture.now;
            assert_eq!(endpoint.driver.config.work.native_write_batch, 2);
            assert_eq!(endpoint.driver.counters.native_written, 0);
            assert_eq!(endpoint.driver.native.len(), 1);
            let first = endpoint
                .driver
                .native
                .common()?
                .front()
                .ok_or("first native")?;
            let token = first.metadata().token;
            let deadline = first.metadata().deadline;
            let bytes = first.bytes().to_vec();
            let mut filler_packets = 0;
            {
                let mut ready = tokio::time::timeout(
                    Duration::from_secs(1),
                    endpoint.device.ready_mut(Interest::WRITABLE),
                )
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "initial native writable readiness")
                })??;
                // Fill the real datagram send queue after acquiring readiness.
                // Draining it below then creates a genuine writable transition.
                let mut saturated = false;
                for _ in 0..4096 {
                    match ready.get_inner_mut().socket.send(&[0]) {
                        Ok(length) => {
                            assert_eq!(length, 1);
                            filler_packets += 1;
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            saturated = true;
                            break;
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                assert!(
                    saturated && filler_packets > 0,
                    "bounded fixture queue saturation"
                );
                assert_eq!(
                    endpoint
                        .driver
                        .write_native_batch(&mut ready, 0, || Ok(now))?,
                    0
                );
                assert_eq!(
                    endpoint
                        .driver
                        .write_native_batch(&mut ready, 2, || Ok(now))?,
                    1
                );
            }
            let held = endpoint
                .driver
                .native
                .common()?
                .front()
                .ok_or("blocked native")?;
            assert_eq!(held.metadata().token, token);
            assert_eq!(held.metadata().deadline, deadline);
            assert_eq!(held.bytes(), bytes);
            assert_eq!(endpoint.driver.counters.native_written, 0);
            let mut filler = [0; 2];
            for _ in 0..filler_packets {
                assert_eq!(endpoint.host.recv(&mut filler)?, 1);
                assert_eq!(filler[0], 0);
            }
            assert_eq!(
                endpoint
                    .host
                    .recv(&mut filler)
                    .err()
                    .map(|error| error.kind()),
                Some(io::ErrorKind::WouldBlock)
            );
            // Cache actual writable readiness, then exercise the same production
            // pre-select flush used by the sole runtime loop.
            drop(
                tokio::time::timeout(
                    Duration::from_secs(1),
                    endpoint.device.ready_mut(Interest::WRITABLE),
                )
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "native writable readiness after filler drain",
                    )
                })??,
            );
            assert_eq!(
                endpoint
                    .driver
                    .flush_native_ready(&mut endpoint.device, || Ok(now))
                    .await?,
                2
            );
            assert_eq!(endpoint.driver.counters.native_written, 2);
            assert_eq!(
                endpoint
                    .driver
                    .performance
                    .counters
                    .native_write_batch_limit_hits,
                1
            );
            assert!(
                endpoint.driver.native.is_empty(),
                "no preparation beyond the turn grant"
            );
            let mut actual = Vec::new();
            let mut output = [0; 513];
            for _ in 0..2 {
                let length = endpoint.host.recv(&mut output)?;
                actual.push(output[..length].to_vec());
            }
            assert_eq!(actual, expected[..2]);
            assert_eq!(
                endpoint.host.recv(&mut output).err().map(|e| e.kind()),
                Some(io::ErrorKind::WouldBlock)
            );

            // A clock failure between a completed write and the next refill
            // preserves the successful receipt and does not prepare its successor.
            endpoint.driver.collect_native(now)?;
            let mut ready = tokio::time::timeout(
                Duration::from_secs(1),
                endpoint.device.ready_mut(Interest::WRITABLE),
            )
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "native writable readiness before refill clock failure",
                )
            })??;
            let mut samples = 0;
            let result = endpoint.driver.write_native_batch(&mut ready, 2, || {
                samples += 1;
                if samples == 3 {
                    Err(io::Error::other("injected refill clock failure"))
                } else {
                    Ok(now)
                }
            });
            assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::Other));
            assert_eq!(samples, 3);
            assert_eq!(endpoint.driver.counters.native_written, 3);
            assert!(endpoint.driver.native.is_empty());
            drop(ready);
            let length = endpoint.host.recv(&mut output)?;
            actual.push(output[..length].to_vec());
            endpoint.driver.collect_native(now)?;
            let mut ready = tokio::time::timeout(
                Duration::from_secs(1),
                endpoint.device.ready_mut(Interest::WRITABLE),
            )
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "native writable readiness for final packet",
                )
            })??;
            assert_eq!(
                endpoint
                    .driver
                    .write_native_batch(&mut ready, 1, || Ok(now))?,
                1
            );
            let length = endpoint.host.recv(&mut output)?;
            actual.push(output[..length].to_vec());
            assert_eq!(actual, expected);
            assert_eq!(endpoint.driver.counters.native_written, 4);
            assert_eq!(
                endpoint.host.recv(&mut output).err().map(|e| e.kind()),
                Some(io::ErrorKind::WouldBlock)
            );
            Ok(())
        })
}
