//! Retained output distinguishes service wakes from its original custody cap.
use super::*;
use l2tunnel::record_engine as engine;

fn longer_native_frame() -> Vec<u8> {
    let mut packet = frame(40_101, 92);
    packet.resize(100, 0);
    packet[16..18].copy_from_slice(&86_u16.to_be_bytes());
    packet[38..40].copy_from_slice(&66_u16.to_be_bytes());
    packet[24..26].fill(0);
    let mut sum = packet[14..34].chunks_exact(2).fold(0u32, |sum, pair| {
        sum + u32::from(u16::from_be_bytes([pair[0], pair[1]]))
    });
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    packet[24..26].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    packet
}

#[test]
fn held_aligned_ciphertext_survives_unrelated_receive_fec_eviction() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(Box::pin(async {
            let appearance = cover::Appearance::QuicLike;
            let values = udp_values(appearance)?;
            let aligned = values[1];
            assert!(matches!(
                aligned.descriptor().profile(),
                l2tunnel::record_configuration::Profile::Aligned { .. }
            ));
            let descriptor = *aligned.descriptor();
            let contracts =
                contracts_with_catalog(appearance, Catalog::new(descriptor, &[descriptor])?, 16)?;
            let mut fixture = Fixture::from_contracts(appearance, contracts).await?;
            // Two real source records make a repair insufficient to decode.
            // Discard every source; authenticate only the actual repair at A.
            fixture.admit(1, &frame(40_100, 91)).await?;
            fixture.admit(1, &longer_native_frame()).await?;
            let mut repair = None;
            let mut systematic_bytes = Vec::new();
            for _ in 0..32 {
                fixture.now += 1000;
                let driver = &mut fixture.endpoints[1].driver;
                driver.progress_common(fixture.now)?;
                assert!(!driver.send_common_user_with(fixture.now, |_| {
                    Err(io::ErrorKind::WouldBlock.into())
                })?);
                let pending = driver
                    .common
                    .as_ref()
                    .and_then(|runtime| runtime.sealed.as_ref());
                let Some(pending) = pending else {
                    continue;
                };
                let emission = pending
                    .carrier
                    .as_ref()
                    .ok_or("actual Aligned carrier witness missing")?
                    .emission();
                let kind = emission.kind;
                let extent = driver
                    .common_state()?
                    .engine(core::Epoch(pending.scope.epoch.0))?
                    .inspect_output_extent(&driver.buffers.frame[..emission.bytes], kind, false)?;
                let recovery = extent.recovery.ok_or("actual recovery extent missing")?;
                assert_eq!(recovery.systematic_coded_fill_bytes, 0);
                assert_eq!(pending.cost, pending.sealed.bytes + 28);
                assert_eq!(emission.wire_bytes, pending.cost);
                if recovery.kind == l2tunnel_reliable::RecordKind::Systematic {
                    systematic_bytes.push(recovery.bytes);
                }
                let mut packet = Vec::new();
                assert!(driver.flush_common_wire_with(fixture.now, |bytes| {
                    packet.extend_from_slice(bytes);
                    Ok(bytes.len())
                })?);
                if kind == engine::EmissionKind::Repair {
                    repair = Some(packet);
                    break;
                }
            }
            assert_eq!(systematic_bytes.len(), 2);
            assert_ne!(
                systematic_bytes[0], systematic_bytes[1],
                "actual protected systematic records retain their unequal source extents"
            );
            let repair = repair.ok_or("two-source repair was not emitted")?;
            let driver = &mut fixture.endpoints[0].driver;
            driver.receive_selected(&repair, fixture.now, driver.origin + duration(fixture.now))?;
            let epoch = driver.common_state()?.epoch();
            let owner = driver.common_state()?.engine(epoch)?;
            let eviction = owner
                .expiry_deadline()?
                .ok_or("actual incomplete receive FEC cache missing")?
                .0;
            assert!(eviction > fixture.now);
            assert_eq!(owner.custody_deadline()?, None);

            fixture.admit(0, &frame(40_102, 93)).await?;
            let driver = &mut fixture.endpoints[0].driver;
            // Respect the selected Aligned batch flush timer. Poll within the
            // original receive-cache lifetime rather than assuming immediate output.
            for _ in 0..32 {
                fixture.now += 1000;
                assert!(fixture.now < eviction);
                driver.progress_common(fixture.now)?;
                assert!(!driver.send_common_user_with(fixture.now, |_| {
                    Err(io::ErrorKind::WouldBlock.into())
                })?);
                if driver.common.as_ref().is_some_and(|r| r.sealed.is_some()) {
                    break;
                }
            }
            let runtime = driver
                .common
                .as_ref()
                .ok_or("actual Common runtime missing")?;
            let pending = runtime.sealed.as_ref().ok_or("held source missing")?;
            assert!(matches!(
                pending
                    .carrier
                    .as_ref()
                    .ok_or("source witness missing")?
                    .emission()
                    .kind,
                engine::EmissionKind::Source(_)
            ));
            assert_eq!(pending.deadline, driver.lease);
            assert!(pending.deadline > eviction);
            let identity = (
                pending.scope,
                pending.sealed,
                pending.cost,
                pending.deadline,
            );
            let packet = runtime.wire[..pending.sealed.bytes].to_vec();
            let next_number = driver.records.next_number(Class::User);
            let before = driver.counters.socket_accepted_packets;
            let after_eviction = eviction + 1;
            driver.progress_common(after_eviction)?;
            driver.service_common_rolling(after_eviction)?;
            assert_eq!(
                driver.common_state()?.engine(epoch)?.expiry_deadline()?,
                None
            );
            assert_eq!(
                driver.common_state()?.engine(epoch)?.custody_deadline()?,
                None
            );
            assert!(!driver.flush_common_wire_with(after_eviction, |_| {
                Err(io::ErrorKind::WouldBlock.into())
            })?);
            let runtime = driver.common.as_ref().ok_or("held Common runtime lost")?;
            let pending = runtime.sealed.as_ref().ok_or("held source lost")?;
            assert_eq!(
                (
                    pending.scope,
                    pending.sealed,
                    pending.cost,
                    pending.deadline
                ),
                identity
            );
            assert_eq!(&runtime.wire[..pending.sealed.bytes], packet);
            assert_eq!(driver.records.next_number(Class::User), next_number);
            assert_eq!(driver.counters.socket_accepted_packets, before);
            assert!(driver.flush_common_wire_with(after_eviction + 1, |bytes| {
                assert_eq!(bytes, packet);
                Ok(bytes.len())
            })?);
            assert_eq!(driver.counters.socket_accepted_packets, before + 1);
            assert!(
                driver
                    .common
                    .as_ref()
                    .ok_or("runtime lost")?
                    .sealed
                    .is_none()
            );
            assert_eq!(
                driver.lease, identity.3,
                "maintenance must not renew the cap"
            );
            Ok(())
        }))
}

#[test]
fn held_swift_ciphertext_wakes_at_retry_without_arming_sender_attempt() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let kind = cover::Appearance::QuicLike;
            let [client, server] = contracts(kind)?;
            let explicit_timing =
                |contract: CommonTransactionContract| -> Result<CommonTransactionContract> {
                    let mut resources = contract.resources();
                    // Keep the existing explicit recovery cadence, independently of
                    // product defaults; an unaccepted Swift attempt stays pending.
                    resources.work.receive_interval = Duration::from_millis(100);
                    resources.lifetime.ping_interval = Duration::from_secs(10);
                    Ok(CommonTransactionContract::new_compact_wire(
                        contract.expected_configuration(),
                        contract.role(),
                        [resources; 2],
                        contract.cover(),
                        contract.ipv6(),
                        contract.envelope(),
                        contract.catalog().clone(),
                        contract.settings(),
                        contract.compact_wire(),
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
            assert_eq!(
                pending
                    .carrier
                    .as_ref()
                    .ok_or("actual Swift witness")?
                    .emission()
                    .kind,
                engine::EmissionKind::Source(engine::SourceForm::Swift)
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
            let after_prepare = fixture.now.checked_add(1).ok_or("fixture clock overflow")?;
            assert!(after_prepare < retry);
            assert!(retry < driver.lease && retry < driver.next_ping);
            driver.progress_common(after_prepare)?;
            // The direct User-send seam bypasses send_sampled's preceding
            // Control poll. Complete the real empty owners' bounded initial
            // rotations rather than excluding their legitimate immediate work.
            assert!(driver.control.deadline() <= duration(after_prepare));
            assert_eq!(driver.prepare_control(after_prepare)?, None);
            assert!(driver.control.deadline() > duration(retry));
            let wake = driver.wake_common(after_prepare)?;
            assert_eq!(wake, driver.origin + duration(retry));
            assert!(wake > driver.origin + duration(after_prepare));
            let mut premature_socket_call = false;
            assert!(!driver.flush_common_wire_with(after_prepare, |_| {
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
