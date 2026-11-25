//! Same shared tag8 generation with genuine authenticated reuse, not a local reset.
use super::*;

fn flow(bytes: &[u8]) -> Result<l2tunnel::packet::FlowKey> {
    Ok(l2tunnel::packet::classify(
        l2tunnel::packet::PacketLayer::Ip,
        bytes,
        l2tunnel::packet::ParseLimits::default(),
    )?
    .key)
}
fn next_packet(reverse: bool, payload: bool) -> Result<Vec<u8>> {
    let mut bytes = tcp(reverse, payload)?;
    let range = if reverse { 22..24 } else { 20..22 };
    bytes[range].copy_from_slice(&41001u16.to_be_bytes());
    bytes[36..38].fill(0);
    let length = u16::try_from(bytes.len() - 20)?;
    let mut pseudo = bytes[12..20].to_vec();
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&length.to_be_bytes());
    pseudo.extend_from_slice(&bytes[20..]);
    let value = checksum(&pseudo);
    bytes[36..38].copy_from_slice(&value.to_be_bytes());
    Ok(bytes)
}
#[tokio::test]
async fn selected_reuse_service_keeps_original_cap_key_generation_and_peer_confirmed_new_bytes()
-> Result {
    exercise(None).await
}
#[tokio::test]
async fn compact_wire_reuse_service_preserves_full_lifecycle_under_both_data_suites() -> Result {
    for protection in [
        l2tunnel_security::compact::Protection::Aes128Ccm4,
        l2tunnel_security::compact::Protection::ChaCha20Crc32c,
    ] {
        exercise(Some(l2tunnel::secure_record::compact::Selection {
            protection,
            limits: l2tunnel_security::compact::Selection {
                max_forward_packets: 32_768,
                max_failed_checks: 64,
            },
        }))
        .await?;
    }
    Ok(())
}
async fn exercise(wire: Option<l2tunnel::secure_record::compact::Selection>) -> Result {
    timeout(Duration::from_secs(20), async {
        let hosts = support::hosts();
        let Selected {
            plans: [left, right],
            addresses,
            profile,
        } = selected_wire(&hosts, true, wire)?;
        assert!(profile.connection_reuse());
        let (client, client_run) = channel();
        let (server, server_run) = channel();
        let tasks = [tokio::spawn(client_run), tokio::spawn(server_run)];
        let accepted = [
            client
                .connect(left, client.next_key().map_err(submit)?)
                .map_err(submit)?,
            server
                .connect(right, server.next_key().map_err(submit)?)
                .map_err(submit)?,
        ];
        let (a, b) = tokio::try_join!(
            connected(&client, accepted[0]),
            connected(&server, accepted[1])
        )?;
        let handles = [client, server];
        let generations = [a, b];
        let data = tcp(false, true)?;
        let ack = tcp(true, false)?;
        hosts[0].send(&data)?;
        hosts[1].expect(&data).await?;
        hosts[1].send(&ack)?;
        hosts[0].expect(&ack).await?;
        tokio::try_join!(reported(&handles[0], false), reported(&handles[1], true))?;
        for handle in &handles {
            let frame = common_frame(handle)?;
            let status = frame.status()?;
            let protection = status
                .compact_wire
                .as_ref()
                .ok_or("current wire status absent")?;
            assert_eq!(
                protection.requested,
                crate::secure_udp::common_status::CompactWireSelection::from_selection(
                    profile.compact_wire(),
                )?
            );
            assert_eq!(protection.effective, Some(protection.requested));
            let selected = status
                .connection_reuse
                .ok_or("selected idle controller absent")?;
            assert!(selected.requested);
            assert_eq!(selected.effective, Some(true));
            assert!(selected.reserved_bytes.is_some_and(|bytes| bytes > 0));
            assert_eq!(selected.allocations, Some(1));
            assert_eq!(
                selected.capability,
                frame
                    .runtime
                    .as_ref()
                    .and_then(|value| value.connections)
                    .is_some_and(|value| value.flow_reuse)
            );
        }
        let old = flow(&data)?;
        let next = next_packet(false, true)?;
        let next_key = flow(&next)?;
        let request = local::ConnectionReuseRequest::new(0, old, next_key)?;
        let key = handles[0].next_key().map_err(submit)?;
        let before = Instant::now();
        let reuse = handles[0]
            .reuse_connection(0, old, next_key, key)
            .map_err(submit)?;
        let after = Instant::now();
        let cap = Duration::from_millis(profile.parameters().max_operation_ms);
        assert!(
            reuse
                .deadline
                .is_some_and(|deadline| deadline >= before + cap && deadline <= after + cap)
        );
        assert_eq!(
            handles[0]
                .reuse_connection(0, old, next_key, key)
                .map_err(submit)?,
            reuse
        );
        assert_eq!(
            handles[0].reuse_connection(1, old, next_key, key),
            Err(SubmitError::Conflict)
        );
        assert_eq!(
            handles[0].cancel(reuse.operation),
            Err(SubmitError::Unsupported)
        );
        let completed = handles[0].wait(reuse.operation).await.map_err(submit)?;
        let Completed::ConnectionReuse {
            request: actual,
            generation,
            outcome: Ok(outcome),
        } = completed
        else {
            return Err(format!("reuse did not confirm: {completed:?}").into());
        };
        assert_eq!(actual, request);
        assert_eq!(generation, generations[0].value());
        assert_eq!(
            (
                outcome.owner,
                outcome.old_incarnation,
                outcome.next_incarnation
            ),
            (0, 29, 30)
        );
        let local_request = local::Request {
            version: local::COMMON_VERSION,
            action: local::Action::ReuseConnection {
                request,
                request_key: key.value(),
            },
        };
        let replay = handles[0].request(local_request.clone()).await;
        assert!(replay.ok, "{replay:?}");
        let result = replay
            .state
            .as_ref()
            .and_then(|value| value.common.as_ref())
            .and_then(|value| value.connection_reuse_result.as_ref())
            .ok_or("exact retained reuse result absent")?
            .clone();
        assert_eq!(result.request, request);
        assert_eq!(result.generation, Some(generations[0].value()));
        assert_eq!(result.operation, reuse.operation.value());
        assert_eq!(result.request_key, key.value());
        assert_eq!(
            result.outcome,
            crate::secure_udp::common_status::ConnectionReuseOutcome::Confirmed
        );
        assert_eq!(
            result.confirmation.as_ref().map(|value| value.attempt),
            Some(outcome.attempt)
        );
        hosts[0].send(&next)?;
        hosts[1].expect(&next).await?;
        let reverse = next_packet(true, false)?;
        hosts[1].send(&reverse)?;
        hosts[0].expect(&reverse).await?;
        for (side, handle) in handles.iter().enumerate() {
            let frame = common_frame(handle)?;
            let status = frame.status()?;
            assert_eq!(frame.generation, generations[side].value());
            assert_eq!(status.epoch, Some(outcome.epoch.0));
            assert_eq!(frame.info.local_addr, addresses[side]);
            assert_eq!(frame.info.peer_addr, addresses[1 - side]);
            let selected = status
                .connection_reuse
                .as_ref()
                .ok_or("selected reuse observation absent")?;
            assert!(selected.requested);
            assert_eq!(selected.effective, Some(true));
            assert_eq!(
                selected.capability,
                status
                    .connections
                    .as_ref()
                    .is_some_and(|value| value.flow_reuse)
            );
            // Availability and this operation outcome are separate actual facts.
            let operation = selected
                .operation
                .as_ref()
                .ok_or("actual completed reuse operation absent")?;
            assert_eq!(operation.request, request);
            assert_eq!(
                operation.phase,
                crate::secure_udp::common_status::ConnectionReusePhase::Completed
            );
            let canonical = serde_json::to_vec(&status)?;
            assert_eq!(
                serde_json::from_slice::<crate::secure_udp::common_status::Status>(&canonical)?,
                status
            );
            assert!(
                status
                    .liveness
                    .as_ref()
                    .is_some_and(|value| value.last_pong_micros.is_some())
            );
            assert_no_native_replay(&hosts[side])?;
        }
        let stop = [
            handles[0]
                .disconnect(handles[0].next_key().map_err(submit)?)
                .map_err(submit)?,
            handles[1]
                .disconnect(handles[1].next_key().map_err(submit)?)
                .map_err(submit)?,
        ];
        let (a, b) = tokio::join!(
            handles[0].wait(stop[0].operation),
            handles[1].wait(stop[1].operation)
        );
        assert_eq!(a.map_err(submit)?, Completed::Aborted);
        assert_eq!(b.map_err(submit)?, Completed::Aborted);
        // Cached acceptance/result remains exact after release, without minting a cap.
        assert_eq!(
            handles[0]
                .reuse_connection(0, old, next_key, key)
                .map_err(submit)?,
            reuse
        );
        let retired = handles[0].request(local_request).await;
        assert!(retired.ok);
        assert_eq!(
            retired
                .state
                .as_ref()
                .and_then(|value| value.common.as_ref())
                .and_then(|value| value.connection_reuse_result.as_ref()),
            Some(&result)
        );
        assert!(
            hosts
                .iter()
                .all(|host| host.live.load(Ordering::SeqCst) == 0)
        );
        support::assert_ports_free(addresses)?;
        for task in tasks {
            task.abort();
            let _ = task.await;
        }
        Ok::<(), Error>(())
    })
    .await?
}
