//! Actual rolling whole-write completion followed by a fresh same-batch poll.
use super::*;

fn trace_directory() -> Result<std::path::PathBuf> {
    let trace_dir = std::env::temp_dir().join(format!(
        "l2t-udp-trace-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos(),
    ));
    std::fs::create_dir(&trace_dir)?;
    Ok(trace_dir)
}

#[tokio::test]
async fn forward_record_trace_links_native_data_on_both_udp_endpoints() -> Result {
    record_trace_fixture(reverse_trace::Direction::Forward, false).await
}

#[tokio::test]
async fn both_record_traces_link_each_direction_on_the_same_udp_endpoints() -> Result {
    record_trace_fixture(reverse_trace::Direction::Both, false).await
}

#[tokio::test]
async fn mixed_record_traces_link_actual_socket_members_to_native_writes() -> Result {
    record_trace_fixture(reverse_trace::Direction::Both, true).await
}

fn mixed_trace_contracts(kind: cover::Appearance) -> Result<[CommonTransactionContract; 2]> {
    let original = values(kind, rolling::wire::SourceWire::Exact)?[3];
    let desc = original.descriptor();
    let c::Profile::Rolling { config, .. } = desc.profile() else {
        return Err("missing Packed fixture".into());
    };
    let direction =
        |d: rolling_records::DirectionConfig, overhead| l2tunnel::striped_records::Direction {
            packing: d.packing,
            receiver: d.receiver,
            native_policy: d.native_policy,
            profile: l2tunnel_fec::mixed_datagram::Profile {
                data_cells: 4,
                parity_cells: 1,
                max_body_bytes: 1000,
                max_wire_bytes: 1000,
            },
            first: l2tunnel_fec::GenerationId(0),
            source_limit: 32,
            expanded_limit: 128 << 10,
            hold_micros: 500,
            timing: l2tunnel_fec::striped_group::schedule::RecoveryTiming {
                gap_delay: 1000,
                gap_repeat: 35000,
                ack_delay: 1000,
                quiet: 70000,
            },
            overhead_bytes: overhead,
            stream: 17,
            codec_stage_micros: d.codec_stage_micros,
            native_stall_micros: config.native_stall_micros,
        };
    let policy = c::Profile::Striped {
        forward: direction(config.forward, config.geometry.forward_overhead_bytes),
        reverse: direction(config.reverse, config.geometry.reverse_overhead_bytes),
    };
    let mixed = c::Descriptor::new(
        desc.path_mtu(),
        desc.duplex(),
        *desc.direction(mg::Role::Client).common(),
        *desc.direction(mg::Role::Server).common(),
        policy,
    )?;
    contracts_with_catalog(kind, Catalog::new(mixed, &[mixed])?, 16)
}

async fn record_trace_fixture(direction: reverse_trace::Direction, mixed: bool) -> Result {
    let kind = cover::Appearance::QuicLike;
    let contracts = if mixed {
        mixed_trace_contracts(kind)?
    } else {
        selected(kind, rolling::wire::SourceWire::Exact, 3)?.0
    };
    let mut fixture = Fixture::from_contracts(kind, contracts).await?;
    let dir = trace_directory()?;
    for endpoint in &mut fixture.endpoints {
        let driver = &mut endpoint.driver;
        let trace = reverse_trace::Trace::in_directory(
            &dir,
            driver.info.role == security::Role::Responder,
            direction,
            driver.origin,
        )?;
        driver
            .common
            .as_deref_mut()
            .ok_or("common runtime")?
            .reverse_trace = Some(trace);
    }
    let packets = [frame(40_000, 95), frame(40_001, 123)];
    let flows = if direction == reverse_trace::Direction::Both {
        2
    } else {
        1
    };
    let origin = fixture.endpoints[0].driver.origin;
    for (side, packet) in packets.iter().enumerate().take(flows) {
        fixture.admit(side, packet).await?;
    }
    let before = clock(origin, Instant::now())?;
    let mut delivered = [false; 2];
    let mut readback = [0; 1501];
    for _ in 0..40 {
        fixture.turn().await?;
        for side in 0..flows {
            if !delivered[side] {
                match fixture.endpoints[1 - side].host.recv(&mut readback) {
                    Ok(n) => {
                        assert_eq!(packets[side], readback[..n]);
                        delivered[side] = true;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
        if delivered[..flows].iter().all(|seen| *seen) {
            break;
        }
    }
    assert!(delivered[..flows].iter().all(|seen| *seen));
    let after = clock(origin, Instant::now())?;
    drop(fixture);
    let pid = std::process::id();
    for (side, (prefix, from, to)) in [("forward-records", "a", "b"), ("records", "b", "a")]
        .into_iter()
        .take(flows)
        .enumerate()
    {
        let read = |role| std::fs::read_to_string(dir.join(format!("{prefix}-{role}-{pid}.tsv")));
        let sent = read(from)?;
        let received = read(to)?;
        let tx: Vec<_> = sent
            .lines()
            .skip(2)
            .map(|line| line.split('\t').collect::<Vec<_>>())
            .collect();
        let rx: Vec<_> = received
            .lines()
            .skip(2)
            .map(|line| line.split('\t').collect::<Vec<_>>())
            .collect();
        for event in ["read_done", "packed", "unit", "selected", "socket"] {
            assert!(tx.iter().any(|row| row[3] == event));
            assert!(!rx.iter().any(|row| row[3] == event));
        }
        for event in ["opened", "native_ready", "tun"] {
            assert!(rx.iter().any(|row| row[3] == event));
            assert!(!tx.iter().any(|row| row[3] == event));
        }
        let hash = ring::digest::digest(&ring::digest::SHA256, &packets[side])
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert!(tx.iter().any(|row| row[3] == "read_done" && row[4] == hash));
        let ready = rx
            .iter()
            .find(|row| row[3] == "native_ready" && row[6] == hash)
            .ok_or("missing prepared packet")?;
        if mixed {
            let seals: Vec<_> = tx.iter().filter(|r| r[3] == "mixed_seal").collect();
            let [seal] = seals.as_slice() else {
                return Err("expected one local seal decision".into());
            };
            let first = tx
                .iter()
                .find(|r| {
                    r[1..3] == seal[1..3]
                        && r.get(3..8) == Some(&["mixed_member", "fresh", "0", "0", "split"])
                })
                .ok_or("seal was not joined to its first fresh physical member")?;
            assert_eq!(first.len(), 10);
            assert!(tx.iter().any(|r| r[1..3] == seal[1..3] && r[3] == "socket"));
            assert_eq!(seal.len(), 10);
            assert!(seal[4].parse::<u64>()? >= seal[5].parse::<u64>()?);
            assert_eq!(seal[6..8], ["0", "1"]);
            assert_eq!(seal[8], first[8]);
            assert_eq!(seal[9], "1");
            let member = tx
                .iter()
                .find(|row| {
                    row[3] == "mixed_member"
                        && row[4] == "fresh"
                        && row[5] == "0"
                        && row[7] == "split"
                        && row[9] == "1"
                        && rx.iter().any(|r| r[1..3] == row[1..3] && r[3] == "opened")
                })
                .ok_or("missing opened mixed group member")?;
            assert!(
                tx.iter()
                    .any(|r| r[1..3] == member[1..3] && r[3] == "unit" && r[4..6] == ready[4..6])
            );
            assert!(
                tx.iter()
                    .any(|r| r[1..3] == member[1..3] && r[3] == "socket")
            );
            assert!(
                tx.iter()
                    .any(|r| r[1] == ready[1] && r[3] == "packed" && r[4..6] == ready[4..6])
            );
        }
        assert!((before..=after).contains(&ready[0].parse::<u64>()?));
        assert!(
            rx.iter()
                .any(|row| row[3] == "tun" && row[1] == ready[1] && row[4..6] == ready[4..6])
        );
        for trace in [&sent, &received] {
            assert!(
                trace
                    .lines()
                    .nth(1)
                    .is_some_and(|l| l.starts_with("limits\t") && l.ends_with("\t0"))
            );
        }
    }
    for role in ["a", "b"] {
        assert!(
            dir.join(format!("udp-send-yields-{role}-{pid}.tsv"))
                .is_file()
        );
    }
    assert_eq!(std::fs::read_dir(&dir)?.count(), 2 * flows + 2);
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[tokio::test]
async fn long_udp_send_turn_yields_to_unconsumed_input_and_resumes() -> Result {
    let kind = cover::Appearance::QuicLike;
    let mut fixture = Fixture::new(kind)?.await?;
    for port in 40_000..40_003 {
        fixture.admit(0, &frame(port, 95)).await?;
    }
    let now = fixture.now + 1000;
    let [mut sender, peer] = fixture.endpoints;
    sender.driver.progress_common(now)?;
    let at = sender.driver.origin + duration(now);
    let later = at + sender.driver.config.work.receive_interval;
    let before = sender.driver.counters.socket_accepted_packets;
    let trace_dir = trace_directory()?;
    sender
        .driver
        .common
        .as_deref_mut()
        .ok_or("common runtime")?
        .reverse_trace = Some(reverse_trace::Trace::in_directory(
        &trace_dir,
        false,
        reverse_trace::Direction::Reverse,
        sender.driver.origin,
    )?);
    let quota = sender.driver.ingress.left;
    let incoming = b"queued reverse datagram";
    peer.socket.send(incoming).await?;
    let mut first = true;
    sender.driver.send_sampled(&sender.socket, now, at, || {
        if std::mem::take(&mut first) {
            at
        } else {
            later
        }
    })?;
    assert_eq!(sender.driver.counters.socket_accepted_packets - before, 1);
    assert_eq!(sender.driver.ingress.left, quota);
    assert!(sender.driver.ingress.observed_udp);
    let mut owner = carrier::IoOwner::from(sender.socket);
    let work = SelectedWake {
        at: later,
        work_ready: true,
    };
    let event = next_io(
        &mut owner,
        &mut sender.device,
        Interest::READABLE,
        false,
        sender.driver.ingress.interest(),
        work.wait(None),
        true,
    )
    .await?;
    assert!(matches!(event, IoEvent::Udp));
    let mut bytes = [0; 128];
    let (length, _, _) = owner
        .receive_after_selection(&mut bytes, &mut sender.driver.ingress.observed_udp)
        .await?;
    assert_eq!(&bytes[..length], incoming);
    let error = owner
        .receive_after_selection(&mut bytes, &mut sender.driver.ingress.observed_udp)
        .await
        .err()
        .ok_or("datagram consumed twice")?;
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert!(!sender.driver.ingress.observed_udp);
    let carrier::IoOwner::Udp(socket) = &owner else {
        return Err("expected UDP".into());
    };
    let next = clock(sender.driver.origin, later)?;
    let mut sample = later;
    let interval = sender.driver.config.work.receive_interval;
    sender.driver.send_sampled(socket, next, later, || {
        let current = sample;
        sample += interval;
        current
    })?;
    assert!(sender.driver.counters.socket_accepted_packets - before >= 3);
    drop(
        sender
            .driver
            .common
            .as_deref_mut()
            .ok_or("common runtime")?
            .reverse_trace
            .take(),
    );
    let pid = std::process::id();
    let yields = std::fs::read_to_string(trace_dir.join(format!("udp-send-yields-a-{pid}.tsv")))?;
    let rows: Vec<_> = yields.lines().skip(3).collect();
    assert_eq!(rows, [format!("{next}\t1\t{}", interval.as_micros())]);
    let records = std::fs::read_to_string(trace_dir.join(format!("records-a-{pid}.tsv")))?;
    assert_eq!(records.lines().count(), 2);
    std::fs::remove_dir_all(trace_dir)?;
    Ok(())
}

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
            let last_refill = endpoint.driver.bucket.last;
            let discarded = endpoint.driver.bucket.discarded;
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
            let bucket = &endpoint.driver.bucket;
            assert_eq!(Some(&bucket.last), samples.last());
            // This sealed source already paid its wire cost. A later physical
            // poll earns elapsed credit and may discard excess at the burst cap.
            let earned = u128::from(bucket.last - last_refill) * u128::from(bucket.rate);
            assert_eq!(
                bucket.tokens + (bucket.discarded - discarded),
                debit + earned
            );
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
