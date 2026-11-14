//! Actual original-socket generic Driver integration with real native writes.
//!
//! Driver-method cases inject finite protocol time after real Noise/member setup;
//! they do not claim privileged TAP/netem qualification or other record profiles.

use super::*;
use l2tunnel::swift_configuration::{Catalog, Configuration as C, Descriptor, EnvelopeDigest};
use l2tunnel_management::{messages, transaction};

fn contracts(kind: cover::Appearance) -> Result<[TransactionContract; 2]> {
    let mut base = config(kind);
    base.lifetime.lease = Duration::from_secs(60);
    base.report_interval = None;
    let mut forward = base.send;
    forward.records.codec.repair_numerator = 0;
    let mut reverse = forward;
    reverse.records.channels = 3;
    reverse.bytes_per_second = 750_000;
    let initial = Descriptor::new(base.path_mtu, forward, reverse)?;
    let mut next_forward = forward;
    next_forward.records.channels = 4;
    next_forward.records.codec.datagram_bytes = 640;
    let mut next_reverse = reverse;
    next_reverse.records.channels = 1;
    next_reverse.records.codec.window = 7;
    let target = Descriptor::new(base.path_mtu, next_forward, next_reverse)?;
    let catalog = Catalog::new(initial, &[initial, target])?;
    let make = |role| -> Result<TransactionContract> {
        let mut config = base;
        (config.send, config.receive) = if role == security::Role::Initiator {
            (forward, reverse)
        } else {
            (reverse, forward)
        };
        let selected = messages::Settings {
            delivery: delivery::Settings {
                wire_overhead: config.control.wire_overhead + mg::control_streams::HEADER_BYTES,
                ..config.control
            },
            path_mtu: config.path_mtu,
            max_message_bytes: 4096,
            max_outbound_messages: 4,
            max_outbound_bytes: 131_072,
            max_fragments: 32,
            max_reassembly_bytes: 16_384,
            max_incomplete_messages: 2,
            message_lifetime: Duration::from_secs(5),
            work_per_call: 8,
        };
        config.streams = Some(control_owner::Settings {
            streams: [selected; 3],
        });
        Ok(TransactionContract::new(
            security::ConfigDigest([3; 32]),
            role,
            config,
            appearance(kind, role == security::Role::Initiator)?,
            false,
            EnvelopeDigest::new([0x71; 32]),
            catalog.clone(),
            TransactionSettings {
                protocol: transaction::Settings {
                    retry_ms: 10,
                    phase_timeout_ms: 1000,
                    reconcile_timeout_ms: 2000,
                },
                max_operation_ms: 3000,
                retained_bytes: 64 << 20,
            },
        )?)
    };
    Ok([
        make(security::Role::Initiator)?,
        make(security::Role::Responder)?,
    ])
}

fn frame(port: u16, number: u8) -> Vec<u8> {
    let mut packet = vec![0; 46];
    packet[..12].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    packet[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    let ip = &mut packet[14..];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&32_u16.to_be_bytes());
    ip[4..6].copy_from_slice(&u16::from(number).to_be_bytes());
    ip[6] = 0x40;
    ip[8] = 64;
    ip[9] = 17;
    ip[12..20].copy_from_slice(&[198, 18, 0, 1, 198, 18, 0, 2]);
    let sum: u32 = ip[..20]
        .chunks_exact(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], pair[1]])))
        .sum();
    let sum = (sum & 0xffff) + (sum >> 16);
    let sum = (sum & 0xffff) + (sum >> 16);
    ip[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    ip[20..22].copy_from_slice(&port.to_be_bytes());
    ip[22..24].copy_from_slice(&24_500_u16.to_be_bytes());
    ip[24..26].copy_from_slice(&12_u16.to_be_bytes());
    ip[28..32].fill(number);
    packet
}

fn channel_packet(channel: usize, channels: usize, number: u8) -> Result<Vec<u8>> {
    let port = (40_000..41_024_u16)
        .find(|port| swift::flow::classify_ethernet(&frame(*port, number), channels) == channel)
        .ok_or("generic fixture lacks actual classified channel")?;
    Ok(frame(port, number))
}

struct Endpoint {
    socket: tokio::net::UdpSocket,
    driver: Box<Driver>,
    device: AsyncFd<Device>,
    host: UnixDatagram,
    original: (SocketAddr, SocketAddr),
}

struct Fixture {
    endpoints: [Endpoint; 2],
    now: u64,
}

impl Fixture {
    async fn new(kind: cover::Appearance) -> Result<Self> {
        let [client, server] = contracts(kind)?;
        let (a, b) = parts_pair(kind).await?;
        let setup_end = a.deadline.max(b.deadline);
        let origin = Instant::now();
        let make = |parts: member::Parts, contract| -> Result<Endpoint> {
            let original = (parts.socket.local_addr()?, parts.socket.peer_addr()?);
            let (socket, mut driver) = Driver::new_transaction(parts, contract, origin)?;
            driver.bucket.tokens = 0;
            assert!(driver.tail(setup_end)?.is_none());
            let (native, host) = UnixDatagram::pair()?;
            native.set_nonblocking(true)?;
            host.set_nonblocking(true)?;
            let device = AsyncFd::with_interest(
                Device {
                    socket: native,
                    blocked: false,
                    wouldblock: None,
                },
                Interest::READABLE.add(Interest::WRITABLE),
            )?;
            Ok(Endpoint {
                socket,
                driver: Box::new(driver),
                device,
                host,
                original,
            })
        };
        let endpoints = [make(a, client)?, make(b, server)?];
        // Retire only the actual original setup tails, then clear their finite
        // already-queued datagrams before exact new-emission accounting starts.
        for _ in 0..2 {
            tokio::task::yield_now().await;
            for endpoint in &endpoints {
                let mut input = [0; 1501];
                let mut empty = false;
                for _ in 0..128 {
                    match endpoint.socket.try_recv(&mut input) {
                        Ok(_) => {}
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            empty = true;
                            break;
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                assert!(empty, "bounded original setup drain");
            }
        }
        Ok(Self {
            endpoints,
            now: clock(origin, setup_end)? + 20_000,
        })
    }

    async fn turn(&mut self) -> Result {
        self.turn_with_held_native(None).await
    }

    async fn turn_with_held_native(&mut self, held: Option<usize>) -> Result {
        self.now = self.now.checked_add(1000).ok_or("fixture time exhausted")?;
        let now = self.now;
        let mut sent = [0; 2];
        for (side, endpoint) in self.endpoints.iter_mut().enumerate() {
            assert!(endpoint.driver.check_expiry(now)?);
            endpoint.driver.admit_transaction(|| Ok(duration(now)))?;
            endpoint.driver.collect_native(now)?;
            endpoint.driver.progress_transaction(now)?;
            endpoint.driver.service_selected_control(now, None)?;
            endpoint.driver.submit_control(now)?;
            let before = endpoint.driver.counters.socket_accepted_packets;
            endpoint.driver.send(
                &endpoint.socket,
                now,
                endpoint.driver.origin + duration(now),
            )?;
            sent[side] = endpoint.driver.counters.socket_accepted_packets - before;
            assert_eq!(endpoint.driver.counters.socket_drops, 0);
        }
        for (side, count) in sent.into_iter().enumerate() {
            let target = &mut self.endpoints[1 - side];
            for _ in 0..count {
                let mut input = [0; 1501];
                let bytes =
                    tokio::time::timeout(Duration::from_secs(1), target.socket.recv(&mut input))
                        .await??;
                target.driver.receive_selected(
                    &input[..bytes],
                    now,
                    target.driver.origin + duration(now),
                    None,
                )?;
            }
        }
        for (side, endpoint) in self.endpoints.iter_mut().enumerate() {
            endpoint.driver.collect_native(now)?;
            if held != Some(side) {
                for _ in 0..endpoint.driver.config.work.native_write_batch {
                    if endpoint.driver.native.is_empty() {
                        break;
                    }
                    let mut ready = tokio::time::timeout(
                        Duration::from_secs(1),
                        endpoint.device.ready_mut(Interest::WRITABLE),
                    )
                    .await??;
                    if !endpoint.driver.write_native(&mut ready, || Ok(now))? {
                        break;
                    }
                }
            }
            endpoint.driver.progress_transaction(now)?;
            assert_eq!(
                (endpoint.socket.local_addr()?, endpoint.socket.peer_addr()?),
                endpoint.original
            );
        }
        Ok(())
    }

    async fn admit(&mut self, side: usize, packet: &[u8]) -> Result {
        let endpoint = &mut self.endpoints[side];
        assert!(endpoint.driver.can_admit_native()?);
        assert_eq!(endpoint.host.send(packet)?, packet.len());
        let mut ready = tokio::time::timeout(
            Duration::from_secs(1),
            endpoint.device.ready_mut(Interest::READABLE),
        )
        .await??;
        let mut input = [0; READ_BUFFER_BYTES];
        assert!(
            endpoint
                .driver
                .read_native(&mut ready, &mut input, || Ok(self.now))?
        );
        Ok(())
    }

    async fn exchange_all_channels(&mut self, number: u8) -> Result {
        let widths = self
            .endpoints
            .each_ref()
            .map(|endpoint| endpoint.driver.send.records.channels);
        let mut expected: [Vec<Vec<u8>>; 2] = [Vec::new(), Vec::new()];
        for side in 0..2 {
            for channel in 0..widths[side] {
                let packet =
                    channel_packet(channel, widths[side], number.wrapping_add(channel as u8))?;
                self.admit(side, &packet).await?;
                expected[1 - side].push(packet);
            }
        }
        let mut actual: [Vec<Vec<u8>>; 2] = [Vec::new(), Vec::new()];
        let mut done = false;
        for _ in 0..500 {
            self.turn().await?;
            for (side, received) in actual.iter_mut().enumerate() {
                let mut output = [0; 513];
                for _ in 0..16 {
                    match self.endpoints[side].host.recv(&mut output) {
                        Ok(bytes) => received.push(output[..bytes].to_vec()),
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) => return Err(error.into()),
                    }
                }
            }
            if actual.each_ref().map(Vec::len) == expected.each_ref().map(Vec::len)
                && self.endpoints.iter().all(|endpoint| {
                    endpoint
                        .driver
                        .owner
                        .engine(core::Epoch(endpoint.driver.source_scope.epoch.0))
                        .is_ok_and(|engine| engine.send_drained() && engine.receive_drained())
                })
            {
                done = true;
                break;
            }
        }
        assert!(
            done,
            "actual native/device and recovery drain did not complete"
        );
        for side in 0..2 {
            actual[side].sort();
            expected[side].sort();
            assert_eq!(actual[side], expected[side]);
            let driver = &self.endpoints[side].driver;
            assert!(driver.native.is_empty());
            assert!(
                driver.written.matches_extracted(
                    driver
                        .owner
                        .engine(core::Epoch(driver.feedback_scope.epoch.0))?,
                    NativeOrigin::new(
                        &driver.info,
                        driver.feedback_scope,
                        records::Direction::Receive
                    ),
                )
            );
        }
        Ok(())
    }

    async fn switch(&mut self, target: C) -> Result<core::Epoch> {
        let (reply, mut result) = oneshot::channel();
        self.endpoints[0]
            .driver
            .request_transaction(self.now, target, reply)?;
        let mut answer = None;
        let mut settled = false;
        for _ in 0..1500 {
            self.turn().await?;
            if answer.is_none() {
                match result.try_recv() {
                    Ok(value) => {
                        answer = Some(value.map_err(|error| {
                            io::Error::other(format!("actual switch result: {error:?}"))
                        })?)
                    }
                    Err(oneshot::error::TryRecvError::Empty) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            if answer.is_some()
                && self.endpoints.iter().all(|endpoint| {
                    let owner::DataOwner::Generic(state) = &endpoint.driver.owner else {
                        return false;
                    };
                    state.peer().operation().is_none()
                        && state.can_admit_data()
                        && endpoint.driver.records.additional_data().is_none()
                })
            {
                settled = true;
                break;
            }
        }
        assert!(settled, "actual final whole-message custody did not settle");
        answer.ok_or_else(|| "actual switch reply missing".into())
    }
}

#[test]
fn actual_generic_constructor_keeps_one_root_socket_and_h0_distinct_from_d0() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(Box::pin(async {
            for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
                let fixture = Fixture::new(kind).await?;
                for endpoint in &fixture.endpoints {
                    let driver = &endpoint.driver;
                    let owner::DataOwner::Generic(state) = &driver.owner else {
                        return Err("generic constructor selected legacy owner".into());
                    };
                    assert!(driver.owner.legacy().is_err());
                    assert_eq!(
                        driver.records.control_scope().configuration,
                        security::ConfigDigest([3; 32])
                    );
                    assert_ne!(
                        driver.records.active_data().configuration,
                        driver.records.control_scope().configuration
                    );
                    assert_eq!(
                        driver.records.active_data().configuration.0,
                        transaction::configuration_digest(state.current())?.0
                    );
                    assert_eq!(driver.source_scope, driver.feedback_scope);
                    assert_eq!(driver.records.next_number(Class::User).0, 0);
                    assert_eq!(driver.records.next_number(Class::Control).0, 0);
                    let snapshot = driver.snapshot_transaction(fixture.now, true)?;
                    assert_eq!(
                        snapshot.configuration.0,
                        snapshot.info.authenticated.configuration
                    );
                    assert_eq!(snapshot.physical_scope, driver.source_scope);
                    assert_eq!(snapshot.current, *state.current());
                    assert!(!snapshot.resource_preallocation_complete);
                    assert!(snapshot.storage.engine_bytes > 0);
                }
            }
            Ok(())
        }))
}

#[test]
fn actual_generic_constructor_rejects_wrong_role_cover_h0_and_original_deadline() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(Box::pin(async {
            for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
                for invalid in 0..4 {
                    let (a, _b) = parts_pair(kind).await?;
                    let [client, server] = contracts(kind)?;
                    let mut contract = if invalid == 0 { server } else { client };
                    if invalid == 1 {
                        let other = if kind == cover::Appearance::QuicLike {
                            cover::Appearance::MediaLike
                        } else {
                            cover::Appearance::QuicLike
                        };
                        contract = contracts(other)?[0].clone();
                    }
                    if invalid == 2 {
                        contract = TransactionContract::new(
                            security::ConfigDigest([4; 32]),
                            contract.role(),
                            contract.config(),
                            contract.cover(),
                            false,
                            contract.envelope(),
                            contract.catalog().clone(),
                            contract.settings(),
                        )?;
                    }
                    let now = if invalid == 3 {
                        a.deadline
                    } else {
                        Instant::now()
                    };
                    let error = Driver::new_transaction(a, contract, now)
                        .err()
                        .ok_or("invalid actual construction succeeded")?;
                    assert_eq!(
                        error.kind(),
                        if invalid == 3 {
                            io::ErrorKind::TimedOut
                        } else {
                            io::ErrorKind::InvalidInput
                        }
                    );
                }
            }
            Ok(())
        }))
}

#[test]
fn protected_original_udp_nonzero_native_fences_switch_2_3_to_4_1_and_back() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(Box::pin(async {
            for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
                let mut fixture = Fixture::new(kind).await?;
                fixture.exchange_all_channels(1).await?;
                let before = fixture
                    .endpoints
                    .each_ref()
                    .map(|endpoint| endpoint.driver.records.next_number(Class::User));
                let contract = fixture.endpoints[0]
                    .driver
                    .generic
                    .as_ref()
                    .ok_or("missing actual contract")?
                    .contract
                    .clone();
                let target = contract
                    .catalog()
                    .descriptors()
                    .iter()
                    .copied()
                    .find(|value| *value != contract.catalog().initial())
                    .ok_or("missing exact target")?;
                let target = C::new(contract.envelope(), target)?;
                assert_eq!(
                    fixture.switch(target).await?,
                    core::Epoch(contract.config().data_epoch.0 + 1)
                );
                assert_eq!(
                    fixture.endpoints.each_ref().map(|endpoint| endpoint
                        .driver
                        .send
                        .records
                        .channels),
                    [4, 1]
                );
                assert_eq!(
                    fixture.endpoints.each_ref().map(|endpoint| endpoint
                        .driver
                        .receive
                        .records
                        .channels),
                    [1, 4]
                );
                fixture.exchange_all_channels(40).await?;
                assert_eq!(
                    fixture.switch(contract.initial()).await?,
                    core::Epoch(contract.config().data_epoch.0 + 2)
                );
                fixture.exchange_all_channels(90).await?;
                for (side, endpoint) in fixture.endpoints.iter().enumerate() {
                    let driver = &endpoint.driver;
                    assert!(driver.records.next_number(Class::User).0 > before[side].0);
                    assert!(driver.records.next_number(Class::Control).0 > 0);
                    assert!(driver.live.last_pong_micros.is_some());
                    assert_eq!(driver.counters.native_read, if side == 0 { 8 } else { 7 });
                    assert_eq!(
                        driver.counters.native_written,
                        if side == 0 { 7 } else { 8 }
                    );
                    assert_eq!(
                        driver.counters.native_written,
                        driver.performance.counters.native_write_batch_packets
                    );
                    assert!(driver.retired_send.is_none() && driver.retired_receive.is_none());
                    assert!(driver.target.is_none() && driver.records.additional_data().is_none());
                    assert_eq!(driver.counters.socket_drops, 0);
                }
            }
            Ok(())
        }))
}

#[test]
fn public_generic_run_publishes_actual_readiness_and_cancels_on_original_ports() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(Box::pin(async {
            for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
                let (a, _b) = parts_pair(kind).await?;
                let original = (a.socket.local_addr()?, a.socket.peer_addr()?);
                let [contract, _] = contracts(kind)?;
                let (native, _host) = UnixDatagram::pair()?;
                native.set_nonblocking(true)?;
                let (cancel, cancelled) = oneshot::channel();
                let mut cancel = Some(cancel);
                let mut snapshots = Vec::new();
                let stopped = run_transaction(
                    Device {
                        socket: native,
                        blocked: false,
                        wouldblock: None,
                    },
                    a,
                    contract,
                    None,
                    async move {
                        let _ = cancelled.await;
                    },
                    |snapshot| {
                        snapshots.push(snapshot.clone());
                        if snapshot.running
                            && let Some(cancel) = cancel.take()
                        {
                            let _ = cancel.send(());
                        }
                    },
                )
                .await?;
                assert_eq!(stopped.reason, StopReason::Cancelled);
                assert!(snapshots.first().is_some_and(|snapshot| snapshot.running));
                assert!(snapshots.last().is_some_and(|snapshot| !snapshot.running));
                assert!(!stopped.snapshot.running);
                assert_eq!(
                    (
                        stopped.snapshot.info.local_addr,
                        stopped.snapshot.info.peer_addr
                    ),
                    original
                );
                assert_ne!(
                    stopped.snapshot.physical_scope.configuration,
                    stopped.snapshot.configuration
                );
                assert!(!stopped.snapshot.resource_preallocation_complete);
            }
            Ok(())
        }))
}

/// Keep genuine old native custody while two actual leased peers exchange the
/// original PREPARE/READY. The fixture withholds physical output service, leaving
/// the real socket's readiness untouched; no fence or device result is fabricated.
async fn native_at_original_operation_cap(
    kind: cover::Appearance,
) -> Result<(Fixture, Vec<u8>, u64)> {
    let mut fixture = Fixture::new(kind).await?;
    let packet = channel_packet(0, fixture.endpoints[1].driver.send.records.channels, 117)?;
    fixture.admit(1, &packet).await?;
    fixture.now = fixture
        .now
        .checked_add(1_000)
        .ok_or("fixture time exhausted")?;
    let now = fixture.now;
    {
        let [local, remote] = &mut fixture.endpoints;
        remote.driver.progress_transaction(now)?;
        remote.socket.writable().await?;
        assert!(remote.driver.send_transaction_user(&remote.socket, now)?);
        let mut input = [0; 1501];
        let length = tokio::time::timeout(Duration::from_secs(1), local.socket.recv(&mut input))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "operation-cap fixture original UDP User receive",
                )
            })??;
        local.driver.receive_selected(
            &input[..length],
            now,
            local.driver.origin + duration(now),
            None,
        )?;
        local.driver.collect_native(now)?;
        assert_eq!(local.driver.native.len(), 1);
        assert_eq!(
            local
                .driver
                .native
                .front()
                .ok_or("missing real native packet")?
                .bytes(),
            packet
        );
        let contract = &local
            .driver
            .generic
            .as_ref()
            .ok_or("missing generic runtime")?
            .contract;
        let target = contract
            .catalog()
            .descriptors()
            .iter()
            .copied()
            .find(|value| *value != contract.catalog().initial())
            .ok_or("missing target")?;
        let target = C::new(contract.envelope(), target)?;
        // A real explicit cap within the negotiated maximum, shorter than the
        // unchanged native stall and phase deadlines, isolates operation expiry.
        let cap = transaction::Tick(
            u64::try_from(duration(now).as_millis())?
                .checked_add(250)
                .ok_or("cap overflow")?,
        );
        let owner::DataOwner::Generic(state) = &mut local.driver.owner else {
            return Err("missing actual generic State".into());
        };
        assert_eq!(
            state.propose(&mut local.driver.control, target, cap, || Ok(duration(now)))?,
            transactions::Progress::Advanced
        );
        assert_eq!(
            state
                .peer()
                .operation()
                .ok_or("missing actual operation")?
                .expires(),
            cap
        );
    }
    let mut witnessed = false;
    for _ in 0..100 {
        fixture.turn_with_held_native(Some(0)).await?;
        let driver = &fixture.endpoints[0].driver;
        let owner::DataOwner::Generic(state) = &driver.owner else {
            return Err("missing actual generic State".into());
        };
        if let Some(peer) = state.peer().peer_fence() {
            let front = driver
                .native
                .front()
                .ok_or("blocked native custody disappeared")?;
            assert_eq!(front.bytes(), packet);
            assert!(
                front.metadata().identity.record.0
                    < peer.counts()[front.metadata().identity.channel.index()]
            );
            assert_eq!(driver.counters.native_written, 0);
            witnessed = true;
            break;
        }
    }
    assert!(
        witnessed,
        "actual PREPARE/READY never supplied the independent peer fence"
    );
    let driver = &fixture.endpoints[0].driver;
    let owner::DataOwner::Generic(state) = &driver.owner else {
        return Err("missing actual generic State".into());
    };
    let operation = state
        .peer()
        .operation()
        .ok_or("actual operation lost original cap")?;
    let cap = operation
        .expires()
        .0
        .checked_mul(1_000)
        .ok_or("cap conversion overflow")?;
    assert!(fixture.now < cap);
    let since = driver
        .native
        .front()
        .ok_or("missing blocked packet")?
        .since();
    assert!(cap < add(since, driver.config.native.stall_timeout)?);
    assert!(cap < driver.lease);
    Ok((fixture, packet, cap))
}

#[test]
fn generic_original_operation_cap_guards_ready_native_write_at_exact_boundary() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(Box::pin(async {
            for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
                for offset in [-1_i64, 0, 1] {
                    let (mut fixture, packet, cap) = native_at_original_operation_cap(kind).await?;
                    let endpoint = &mut fixture.endpoints[0];
                    assert!(!endpoint.device.get_ref().blocked);
                    let before = endpoint.driver.written.boundary();
                    let front = endpoint
                        .driver
                        .native
                        .front()
                        .ok_or("missing original native custody")?;
                    let identity = front.metadata().identity;
                    let origin = front.metadata().origin;
                    let since = front.since();
                    let capacity = endpoint.driver.native.capacity_bytes();
                    let at = cap
                        .checked_add_signed(offset)
                        .ok_or("boundary time overflow")?;
                    let mut ready = tokio::time::timeout(
                        Duration::from_secs(1),
                        endpoint.device.ready_mut(Interest::WRITABLE),
                    )
                    .await
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "operation-cap boundary native writable readiness",
                        )
                    })??;
                    let result = endpoint.driver.write_native(&mut ready, || Ok(at));
                    let mut output = [0; 513];
                    if offset < 0 {
                        assert!(result?);
                        let length = endpoint.host.recv(&mut output)?;
                        assert_eq!(&output[..length], packet);
                        assert!(endpoint.driver.native.is_empty());
                        let after = endpoint.driver.written.boundary();
                        assert_eq!(
                            after.counts[identity.channel.index()],
                            before.counts[identity.channel.index()] + 1
                        );
                        assert_eq!(endpoint.driver.counters.native_written, 1);
                        assert_eq!(endpoint.driver.terminal, None);
                    } else {
                        let error = result
                            .err()
                            .ok_or("native write accepted an expired original operation")?;
                        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
                        assert_eq!(endpoint.driver.terminal, Some(StopReason::PolicyTimeout));
                        let retained = endpoint
                            .driver
                            .native
                            .front()
                            .ok_or("expired write consumed native custody")?;
                        assert_eq!(retained.metadata().identity, identity);
                        assert_eq!(retained.metadata().origin, origin);
                        assert_eq!(retained.since(), since);
                        assert_eq!(retained.bytes(), packet);
                        assert_eq!(endpoint.driver.written.boundary(), before);
                        assert_eq!(endpoint.driver.counters.native_written, 0);
                    }
                    assert_eq!(endpoint.driver.native.capacity_bytes(), capacity);
                    assert_eq!(
                        endpoint
                            .host
                            .recv(&mut output)
                            .err()
                            .map(|error| error.kind()),
                        Some(io::ErrorKind::WouldBlock)
                    );
                    let owner::DataOwner::Generic(state) = &endpoint.driver.owner else {
                        return Err("missing actual generic State".into());
                    };
                    assert_eq!(state.epoch(), core::Epoch(origin.scope.epoch.0));
                    assert_ne!(state.peer().phase(), transaction::Phase::Idle);
                    assert_eq!(endpoint.driver.records.active_data(), origin.scope);
                }
            }
            Ok(())
        }))
}

#[test]
fn generic_late_native_success_keeps_irreversible_facts_but_fails_original_cap() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(Box::pin(async {
            for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
                let (mut fixture, packet, cap) = native_at_original_operation_cap(kind).await?;
                let endpoint = &mut fixture.endpoints[0];
                assert!(!endpoint.device.get_ref().blocked);
                let before = endpoint.driver.written.boundary();
                let identity = endpoint
                    .driver
                    .native
                    .front()
                    .ok_or("missing original native custody")?
                    .metadata()
                    .identity;
                let mut ready = tokio::time::timeout(
                    Duration::from_secs(1),
                    endpoint.device.ready_mut(Interest::WRITABLE),
                )
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "late-success operation-cap native writable readiness",
                    )
                })??;
                let mut samples = 0;
                let result = endpoint.driver.write_native(&mut ready, || {
                    samples += 1;
                    match samples {
                        1 => Ok(cap - 1),
                        2 => Ok(cap),
                        _ => Err(io::Error::other("unexpected clock sample")),
                    }
                });
                assert_eq!(samples, 2);
                let error = result
                    .err()
                    .ok_or("late native success erased the original operation cap")?;
                assert_eq!(error.kind(), io::ErrorKind::TimedOut);
                assert_eq!(endpoint.driver.terminal, Some(StopReason::PolicyTimeout));
                assert!(endpoint.driver.native.is_empty());
                let after = endpoint.driver.written.boundary();
                assert_eq!(
                    after.counts[identity.channel.index()],
                    before.counts[identity.channel.index()] + 1
                );
                assert_eq!(endpoint.driver.counters.native_written, 1);
                assert_eq!(
                    endpoint
                        .driver
                        .performance
                        .counters
                        .native_write_batch_packets,
                    1
                );
                let mut output = [0; 513];
                let length = endpoint.host.recv(&mut output)?;
                assert_eq!(&output[..length], packet);
                assert!(!endpoint.driver.write_native(&mut ready, || Ok(cap + 1))?);
                assert_eq!(endpoint.driver.counters.native_written, 1);
                assert_eq!(
                    endpoint
                        .host
                        .recv(&mut output)
                        .err()
                        .map(|error| error.kind()),
                    Some(io::ErrorKind::WouldBlock)
                );
                let owner::DataOwner::Generic(state) = &endpoint.driver.owner else {
                    return Err("missing actual generic State".into());
                };
                assert_eq!(state.epoch(), core::Epoch(before.origin.scope.epoch.0));
                assert_ne!(state.peer().phase(), transaction::Phase::Idle);
                assert_eq!(endpoint.driver.records.active_data(), before.origin.scope);
            }
            Ok(())
        }))
}
