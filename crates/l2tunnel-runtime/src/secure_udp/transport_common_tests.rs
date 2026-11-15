//! Real protected original-UDP and Unix native custody across three record families.
use super::super::common_engines::tests as catalog_fixture;
use super::*;
use l2tunnel::record_configuration::{Catalog, Configuration as C};
fn udp_values(kind: cover::Appearance) -> Result<[C; 3]> {
    use l2tunnel::record_configuration as c;
    let values = catalog_fixture::values().map_err(|e| io::Error::other(e.to_string()))?;
    let overhead = config(kind).control.wire_overhead;
    let mut result = values;
    for (output, value) in result.iter_mut().zip(values) {
        let descriptor = value.descriptor();
        let profile = match *descriptor.profile() {
            c::Profile::Swift { forward, reverse } => c::Profile::Swift { forward, reverse },
            c::Profile::Aligned {
                mut forward,
                mut reverse,
            } => {
                forward.recovery.outer_overhead_bytes = overhead;
                reverse.recovery.outer_overhead_bytes = overhead;
                c::Profile::Aligned { forward, reverse }
            }
            c::Profile::Packed {
                mut forward,
                mut reverse,
            } => {
                forward.base.recovery.outer_overhead_bytes = overhead;
                reverse.base.recovery.outer_overhead_bytes = overhead;
                c::Profile::Packed { forward, reverse }
            }
            c::Profile::Rolling { .. } => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "three-family runtime fixture does not install rolling work or carrier custody",
                )
                .into());
            }
        };
        *output = C::new(
            value.envelope(),
            c::Descriptor::new(
                descriptor.path_mtu(),
                descriptor.duplex(),
                *descriptor.direction(mg::Role::Client).common(),
                *descriptor.direction(mg::Role::Server).common(),
                profile,
            )?,
        )?;
    }
    Ok(result)
}
fn contracts(kind: cover::Appearance) -> Result<[CommonTransactionContract; 2]> {
    let values = udp_values(kind)?;
    let descriptors = values.map(|value| *value.descriptor());
    let catalog = Catalog::new(descriptors[0], &descriptors)?;
    contracts_with_catalog(kind, catalog, 16)
}
fn contracts_with_catalog(
    kind: cover::Appearance,
    catalog: Catalog,
    work: usize,
) -> Result<[CommonTransactionContract; 2]> {
    contracts_with_catalog_and_work(kind, catalog, work, None)
}
fn contracts_with_catalog_and_work(
    kind: cover::Appearance,
    catalog: Catalog,
    work: usize,
    rolling_work: Option<l2tunnel_fec::rolling::WorkBudget>,
) -> Result<[CommonTransactionContract; 2]> {
    let mut base = config(kind);
    base.rolling_work = rolling_work;
    base.work.native_write_batch = work;
    base.report_interval = None;
    base.lifetime.lease = Duration::from_secs(60);
    base.native.stall_timeout = Duration::from_secs(10);
    let selected = mg::messages::Settings {
        delivery: delivery::Settings {
            wire_overhead: base.control.wire_overhead + streams::HEADER_BYTES,
            ..base.control
        },
        path_mtu: base.path_mtu,
        max_message_bytes: 4096,
        max_outbound_messages: 4,
        max_outbound_bytes: 131072,
        max_fragments: 32,
        max_reassembly_bytes: 16384,
        max_incomplete_messages: 2,
        message_lifetime: Duration::from_secs(5),
        work_per_call: 8,
    };
    base.streams = Some(control_owner::Settings {
        streams: [selected; 3],
    });
    let make = |role| -> Result<CommonTransactionContract> {
        Ok(CommonTransactionContract::new(
            security::ConfigDigest([3; 32]),
            role,
            base,
            appearance(kind, role == security::Role::Initiator)?,
            false,
            l2tunnel::record_configuration::EnvelopeDigest::new([0x39; 32]),
            catalog.clone(),
            TransactionSettings {
                protocol: transaction::Settings {
                    retry_ms: 10,
                    phase_timeout_ms: 1000,
                    reconcile_timeout_ms: 2000,
                },
                max_operation_ms: 3000,
                retained_bytes: 256 << 20,
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
        Self::from_contracts(kind, contracts(kind)?).await
    }

    async fn from_contracts(
        kind: cover::Appearance,
        contracts: [CommonTransactionContract; 2],
    ) -> Result<Self> {
        let [client, server] = contracts;
        let (a, b) = parts_pair(kind).await?;
        let setup_end = a.deadline.max(b.deadline);
        let origin = Instant::now();
        let make = |parts: member::Parts, contract| -> Result<Endpoint> {
            let original = (parts.socket.local_addr()?, parts.socket.peer_addr()?);
            let (socket, mut driver) = Driver::new_common(parts, contract, origin)?;
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
            endpoint.driver.admit_common(|| Ok(duration(now)))?;
            endpoint.driver.collect_native(now)?;
            endpoint.driver.progress_common(now)?;
            endpoint.driver.service_common_rolling(now)?;
            endpoint.driver.report_transaction_completion(
                || Ok(now),
                |driver, at| {
                    driver.snapshot_common(at, true)?;
                    Ok(())
                },
            )?;
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
            endpoint.driver.progress_common(now)?;
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
        let width = |side: usize| -> Result<usize> {
            let driver = &self.endpoints[side].driver;
            Ok(usize::from(
                driver
                    .common_state()?
                    .current()
                    .descriptor()
                    .direction(common_contract::mg_role(driver.info.role))
                    .channels(),
            ))
        };
        let widths = [width(0)?, width(1)?];
        let mut expected: [Vec<Vec<u8>>; 2] = [Vec::new(), Vec::new()];
        for side in 0..2 {
            for channel in 0..widths[side] {
                let packet = frame(40_000 + channel as u16, number.wrapping_add(channel as u8));
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
                    endpoint.driver.common_state().is_ok_and(|state| {
                        state
                            .engine(state.epoch())
                            .is_ok_and(|engine| engine.drained().unwrap_or(false))
                    })
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
            let counts = driver
                .common_state()?
                .engine(driver.common_state()?.epoch())?
                .native_counts()?;
            assert_eq!(counts.prepared, counts.committed);
            assert!(counts.committed.iter().any(|value| *value > 0));
        }
        Ok(())
    }

    async fn switch(&mut self, target: C) -> Result<core::Epoch> {
        let (reply, mut result) = oneshot::channel();
        self.endpoints[0]
            .driver
            .request_common(self.now, target, reply)?;
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
                    let owner::DataOwner::Common(state) = &endpoint.driver.owner else {
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
fn original_udp_nonempty_swift_aligned_packed_switches_preserve_physical_native_bytes() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
                let mut fixture = Fixture::new(kind).await?;
                let contract = fixture.endpoints[0]
                    .driver
                    .common
                    .as_ref()
                    .ok_or("common contract absent")?
                    .contract
                    .clone();
                let values = contract.catalog().configurations(contract.envelope())?;
                fixture.exchange_all_channels(1).await?;
                let mut epoch = contract.resources().data_epoch.0;
                for descriptor in contract
                    .catalog()
                    .descriptors()
                    .iter()
                    .filter(|d| **d != contract.catalog().initial())
                {
                    let value = C::new(contract.envelope(), *descriptor)?;
                    assert_eq!(fixture.switch(value).await?, core::Epoch(epoch + 1));
                    epoch += 1;
                    fixture.exchange_all_channels(epoch as u8 + 30).await?;
                    for endpoint in &fixture.endpoints {
                        let snapshot = endpoint.driver.snapshot_common(fixture.now, true)?;
                        assert_eq!(snapshot.current, value);
                        assert_eq!(snapshot.epoch.0, epoch);
                        assert!(!snapshot.resource_preallocation_complete);
                        assert!(
                            snapshot.counters.native_read > 0
                                && snapshot.counters.native_written > 0
                        );
                    }
                }
                assert_eq!(values.len(), 3);
                assert_eq!(
                    fixture.switch(contract.initial()).await?,
                    core::Epoch(epoch + 1)
                );
                fixture.exchange_all_channels(90).await?;
                for endpoint in &fixture.endpoints {
                    assert_eq!(
                        (endpoint.socket.local_addr()?, endpoint.socket.peer_addr()?),
                        endpoint.original
                    );
                    assert!(endpoint.driver.records.next_number(Class::User).0 > 0);
                    assert!(endpoint.driver.records.next_number(Class::Control).0 > 0);
                    assert_eq!(
                        endpoint.driver.counters.native_written,
                        endpoint
                            .driver
                            .performance
                            .counters
                            .native_write_batch_packets
                    );
                    assert!(
                        endpoint.driver.target.is_none()
                            && endpoint.driver.records.additional_data().is_none()
                    );
                }
            }
            Ok(())
        })
}
#[test]
fn held_common_physical_token_blocks_real_switch_and_preserves_original_native_age() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
                let mut fixture = Fixture::new(kind).await?;
                let packet = frame(40000, 71);
                fixture.admit(0, &packet).await?;
                let mut held = None;
                for _ in 0..100 {
                    fixture.turn_with_held_native(Some(1)).await?;
                    if let Some(front) = fixture.endpoints[1].driver.native.common()?.front() {
                        held = Some((*front.metadata(), front.since(), front.bytes().to_vec()));
                        break;
                    }
                }
                let (metadata, since, bytes) = held.ok_or("no actual held Common native")?;
                let contract = fixture.endpoints[0]
                    .driver
                    .common
                    .as_ref()
                    .ok_or("no common")?
                    .contract
                    .clone();
                let target = contract
                    .catalog()
                    .configurations(contract.envelope())?
                    .into_iter()
                    .find(|v| *v != contract.initial())
                    .ok_or("no target")?;
                let (reply, mut result) = oneshot::channel();
                fixture.endpoints[0]
                    .driver
                    .request_common(fixture.now, target, reply)?;
                for _ in 0..20 {
                    fixture.turn_with_held_native(Some(1)).await?;
                }
                assert!(matches!(
                    result.try_recv(),
                    Err(oneshot::error::TryRecvError::Empty)
                ));
                let front = fixture.endpoints[1]
                    .driver
                    .native
                    .common()?
                    .front()
                    .ok_or("held tuple lost")?;
                assert_eq!(front.metadata().token, metadata.token);
                assert_eq!(front.metadata().origin, metadata.origin);
                assert_eq!(front.since(), since);
                assert_eq!(front.bytes(), bytes);
                assert_eq!(fixture.endpoints[1].driver.counters.native_written, 0);
                let mut settled = false;
                for _ in 0..1000 {
                    fixture.turn().await?;
                    if let Ok(answer) = result.try_recv() {
                        assert!(answer.is_ok());
                        settled = true;
                        break;
                    }
                }
                assert!(
                    settled,
                    "held native release must complete actual transaction"
                );
                let mut output = [0; 1024];
                let count = fixture.endpoints[1].host.recv(&mut output)?;
                assert_eq!(&output[..count], packet);
                assert_eq!(fixture.endpoints[1].driver.counters.native_written, 1);
            }
            Ok(())
        })
}

#[test]
fn common_sealed_user_wouldblock_retains_exact_bytes_number_scope_and_single_debit() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
                let mut fixture = Fixture::new(kind).await?;
                let packet = frame(40000, 83);
                fixture.admit(0, &packet).await?;
                let now = fixture.now;
                let endpoint = &mut fixture.endpoints[0];
                endpoint.driver.bucket.refill(now)?;
                let before = endpoint.driver.bucket.tokens;
                let wire_packets = endpoint.driver.counters.wire_packets;
                let blocked = |_: &[u8]| Err(io::Error::from(io::ErrorKind::WouldBlock));
                assert!(!endpoint.driver.send_common_user_with(now, blocked)?);
                let runtime = endpoint
                    .driver
                    .common
                    .as_ref()
                    .ok_or("common runtime missing")?;
                let retained = runtime
                    .sealed
                    .as_ref()
                    .ok_or("real Common seal not retained")?;
                assert!(retained.carrier.is_none());
                let pending = common::PendingWire {
                    scope: retained.scope,
                    sealed: retained.sealed,
                    cost: retained.cost,
                    deadline: retained.deadline,
                    carrier: None,
                };
                let bytes = runtime.wire[..pending.sealed.bytes].to_vec();
                let next = endpoint.driver.records.next_number(Class::User);
                assert_eq!(
                    before - endpoint.driver.bucket.tokens,
                    pending.cost as u128 * SCALE
                );
                assert_eq!(endpoint.driver.counters.wire_packets, wire_packets + 1);
                assert!(!endpoint.driver.send_common_user_with(now, blocked)?);
                assert_eq!(endpoint.driver.records.next_number(Class::User), next);
                assert_eq!(
                    before - endpoint.driver.bucket.tokens,
                    pending.cost as u128 * SCALE
                );
                // Independently seal actual fixed-scope liveness through the real
                // Control owner while its User slot remains socket-blocked.
                endpoint.driver.submit_control(now)?;
                let mut control_packet = None;
                for _ in 0..32 {
                    if let Some(emission) = endpoint.driver.control.poll(
                        duration(now),
                        endpoint.driver.bucket.allowance(),
                        &mut endpoint.driver.buffers.control_wire,
                    )? {
                        let sealed = endpoint.driver.records.seal(
                            Class::Control,
                            meta(endpoint.driver.outer, cover::Phase::Established),
                            &endpoint.driver.buffers.control_wire[..emission.bytes],
                            &mut endpoint.driver.buffers.seal,
                            &mut endpoint.driver.buffers.wire,
                        )?;
                        endpoint.driver.handed(
                            &endpoint.socket,
                            sealed.bytes,
                            performance::WireKind::Control,
                        )?;
                        control_packet = Some(sealed.bytes);
                        break;
                    }
                }
                assert!(
                    control_packet.is_some(),
                    "actual independent liveness must progress"
                );
                assert_eq!(
                    endpoint
                        .driver
                        .common
                        .as_ref()
                        .ok_or("common missing")?
                        .sealed
                        .as_ref(),
                    Some(&pending)
                );
                assert_eq!(
                    &endpoint
                        .driver
                        .common
                        .as_ref()
                        .ok_or("common missing")?
                        .wire[..pending.sealed.bytes],
                    bytes
                );
                let accepted = endpoint.driver.counters.socket_accepted_packets;
                let debit = endpoint.driver.bucket.tokens;
                assert!(
                    endpoint
                        .driver
                        .flush_common_wire_with(now, |bytes| endpoint.socket.try_send(bytes))?
                );
                assert_eq!(endpoint.driver.bucket.tokens, debit);
                assert_eq!(
                    endpoint.driver.counters.socket_accepted_packets,
                    accepted + 1
                );
                assert_eq!(endpoint.driver.records.next_number(Class::User), next);
                assert!(
                    !endpoint
                        .driver
                        .flush_common_wire_with(now, |bytes| endpoint.socket.try_send(bytes))?
                );
                let target = &mut fixture.endpoints[1];
                for _ in 0..2 {
                    let mut input = [0; 1501];
                    let length = tokio::time::timeout(
                        Duration::from_secs(1),
                        target.socket.recv(&mut input),
                    )
                    .await??;
                    target.driver.receive_selected(
                        &input[..length],
                        now,
                        target.driver.origin + duration(now),
                        None,
                    )?;
                }
                let mut actual = None;
                for _ in 0..100 {
                    fixture.turn().await?;
                    let mut output = [0; 1024];
                    match fixture.endpoints[1].host.recv(&mut output) {
                        Ok(bytes) => {
                            actual = Some(output[..bytes].to_vec());
                            break;
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                assert_eq!(actual, Some(packet));
                assert_eq!(fixture.endpoints[1].driver.counters.native_written, 1);
            }
            Ok(())
        })
}

#[test]
fn aligned_context_progress_revisits_one_channel_after_ingress_stops() -> Result {
    use l2tunnel::record_configuration as c;
    use l2tunnel_pipeline::Mapping;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
                let values = udp_values(kind)?;
                let descriptor = values[1].descriptor();
                let c::Profile::Aligned {
                    mut forward,
                    mut reverse,
                } = *descriptor.profile()
                else {
                    return Err("fixture missing Aligned".into());
                };
                forward.receiver.channels = 1;
                reverse.receiver.channels = 1;
                let one = |role| -> Result<c::CommonDirection> {
                    let original = descriptor.direction(role).common();
                    let mut pipeline = original.pipeline();
                    pipeline.flows.channels = 1;
                    pipeline.flows.mapping = Mapping::ConnectionRoundRobin;
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
                    one(mg::Role::Client)?,
                    one(mg::Role::Server)?,
                    c::Profile::Aligned { forward, reverse },
                )?;
                let catalog = Catalog::new(descriptor, &[descriptor])?;
                let mut fixture =
                    Fixture::from_contracts(kind, contracts_with_catalog(kind, catalog, 1)?)
                        .await?;
                let packet = frame(40000, 93);
                fixture.admit(0, &packet).await?;
                // Deliver real protected codec records without running the receiving
                // native collector. Subsequent context/body service has no more UDP
                // ingress available to replenish its bounded scan marker.
                for _ in 0..8 {
                    fixture.now += 1000;
                    let endpoint = &mut fixture.endpoints[0];
                    endpoint.driver.progress_common(fixture.now)?;
                    let before = endpoint.driver.counters.socket_accepted_packets;
                    endpoint.driver.send(
                        &endpoint.socket,
                        fixture.now,
                        endpoint.driver.origin + duration(fixture.now),
                    )?;
                    let sent = endpoint.driver.counters.socket_accepted_packets - before;
                    let receiver = &mut fixture.endpoints[1];
                    for _ in 0..sent {
                        let mut input = [0; 1501];
                        let length = tokio::time::timeout(
                            Duration::from_secs(1),
                            receiver.socket.recv(&mut input),
                        )
                        .await??;
                        receiver.driver.receive_selected(
                            &input[..length],
                            fixture.now,
                            receiver.driver.origin + duration(fixture.now),
                            None,
                        )?;
                    }
                }
                let endpoint = &mut fixture.endpoints[1];
                assert_eq!(endpoint.driver.counters.native_written, 0);
                assert!(endpoint.driver.native.is_empty());
                endpoint.driver.collect_common_native(fixture.now)?;
                if endpoint.driver.native.is_empty() {
                    assert!(
                        endpoint.driver.native_deliverable()?,
                        "real context Progress must retain bounded native work"
                    );
                }
                for _ in 0..32 {
                    if !endpoint.driver.native.is_empty() {
                        break;
                    }
                    endpoint.driver.collect_common_native(fixture.now)?;
                }
                assert!(
                    !endpoint.driver.native.is_empty(),
                    "complete body must follow context without additional ingress"
                );
                let mut ready = tokio::time::timeout(
                    Duration::from_secs(1),
                    endpoint.device.ready_mut(Interest::WRITABLE),
                )
                .await??;
                assert!(
                    endpoint
                        .driver
                        .write_native(&mut ready, || Ok(fixture.now))?
                );
                let mut output = [0; 1024];
                let bytes = endpoint.host.recv(&mut output)?;
                assert_eq!(&output[..bytes], packet);
                assert_eq!(fixture.endpoints[1].driver.counters.native_written, 1);
            }
            Ok(())
        })
}

#[test]
fn common_original_operation_cap_guards_physical_write_and_preserves_late_success_facts() -> Result
{
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
                for late_success in [false, true] {
                    let mut fixture = Fixture::new(kind).await?;
                    let packet = frame(40000, 101);
                    fixture.admit(0, &packet).await?;
                    for _ in 0..100 {
                        fixture.turn_with_held_native(Some(1)).await?;
                        if !fixture.endpoints[1].driver.native.is_empty() {
                            break;
                        }
                    }
                    assert_eq!(fixture.endpoints[1].driver.native.len(), 1);
                    let contract = fixture.endpoints[0]
                        .driver
                        .common
                        .as_ref()
                        .ok_or("common contract missing")?
                        .contract
                        .clone();
                    let target = contract
                        .catalog()
                        .configurations(contract.envelope())?
                        .into_iter()
                        .find(|v| *v != contract.initial())
                        .ok_or("no Common target")?;
                    let (reply, _answer) = oneshot::channel();
                    fixture.endpoints[0]
                        .driver
                        .request_common(fixture.now, target, reply)?;
                    for _ in 0..30 {
                        fixture.turn_with_held_native(Some(1)).await?;
                    }
                    let endpoint = &mut fixture.endpoints[1];
                    let operation = endpoint
                        .driver
                        .common_state()?
                        .peer()
                        .operation()
                        .ok_or("actual operation missing")?;
                    assert!(
                        endpoint
                            .driver
                            .common_state()?
                            .peer()
                            .peer_fence()
                            .is_some()
                    );
                    assert!(
                        endpoint.driver.challenge.is_none(),
                        "actual matching Pong must settle before exact cap test"
                    );
                    let cap = operation
                        .expires()
                        .0
                        .checked_mul(1000)
                        .ok_or("cap conversion")?;
                    let mut ready = tokio::time::timeout(
                        Duration::from_secs(1),
                        endpoint.device.ready_mut(Interest::WRITABLE),
                    )
                    .await??;
                    let mut samples = 0;
                    let result = endpoint.driver.write_native(&mut ready, || {
                        samples += 1;
                        Ok(if late_success && samples == 1 {
                            cap - 1
                        } else {
                            cap
                        })
                    });
                    assert_eq!(
                        result.err().map(|e| e.kind()),
                        Some(io::ErrorKind::TimedOut)
                    );
                    assert_eq!(endpoint.driver.terminal, Some(StopReason::PolicyTimeout));
                    let engine = endpoint
                        .driver
                        .common_state()?
                        .engine(operation.origin().epoch)?;
                    let counts = engine.native_counts()?;
                    if late_success {
                        assert!(endpoint.driver.native.is_empty());
                        assert_eq!(endpoint.driver.counters.native_written, 1);
                        assert_eq!(counts.committed.iter().sum::<u64>(), 1);
                        let mut output = [0; 1024];
                        let bytes = endpoint.host.recv(&mut output)?;
                        assert_eq!(&output[..bytes], packet);
                    } else {
                        assert_eq!(endpoint.driver.native.len(), 1);
                        assert_eq!(endpoint.driver.counters.native_written, 0);
                        assert_eq!(counts.committed.iter().sum::<u64>(), 0);
                        let mut output = [0; 1024];
                        assert_eq!(
                            endpoint.host.recv(&mut output).err().map(|e| e.kind()),
                            Some(io::ErrorKind::WouldBlock)
                        );
                    }
                    // A failed session is inspected only; this test never resumes it.
                }
            }
            Ok(())
        })
}

#[path = "transport_common_feedback_tests.rs"]
mod feedback;

#[path = "transport_common_rolling_tests.rs"]
mod rolling;
