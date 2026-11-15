//! Native identity custody through actual protected UDP and complete device writes.
//!
//! Policy messages below come from the actual coordinators and their retained
//! output API. Their direct delivery tests the runtime hooks, not ARQ completion.

use super::*;

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

fn packet(channel: usize, channels: usize, number: u8) -> Result<Vec<u8>> {
    let port = (40_000..40_256_u16)
        .find(|port| swift::flow::classify_ethernet(&frame(*port, number), channels) == channel)
        .ok_or("native custody fixture has no matching flow")?;
    Ok(frame(port, number))
}

fn count(driver: &Driver, channel: usize) -> Result<u64> {
    Ok(driver
        .owner
        .legacy()?
        .engine
        .boundary(
            records::Direction::Receive,
            records::ChannelId::new(channel).ok_or("invalid fixture channel")?,
        )
        .ok_or("absent fixture receive channel")?
        .count
        .0)
}

fn seal_next(driver: &mut Driver, now: u64, kind: u8) -> Result<Vec<u8>> {
    let seed = driver.records.next_number(Class::User);
    let body = driver
        .owner
        .legacy_mut()?
        .engine
        .poll(now, records::RecordNumber(seed.0), true)?
        .ok_or("fixture has no Swift output")?;
    assert_eq!(body[0] & swift::KIND_MASK, kind);
    let scope = if kind == swift::KIND_FEEDBACK {
        driver.feedback_scope
    } else {
        driver.source_scope
    };
    let mut wire = vec![0; driver.cover.limits().max_packet_bytes];
    let sealed = driver.records.seal_user_in(
        scope,
        meta(driver.outer, cover::Phase::Established),
        body,
        &mut driver.buffers.seal,
        &mut wire,
    )?;
    driver.outer = driver.outer.checked_add(1).ok_or_else(exhausted)?;
    wire.truncate(sealed.bytes);
    Ok(wire)
}

fn drain_setup(socket: &tokio::net::UdpSocket) -> Result {
    let mut bytes = [0; 1501];
    for _ in 0..128 {
        match socket.try_recv(&mut bytes) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error.into()),
        }
    }
    Err("native custody setup drain exceeded its bound".into())
}

async fn transfer(
    source: &tokio::net::UdpSocket,
    destination: &tokio::net::UdpSocket,
    owner: &mut Driver,
    wire: &[u8],
    now: u64,
) -> Result {
    assert_eq!(source.send(wire).await?, wire.len());
    let mut input = [0; 1501];
    let length =
        tokio::time::timeout(Duration::from_secs(1), destination.recv(&mut input)).await??;
    assert_eq!(&input[..length], wire);
    owner.receive(
        &input[..length],
        now,
        owner.origin + duration(now),
        &resolve(owner.config),
    )?;
    Ok(())
}

struct Fixture {
    socket: tokio::net::UdpSocket,
    remote_socket: tokio::net::UdpSocket,
    driver: Driver,
    remote: Driver,
    device: AsyncFd<EventDevice>,
    host: UnixDatagram,
    writes: Arc<AtomicUsize>,
    time: Arc<AtomicU64>,
    now: u64,
}

impl Fixture {
    async fn new(kind: cover::Appearance) -> Result<Self> {
        let mut config = config(kind);
        config.send.records.codec.repair_numerator = 0;
        config.receive = config.send;
        config.native.stall_timeout = Duration::from_millis(50);
        config.lifetime.lease = Duration::from_secs(60);
        config.lifetime.ping_interval = Duration::from_secs(10);
        config.report_interval = None;
        let (a, b) = parts_pair(kind).await?;
        let setup_end = a.deadline.max(b.deadline);
        let origin = Instant::now();
        let (socket, mut driver) = Driver::new(a, security::ConfigDigest([3; 32]), config, origin)?;
        let (remote_socket, mut remote) =
            Driver::new(b, security::ConfigDigest([3; 32]), config, origin)?;
        for owner in [&mut driver, &mut remote] {
            owner.bucket.tokens = 0;
            assert!(owner.tail(setup_end)?.is_none());
        }
        drain_setup(&socket)?;
        drain_setup(&remote_socket)?;
        let now = clock(origin, setup_end)? + 20_000;
        driver.bucket.refill(now)?;
        remote.bucket.refill(now)?;
        let (native, host) = UnixDatagram::pair()?;
        native.set_nonblocking(true)?;
        host.set_nonblocking(true)?;
        let writes = Arc::new(AtomicUsize::new(0));
        let time = Arc::new(AtomicU64::new(now));
        let device = AsyncFd::with_interest(
            EventDevice {
                inner: Device {
                    socket: native,
                    blocked: false,
                    wouldblock: None,
                },
                time: time.clone(),
                writes: writes.clone(),
                reads: Arc::new(AtomicUsize::new(0)),
                written_at: None,
                read_at: None,
            },
            Interest::WRITABLE,
        )?;
        Ok(Self {
            socket,
            remote_socket,
            driver,
            remote,
            device,
            host,
            writes,
            time,
            now,
        })
    }

    async fn receive(&mut self, packet: &[u8]) -> Result<records::NativeIdentity> {
        let identity = match self
            .remote
            .owner
            .legacy_mut()?
            .engine
            .offer_identified(self.now, packet)?
        {
            records::IdentifiedAdmission::Accepted(identity) => identity,
            other => return Err(format!("fixture admission refused: {other:?}").into()),
        };
        let wire = seal_next(&mut self.remote, self.now, swift::KIND_SOURCE)?;
        transfer(
            &self.remote_socket,
            &self.socket,
            &mut self.driver,
            &wire,
            self.now,
        )
        .await?;
        self.driver.collect_native(self.now)?;
        self.now += 1;
        Ok(identity)
    }

    async fn confirm_remote_sources(&mut self) -> Result {
        self.now += self.driver.receive.records.codec.feedback_micros + 1;
        let wire = seal_next(&mut self.driver, self.now, swift::KIND_FEEDBACK)?;
        transfer(
            &self.socket,
            &self.remote_socket,
            &mut self.remote,
            &wire,
            self.now,
        )
        .await?;
        assert!(self.remote.owner.legacy()?.engine.send_drained());
        Ok(())
    }

    async fn write(&mut self) -> io::Result<bool> {
        let mut ready = tokio::time::timeout(
            Duration::from_secs(1),
            self.device.ready_mut(Interest::WRITABLE),
        )
        .await??;
        let time = self.time.clone();
        self.driver
            .write_native(&mut ready, || Ok(time.load(Ordering::SeqCst)))
    }

    fn received_once(&self, expected: &[u8]) -> Result {
        let mut input = [0; 513];
        let length = self.host.recv(&mut input)?;
        assert_eq!(&input[..length], expected);
        assert_eq!(
            self.host.recv(&mut input).err().map(|error| error.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        Ok(())
    }
}

fn take_output(driver: &mut Driver, now: u64) -> Result<swift::control::Message> {
    let output = driver
        .owner
        .legacy()?
        .coordinator
        .outbound()
        .ok_or("missing genuine coordinator output")?;
    driver
        .owner
        .legacy_mut()?
        .coordinator
        .complete_outbound(policy::Time(now), output.id)?;
    Ok(output.message)
}

fn deliver_profile(
    driver: &mut Driver,
    now: u64,
    scope: Scope,
    message: swift::control::Message,
) -> Result {
    driver.profile(now, scope, message, &resolve(driver.config))?;
    Ok(())
}

fn hooks(driver: &mut Driver) -> Result<Hooks<'_>> {
    Ok(Hooks {
        info: &driver.info,
        next: records::RecordNumber(driver.records.next_number(Class::User).0),
        engine: &mut driver.owner.legacy_mut()?.engine,
        written: &mut driver.written,
        retired_send: &mut driver.retired_send,
        retired_receive: &mut driver.retired_receive,
        send: &mut driver.send,
        receive: &mut driver.receive,
        source: &mut driver.source_scope,
        feedback: &mut driver.feedback_scope,
        target: driver.target,
        native_pending: !driver.native.is_empty(),
        bucket: &mut driver.bucket,
    })
}

/// Return the genuine local barrier while the opposite receive barrier waits on
/// the old physical FIFO. No external delivery-completion proof is fabricated.
fn waiting_for_physical_receive(fixture: &mut Fixture) -> Result<swift::control::Message> {
    let old = fixture.driver.records.active_data();
    let (reply, _result) = oneshot::channel();
    fixture.driver.request(
        fixture.now,
        policy_value(),
        reply,
        &resolve(fixture.driver.config),
    )?;
    let propose = take_output(&mut fixture.driver, fixture.now)?;
    deliver_profile(&mut fixture.remote, fixture.now, old, propose)?;
    let accept = take_output(&mut fixture.remote, fixture.now)?;
    deliver_profile(&mut fixture.driver, fixture.now, old, accept)?;
    fixture.driver.progress(fixture.now)?;
    let local_barrier = take_output(&mut fixture.driver, fixture.now)?;
    assert!(matches!(
        local_barrier,
        swift::control::Message::Barrier { .. }
    ));
    fixture.remote.progress(fixture.now)?;
    let remote_barrier = take_output(&mut fixture.remote, fixture.now)?;
    assert!(matches!(
        remote_barrier,
        swift::control::Message::Barrier { .. }
    ));
    deliver_profile(&mut fixture.driver, fixture.now, old, remote_barrier)?;
    fixture.driver.progress(fixture.now)?;
    assert!(
        fixture
            .driver
            .owner
            .legacy()?
            .coordinator
            .outbound()
            .is_none(),
        "physical custody must withhold BarrierAck"
    );
    assert!(matches!(
        fixture
            .driver
            .owner
            .legacy()?
            .coordinator
            .pending()
            .map(|pending| pending.receive),
        Some(policy::ReceivePhase::Flushing { .. })
    ));
    assert_eq!(fixture.driver.feedback_scope, old);
    assert_eq!(fixture.driver.receive.records.channels, 2);
    assert!(fixture.driver.retired_receive.is_none());
    assert_eq!(
        fixture.driver.owner.legacy()?.coordinator.committed().epoch,
        policy::Epoch(0)
    );
    Ok(local_barrier)
}

#[tokio::test]
async fn would_block_retains_original_native_identity_origin_age_and_physical_vector() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let mut fixture = Fixture::new(kind).await?;
        let first = packet(1, 2, 1)?;
        let second = packet(1, 2, 2)?;
        let identity = fixture.receive(&first).await?;
        let second_identity = fixture.receive(&second).await?;
        assert_eq!(identity.record, records::NativeRecordId(0));
        assert_eq!(second_identity.record, records::NativeRecordId(1));
        assert_eq!(count(&fixture.driver, 1)?, 2);
        assert_eq!(fixture.driver.written.counts[1], 0);
        let origin = NativeOrigin::new(
            &fixture.driver.info,
            fixture.driver.feedback_scope,
            records::Direction::Receive,
        );
        assert_eq!(origin.direction, security::Direction::ResponderToInitiator);
        let before: Vec<_> = fixture
            .driver
            .native
            .iter()
            .map(|packet| {
                (
                    packet.metadata().origin,
                    packet.metadata().identity,
                    packet.since(),
                    packet.bytes().to_vec(),
                )
            })
            .collect();
        fixture.device.get_mut().inner.blocked = true;
        fixture.time.store(fixture.now, Ordering::SeqCst);
        assert!(!fixture.write().await?);
        assert_eq!(
            fixture
                .driver
                .native
                .iter()
                .map(|packet| (
                    packet.metadata().origin,
                    packet.metadata().identity,
                    packet.since(),
                    packet.bytes().to_vec()
                ))
                .collect::<Vec<_>>(),
            before
        );
        assert!(
            fixture
                .driver
                .native
                .iter()
                .all(|packet| packet.metadata().origin == origin)
        );
        assert_eq!(fixture.driver.written.counts[1], 0);
        assert!(
            !fixture
                .driver
                .written
                .matches_extracted(&fixture.driver.owner.legacy()?.engine, origin)
        );
        assert_eq!(fixture.driver.counters.native_written, 0);
        // The synthetic WouldBlock cleared readiness despite the real socket
        // remaining writable. Re-register that same owned descriptor explicitly.
        let mut device = fixture.device.into_inner();
        device.inner.blocked = false;
        fixture.device = AsyncFd::with_interest(device, Interest::WRITABLE)?;
        assert!(fixture.write().await?);
        assert_eq!(
            fixture
                .driver
                .native
                .front()
                .map(|packet| packet.metadata().identity),
            Some(second_identity)
        );
        assert_eq!(fixture.driver.written.counts[1], 1);
        let mut input = [0; 513];
        let length = fixture.host.recv(&mut input)?;
        assert_eq!(&input[..length], first);
        assert!(fixture.write().await?);
        fixture.received_once(&second)?;
        assert_eq!(fixture.driver.written.counts[1], 2);
        assert!(
            fixture
                .driver
                .written
                .matches_extracted(&fixture.driver.owner.legacy()?.engine, origin)
        );
        assert!(fixture.driver.native.is_empty());
        assert_eq!(fixture.driver.counters.native_written, 2);
        assert_eq!(fixture.writes.load(Ordering::SeqCst), 3);
    }
    Ok(())
}

#[tokio::test]
async fn internal_native_metadata_guards_refuse_before_device_io_without_consumption() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let mut fixture = Fixture::new(kind).await?;
        let packet = packet(1, 2, 1)?;
        let identity = fixture.receive(&packet).await?;
        let origin = fixture.driver.written.origin;
        let counts = fixture.driver.written.counts;
        let age = fixture
            .driver
            .native
            .front()
            .ok_or("missing fixture native packet")?
            .since();
        // These are deliberately inconsistent local metadata, not authenticated
        // peer flows. Genuine bytes and pure extracted boundaries remain intact.
        for variant in 0..8 {
            let mut front = Native { origin, identity };
            fixture.driver.written.counts = counts;
            fixture.driver.written.channels = 2;
            match variant {
                0 => front.origin.scope.epoch.0 += 1,
                1 => front.origin.binding.transcript[0] ^= 1,
                2 => front.origin.lane = security::LaneId(LANE + 1),
                3 => front.origin.direction = security::Direction::InitiatorToResponder,
                4 => front.identity.record = records::NativeRecordId(1),
                5 => {
                    front.identity.channel = records::ChannelId::new(2).ok_or("fixture channel")?
                }
                6 => fixture.driver.written.channels = 1,
                _ => {
                    fixture.driver.written.counts[1] = u64::MAX;
                    front.identity.record = records::NativeRecordId(u64::MAX);
                }
            }
            // Republish deliberately inconsistent trusted metadata through the
            // same actual lease API; no public mutable backing escape is needed.
            fixture.driver.native.complete_front()?;
            fixture
                .driver
                .native
                .acquire()
                .ok_or("fixture native lease")?
                .copy(front, age, &packet)?;
            fixture.time.store(fixture.now, Ordering::SeqCst);
            assert!(
                fixture.write().await.is_err(),
                "invalid local metadata variant {variant}"
            );
            assert_eq!(fixture.writes.load(Ordering::SeqCst), 0);
            assert_eq!(fixture.driver.counters.native_written, 0);
            assert_eq!(fixture.driver.native.len(), 1);
            assert_eq!(
                fixture.driver.native.front().map(|packet| packet.since()),
                Some(age)
            );
            assert_eq!(count(&fixture.driver, 1)?, 1);
        }
        fixture.driver.written.channels = 2;
        fixture.driver.written.counts = counts;
        fixture.driver.native.complete_front()?;
        fixture
            .driver
            .native
            .acquire()
            .ok_or("fixture native lease")?
            .copy(Native { origin, identity }, age, &packet)?;
        assert!(fixture.write().await?);
        fixture.received_once(&packet)?;
        assert_eq!(fixture.driver.written.counts[1], 1);
    }
    Ok(())
}

#[tokio::test]
async fn empty_fifo_cannot_reset_receive_with_mismatched_physical_generation_or_count() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let mut fixture = Fixture::new(kind).await?;
        let packet = packet(1, 2, 1)?;
        fixture.receive(&packet).await?;
        fixture.time.store(fixture.now, Ordering::SeqCst);
        assert!(fixture.write().await?);
        fixture.received_once(&packet)?;
        assert!(fixture.driver.native.is_empty());
        assert!(fixture.driver.owner.legacy()?.engine.receive_drained());
        let old = fixture.driver.feedback_scope;
        let origin = fixture.driver.written.origin;
        let counts = fixture.driver.written.counts;
        let before = fixture.driver.owner.legacy()?.engine.stats();
        let floor = fixture.driver.owner.legacy()?.engine.source_floor();
        let direction = fixture.driver.receive;
        let (reply, _result) = oneshot::channel();
        fixture.driver.request(
            fixture.now,
            policy_value(),
            reply,
            &resolve(fixture.driver.config),
        )?;
        let target = fixture
            .driver
            .target
            .ok_or("missing staged fixture policy")?;
        let replacement = resolve(fixture.driver.config)(&policy_value())
            .ok_or("missing fixture policy")?
            .receive;
        // Deliberately inconsistent internal ledger metadata must not be
        // accepted merely because the FIFO and pure receive bytes are empty.
        for variant in 0..6 {
            fixture.driver.written.origin = origin;
            fixture.driver.written.channels = 2;
            fixture.driver.written.counts = counts;
            match variant {
                0 => fixture.driver.written.origin.scope = target,
                1 => fixture.driver.written.origin.binding.transcript[0] ^= 1,
                2 => fixture.driver.written.origin.lane = security::LaneId(LANE + 1),
                3 => {
                    fixture.driver.written.origin.direction =
                        security::Direction::InitiatorToResponder
                }
                4 => fixture.driver.written.channels = 1,
                _ => fixture.driver.written.counts[1] = 0,
            }
            {
                let mut actual = hooks(&mut fixture.driver)?;
                assert!(!policy::Hooks::status(&actual).receive_drained);
                assert!(
                    policy::Hooks::replace_receive(
                        &mut actual,
                        replacement,
                        records::RecordNumber(100)
                    )
                    .is_err()
                );
            }
            assert_eq!(fixture.driver.feedback_scope, old);
            assert_eq!(fixture.driver.receive, direction);
            assert_eq!(fixture.driver.owner.legacy()?.engine.source_floor(), floor);
            assert_eq!(fixture.driver.owner.legacy()?.engine.stats(), before);
            assert_eq!(count(&fixture.driver, 1)?, 1);
            assert!(fixture.driver.retired_receive.is_none());
            assert_eq!(fixture.driver.counters.native_written, 1);
            assert_eq!(fixture.writes.load(Ordering::SeqCst), 1);
        }
        fixture.driver.written.origin = origin;
        fixture.driver.written.channels = 2;
        fixture.driver.written.counts = counts;
        assert!(policy::Hooks::status(&hooks(&mut fixture.driver)?).receive_drained);
        assert_eq!(
            fixture.driver.owner.legacy()?.coordinator.committed().epoch,
            policy::Epoch(0)
        );
    }
    Ok(())
}

#[tokio::test]
async fn directional_policy_hooks_keep_physical_old_witness_and_collect_in_feedback_scope() -> Result
{
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let mut fixture = Fixture::new(kind).await?;
        let old_packet = packet(1, 2, 1)?;
        fixture.receive(&old_packet).await?;
        fixture.confirm_remote_sources().await?;
        let old = fixture.driver.records.active_data();
        assert!(
            fixture
                .driver
                .owner
                .legacy()?
                .engine
                .boundary(
                    records::Direction::Receive,
                    records::ChannelId::new(2).ok_or("fixture channel")?
                )
                .is_none()
        );
        let original = fixture.driver.written.origin;
        let local_barrier = waiting_for_physical_receive(&mut fixture)?;
        assert_eq!(count(&fixture.driver, 1)?, 1);
        assert_eq!(fixture.driver.written.counts[1], 0);
        assert!(
            !fixture
                .driver
                .written
                .matches_extracted(&fixture.driver.owner.legacy()?.engine, original)
        );
        fixture.time.store(fixture.now, Ordering::SeqCst);
        assert!(fixture.write().await?);
        fixture.received_once(&old_packet)?;
        fixture.driver.progress(fixture.now)?;
        let target = fixture.driver.target.ok_or("missing staged target")?;
        assert_ne!(target, old);
        assert_eq!(fixture.driver.feedback_scope, target);
        assert_eq!(fixture.driver.source_scope, old);
        assert_eq!(fixture.driver.records.active_data(), old);
        assert_eq!(fixture.driver.written.channels, 3);
        assert_eq!(fixture.driver.written.counts, [0; swift::MAX_CHANNELS]);
        assert_eq!(count(&fixture.driver, 1)?, 0);
        let retired = fixture
            .driver
            .retired_receive
            .ok_or("missing old physical witness")?;
        assert_eq!(retired.origin, original);
        assert_eq!(retired.direction, records::Direction::Receive);
        assert_eq!(retired.channels, 2);
        assert_eq!(retired.counts[1], 1);
        assert!(fixture.driver.retired_send.is_none());
        let ack = take_output(&mut fixture.driver, fixture.now)?;
        assert!(matches!(ack, swift::control::Message::BarrierAck { .. }));
        deliver_profile(&mut fixture.remote, fixture.now, old, ack)?;
        assert_eq!(fixture.remote.source_scope, target);
        assert_eq!(fixture.remote.feedback_scope, old);
        assert_eq!(fixture.remote.records.active_data(), old);
        // The new receive width and target scope are active in this direction
        // while common Records and the opposite local send still retain old.
        let new_packet = packet(2, 3, 2)?;
        let identity = fixture.receive(&new_packet).await?;
        assert_eq!(identity.channel.index(), 2);
        assert_eq!(identity.record, records::NativeRecordId(0));
        let queued = fixture
            .driver
            .native
            .front()
            .ok_or("missing target native packet")?;
        assert_eq!(
            queued.metadata().origin.scope,
            fixture.driver.feedback_scope
        );
        assert_ne!(
            queued.metadata().origin.scope,
            fixture.driver.records.active_data()
        );
        assert_eq!(
            queued.metadata().origin.binding,
            fixture.driver.info.binding
        );
        assert_eq!(
            queued.metadata().origin.direction,
            security::Direction::ResponderToInitiator
        );
        assert_eq!(fixture.driver.retired_receive, Some(retired));
        fixture.time.store(fixture.now, Ordering::SeqCst);
        assert!(fixture.write().await?);
        fixture.received_once(&new_packet)?;
        assert_eq!(fixture.driver.written.counts[2], 1);
        assert_eq!(fixture.driver.retired_receive, Some(retired));
        // Only the genuine remaining directional barrier/ack and local output
        // completions permit the existing policy settlement to retire witnesses.
        deliver_profile(&mut fixture.remote, fixture.now, old, local_barrier)?;
        fixture.remote.progress(fixture.now)?;
        let ack = take_output(&mut fixture.remote, fixture.now)?;
        assert!(matches!(ack, swift::control::Message::BarrierAck { .. }));
        deliver_profile(&mut fixture.driver, fixture.now, old, ack)?;
        let send = fixture
            .driver
            .retired_send
            .ok_or("missing old admitted witness")?;
        assert_eq!(send.origin.scope, old);
        assert_eq!(send.direction, records::Direction::Send);
        assert_eq!(send.channels, 2);
        assert_eq!(send.counts, [0; swift::MAX_CHANNELS]);
        assert_eq!(fixture.driver.written.counts[2], 1);
        fixture.driver.progress(fixture.now)?;
        fixture.remote.progress(fixture.now)?;
        assert_eq!(
            fixture.driver.owner.legacy()?.coordinator.committed().epoch,
            policy::Epoch(1)
        );
        assert_eq!(fixture.driver.records.active_data(), target);
        assert!(fixture.driver.retired_send.is_none());
        assert!(fixture.driver.retired_receive.is_none());
        assert_eq!(fixture.driver.written.counts[2], 1);
        assert!(fixture.driver.written.matches_extracted(
            &fixture.driver.owner.legacy()?.engine,
            fixture.driver.written.origin
        ));
        assert_eq!(fixture.driver.counters.native_written, 2);
    }
    Ok(())
}

#[tokio::test]
async fn noncanonical_retained_native_boundaries_block_scope_settlement_without_retirement()
-> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        for corrupt_send in [true, false] {
            for malformed in 0..3 {
                // Every case reaches its retained witnesses through real old
                // source bytes, a complete device write and both actual policy
                // hook transitions. Only local witness shape is then corrupted.
                let mut fixture = Fixture::new(kind).await?;
                let packet = packet(1, 2, 1)?;
                fixture.receive(&packet).await?;
                fixture.confirm_remote_sources().await?;
                let old = fixture.driver.records.active_data();
                let local_barrier = waiting_for_physical_receive(&mut fixture)?;
                fixture.time.store(fixture.now, Ordering::SeqCst);
                assert!(fixture.write().await?);
                fixture.received_once(&packet)?;
                fixture.driver.progress(fixture.now)?;
                let target = fixture.driver.target.ok_or("missing staged target")?;
                let ack = take_output(&mut fixture.driver, fixture.now)?;
                assert!(matches!(ack, swift::control::Message::BarrierAck { .. }));
                deliver_profile(&mut fixture.remote, fixture.now, old, ack)?;
                deliver_profile(&mut fixture.remote, fixture.now, old, local_barrier)?;
                fixture.remote.progress(fixture.now)?;
                let ack = take_output(&mut fixture.remote, fixture.now)?;
                assert!(matches!(ack, swift::control::Message::BarrierAck { .. }));
                deliver_profile(&mut fixture.driver, fixture.now, old, ack)?;
                assert_eq!(fixture.driver.source_scope, target);
                assert_eq!(fixture.driver.feedback_scope, target);
                assert_eq!(fixture.driver.records.active_data(), old);
                let reader = fixture.driver.records.additional_data();
                assert_eq!(reader.map(|reader| reader.scope), Some(target));
                assert_eq!(fixture.driver.counters.native_written, 1);
                assert!(fixture.driver.native.is_empty());
                let boundary = if corrupt_send {
                    fixture.driver.retired_send.as_mut()
                } else {
                    fixture.driver.retired_receive.as_mut()
                }
                .ok_or("missing retained native boundary")?;
                match malformed {
                    0 => boundary.channels = 0,
                    1 => boundary.channels = swift::MAX_CHANNELS + 1,
                    _ => boundary.counts[boundary.channels] = 1,
                }
                let local_direction = if corrupt_send {
                    records::Direction::Send
                } else {
                    records::Direction::Receive
                };
                assert!(!boundary.canonical_for(
                    NativeOrigin::new(&fixture.driver.info, old, local_direction),
                    local_direction
                ));
                let retained_send = fixture.driver.retired_send;
                let retained_receive = fixture.driver.retired_receive;
                let written = fixture.driver.written.boundary();
                let statistics = fixture.driver.owner.legacy()?.engine.stats();
                let number = fixture.driver.records.next_number(Class::User);
                assert_eq!(
                    fixture
                        .driver
                        .progress(fixture.now)
                        .err()
                        .map(|error| error.kind()),
                    Some(io::ErrorKind::InvalidData)
                );
                assert_eq!(fixture.driver.records.active_data(), old);
                assert_eq!(fixture.driver.records.additional_data(), reader);
                assert_eq!(fixture.driver.target, Some(target));
                assert_eq!(fixture.driver.retired_send, retained_send);
                assert_eq!(fixture.driver.retired_receive, retained_receive);
                assert_eq!(fixture.driver.written.boundary(), written);
                assert_eq!(fixture.driver.owner.legacy()?.engine.stats(), statistics);
                assert_eq!(fixture.driver.records.next_number(Class::User), number);
                assert_eq!(fixture.driver.counters.native_written, 1);
                assert_eq!(fixture.writes.load(Ordering::SeqCst), 1);
                // This failure is a local invariant guard, not a peer Fence
                // comparison, rollback promise or permission to resume a session.
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn physical_success_commits_native_identity_once_even_when_completion_fails() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        for failure in 0..3 {
            let mut fixture = Fixture::new(kind).await?;
            let packet = packet(1, 2, 1)?;
            let identity = fixture.receive(&packet).await?;
            fixture.confirm_remote_sources().await?;
            waiting_for_physical_receive(&mut fixture)?;
            let origin = fixture.driver.written.origin;
            let since = fixture
                .driver
                .native
                .front()
                .ok_or("missing fixture native packet")?
                .since();
            let deadline = add(since, fixture.driver.config.native.stall_timeout)?;
            fixture.time.store(deadline - 1, Ordering::SeqCst);
            if failure == 0 {
                fixture.device.get_mut().written_at = Some(deadline);
            }
            let mut ready = tokio::time::timeout(
                Duration::from_secs(1),
                fixture.device.ready_mut(Interest::WRITABLE),
            )
            .await??;
            let time = fixture.time.clone();
            let previous = fixture.now - 1;
            let mut calls = 0;
            let result = fixture.driver.write_native(&mut ready, || {
                calls += 1;
                if calls == 1 || failure == 0 {
                    Ok(time.load(Ordering::SeqCst))
                } else if failure == 1 {
                    Err(io::Error::other("injected fresh completion clock failure"))
                } else {
                    Ok(previous)
                }
            });
            assert_eq!(
                result.err().map(|error| error.kind()),
                Some(match failure {
                    0 => io::ErrorKind::TimedOut,
                    1 => io::ErrorKind::Other,
                    _ => io::ErrorKind::InvalidData,
                })
            );
            drop(ready);
            assert_eq!(fixture.writes.load(Ordering::SeqCst), 1);
            assert_eq!(fixture.driver.written.origin, origin);
            assert_eq!(
                fixture.driver.written.counts[identity.channel.index()],
                identity.record.0 + 1
            );
            assert!(fixture.driver.native.is_empty());
            assert_eq!(fixture.driver.native.bytes(), 0);
            assert_eq!(fixture.driver.counters.native_written, 1);
            assert_eq!(
                fixture
                    .driver
                    .performance
                    .counters
                    .native_write_batch_packets,
                1
            );
            assert_eq!(
                fixture.driver.owner.legacy()?.coordinator.committed().epoch,
                policy::Epoch(0)
            );
            assert!(
                fixture
                    .driver
                    .owner
                    .legacy()?
                    .coordinator
                    .outbound()
                    .is_none()
            );
            assert!(matches!(
                fixture
                    .driver
                    .owner
                    .legacy()?
                    .coordinator
                    .pending()
                    .map(|pending| pending.receive),
                Some(policy::ReceivePhase::Flushing { .. })
            ));
            assert!(fixture.driver.retired_receive.is_none());
            if failure == 0 {
                assert_eq!(fixture.driver.terminal, Some(StopReason::NativeStall));
            }
            fixture.received_once(&packet)?;
            // Inspect the irreversible result only; do not resume a session
            // after its operation has failed in order to obtain a policy result.
        }
    }
    Ok(())
}
