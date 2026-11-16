//! Explicit nonprivileged process/IPC probe for the selected generic CLI.
//!
//! Run only after separately building the exact daemon. This example never runs
//! Cargo, attaches TUN/TAP, changes host networking or measures performance. Its
//! IPC peers use the real shared authentication/runtime with Unix packet devices;
//! that is distinct from successful production connect/serve device attachment.

#[cfg(unix)]
mod probe {
    use l2tunnel::swift_configuration::{Catalog, Configuration, Descriptor, EnvelopeDigest};
    use l2tunnel_client_core::{
        Compression, ConnectionConfig, local,
        secure_udp::{self, credentials, transaction_profile, transaction_status},
        service::{self, Attachment, Completed, Handle, Observation, Prepared},
    };
    use l2tunnel_core::{ConfigDigest, Duplex};
    use l2tunnel_cover::{Appearance, ConnectionId, Ssrc};
    use l2tunnel_device::{PacketDevice, PacketLayer};
    use l2tunnel_handshake as hs;
    use l2tunnel_management::{control_streams, delivery, messages, transaction};
    use l2tunnel_runtime::secure_udp::{control, establish, transport};
    use l2tunnel_security as security;
    use l2tunnel_swift::{policy, records};
    use l2tunnel_udp_control as gate;
    use serde_json::{Value, json};
    use std::{
        ffi::OsString,
        fs::{self, OpenOptions},
        io::{self, Read, Write},
        net::{SocketAddr, UdpSocket},
        os::{
            fd::AsRawFd,
            unix::{
                fs::{DirBuilderExt, OpenOptionsExt},
                net::UnixDatagram,
            },
        },
        path::{Path, PathBuf},
        process::{Child, Command, ExitStatus, Stdio},
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        },
        thread,
        time::{Duration, Instant},
    };
    use tokio::{task::JoinHandle, time::timeout};
    use zeroize::Zeroizing;

    type Result<T = ()> = io::Result<T>;
    const STDOUT_LIMIT: usize = 128 * 1024;
    const STDERR_LIMIT: usize = 16 * 1024;
    const MAXIMUM_MTU: usize = 2000;

    fn error(value: impl std::fmt::Display) -> io::Error {
        io::Error::other(value.to_string())
    }
    fn require(value: bool, message: &str) -> Result {
        if value { Ok(()) } else { Err(error(message)) }
    }
    fn submit(value: service::SubmitError) -> io::Error {
        error(format!("service request: {value:?}"))
    }
    fn lock<T>(value: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        value
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn save(path: &Path, bytes: &[u8]) -> Result {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)
    }
    fn private_directory(path: &Path) -> Result {
        fs::DirBuilder::new().mode(0o700).create(path)
    }
    fn path_text(path: &Path) -> Result<String> {
        path.to_str()
            .map(str::to_owned)
            .ok_or_else(|| error("probe requires UTF-8 paths"))
    }

    struct Keys {
        member: Zeroizing<Vec<u8>>,
        member_public: l2tunnel_identity::MemberPublicKey,
        peers: establish::Peers,
    }
    impl Keys {
        fn new(directory: &Path) -> Result<Self> {
            // Deliberate finite test credentials, never a production fallback.
            let member = Zeroizing::new(l2tunnel_auth::MemberKey::generate_pkcs8().map_err(error)?);
            let identity = l2tunnel_identity::IdentityKey::from_pkcs8(&member).map_err(error)?;
            let member_public = identity.public_key();
            let peers = establish::Peers {
                initiator: hs::LocalSecret::new(Zeroizing::new([11; 32])).public_key(),
                responder: hs::LocalSecret::new(Zeroizing::new([22; 32])).public_key(),
            };
            for (name, bytes) in [
                ("initiator.raw", &[11; 32][..]),
                ("responder.raw", &[22; 32][..]),
                ("initiator.pub", &peers.initiator.0[..]),
                ("responder.pub", &peers.responder.0[..]),
                ("member.pk8", &member[..]),
                ("member.pub", &member_public.0[..]),
                ("psk.raw", &[66; 32][..]),
            ] {
                save(&directory.join(name), bytes)?;
            }
            Ok(Self {
                member,
                member_public,
                peers,
            })
        }
        fn noise(&self, role: security::Role) -> Result<credentials::NoiseIdentity> {
            credentials::NoiseIdentity::new(
                Zeroizing::new(if role == security::Role::Initiator {
                    [11; 32]
                } else {
                    [22; 32]
                }),
                if role == security::Role::Initiator {
                    self.peers.responder
                } else {
                    self.peers.initiator
                },
                hs::Profile::Ik,
                None,
            )
        }
    }

    struct Pipe {
        socket: UnixDatagram,
        host: Arc<Host>,
    }
    impl AsRawFd for Pipe {
        fn as_raw_fd(&self) -> std::os::fd::RawFd {
            self.socket.as_raw_fd()
        }
    }
    impl Drop for Pipe {
        fn drop(&mut self) {
            self.host.live.fetch_sub(1, Ordering::SeqCst);
        }
    }
    impl PacketDevice for Pipe {
        type Error = io::Error;
        fn layer(&self) -> PacketLayer {
            PacketLayer::Ip
        }
        fn receive(&mut self, bytes: &mut [u8]) -> Result<Option<usize>> {
            match self.socket.recv(bytes) {
                Ok(length) => Ok(Some(length)),
                Err(value) if value.kind() == io::ErrorKind::WouldBlock => Ok(None),
                Err(value) => Err(value),
            }
        }
        fn transmit(&mut self, bytes: &[u8]) -> Result {
            require(
                self.socket.send(bytes)? == bytes.len(),
                "partial native packet write",
            )
        }
    }
    #[derive(Default)]
    struct Host {
        application: Mutex<Option<UnixDatagram>>,
        opened: AtomicUsize,
        live: AtomicUsize,
    }
    impl Host {
        fn attachment(self: &Arc<Self>) -> Attachment {
            let host = self.clone();
            Attachment::readable(PacketLayer::Ip, move || {
                let (socket, application) = UnixDatagram::pair()?;
                socket.set_nonblocking(true)?;
                application.set_nonblocking(true)?;
                *lock(&host.application) = Some(application);
                host.opened.fetch_add(1, Ordering::SeqCst);
                host.live.fetch_add(1, Ordering::SeqCst);
                Ok(l2tunnel_client_core::swift::Native::new(Pipe {
                    socket,
                    host: host.clone(),
                }))
            })
        }
        fn send(&self, bytes: &[u8]) -> Result {
            let held = lock(&self.application);
            let socket = held
                .as_ref()
                .ok_or_else(|| error("native attachment missing"))?;
            require(
                socket.send(bytes)? == bytes.len(),
                "partial host packet write",
            )
        }
        async fn expect(&self, expected: &[u8]) -> Result {
            timeout(Duration::from_secs(3), async {
                let mut bytes = [0; l2tunnel_device::READ_BUFFER_BYTES];
                loop {
                    let received = lock(&self.application)
                        .as_ref()
                        .ok_or_else(|| error("native attachment missing"))?
                        .recv(&mut bytes);
                    match received {
                        Ok(length) => {
                            return require(
                                &bytes[..length] == expected,
                                "native bytes/order changed",
                            );
                        }
                        Err(value) if value.kind() == io::ErrorKind::WouldBlock => {
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        }
                        Err(value) => return Err(value),
                    }
                }
            })
            .await
            .map_err(error)?
        }
        fn empty(&self) -> Result {
            let mut bytes = [0; 1601];
            let received = lock(&self.application)
                .as_ref()
                .ok_or_else(|| error("native attachment missing"))?
                .recv(&mut bytes);
            require(
                matches!(received, Err(ref value) if value.kind() == io::ErrorKind::WouldBlock),
                "unexpected duplicate or old-session native output",
            )
        }
    }

    fn connection() -> ConnectionConfig {
        ConnectionConfig {
            layer: PacketLayer::Ip,
            duplex: Duplex::Full,
            max_packet: 1600,
            compression: Compression::None,
            handshake_timeout: Duration::from_secs(3),
        }
    }
    fn overhead(appearance: Appearance) -> usize {
        28 + if appearance == Appearance::QuicLike {
            13
        } else {
            14
        } + 9
            + security::COMMON_PREFIX_BYTES
            + 16
    }
    fn raw_settings(
        appearance: Appearance,
        addresses: [SocketAddr; 2],
        keys: &Keys,
    ) -> Result<secure_udp::Settings> {
        let header = if appearance == Appearance::QuicLike {
            13
        } else {
            14
        };
        let handshake = if appearance == Appearance::QuicLike {
            30
        } else {
            14
        };
        let cover = secure_udp::Cover {
            appearance,
            initiator_connection: ConnectionId([1; 8]),
            responder_connection: ConnectionId([2; 8]),
            initiator_ssrc: Ssrc(101),
            responder_ssrc: Ssrc(202),
            payload_type: 96,
            max_packet_bytes: MAXIMUM_MTU - 28 - header + handshake,
            max_protected_bytes: MAXIMUM_MTU - 28 - header,
        };
        let mut gate = gate::Config::new(
            gate::Path {
                client: addresses[0],
                server: addresses[1],
            },
            [3; 32],
            1,
        )
        .map_err(error)?;
        gate.path_mtu = 1500;
        gate.outer_overhead = cover.bootstrap_overhead(false)?;
        gate.arq.max_source_bytes = (gate.path_mtu
            - gate.outer_overhead
            - gate::CONTROL_OVERHEAD
            - l2tunnel_recovery::DATA_HEADER_BYTES)
            .min(1200);
        gate.arq.send_bytes = gate.arq.max_source_bytes * gate.arq.send_records;
        gate.arq.receive_bytes = gate.arq.max_source_bytes * gate.arq.receive_records;
        gate.handshake_timeout = connection().handshake_timeout;
        gate.cookie_ttl = gate.cookie_ttl.min(gate.handshake_timeout);
        gate.maximum_rto = gate.maximum_rto.min(gate.handshake_timeout);
        gate.initial_rto = gate.initial_rto.min(gate.maximum_rto);
        Ok(secure_udp::Settings {
            gate,
            cover,
            profile: hs::Profile::Ik,
            application: ConfigDigest([31; 32]),
            outer: [4; 32],
            member: keys.member_public,
            membership: secure_udp::Membership {
                retry_interval: Duration::from_millis(100),
                max_attempts: 128,
                receive_interval: Duration::from_millis(10),
                receive_packets_per_interval: 128,
            },
            bootstrap_receive_packets_per_interval: 128,
        })
    }
    fn direction(appearance: Appearance, forward: bool) -> policy::Direction {
        policy::Direction {
            records: records::Config {
                channels: if forward { 2 } else { 3 },
                layer: records::Layer::Ip,
                max_native: 1600,
                codec: l2tunnel_swift::Config {
                    datagram_bytes: 1500 - overhead(appearance),
                    window: if forward { 7 } else { 11 },
                    repair_numerator: if forward { 1 } else { 2 },
                    repair_denominator: if forward { 3 } else { 7 },
                    flow_sources: 64,
                    queue_bytes: 65_536,
                    max_packet: 1600 + l2tunnel_swift::header::MAX_EXPANSION,
                    flush_micros: 1000,
                    feedback_micros: 5000,
                    tail_micros: 10000,
                    min_rto_micros: 20000,
                    max_rto_micros: 1_000_000,
                },
            },
            bytes_per_second: if forward { 1_250_001 } else { 625_003 },
        }
    }
    fn runtime(appearance: Appearance) -> transport::Config {
        let recovery = l2tunnel_recovery::ArqConfig {
            max_source_bytes: 256,
            send_bytes: 8192,
            receive_bytes: 8192,
            send_records: 32,
            receive_records: 32,
            ..Default::default()
        };
        let base = delivery::Settings {
            recovery,
            interval: Duration::from_millis(10),
            packets_per_interval: 4,
            bytes_per_interval: 2048,
            wire_overhead: overhead(appearance),
        };
        let entry = messages::Settings {
            delivery: delivery::Settings {
                wire_overhead: base.wire_overhead + control_streams::HEADER_BYTES,
                ..base
            },
            path_mtu: 1500,
            max_message_bytes: 4096,
            max_outbound_messages: 4,
            max_outbound_bytes: 131_072,
            max_fragments: 32,
            max_reassembly_bytes: 16_384,
            max_incomplete_messages: 2,
            message_lifetime: Duration::from_secs(5),
            work_per_call: 8,
        };
        transport::Config {
            path_mtu: 1500,
            send: direction(appearance, true),
            receive: direction(appearance, false),
            policy: policy::Settings {
                transaction_micros: 10_000_000,
                max_outbound: 32,
            },
            security: security::Limits {
                max_body_bytes: MAXIMUM_MTU - overhead(appearance),
                packets_per_key: security::MAX_PACKETS_PER_KEY,
                max_body_bytes_per_key: security::MAX_BODY_BYTES_PER_KEY,
            },
            control: base,
            streams: Some(control::Settings {
                streams: [entry; 3],
            }),
            control_epoch: security::Epoch(1),
            data_epoch: security::Epoch(1),
            wire: transport::WireBudget { burst_bytes: 8192 },
            work: transport::WorkBudget {
                receive_interval: Duration::from_millis(1),
                receive_packets: 256,
                send_batch: 64,
                native_read_batch: 64,
                native_write_batch: 64,
            },
            rolling_work: None,
            ack_coalescing: None,
            native: transport::NativeBudget {
                pending_packets: 64,
                pending_bytes: 102_400,
                stall_timeout: Duration::from_secs(10),
            },
            lifetime: transport::Lifetime {
                lease: Duration::from_secs(60),
                ping_interval: Duration::from_millis(10),
                pong_timeout: Duration::from_secs(5),
            },
            report_interval: None,
        }
    }
    fn parameters() -> transaction_profile::Parameters {
        transaction_profile::Parameters {
            protocol: transaction::Settings {
                retry_ms: 10,
                phase_timeout_ms: 500,
                reconcile_timeout_ms: 1000,
            },
            max_operation_ms: 1500,
            retained_bytes: 16 * 1024 * 1024,
        }
    }
    fn descriptors(appearance: Appearance, count: usize) -> Result<Vec<Descriptor>> {
        let mut values = Vec::with_capacity(count);
        for index in 0..count {
            let mut forward = direction(appearance, true);
            let mut reverse = direction(appearance, false);
            forward.bytes_per_second += u64::try_from(index).map_err(error)? * 2;
            if index == 1 {
                forward.records.channels = 4;
                reverse.records.channels = 1;
            }
            if index == 63 {
                forward.records.channels = 64;
                reverse.records.channels = 64;
            }
            values.push(Descriptor::new(1500, forward, reverse).map_err(error)?);
        }
        Ok(values)
    }

    #[derive(Default)]
    struct Tasks(Vec<JoinHandle<Result>>);
    impl Tasks {
        fn add(&mut self, task: JoinHandle<Result>) {
            self.0.push(task);
        }
        async fn stop(&mut self) {
            for task in &self.0 {
                task.abort();
            }
            for task in self.0.drain(..) {
                let _ = task.await;
            }
        }
    }
    impl Drop for Tasks {
        fn drop(&mut self) {
            for task in &self.0 {
                task.abort();
            }
        }
    }

    struct Fixture {
        handles: [Handle; 2],
        hosts: [Arc<Host>; 2],
        tasks: Tasks,
        addresses: [SocketAddr; 2],
        profile: transaction_profile::Profile,
        initial: Configuration,
        target: Configuration,
        outside: Configuration,
        foreign: Configuration,
        api: [PathBuf; 2],
        requests: [Arc<AtomicU64>; 2],
    }
    impl Fixture {
        async fn start(directory: &Path, appearance: Appearance, keys: &Keys) -> Result<Self> {
            let held = [
                UdpSocket::bind("127.0.0.1:0")?,
                UdpSocket::bind("127.0.0.1:0")?,
            ];
            let addresses = [held[0].local_addr()?, held[1].local_addr()?];
            let initiator = runtime(appearance);
            let responder = transport::Config {
                send: initiator.receive,
                receive: initiator.send,
                ..initiator
            };
            let values = descriptors(appearance, 2)?;
            let profile = transaction_profile::Profile::new(
                connection(),
                raw_settings(appearance, addresses, keys)?,
                keys.peers,
                initiator,
                responder,
                Catalog::new(values[0], &values).map_err(error)?,
                parameters(),
            )?;
            let initial = profile.initial();
            let target = Configuration::new(profile.envelope(), values[1]).map_err(error)?;
            let mut unlisted = values[1].forward();
            unlisted.bytes_per_second += 1;
            let outside = Configuration::new(
                profile.envelope(),
                Descriptor::new(1500, unlisted, values[1].reverse()).map_err(error)?,
            )
            .map_err(error)?;
            let mut foreign = *profile.envelope().as_bytes();
            foreign[0] ^= 1;
            let foreign =
                Configuration::new(EnvelopeDigest::new(foreign), values[1]).map_err(error)?;
            let hosts = [Arc::new(Host::default()), Arc::new(Host::default())];
            let client = Prepared::secure_udp_transaction_client(
                profile.clone(),
                credentials::Client::new(
                    keys.noise(security::Role::Initiator)?,
                    l2tunnel_identity::IdentityKey::from_pkcs8(&keys.member).map_err(error)?,
                    credentials::Secret32::new(Zeroizing::new([44; 32]))?,
                )?,
                hosts[0].attachment(),
            )?;
            let server = Prepared::secure_udp_transaction_server(
                profile.clone(),
                credentials::Server::new(
                    keys.noise(security::Role::Responder)?,
                    credentials::Secret32::new(Zeroizing::new([44; 32]))?,
                    credentials::Secret32::new(Zeroizing::new([55; 32]))?,
                )?,
                hosts[1].attachment(),
            )?;
            let (a, a_run) = service::channel();
            let (b, b_run) = service::channel();
            let handles = [a, b];
            let mut tasks = Tasks::default();
            tasks.add(tokio::spawn(a_run));
            tasks.add(tokio::spawn(b_run));
            drop(held);
            let left = handles[0]
                .connect(client, handles[0].next_key().map_err(submit)?)
                .map_err(submit)?;
            let right = handles[1]
                .connect(server, handles[1].next_key().map_err(submit)?)
                .map_err(submit)?;
            let connected = |handle: Handle, id| async move {
                match timeout(Duration::from_secs(4), handle.wait(id))
                    .await
                    .map_err(error)?
                    .map_err(submit)?
                {
                    Completed::Connected { .. } => Ok(()),
                    _ => Err(error("actual fixture did not become ready")),
                }
            };
            tokio::try_join!(
                connected(handles[0].clone(), left.operation),
                connected(handles[1].clone(), right.operation)
            )?;
            let api = [directory.join("client.sock"), directory.join("server.sock")];
            let requests = [Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0))];
            for side in 0..2 {
                let server = local::Server::bind(&api[side])?;
                let handle = handles[side].clone();
                let requests = requests[side].clone();
                tasks.add(tokio::spawn(async move {
                    server
                        .serve(move |request| {
                            requests.fetch_add(1, Ordering::SeqCst);
                            let handle = handle.clone();
                            async move { handle.lifecycle_request(request).await }
                        })
                        .await
                }));
            }
            Ok(Self {
                handles,
                hosts,
                tasks,
                addresses,
                profile,
                initial,
                target,
                outside,
                foreign,
                api,
                requests,
            })
        }
        fn status(&self, side: usize) -> Result<transaction_status::Status> {
            self.handles[side]
                .snapshot()
                .runtime
                .as_ref()
                .and_then(Observation::secure_udp_transaction)
                .ok_or_else(|| error("missing actual generic observation"))?
                .status()
        }
        async fn follower(&self, expected: Configuration, epoch: u64) -> Result {
            let mut changed = self.handles[1].subscribe();
            timeout(Duration::from_secs(3), async {
                loop {
                    let status = self.status(1)?;
                    if status.epoch == Some(epoch)
                        && status.phase == Some(transaction_status::Phase::Idle)
                        && status.operation.is_none()
                    {
                        return current(&status, expected, epoch);
                    }
                    changed.changed().await.map_err(error)?;
                }
            })
            .await
            .map_err(error)?
        }
        async fn traffic(&self, widths: [usize; 2], marker: u8) -> Result {
            for (side, width) in widths.into_iter().enumerate() {
                for channel in 0..width {
                    let mut matched = None;
                    for port in 1..=u16::MAX {
                        let mut packet = vec![marker; 512];
                        packet[..28].fill(0);
                        packet[0] = 0x45;
                        packet[2..4].copy_from_slice(&512u16.to_be_bytes());
                        packet[8] = 64;
                        packet[9] = 17;
                        packet[12..20].copy_from_slice(&[198, 18, 0, 1, 198, 18, 0, 2]);
                        packet[20..22].copy_from_slice(&port.to_be_bytes());
                        packet[22..24].copy_from_slice(&[0x91, marker]);
                        if l2tunnel_swift::flow::classify_ip(&packet, width) == channel {
                            matched = Some(packet);
                            break;
                        }
                    }
                    let packet =
                        matched.ok_or_else(|| error("bounded classifier search exhausted"))?;
                    self.hosts[side].send(&packet)?;
                    self.hosts[1 - side].expect(&packet).await?;
                }
            }
            for host in &self.hosts {
                host.empty()?;
            }
            Ok(())
        }
        async fn close(&mut self) -> Result {
            self.tasks.stop().await;
            require(
                self.hosts
                    .iter()
                    .all(|host| host.live.load(Ordering::SeqCst) == 0),
                "fixture device leaked",
            )
        }
    }
    fn current(status: &transaction_status::Status, expected: Configuration, epoch: u64) -> Result {
        require(
            status.running
                && status.configuration_change
                && status.epoch == Some(epoch)
                && status.phase == Some(transaction_status::Phase::Idle)
                && status.operation.is_none()
                && status
                    .current
                    .as_ref()
                    .map(transaction_status::CanonicalConfiguration::configuration)
                    .transpose()?
                    == Some(expected)
                && status.physical_scope.map(|scope| scope.epoch) == Some(epoch),
            "actual committed/physical state differs",
        )?;
        require(
            !status.cross_profile_switching
                && !status.retained_state_recovery
                && !status.fresh_rekey,
            "probe must not overclaim broader capabilities",
        )
    }

    struct Capture {
        bytes: Vec<u8>,
        overflow: bool,
    }
    fn capture(mut reader: impl Read, maximum: usize, overflow: &AtomicBool) -> Result<Capture> {
        let mut bytes = Vec::new();
        let mut exceeded = false;
        let mut buffer = [0; 8192];
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            let room = maximum.saturating_sub(bytes.len());
            bytes.extend_from_slice(&buffer[..count.min(room)]);
            if count > room {
                exceeded = true;
                overflow.store(true, Ordering::SeqCst);
            }
        }
        Ok(Capture {
            bytes,
            overflow: exceeded,
        })
    }
    struct OwnedChild {
        child: Child,
        stdout: Option<thread::JoinHandle<Result<Capture>>>,
        stderr: Option<thread::JoinHandle<Result<Capture>>>,
        overflow: Arc<AtomicBool>,
    }
    impl OwnedChild {
        fn spawn(binary: &Path, arguments: &[OsString]) -> Result<Self> {
            let child = Command::new(binary)
                .args(arguments)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            let mut owned = Self {
                child,
                stdout: None,
                stderr: None,
                overflow: Arc::new(AtomicBool::new(false)),
            };
            let stdout = owned
                .child
                .stdout
                .take()
                .ok_or_else(|| error("missing child stdout"))?;
            let stderr = owned
                .child
                .stderr
                .take()
                .ok_or_else(|| error("missing child stderr"))?;
            let flag = owned.overflow.clone();
            owned.stdout = Some(
                thread::Builder::new()
                    .name("generic-probe-stdout".into())
                    .spawn(move || capture(stdout, STDOUT_LIMIT, &flag))?,
            );
            let flag = owned.overflow.clone();
            owned.stderr = Some(
                thread::Builder::new()
                    .name("generic-probe-stderr".into())
                    .spawn(move || capture(stderr, STDERR_LIMIT, &flag))?,
            );
            Ok(owned)
        }
        async fn finish(mut self) -> Result<Execution> {
            let deadline = Instant::now()
                .checked_add(Duration::from_secs(8))
                .ok_or_else(|| error("child deadline overflow"))?;
            let status = loop {
                if let Some(status) = self.child.try_wait()? {
                    break status;
                }
                if self.overflow.load(Ordering::SeqCst) {
                    return Err(error("CLI output exceeded hard bound"));
                }
                if Instant::now() >= deadline {
                    return Err(error("CLI child original deadline elapsed"));
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            };
            let stdout = self
                .stdout
                .take()
                .ok_or_else(|| error("missing stdout owner"))?
                .join()
                .map_err(|_| error("stdout reader panicked"))??;
            let stderr = self
                .stderr
                .take()
                .ok_or_else(|| error("missing stderr owner"))?
                .join()
                .map_err(|_| error("stderr reader panicked"))??;
            require(
                !stdout.overflow && !stderr.overflow,
                "CLI output exceeded hard bound",
            )?;
            Ok(Execution {
                status,
                stdout: stdout.bytes,
                stderr: stderr.bytes,
            })
        }
    }
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            if !matches!(self.child.try_wait(), Ok(Some(_))) {
                let _ = self.child.kill();
            }
            let _ = self.child.wait();
            if let Some(reader) = self.stdout.take() {
                let _ = reader.join();
            }
            if let Some(reader) = self.stderr.take() {
                let _ = reader.join();
            }
        }
    }
    struct Execution {
        status: ExitStatus,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    }
    impl Execution {
        fn json(&self) -> Result<Value> {
            serde_json::from_slice(&self.stdout).map_err(error)
        }
        fn response(&self) -> Result<local::Response> {
            serde_json::from_slice(&self.stdout).map_err(error)
        }
    }
    struct Runner {
        binary: PathBuf,
        directory: PathBuf,
        executions: usize,
    }
    impl Runner {
        async fn command(
            &mut self,
            label: &str,
            arguments: Vec<OsString>,
            success: bool,
        ) -> Result<Execution> {
            self.executions = self
                .executions
                .checked_add(1)
                .ok_or_else(|| error("probe ordinal exhausted"))?;
            let prefix = format!("{:03}-{label}", self.executions);
            let result = OwnedChild::spawn(&self.binary, &arguments)?.finish().await;
            match result {
                Ok(execution) => {
                    save(
                        &self.directory.join(format!("{prefix}.stdout")),
                        &execution.stdout,
                    )?;
                    save(
                        &self.directory.join(format!("{prefix}.stderr")),
                        &execution.stderr,
                    )?;
                    save(&self.directory.join(format!("{prefix}.json")), &serde_json::to_vec(&json!({
                        "label":label,"code":execution.status.code(),"success":execution.status.success(),
                        "stdout_bytes":execution.stdout.len(),"stderr_bytes":execution.stderr.len()
                    })).map_err(error)?)?;
                    require(
                        execution.status.success() == success,
                        &format!("unexpected CLI exit for {prefix}"),
                    )?;
                    Ok(execution)
                }
                Err(value) => {
                    save(&self.directory.join(format!("{prefix}.json")), &serde_json::to_vec(&json!({
                        "label":label,"status":"observer_failure","kind":format!("{:?}",value.kind())
                    })).map_err(error)?)?;
                    Err(value)
                }
            }
        }
        async fn api(
            &mut self,
            label: &str,
            path: &Path,
            command: &str,
            version: Option<u16>,
            configuration: Option<Configuration>,
            success: bool,
        ) -> Result<Execution> {
            let mut args = vec![
                command.into(),
                "--control-socket".into(),
                path.as_os_str().to_owned(),
            ];
            if let Some(version) = version {
                args.extend(["--api-version".into(), version.to_string().into()]);
            }
            if let Some(configuration) = configuration {
                args.extend([
                    "--configuration".into(),
                    transaction_status::CanonicalConfiguration::from_configuration(configuration)?
                        .as_str()
                        .into(),
                ]);
            }
            self.command(label, args, success).await
        }
    }

    fn direction_json(value: policy::Direction) -> Value {
        let c = value.records.codec;
        json!({"channels":value.records.channels,"layer":"ip","max_native":value.records.max_native,
            "bytes_per_second":value.bytes_per_second,"datagram_bytes":c.datagram_bytes,"window":c.window,
            "repair_numerator":c.repair_numerator,"repair_denominator":c.repair_denominator,
            "flow_sources":c.flow_sources,"queue_bytes":c.queue_bytes,"max_packet":c.max_packet,
            "flush_micros":c.flush_micros,"feedback_micros":c.feedback_micros,"tail_micros":c.tail_micros,
            "min_rto_micros":c.min_rto_micros,"max_rto_micros":c.max_rto_micros})
    }
    fn message_json(entry: messages::Settings) -> Value {
        json!({"max_message_bytes":entry.max_message_bytes,"max_outbound_messages":entry.max_outbound_messages,
            "max_outbound_bytes":entry.max_outbound_bytes,"max_fragments":entry.max_fragments,
            "max_reassembly_bytes":entry.max_reassembly_bytes,"max_incomplete_messages":entry.max_incomplete_messages,
            "message_lifetime_micros":entry.message_lifetime.as_micros(),"work_per_call":entry.work_per_call})
    }
    fn plan_json(appearance: Appearance, count: usize) -> Result<Value> {
        let mut values = descriptors(appearance, count)?;
        values.reverse();
        let catalog = values
            .iter()
            .map(|value| {
                json!({"path_mtu":value.path_mtu(),
            "forward":direction_json(value.forward()),"reverse":direction_json(value.reverse())})
            })
            .collect::<Vec<_>>();
        let value = runtime(appearance);
        let arq = value.control.recovery;
        let streams = value
            .streams
            .ok_or_else(|| error("fixture requires explicit streams"))?
            .streams;
        let timing = parameters();
        Ok(
            json!({"version":1,"backend":"generic_swift_v1","initial_index":count-1,"catalog":catalog,
            "transaction":{"retry_ms":timing.protocol.retry_ms,"phase_timeout_ms":timing.protocol.phase_timeout_ms,
                "reconcile_timeout_ms":timing.protocol.reconcile_timeout_ms,"max_operation_ms":timing.max_operation_ms,
                "retained_bytes":timing.retained_bytes},
            "runtime":{"control_epoch":value.control_epoch.0,"data_epoch":value.data_epoch.0,
                "legacy_policy":{"transaction_micros":value.policy.transaction_micros,"max_outbound":value.policy.max_outbound},
                "security":{"packets_per_key":value.security.packets_per_key,"max_body_bytes_per_key":value.security.max_body_bytes_per_key},
                "control":{"recovery":{"max_source_bytes":arq.max_source_bytes,"send_bytes":arq.send_bytes,
                    "receive_bytes":arq.receive_bytes,"send_records":arq.send_records,"receive_records":arq.receive_records,
                    "initial_rto_micros":arq.initial_rto.as_micros(),"maximum_rto_micros":arq.maximum_rto.as_micros(),
                    "ack_delay_micros":arq.ack_delay.as_micros(),"max_retries":arq.max_retries},
                    "interval_micros":value.control.interval.as_micros(),"packets_per_interval":value.control.packets_per_interval,
                    "bytes_per_interval":value.control.bytes_per_interval},
                "streams":{"transaction":message_json(streams[0]),"liveness":message_json(streams[1]),"data_feedback":message_json(streams[2])},
                "wire":{"initiator_burst_bytes":value.wire.burst_bytes,"responder_burst_bytes":value.wire.burst_bytes},
                "work":{"receive_interval_micros":value.work.receive_interval.as_micros(),"receive_packets":value.work.receive_packets,
                    "send_batch":value.work.send_batch,"native_read_batch":value.work.native_read_batch,"native_write_batch":value.work.native_write_batch},
                "native":{"pending_packets":value.native.pending_packets,"pending_bytes":value.native.pending_bytes,"stall_timeout_micros":value.native.stall_timeout.as_micros()},
                "lifetime":{"lease_micros":value.lifetime.lease.as_micros(),"ping_interval_micros":value.lifetime.ping_interval.as_micros(),
                    "pong_timeout_micros":value.lifetime.pong_timeout.as_micros()},"report_interval_micros":null}}),
        )
    }
    fn inspection_args(
        directory: &Path,
        file: &Path,
        appearance: Appearance,
        addresses: [SocketAddr; 2],
        responder: bool,
        psk: bool,
    ) -> Result<Vec<OsString>> {
        let mut args = vec![
            "inspect-swift-transaction-plan".into(),
            "--role".into(),
            if responder {
                "serve".into()
            } else {
                "connect".into()
            },
            "--carrier".into(),
            if appearance == Appearance::QuicLike {
                "quic-like".into()
            } else {
                "media-like".into()
            },
            "--record-profile".into(),
            "swift".into(),
            "--duplex".into(),
            "full".into(),
            "--compression".into(),
            "off".into(),
            "--layer".into(),
            "tun".into(),
            "--max-packet".into(),
            "1600".into(),
            "--max-path-mtu".into(),
            MAXIMUM_MTU.to_string().into(),
            "--udp-bind".into(),
            addresses[usize::from(responder)].to_string().into(),
            "--udp-peer".into(),
            addresses[usize::from(!responder)].to_string().into(),
            "--noise-profile".into(),
            if psk { "ikpsk2".into() } else { "ik".into() },
            "--noise-private-key-file".into(),
            directory
                .join(if responder {
                    "responder.raw"
                } else {
                    "initiator.raw"
                })
                .into_os_string(),
            "--noise-peer-key-file".into(),
            directory
                .join(if responder {
                    "initiator.pub"
                } else {
                    "responder.pub"
                })
                .into_os_string(),
            if responder {
                "--allow-key".into()
            } else {
                "--identity".into()
            },
            directory
                .join(if responder {
                    "member.pub"
                } else {
                    "member.pk8"
                })
                .into_os_string(),
            "--swift-transaction-plan".into(),
            file.as_os_str().to_owned(),
        ];
        if psk {
            args.extend([
                "--noise-psk-file".into(),
                directory.join("psk.raw").into_os_string(),
            ]);
        }
        Ok(args)
    }
    fn check_inspection(value: &Value, appearance: Appearance) -> Result {
        require(
            value["event"] == "secure_udp_transaction_plan"
                && value["schema"] == 1
                && value["requested"] == true
                && value["validated"] == true
                && value["authenticated"] == false
                && value["resource_preallocation_complete"] == false
                && value["catalog_members"] == 64,
            "inspection status or full catalog missing",
        )?;
        let configurations = value["configurations"]
            .as_array()
            .ok_or_else(|| error("missing inspection catalog"))?;
        require(
            configurations.len() == 64,
            "inspection truncated the catalog",
        )?;
        let expected_values = descriptors(appearance, 64)?;
        let expected_catalog = Catalog::new(expected_values[0], &expected_values).map_err(error)?;
        let mut envelope = None;
        let mut decoded = Vec::new();
        for encoded in configurations {
            let checked: transaction_status::CanonicalConfiguration =
                serde_json::from_value(encoded.clone()).map_err(error)?;
            let actual = checked.configuration()?;
            if let Some(previous) = envelope {
                require(
                    previous == actual.envelope(),
                    "catalog has conflicting envelopes",
                )?;
            }
            envelope = Some(actual.envelope());
            decoded.push(actual.descriptor());
        }
        require(
            decoded == expected_catalog.descriptors(),
            "inspection changed complete descriptors or canonical order",
        )?;
        let initial: transaction_status::CanonicalConfiguration =
            serde_json::from_value(value["initial"].clone()).map_err(error)?;
        require(
            initial.configuration()?.descriptor() == expected_values[0],
            "initial_index was applied after sorting",
        )?;
        require(
            value["parameters"]["retained_bytes"] == parameters().retained_bytes,
            "inspection changed explicit transaction resources",
        )
    }
    async fn inspections(runner: &mut Runner, directory: &Path, appearance: Appearance) -> Result {
        let held = [
            UdpSocket::bind("127.0.0.1:0")?,
            UdpSocket::bind("127.0.0.1:0")?,
        ];
        let addresses = [held[0].local_addr()?, held[1].local_addr()?];
        let mut document = plan_json(appearance, 64)?;
        let file = directory.join("full-plan.json");
        let serialized = serde_json::to_vec(&document).map_err(error)?;
        require(
            serialized.len() <= 256 * 1024,
            "full64 fixture does not fit frozen plan limit",
        )?;
        save(&file, &serialized)?;
        let mut baseline = None;
        for psk in [false, true] {
            let mut roles = Vec::new();
            for responder in [false, true] {
                let result = runner
                    .command(
                        "inspect-full64",
                        inspection_args(directory, &file, appearance, addresses, responder, psk)?,
                        true,
                    )
                    .await?;
                let value = result.json()?;
                check_inspection(&value, appearance)?;
                roles.push(value);
            }
            for field in [
                "configuration",
                "envelope",
                "catalog",
                "data_digest",
                "initial",
                "configurations",
            ] {
                require(
                    roles[0][field] == roles[1][field],
                    "role ordering changed inspection identity",
                )?;
            }
            if !psk {
                baseline = Some(roles.remove(0));
            }
        }
        let baseline = baseline.ok_or_else(|| error("missing inspection baseline"))?;
        document["catalog"]
            .as_array_mut()
            .ok_or_else(|| error("missing catalog fixture"))?
            .reverse();
        document["initial_index"] = json!(0);
        document["runtime"]["report_interval_micros"] = json!(20_000);
        let reordered = directory.join("reordered-local-cadence.json");
        save(&reordered, &serde_json::to_vec(&document).map_err(error)?)?;
        let result = runner
            .command(
                "inspect-reordered",
                inspection_args(directory, &reordered, appearance, addresses, false, false)?,
                true,
            )
            .await?
            .json()?;
        for field in [
            "configuration",
            "envelope",
            "catalog",
            "data_digest",
            "initial",
            "configurations",
        ] {
            require(
                result[field] == baseline[field],
                "JSON ordering/local report cadence changed peer identity",
            )?;
        }
        document["runtime"]["work"]["send_batch"] = json!(1);
        let immutable = directory.join("changed-immutable.json");
        save(&immutable, &serde_json::to_vec(&document).map_err(error)?)?;
        let changed = runner
            .command(
                "inspect-immutable",
                inspection_args(directory, &immutable, appearance, addresses, false, false)?,
                true,
            )
            .await?
            .json()?;
        require(
            changed["configuration"] != baseline["configuration"]
                && changed["envelope"] != baseline["envelope"],
            "real immutable contract change was omitted from peer identity",
        )?;
        let mut negative = plan_json(appearance, 65)?;
        let too_many = directory.join("sixty-five.json");
        save(&too_many, &serde_json::to_vec(&negative).map_err(error)?)?;
        runner
            .command(
                "reject65",
                inspection_args(directory, &too_many, appearance, addresses, false, false)?,
                false,
            )
            .await?;
        negative = plan_json(appearance, 64)?;
        negative["runtime"]
            .as_object_mut()
            .ok_or_else(|| error("missing runtime fixture"))?
            .remove("report_interval_micros");
        let missing = directory.join("missing-nullable.json");
        save(&missing, &serde_json::to_vec(&negative).map_err(error)?)?;
        runner
            .command(
                "reject-missing-nullable",
                inspection_args(directory, &missing, appearance, addresses, false, false)?,
                false,
            )
            .await?;
        let duplicate = directory.join("duplicate-field.json");
        let text = String::from_utf8(serialized.clone()).map_err(error)?;
        save(
            &duplicate,
            text.replacen("\"version\":1", "\"version\":1,\"version\":1", 1)
                .as_bytes(),
        )?;
        runner
            .command(
                "reject-duplicate",
                inspection_args(directory, &duplicate, appearance, addresses, false, false)?,
                false,
            )
            .await?;
        let oversized = directory.join("oversized.json");
        let mut bytes = serialized;
        bytes.resize(256 * 1024 + 1, b' ');
        save(&oversized, &bytes)?;
        runner
            .command(
                "reject-oversized",
                inspection_args(directory, &oversized, appearance, addresses, false, false)?,
                false,
            )
            .await?;
        let mut conflict = inspection_args(directory, &file, appearance, addresses, false, false)?;
        conflict.extend(["--path-mtu".into(), "1500".into()]);
        runner
            .command("reject-conflicting-policy", conflict, false)
            .await?;
        let mut device = inspection_args(directory, &file, appearance, addresses, false, false)?;
        device.extend(["--device".into(), "must-not-open".into()]);
        runner
            .command("reject-inspection-device", device, false)
            .await?;
        // Both exact endpoints remain bound for every inspection/negative command.
        require(
            held[0].local_addr()? == addresses[0] && held[1].local_addr()? == addresses[1],
            "inspection fixture lost endpoint ownership",
        )
    }

    fn transaction_response(execution: &Execution) -> Result<transaction_status::Status> {
        let response = execution.response()?;
        require(
            response.version == local::TRANSACTION_VERSION && response.ok,
            "actual v3 command refused",
        )?;
        let state = response.state.ok_or_else(|| error("missing v3 state"))?;
        require(
            state.swift.is_none() && state.secure_udp.is_none(),
            "generic response projected a legacy backend",
        )?;
        state
            .transaction
            .ok_or_else(|| error("missing actual transaction DTO"))
    }
    impl Runner {
        async fn pair_lifecycle(
            &mut self,
            paths: &[PathBuf; 2],
            command: &str,
        ) -> Result<[Execution; 2]> {
            let arguments = |path: &Path| {
                vec![
                    OsString::from(command),
                    OsString::from("--control-socket"),
                    path.as_os_str().to_owned(),
                    OsString::from("--api-version"),
                    OsString::from("3"),
                ]
            };
            let left = OwnedChild::spawn(&self.binary, &arguments(&paths[0]))?;
            let right = OwnedChild::spawn(&self.binary, &arguments(&paths[1]))?;
            let (left, right) = tokio::join!(left.finish(), right.finish());
            let results = [left?, right?];
            for (side, result) in results.iter().enumerate() {
                self.executions = self
                    .executions
                    .checked_add(1)
                    .ok_or_else(|| error("probe ordinal exhausted"))?;
                let prefix = format!("{:03}-{command}-{side}", self.executions);
                save(
                    &self.directory.join(format!("{prefix}.stdout")),
                    &result.stdout,
                )?;
                save(
                    &self.directory.join(format!("{prefix}.stderr")),
                    &result.stderr,
                )?;
                save(&self.directory.join(format!("{prefix}.json")),&serde_json::to_vec(&json!({
                    "label":command,"side":side,"code":result.status.code(),"success":result.status.success()
                })).map_err(error)?)?;
                require(result.status.success(), "paired lifecycle CLI failed")?;
            }
            Ok(results)
        }
    }
    async fn exercise(runner: &mut Runner, fixture: &Fixture) -> Result<Value> {
        let before = fixture.status(0)?;
        let epoch = before
            .epoch
            .ok_or_else(|| error("missing initial runtime epoch"))?;
        current(&before, fixture.initial, epoch)?;
        require(
            before.configuration == fixture.profile.configuration()?.0,
            "service did not authenticate the actual Profile H0",
        )?;
        require(
            before.configuration != fixture.profile.data_digest().0,
            "probe must retain separate setup and data digests",
        )?;
        require(
            (before.local.as_str(), before.peer.as_str())
                == (
                    fixture.addresses[0].to_string().as_str(),
                    fixture.addresses[1].to_string().as_str(),
                ),
            "actual original socket endpoints differ",
        )?;
        require(
            fixture
                .hosts
                .iter()
                .all(|host| host.opened.load(Ordering::SeqCst) == 1),
            "deferred native attachment did not open exactly once",
        )?;
        fixture.traffic([2, 3], 31).await?;
        let execution = runner
            .api("status-v3", &fixture.api[0], "status", Some(3), None, true)
            .await?;
        current(&transaction_response(&execution)?, fixture.initial, epoch)?;
        for version in [None, Some(1), Some(2)] {
            let result = runner
                .api(
                    "wrong-version",
                    &fixture.api[0],
                    "disconnect",
                    version,
                    None,
                    false,
                )
                .await?
                .response()?;
            require(
                result.version == version.unwrap_or(1)
                    && !result.ok
                    && result.code == "requires_version_3"
                    && result.state.is_none(),
                "wrong-version request was downgraded or admitted",
            )?;
            current(&fixture.status(0)?, fixture.initial, epoch)?;
        }
        let requests = fixture.requests[0].load(Ordering::SeqCst);
        for version in [None, Some(1), Some(2), Some(4)] {
            runner
                .api(
                    "complete-c-needs-v3",
                    &fixture.api[0],
                    "switch-swift-configuration",
                    version,
                    Some(fixture.target),
                    false,
                )
                .await?;
        }
        require(
            fixture.requests[0].load(Ordering::SeqCst) == requests,
            "missing or invalid explicit v3 sent a local request",
        )?;
        let hex = transaction_status::CanonicalConfiguration::from_configuration(fixture.target)?;
        let mut invalid_digit = hex.as_str().to_owned();
        invalid_digit.replace_range(..1, "g");
        let mut bad_prefix = hex.as_str().to_owned();
        bad_prefix.replace_range(..2, "00");
        for malformed in [
            hex.as_str()[..607].to_owned(),
            format!("{}0", hex.as_str()),
            hex.as_str().to_ascii_uppercase(),
            invalid_digit,
            bad_prefix,
        ] {
            runner
                .command(
                    "malformed-c",
                    vec![
                        "switch-swift-configuration".into(),
                        "--control-socket".into(),
                        fixture.api[0].as_os_str().to_owned(),
                        "--api-version".into(),
                        "3".into(),
                        "--configuration".into(),
                        malformed.into(),
                    ],
                    false,
                )
                .await?;
        }
        require(
            fixture.requests[0].load(Ordering::SeqCst) == requests,
            "malformed complete C reached the local service",
        )?;
        for (label, configuration) in [
            ("unlisted-c", fixture.outside),
            ("foreign-envelope", fixture.foreign),
        ] {
            let outside = runner
                .api(
                    label,
                    &fixture.api[0],
                    "switch-swift-configuration",
                    Some(3),
                    Some(configuration),
                    false,
                )
                .await?
                .response()?;
            require(
                outside.version == 3 && !outside.ok && outside.code == "invalid_configuration",
                "foreign or unlisted complete C was rewritten or admitted",
            )?;
        }
        current(&fixture.status(0)?, fixture.initial, epoch)?;

        let follower = runner
            .api(
                "follower-not-coordinator",
                &fixture.api[1],
                "switch-swift-configuration",
                Some(3),
                Some(fixture.target),
                false,
            )
            .await?
            .response()?;
        require(
            follower.version == 3 && !follower.ok && follower.code == "not_coordinator",
            "follower was granted coordinator authority",
        )?;
        current(&fixture.status(1)?, fixture.initial, epoch)?;

        let requests = fixture.requests[0].load(Ordering::SeqCst);
        let switched = runner
            .api(
                "switch-target",
                &fixture.api[0],
                "switch-swift-configuration",
                Some(3),
                Some(fixture.target),
                true,
            )
            .await?;
        require(
            fixture.requests[0].load(Ordering::SeqCst) == requests + 1,
            "one complete-C command did not send exactly one local request",
        )?;
        let switched = transaction_response(&switched)?;
        current(&switched, fixture.target, epoch + 1)?;
        current(&fixture.status(0)?, fixture.target, epoch + 1)?;
        require(
            switched
                .liveness
                .as_ref()
                .and_then(|value| value.last_pong_micros)
                .is_some(),
            "actual fixed-control Pong did not progress",
        )?;
        fixture.follower(fixture.target, epoch + 1).await?;
        fixture.traffic([4, 1], 71).await?;
        let returned = runner
            .api(
                "switch-back",
                &fixture.api[0],
                "switch-swift-configuration",
                Some(3),
                Some(fixture.initial),
                true,
            )
            .await?;
        current(
            &transaction_response(&returned)?,
            fixture.initial,
            epoch + 2,
        )?;
        current(&fixture.status(0)?, fixture.initial, epoch + 2)?;
        fixture.follower(fixture.initial, epoch + 2).await?;
        fixture.traffic([2, 3], 111).await?;

        let stopped = runner.pair_lifecycle(&fixture.api, "disconnect").await?;
        for result in &stopped {
            require(
                !transaction_response(result)?.running,
                "disconnect claimed a live session",
            )?;
        }
        require(
            fixture
                .hosts
                .iter()
                .all(|host| host.live.load(Ordering::SeqCst) == 0),
            "disconnect returned before real device release",
        )?;
        let retained = fixture.status(0)?;
        require(
            !retained.running && retained.service_terminal.as_deref() == Some("Aborted"),
            "disconnect lost actual service terminal overlay",
        )?;
        let held = [
            UdpSocket::bind(fixture.addresses[0])?,
            UdpSocket::bind(fixture.addresses[1])?,
        ];
        drop(held);
        let reconnected = runner.pair_lifecycle(&fixture.api, "reconnect").await?;
        let fresh = transaction_response(&reconnected[0])?;
        current(&fresh, fixture.initial, epoch)?;
        require(
            fresh.session != before.session && fresh.transcript != before.transcript,
            "reconnect reused an old authenticated root/transcript",
        )?;
        require(
            fresh.local == before.local && fresh.peer == before.peer,
            "reconnect changed the original fixed endpoint pair",
        )?;
        require(
            fixture.hosts.iter().all(|host| {
                host.opened.load(Ordering::SeqCst) == 2 && host.live.load(Ordering::SeqCst) == 1
            }),
            "reconnect did not create fresh deferred native owners",
        )?;
        for host in &fixture.hosts {
            host.empty()?;
        }
        fixture.traffic([2, 3], 151).await?;
        Ok(
            json!({"status":"passed","original_addresses":fixture.addresses.map(|value|value.to_string()),
            "switches":2,"old_widths":[2,3],"target_widths":[4,1],"periodic_reports":false,
            "fresh_authenticated_reconnect":true,"native_attachment":"UnixDatagram PacketDevice",
            "production_connect_serve_tuntap_qualified":false}),
        )
    }
    async fn case(binary: &Path, root: &Path, appearance: Appearance) -> Result<Value> {
        let name = if appearance == Appearance::QuicLike {
            "quic-like"
        } else {
            "media-like"
        };
        let directory = root.join(name);
        private_directory(&directory)?;
        let keys = Keys::new(&directory)?;
        let mut runner = Runner {
            binary: binary.to_owned(),
            directory: directory.clone(),
            executions: 0,
        };
        inspections(&mut runner, &directory, appearance).await?;
        let mut fixture = Fixture::start(&directory, appearance, &keys).await?;
        let result = exercise(&mut runner, &fixture).await;
        let cleanup = fixture.close().await;
        let value = match (result, cleanup) {
            (Ok(value), Ok(())) => value,
            (Err(value), _) => return Err(value),
            (Ok(_), Err(value)) => return Err(value),
        };
        Ok(
            json!({"cover":name,"external_processes":runner.executions,"result":value,
            "full_inspected_catalog":64,"cleanup":"released"}),
        )
    }
    pub(super) fn main() -> Result {
        let mut binary = None;
        let mut directory = None;
        let mut args = std::env::args_os().skip(1);
        while let Some(flag) = args.next() {
            let value = args
                .next()
                .ok_or_else(|| error("expected --binary PATH --work-dir FRESH_DIRECTORY"))?;
            match flag.to_str() {
                Some("--binary") if binary.is_none() => binary = Some(PathBuf::from(value)),
                Some("--work-dir") if directory.is_none() => directory = Some(PathBuf::from(value)),
                _ => return Err(error("unknown or duplicate probe argument")),
            }
        }
        let binary =
            binary.ok_or_else(|| error("--binary is mandatory; build the daemon separately"))?;
        let directory =
            directory.ok_or_else(|| error("--work-dir is mandatory and must be fresh"))?;
        require(
            binary.is_absolute() && binary.metadata()?.is_file(),
            "binary must be an existing absolute regular file",
        )?;
        require(directory.is_absolute(), "work directory must be absolute")?;
        private_directory(&directory)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let result: Result<Vec<Value>> = runtime.block_on(async {
            let mut results = Vec::new();
            for appearance in [Appearance::QuicLike, Appearance::MediaLike] {
                results.push(case(&binary, &directory, appearance).await?);
            }
            Ok(results)
        });
        let validation = match &result {
            Ok(cases) => {
                json!({"schema":1,"status":"passed","binary":path_text(&binary)?,"cases":cases,
                "scope":"external inspection/local commands with actual shared authentication and Unix packet devices",
                "performance_qualified":false,"production_tuntap_startup_qualified":false})
            }
            Err(value) => json!({"schema":1,"status":"failed","binary":path_text(&binary)?,
                "reason":value.to_string(),"kind":format!("{:?}",value.kind())}),
        };
        save(
            &directory.join("validation.json"),
            &serde_json::to_vec_pretty(&validation).map_err(error)?,
        )?;
        result?;
        println!("{}", serde_json::to_string(&validation).map_err(error)?);
        Ok(())
    }
}

#[cfg(unix)]
fn main() -> std::io::Result<()> {
    probe::main()
}

#[cfg(not(unix))]
fn main() -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "the explicit external CLI process probe requires Unix",
    ))
}
