//! Explicit nonprivileged process/IPC probe for the selected Common control CLI.
//!
//! Run only after separately building the exact daemon. This example never runs
//! Cargo, attaches TUN/TAP, changes host networking or measures performance. Its
//! IPC peers use the real shared authentication/runtime with Unix packet devices;
//! that is distinct from successful production connect/serve device attachment.

#[cfg(unix)]
mod probe {
    use l2tunnel::record_configuration::{Catalog, Configuration, Descriptor};
    use l2tunnel_client_core::{
        Compression, ConnectionConfig, local,
        secure_udp::{self, common_status, common_transaction_profile, credentials},
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
    const STDOUT_LIMIT: usize = 256 * 1024;
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
                Ok(l2tunnel_client_core::native::Native::new(Pipe {
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
    fn overhead(_appearance: Appearance) -> usize {
        // Appearance belongs to bootstrap; final packets carry one full-tag record.
        28 + l2tunnel::secure_record::compact::AUTHENTICATED_OVERHEAD
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
            rolling_work: Some(rolling_work()),
            ack_coalescing: None,
            connection_ingress: None,
            rolling_fragments: None,
            rolling_ingress: None,
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
            report_interval: Some(Duration::from_millis(10)),
        }
    }
    fn parameters() -> transport::TransactionSettings {
        transport::TransactionSettings {
            protocol: transaction::Settings {
                retry_ms: 10,
                phase_timeout_ms: 500,
                reconcile_timeout_ms: 1000,
            },
            max_operation_ms: 1500,
            retained_bytes: 64 * 1024 * 1024,
        }
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
        deadline: Instant,
    }
    impl OwnedChild {
        fn spawn(binary: &Path, arguments: &[OsString]) -> Result<Self> {
            let deadline = Instant::now()
                .checked_add(Duration::from_secs(8))
                .ok_or_else(|| error("child deadline overflow"))?;
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
                deadline,
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
                    .name("common-probe-stdout".into())
                    .spawn(move || capture(stdout, STDOUT_LIMIT, &flag))?,
            );
            let flag = owned.overflow.clone();
            owned.stderr = Some(
                thread::Builder::new()
                    .name("common-probe-stderr".into())
                    .spawn(move || capture(stderr, STDERR_LIMIT, &flag))?,
            );
            Ok(owned)
        }
        async fn finish(mut self) -> Result<Execution> {
            let deadline = self.deadline;
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
        fn lines(&self) -> Result<Vec<Value>> {
            self.stdout
                .split(|b| *b == b'\n')
                .filter(|line| !line.is_empty())
                .map(|line| {
                    require(line.len() < 128 * 1024, "CLI JSON line exceeds bound")?;
                    serde_json::from_slice(line).map_err(error)
                })
                .collect()
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
            require(self.executions < 96, "finite case command budget exhausted")?;
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
            extra: Vec<OsString>,
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
            args.extend(extra);
            self.command(label, args, success).await
        }
    }
    fn message_json(entry: messages::Settings) -> Value {
        json!({"max_message_bytes":entry.max_message_bytes,"max_outbound_messages":entry.max_outbound_messages,
            "max_outbound_bytes":entry.max_outbound_bytes,"max_fragments":entry.max_fragments,
            "max_reassembly_bytes":entry.max_reassembly_bytes,"max_incomplete_messages":entry.max_incomplete_messages,
            "message_lifetime_micros":entry.message_lifetime.as_micros(),"work_per_call":entry.work_per_call})
    }
    fn plan_json(appearance: Appearance) -> Result<Value> {
        let mut values = descriptors(appearance)?;
        let initial = values[0];
        values.reverse();
        let initial_index = values
            .iter()
            .position(|value| *value == initial)
            .ok_or_else(|| error("missing initial"))?;
        let catalog = values
            .iter()
            .map(|descriptor| {
                let mut bytes = [0; l2tunnel::record_configuration::DESCRIPTOR_BYTES];
                descriptor.encode_into(&mut bytes).map_err(error)?;
                Ok(bytes
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>())
            })
            .collect::<Result<Vec<_>>>()?;
        let value = runtime(appearance);
        let arq = value.control.recovery;
        let streams = value
            .streams
            .ok_or_else(|| error("fixture requires explicit streams"))?
            .streams;
        let timing = parameters();
        Ok(
            json!({"version":1,"backend":"common_records_v2","initial_index":initial_index,"catalog":catalog,
            "rolling_work":{"field":rolling_work().field,"copies":rolling_work().copies,"metadata":rolling_work().metadata},
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
                    "pong_timeout_micros":value.lifetime.pong_timeout.as_micros()},"report_interval_micros":10000}}),
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
            "inspect-common-transaction-plan".into(),
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
            "common".into(),
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
            "--common-transaction-plan".into(),
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
    fn rolling_work() -> l2tunnel_fec::rolling::WorkBudget {
        l2tunnel_fec::rolling::WorkBudget {
            field: 4096,
            copies: 4096,
            metadata: 4096,
        }
    }
    fn common_direction(
        channels: u16,
        rate: u64,
    ) -> Result<l2tunnel::record_configuration::CommonDirection> {
        use l2tunnel::{pipeline as p, record_configuration as c};
        use l2tunnel_core::traffic;
        let queue = p::QueueLimits {
            bytes: 65536,
            packets: 8,
        };
        c::CommonDirection::new(
            traffic::TrafficPolicy {
                layer: traffic::NetworkLayer::Tun,
                tcp: traffic::TcpControl::System,
                qos: traffic::Qos::WeightedDeficit,
            },
            p::PipelineConfig {
                profile: p::Profile::TunDrr(p::TunQosConfig {
                    base_quantum_bytes: 1600,
                    max_weight: 1,
                    per_flow: queue,
                }),
                flows: p::FlowTableConfig {
                    capacity: 8,
                    channels,
                    mapping: p::Mapping::Crc32,
                    idle_timeout: Duration::from_secs(5),
                },
                parse: p::ParseLimits {
                    max_packet_bytes: 1600,
                    ..p::ParseLimits::default()
                },
                queue,
            },
            rate,
            65536,
            c::NativeWindow::Disabled,
        )
        .map_err(error)
    }
    fn aligned_direction(
        channels: u16,
        appearance: Appearance,
        packed: bool,
    ) -> l2tunnel::aligned::Config {
        let native = 1600;
        let symbol = if packed { 320 } else { 256 };
        let original = if packed {
            56 + 8 * 3 + symbol
        } else {
            48 + symbol
        };
        let wrapped = 44 + original;
        let fec_packet = 56 + 2 + 2 + wrapped;
        l2tunnel::aligned::Config {
            native_policy: l2tunnel::aligned::NativePolicy::RawIp,
            receiver: l2tunnel::codec::aligned_receiver::Limits {
                body: l2tunnel::codec::aligned_body::Config {
                    max_frame_bytes: native,
                    symbol_bytes: symbol,
                    elide_payload_length: false,
                    predictive: false,
                    timestamp_pair_dictionary: false,
                    independent_short_frame_bytes: 0,
                },
                channels,
                first_record: l2tunnel::codec::aligned_receiver::RecordId(0),
                first_source: l2tunnel::codec::aligned_receiver::SourceId(0),
                record_window: 32,
                source_window: 32,
                lookahead_records: 4,
                lookahead_bytes: 4 * 65535,
                lookahead_fragments: 64,
                max_fragments_per_record: 16,
                lifetime_ticks: 5_000_000,
            },
            recovery: l2tunnel_reliable::ReliableConfig {
                arq: l2tunnel_recovery::ArqConfig {
                    max_source_bytes: original,
                    send_bytes: 8 * original,
                    receive_bytes: 8 * original,
                    send_records: 8,
                    receive_records: 8,
                    initial_rto: Duration::from_millis(10),
                    maximum_rto: Duration::from_millis(100),
                    ack_delay: Duration::from_millis(1),
                    max_retries: 2,
                },
                fec: l2tunnel_fec::DecoderConfig {
                    block: l2tunnel_fec::BlockConfig {
                        max_sources: 2,
                        max_source_bytes: wrapped,
                        max_packet_bytes: fec_packet,
                        max_work_per_symbol: 1_000_000,
                    },
                    max_generations: 4,
                    max_symbols_per_generation: 3,
                    max_reserved_bytes: 1_000_000,
                    max_lifetime_ticks: 50,
                    generation_window: 32,
                },
                repair_symbols: 1,
                flush_after: Duration::from_millis(1),
                max_restored_packets: 16,
                max_restored_bytes: 16 * wrapped,
                outer_overhead_bytes: overhead(appearance),
            },
            max_recovery_packet_bytes: 8 + fec_packet,
        }
    }
    fn descriptors(appearance: Appearance) -> Result<Vec<Descriptor>> {
        use l2tunnel::{codec, record_configuration::Profile, rolling_records};
        use l2tunnel_fec::rolling;
        let forward = direction(appearance, true);
        let reverse = direction(appearance, false);
        let build = |profile, extra| {
            Descriptor::new(
                1500,
                Duplex::Full,
                common_direction(2, forward.bytes_per_second + extra)?,
                common_direction(3, reverse.bytes_per_second)?,
                profile,
            )
            .map_err(error)
        };
        let mut values = Vec::with_capacity(64);
        values.push(build(
            Profile::Swift {
                forward: forward.records,
                reverse: reverse.records,
            },
            0,
        )?);
        values.push(build(
            Profile::Aligned {
                forward: aligned_direction(2, appearance, false),
                reverse: aligned_direction(3, appearance, false),
            },
            0,
        )?);
        let packed = |channels| l2tunnel::aligned::packed::Config {
            base: aligned_direction(channels, appearance, true),
            hold_micros: 100,
            max_units: 3,
            work_limit: 4,
        };
        values.push(build(
            Profile::Packed {
                forward: packed(2),
                reverse: packed(3),
            },
            0,
        )?);
        let roll = |channels| {
            let packed = packed(channels);
            let receiver = packed.base.receiver;
            rolling_records::DirectionConfig {
                native_policy: packed.base.native_policy,
                receiver,
                packing: codec::packed_sender::Config {
                    sender: codec::aligned_sender::Config {
                        body: receiver.body,
                        channels: receiver.channels,
                        first_record: receiver.first_record,
                    },
                    packing: codec::packed::Config {
                        symbol_bytes: receiver.body.symbol_bytes,
                        hold_micros: packed.hold_micros,
                    },
                    max_units: packed.max_units,
                    first_unit: receiver.first_source,
                    work_limit: packed.work_limit,
                },
                codec_stage_micros: 1_000_000,
                scheduler: rolling::scheduler::Policy {
                    recovery: rolling::Config {
                        window: 16,
                        local_window: 4,
                        global_every: 2,
                        max_payload: 1024,
                        max_rows: 16,
                        repair_history: 64,
                        handoff_sources: 2,
                        job_ticks: 1_000_000,
                        debt_ticks: 10_000_000,
                        handoff_ticks: 2_000_000,
                        memory_bytes: 16 << 20,
                    },
                    repair_numerator: 1,
                    repair_denominator: 2,
                    tail_ticks: 1000,
                    feedback_ticks: 100,
                    feedback_packets: 2,
                    memory_bytes: 16 << 20,
                    source_wire: rolling::wire::SourceWire::Exact,
                },
            }
        };
        values.push(build(
            Profile::Rolling {
                config: rolling_records::Config {
                    forward: roll(2),
                    reverse: roll(3),
                    geometry: l2tunnel::record_engine::Geometry {
                        forward_overhead_bytes: overhead(appearance),
                        reverse_overhead_bytes: overhead(appearance),
                    },
                    native_stall_micros: 10_000_000,
                },
                stream: 17,
            },
            0,
        )?);
        for index in 4..64 {
            values.push(build(
                Profile::Swift {
                    forward: forward.records,
                    reverse: reverse.records,
                },
                index,
            )?);
        }
        Ok(values)
    }
    struct Fixture {
        handles: [Handle; 2],
        hosts: [Arc<Host>; 2],
        tasks: Tasks,
        addresses: [SocketAddr; 2],
        profile: common_transaction_profile::Profile,
        stages: [Configuration; 4],
        outside: Configuration,
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
            let values = descriptors(appearance)?;
            let initiator = runtime(appearance);
            let responder = transport::Config {
                send: initiator.receive,
                receive: initiator.send,
                ..initiator
            };
            let profile = common_transaction_profile::Profile::new(
                connection(),
                raw_settings(appearance, addresses, keys)?,
                keys.peers,
                initiator,
                responder,
                Catalog::new(values[0], &values).map_err(error)?,
                parameters(),
            )?;
            let make =
                |descriptor| Configuration::new(profile.envelope(), descriptor).map_err(error);
            let stages = [
                make(values[0])?,
                make(values[1])?,
                make(values[2])?,
                make(values[3])?,
            ];
            let initial = values[0];
            let outside = Configuration::new(
                profile.envelope(),
                Descriptor::new(
                    1500,
                    Duplex::Full,
                    common_direction(2, direction(appearance, true).bytes_per_second + 999)?,
                    *initial
                        .direction(l2tunnel_management::Role::Server)
                        .common(),
                    *initial.profile(),
                )
                .map_err(error)?,
            )
            .map_err(error)?;
            let hosts = [Arc::new(Host::default()), Arc::new(Host::default())];
            let client = Prepared::secure_udp_common_client(
                profile.clone(),
                credentials::Client::new(
                    keys.noise(security::Role::Initiator)?,
                    l2tunnel_identity::IdentityKey::from_pkcs8(&keys.member).map_err(error)?,
                    credentials::Secret32::new(Zeroizing::new([44; 32]))?,
                )?,
                hosts[0].attachment(),
            )?;
            let server = Prepared::secure_udp_common_server(
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
            let a = handles[0]
                .connect(client, handles[0].next_key().map_err(submit)?)
                .map_err(submit)?;
            let b = handles[1]
                .connect(server, handles[1].next_key().map_err(submit)?)
                .map_err(submit)?;
            let connected = |handle: Handle, id| async move {
                require(
                    matches!(
                        timeout(Duration::from_secs(4), handle.wait(id))
                            .await
                            .map_err(error)?
                            .map_err(submit)?,
                        Completed::Connected { .. }
                    ),
                    "Common fixture did not become ready",
                )
            };
            tokio::try_join!(
                connected(handles[0].clone(), a.operation),
                connected(handles[1].clone(), b.operation)
            )?;
            let api = [directory.join("client.sock"), directory.join("server.sock")];
            let requests = [Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0))];
            for side in 0..2 {
                let api = local::Server::bind(&api[side])?;
                let handle = handles[side].clone();
                let count = requests[side].clone();
                tasks.add(tokio::spawn(async move {
                    api.serve(move |request| {
                        count.fetch_add(1, Ordering::SeqCst);
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
                stages,
                outside,
                api,
                requests,
            })
        }
        fn status(&self, side: usize) -> Result<common_status::Status> {
            self.handles[side]
                .snapshot()
                .runtime
                .as_ref()
                .and_then(Observation::secure_udp_common)
                .ok_or_else(|| error("missing actual Common frame"))?
                .status()
        }
        async fn follower(&self, expected: Configuration, epoch: u64) -> Result {
            let mut changed = self.handles[1].subscribe();
            timeout(Duration::from_secs(3), async {
                loop {
                    let status = self.status(1)?;
                    if status.epoch == Some(epoch)
                        && status.phase == Some(common_status::Phase::Idle)
                        && status.operation.is_none()
                    {
                        return current(&status, expected, epoch);
                    }
                    changed.changed().await.map_err(error)?;
                }
            })
            .await
            .map_err(|value| error(format!("follower_ready epoch={epoch}: {value}")))?
        }
        async fn traffic(&self, marker: u8) -> Result {
            let previous = [
                self.status(0)?.liveness.and_then(|v| v.last_pong_micros),
                self.status(1)?.liveness.and_then(|v| v.last_pong_micros),
            ];
            for side in 0..2 {
                let mut packet = vec![marker + side as u8; 512 + usize::from(marker) % 31];
                let size = u16::try_from(packet.len()).map_err(error)?;
                packet[..28].fill(0);
                packet[0] = 0x45;
                packet[2..4].copy_from_slice(&size.to_be_bytes());
                packet[8] = 64;
                packet[9] = 17;
                packet[12..20].copy_from_slice(&[198, 18, 0, 1, 198, 18, 0, 2]);
                packet[20..22].copy_from_slice(&[0x80, marker]);
                packet[22..24].copy_from_slice(&[0x91, marker]);
                packet[24..26].copy_from_slice(&(size - 20).to_be_bytes());
                self.hosts[side].send(&packet).map_err(|value| {
                    error(format!("native_send marker={marker} side={side}: {value}"))
                })?;
                self.hosts[1 - side]
                    .expect(&packet)
                    .await
                    .map_err(|value| {
                        error(format!(
                            "native_receive marker={marker} sender={side} receiver={}: {value}",
                            1 - side
                        ))
                    })?;
            }
            timeout(Duration::from_secs(3), async {
                loop {
                    let a = self.status(0)?;
                    let b = self.status(1)?;
                    if [a, b].into_iter().zip(previous).all(|(status, before)| {
                        status
                            .liveness
                            .and_then(|v| v.last_pong_micros)
                            .is_some_and(|now| before.is_none_or(|before| now > before))
                    }) {
                        return Ok::<(), io::Error>(());
                    }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .map_err(|value| error(format!("liveness_after_native marker={marker}: {value}")))??;
            for host in &self.hosts {
                host.empty()?;
            }
            Ok(())
        }
        fn failure_snapshot(&self, reason: &io::Error) -> Value {
            let peers=(0..2).map(|side| {
                let snapshot=self.handles[side].snapshot();
                let engine=snapshot.runtime.as_ref().and_then(Observation::secure_udp_common)
                    .and_then(|frame|frame.runtime.as_ref()).map(|runtime|format!("{:?}",runtime.engine));
                let status=match self.status(side) {
                    Ok(value)=>serde_json::to_value(value).unwrap_or_else(|_|json!({"projection_error":"serialization"})),
                    Err(value)=>json!({"projection_error":value.to_string()}),
                };
                json!({"side":side,"service_phase":format!("{:?}",snapshot.phase),
                    "service_operation":snapshot.operation.map(|id|id.value()),"service_generation":snapshot.generation.map(|id|id.value()),
                    "service_terminal":snapshot.terminal.map(|value|format!("{value:?}")),"engine":engine,"status":status})
            }).collect::<Vec<_>>();
            json!({"status":"failed","reason":reason.to_string(),"kind":format!("{:?}",reason.kind()),"peers":peers})
        }
        async fn close(&mut self) -> Result {
            self.tasks.stop().await;
            require(
                self.hosts
                    .iter()
                    .all(|host| host.live.load(Ordering::SeqCst) == 0),
                "native fixture owner leaked",
            )
        }
    }
    fn current(status: &common_status::Status, expected: Configuration, epoch: u64) -> Result {
        require(
            status.running
                && status.backend == "common_records_v2"
                && status.epoch == Some(epoch)
                && status.phase == Some(common_status::Phase::Idle)
                && status.operation.is_none()
                && status
                    .current
                    .as_ref()
                    .map(common_status::CanonicalConfiguration::configuration)
                    .transpose()?
                    == Some(expected)
                && status.physical_scope
                    == Some(common_status::Scope {
                        epoch,
                        configuration: transaction::configuration_digest(&expected)
                            .map_err(error)?
                            .0,
                    }),
            "actual current/physical Common state differs",
        )?;
        require(
            !status.resource_preallocation_complete
                && !status.retained_state_recovery
                && !status.fresh_rekey,
            "finite probe must not qualify full parent gates",
        )
    }
    fn common_response(
        execution: &Execution,
        success: bool,
    ) -> Result<(local::Snapshot, common_status::Status)> {
        let response = execution.response()?;
        require(
            response.version == 4 && response.ok == success,
            "external command returned wrong version/outcome",
        )?;
        let mut state = response
            .state
            .ok_or_else(|| error("missing actual Common state"))?;
        require(
            state.proxy.is_none(),
            "native Common reply projected a proxy backend",
        )?;
        let status = state
            .common
            .take()
            .ok_or_else(|| error("missing actual Common DTO"))?;
        Ok((state, status))
    }
    fn change(configuration: Configuration, key: u64) -> Result<Vec<OsString>> {
        Ok(vec![
            "--configuration".into(),
            common_status::CanonicalConfiguration::from_configuration(configuration)?
                .as_str()
                .into(),
            "--request-key".into(),
            key.to_string().into(),
        ])
    }
    fn root_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
    async fn inspections(runner: &mut Runner, directory: &Path, appearance: Appearance) -> Result {
        let held = [
            UdpSocket::bind("127.0.0.1:0")?,
            UdpSocket::bind("127.0.0.1:0")?,
        ];
        let addresses = [held[0].local_addr()?, held[1].local_addr()?];
        let file = directory.join("full-common-plan.json");
        let document = plan_json(appearance)?;
        let bytes = serde_json::to_vec(&document).map_err(error)?;
        require(
            bytes.len() <= 256 * 1024,
            "full64 plan exceeds frozen file bound",
        )?;
        save(&file, &bytes)?;
        let descriptors = descriptors(appearance)?;
        let catalog = Catalog::new(descriptors[0], &descriptors).map_err(error)?;
        let mut roles = Vec::new();
        for responder in [false, true] {
            let execution = runner
                .command(
                    "inspect-common-full64",
                    inspection_args(directory, &file, appearance, addresses, responder, false)?,
                    true,
                )
                .await?;
            let lines = execution.lines()?;
            require(lines.len() == 17, "inspection pruned full64 catalog")?;
            let header = &lines[0];
            require(
                header["event"] == "secure_udp_common_plan"
                    && header["backend"] == "common_records_v2"
                    && header["api_version"] == 4
                    && header["authenticated"] == false
                    && header["catalog_members"] == 64
                    && header["resource_preallocation_complete"] == false,
                "inspection overclaimed startup or wrong backend",
            )?;
            let root: [u8; 32] =
                serde_json::from_value(header["catalog"].clone()).map_err(error)?;
            require(
                root == *catalog.root().as_bytes(),
                "inspection changed exact catalog root",
            )?;
            let initial: common_status::CanonicalConfiguration =
                serde_json::from_value(header["initial"].clone()).map_err(error)?;
            require(
                initial.configuration()?.descriptor() == &descriptors[0],
                "inspection changed initial full C",
            )?;
            let expected = catalog
                .configurations(initial.configuration()?.envelope())
                .map_err(error)?;
            let mut all = Vec::new();
            for (index, line) in lines.iter().skip(1).enumerate() {
                require(
                    line["event"] == "secure_udp_common_plan_catalog"
                        && line["offset"] == index * 4
                        && line["total"] == 64,
                    "inspection page order/size differs",
                )?;
                let values: Vec<common_status::CanonicalConfiguration> =
                    serde_json::from_value(line["configurations"].clone()).map_err(error)?;
                require(values.len() == 4, "inspection page exceeds bound")?;
                for value in values {
                    all.push(value.configuration()?);
                }
            }
            require(
                all == expected,
                "inspection lost or changed complete catalog members",
            )?;
            roles.push(lines);
        }
        for field in [
            "configuration",
            "envelope",
            "catalog",
            "initial",
            "rolling_work",
        ] {
            require(
                roles[0][0][field] == roles[1][0][field],
                "role projection changed common authenticated plan",
            )?;
        }
        let mut no_work = document;
        no_work["rolling_work"] = Value::Null;
        let file = directory.join("rolling-without-work.json");
        save(&file, &serde_json::to_vec(&no_work).map_err(error)?)?;
        runner
            .command(
                "rolling-capability-refusal",
                inspection_args(directory, &file, appearance, addresses, false, false)?,
                false,
            )
            .await?;
        Ok(())
    }
    impl Runner {
        async fn pair_lifecycle(
            &mut self,
            paths: &[PathBuf; 2],
            command: &str,
        ) -> Result<[Execution; 2]> {
            let args = |path: &Path| {
                vec![
                    OsString::from(command),
                    "--control-socket".into(),
                    path.as_os_str().to_owned(),
                    "--api-version".into(),
                    "4".into(),
                ]
            };
            require(
                self.executions <= 94,
                "finite case command budget exhausted",
            )?;
            let left = OwnedChild::spawn(&self.binary, &args(&paths[0]))?;
            let right = OwnedChild::spawn(&self.binary, &args(&paths[1]))?;
            let (left, right) = tokio::join!(left.finish(), right.finish());
            let results = [left?, right?];
            for (side, result) in results.iter().enumerate() {
                self.executions += 1;
                let prefix = format!("{:03}-{command}-{side}", self.executions);
                save(
                    &self.directory.join(format!("{prefix}.stdout")),
                    &result.stdout,
                )?;
                save(
                    &self.directory.join(format!("{prefix}.stderr")),
                    &result.stderr,
                )?;
                save(&self.directory.join(format!("{prefix}.json")),&serde_json::to_vec(&json!({"command":command,"side":side,"success":result.status.success(),"code":result.status.code()})).map_err(error)?)?;
                require(
                    result.status.success(),
                    "paired lifecycle CLI command failed",
                )?;
            }
            Ok(results)
        }
    }
    async fn exercise(runner: &mut Runner, fixture: &Fixture) -> Result<Value> {
        let (_, before) = common_response(
            &runner
                .api(
                    "status-v4",
                    &fixture.api[0],
                    "status",
                    Some(4),
                    vec![],
                    true,
                )
                .await?,
            true,
        )?;
        let epoch = before.epoch.ok_or_else(|| error("missing actual epoch"))?;
        current(&before, fixture.stages[0], epoch)?;
        require(
            before.configuration == fixture.profile.configuration()?.0,
            "wrong actual authenticated H0",
        )?;
        let next = before
            .next_request_key
            .ok_or_else(|| error("missing actual next request key"))?;
        require(
            next == fixture.handles[0].next_key().map_err(submit)?.value(),
            "advisory next key differs from actual actor",
        )?;
        let expected = fixture
            .profile
            .catalog()
            .configurations(fixture.profile.envelope())
            .map_err(error)?;
        let mut all = Vec::new();
        for offset in (0..64u16).step_by(4) {
            let key = fixture.handles[0].next_key().map_err(submit)?;
            let count = fixture.requests[0].load(Ordering::SeqCst);
            let args = vec![
                "--generation".into(),
                before.generation.to_string().into(),
                "--catalog".into(),
                root_hex(&before.catalog).into(),
                "--offset".into(),
                offset.to_string().into(),
                "--limit".into(),
                "4".into(),
            ];
            let (_, status) = common_response(
                &runner
                    .api(
                        "catalog-full64",
                        &fixture.api[0],
                        "common-catalog",
                        Some(4),
                        args,
                        true,
                    )
                    .await?,
                true,
            )?;
            let page = status
                .catalog_page
                .ok_or_else(|| error("missing full catalog page"))?;
            require(
                page.offset == offset
                    && page.total == 64
                    && page.configurations.len() == 4
                    && page.next == if offset == 60 { None } else { Some(offset + 4) },
                "catalog page continuation differs",
            )?;
            for configuration in page.configurations {
                all.push(configuration.configuration()?);
            }
            require(
                fixture.requests[0].load(Ordering::SeqCst) == count + 1
                    && fixture.handles[0].next_key().map_err(submit)? == key,
                "catalog query retried or consumed a service key",
            )?;
        }
        require(
            all == expected,
            "external catalog retrieval pruned or changed full64",
        )?;
        for version in [None, Some(1)] {
            let count = fixture.requests[0].load(Ordering::SeqCst);
            let result = runner
                .api(
                    "requires-v4",
                    &fixture.api[0],
                    "disconnect",
                    version,
                    vec![],
                    false,
                )
                .await?
                .response()?;
            require(
                result.version == version.unwrap_or(1)
                    && !result.ok
                    && result.code == "requires_version_4"
                    && result.state.is_none(),
                "wrong version was downgraded or admitted",
            )?;
            require(
                fixture.requests[0].load(Ordering::SeqCst) == count + 1,
                "CLI automatically retried version refusal",
            )?;
            current(&fixture.status(0)?, fixture.stages[0], epoch)?;
        }
        for version in [2, 3] {
            let count = fixture.requests[0].load(Ordering::SeqCst);
            let execution = runner
                .api(
                    "retired-api-version",
                    &fixture.api[0],
                    "disconnect",
                    Some(version),
                    vec![],
                    false,
                )
                .await?;
            require(
                execution.stdout.is_empty()
                    && String::from_utf8_lossy(&execution.stderr)
                        .contains("api-version must be explicitly 1 or 4")
                    && fixture.requests[0].load(Ordering::SeqCst) == count,
                "retired API version reached the service or lost its migration diagnostic",
            )?;
            current(&fixture.status(0)?, fixture.stages[0], epoch)?;
        }
        let count = fixture.requests[0].load(Ordering::SeqCst);
        for version in [None, Some(1), Some(2), Some(3), Some(5)] {
            runner
                .api(
                    "switch-explicit-v4",
                    &fixture.api[0],
                    "switch-common-configuration",
                    version,
                    change(fixture.stages[1], next)?,
                    false,
                )
                .await?;
        }
        let mut malformed = change(fixture.stages[1], next)?;
        malformed[1] = "ab".into();
        runner
            .api(
                "malformed-full-c",
                &fixture.api[0],
                "switch-common-configuration",
                Some(4),
                malformed,
                false,
            )
            .await?;
        require(
            fixture.requests[0].load(Ordering::SeqCst) == count,
            "invalid explicit version/C reached local service",
        )?;
        let key = fixture.handles[0].next_key().map_err(submit)?;
        let outside = runner
            .api(
                "unlisted-full-c",
                &fixture.api[0],
                "switch-common-configuration",
                Some(4),
                change(fixture.outside, key.value())?,
                false,
            )
            .await?
            .response()?;
        require(
            outside.code == "invalid_configuration"
                && !outside.ok
                && fixture.handles[0].next_key().map_err(submit)? == key,
            "unlisted C consumed a key or was coerced",
        )?;
        fixture.traffic(31).await?;
        let mut outcomes = Vec::new();
        for (index, target) in [
            fixture.stages[1],
            fixture.stages[2],
            fixture.stages[3],
            fixture.stages[0],
        ]
        .into_iter()
        .enumerate()
        {
            let query = runner
                .api(
                    "before-switch-key",
                    &fixture.api[0],
                    "status",
                    Some(4),
                    vec![],
                    true,
                )
                .await?;
            let (_, status) = common_response(&query, true)?;
            let key = status
                .next_request_key
                .ok_or_else(|| error("missing next key"))?;
            let count = fixture.requests[0].load(Ordering::SeqCst);
            let execution = runner
                .api(
                    "switch-four-families",
                    &fixture.api[0],
                    "switch-common-configuration",
                    Some(4),
                    change(target, key)?,
                    true,
                )
                .await?;
            require(
                fixture.requests[0].load(Ordering::SeqCst) == count + 1,
                "one keyed switch sent multiple local requests",
            )?;
            let (state, status) = common_response(&execution, true)?;
            let target_epoch = epoch + index as u64 + 1;
            require(
                state.phase == "forwarding",
                "switch completion raced actual settled service phase",
            )?;
            current(&status, target, target_epoch)?;
            let result = status
                .result
                .as_ref()
                .ok_or_else(|| error("missing actual Completed Common result"))?;
            require(
                result.configuration.configuration()? == target
                    && result.epoch == Some(target_epoch)
                    && result.request_key == key
                    && result.outcome == "ok",
                "keyed result does not match actual target/epoch",
            )?;
            require(
                status.generation == before.generation
                    && status.session == before.session
                    && status.transcript == before.transcript
                    && status.local == before.local
                    && status.peer == before.peer
                    && status.configuration == before.configuration,
                "same-session switch replaced original auth/socket tuple",
            )?;
            fixture
                .follower(target, target_epoch)
                .await
                .map_err(|value| {
                    error(format!(
                        "family_switch index={index} epoch={target_epoch} phase=follower: {value}"
                    ))
                })?;
            fixture
                .traffic(51 + index as u8 * 20)
                .await
                .map_err(|value| {
                    error(format!(
                        "family_switch index={index} epoch={target_epoch} phase=traffic: {value}"
                    ))
                })?;
            if index == 2 {
                let actual = fixture.status(0)?;
                require(
                    actual.rolling_work
                        == Some(common_status::RollingWork {
                            field: 4096,
                            copies: 4096,
                            metadata: 4096,
                        })
                        && actual.rolling_scheduler_steps.is_some_and(|v| v > 0)
                        && actual.rolling_work_used.is_some_and(|v| v[1] > 0),
                    "rolling runtime did not consume configured actual work",
                )?;
            }
            let (_, replay) = common_response(
                &runner
                    .api(
                        "exact-key-replay",
                        &fixture.api[0],
                        "switch-common-configuration",
                        Some(4),
                        change(target, key)?,
                        true,
                    )
                    .await?,
                true,
            )?;
            require(
                replay.result == status.result,
                "retained key replay changed actual completed result",
            )?;
            current(&replay, target, target_epoch)?;
            if index == 0 {
                let conflict = runner
                    .api(
                        "key-conflict",
                        &fixture.api[0],
                        "switch-common-configuration",
                        Some(4),
                        change(fixture.stages[0], key)?,
                        false,
                    )
                    .await?
                    .response()?;
                require(
                    conflict.code == "conflict" && !conflict.ok,
                    "same key accepted a different target",
                )?;
            }
            outcomes.push(json!({"epoch":target_epoch,"operation":result.operation,"request_key":key,"configuration":common_status::CanonicalConfiguration::from_configuration(target)?}));
        }
        let stopped = runner.pair_lifecycle(&fixture.api, "disconnect").await?;
        for execution in stopped {
            let (state, status) = common_response(&execution, true)?;
            require(
                state.phase == "disconnected"
                    && !status.running
                    && status.service_terminal.as_deref() == Some("Aborted"),
                "disconnect did not report actual release",
            )?;
        }
        require(
            fixture
                .hosts
                .iter()
                .all(|host| host.live.load(Ordering::SeqCst) == 0),
            "CLI disconnect returned before native owner release",
        )?;
        let held = [
            UdpSocket::bind(fixture.addresses[0])?,
            UdpSocket::bind(fixture.addresses[1])?,
        ];
        drop(held);
        let fresh = runner.pair_lifecycle(&fixture.api, "reconnect").await?;
        let (_, fresh) = common_response(&fresh[0], true)?;
        current(&fresh, fixture.stages[0], epoch)?;
        require(
            fresh.generation != before.generation
                && fresh.session != before.session
                && fresh.transcript != before.transcript
                && fresh.local == before.local
                && fresh.peer == before.peer,
            "reconnect did not make fresh authenticated owners on fixed endpoint pair",
        )?;
        require(
            fixture.hosts.iter().all(|host| {
                host.opened.load(Ordering::SeqCst) == 2 && host.live.load(Ordering::SeqCst) == 1
            }),
            "fresh reconnect native attachment count differs",
        )?;
        fixture.traffic(151).await?;
        let stopped = runner.pair_lifecycle(&fixture.api, "disconnect").await?;
        for result in stopped {
            require(
                !common_response(&result, true)?.1.running,
                "final disconnect remained running",
            )?;
        }
        Ok(
            json!({"status":"passed","catalog_members":64,"catalog_pages":16,"switches":outcomes,"original_addresses":fixture.addresses.map(|value|value.to_string()),
            "fresh_authenticated_reconnect":true,"native_attachment":"UnixDatagram PacketDevice","external_control_cli":true,
            "external_connect_serve_qualified":false,"production_tuntap_startup_qualified":false,"performance_qualified":false}),
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
        let diagnostic = if let Err(reason) = &result {
            let value = fixture.failure_snapshot(reason);
            let bytes = serde_json::to_vec_pretty(&value).map_err(error)?;
            require(
                bytes.len() <= 128 * 1024,
                "probe failure snapshot exceeds bounded diagnostic capacity",
            )?;
            save(&directory.join("functional-failure.json"), &bytes)
        } else {
            Ok(())
        };
        let cleanup = fixture.close().await;
        diagnostic?;
        let result = match (result, cleanup) {
            (Ok(value), Ok(())) => value,
            (Err(error), _) | (_, Err(error)) => return Err(error),
        };
        Ok(
            json!({"cover":name,"external_processes":runner.executions,"result":result,"cleanup":"released"}),
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
            "binary must be existing absolute regular file",
        )?;
        require(directory.is_absolute(), "work directory must be absolute")?;
        private_directory(&directory)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let result: Result<Vec<Value>> = runtime.block_on(async {
            let mut cases = Vec::new();
            for appearance in [Appearance::QuicLike, Appearance::MediaLike] {
                cases.push(
                    timeout(
                        Duration::from_secs(60),
                        case(&binary, &directory, appearance),
                    )
                    .await
                    .map_err(error)??,
                );
            }
            Ok(cases)
        });
        let validation = match &result {
            Ok(cases) => {
                json!({"schema":1,"status":"passed","binary":path_text(&binary)?,"cases":cases,
            "scope":"actual external Common control CLI and inspection with real programmatic shared service/authenticated original UDP/Unix packet devices",
            "external_connect_serve_qualified":false,"production_tuntap_startup_qualified":false,"performance_qualified":false})
            }
            Err(error) => {
                json!({"schema":1,"status":"failed","binary":path_text(&binary)?,"reason":error.to_string(),"kind":format!("{:?}",error.kind())})
            }
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
        "explicit Common control CLI process probe requires Unix",
    ))
}
