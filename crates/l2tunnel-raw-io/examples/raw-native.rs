//! Explicit isolated-lab helper; never enables the ordinary client's raw profile.
#[cfg(target_os = "linux")]
mod native {
    use l2tunnel_auth::{
        AuthenticatedIo, ClientTls, MemberAllowlist, MemberKey, MemberPublicKey, ServerTls,
        SessionConfig, client_connect_io, server_accept_io,
    };
    use l2tunnel_core::ConfigDigest;
    use l2tunnel_device::{PacketDevice, PacketLayer};
    use l2tunnel_platform_linux::TunTap;
    use l2tunnel_raw_io::Counters;
    use l2tunnel_raw_tcp::{Config, Role};
    use l2tunnel_runtime::{
        Compression, Duplex, Link, RuntimeConfig, client_pair, drained, server_pair,
    };
    use ring::{
        digest::{SHA256, digest},
        rand::{SecureRandom, SystemRandom},
    };
    use std::{
        fs::OpenOptions,
        io::{self, Write},
        net::SocketAddrV4,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
        path::Path,
        time::Duration,
    };
    use tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWriteExt, DuplexStream},
        net::{UnixListener, UnixStream},
        sync::oneshot,
        task::JoinSet,
        time::{Instant, timeout},
    };

    type Failure = Box<dyn std::error::Error + Send + Sync>;

    fn invalid(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, message)
    }
    fn read(path: &Path) -> io::Result<Vec<u8>> {
        if std::fs::metadata(path)?.len() > 65_536 {
            return Err(invalid("credential exceeds bound"));
        }
        std::fs::read(path)
    }
    fn private_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?
            .write_all(bytes)
    }
    fn raw(local: SocketAddrV4, peer: SocketAddrV4) -> Result<Config, Failure> {
        let mut seed = [0; 8];
        SystemRandom::new()
            .fill(&mut seed)
            .map_err(|_| invalid("random seed failure"))?;
        Ok(Config {
            local,
            peer,
            mtu: 1200,
            send_bytes: 65_536,
            receive_bytes: 65_536,
            packet_slots: 64,
            random_seed: u64::from_be_bytes(seed),
            ack_delay_millis: 10,
            keepalive_millis: 1000,
            idle_timeout_millis: 30_000,
        })
    }
    fn parse_mark(text: &str) -> io::Result<u32> {
        let (digits, radix) = text
            .strip_prefix("0x")
            .map_or((text, 10), |value| (value, 16));
        if digits.is_empty()
            || digits.len() > if radix == 16 { 8 } else { 10 }
            || !digits.bytes().all(|byte| {
                if radix == 16 {
                    byte.is_ascii_hexdigit()
                } else {
                    byte.is_ascii_digit()
                }
            })
        {
            return Err(invalid(
                "raw mark requires a nonzero decimal or 0x hexadecimal u32",
            ));
        }
        u32::from_str_radix(digits, radix)
            .ok()
            .filter(|mark| *mark != 0)
            .ok_or_else(|| invalid("raw mark outside nonzero u32 bounds"))
    }
    fn optional_mark(args: &[String]) -> io::Result<Option<u32>> {
        match args.len() {
            8 => Ok(None),
            10 if args[8] == "--raw-mark" => parse_mark(&args[9]).map(Some),
            _ => Err(invalid(
                "usage: raw-native client|server tap|tun full|half LOCAL:PORT PEER:PORT DEVICE SECRETS_DIR DRAIN_SOCKET [--raw-mark NONZERO_U32] (or keygen PRIVATE PUBLIC)",
            )),
        }
    }
    fn binding(
        layer: PacketLayer,
        half: bool,
        local: SocketAddrV4,
        peer: SocketAddrV4,
        client: bool,
        marked_policy: bool,
    ) -> SessionConfig {
        let (a, b) = if client { (local, peer) } else { (peer, local) };
        let mut canonical =
            b"l2tunnel/raw-native-lab/v1/retained-tls/no-sni/system-packets".to_vec();
        canonical.extend_from_slice(&[u8::from(layer == PacketLayer::Ip), u8::from(half)]);
        for endpoint in [a, b] {
            canonical.extend_from_slice(&endpoint.ip().octets());
            canonical.extend_from_slice(&endpoint.port().to_be_bytes());
        }
        for value in [
            1200_u64, 65_536, 65_536, 64, 10, 1000, 30_000, 1600, 64, 1000, 60_000,
        ] {
            canonical.extend_from_slice(&value.to_be_bytes());
        }
        if marked_policy {
            // The policy kind is negotiated; the numeric SO_MARK is local metadata.
            canonical.extend_from_slice(b"/marked-socket-policy/v1");
        }
        let mut bytes = [0; 32];
        bytes.copy_from_slice(digest(&SHA256, &canonical).as_ref());
        SessionConfig {
            layer,
            digest: ConfigDigest(bytes),
        }
    }
    async fn lane(
        config: Config,
        client: bool,
        secrets: &Path,
        session: SessionConfig,
        mark: Option<u32>,
        drivers: &mut JoinSet<io::Result<Counters>>,
    ) -> Result<AuthenticatedIo<DuplexStream>, Failure> {
        let role = if client { Role::Client } else { Role::Server };
        let (stream, driver) = match mark {
            Some(mark) => l2tunnel_raw_io::open_marked(config, role, mark)?,
            None => l2tunnel_raw_io::open(config, role)?,
        };
        drivers.spawn(driver.run());
        let certificate = read(&secrets.join("cert.der"))?;
        let handshake = async {
            if client {
                let tls = ClientTls::from_der_roots(&[certificate])?;
                let member = MemberKey::from_pkcs8(&read(&secrets.join("member.der"))?)?;
                Ok::<_, Failure>(
                    client_connect_io(
                        stream,
                        &tls,
                        "lab.invalid",
                        &member,
                        session,
                        Duration::from_secs(60),
                    )
                    .await?,
                )
            } else {
                let tls = ServerTls::from_der(&[certificate], &read(&secrets.join("server.der"))?)?;
                let key: [u8; 32] = read(&secrets.join("member.pub"))?
                    .try_into()
                    .map_err(|_| invalid("member public key length"))?;
                let members = MemberAllowlist::new(&[MemberPublicKey(key)])?;
                Ok(
                    server_accept_io(stream, &tls, &members, session, Duration::from_secs(60))
                        .await?,
                )
            }
        };
        tokio::select! {
            result = handshake => result,
            result = drivers.join_next() => Err(io::Error::other(format!("raw driver ended during authentication: {result:?}")).into()),
        }
    }
    fn diagnostic(operation: &str, error: &io::Error) {
        let value = serde_json::json!({"kind":"raw_helper_error", "operation":operation,
            "error_kind":format!("{:?}", error.kind()), "raw_os_error":error.raw_os_error()});
        let _ = writeln!(io::stderr(), "{value}");
    }
    struct ObservedDevice(TunTap);
    impl PacketDevice for ObservedDevice {
        type Error = io::Error;
        fn layer(&self) -> PacketLayer {
            self.0.layer()
        }
        fn receive(&mut self, output: &mut [u8]) -> io::Result<Option<usize>> {
            self.0.receive(output).inspect_err(|error| {
                if error.kind() != io::ErrorKind::WouldBlock {
                    diagnostic("native.read", error);
                }
            })
        }
        fn transmit(&mut self, packet: &[u8]) -> io::Result<()> {
            self.0.transmit(packet).inspect_err(|error| {
                if error.kind() != io::ErrorKind::WouldBlock {
                    diagnostic("native.write", error);
                }
            })
        }
    }
    fn native_report(proof: drained::DrainReport) -> serde_json::Value {
        serde_json::json!({
            "local_admitted": proof.local_admitted, "local_handed": proof.local_handed,
            "local_flushed": proof.local_flushed, "peer_barrier": proof.peer_barrier,
            "native_confirmed": proof.native_confirmed, "local_barrier": proof.local_barrier,
            "local_ack": proof.local_ack, "peer_ack": proof.peer_ack,
            "tls_lanes_closed": proof.tls_lanes_closed
        })
    }
    async fn request<R: AsyncRead + Unpin>(stream: &mut R) -> io::Result<()> {
        let mut bytes = Vec::with_capacity(8);
        timeout(
            Duration::from_secs(5),
            stream.take(8).read_to_end(&mut bytes),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "local drain request timeout"))??;
        if bytes != b"DRAIN1\n" {
            return Err(invalid("one exact drain request and write EOF required"));
        }
        Ok(())
    }
    async fn accept_request(listener: UnixListener) -> io::Result<UnixStream> {
        let (mut stream, _) = listener.accept().await?;
        request(&mut stream)
            .await
            .inspect_err(|error| diagnostic("control.request.read", error))?;
        Ok(stream)
    }
    fn private_listener(path: &Path) -> io::Result<UnixListener> {
        let parent = path
            .parent()
            .ok_or_else(|| invalid("drain socket parent"))?;
        let metadata = std::fs::symlink_metadata(parent)?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(invalid("drain socket requires a private owned directory"));
        }
        let listener = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(listener)
    }
    async fn forward_and_drain(
        device: TunTap,
        link: Link,
        config: drained::Config,
        listener: UnixListener,
        mut drivers: JoinSet<io::Result<Counters>>,
    ) -> Result<(), Failure> {
        let started = Instant::now();
        let (stop, stopped) = oneshot::channel();
        let mut stop = Some(stop);
        let forwarding = drained::run(ObservedDevice(device), link, config, stopped);
        let requesting = accept_request(listener);
        tokio::pin!(forwarding, requesting);
        let mut report = None;
        let mut controller = None;
        let mut deadline = None;
        let mut counters = Vec::new();
        let lanes = if config.duplex == Duplex::Half { 2 } else { 1 };
        loop {
            tokio::select! {
                received = &mut requesting, if controller.is_none() => {
                    controller = Some(received?);
                    println!("{}",serde_json::json!({"kind":"raw_native_drain_requested", "elapsed_millis":started.elapsed().as_millis()}));
                    deadline.get_or_insert(Instant::now() + Duration::from_secs(75));
                    if let Some(stop) = stop.take() { let _ = stop.send(()); }
                }
                result = &mut forwarding, if report.is_none() => {
                    let proof = result.inspect_err(|error| diagnostic("native_tls_runtime", error))?;
                    println!("{}",serde_json::json!({"kind":"raw_native_tls_drained", "elapsed_millis": started.elapsed().as_millis(), "native":native_report(proof)}));
                    report = Some(proof);
                    let driver_limit = Instant::now() + Duration::from_secs(45);
                    deadline = Some(deadline.map_or(driver_limit, |old: Instant| old.min(driver_limit)));
                }
                result = drivers.join_next(), if !drivers.is_empty() => {
                    let clean = result.ok_or_else(|| invalid("missing raw driver result"))??
                        .inspect_err(|error| diagnostic("raw_driver", error))?;
                    counters.push(clean);
                    println!("{}",serde_json::json!({"kind":"raw_driver_clean", "elapsed_millis":started.elapsed().as_millis(), "completed_drivers":counters.len(), "expected_drivers":lanes}));
                }
                _ = tokio::time::sleep_until(deadline.unwrap_or_else(|| Instant::now() + Duration::from_secs(75))), if deadline.is_some() => {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "finite helper native/raw-driver drain deadline").into());
                }
            }
            if let Some(proof) = report
                && let Some(stream) = controller.as_mut()
                && drivers.is_empty()
            {
                if counters.len() != lanes {
                    return Err(invalid("missing clean raw driver proof").into());
                }
                let counters: Vec<_> = counters.iter().map(|counter| serde_json::json!({
                    "received_packets": counter.received_packets, "sent_packets": counter.sent_packets,
                    "discarded_packets": counter.discarded_packets, "sent_bytes": counter.sent_bytes,
                    "received_bytes": counter.received_bytes
                })).collect();
                let response = serde_json::json!({
                    "kind": "raw_native_drained", "status": "passed", "raw_drivers_clean": lanes,
                    "native": native_report(proof),
                    "drivers": counters,
                    "bounds": {"native_tls_seconds": 30, "additional_driver_seconds": 45, "request_seconds": 5}
                });
                let mut encoded = serde_json::to_vec(&response)?;
                encoded.push(b'\n');
                timeout(Duration::from_secs(5), async {
                    stream
                        .write_all(&encoded)
                        .await
                        .inspect_err(|error| diagnostic("control.reply.write", error))?;
                    stream
                        .flush()
                        .await
                        .inspect_err(|error| diagnostic("control.reply.flush", error))?;
                    stream
                        .shutdown()
                        .await
                        .inspect_err(|error| diagnostic("control.reply.shutdown", error))
                })
                .await??;
                println!("{response}");
                return Ok(());
            }
        }
    }
    pub async fn run() -> Result<(), Failure> {
        let args: Vec<_> = std::env::args().skip(1).collect();
        if args.len() == 3 && args[0] == "keygen" {
            let encoded = MemberKey::generate_pkcs8()?;
            let key = MemberKey::from_pkcs8(&encoded)?;
            private_write(Path::new(&args[1]), &encoded)?;
            private_write(Path::new(&args[2]), &key.public_key().0)?;
            return Ok(());
        }
        let mark = optional_mark(&args)?;
        let client = match args[0].as_str() {
            "client" => true,
            "server" => false,
            _ => return Err(invalid("role").into()),
        };
        let layer = match args[1].as_str() {
            "tap" => PacketLayer::Ethernet,
            "tun" => PacketLayer::Ip,
            _ => return Err(invalid("layer").into()),
        };
        let half = match args[2].as_str() {
            "half" => true,
            "full" => false,
            _ => return Err(invalid("duplex").into()),
        };
        let local: SocketAddrV4 = args[3].parse()?;
        let peer: SocketAddrV4 = args[4].parse()?;
        let secrets = Path::new(&args[6]);
        let runtime = RuntimeConfig {
            layer,
            max_packet: 1600,
            compression: Compression::None,
            queue_packets: 64,
            poll_interval: Duration::from_millis(1),
        };
        let config = drained::Config {
            runtime,
            duplex: if half { Duplex::Half } else { Duplex::Full },
            drain_timeout: Duration::from_secs(30),
            carrier_context: binding(layer, half, local, peer, client, mark.is_some()).digest,
        };
        let session = drained::session_config(config)?;
        let listener = private_listener(Path::new(&args[7]))?;
        let mut drivers = JoinSet::new();
        let first = lane(
            raw(local, peer)?,
            client,
            secrets,
            session,
            mark,
            &mut drivers,
        )
        .await?;
        let link = if half {
            let local = SocketAddrV4::new(
                *local.ip(),
                local
                    .port()
                    .checked_add(2)
                    .ok_or_else(|| invalid("port overflow"))?,
            );
            let peer = SocketAddrV4::new(
                *peer.ip(),
                peer.port()
                    .checked_add(2)
                    .ok_or_else(|| invalid("port overflow"))?,
            );
            let second = lane(
                raw(local, peer)?,
                client,
                secrets,
                session,
                mark,
                &mut drivers,
            )
            .await?;
            if client {
                client_pair(first, second).await?
            } else {
                server_pair(first, second).await?
            }
        } else {
            Link::full(first)
        };
        let device = TunTap::attach(&args[5], layer)?;
        println!(
            "{}",
            serde_json::json!({"kind":"raw_native_ready",
            "authenticated_lanes":if half { 2 } else { 1 },"layer":args[1],"duplex":args[2],
            "reset_policy":if mark.is_some() { "marked-v1" } else { "legacy" }, "socket_mark":mark})
        );
        forward_and_drain(device, link, config, listener, drivers).await
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn marked_selection_is_explicit_strict_and_authentication_bound() -> Result<(), Failure> {
            let mut args = vec![String::new(); 8];
            assert_eq!(optional_mark(&args)?, None);
            args.extend(["--raw-mark".into(), "0x12aa0001".into()]);
            assert_eq!(optional_mark(&args)?, Some(0x12aa0001));
            for bad in [
                "0",
                "0x0",
                "",
                "-1",
                "+1",
                " 1",
                "1 ",
                "0X12",
                "0x",
                "0x100000000",
                "4294967296",
                "é",
            ] {
                args[9] = bad.into();
                assert!(optional_mark(&args).is_err(), "accepted {bad}");
            }
            args[9] = "4294967295".into();
            assert_eq!(optional_mark(&args)?, Some(u32::MAX));
            args.push("extra".into());
            assert!(optional_mark(&args).is_err());
            args.pop();
            args[8] = "--unknown".into();
            assert!(optional_mark(&args).is_err());
            let a = "192.0.2.2:24440".parse()?;
            let b = "192.0.2.6:24441".parse()?;
            let legacy = binding(PacketLayer::Ethernet, false, a, b, true, false);
            let marked = binding(PacketLayer::Ethernet, false, a, b, true, true);
            assert_eq!(
                legacy.digest.0,
                [
                    74, 157, 187, 60, 88, 153, 37, 242, 194, 212, 22, 76, 141, 115, 166, 181, 50,
                    27, 28, 92, 174, 17, 123, 214, 31, 142, 83, 118, 228, 43, 208, 195
                ]
            );
            assert_ne!(legacy, marked);
            assert_eq!(
                legacy,
                binding(PacketLayer::Ethernet, false, b, a, false, false)
            );
            assert_eq!(
                marked,
                binding(PacketLayer::Ethernet, false, b, a, false, true)
            );
            assert_ne!(
                marked,
                binding(PacketLayer::Ethernet, true, a, b, true, true)
            );
            Ok(())
        }
        #[tokio::test]
        async fn strict_private_request_requires_exact_bytes_and_eof() -> Result<(), Failure> {
            for input in [
                b"DRAIN1\n".as_slice(),
                b"DRAIN1\nX",
                b"DRAIN1",
                b"",
                b"drain1\n",
            ] {
                let (mut writer, mut reader) = tokio::io::duplex(32);
                writer.write_all(input).await?;
                writer.shutdown().await?;
                assert_eq!(request(&mut reader).await.is_ok(), input == b"DRAIN1\n");
            }
            Ok(())
        }
        #[tokio::test(start_paused = true)]
        async fn incomplete_private_request_has_fixed_deadline() -> Result<(), Failure> {
            let (_writer, mut reader) = tokio::io::duplex(32);
            assert_eq!(
                request(&mut reader)
                    .await
                    .err()
                    .ok_or("request unexpectedly completed")?
                    .kind(),
                io::ErrorKind::TimedOut
            );
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    native::run().await
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("raw-native is an isolated Linux lab helper");
    std::process::exit(2);
}
