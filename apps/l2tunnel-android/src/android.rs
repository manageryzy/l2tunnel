use l2tunnel_client_core::secure_udp::native_client::UdpClientProfile;
use l2tunnel_client_core::{local, native::Native, service};
use l2tunnel_device::{PacketDevice, PacketLayer};
use rustix::net::{
    self, RecvAncillaryBuffer, RecvAncillaryMessage, SendAncillaryBuffer, SendAncillaryMessage,
};
use std::{
    fs::File,
    io::{self, IoSlice, IoSliceMut, Read, Write},
    mem::MaybeUninit,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd},
        unix::net::UnixStream,
    },
    path::PathBuf,
    time::Duration,
};
use tokio::io::AsyncReadExt;

const IPC_WAIT: Duration = Duration::from_secs(4);

fn protocol() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid Android FD broker response",
    )
}

fn open(name: &str) -> io::Result<UnixStream> {
    let address = net::SocketAddrUnix::new_abstract_name(name.as_bytes())?;
    let fd = net::socket_with(
        net::AddressFamily::UNIX,
        net::SocketType::STREAM,
        net::SocketFlags::CLOEXEC,
        None,
    )?;
    net::connect(&fd, &address)?;
    if net::sockopt::socket_peercred(&fd)?.uid != rustix::process::geteuid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Android broker UID mismatch",
        ));
    }
    let socket = UnixStream::from(fd);
    socket.set_read_timeout(Some(IPC_WAIT))?;
    socket.set_write_timeout(Some(IPC_WAIT))?;
    Ok(socket)
}

fn protect(name: &str, fd: BorrowedFd<'_>) -> io::Result<()> {
    let mut socket = open(name)?;
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    let fds = [fd];
    if !control.push(SendAncillaryMessage::ScmRights(&fds))
        || net::sendmsg(
            &socket,
            &[IoSlice::new(b"P")],
            &mut control,
            net::SendFlags::NOSIGNAL,
        )? != 1
    {
        return Err(protocol());
    }
    let mut result = [0];
    socket.read_exact(&mut result)?;
    if result != *b"1" {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "VpnService refused the outer socket",
        ));
    }
    Ok(())
}

fn open_tun(name: &str) -> io::Result<Native> {
    let mut socket = open(name)?;
    socket.write_all(b"T")?;
    let mut reply = [0];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let msg = net::recvmsg(
        &socket,
        &mut [IoSliceMut::new(&mut reply)],
        &mut control,
        net::RecvFlags::CMSG_CLOEXEC,
    )?;
    if msg.bytes != 1 || msg.flags.contains(net::ReturnFlags::CTRUNC) || reply != *b"1" {
        return Err(protocol());
    }
    let mut descriptor: Option<OwnedFd> = None;
    for value in control.drain() {
        if let RecvAncillaryMessage::ScmRights(fds) = value {
            for fd in fds {
                if descriptor.replace(fd).is_some() {
                    return Err(protocol());
                }
            }
        }
    }
    let file = File::from(descriptor.ok_or_else(protocol)?);
    let flags = rustix::fs::fcntl_getfl(&file)?;
    rustix::fs::fcntl_setfl(&file, flags | rustix::fs::OFlags::NONBLOCK)?;
    Ok(Native::new(Tun(file)))
}

struct Tun(File);
impl AsRawFd for Tun {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
impl PacketDevice for Tun {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ip
    }
    fn receive(&mut self, data: &mut [u8]) -> io::Result<Option<usize>> {
        match self.0.read(data) {
            Ok(0) => Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => Ok(Some(n)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }
    fn transmit(&mut self, data: &[u8]) -> io::Result<()> {
        if self.0.write(data)? == data.len() {
            Ok(())
        } else {
            Err(io::ErrorKind::WriteZero.into())
        }
    }
}

pub(super) fn enter() -> io::Result<()> {
    let mut args = std::env::args_os().skip(1);
    let first = args.next().ok_or_else(protocol)?;
    if first == "--keygen" {
        let out_dir = PathBuf::from(args.next().ok_or_else(protocol)?);
        if args.next().is_some() {
            return Err(protocol());
        }
        return generate_profile_keys(&out_dir);
    }
    let directory = PathBuf::from(first);
    let path = PathBuf::from(args.next().ok_or_else(protocol)?);
    let name = args
        .next()
        .and_then(|s| s.into_string().ok())
        .ok_or_else(protocol)?;
    if args.next().is_some() {
        return Err(protocol());
    }
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?
        .block_on(run(directory, path, name))
}

fn generate_profile_keys(out_dir: &std::path::Path) -> io::Result<()> {
    use l2tunnel_client_core::local::keys::{KeyGeneration, generate};
    std::fs::create_dir_all(out_dir)?;
    let member_pub = generate(&KeyGeneration::Member {
        private: out_dir.join("member.pk8"),
        public: out_dir.join("member.pub"),
    })?
    .ok_or_else(protocol)?;
    let noise_pub = generate(&KeyGeneration::Noise {
        private: out_dir.join("noise-private.key"),
        public: out_dir.join("noise-client.pub"),
    })?
    .ok_or_else(protocol)?;
    generate(&KeyGeneration::Secret {
        output: out_dir.join("admission.key"),
    })?;
    println!(r#"{{"member_pub":"{member_pub}","noise_pub":"{noise_pub}"}}"#);
    Ok(())
}

async fn run(directory: PathBuf, path: PathBuf, name: String) -> io::Result<()> {
    // A dedicated connection ties every native owner to the lifetime of the Java service.
    let mut parent = open(&name)?;
    parent.write_all(b"M")?;
    parent.set_nonblocking(true)?;
    let mut parent = tokio::net::UnixStream::from_std(parent)?;
    let tun_name = name.clone();
    let ready_name = name.clone();
    let plan = UdpClientProfile::load(&directory)?
        .prepare(service::Attachment::readable(PacketLayer::Ip, move || {
            open_tun(&tun_name)
        }))?
        .with_udp_socket_protector(move |socket| {
            let fd = socket.as_fd().try_clone_to_owned();
            let name = name.clone();
            async move {
                let fd = fd?;
                tokio::task::spawn_blocking(move || protect(&name, fd.as_fd()))
                    .await
                    .map_err(io::Error::other)?
            }
        })?;
    let api = local::Server::bind(path)?;
    let (handle, owner) = service::channel();
    // Battery-aware bounded automatic fresh-auth recovery (CL-30 / CL-38):
    // handles lease expiry, counter exhaustion, and transient mobile outages
    // without unbounded background loops. Explicit user commands cancel it.
    handle.set_auto_recovery(service::AutoRecoveryPolicy {
        enabled: true,
        max_attempts: 8,
        initial_backoff: Duration::from_secs(2),
        max_backoff: Duration::from_secs(60),
    });
    let submit_error = |_| io::Error::other("Common service operation rejected");
    let key = handle.next_key().map_err(submit_error)?;
    let operation = handle.connect(plan, key).map_err(submit_error)?.operation;
    let mut byte = [0];
    let ready_signal = async {
        // Wait for initial connection establishment and notify VpnService (`R`),
        // then stay idle so Local API v5 (status, reconnect, live tuning, live
        // carrier switch, meters, tunnel tests) and bounded auto-recovery remain
        // active for the lifetime of the VpnService monitor connection (`M`).
        if let Ok(service::Completed::Connected { .. }) = handle.wait(operation).await {
            let _ = tokio::task::spawn_blocking(move || -> io::Result<()> {
                let mut observed = open(&ready_name)?;
                observed.write_all(b"R")
            })
            .await;
        }
        std::future::pending::<io::Result<()>>().await
    };
    tokio::select! {
        result = ready_signal => result,
        result = parent.read(&mut byte) => result.map(|_| ()),
        result = api.serve_service(handle.clone()) => result,
        _ = owner => Err(io::Error::other("Common owner stopped")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    fn unique_abstract_name(tag: &str) -> String {
        static SEQ: AtomicUsize = AtomicUsize::new(1);
        format!(
            "l2tunnel-android-test-{}-{}-{}",
            tag,
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn bind_abstract_listener(name: &str) -> io::Result<OwnedFd> {
        let fd = net::socket_with(
            net::AddressFamily::UNIX,
            net::SocketType::STREAM,
            net::SocketFlags::CLOEXEC,
            None,
        )?;
        let addr = net::SocketAddrUnix::new_abstract_name(name.as_bytes())?;
        net::bind(&fd, &addr)?;
        net::listen(&fd, 8)?;
        Ok(fd)
    }

    #[test]
    fn broker_protect_and_open_tun_round_trip_and_reject_bad_replies() -> io::Result<()> {
        let name = unique_abstract_name("broker");
        let listener = bind_abstract_listener(&name)?;
        let (hold_tx, hold_rx) = std::sync::mpsc::channel::<OwnedFd>();
        let server_thread = thread::spawn(move || -> io::Result<()> {
            // 1. Protect accepted: receive 1 FD via ScmRights, verify command 'P', reply '1'.
            let conn = net::accept_with(&listener, net::SocketFlags::CLOEXEC)?;
            let mut cmd = [0_u8; 1];
            let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
            let mut control = RecvAncillaryBuffer::new(&mut space);
            let msg = net::recvmsg(
                &conn,
                &mut [IoSliceMut::new(&mut cmd)],
                &mut control,
                net::RecvFlags::CMSG_CLOEXEC,
            )?;
            assert_eq!(msg.bytes, 1);
            assert_eq!(cmd, *b"P");
            let mut got_fd = false;
            for item in control.drain() {
                if let RecvAncillaryMessage::ScmRights(fds) = item {
                    got_fd = fds.count() == 1;
                }
            }
            assert!(got_fd, "expected 1 protected FD via ScmRights");
            let mut s = UnixStream::from(conn);
            s.write_all(b"1")?;
            drop(s);

            // 2. Protect refused: reply '0'.
            let conn = net::accept_with(&listener, net::SocketFlags::CLOEXEC)?;
            let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
            let mut control = RecvAncillaryBuffer::new(&mut space);
            let _ = net::recvmsg(
                &conn,
                &mut [IoSliceMut::new(&mut cmd)],
                &mut control,
                net::RecvFlags::CMSG_CLOEXEC,
            )?;
            let mut s = UnixStream::from(conn);
            s.write_all(b"0")?;
            drop(s);

            // 3. TUN handoff: receive 'T', send '1' + 1 pipe FD via ScmRights.
            let conn = net::accept_with(&listener, net::SocketFlags::CLOEXEC)?;
            let mut s = UnixStream::from(conn);
            s.read_exact(&mut cmd)?;
            assert_eq!(cmd, *b"T");
            let (rx_fd, tx_fd) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?;
            let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
            let mut control = SendAncillaryBuffer::new(&mut space);
            let fds = [rx_fd.as_fd()];
            assert!(control.push(SendAncillaryMessage::ScmRights(&fds)));
            let sent = net::sendmsg(
                &s,
                &[IoSlice::new(b"1")],
                &mut control,
                net::SendFlags::NOSIGNAL,
            )?;
            assert_eq!(sent, 1);
            // Keep write end alive on the main thread until after open_tun checks O_NONBLOCK.
            let _ = hold_tx.send(tx_fd);
            drop(rx_fd);
            Ok(())
        });

        // Test 1: protect accepted
        let udp = std::net::UdpSocket::bind("127.0.0.1:0")?;
        protect(&name, udp.as_fd())?;

        // Test 2: protect refused -> PermissionDenied
        let refused = protect(&name, udp.as_fd());
        assert_eq!(
            refused.err().map(|e| e.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );

        // Test 3: open_tun succeeds and sets O_NONBLOCK on the received FD
        let mut tun = open_tun(&name)?;
        let _keep_pipe_open = hold_rx
            .recv()
            .map_err(|_| io::Error::other("pipe write end channel closed"))?;
        let mut buf = [0_u8; 16];
        assert_eq!(
            tun.receive(&mut buf)?,
            None,
            "received TUN FD must be O_NONBLOCK and yield WouldBlock (None) when empty"
        );
        drop(tun);

        server_thread
            .join()
            .map_err(|_| io::Error::other("broker thread panicked"))??;
        Ok(())
    }

    #[test]
    fn keygen_mode_writes_valid_member_noise_and_admission_files() -> io::Result<()> {
        let dir = std::env::temp_dir().join(format!(
            "l2t-android-keygen-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        generate_profile_keys(&dir)?;
        for name in [
            "member.pk8",
            "member.pub",
            "noise-private.key",
            "noise-client.pub",
            "admission.key",
        ] {
            assert!(dir.join(name).is_file(), "missing generated file {name}");
        }
        assert_eq!(std::fs::read(dir.join("member.pub"))?.len(), 32);
        assert_eq!(std::fs::read(dir.join("noise-client.pub"))?.len(), 32);
        assert_eq!(std::fs::read(dir.join("noise-private.key"))?.len(), 32);
        assert_eq!(std::fs::read(dir.join("admission.key"))?.len(), 32);
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
