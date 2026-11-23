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
    let directory = PathBuf::from(args.next().ok_or_else(protocol)?);
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
    let submit_error = |_| io::Error::other("Common service operation rejected");
    let key = handle.next_key().map_err(submit_error)?;
    let operation = handle.connect(plan, key).map_err(submit_error)?.operation;
    let mut byte = [0];
    let lifecycle = async {
        match handle.wait(operation).await.map_err(submit_error)? {
            service::Completed::Connected { generation } => {
                // Signal readiness only after authentication, TUN attachment and runtime observation.
                let mut observed = open(&ready_name)?;
                observed.write_all(b"R")?;
                let _ = handle
                    .wait_stopped(generation)
                    .await
                    .map_err(submit_error)?;
                Err(io::Error::other("Common session stopped"))
            }
            _ => Err(io::Error::other("UDP client setup failed")),
        }
    };
    tokio::select! {
        result = lifecycle => result,
        result = parent.read(&mut byte) => result.map(|_| ()),
        result = api.serve(|request| handle.request(request)) => result,
        _ = owner => Err(io::Error::other("Common owner stopped")),
    }
}
