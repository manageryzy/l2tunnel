//! Unix endpoint of the shared local API transport: one private socket path,
//! peer-UID authorization and owned-path cleanup.
use super::invalid;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::task::{Context, Poll};
use tokio::net::{UnixListener, UnixStream};

/// Accepted server-side connection.
pub(super) type ServerStream = UnixStream;

/// Listener owning exactly one private Unix socket path.
pub(super) struct Listener {
    listener: UnixListener,
    path: PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
}
impl Listener {
    /// Bind only inside an existing private directory owned by the effective UID.
    pub(super) fn bind(path: &Path) -> io::Result<Self> {
        let parent = path
            .parent()
            .ok_or_else(|| invalid("socket requires private parent directory"))?;
        let metadata = std::fs::symlink_metadata(parent)?;
        let uid = rustix::process::geteuid().as_raw();
        if !metadata.is_dir() || metadata.uid() != uid || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "local API parent must be an owned private directory",
            ));
        }
        let listener = UnixListener::bind(path)?;
        let metadata = std::fs::symlink_metadata(path)?;
        let server = Self {
            listener,
            path: path.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
            uid,
        };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(server)
    }
    /// Poll the next connection; an accept error ends the server.
    pub(super) fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<Option<UnixStream>>> {
        self.listener
            .poll_accept(cx)
            .map(|accepted| accepted.map(|(stream, _)| Some(stream)))
    }
    /// Only the server's own effective UID is served.
    pub(super) fn authorize(&self, stream: &UnixStream) -> io::Result<bool> {
        Ok(stream.peer_cred()?.uid() == self.uid)
    }
}
impl Drop for Listener {
    fn drop(&mut self) {
        if let Ok(metadata) = std::fs::symlink_metadata(&self.path)
            && metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _cleanup = std::fs::remove_file(&self.path);
        }
    }
}

/// Connect and require the server to run as this effective UID.
pub(super) async fn connect(path: &Path) -> io::Result<UnixStream> {
    let stream = UnixStream::connect(path).await?;
    if stream.peer_cred()?.uid() != rustix::process::geteuid().as_raw() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "local API server UID mismatch",
        ));
    }
    Ok(stream)
}
