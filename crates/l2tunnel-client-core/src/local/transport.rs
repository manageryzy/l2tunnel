//! Private, bounded Unix API transport; wire types live in the portable schema.
use super::framing::*;
use super::*;
use l2tunnel_runtime::initialization_timing::{
    Outcome as TimingOutcome, Owner as TimingOwner, Stage as TimingStage, Timing,
};
use std::future::Future;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
#[cfg(test)]
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::time::Instant;

/// Listener owning exactly one private Unix socket path.
pub struct Server {
    listener: UnixListener,
    path: PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
}
impl Server {
    /// Bind only inside an existing private directory owned by the effective UID.
    pub fn bind(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
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
    /// Process one authenticated local request at a time. Disconnect does not undo
    /// a handler's submitted peer transaction. Slow/malformed clients are isolated.
    pub async fn serve<F, Fut>(&self, mut handler: F) -> io::Result<()>
    where
        F: FnMut(Request) -> Fut,
        Fut: Future<Output = Response>,
    {
        let mut timing = Timing::from_environment(TimingOwner::LocalApi, Instant::now());
        loop {
            let (mut stream, _) = self.listener.accept().await?;
            timing.accepted_at(Instant::now());
            let credentials = stream.peer_cred().inspect_err(|_| {
                timing.end_request_at(Instant::now(), TimingOutcome::Failed);
            })?;
            if credentials.uid() != self.uid {
                timing.end_request_at(Instant::now(), TimingOutcome::Failed);
                continue;
            }
            let request = match tokio::time::timeout(
                Duration::from_secs(5),
                read_json::<_, Request>(&mut stream, REQUEST_LIMIT),
            )
            .await
            {
                Ok(Ok(request)) if supported_version(request.version) => request,
                _ => {
                    timing.end_request_at(Instant::now(), TimingOutcome::Failed);
                    continue;
                }
            };
            timing.enter_at(TimingStage::ApiHandler, Instant::now());
            let limit = response_limit(request.version);
            let response = handler(request).await;
            timing.enter_at(TimingStage::ApiReply, Instant::now());
            // A disconnected or non-reading client cannot terminate/block the API.
            let reply = tokio::time::timeout(
                Duration::from_secs(5),
                write_json(&mut stream, &response, limit),
            )
            .await;
            timing.replied_at(Instant::now(), matches!(reply, Ok(Ok(()))));
        }
    }
}
impl Drop for Server {
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
/// Submit a local operation. A timeout has unknown remote outcome; query status
/// before retrying a mode change, because an accepted transaction is not rolled back.
pub async fn request(path: impl AsRef<Path>, request: &Request) -> io::Result<Response> {
    if !supported_version(request.version) {
        return Err(invalid("unsupported local API version"));
    }
    tokio::time::timeout(Duration::from_secs(65), async {
        let mut stream = UnixStream::connect(path).await?;
        if stream.peer_cred()?.uid() != rustix::process::geteuid().as_raw() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "local API server UID mismatch",
            ));
        }
        write_json(&mut stream, request, REQUEST_LIMIT).await?;
        let response: Response = read_json(&mut stream, response_limit(request.version)).await?;
        if response.version != request.version {
            return Err(invalid("unsupported local API response version"));
        }
        Ok(response)
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "local request timeout; remote outcome unknown",
        )
    })?
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
