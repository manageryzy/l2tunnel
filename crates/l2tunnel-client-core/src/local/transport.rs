//! Private, bounded Unix API transport; wire types live in the portable schema.
use super::*;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

const REQUEST_LIMIT: usize = 4096;
const RESPONSE_LIMIT: usize = 8192;
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
async fn read_json<R: AsyncRead + Unpin, T: for<'a> Deserialize<'a>>(
    stream: &mut R,
    maximum: usize,
) -> io::Result<T> {
    let count = stream.read_u32().await? as usize;
    if count == 0 || count > maximum {
        return Err(invalid("local API message exceeds bound"));
    }
    let mut bytes = vec![0; count];
    stream.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes).map_err(|_| invalid("invalid local API JSON"))
}
async fn write_json<W: AsyncWrite + Unpin, T: Serialize>(
    stream: &mut W,
    value: &T,
    maximum: usize,
) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(invalid("local API reply exceeds bound"));
    }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await
}

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
        loop {
            let (mut stream, _) = self.listener.accept().await?;
            if stream.peer_cred()?.uid() != self.uid {
                continue;
            }
            let request = match tokio::time::timeout(
                Duration::from_secs(5),
                read_json::<_, Request>(&mut stream, REQUEST_LIMIT),
            )
            .await
            {
                Ok(Ok(request)) if supported_version(request.version) => request,
                _ => continue,
            };
            let response = handler(request).await;
            // A disconnected or non-reading client cannot terminate/block the API.
            let _reply = tokio::time::timeout(
                Duration::from_secs(5),
                write_json(&mut stream, &response, RESPONSE_LIMIT),
            )
            .await;
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
        let response: Response = read_json(&mut stream, RESPONSE_LIMIT).await?;
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
