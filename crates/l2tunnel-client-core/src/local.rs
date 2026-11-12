//! Private, bounded Unix API transport shared by local frontends.
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
/// Current strict local protocol version.
pub const VERSION: u16 = 1;
/// Supported local policy changes; peer authorization still applies separately.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Compression {
    /// Preserve native bytes without compression.
    Off,
    /// Use independent LZ4 only if it is smaller.
    Lz4,
}
/// Local action, independent of wire-management frame bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    /// Query current committed state and pending phase.
    Status {},
    /// Begin proxy drain; acceptance and terminal outcome are separate.
    DrainProxy {},
    /// Submit a standalone native drain; acceptance is not actual completion.
    DrainOpenVpn {},
    /// Request a coordinated peer switch; completion is not a local file edit.
    SwitchCompression {
        /// Target independent packet compression policy.
        compression: Compression,
    },
    /// Request an exact policy from the session's authenticated active catalog.
    SwitchActivePolicy {
        /// Complete channel/weight policy; partial local mutations are not supported.
        policy: crate::active_managed::Policy,
    },
}
/// One finite, versioned local request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Must equal [`VERSION`].
    pub version: u16,
    /// Requested operation.
    pub action: Action,
}
/// Non-secret service state shared by CLI and future GUI.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    /// Committed data configuration epoch.
    pub epoch: u64,
    /// Current transaction phase; this is not inferred from a pending request.
    pub phase: String,
    /// Currently committed compression.
    pub compression: Compression,
    /// Present only for the distinct managed active profile; legacy bytes stay unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<ActiveSnapshot>,
    /// Present only for the fixed proxy profile; omitted from legacy replies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<ProxySnapshot>,
    /// Present only for the explicit standalone native-drain profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub openvpn_drain: Option<crate::openvpn::drain::Snapshot>,
}
/// Fixed authenticated proxy configuration and observed local lifecycle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxySnapshot {
    /// Exact immutable authenticated configuration digest in lowercase hexadecimal.
    pub digest: String,
    /// This frontend successfully submitted a drain command; not completion.
    pub drain_accepted: bool,
    /// Last actual runtime snapshot, absent before its first iteration.
    pub runtime: Option<ProxyStatus>,
    /// Populated only after the actual run future returns.
    pub terminal: Option<ProxyTerminal>,
}
/// Observed runtime counters without credentials or application payloads.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyStatus {
    /// Actual runtime phase name.
    pub phase: String,
    /// Lifetime allocated proxy owners.
    pub flows: usize,
    /// Active proxy owners.
    pub active: usize,
    /// Explicitly stopped or refused owners.
    pub stopped: usize,
    /// Cleanly retired owners.
    pub retired: usize,
    /// Retained common-arbiter bytes.
    pub queued_bytes: usize,
    /// Retained common-arbiter records.
    pub queued_records: usize,
    /// Transparent native bytes admitted to the writer.
    pub transparent_admitted_bytes: u64,
    /// Transparent packets admitted to the writer.
    pub transparent_admitted_packets: u64,
    /// Peer packets actually written to the native device.
    pub native_confirmed_packets: u64,
}
/// Actual run result, distinct from a locally accepted request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProxyTerminal {
    /// Exact coordinated closure completed.
    Closed {
        /// Final runtime accounting, including stopped flows.
        report: ProxyCloseReport,
    },
    /// The runtime failed; no complete-delivery claim.
    Failed {
        /// Bounded non-secret diagnostic produced by the runtime wrapper.
        error: String,
    },
}
/// Finite completed-drain accounting; not an application-consumption guarantee.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyCloseReport {
    /// Local user records handed to the carrier.
    pub local_user_records: u64,
    /// Peer user records received.
    pub peer_user_records: u64,
    /// Local transparent packets admitted.
    pub local_transparent_packets: u64,
    /// Peer transparent packets written to the device.
    pub native_confirmed_packets: u64,
    /// Cleanly retired proxy flows.
    pub clean_flows: usize,
    /// Explicitly stopped or refused proxy flows.
    pub stopped_flows: usize,
    /// Original authenticated physical lanes closed.
    pub tls_lanes_closed: usize,
}
/// Actual active policy and admission state, for CLI and future GUI status.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveSnapshot {
    /// Complete locally committed policy.
    pub policy: crate::active_managed::Policy,
    /// Local admission gate including real Final and management flush barriers.
    pub admitting: bool,
    /// Whether the runtime still owns its authenticated lanes and device.
    pub running: bool,
    /// Canonical committed policy digest, lowercase hexadecimal.
    pub digest: String,
}
/// Structured response, including the actual observed state on rejection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    /// Response schema version.
    pub version: u16,
    /// Action-specific success; DrainProxy means accepted submission, not terminal closure.
    pub ok: bool,
    /// Machine-readable bounded outcome code.
    pub code: String,
    /// Current observed state, when available.
    pub state: Option<Snapshot>,
}
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
                Ok(Ok(request)) if request.version == VERSION => request,
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
    if request.version != VERSION {
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
        if response.version != VERSION {
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
mod tests;
