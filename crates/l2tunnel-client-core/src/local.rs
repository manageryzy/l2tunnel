//! Portable strict local API schema and one shared transport with two
//! platform endpoints: a private Unix socket, or on Windows the local API
//! named pipe (docs/modules/windows-local-service.md).
//!
//! Basic proxy actions use version 1; current Common transactions use version 4.
//! Sharing these types does not provide a platform device adapter.
mod carrier;
mod describe;
mod framing;
mod host;
mod info;
mod meters;
mod metrics;
mod operations;
mod profile;
mod schema;
mod sessions;
mod socks;
mod tuning;
mod worker;
pub use carrier::*;
pub use describe::configuration_summary;
pub use host::*;
pub use info::*;
pub use meters::*;
pub use metrics::*;
pub use operations::*;
pub use profile::*;
pub use schema::*;
pub use sessions::*;
pub use socks::*;
pub use tuning::*;
pub use worker::serve_private_common_stream;
#[cfg(any(unix, windows))]
pub mod client;
#[cfg(any(unix, windows))]
pub mod diagnostics;
#[cfg(any(unix, windows))]
pub mod elevate;
pub mod keys;
pub mod redirect_policy;
pub mod share_uri;
#[cfg(any(unix, windows))]
mod transport;
pub mod tunnel_test;
#[cfg(any(unix, windows))]
pub use transport::{CONCURRENT_CONNECTIONS, Server, request, request_operation};
