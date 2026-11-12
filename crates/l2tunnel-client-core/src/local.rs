//! Portable strict local API schema and separately gated Unix transport.
//!
//! Request/response serde bytes and the local protocol version are unchanged.
//! Sharing these types does not provide Windows IPC or a platform device adapter.
mod schema;
pub use schema::*;
#[cfg(unix)]
mod transport;
#[cfg(unix)]
pub use transport::{Server, request};
