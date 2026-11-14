//! Portable strict local API schema and separately gated Unix transport.
//!
//! Existing version 1/2 serde bytes are preserved; explicit transactions add version 3.
//! Sharing these types does not provide Windows IPC or a platform device adapter.
mod schema;
pub use schema::*;
#[cfg(unix)]
mod transport;
#[cfg(unix)]
pub use transport::{Server, request};
