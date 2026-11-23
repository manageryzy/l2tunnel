//! Portable strict local API schema and separately gated Unix transport.
//!
//! Basic proxy actions use version 1; current Common transactions use version 4.
//! Sharing these types does not provide Windows IPC or a platform device adapter.
mod framing;
mod schema;
mod worker;
pub use schema::*;
pub use worker::serve_private_common_stream;
#[cfg(unix)]
mod transport;
#[cfg(unix)]
pub use transport::{Server, request};
