//! Shared current Common proxy presentation.
#[cfg(target_os = "linux")]
use super::*;
#[cfg(target_os = "linux")]
#[path = "cli_service.rs"]
mod shared;
#[cfg(target_os = "linux")]
pub(crate) use shared::{
    Event as SharedEvent, Presentation as SharedPresentation, serve as serve_shared,
};
#[cfg(all(test, target_os = "linux"))]
pub(crate) use shared::{
    Event as ServiceEvent, Presentation as ServicePresentation, serve as serve_shared_for_test,
};
