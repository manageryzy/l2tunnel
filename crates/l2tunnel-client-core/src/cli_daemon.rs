//! `daemon`: the long-running Linux service (owner decision 2026-11-23,
//! in-process profile switching). It owns the local API, the state directory
//! (device/route ownership record and profile store) and one service owner
//! that runs whichever stored profile is connected. It starts idle unless a
//! default profile is set; nothing is connected or opened before that.
use super::*;
use crate::local::{ProfileDocument, SERVICE_OPTIONS};
use crate::service;

/// Build a stored profile's plan with the same option checks and preparation
/// as `connect`/`serve`. Reads credentials and the transaction plan; opens no
/// socket or device.
pub(super) fn prepare_profile(document: &ProfileDocument) -> io::Result<service::Prepared> {
    document.validate().map_err(input)?;
    let command = document.role.command();
    let allowed = run_options(command);
    if let Some(key) = document
        .options
        .keys()
        .find(|key| SERVICE_OPTIONS.contains(&key.as_str()) || !allowed.contains(&key.as_str()))
    {
        return Err(input(format!("{key} is not a {command} profile option")));
    }
    let options = &document.options;
    tls_frontend::preflight(command, options)?;
    let config = configuration(options)?;
    let selected = secure_udp_frontend::selection(command, options, config)?.ok_or_else(|| {
        input("select --record-profile common and an explicit --carrier with --common-transaction-plan")
    })?;
    secure_udp_frontend::prepare(command, options, config, &selected)
}

/// Serve until the service owner or the API server ends.
pub(super) async fn run(options: &BTreeMap<String, String>) -> io::Result<()> {
    let socket = required(options, "--control-socket")?;
    let state = required(options, "--state-dir")?.to_owned();
    let api = local::Server::bind(socket)?;
    let (handle, owner) = service::channel();
    // Checks the state directory and releases routes a crashed run left.
    service::host::attach_state_dir(&handle, Some(&state)).await?;
    let store = service::profile_store::FileStore::open(
        Path::new(&state),
        std::sync::Arc::new(prepare_profile),
    )?;
    if handle.attach_profiles(store.clone()).is_err() {
        return Err(io::Error::other("a profile store is already attached"));
    }
    if let Some(name) = service::profiles::ProfileStore::default_profile(&*store) {
        let key = handle
            .next_key()
            .map_err(|error| io::Error::other(format!("service: {error:?}")))?;
        // A default that cannot connect leaves the service idle and reachable.
        if let Err(error) = handle.connect_profile(&name, false, key) {
            eprintln!("l2tunnel: default profile {name} was not connected: {error:?}");
        }
    }
    let mut stop = handle.enable_stop();
    tokio::select! {
        result = owner => result,
        result = api.serve_service(handle.clone()) => result,
        // The stop operation already disconnected and completed.
        _ = stop.wait_for(|stopping| *stopping) => Ok(()),
    }
}
