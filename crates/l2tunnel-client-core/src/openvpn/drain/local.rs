//! Private local frontend. Its observation grace never retains network owners.
use super::{Acceptance, Handle, Run};
use crate::{Compression, local};
use std::{io, time::Duration};

pub(super) fn action(
    handle: &Handle,
    compression: Compression,
    request: local::Request,
) -> local::Response {
    let result = match request.action {
        local::Action::Status {} => Ok("ok"),
        local::Action::DrainOpenVpn {} => match handle.request_drain() {
            Ok(Acceptance::Accepted) => Ok("accepted"),
            Ok(Acceptance::AlreadyAccepted) => Ok("already_accepted"),
            Err(_) => Err("closed"),
        },
        local::Action::DrainProxy {}
        | local::Action::SetSwiftPolicy { .. }
        | local::Action::Disconnect {}
        | local::Action::Reconnect {}
        | local::Action::SwitchCompression { .. }
        | local::Action::SwitchActivePolicy { .. } => Err("unsupported"),
    };
    match handle.snapshot() {
        Ok(state) => local::Response {
            version: local::VERSION,
            ok: result.is_ok(),
            code: result.unwrap_or_else(|v| v).into(),
            state: Some(local::Snapshot {
                epoch: 1,
                phase: if state.terminal.is_some() {
                    "terminal"
                } else if state.drain_accepted {
                    "drain_accepted"
                } else {
                    "running"
                }
                .into(),
                compression: match compression {
                    Compression::None => local::Compression::Off,
                    Compression::Lz4IfSmaller => local::Compression::Lz4,
                },
                raw_packet: None,
                rolling: None,
                #[cfg(unix)]
                swift: None,
                #[cfg(unix)]
                secure_udp: None,
                active: None,
                proxy: None,
                openvpn_drain: Some(state),
            }),
        },
        Err(_) => local::Response {
            version: local::VERSION,
            ok: false,
            code: "internal_state".into(),
            state: None,
        },
    }
}
fn print_status(handle: &Handle) -> io::Result<()> {
    println!(
        "{}",
        serde_json::json!({"kind":"openvpn_drain_status", "state":handle.snapshot()?})
    );
    Ok(())
}
/// Supervise the actual runner and local API, then retain only local status briefly.
pub(crate) async fn serve(
    run: Run,
    handle: Handle,
    compression: Compression,
    api: Option<local::Server>,
    stats: Duration,
    grace: Duration,
) -> io::Result<()> {
    let service = async {
        match &api {
            Some(api) => {
                api.serve(|request| std::future::ready(action(&handle, compression, request)))
                    .await
            }
            None => std::future::pending::<io::Result<()>>().await,
        }
    };
    let diagnostics = async {
        if stats.is_zero() {
            return std::future::pending::<io::Result<()>>().await;
        }
        let mut ticker = tokio::time::interval(stats);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            print_status(&handle)?;
        }
    };
    tokio::pin!(service, diagnostics);
    let mut run = Box::pin(run);
    let outcome = tokio::select! {
        result=&mut run => result,
        result=&mut service => { drop(run); print_status(&handle)?; return Err(result.err().unwrap_or_else(||io::Error::other("native local API unexpectedly stopped"))); },
        result=&mut diagnostics => { drop(run); print_status(&handle)?; return Err(result.err().unwrap_or_else(||io::Error::other("native diagnostics unexpectedly stopped"))); },
    };
    // Actual runtime returned. Release the completed retained future before local grace.
    drop(run);
    print_status(&handle)?;
    if api.is_some() {
        let end = tokio::time::Instant::now()
            .checked_add(grace)
            .ok_or_else(|| io::Error::other("local observation deadline overflow"))?;
        tokio::select! { _=tokio::time::sleep_until(end)=>{}, _=&mut service=>{} }
    }
    match outcome {
        Ok(_) => Ok(()),
        Err(error) => Err(error.reason),
    }
}
