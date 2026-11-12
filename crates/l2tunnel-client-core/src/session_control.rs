//! Shared typed session commands for authorized local frontends.
//!
//! This dispatches existing authenticated-session operations. It does not own
//! connection startup, reconnect, devices or local IPC authorization. The caller
//! must enforce its platform's local access policy before invoking commands.
use crate::Compression;
use crate::local::{Request, Response, VERSION};

/// Cloneable command handle independent of CLI parsing and presentation.
#[derive(Clone)]
pub struct Control(Backend);
#[derive(Clone)]
enum Backend {
    Managed(l2tunnel_runtime::managed::ControlHandle),
    Active(
        l2tunnel_runtime::active_management::ControlHandle,
        Compression,
    ),
}
impl Control {
    /// Bind commands to an existing managed compression session.
    pub fn managed(handle: l2tunnel_runtime::managed::ControlHandle) -> Self {
        Self(Backend::Managed(handle))
    }
    /// Bind commands to an existing active-TUN policy session.
    pub fn active(
        handle: l2tunnel_runtime::active_management::ControlHandle,
        compression: Compression,
    ) -> Self {
        Self(Backend::Active(handle, compression))
    }
    /// Execute a bounded existing session command and await its runtime result.
    /// Enqueueing a switch is not a successful peer commit. Unsupported versions
    /// and operations cannot submit a runtime command.
    pub async fn request(self, request: Request) -> Response {
        if request.version != VERSION {
            return Response {
                version: VERSION,
                ok: false,
                code: "unsupported_version".into(),
                state: None,
            };
        }
        match self.0 {
            Backend::Managed(handle) => local_action(handle, request).await,
            Backend::Active(handle, compression) => {
                active_local_action(handle, compression, request).await
            }
        }
    }
}
async fn local_action(
    handle: l2tunnel_runtime::managed::ControlHandle,
    request: super::local::Request,
) -> super::local::Response {
    use super::local::{Action, Compression as ApiCompression, Response, Snapshot, VERSION};
    use l2tunnel_runtime::managed::ControlError;
    let result = match request.action {
        Action::Status {} => Ok(()),
        Action::SwitchCompression { compression } => handle
            .switch_compression(match compression {
                ApiCompression::Off => Compression::None,
                ApiCompression::Lz4 => Compression::Lz4IfSmaller,
            })
            .await
            .map(|_| ())
            .map_err(|error| match error {
                ControlError::Busy => "busy",
                ControlError::NotCoordinator => "not_coordinator",
                ControlError::Aborted => "aborted",
                ControlError::Closed => "closed",
            }),
        Action::SwitchActivePolicy { .. } | Action::DrainProxy {} | Action::DrainOpenVpn {} => {
            Err("unsupported")
        }
    };
    let code = result.err().unwrap_or("ok");
    let state = handle.status().map(|status| Snapshot {
        epoch: status.epoch.0,
        phase: format!("{:?}", status.phase),
        compression: match status.compression {
            Compression::None => ApiCompression::Off,
            Compression::Lz4IfSmaller => ApiCompression::Lz4,
        },
        active: None,
        proxy: None,
        openvpn_drain: None,
        raw_packet: None,
        rolling: None,
        #[cfg(unix)]
        swift: None,
    });
    Response {
        version: VERSION,
        ok: result.is_ok(),
        code: code.into(),
        state,
    }
}
async fn active_local_action(
    handle: l2tunnel_runtime::active_management::ControlHandle,
    compression: Compression,
    request: super::local::Request,
) -> super::local::Response {
    use super::local::{
        Action, ActiveSnapshot, Compression as ApiCompression, Response, Snapshot, VERSION,
    };
    use l2tunnel_runtime::active_management::ControlError;
    let result = match request.action {
        Action::Status {} => Ok(()),
        Action::SwitchCompression { .. } | Action::DrainProxy {} | Action::DrainOpenVpn {} => {
            Err("unsupported")
        }
        Action::SwitchActivePolicy { policy } => match policy.mode() {
            Err(_) => Err("invalid_policy"),
            Ok(mode) => handle
                .switch_policy(mode)
                .await
                .map(|_| ())
                .map_err(|error| match error {
                    ControlError::Busy => "busy",
                    ControlError::NotCoordinator => "not_coordinator",
                    ControlError::Unsupported => "unsupported_policy",
                    ControlError::Aborted => "aborted",
                    ControlError::Closed => "closed",
                }),
        },
    };
    let state = handle.status().map(|status| Snapshot {
        epoch: status.epoch.0,
        phase: format!("{:?}", status.phase),
        compression: match compression {
            Compression::None => ApiCompression::Off,
            Compression::Lz4IfSmaller => ApiCompression::Lz4,
        },
        active: Some(ActiveSnapshot {
            policy: super::active_managed::Policy::from_mode(status.mode),
            admitting: status.admitting,
            running: status.traffic.running,
            digest: status
                .digest
                .0
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        }),
        proxy: None,
        openvpn_drain: None,
        raw_packet: None,
        rolling: None,
        #[cfg(unix)]
        swift: None,
    });
    Response {
        version: VERSION,
        ok: result.is_ok(),
        code: result.err().unwrap_or("ok").into(),
        state,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn version_rejection_cannot_submit_a_switch() -> std::io::Result<()> {
        let (handle, _owner) = l2tunnel_runtime::managed::channel();
        let control = Control::managed(handle);
        let mut invalid = Box::pin(control.clone().request(Request {
            version: VERSION + 1,
            action: crate::local::Action::SwitchCompression {
                compression: crate::local::Compression::Lz4,
            },
        }));
        let response =
            std::future::poll_fn(|cx| match std::future::Future::poll(invalid.as_mut(), cx) {
                std::task::Poll::Ready(response) => std::task::Poll::Ready(Ok(response)),
                std::task::Poll::Pending => std::task::Poll::Ready(Err(std::io::Error::other(
                    "invalid version submitted a runtime switch",
                ))),
            })
            .await?;
        assert!(!response.ok);
        assert_eq!(response.code, "unsupported_version");
        let status = control
            .request(Request {
                version: VERSION,
                action: crate::local::Action::Status {},
            })
            .await;
        assert!(status.ok);
        Ok(())
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn active_local_requests_wait_for_runtime_and_report_closed_or_busy() {
        use crate::local::{Action, Request, VERSION};
        let (handle, receiver) = l2tunnel_runtime::active_management::channel();
        let valid = crate::active_managed::Policy {
            channels: 2,
            dscp_weights: vec![1; 64],
        };
        for (action, code) in [
            (Action::DrainProxy {}, "unsupported"),
            (Action::DrainOpenVpn {}, "unsupported"),
            (
                Action::SwitchCompression {
                    compression: crate::local::Compression::Off,
                },
                "unsupported",
            ),
            (
                Action::SwitchActivePolicy {
                    policy: crate::active_managed::Policy {
                        channels: 0,
                        ..valid.clone()
                    },
                },
                "invalid_policy",
            ),
        ] {
            let response = Control::active(handle.clone(), Compression::None)
                .request(Request {
                    version: VERSION,
                    action,
                })
                .await;
            assert!(!response.ok);
            assert_eq!(response.code, code);
            assert!(response.state.is_none());
        }
        let request = Request {
            version: VERSION,
            action: Action::SwitchActivePolicy { policy: valid },
        };
        let mut pending =
            Box::pin(Control::active(handle.clone(), Compression::None).request(request.clone()));
        // Poll exactly once: enqueueing a request is never a successful switch.
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(pending.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        let busy = Control::active(handle, Compression::None)
            .request(request)
            .await;
        assert!(!busy.ok);
        assert_eq!(busy.code, "busy");
        drop(receiver);
        let closed = pending.await;
        assert!(!closed.ok);
        assert_eq!(closed.code, "closed");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn managed_profile_rejects_proxy_drain_without_submission() {
        use crate::local::{Action, Request, VERSION};
        let (handle, _control) = l2tunnel_runtime::managed::channel();
        for action in [Action::DrainProxy {}, Action::DrainOpenVpn {}] {
            let response = Control::managed(handle.clone())
                .request(Request {
                    version: VERSION,
                    action,
                })
                .await;
            assert!(!response.ok);
            assert_eq!(response.code, "unsupported");
        }
    }
}
