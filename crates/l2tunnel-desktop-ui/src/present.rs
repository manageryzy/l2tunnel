//! Plain-language presentation of service state for the window (usability
//! review 2026-11-24): one headline with a tone, the reason a session ended
//! and the next step, and which profile and device the session uses. Pure
//! functions over the model, so the wording is unit-tested.
use crate::model::Model;
use l2tunnel_client_core::local::{DeviceState, TerminalState};

/// Colour class of the headline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tone {
    /// Connected.
    Good,
    /// Setting up, switching or stopping.
    Busy,
    /// Failed or no service.
    Bad,
    /// Disconnected or not attached.
    Idle,
}

/// What the top bar and the Overview lead with.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Headline {
    /// Short state, e.g. "Connected" or "Connection failed".
    pub text: String,
    /// Colour class.
    pub tone: Tone,
    /// Why, and what to do next, when that is not obvious.
    pub detail: Option<String>,
}

/// Why a session ended, in words, preferring the distinct `terminal_reason`
/// when reported by the service.
pub fn ended_reason_text(reason: Option<&str>, terminal: Option<&TerminalState>) -> String {
    if let Some(reason) = reason {
        return match reason {
            "lease_expired" => "the session lease expired".into(),
            "counter_exhausted" => "the session packet-counter limit was reached".into(),
            "peer_timeout" => "the peer stopped answering liveness checks".into(),
            "native_stall" => "the local tunnel device stalled writing packets".into(),
            "policy_timeout" => "a live protocol switch timed out waiting for the peer".into(),
            "recovery_exhausted" => "automatic recovery retries were exhausted".into(),
            "cancelled" => "it was disconnected".into(),
            "closed" | "proxy_retired" => "the session closed normally".into(),
            "protocol" => "the profile or the peer sent something invalid".into(),
            other => format!("an error occurred ({})", other.replace('_', " ")),
        };
    }
    match terminal {
        Some(terminal) => ended_text(terminal),
        None => "an unexpected error occurred".into(),
    }
}

/// Why a session ended, in words.
pub fn ended_text(terminal: &TerminalState) -> String {
    match terminal {
        TerminalState::Aborted => "it was disconnected".into(),
        TerminalState::Closed => "the proxy session closed normally".into(),
        TerminalState::Failed { error_kind } => match error_kind.as_str() {
            "timed_out" => {
                "the peer stopped answering or the session lease ran out (timed out)".into()
            }
            "connection_refused" => "the peer refused the connection".into(),
            "permission_denied" => "the service lacks a permission it needs".into(),
            "not_found" => "a file or device the profile names was not found".into(),
            "invalid_input" | "invalid_data" => {
                "the profile or the peer sent something invalid".into()
            }
            other => format!("an error occurred ({})", other.replace('_', " ")),
        },
    }
}

/// The current headline.
pub fn headline(model: &Model) -> Headline {
    let Some(status) = model.status() else {
        return match model.path() {
            None => Headline {
                text: "Not attached".into(),
                tone: Tone::Idle,
                detail: Some("Start the service or choose a running one.".into()),
            },
            Some(_) if model.offline() => Headline {
                text: "Service not running".into(),
                tone: Tone::Bad,
                detail: Some("Start the service to connect.".into()),
            },
            Some(_) => Headline {
                text: "Contacting the service…".into(),
                tone: Tone::Busy,
                detail: None,
            },
        };
    };
    let setup = model
        .setup_stage()
        .map(|stage| format!(" ({})", stage.replace('_', " ")))
        .unwrap_or_default();
    if let Some(recovery) = status.recovery.as_ref().filter(|r| r.active) {
        let wait = recovery
            .next_retry_ms
            .map(|ms| format!(" in {:.1} s", ms as f64 / 1000.0))
            .unwrap_or_default();
        return Headline {
            text: format!(
                "Reconnecting (attempt {}/{})…",
                recovery.attempt, recovery.max_attempts
            ),
            tone: Tone::Busy,
            detail: Some(format!(
                "Automatic fresh-authentication recovery{wait} after {}.",
                ended_reason_text(Some(recovery.reason.as_str()), status.terminal.as_ref())
            )),
        };
    }
    match status.phase.as_str() {
        "connected" => Headline {
            text: "Connected".into(),
            tone: Tone::Good,
            detail: None,
        },
        "preparing" | "authenticating" if status.listening.is_some() => Headline {
            text: "Waiting for the client".into(),
            tone: Tone::Busy,
            detail: status
                .listening
                .as_ref()
                .map(|address| format!("Listening on {address}.")),
        },
        "preparing" | "authenticating" => Headline {
            text: format!("Connecting…{setup}"),
            tone: Tone::Busy,
            detail: None,
        },
        "applying" => Headline {
            text: "Switching configuration…".into(),
            tone: Tone::Busy,
            detail: None,
        },
        "stopping" => Headline {
            text: "Disconnecting…".into(),
            tone: Tone::Busy,
            detail: None,
        },
        "failed" => Headline {
            text: "Connection failed".into(),
            tone: Tone::Bad,
            detail: Some(
                if status.terminal_reason.is_some() || status.terminal.is_some() {
                    format!(
                        "The session ended because {}. Reconnect to try again.",
                        ended_reason_text(
                            status.terminal_reason.as_deref(),
                            status.terminal.as_ref()
                        )
                    )
                } else {
                    "Reconnect to try again.".into()
                },
            ),
        },
        "closed" => Headline {
            text: "Service closing".into(),
            tone: Tone::Idle,
            detail: None,
        },
        _ => Headline {
            text: "Disconnected".into(),
            tone: Tone::Idle,
            detail: None,
        },
    }
}

/// How the outer carrier looks on the network, in words.
pub fn carrier_words(outer: &str, cover: &str) -> String {
    let cover = match cover {
        "quic-like" => Some("looks like QUIC"),
        "media-like" => Some("looks like media streaming"),
        "openvpn-like" => Some("looks like OpenVPN"),
        "—" | "" => None,
        _ => None,
    };
    match cover {
        Some(cover) => format!("{outer}, {cover}"),
        None => outer.to_owned(),
    }
}

/// Profile the service runs (reported by the service).
pub fn running_profile(model: &Model) -> Option<&str> {
    model.status().and_then(|status| status.profile.as_deref())
}

/// Tunnel device of the running profile, else of the default profile.
pub fn profile_device(model: &Model) -> Option<String> {
    let profiles = model.profiles()?;
    let running = running_profile(model);
    profiles
        .iter()
        .find(|profile| Some(profile.name.as_str()) == running)
        .or_else(|| profiles.iter().find(|profile| profile.default))
        .and_then(|profile| profile.device.clone())
}

/// Profiles naming `device`.
pub fn profiles_using(model: &Model, device: &str) -> Vec<String> {
    model
        .profiles()
        .unwrap_or_default()
        .iter()
        .filter(|profile| profile.device.as_deref() == Some(device))
        .map(|profile| profile.name.clone())
        .collect()
}

/// A tunnel device: created by the service or named by a stored profile.
pub fn is_tunnel(model: &Model, device: &DeviceState) -> bool {
    device.owned || !profiles_using(model, &device.name).is_empty()
}

/// Warning when the running session's device cannot carry traffic.
pub fn device_warning(model: &Model) -> Option<String> {
    let connected = model.status()?.phase == "connected";
    let name = profile_device(model)?;
    let device = model.devices()?.iter().find(|device| device.name == name)?;
    let problem = match (device.up, device.addresses.is_empty()) {
        (false, true) => "is down and has no address",
        (false, false) => "is down",
        (true, true) => "has no address",
        (true, false) => return None,
    };
    let owner = if device.owned {
        "Configure it on the Devices page."
    } else {
        "It was created outside l2tunnel, so set it up with your system tools (ip link / ip addr)."
    };
    Some(format!(
        "{name} {problem}, so {} {owner}",
        if connected {
            "no user traffic passes through the tunnel."
        } else {
            "user traffic will not pass once connected."
        }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reasons_and_carriers_read_as_words() {
        assert_eq!(
            ended_text(&TerminalState::Failed {
                error_kind: "timed_out".into()
            }),
            "the peer stopped answering or the session lease ran out (timed out)"
        );
        assert_eq!(
            ended_text(&TerminalState::Failed {
                error_kind: "weird_thing".into()
            }),
            "an error occurred (weird thing)"
        );
        assert_eq!(
            ended_reason_text(Some("lease_expired"), None),
            "the session lease expired"
        );
        assert_eq!(
            ended_reason_text(Some("peer_timeout"), None),
            "the peer stopped answering liveness checks"
        );
        assert_eq!(
            ended_reason_text(Some("recovery_exhausted"), None),
            "automatic recovery retries were exhausted"
        );
        assert_eq!(carrier_words("UDP", "quic-like"), "UDP, looks like QUIC");
        assert_eq!(carrier_words("TCP", "—"), "TCP");
        let model = Model::default();
        assert_eq!(headline(&model).text, "Not attached");
        assert_eq!(headline(&model).tone, Tone::Idle);
        assert_eq!(profile_device(&model), None);
        assert_eq!(device_warning(&model), None);
    }
}
