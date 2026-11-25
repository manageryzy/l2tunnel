//! Local API live in-session carrier / UDP cover switching view (`DGUI-14`).
use super::{Handle, ObservedBackend};
use crate::local::{CarrierChoice, CarrierSwitchView, Role};

impl Handle {
    /// Current effective carrier/cover and selectable live switch targets.
    pub(super) fn carrier_switch_view(&self) -> Result<CarrierSwitchView, &'static str> {
        let (frame, role) = {
            let state = self.0.lock();
            let role = state
                .plan
                .as_ref()
                .map_or(Role::Unconfigured, super::Prepared::role);
            let snapshot = Self::snapshot_locked(&state);
            let frame = match snapshot.runtime {
                Some(super::Observation::SecureUdpCommon(frame)) => *frame,
                Some(super::Observation::Proxy(_)) => return Err("unsupported"),
                None => return Err("not_running"),
            };
            if !matches!(state.backend, Some(ObservedBackend::SecureUdpCommon(_))) {
                return Err("not_running");
            }
            (frame, role)
        };
        let status = frame.status().map_err(|_| "status_unavailable")?;
        let is_udp = status.maintained_carrier.is_none()
            && status.raw_carrier.is_none()
            && status.original_carrier.is_none();
        let current_carrier = if is_udp {
            "udp".to_owned()
        } else {
            status.carrier.clone()
        };
        let current_cover = is_udp.then(|| status.carrier.clone());
        let switches = frame
            .runtime
            .as_ref()
            .and_then(|rt| rt.carrier_switch)
            .map_or(0, |cs| cs.switches);

        let udp_reason: Option<String> = if role == Role::Server {
            Some("client initiates live carrier switches".into())
        } else if !is_udp {
            Some("live carrier switching is currently supported on UDP Common sessions".into())
        } else {
            None
        };

        let udp_choice = |id: &str, label: &str| CarrierChoice {
            id: id.into(),
            label: label.into(),
            available: udp_reason.is_none(),
            reason: udp_reason.clone(),
        };

        let choices = vec![
            udp_choice("quic-like", "UDP · QUIC-like"),
            udp_choice("media-like", "UDP · Media-like (RTP)"),
            udp_choice("tls-like", "UDP · TLS-like"),
            CarrierChoice {
                id: "tcp".into(),
                label: "TCP / TLS".into(),
                available: false,
                reason: Some(
                    "requires TLS credentials (--cert/--key/--ca) and a TCP listener; switch via profile reconnect"
                        .into(),
                ),
            },
            CarrierChoice {
                id: "quic".into(),
                label: "QUIC (Quinn)".into(),
                available: false,
                reason: Some(
                    "requires TLS credentials (--cert/--key/--ca) and a QUIC listener; switch via profile reconnect"
                        .into(),
                ),
            },
        ];

        Ok(CarrierSwitchView {
            current_carrier,
            current_cover,
            local: status.local,
            peer: status.peer,
            switches,
            choices,
        })
    }
}
