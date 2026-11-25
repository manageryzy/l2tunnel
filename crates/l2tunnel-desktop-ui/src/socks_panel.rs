//! SOCKS5 entry page over the TCP-proxy profile (`docs/modules/desktop-gui.md`,
//! `DGUI-08`). Shares the same version-5 `socks_get`, `socks_set` and
//! `socks_flows` actions as `l2tunnelctl socks`.
use crate::model::{Command, Model};
use crate::pages::tone_dot;
use crate::present::Tone;
use crate::stats::format_bytes;
use eframe::egui;
use l2tunnel_client_core::local::{
    SOCKS_DEFAULT_HOST, SOCKS_DEFAULT_MAX_FLOWS, SOCKS_DEFAULT_PORT, SocksAuthMode, SocksSettings,
    SocksStatus,
};

/// Editable draft of SOCKS5 settings inside the desktop window.
#[derive(Clone, Debug)]
pub struct SocksForm {
    /// Draft enable switch.
    pub enabled: bool,
    /// Draft bind IP literal.
    pub listen_host: String,
    /// Draft TCP listen port text.
    pub listen_port: String,
    /// Draft authentication mode.
    pub auth_mode: SocksAuthMode,
    /// Draft RFC 1929 username.
    pub username: String,
    /// Write-only password entry (left blank to keep an existing stored password).
    pub password: String,
    /// Comma-separated allowed client CIDRs.
    pub allowed_clients: String,
    /// Draft maximum simultaneous flows.
    pub max_flows: String,
    /// Whether the form has been populated from the attached service.
    pub synced: bool,
    /// Whether the user has unsaved edits.
    pub dirty: bool,
}

impl Default for SocksForm {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_host: SOCKS_DEFAULT_HOST.into(),
            listen_port: SOCKS_DEFAULT_PORT.to_string(),
            auth_mode: SocksAuthMode::None,
            username: String::new(),
            password: String::new(),
            allowed_clients: "127.0.0.1/32".into(),
            max_flows: SOCKS_DEFAULT_MAX_FLOWS.to_string(),
            synced: false,
            dirty: false,
        }
    }
}

impl SocksForm {
    /// Populate the form from the service's current settings.
    pub fn load_from(&mut self, settings: &SocksSettings) {
        self.enabled = settings.enabled;
        self.listen_host = settings.listen_host.clone();
        self.listen_port = settings.listen_port.to_string();
        self.auth_mode = settings.auth_mode;
        self.username = settings.username.clone().unwrap_or_default();
        self.password.clear();
        self.allowed_clients = settings.allowed_clients.join(", ");
        self.max_flows = settings.max_flows.to_string();
        self.synced = true;
        self.dirty = false;
    }

    /// Build and validate [`SocksSettings`] using the same strict rules as the service.
    pub fn build(&self, password_set: bool) -> Result<SocksSettings, String> {
        let listen_port: u16 = self
            .listen_port
            .trim()
            .parse()
            .map_err(|_| "Listen port must be 1..=65535".to_owned())?;
        let max_flows: u16 = self
            .max_flows
            .trim()
            .parse()
            .map_err(|_| "Max flows must be 1..=512".to_owned())?;
        let allowed_clients: Vec<String> = self
            .allowed_clients
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(str::to_owned)
            .collect();
        let settings = SocksSettings {
            enabled: self.enabled,
            listen_host: self.listen_host.trim().to_owned(),
            listen_port,
            auth_mode: self.auth_mode,
            username: match self.auth_mode {
                SocksAuthMode::None => None,
                SocksAuthMode::UserPass => Some(self.username.trim().to_owned()),
            },
            password: match self.auth_mode {
                SocksAuthMode::None => None,
                SocksAuthMode::UserPass => {
                    if self.password.is_empty() {
                        None
                    } else {
                        Some(self.password.clone())
                    }
                }
            },
            password_set,
            allowed_clients,
            max_flows,
        };
        settings.validate(password_set, false)?;
        Ok(settings)
    }
}

/// Draw the SOCKS5 page and return any service exchanges requested.
pub fn panel(ui: &mut egui::Ui, model: &mut Model, form: &mut SocksForm) -> Vec<Command> {
    let mut commands = Vec::new();
    let status = model.socks().cloned();
    if status.is_none() && !model.socks_loading() && model.socks_error().is_none() {
        commands.extend(model.refresh_socks());
    }
    if let Some(status) = &status
        && (!form.synced || (!form.dirty && !model.socks_busy()))
    {
        form.load_from(&status.settings);
    }

    // Card 1: Status & counters
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal_wrapped(|ui| {
            let (tone, headline) = match status.as_ref() {
                Some(SocksStatus {
                    listening: Some(addr),
                    ..
                }) => (Tone::Good, format!("Listening on {addr}")),
                Some(SocksStatus {
                    proxy_active: true, ..
                }) => (Tone::Idle, "Stopped".to_owned()),
                Some(_) => (Tone::Busy, "Waiting for TCP-proxy profile".to_owned()),
                None => (Tone::Idle, "Loading SOCKS5 status…".to_owned()),
            };
            tone_dot(ui, tone);
            ui.strong(headline);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add_enabled(!model.socks_loading(), egui::Button::new("Refresh"))
                    .clicked()
                {
                    commands.extend(model.refresh_socks());
                }
                if model.socks_loading() || model.socks_busy() {
                    ui.spinner();
                }
            });
        });
        if let Some(status) = &status {
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                let proxy_badge = if status.proxy_active {
                    "needs: tcp-proxy profile ✓"
                } else {
                    "needs: tcp-proxy profile (inactive)"
                };
                ui.weak(proxy_badge);
                ui.separator();
                ui.weak(format!(
                    "{} active / {} max · {} total · {} refused · {} rejected clients",
                    status.active_flows,
                    status.settings.max_flows,
                    status.total_flows,
                    status.failed_connects,
                    status.rejected_clients
                ));
            });
            if let Some(error) = &status.last_error {
                ui.add_space(4.0);
                ui.colored_label(ui.visuals().warn_fg_color, format!("Last error: {error}"));
            }
        }
        if let Some(error) = model.socks_error() {
            ui.add_space(4.0);
            ui.colored_label(ui.visuals().warn_fg_color, error);
        }
    });

    ui.add_space(10.0);

    // Card 2: Settings form
    let password_set = status
        .as_ref()
        .is_some_and(|status| status.settings.password_set);
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.strong("SOCKS5 listener settings");
        ui.weak(
            "Defaults to loopback only (127.0.0.1:1080). Listening on a wider address requires an \
             explicit allowed-client CIDR list.",
        );
        ui.add_space(6.0);
        let mut changed = false;
        egui::Grid::new("socks-settings-grid")
            .num_columns(2)
            .spacing([14.0, 6.0])
            .show(ui, |ui| {
                ui.label("Listener");
                if ui
                    .checkbox(&mut form.enabled, "Enable local SOCKS5 proxy")
                    .changed()
                {
                    changed = true;
                }
                ui.end_row();

                ui.label("Listen");
                ui.horizontal(|ui| {
                    if ui
                        .add(
                            egui::TextEdit::singleline(&mut form.listen_host)
                                .desired_width(170.0)
                                .hint_text("127.0.0.1"),
                        )
                        .changed()
                    {
                        changed = true;
                    }
                    ui.label(":");
                    if ui
                        .add(
                            egui::TextEdit::singleline(&mut form.listen_port)
                                .desired_width(70.0)
                                .hint_text("1080"),
                        )
                        .changed()
                    {
                        changed = true;
                    }
                });
                ui.end_row();

                ui.label("Authentication");
                ui.horizontal(|ui| {
                    if ui
                        .radio_value(&mut form.auth_mode, SocksAuthMode::None, "None")
                        .changed()
                    {
                        changed = true;
                    }
                    if ui
                        .radio_value(
                            &mut form.auth_mode,
                            SocksAuthMode::UserPass,
                            "Username / password",
                        )
                        .changed()
                    {
                        changed = true;
                    }
                });
                ui.end_row();

                if form.auth_mode == SocksAuthMode::UserPass {
                    ui.label("Username");
                    if ui
                        .add(
                            egui::TextEdit::singleline(&mut form.username)
                                .desired_width(220.0)
                                .hint_text("client"),
                        )
                        .changed()
                    {
                        changed = true;
                    }
                    ui.end_row();

                    ui.label("Password");
                    let hint = if password_set {
                        "(unchanged — type to replace)"
                    } else {
                        "required"
                    };
                    if ui
                        .add(
                            egui::TextEdit::singleline(&mut form.password)
                                .password(true)
                                .desired_width(220.0)
                                .hint_text(hint),
                        )
                        .changed()
                    {
                        changed = true;
                    }
                    ui.end_row();
                }

                ui.label("Allowed clients");
                if ui
                    .add(
                        egui::TextEdit::singleline(&mut form.allowed_clients)
                            .desired_width(320.0)
                            .hint_text("127.0.0.1/32, ::1/128"),
                    )
                    .changed()
                {
                    changed = true;
                }
                ui.end_row();

                ui.label("Max concurrent flows");
                if ui
                    .add(
                        egui::TextEdit::singleline(&mut form.max_flows)
                            .desired_width(80.0)
                            .hint_text("128"),
                    )
                    .changed()
                {
                    changed = true;
                }
                ui.end_row();
            });
        if changed {
            form.dirty = true;
        }
        let validated = form.build(password_set);
        if let Err(reason) = &validated {
            ui.add_space(4.0);
            ui.colored_label(ui.visuals().warn_fg_color, reason.as_str());
        }
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            let can_apply = validated.is_ok() && !model.socks_busy();
            if ui
                .add_enabled(can_apply, egui::Button::new("Apply"))
                .clicked()
                && let Ok(settings) = validated
            {
                form.dirty = false;
                form.password.clear();
                commands.extend(model.apply_socks(settings));
            }
            if form.dirty
                && let Some(status) = &status
                && ui.button("Reset").clicked()
            {
                form.load_from(&status.settings);
            }
        });
    });

    ui.add_space(10.0);

    // Card 3: Active and recently ended inner flows
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_width(ui.available_width());
        let flows = model.socks_flows();
        let active = flows.map_or(0, |table| table.total_active);
        ui.strong(format!(
            "Active flows ({active} open — inner flows, separate from carrier lanes and MUX channels)"
        ));
        ui.add_space(4.0);
        match flows {
            None => {
                ui.weak("Waiting for flow list…");
            }
            Some(table) if table.flows.is_empty() => {
                ui.weak("No SOCKS5 flows yet.");
            }
            Some(table) => {
                egui::Grid::new("socks-flows-grid")
                    .striped(true)
                    .num_columns(7)
                    .spacing([12.0, 4.0])
                    .show(ui, |ui| {
                        for header in [
                            "flow", "client", "target", "↑ sent", "↓ recv", "state", "detail",
                        ] {
                            ui.strong(header);
                        }
                        ui.end_row();
                        for flow in &table.flows {
                            ui.monospace(format!("#{}", flow.id));
                            ui.monospace(flow.client.as_str());
                            ui.monospace(flow.target.as_str());
                            ui.monospace(format_bytes(flow.sent_bytes));
                            ui.monospace(format_bytes(flow.received_bytes));
                            ui.label(flow.state.as_str());
                            if let Some(error) = &flow.error {
                                ui.colored_label(ui.visuals().warn_fg_color, error.as_str());
                            } else {
                                ui.weak(format!("{} ms", flow.age_ms));
                            }
                            ui.end_row();
                        }
                    });
            }
        }
    });
    commands
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_validates_loopback_allowlist_and_auth_like_the_service() {
        let mut form = SocksForm::default();
        assert!(form.build(false).is_ok());

        form.listen_host = "0.0.0.0".into();
        form.allowed_clients.clear();
        assert!(form.build(false).is_err());

        form.allowed_clients = "192.168.10.0/24".into();
        let built = form.build(false);
        assert!(built.is_ok());

        form.auth_mode = SocksAuthMode::UserPass;
        form.username = "alice".into();
        assert!(form.build(false).is_err());
        assert!(form.build(true).is_ok());

        form.password = "pw123".into();
        let with_pw = form.build(false);
        assert!(with_pw.is_ok_and(|s| s.password.as_deref() == Some("pw123")));
    }
}
