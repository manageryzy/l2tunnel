//! The sidebar pages. Each page draws from the model and returns the
//! exchanges to run; a page whose feature the service does not serve shows the
//! service's reason and the equivalent CLI command instead of hiding.
use crate::model::{Action, Command, Model};
use crate::present::{self, Tone};
use crate::stats::{Rate, format_bytes, rate_text};
use eframe::egui;
use l2tunnel_client_core::local::{
    self, DeviceChange, DeviceLayer, Feature, MeterSide, Role, RouteChange,
};

/// Placeholder of the service field.
#[cfg(windows)]
pub const SOCKET_HINT: &str = r"\\.\pipe\l2tunnel";
/// Placeholder of the service field.
#[cfg(not(windows))]
pub const SOCKET_HINT: &str = "/run/l2tunnel-UID/api.sock";

/// Sidebar pages, in display order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Page {
    /// State, rates and recent events.
    Overview,
    /// Profile, carrier and configuration switching.
    Connection,
    /// TUN/TAP devices.
    Devices,
    /// Routes.
    Routes,
    /// SOCKS5 entry.
    Socks5,
    /// Counters and charts.
    Statistics,
    /// Service, profiles, keys and sessions.
    Management,
    /// Complete event log.
    Events,
}
impl Page {
    /// Every page in sidebar order.
    pub const ALL: [Self; 8] = [
        Self::Overview,
        Self::Connection,
        Self::Devices,
        Self::Routes,
        Self::Socks5,
        Self::Statistics,
        Self::Management,
        Self::Events,
    ];
    /// Page named on the command line (`--page`), case-insensitive.
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|page| page.title().eq_ignore_ascii_case(name))
    }
    /// Sidebar title.
    pub fn title(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Connection => "Connection",
            Self::Devices => "Devices",
            Self::Routes => "Routes",
            Self::Socks5 => "SOCKS5",
            Self::Statistics => "Statistics",
            Self::Management => "Management",
            Self::Events => "Events",
        }
    }
    fn feature(self) -> Option<Feature> {
        match self {
            Self::Devices => Some(Feature::Devices),
            Self::Routes => Some(Feature::Routes),
            Self::Socks5 => Some(Feature::Socks5),
            Self::Statistics => Some(Feature::Metrics),
            _ => None,
        }
    }
    fn cli(self) -> Option<&'static str> {
        match self {
            Self::Devices => Some("l2tunnelctl device list"),
            Self::Routes => Some("l2tunnelctl route list"),
            Self::Socks5 => Some("l2tunnelctl socks show"),
            Self::Statistics => Some("l2tunnelctl stats watch"),
            _ => Some("l2tunnelctl service status"),
        }
    }
}

/// Per-window UI choices that are not service state.
#[derive(Debug)]
pub struct UiState {
    /// Chart window in seconds.
    pub window: u64,
    /// Event log filter.
    pub filter: String,
    /// New-device form.
    pub device: DeviceForm,
    /// Device being configured.
    pub editing: Option<EditForm>,
    /// Device or route awaiting a second click to confirm removal.
    pub confirm: Option<String>,
    /// New-route form.
    pub route: RouteForm,
    /// Stored profiles section and picker.
    pub profiles: crate::profiles::ProfileState,
    /// Member revoke: new member public key file.
    pub revoke: String,
    /// Diagnostic export destination.
    pub export: String,
    /// Elevated service start form.
    pub start: crate::start::StartForm,
    /// Detected older-service warning and install action (from startup check).
    pub service_update: Option<crate::start::ServiceUpdate>,
    /// Keep IP addresses in the export.
    pub include_addresses: bool,
    /// Tunnel test form.
    pub tests: crate::test_panel::TestForm,
    /// SOCKS5 settings draft.
    pub socks: crate::socks_panel::SocksForm,
    /// Selected live carrier switch target on the Connection page.
    pub carrier_target: String,
    /// Live-tuning controls being edited.
    pub tune: crate::tuning_panel::TuneForm,
    /// Elapsed milliseconds since `ServiceInfo` was fetched (for live uptime).
    pub info_elapsed_ms: u64,
    /// Elapsed milliseconds since `ServiceStatus` was fetched (for live connected time).
    pub status_elapsed_ms: u64,
    /// CSR meters side (`Local` or `Remote`).
    pub meters_side: MeterSide,
    /// CSR meters prefix filter (dot-separated segments).
    pub meters_prefix: String,
    /// CSR meters client-side substring filter.
    pub meters_filter: String,
    /// Auto-refresh CSR meters while on Statistics.
    pub meters_auto: bool,
    /// Page the window should switch to (a page asked to navigate).
    pub goto: Option<Page>,
}
impl Default for UiState {
    fn default() -> Self {
        Self {
            window: 60,
            filter: String::new(),
            device: DeviceForm::default(),
            editing: None,
            confirm: None,
            route: RouteForm::default(),
            profiles: crate::profiles::ProfileState::default(),
            revoke: String::new(),
            export: String::new(),
            start: crate::start::StartForm::default(),
            service_update: None,
            include_addresses: false,
            tune: crate::tuning_panel::TuneForm::default(),
            tests: crate::test_panel::TestForm::default(),
            socks: crate::socks_panel::SocksForm::default(),
            carrier_target: String::new(),
            info_elapsed_ms: 0,
            status_elapsed_ms: 0,
            meters_side: MeterSide::Local,
            meters_prefix: String::new(),
            meters_filter: String::new(),
            meters_auto: false,
            goto: None,
        }
    }
}

/// New-device form fields.
#[derive(Debug)]
pub struct DeviceForm {
    /// Interface name.
    pub name: String,
    /// TAP instead of TUN.
    pub tap: bool,
    /// MTU text (empty: kernel default).
    pub mtu: String,
    /// Comma-separated `ADDRESS/LENGTH` list.
    pub addresses: String,
    /// Bring up after creation.
    pub up: bool,
}
impl Default for DeviceForm {
    fn default() -> Self {
        Self {
            name: String::new(),
            tap: false,
            mtu: "1400".into(),
            addresses: String::new(),
            up: true,
        }
    }
}
/// Configure-device form fields.
#[derive(Debug, Default)]
pub struct EditForm {
    /// Device name.
    pub name: String,
    /// New MTU text (empty: unchanged).
    pub mtu: String,
    /// Addresses to add.
    pub add: String,
    /// Addresses to remove.
    pub remove: String,
    /// Up state: unchanged, up or down.
    pub up: Option<bool>,
    /// Configure request in flight; keep the form open until accepted.
    pub saving: bool,
    /// Last refusal or error from applying this configure form.
    pub save_error: Option<String>,
}
/// New-route form fields.
#[derive(Debug, Default)]
pub struct RouteForm {
    /// Destination `ADDRESS/LENGTH`.
    pub destination: String,
    /// Output device.
    pub device: String,
    /// Optional gateway.
    pub gateway: String,
    /// Optional metric text.
    pub metric: String,
}

fn split_list(text: &str) -> Vec<String> {
    text.split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}
fn optional_number(text: &str) -> Result<Option<u32>, &'static str> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    text.parse().map(Some).map_err(|_| "must be a number")
}

/// Build the create change from the form, validated like the CLI.
pub fn create_change(form: &DeviceForm) -> Result<DeviceChange, String> {
    let change = DeviceChange::Create {
        name: form.name.trim().to_owned(),
        layer: if form.tap {
            DeviceLayer::Tap
        } else {
            DeviceLayer::Tun
        },
        mtu: optional_number(&form.mtu).map_err(|error| format!("MTU {error}"))?,
        addresses: split_list(&form.addresses),
        up: form.up,
    };
    change.validate().map_err(str::to_owned)?;
    Ok(change)
}
/// Build the configure change from the form.
pub fn configure_change(form: &EditForm) -> Result<DeviceChange, String> {
    let change = DeviceChange::Configure {
        name: form.name.clone(),
        mtu: optional_number(&form.mtu).map_err(|error| format!("MTU {error}"))?,
        add: split_list(&form.add),
        remove: split_list(&form.remove),
        up: form.up,
    };
    change.validate().map_err(str::to_owned)?;
    Ok(change)
}
/// Build the add-route change from the form.
pub fn route_change(form: &RouteForm) -> Result<RouteChange, String> {
    let gateway = form.gateway.trim();
    let change = RouteChange::Add {
        destination: form.destination.trim().to_owned(),
        device: form.device.trim().to_owned(),
        gateway: (!gateway.is_empty()).then(|| gateway.to_owned()),
        metric: optional_number(&form.metric).map_err(|error| format!("metric {error}"))?,
    };
    change.validate().map_err(str::to_owned)?;
    Ok(change)
}

/// Role text for the top bar.
pub fn role_text(role: Role) -> &'static str {
    match role {
        Role::Client => "client",
        Role::Server => "server",
        Role::Unconfigured => "unconfigured",
    }
}

/// Effective outer carrier and cover for the top bar, when connected.
pub fn carrier_text(model: &Model) -> Option<String> {
    let view = model.view();
    (view.rows[2] != "—").then(|| {
        if view.rows[3] == "—" {
            view.rows[2].clone()
        } else {
            format!("{} / {}", view.rows[2], view.rows[3])
        }
    })
}

/// Concise active protocol summary for the top bar (e.g. `swift · ARQ`).
pub fn active_protocol_short(model: &Model) -> Option<String> {
    let current = model
        .status()?
        .observation
        .as_ref()?
        .common
        .as_ref()?
        .current
        .as_ref()?;
    let full = local::configuration_summary(current);
    let mut parts = full.split(" · ");
    match (parts.next(), parts.next()) {
        (Some(alg), Some(rec)) => Some(format!("{alg} · {rec}")),
        (Some(alg), None) => Some(alg.to_owned()),
        _ => None,
    }
}

/// Why `page` cannot be used now, if it cannot.
pub fn unavailable(model: &Model, page: Page) -> Option<String> {
    model.path()?;
    let feature = page.feature()?;
    model.capability(feature).err()
}

/// Exchanges to run when a page is opened.
pub fn opened(model: &mut Model, page: Page) -> Vec<Command> {
    let mut commands = Vec::new();
    match page {
        Page::Connection => {
            if model.capability(Feature::Profiles).is_ok() {
                commands.extend(model.refresh_profiles());
            }
            if model.catalog().is_none() && model.catalog_error().is_none() {
                commands.extend(model.catalog_page(0));
            }
            if model.capability(Feature::Catalog).is_ok() {
                commands.extend(model.refresh_carrier_switch());
            }
        }
        Page::Management => {
            commands.extend(model.refresh_info());
            if model.capability(Feature::Profiles).is_ok() {
                commands.extend(model.refresh_profiles());
            }
            if model.capability(Feature::Sessions).is_ok() {
                commands.extend(model.refresh_sessions());
            }
        }
        Page::Devices => {
            commands.extend(model.refresh_devices());
            if model.capability(Feature::Profiles).is_ok() {
                commands.extend(model.refresh_profiles());
            }
        }
        // The connect card warns when the profile's device cannot carry traffic.
        Page::Overview => {
            if model.capability(Feature::Devices).is_ok() {
                commands.extend(model.refresh_devices());
            }
            if model.capability(Feature::Profiles).is_ok() {
                commands.extend(model.refresh_profiles());
            }
        }
        Page::Routes => {
            commands.extend(model.refresh_routes());
            commands.extend(model.refresh_devices());
            if model.capability(Feature::Profiles).is_ok() {
                commands.extend(model.refresh_profiles());
            }
        }
        Page::Socks5 => {
            if model.capability(Feature::Socks5).is_ok() {
                commands.extend(model.refresh_socks());
            }
        }
        _ => {}
    }
    commands
}

fn unavailable_panel(ui: &mut egui::Ui, page: Page, reason: &str) {
    ui.add_space(8.0);
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.strong(format!("{} is unavailable", page.title()));
        ui.label(reason);
        if let Some(cli) = page.cli() {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.weak("Same function from the command line:");
                ui.monospace(cli);
            });
        }
    });
}

/// Draw `page` and return the exchanges its controls requested.
pub fn show(ui: &mut egui::Ui, model: &mut Model, state: &mut UiState, page: Page) -> Vec<Command> {
    ui.heading(page.title());
    ui.add_space(6.0);
    if model.offline() {
        // No service answers: offer the elevated start (owner decision
        // 2026-11-24) above the usual attach hint.
        let commands = crate::start::panel(ui, model, &mut state.start);
        return commands;
    }
    if let Some(reason) = unavailable(model, page) {
        unavailable_panel(ui, page, &reason);
        return Vec::new();
    }
    match page {
        Page::Overview => {
            let commands = connect_card(ui, model, state);
            ui.add_space(10.0);
            overview(ui, model);
            commands
        }
        Page::Connection => {
            let mut commands = connect_card(ui, model, state);
            ui.add_space(10.0);
            commands.extend(connection(ui, model, state));
            ui.add_space(10.0);
            commands.extend(crate::test_panel::panel(ui, model, &mut state.tests));
            commands
        }
        Page::Statistics => statistics(ui, model, state),
        Page::Management => management(ui, model, state),
        Page::Events => events(ui, model, state),
        Page::Devices => devices(ui, model, state),
        Page::Routes => routes(ui, model, state),
        Page::Socks5 => crate::socks_panel::panel(ui, model, &mut state.socks),
    }
}

/// Profile choice for the connect card: the running profile, else the
/// default profile, else the first.
fn preferred_profile(model: &Model, names: &[String]) -> Option<String> {
    let profiles = model.profiles().unwrap_or_default();
    present::running_profile(model)
        .map(str::to_owned)
        .filter(|name| names.contains(name))
        .or_else(|| {
            profiles
                .iter()
                .find(|profile| profile.default)
                .map(|profile| profile.name.clone())
                .filter(|name| names.contains(name))
        })
        .or_else(|| names.first().cloned())
}

/// The primary action on Overview and Connection: connect a profile,
/// follow setup, or disconnect, with the reason a session ended.
fn connect_card(ui: &mut egui::Ui, model: &mut Model, state: &mut UiState) -> Vec<Command> {
    let mut commands = Vec::new();
    let Some(status) = model.status().cloned() else {
        return commands;
    };
    if model.profiles().is_none() && model.capability(Feature::Profiles).is_ok() {
        commands.extend(model.refresh_profiles());
    }
    let names: Vec<String> = model
        .profiles()
        .unwrap_or_default()
        .iter()
        .filter(|profile| profile.editable)
        .map(|profile| profile.name.clone())
        .collect();
    let running = present::running_profile(model).map(str::to_owned);
    let connected = status.phase == "connected";
    // While connected, offer only the other profiles to switch to.
    let names: Vec<String> = if connected {
        names
            .into_iter()
            .filter(|name| Some(name) != running.as_ref())
            .collect()
    } else {
        names
    };
    if !names.contains(&state.profiles.choice)
        && let Some(name) = preferred_profile(model, &names)
    {
        state.profiles.choice = name;
    }
    if model.devices().is_none() && model.capability(Feature::Devices).is_ok() {
        commands.extend(model.refresh_devices());
    }
    let headline = present::headline(model);
    let busy = model.busy();
    let server = model.info().is_some_and(|info| info.role == Role::Server);
    let common = status
        .observation
        .as_ref()
        .and_then(|observation| observation.common.as_ref())
        .cloned();
    let view = model.view();
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            dot(ui, headline.tone);
            ui.heading(headline.text.as_str());
            if let Some(profile) = present::running_profile(model) {
                ui.label(format!("· {profile}"));
            }
            if let Some(ms) = status.connected_ms {
                ui.weak(format!(
                    "· up {}",
                    uptime(ms.saturating_add(state.status_elapsed_ms))
                ));
            }
            if let Some(epoch) = common.as_ref().and_then(|c| c.epoch) {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.weak(format!("epoch {epoch}"));
                });
            }
        });
        if connected && let Some(common) = &common {
            ui.add_space(4.0);
            let carrier_label = {
                let carrier = common.carrier.as_str();
                if !carrier.is_empty() && carrier != "—" {
                    format!(
                        "{} ({carrier})",
                        present::carrier_words(&view.rows[2], &view.rows[3])
                    )
                } else {
                    present::carrier_words(&view.rows[2], &view.rows[3])
                }
            };
            let protocol_label = common
                .current
                .as_ref()
                .map(local::configuration_summary)
                .unwrap_or_else(|| view.rows[5].clone());
            let mut summary_rows = vec![
                ("Peer", view.rows[4].clone()),
                ("Carrier", carrier_label),
                ("Protocol", protocol_label),
            ];
            if let (Some(send), Some(recv)) = (common.send_rate, common.receive_rate) {
                let up = rate_text(Rate::SentBits, Some(send as f64 * 8.0));
                let down = rate_text(Rate::SentBits, Some(recv as f64 * 8.0));
                let note = if recv.saturating_mul(2) < send || send.saturating_mul(2) < recv {
                    " (asymmetric plan cap)"
                } else {
                    ""
                };
                summary_rows.push(("Plan budget", format!("Up {up} · Down {down}{note}")));
            }
            rows(ui, "connect-card-summary", &summary_rows);
        }
        if let Some(detail) = &headline.detail {
            ui.label(detail.as_str());
        }
        if let Some(warning) = present::device_warning(model) {
            ui.colored_label(ui.visuals().warn_fg_color, format!("⚠ {warning}"));
        }
        let pending = status.operation.is_some();
        // Top bar always provides global Disconnect/Reconnect/Cancel; avoid a
        // duplicate Disconnect button inside the card when there are no other
        // profiles to switch to.
        let show_controls = pending || !connected || !names.is_empty();
        if !show_controls {
            return;
        }
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            if pending {
                ui.spinner();
                if ui.add_enabled(!busy, egui::Button::new("Cancel")).clicked() {
                    commands.extend(model.act(Action::Cancel));
                }
                return;
            }
            if names.is_empty() {
                if model.capability(Feature::Profiles).is_ok() {
                    ui.label("No profile yet.");
                    if ui.button("➕ Create a profile").clicked() {
                        crate::profiles::open_new(&mut state.profiles);
                        state.goto = Some(Page::Management);
                    }
                }
                if !connected && status.phase == "failed" && ui.button("Reconnect").clicked() {
                    commands.extend(model.act(Action::Reconnect));
                }
                return;
            }
            if connected {
                ui.label("Switch to");
            }
            egui::ComboBox::from_id_salt("connect-profile")
                .selected_text(state.profiles.choice.as_str())
                .show_ui(ui, |ui| {
                    for name in &names {
                        ui.selectable_value(
                            &mut state.profiles.choice,
                            name.clone(),
                            name.as_str(),
                        );
                    }
                });
            let label = match (connected, server) {
                (true, _) => "Use this profile",
                (false, true) => "▶ Start listening",
                (false, false) => "▶ Connect",
            };
            if ui.add_enabled(!busy, egui::Button::new(label)).clicked() {
                commands.extend(model.connect_profile(state.profiles.choice.clone(), connected));
            }
            if connected {
                ui.weak("(ends this session, then connects the other profile)");
            }
        });
    });
    commands
}

fn dot(ui: &mut egui::Ui, tone: Tone) {
    let color = match tone {
        Tone::Good => egui::Color32::from_rgb(60, 180, 90),
        Tone::Busy => egui::Color32::from_rgb(220, 170, 40),
        Tone::Bad => egui::Color32::from_rgb(210, 70, 60),
        Tone::Idle => ui.visuals().weak_text_color(),
    };
    let (rect, _) = ui.allocate_exact_size(egui::vec2(12.0, 12.0), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), 5.0, color);
}

/// Colour dot for the top bar.
pub fn tone_dot(ui: &mut egui::Ui, tone: Tone) {
    dot(ui, tone);
}

fn rows(ui: &mut egui::Ui, id: &str, rows: &[(&str, String)]) {
    egui::Grid::new(id)
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            for (label, value) in rows {
                ui.label(*label);
                ui.label(value.as_str());
                ui.end_row();
            }
        });
}

fn window_label(seconds: u64) -> String {
    if seconds > 60 && seconds.is_multiple_of(60) {
        format!("-{} min", seconds / 60)
    } else {
        format!("-{seconds} s")
    }
}

/// Horizontal time axis for [`chart`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum ChartAxis {
    /// Rolling window ending at `now`: points are `(age_secs_before_now, value)`.
    Rolling { window_secs: u64 },
    /// Fixed-duration elapsed series from left (`0 s`) to right (`total_secs s`):
    /// points are `(completed_second_1_based, value)`.
    Elapsed {
        total_secs: u64,
        elapsed_secs: f64,
        running: bool,
    },
}

/// Line chart of one rate series with Y-axis labels, subtle area fill, and
/// hover crosshair. Gaps are left blank; draws as soon as one point arrives.
pub(crate) fn chart(
    ui: &mut egui::Ui,
    title: &str,
    rate: Rate,
    axis: ChartAxis,
    points: &[(f64, Option<f64>)],
) {
    let width = ui.available_width();
    let peak = points
        .iter()
        .filter_map(|(_, value)| *value)
        .fold(0.0_f64, f64::max);
    let latest = points.iter().rev().find_map(|(_, value)| *value);
    let reported = points.iter().filter(|(_, value)| value.is_some()).count();

    let (latest_label, left_axis, right_axis) = match axis {
        ChartAxis::Rolling { window_secs } => ("now", window_label(window_secs), "now".to_owned()),
        ChartAxis::Elapsed {
            total_secs,
            running,
            ..
        } => (
            if running { "last 1 s" } else { "final 1 s" },
            "0 s".to_owned(),
            format!("{} s", total_secs.max(1)),
        ),
    };

    ui.allocate_ui_with_layout(
        egui::vec2(width, 18.0),
        egui::Layout::left_to_right(egui::Align::Center),
        |ui| {
            ui.label(title);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if reported > 0 {
                    ui.weak(format!(
                        "{latest_label} {} · peak {}",
                        rate_text(rate, latest),
                        rate_text(rate, Some(peak))
                    ));
                }
            });
        },
    );

    let (response, painter) = ui.allocate_painter(egui::vec2(width, 108.0), egui::Sense::hover());
    let rect = response.rect;
    let visuals = ui.visuals();
    painter.rect_filled(rect, 4.0, visuals.extreme_bg_color);
    let pad_top = 10.0;
    let pad_bottom = 18.0;
    let plot_left = rect.left() + 58.0;
    let plot_right = rect.right() - 8.0;
    let plot_w = (plot_right - plot_left).max(1.0);
    let plot_h = (rect.height() - pad_top - pad_bottom).max(12.0);
    let plot_top = rect.top() + pad_top;
    let plot_bottom = rect.bottom() - pad_bottom;
    let axis_color = visuals.weak_text_color().linear_multiply(0.30);
    let font_small = egui::FontId::proportional(10.0);

    // Top, midline and baseline guides.
    for frac in [0.0_f32, 0.5, 1.0] {
        let y = plot_bottom - plot_h * frac;
        painter.line_segment(
            [egui::pos2(plot_left, y), egui::pos2(plot_right, y)],
            egui::Stroke::new(0.75, axis_color),
        );
    }
    painter.text(
        egui::pos2(plot_left, rect.bottom() - 3.0),
        egui::Align2::LEFT_BOTTOM,
        left_axis,
        font_small.clone(),
        visuals.weak_text_color(),
    );
    painter.text(
        egui::pos2(plot_right, rect.bottom() - 3.0),
        egui::Align2::RIGHT_BOTTOM,
        right_axis,
        font_small.clone(),
        visuals.weak_text_color(),
    );

    if reported == 0 || peak <= 0.0 {
        painter.text(
            egui::pos2(plot_left - 6.0, plot_bottom),
            egui::Align2::RIGHT_CENTER,
            "0",
            font_small.clone(),
            visuals.weak_text_color(),
        );
        let text = if points.iter().all(|(_, value)| value.is_none()) && !points.is_empty() {
            "not reported"
        } else if reported == 0 {
            "collecting samples…"
        } else {
            painter.line_segment(
                [
                    egui::pos2(plot_left, plot_bottom),
                    egui::pos2(plot_right, plot_bottom),
                ],
                egui::Stroke::new(1.5, visuals.selection.bg_fill),
            );
            "idle (0)"
        };
        painter.text(
            egui::pos2(plot_left + plot_w * 0.5, plot_top + plot_h * 0.5),
            egui::Align2::CENTER_CENTER,
            text,
            egui::FontId::proportional(12.0),
            visuals.weak_text_color(),
        );
        return;
    }

    // Headroom so a steady rate stays below the top border, with readable Y-axis ticks.
    let scale = peak * 1.2;
    painter.text(
        egui::pos2(plot_left - 6.0, plot_top),
        egui::Align2::RIGHT_CENTER,
        rate_text(rate, Some(scale)),
        font_small.clone(),
        visuals.weak_text_color(),
    );
    painter.text(
        egui::pos2(plot_left - 6.0, plot_bottom - plot_h * 0.5),
        egui::Align2::RIGHT_CENTER,
        rate_text(rate, Some(scale * 0.5)),
        font_small.clone(),
        visuals.weak_text_color(),
    );
    painter.text(
        egui::pos2(plot_left - 6.0, plot_bottom),
        egui::Align2::RIGHT_CENTER,
        "0",
        font_small,
        visuals.weak_text_color(),
    );

    let accent = visuals.selection.bg_fill;
    let fill = egui::Color32::from_rgba_unmultiplied(accent.r(), accent.g(), accent.b(), 36);
    let stroke = egui::Stroke::new(2.0, accent);
    let mut segment: Vec<egui::Pos2> = Vec::new();
    let mut plotted: Vec<(egui::Pos2, f64, f64)> = Vec::new();

    let flush_segment = |painter: &egui::Painter, seg: &mut Vec<egui::Pos2>| {
        if seg.len() > 1 {
            for pair in seg.windows(2) {
                let quad = vec![
                    pair[0],
                    pair[1],
                    egui::pos2(pair[1].x, plot_bottom),
                    egui::pos2(pair[0].x, plot_bottom),
                ];
                painter.add(egui::Shape::convex_polygon(quad, fill, egui::Stroke::NONE));
            }
            painter.line(std::mem::take(seg), stroke);
        } else {
            seg.clear();
        }
    };

    // For Elapsed charts, anchor 0 s at the first completed second's height so
    // the curve begins cleanly at the left edge and aligns with the progress bar.
    if let ChartAxis::Elapsed { .. } = axis
        && let Some((_, Some(first_val))) = points.first()
    {
        let y0 = plot_bottom - ((first_val / scale).clamp(0.0, 1.0) as f32) * plot_h;
        segment.push(egui::pos2(plot_left, y0));
    }

    for &(coord, value) in points {
        let frac = match axis {
            ChartAxis::Rolling { window_secs } => {
                let window = window_secs.max(1) as f64;
                (1.0 - (coord / window).clamp(0.0, 1.0)) as f32
            }
            ChartAxis::Elapsed { total_secs, .. } => {
                let span = total_secs.max(1) as f64;
                (coord / span).clamp(0.0, 1.0) as f32
            }
        };
        let x = plot_left + frac * plot_w;
        match value {
            Some(value) => {
                let y = plot_bottom - ((value / scale).clamp(0.0, 1.0) as f32) * plot_h;
                let pos = egui::pos2(x, y);
                segment.push(pos);
                plotted.push((pos, coord, value));
            }
            None => flush_segment(&painter, &mut segment),
        }
    }
    flush_segment(&painter, &mut segment);

    // Live elapsed cursor while a speed test is actively running.
    if let ChartAxis::Elapsed {
        total_secs,
        elapsed_secs,
        running: true,
    } = axis
    {
        let cursor_frac = (elapsed_secs / total_secs.max(1) as f64).clamp(0.0, 1.0) as f32;
        let cursor_x = plot_left + cursor_frac * plot_w;
        if let Some(&(last_pos, _, _)) = plotted.last()
            && cursor_x > last_pos.x + 1.0
        {
            painter.line_segment(
                [last_pos, egui::pos2(cursor_x, last_pos.y)],
                egui::Stroke::new(1.5, accent.linear_multiply(0.55)),
            );
        }
        painter.line_segment(
            [
                egui::pos2(cursor_x, plot_top),
                egui::pos2(cursor_x, plot_bottom),
            ],
            egui::Stroke::new(1.0, visuals.weak_text_color().linear_multiply(0.5)),
        );
    }

    if let Some(&(pos, _, _)) = plotted.last() {
        painter.circle_filled(pos, 3.0, accent);
    }

    if let Some(pointer) = response.hover_pos()
        && let Some(&(pos, coord, value)) = plotted.iter().min_by(|a, b| {
            (a.0.x - pointer.x)
                .abs()
                .total_cmp(&(b.0.x - pointer.x).abs())
        })
    {
        painter.line_segment(
            [egui::pos2(pos.x, plot_top), egui::pos2(pos.x, plot_bottom)],
            egui::Stroke::new(1.0, visuals.text_color().linear_multiply(0.35)),
        );
        painter.circle_filled(pos, 4.0, visuals.text_color());
        let hover = match axis {
            ChartAxis::Rolling { .. } => {
                format!("{} ({:.0} s ago)", rate_text(rate, Some(value)), coord)
            }
            ChartAxis::Elapsed { .. } => {
                format!("second {:.0}: {}", coord, rate_text(rate, Some(value)))
            }
        };
        response.on_hover_text(hover);
    }
}

fn overview(ui: &mut egui::Ui, model: &Model) {
    let view = model.view();
    let mut list: Vec<(&str, String)> = Vec::new();
    if let Some(device) = present::profile_device(model) {
        let state = model
            .devices()
            .and_then(|devices| devices.iter().find(|item| item.name == device))
            .map(|item| {
                let addresses = if item.addresses.is_empty() {
                    "no address".to_owned()
                } else {
                    item.addresses.join(", ")
                };
                format!("{} · {addresses}", if item.up { "up" } else { "down" })
            })
            .unwrap_or_default();
        list.push(("Tunnel device", format!("{device}  {state}")));
    }
    if !list.is_empty() {
        rows(ui, "overview", &list);
        ui.add_space(8.0);
    }
    if model.metrics().is_some() {
        let history = model.history();
        ui.horizontal_wrapped(|ui| {
            ui.label(format!(
                "Sending {}",
                rate_text(Rate::SentBits, history.latest(Rate::SentBits))
            ));
            ui.separator();
            ui.label(format!(
                "Tunnel traffic: out {} · in {}",
                rate_text(Rate::DeviceRead, history.latest(Rate::DeviceRead)),
                rate_text(Rate::DeviceWritten, history.latest(Rate::DeviceWritten)),
            ));
        });
        chart(
            ui,
            "Sent, last 60 s",
            Rate::SentBits,
            ChartAxis::Rolling { window_secs: 60 },
            &history.timed_series(Rate::SentBits, 60),
        );
    }
    ui.add_space(8.0);
    egui::CollapsingHeader::new("Details")
        .id_salt("overview-details")
        .show(ui, |ui| {
            let mut details = vec![
                ("Service state", view.rows[0].clone()),
                ("Pending operation", view.rows[1].clone()),
                ("Algorithm", view.rows[5].clone()),
                ("Epoch", view.rows[6].clone()),
            ];
            if let Some(metrics) = model.metrics() {
                details.push(("Generation", metrics.generation.to_string()));
            }
            rows(ui, "overview-details-rows", &details);
        });
    ui.add_space(8.0);
    ui.strong("Recent activity");
    for line in model.log.iter().rev().take(8) {
        ui.monospace(line.as_str());
    }
}

fn connection(ui: &mut egui::Ui, model: &mut Model, state: &mut UiState) -> Vec<Command> {
    let mut commands = Vec::new();
    let common = model
        .status()
        .and_then(|status| status.observation.as_ref())
        .and_then(|observation| observation.common.as_ref())
        .cloned();
    let connected = model
        .status()
        .is_some_and(|status| status.phase == "connected");
    let switching = model
        .status()
        .is_some_and(|status| status.phase == "applying");

    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            ui.heading("Protocol & Live tuning");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if switching {
                    ui.weak("Switching…");
                    ui.spinner();
                } else if connected {
                    ui.weak("Hot switching keeps the session connected");
                }
            });
        });

        // Quick live tuning (FEC, repair rate, MTU) synchronized with the protocol list below.
        if model.capability(Feature::Catalog).is_ok() {
            commands.extend(crate::tuning_panel::show(
                ui,
                model,
                &mut state.tune,
                connected,
            ));
            ui.add_space(6.0);
            ui.separator();
            ui.add_space(4.0);
            commands.extend(carrier_switch_section(ui, model, state, connected));
        }

        ui.add_space(6.0);
        ui.separator();
        ui.add_space(4.0);
        ui.strong("Protocol catalog");
        if let Err(reason) = model.capability(Feature::Catalog) {
            ui.weak(format!("Unavailable: {reason}"));
            return;
        }
        let Some(common) = common else {
            ui.weak("Connect first; the choices come from the running session's plan.");
            return;
        };
        if let Some(error) = model.catalog_error().map(str::to_owned) {
            ui.horizontal_wrapped(|ui| {
                ui.colored_label(
                    ui.visuals().warn_fg_color,
                    format!("Protocol choices unavailable: {error}"),
                );
                if ui.button("Retry").clicked() {
                    commands.extend(model.retry_catalog());
                }
            });
            return;
        }
        if model.catalog_stale() {
            commands.extend(model.catalog_page(0));
        }
        let Some(catalog) = model.catalog().filter(|_| !model.catalog_stale()).cloned() else {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.weak("Loading the protocol choices…");
            });
            return;
        };
        if usize::from(catalog.total) <= crate::model::CATALOG_ALL
            && let Some(next) = catalog.next
        {
            commands.extend(model.catalog_page(next));
        }
        let current = common.current.clone();
        if catalog.total <= 1 {
            ui.weak(
                "This profile's plan allows only the protocol in use. Use a multi-protocol plan to \
                 switch live.",
            );
        }
        let mut target = model.target().cloned();
        for (index, entry) in catalog.entries.iter().enumerate() {
            let number = u32::from(catalog.offset) + index as u32 + 1;
            let is_current = current.as_ref() == Some(entry);
            let is_requested = common.requested.as_ref() == Some(entry) && !is_current;
            ui.horizontal(|ui| {
                let label = format!("{number}. {}", local::configuration_summary(entry));
                if catalog.total <= 1 {
                    ui.label(label);
                } else {
                    let selected =
                        target.as_ref() == Some(entry) || (target.is_none() && is_current);
                    if ui.radio(selected, label).clicked() {
                        target = (!is_current).then(|| entry.clone());
                        // Picking a catalog member clears any unsaved live-tuning draft so the
                        // two controls never disagree.
                        state.tune.chosen = None;
                    }
                }
                if is_current {
                    dot(ui, Tone::Good);
                    ui.colored_label(egui::Color32::from_rgb(90, 190, 110), "in use");
                } else if is_requested {
                    ui.spinner();
                    ui.weak("switching…");
                }
            });
        }
        if target.as_ref() != model.target() {
            model.select_target(target.clone());
        }
        if usize::from(catalog.total) > crate::model::CATALOG_ALL {
            ui.horizontal(|ui| {
                let first = u32::from(catalog.offset) + 1;
                let last = u32::from(catalog.offset) + catalog.entries.len() as u32;
                ui.weak(format!("{first}–{last} of {}", catalog.total));
                if ui
                    .add_enabled(catalog.offset > 0, egui::Button::new("< Previous"))
                    .clicked()
                {
                    let offset = catalog.offset.saturating_sub(local::CATALOG_LIMIT);
                    commands.extend(model.catalog_page(offset));
                }
                if let Some(next) = catalog.next
                    && ui.button("Next >").clicked()
                {
                    commands.extend(model.catalog_page(next));
                }
            });
        }
        if catalog.total > 1 {
            ui.add_space(4.0);
            let ready = connected
                && !model.busy()
                && target.is_some()
                && target.as_ref() != current.as_ref();
            ui.horizontal_wrapped(|ui| {
                let button = ui.add_enabled(ready, egui::Button::new("Switch protocol"));
                if button.clicked() {
                    commands.extend(model.act(Action::Switch));
                }
                if target.is_some() && ui.button("Reset").clicked() {
                    model.select_target(None);
                }
                if !connected {
                    ui.weak("Connect to switch.");
                } else if model.busy() {
                    ui.weak("Switching… progress shows in the top bar and Events.");
                } else if target.is_none() {
                    ui.weak("Select another protocol above to switch live.");
                }
            });
        }

        ui.add_space(6.0);
        egui::CollapsingHeader::new("Session details")
            .id_salt("connection-details")
            .show(ui, |ui| {
                let mut list = vec![("Requested carrier", common.carrier.clone())];
                if let Some(current) = &current {
                    list.push((
                        "Current configuration",
                        local::configuration_summary(current),
                    ));
                }
                if let Some(requested) = &common.requested
                    && Some(requested) != current.as_ref()
                {
                    list.push((
                        "Requested configuration",
                        local::configuration_summary(requested),
                    ));
                }
                list.push((
                    "Epoch",
                    common.epoch.map_or("—".into(), |epoch| epoch.to_string()),
                ));
                list.push(("Generation", common.generation.to_string()));
                list.push(("Catalog members", catalog.total.to_string()));
                if let (Some(send), Some(recv)) = (common.send_rate, common.receive_rate) {
                    list.push((
                        "Configured rate cap",
                        format!(
                            "Up {} · Down {}",
                            rate_text(Rate::SentBits, Some(send as f64 * 8.0)),
                            rate_text(Rate::SentBits, Some(recv as f64 * 8.0)),
                        ),
                    ));
                }
                rows(ui, "connection-details-rows", &list);
            });
    });
    commands
}

fn carrier_switch_section(
    ui: &mut egui::Ui,
    model: &mut Model,
    state: &mut UiState,
    connected: bool,
) -> Vec<Command> {
    let mut commands = Vec::new();
    ui.horizontal(|ui| {
        ui.strong("Live carrier & UDP cover");
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if model.carrier_switch_busy() || model.carrier_switch_loading() {
                ui.spinner();
            }
            if connected && !model.carrier_switch_loading() && ui.small_button("Refresh").clicked()
            {
                commands.extend(model.refresh_carrier_switch());
            }
        });
    });
    if !connected {
        ui.weak("Connect first to switch carrier/cover live without reconnecting.");
        return commands;
    }
    if model.carrier_switch().is_none()
        && !model.carrier_switch_loading()
        && model.carrier_switch_error().is_none()
    {
        commands.extend(model.refresh_carrier_switch());
    }
    if let Some(error) = model.carrier_switch_error() {
        ui.colored_label(ui.visuals().warn_fg_color, error);
    }
    let Some(view) = model.carrier_switch().cloned() else {
        ui.weak("Loading live carrier choices…");
        return commands;
    };
    let current_id = view
        .current_cover
        .as_deref()
        .unwrap_or(view.current_carrier.as_str());
    if state.carrier_target.is_empty() || !view.choices.iter().any(|c| c.id == state.carrier_target)
    {
        state.carrier_target = current_id.to_owned();
    }
    ui.weak(format!(
        "Active: {} · {} → {} · {} live switches (make-before-break, keeps session & inner flows)",
        current_id, view.local, view.peer, view.switches
    ));
    ui.add_space(4.0);
    for choice in &view.choices {
        let is_current = choice.id == current_id;
        ui.horizontal_wrapped(|ui| {
            ui.add_enabled_ui(choice.available && !model.carrier_switch_busy(), |ui| {
                ui.radio_value(
                    &mut state.carrier_target,
                    choice.id.clone(),
                    choice.label.as_str(),
                );
            });
            if is_current {
                dot(ui, Tone::Good);
                ui.colored_label(egui::Color32::from_rgb(90, 190, 110), "in use");
            } else if !choice.available
                && let Some(reason) = &choice.reason
            {
                ui.weak(format!("— {reason}"));
            }
        });
    }
    let selected_available = view
        .choices
        .iter()
        .any(|c| c.id == state.carrier_target && c.available);
    let can_switch = connected
        && selected_available
        && state.carrier_target != current_id
        && !model.carrier_switch_busy();
    ui.add_space(4.0);
    ui.horizontal_wrapped(|ui| {
        if ui
            .add_enabled(can_switch, egui::Button::new("Switch carrier live"))
            .clicked()
        {
            commands.extend(model.switch_carrier(state.carrier_target.clone()));
        }
        if state.carrier_target != current_id && ui.button("Reset").clicked() {
            state.carrier_target = current_id.to_owned();
        }
        if model.carrier_switch_busy() {
            ui.weak("Probing standby carrier and migrating…");
        }
    });
    commands
}

fn layer_text(layer: Option<DeviceLayer>) -> &'static str {
    match layer {
        Some(DeviceLayer::Tun) => "TUN",
        Some(DeviceLayer::Tap) => "TAP",
        None => "—",
    }
}

fn devices(ui: &mut egui::Ui, model: &mut Model, state: &mut UiState) -> Vec<Command> {
    let mut commands = Vec::new();
    let busy = model.busy();
    if model.profiles().is_none() && model.capability(Feature::Profiles).is_ok() {
        commands.extend(model.refresh_profiles());
    }
    if let Some(edit) = &mut state.editing
        && edit.saving
        && let Some(result) = model.take_action_result(Action::Device)
    {
        match result {
            Ok(_) => state.editing = None,
            Err(reason) => {
                edit.saving = false;
                edit.save_error = Some(reason);
            }
        }
    }
    if ui.button("Refresh").clicked() {
        commands.extend(model.refresh_devices());
        if model.capability(Feature::Profiles).is_ok() {
            commands.extend(model.refresh_profiles());
        }
    }
    let all = model.devices().map(<[_]>::to_vec).unwrap_or_default();
    if let Some(warning) = present::device_warning(model) {
        ui.colored_label(ui.visuals().warn_fg_color, format!("⚠ {warning}"));
    }
    let (list, others): (Vec<_>, Vec<_>) = all
        .into_iter()
        .partition(|device| present::is_tunnel(model, device));
    ui.strong("Tunnel devices");
    ui.weak("Devices the service created, or that a profile uses.");
    if !list.is_empty() {
        egui::Grid::new("devices")
            .striped(true)
            .num_columns(8)
            .spacing([14.0, 6.0])
            .show(ui, |ui| {
                for title in [
                    "name",
                    "used by",
                    "layer",
                    "MTU",
                    "up",
                    "addresses",
                    "owner",
                    "",
                ] {
                    ui.strong(title);
                }
                ui.end_row();
                for device in &list {
                    ui.label(device.name.as_str());
                    let users = present::profiles_using(model, &device.name);
                    ui.label(if users.is_empty() {
                        "—".to_owned()
                    } else {
                        users.join(", ")
                    });
                    ui.label(layer_text(device.layer));
                    ui.label(device.mtu.map_or("—".into(), |mtu| mtu.to_string()));
                    ui.label(if device.up { "yes" } else { "no" });
                    ui.label(if device.addresses.is_empty() {
                        "—".to_owned()
                    } else {
                        device.addresses.join(", ")
                    });
                    ui.label(if device.owned { "l2tunnel" } else { "system" })
                        .on_hover_text(if device.owned {
                            "created by the service; it can change or delete it"
                        } else {
                            "created outside l2tunnel; the service uses it but never changes it"
                        });
                    ui.horizontal(|ui| {
                        if !device.owned {
                            return;
                        }
                        if ui
                            .add_enabled(!busy, egui::Button::new("Configure"))
                            .clicked()
                        {
                            state.editing = Some(EditForm {
                                name: device.name.clone(),
                                ..EditForm::default()
                            });
                        }
                        let key = format!("device:{}", device.name);
                        let confirming = state.confirm.as_deref() == Some(key.as_str());
                        let label = if confirming {
                            "Confirm delete"
                        } else {
                            "Delete"
                        };
                        if ui.add_enabled(!busy, egui::Button::new(label)).clicked() {
                            if confirming {
                                state.confirm = None;
                                commands.extend(model.change_device(DeviceChange::Delete {
                                    name: device.name.clone(),
                                }));
                            } else {
                                state.confirm = Some(key);
                            }
                        }
                    });
                    ui.end_row();
                }
            });
    }
    if model.devices().is_none() {
        ui.weak("Loading…");
    } else if list.is_empty() {
        ui.weak("None yet. Create one below, or name an existing one in a profile.");
    }
    if !others.is_empty() {
        egui::CollapsingHeader::new(format!(
            "Other TUN/TAP interfaces on this computer ({})",
            others.len()
        ))
        .id_salt("devices-other")
        .show(ui, |ui| {
            egui::Grid::new("devices-other-grid")
                .striped(true)
                .num_columns(4)
                .spacing([14.0, 6.0])
                .show(ui, |ui| {
                    for title in ["name", "layer", "up", "addresses"] {
                        ui.strong(title);
                    }
                    ui.end_row();
                    for device in &others {
                        ui.label(device.name.as_str());
                        ui.label(layer_text(device.layer));
                        ui.label(if device.up { "yes" } else { "no" });
                        ui.label(device.addresses.join(", "));
                        ui.end_row();
                    }
                });
            ui.weak("Not used by any profile; l2tunnel never changes them.");
        });
    }
    if let Some(edit) = &mut state.editing {
        ui.add_space(10.0);
        ui.strong(format!("Configure {}", edit.name));
        egui::Grid::new("configure").num_columns(2).show(ui, |ui| {
            ui.label("MTU");
            ui.add(egui::TextEdit::singleline(&mut edit.mtu).hint_text("unchanged"));
            ui.end_row();
            ui.label("Add addresses");
            ui.add(egui::TextEdit::singleline(&mut edit.add).hint_text("10.88.0.2/24, fd00::2/64"));
            ui.end_row();
            ui.label("Remove addresses");
            ui.add(egui::TextEdit::singleline(&mut edit.remove));
            ui.end_row();
            ui.label("State");
            ui.horizontal(|ui| {
                ui.radio_value(&mut edit.up, None, "unchanged");
                ui.radio_value(&mut edit.up, Some(true), "up");
                ui.radio_value(&mut edit.up, Some(false), "down");
            });
            ui.end_row();
        });
        let change = configure_change(edit);
        if let Some(error) = &edit.save_error {
            ui.colored_label(
                ui.visuals().error_fg_color,
                format!("Apply failed: {error}"),
            );
        }
        if let Err(reason) = &change {
            ui.weak(reason.as_str());
        }
        let mut close = false;
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    change.is_ok() && !busy && !edit.saving,
                    egui::Button::new("Apply"),
                )
                .clicked()
                && let Ok(change) = change
            {
                edit.saving = true;
                edit.save_error = None;
                commands.extend(model.change_device(change));
            }
            if edit.saving {
                ui.spinner();
                ui.weak("Applying…");
            }
            if ui
                .add_enabled(!edit.saving, egui::Button::new("Close"))
                .clicked()
            {
                close = true;
            }
        });
        if close {
            state.editing = None;
        }
    }
    ui.add_space(12.0);
    ui.strong("New device");
    let form = &mut state.device;
    egui::Grid::new("new-device").num_columns(2).show(ui, |ui| {
        ui.label("Name");
        ui.add(egui::TextEdit::singleline(&mut form.name).hint_text("l2t0"));
        ui.end_row();
        ui.label("Layer");
        ui.horizontal(|ui| {
            ui.radio_value(&mut form.tap, false, "TUN (IP)");
            ui.radio_value(&mut form.tap, true, "TAP (Ethernet)");
        });
        ui.end_row();
        ui.label("MTU");
        ui.text_edit_singleline(&mut form.mtu);
        ui.end_row();
        ui.label("Addresses");
        ui.add(
            egui::TextEdit::singleline(&mut form.addresses).hint_text("10.88.0.2/24, fd00::2/64"),
        );
        ui.end_row();
        ui.label("");
        ui.checkbox(&mut form.up, "Bring up");
        ui.end_row();
    });
    let change = create_change(form);
    if let (Err(reason), false) = (&change, form.name.is_empty()) {
        ui.weak(reason.as_str());
    }
    if ui
        .add_enabled(change.is_ok() && !busy, egui::Button::new("Create"))
        .clicked()
        && let Ok(change) = change
    {
        commands.extend(model.change_device(change));
    }
    ui.add_space(6.0);
    ui.weak(
        "The service creates persistent devices and records them as its own; \
         preexisting devices can be used by profiles but are never changed.",
    );
    commands
}

fn routes(ui: &mut egui::Ui, model: &mut Model, state: &mut UiState) -> Vec<Command> {
    let mut commands = Vec::new();
    let busy = model.busy();
    let connected = model
        .status()
        .is_some_and(|status| status.phase == "connected");
    if model.profiles().is_none() && model.capability(Feature::Profiles).is_ok() {
        commands.extend(model.refresh_profiles());
    }
    if ui.button("Refresh").clicked() {
        commands.extend(model.refresh_routes());
        commands.extend(model.refresh_devices());
        if model.capability(Feature::Profiles).is_ok() {
            commands.extend(model.refresh_profiles());
        }
    }
    let (list, others): (Vec<_>, Vec<_>) = model
        .routes()
        .map(<[_]>::to_vec)
        .unwrap_or_default()
        .into_iter()
        .partition(|route| route.owned);
    ui.strong("Routes added by l2tunnel");
    if !list.is_empty() {
        egui::Grid::new("routes")
            .striped(true)
            .num_columns(6)
            .spacing([14.0, 6.0])
            .show(ui, |ui| {
                for title in ["destination", "gateway", "device", "metric", "purpose", ""] {
                    ui.strong(title);
                }
                ui.end_row();
                for route in &list {
                    ui.label(route.destination.as_str());
                    ui.label(route.gateway.as_deref().unwrap_or("—"));
                    ui.label(route.device.as_deref().unwrap_or("—"));
                    ui.label(route.metric.map_or("—".into(), |metric| metric.to_string()));
                    ui.label(match route.purpose.as_deref() {
                        Some("default") => "all traffic",
                        Some("peer_exception") => "keeps the peer reachable",
                        _ => "route",
                    });
                    if route.owned
                        && route.purpose.as_deref() == Some("route")
                        && let Some(device) = &route.device
                    {
                        let key = format!("route:{}:{device}", route.destination);
                        let confirming = state.confirm.as_deref() == Some(key.as_str());
                        let label = if confirming {
                            "Confirm remove"
                        } else {
                            "Remove"
                        };
                        if ui.add_enabled(!busy, egui::Button::new(label)).clicked() {
                            if confirming {
                                state.confirm = None;
                                commands.extend(model.change_route(RouteChange::Remove {
                                    destination: route.destination.clone(),
                                    device: device.clone(),
                                }));
                            } else {
                                state.confirm = Some(key);
                            }
                        }
                    } else {
                        ui.label("");
                    }
                    ui.end_row();
                }
            });
    }
    if model.routes().is_none() {
        ui.weak("Loading…");
    } else if list.is_empty() {
        ui.weak("None. Traffic follows your system's routes.");
    }
    if !others.is_empty() {
        egui::CollapsingHeader::new(format!("System routes ({})", others.len()))
            .id_salt("routes-other")
            .show(ui, |ui| {
                egui::Grid::new("routes-other-grid")
                    .striped(true)
                    .num_columns(4)
                    .spacing([14.0, 6.0])
                    .show(ui, |ui| {
                        for title in ["destination", "gateway", "device", "metric"] {
                            ui.strong(title);
                        }
                        ui.end_row();
                        for route in &others {
                            ui.label(route.destination.as_str());
                            ui.label(route.gateway.as_deref().unwrap_or("—"));
                            ui.label(route.device.as_deref().unwrap_or("—"));
                            ui.label(route.metric.map_or("—".into(), |metric| metric.to_string()));
                            ui.end_row();
                        }
                    });
                ui.weak("Routes l2tunnel did not add; it never replaces or removes them.");
            });
    }
    // Only tunnel devices; the running profile's device first and preselected.
    let preferred = present::profile_device(model);
    let mut tunnels: Vec<String> = model
        .devices()
        .unwrap_or_default()
        .iter()
        .filter(|device| device.layer.is_some() && present::is_tunnel(model, device))
        .map(|device| device.name.clone())
        .collect();
    if let Some(preferred) = &preferred
        && let Some(index) = tunnels.iter().position(|name| name == preferred)
    {
        let name = tunnels.remove(index);
        tunnels.insert(0, name);
    }
    if !tunnels.contains(&state.route.device) {
        state.route.device = tunnels.first().cloned().unwrap_or_default();
    }
    ui.add_space(12.0);
    if !connected {
        ui.weak("Routes belong to the running session: connect first. The service removes every route it added when the session ends.");
    }
    ui.add_enabled_ui(connected && !busy, |ui| {
        ui.strong("Send all traffic through the tunnel");
        let all = list
            .iter()
            .any(|route| route.owned && route.purpose.as_deref() == Some("default"));
        ui.horizontal(|ui| {
            device_choice(ui, "default-device", &mut state.route.device, &tunnels);
            let label = if all { "Stop sending all traffic" } else { "Send all traffic" };
            if ui
                .add_enabled(!state.route.device.is_empty(), egui::Button::new(label))
                .clicked()
            {
                commands.extend(model.change_route(RouteChange::Default {
                    enabled: !all,
                    device: state.route.device.clone(),
                }));
            }
        });
        ui.weak("Adds two half-default routes via the device plus an exception keeping the peer's outer address on its current path; existing routes are never replaced.");
        ui.add_space(10.0);
        ui.strong("Add route");
        let form = &mut state.route;
        egui::Grid::new("new-route").num_columns(2).show(ui, |ui| {
            ui.label("Destination");
            ui.add(egui::TextEdit::singleline(&mut form.destination).hint_text("10.20.0.0/16"));
            ui.end_row();
            ui.label("Device");
            device_choice(ui, "route-device", &mut form.device, &tunnels);
            ui.end_row();
            ui.label("Gateway");
            ui.add(egui::TextEdit::singleline(&mut form.gateway).hint_text("optional"));
            ui.end_row();
            ui.label("Metric");
            ui.add(egui::TextEdit::singleline(&mut form.metric).hint_text("optional"));
            ui.end_row();
        });
        let change = route_change(form);
        if let (Err(reason), false) = (&change, form.destination.is_empty()) {
            ui.weak(reason.as_str());
        }
        if ui.add_enabled(change.is_ok(), egui::Button::new("Add")).clicked()
            && let Ok(change) = change
        {
            commands.extend(model.change_route(change));
        }
    });
    commands
}

fn device_choice(ui: &mut egui::Ui, id: &str, selected: &mut String, choices: &[String]) {
    egui::ComboBox::from_id_salt(id)
        .selected_text(if selected.is_empty() {
            if choices.is_empty() {
                "no tunnel device"
            } else {
                "choose device"
            }
        } else {
            selected.as_str()
        })
        .show_ui(ui, |ui| {
            for choice in choices {
                ui.selectable_value(selected, choice.clone(), choice.as_str());
            }
        });
}

fn statistics(ui: &mut egui::Ui, model: &mut Model, state: &mut UiState) -> Vec<Command> {
    let mut commands = Vec::new();
    let Some(metrics) = model.metrics().cloned() else {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label("Waiting for the first sample…");
        });
        return commands;
    };
    ui.horizontal(|ui| {
        ui.label("Window");
        ui.selectable_value(&mut state.window, 60, "60 s");
        ui.selectable_value(&mut state.window, 600, "10 min");
    });
    let history = model.history();
    for (title, rate) in [
        ("Sent on the network", Rate::SentBits),
        ("Packets received from the network", Rate::ReceivedPackets),
        (
            "Your traffic into the tunnel (packets out)",
            Rate::DeviceRead,
        ),
        (
            "Traffic out of the tunnel to you (packets in)",
            Rate::DeviceWritten,
        ),
    ] {
        chart(
            ui,
            title,
            rate,
            ChartAxis::Rolling {
                window_secs: state.window,
            },
            &history.timed_series(rate, state.window),
        );
        ui.add_space(4.0);
    }
    let count = |value: Option<u64>| value.map_or("—".into(), |value| value.to_string());
    ui.add_space(8.0);
    ui.strong("Carrier lanes");
    egui::Grid::new("lanes")
        .striped(true)
        .num_columns(6)
        .show(ui, |ui| {
            for title in [
                "lane",
                "carrier",
                "local",
                "remote",
                "sent pkts",
                "recv pkts",
            ] {
                ui.strong(title);
            }
            ui.end_row();
            for lane in &metrics.lanes {
                ui.label(lane.lane.to_string());
                ui.label(lane.carrier.as_str());
                ui.label(lane.local.as_str());
                ui.label(lane.remote.as_str());
                ui.label(count(lane.wire.map(|wire| wire.sent_packets)));
                ui.label(count(lane.wire.map(|wire| wire.received_packets)));
                ui.end_row();
            }
        });
    if let Some(wire) = metrics.wire {
        ui.weak(format!(
            "send drops {} · receive errors {} · rejected {} · replay {}",
            wire.send_drops, wire.receive_errors, wire.rejected_packets, wire.replay_rejections
        ));
    }
    ui.add_space(8.0);
    ui.strong("MUX channels");
    ui.label(format!(
        "width: send {} · receive {}",
        count(metrics.send_channels.map(u64::from)),
        count(metrics.receive_channels.map(u64::from)),
    ));
    if metrics.channels.is_empty() {
        ui.weak("Per-channel counters are not reported by this profile.");
    } else {
        egui::Grid::new("channels")
            .striped(true)
            .num_columns(4)
            .show(ui, |ui| {
                for title in ["channel", "queued", "admitted", "dropped"] {
                    ui.strong(title);
                }
                ui.end_row();
                for channel in &metrics.channels {
                    ui.label(channel.channel.to_string());
                    ui.label(format_bytes(channel.queued_bytes));
                    ui.label(channel.admitted.to_string());
                    ui.label(channel.dropped.to_string());
                    ui.end_row();
                }
            });
    }
    ui.add_space(8.0);
    ui.strong("Inner flows");
    if metrics.flows.is_empty() {
        ui.weak("Per-flow counters are not reported by this profile.");
    } else {
        egui::Grid::new("flows")
            .striped(true)
            .num_columns(5)
            .show(ui, |ui| {
                for title in ["flow", "target", "sent", "received", "state"] {
                    ui.strong(title);
                }
                ui.end_row();
                for flow in &metrics.flows {
                    ui.label(flow.flow.to_string());
                    ui.label(flow.label.as_str());
                    ui.label(format_bytes(flow.sent_bytes));
                    ui.label(format_bytes(flow.received_bytes));
                    ui.label(flow.state.as_str());
                    ui.end_row();
                }
            });
    }
    if let Some(device) = metrics.device {
        ui.add_space(8.0);
        ui.strong("Device");
        ui.label(format!(
            "pending {} packets / {} · oversize {} · backpressure drops {}",
            device.pending_packets,
            format_bytes(device.pending_bytes),
            device.oversize,
            device.backpressure_drops
        ));
    }
    if model.capability(Feature::Meters).is_ok() {
        ui.add_space(10.0);
        commands.extend(meters_section(ui, model, state));
    }
    ui.add_space(8.0);
    egui::CollapsingHeader::new("Details")
        .id_salt("statistics-details")
        .show(ui, |ui| {
            ui.label(format!(
                "Generation {} · {} samples kept",
                metrics.generation,
                model.history().len()
            ));
            if !metrics.unreported.is_empty() {
                ui.weak(format!(
                    "Counters this profile does not report: {}",
                    metrics.unreported.join(", ")
                ));
            }
        });
    commands
}

fn meters_section(ui: &mut egui::Ui, model: &mut Model, state: &mut UiState) -> Vec<Command> {
    let mut commands = Vec::new();
    egui::CollapsingHeader::new("CSR meters (flow control, runtime, MUX)")
        .id_salt("statistics-csr-meters")
        .show(ui, |ui| {
            ui.weak("Live control/status registers from the running session (same data as `l2tunnelctl meters read`).");
            let mut changed = false;
            ui.horizontal_wrapped(|ui| {
                if ui
                    .radio_value(&mut state.meters_side, MeterSide::Local, "Local")
                    .changed()
                {
                    changed = true;
                }
                if ui
                    .radio_value(&mut state.meters_side, MeterSide::Remote, "Remote peer")
                    .changed()
                {
                    changed = true;
                }
                ui.separator();
                ui.label("Prefix");
                let prefix_edit = ui.add(
                    egui::TextEdit::singleline(&mut state.meters_prefix)
                        .hint_text("e.g. flow_control, runtime, mux")
                        .desired_width(210.0),
                );
                let submitted = prefix_edit.lost_focus()
                    && ui.input(|input| input.key_pressed(egui::Key::Enter));
                if ui
                    .add_enabled(!model.meters_loading(), egui::Button::new("Read"))
                    .clicked()
                    || submitted
                    || changed
                {
                    let prefix = state.meters_prefix.trim().to_owned();
                    commands.extend(model.refresh_meters(state.meters_side, prefix, None));
                }
                ui.checkbox(&mut state.meters_auto, "Auto (2 s)");
                if model.meters_loading() {
                    ui.spinner();
                }
            });
            if model.meters().is_none()
                && model.meters_error().is_none()
                && !model.meters_loading()
            {
                let prefix = state.meters_prefix.trim().to_owned();
                commands.extend(model.refresh_meters(state.meters_side, prefix, None));
            }
            if let Some(error) = model.meters_error() {
                ui.colored_label(ui.visuals().warn_fg_color, format!("Meters unavailable: {error}"));
            }
            if let Some(page) = model.meters().cloned() {
                ui.horizontal_wrapped(|ui| {
                    let side = match page.side {
                        MeterSide::Local => "local",
                        MeterSide::Remote => "remote",
                    };
                    let age = page
                        .age_ms
                        .map(|ms| format!(" · table age {ms} ms"))
                        .unwrap_or_default();
                    ui.weak(format!(
                        "{side} · generation {} · {} registers{age}",
                        page.generation,
                        page.entries.len()
                    ));
                    ui.separator();
                    ui.label("Filter");
                    ui.add(
                        egui::TextEdit::singleline(&mut state.meters_filter)
                            .hint_text("substring")
                            .desired_width(180.0),
                    );
                    if let Some(next) = page.next.clone()
                        && ui
                            .add_enabled(!model.meters_loading(), egui::Button::new("Load more"))
                            .clicked()
                    {
                        let prefix = state.meters_prefix.trim().to_owned();
                        commands.extend(model.refresh_meters(
                            state.meters_side,
                            prefix,
                            Some(next),
                        ));
                    }
                });
                let filter = state.meters_filter.trim().to_lowercase();
                let visible: Vec<_> = page
                    .entries
                    .iter()
                    .filter(|entry| {
                        filter.is_empty() || entry.path.to_lowercase().contains(&filter)
                    })
                    .collect();
                let waits = wait_percentiles(&page.entries, &filter);
                if !waits.is_empty() {
                    ui.add_space(4.0);
                    ui.strong("Wait latency percentiles (completed episodes)");
                    egui::Grid::new("csr-wait-percentiles")
                        .striped(true)
                        .num_columns(4)
                        .spacing([14.0, 4.0])
                        .show(ui, |ui| {
                            for title in ["wait cause", "episodes", "p50", "p99"] {
                                ui.strong(title);
                            }
                            ui.end_row();
                            for (cause, episodes, p50, p99) in &waits {
                                ui.monospace(cause.as_str());
                                ui.monospace(episodes.to_string());
                                ui.monospace(format!("≤ {p50} µs"));
                                ui.monospace(format!("≤ {p99} µs"));
                                ui.end_row();
                            }
                        });
                    ui.add_space(4.0);
                }
                if visible.is_empty() {
                    ui.weak("No matching registers.");
                } else {
                    egui::ScrollArea::vertical()
                        .id_salt("csr-meters-scroll")
                        .min_scrolled_height(240.0)
                        .max_height(320.0)
                        .show(ui, |ui| {
                            egui::Grid::new("csr-meters-grid")
                                .striped(true)
                                .num_columns(3)
                                .spacing([14.0, 4.0])
                                .show(ui, |ui| {
                                    for title in ["register", "value", "rate"] {
                                        ui.strong(title);
                                    }
                                    ui.end_row();
                                    for entry in &visible {
                                        ui.monospace(entry.path.as_str());
                                        ui.monospace(entry.value.to_string());
                                        match model.meter_rate(&entry.path, entry.value) {
                                            Some(rate) if rate > 0.0 => {
                                                ui.monospace(format!("{rate:.1}/s"));
                                            }
                                            Some(_) => {
                                                ui.weak("0/s");
                                            }
                                            None => {
                                                ui.weak("—");
                                            }
                                        }
                                        ui.end_row();
                                    }
                                });
                        });
                }
            }
        });
    commands
}

fn management(ui: &mut egui::Ui, model: &mut Model, state: &mut UiState) -> Vec<Command> {
    let mut commands = Vec::new();
    let mut stop = false;
    ui.heading("Service");
    match model.info() {
        Some(info) => {
            rows(
                ui,
                "service",
                &[
                    ("Version", info.version.clone()),
                    ("Role", role_text(info.role).into()),
                    ("Local API", info.api.to_string()),
                    (
                        "Uptime",
                        uptime(info.uptime_ms.saturating_add(state.info_elapsed_ms)),
                    ),
                    (
                        "Instance",
                        model
                            .service()
                            .map_or("—".into(), |id| format!("{:016x}", id.0)),
                    ),
                ],
            );
            if model.capability(Feature::Stop).is_ok() {
                let confirming = state.confirm.as_deref() == Some("service:stop");
                let label = if confirming {
                    "Confirm: disconnect and stop the service"
                } else {
                    "Stop service"
                };
                if ui
                    .add_enabled(!model.busy(), egui::Button::new(label))
                    .clicked()
                {
                    if confirming {
                        state.confirm = None;
                        stop = true;
                    } else {
                        state.confirm = Some("service:stop".into());
                    }
                }
                ui.weak(
                    "Stopping disconnects first. Start it again from any page with Start service.",
                );
            }
            ui.add_space(4.0);
            egui::CollapsingHeader::new("What this service supports")
                .id_salt("capabilities")
                .show(ui, |ui| {
                    for capability in &info.capabilities {
                        let text = format!("{:?}", capability.feature).to_lowercase();
                        match &capability.reason {
                            None => ui.label(format!("✔ {text}")),
                            Some(reason) => ui.weak(format!("✘ {text}: {reason}")),
                        };
                    }
                });
        }
        None => {
            ui.weak("Service information not read yet.");
        }
    }
    if stop {
        commands.extend(model.act(Action::Stop));
    }
    if let Some(update) = state.service_update.clone() {
        ui.add_space(6.0);
        let (update_commands, _) = crate::start::update_banner(ui, model, &update, false);
        commands.extend(update_commands);
    }
    ui.add_space(10.0);
    ui.heading("Profiles");
    commands.extend(crate::profiles::section(ui, model, &mut state.profiles));
    ui.add_space(12.0);
    ui.heading("Keys and trusted peers");
    commands.extend(crate::profiles::keys(ui, model, &mut state.profiles));
    if model.capability(Feature::Sessions).is_ok() {
        ui.add_space(12.0);
        ui.heading("Client session (server)");
        commands.extend(sessions(ui, model, state));
    }
    commands
}

fn sessions(ui: &mut egui::Ui, model: &mut Model, state: &mut UiState) -> Vec<Command> {
    let mut commands = Vec::new();
    if let Err(reason) = model.capability(Feature::Sessions) {
        ui.weak(format!("Unavailable: {reason}"));
        return commands;
    }
    if model.sessions().is_none() {
        commands.extend(model.refresh_sessions());
    }
    let busy = model.busy();
    let list = model.sessions().map(<[_]>::to_vec).unwrap_or_default();
    if list.is_empty() {
        ui.weak("No live session (the server waits for its member).");
    }
    for session in &list {
        rows(
            ui,
            "session",
            &[
                ("Generation", session.generation.to_string()),
                ("Peer", session.peer.clone().unwrap_or_else(|| "—".into())),
                ("Up", session.connected_ms.map_or("—".into(), uptime)),
                (
                    "Profile",
                    session
                        .profile
                        .clone()
                        .unwrap_or_else(|| "— (not from a stored profile)".into()),
                ),
                (
                    "Trusted member",
                    session.member.clone().unwrap_or_else(|| {
                        if session.profile.is_none() {
                            "— (not from a stored profile)".into()
                        } else {
                            "—".into()
                        }
                    }),
                ),
                (
                    "Sent / received",
                    match (session.sent_bytes, session.received_bytes) {
                        (Some(sent), Some(received)) => {
                            format!("{} / {}", format_bytes(sent), format_bytes(received))
                        }
                        _ => "not reported".into(),
                    },
                ),
            ],
        );
    }
    ui.horizontal(|ui| {
        if ui.button("Refresh").clicked() {
            commands.extend(model.refresh_sessions());
        }
        let confirming = state.confirm.as_deref() == Some("session:kick");
        let label = if confirming {
            "Confirm: end the session"
        } else {
            "Kick session"
        };
        if ui
            .add_enabled(!busy && !list.is_empty(), egui::Button::new(label))
            .clicked()
        {
            if confirming {
                state.confirm = None;
                commands.extend(model.act(Action::Kick));
            } else {
                state.confirm = Some("session:kick".into());
            }
        }
    });
    ui.weak(
        "Kicking ends the session; the server listens again and the same member may reconnect.",
    );
    if model.capability(Feature::Profiles).is_ok() {
        let from_profile = list.iter().any(|session| session.profile.is_some());
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label("New member public key");
            ui.add(
                egui::TextEdit::singleline(&mut state.revoke)
                    .hint_text("/etc/l2tunnel/member-new.pub")
                    .desired_width(300.0),
            );
            let path = std::path::PathBuf::from(state.revoke.trim());
            let ready = from_profile && !busy && path.is_absolute();
            let confirming = state.confirm.as_deref() == Some("member:revoke");
            let label = if confirming {
                "Confirm: revoke the current member"
            } else {
                "Revoke member"
            };
            if ui.add_enabled(ready, egui::Button::new(label)).clicked() {
                if confirming {
                    state.confirm = None;
                    commands.extend(model.revoke(path));
                } else {
                    state.confirm = Some("member:revoke".into());
                }
            }
        });
        ui.weak(
            "Revoking saves the running profile with this key as its only trusted member and \
             replaces the session, so the old member cannot reconnect. Needs a session started \
             from a stored profile and an absolute path the service can read.",
        );
    } else {
        ui.weak("Member revocation requires running the server as a daemon with stored profiles.");
    }
    commands
}

fn uptime(ms: u64) -> String {
    let seconds = ms / 1000;
    let (days, hours, minutes) = (seconds / 86_400, seconds / 3600 % 24, seconds / 60 % 60);
    if days > 0 {
        format!("{days} d {hours:02}:{minutes:02}")
    } else {
        format!("{hours:02}:{minutes:02}:{:02}", seconds % 60)
    }
}

fn events(ui: &mut egui::Ui, model: &mut Model, state: &mut UiState) -> Vec<Command> {
    let mut commands = Vec::new();
    if let Some(Ok(_)) = model.take_exported() {
        state.export = default_export_path();
    }
    ui.strong("Diagnostic export");
    if state.export.is_empty() {
        state.export = default_export_path();
    }
    ui.horizontal(|ui| {
        ui.label("File");
        ui.add(egui::TextEdit::singleline(&mut state.export).desired_width(360.0));
        ui.checkbox(&mut state.include_addresses, "Include IP addresses");
        let ready = !state.export.trim().is_empty() && !model.exporting();
        if ui.add_enabled(ready, egui::Button::new("Export")).clicked() {
            commands.extend(model.export(
                std::path::PathBuf::from(state.export.trim()),
                state.include_addresses,
            ));
        }
    });
    ui.weak(
        "Status, service info, metrics, devices, routes, the service event log and recent \
         operation results as JSON. No keys or payload; addresses are redacted unless included. \
         The file must not exist and is readable by you only.",
    );
    ui.add_space(10.0);
    ui.horizontal(|ui| {
        ui.label("Filter");
        ui.add(egui::TextEdit::singleline(&mut state.filter).desired_width(240.0));
        ui.weak(format!("{} lines retained", model.log.len()));
    });
    ui.add_space(4.0);
    let filter = state.filter.to_lowercase();
    ui.weak("Newest first.");
    for line in model
        .log
        .iter()
        .rev()
        .filter(|line| filter.is_empty() || line.to_lowercase().contains(&filter))
    {
        ui.monospace(line.as_str());
    }
    commands
}

/// A new file name in the home (or current) directory.
fn default_export_path() -> String {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .map(std::path::PathBuf::from)
        .unwrap_or_default();
    home.join(format!("l2tunnel-diagnostics-{stamp}.json"))
        .display()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_page_has_a_title_and_uptime_formats() {
        assert_eq!(Page::ALL.len(), 8);
        assert_eq!(Page::parse("socks5"), Some(Page::Socks5));
        assert_eq!(Page::parse("Statistics"), Some(Page::Statistics));
        assert_eq!(Page::parse("nope"), None);
        assert!(Page::ALL.iter().all(|page| !page.title().is_empty()));
        assert_eq!(uptime(3_723_000), "01:02:03");
        assert_eq!(uptime(90_061_000), "1 d 01:01");
        let model = Model::default();
        assert_eq!(unavailable(&model, Page::Devices), None, "detached");
    }
}

/// Aggregate completed-episode wait histograms (`*.hist.b00..b23`) from CSR
/// entries into `(wait_cause, total_episodes, p50_us, p99_us)` rows.
pub fn wait_percentiles(
    entries: &[l2tunnel_client_core::local::MeterEntry],
    filter_lower: &str,
) -> Vec<(String, u64, u64, u64)> {
    let mut buckets: std::collections::BTreeMap<&str, [u64; l2tunnel_meters::wait::BUCKETS]> =
        std::collections::BTreeMap::new();
    for entry in entries {
        if let Some((base, bucket)) = entry.path.rsplit_once(".hist.b")
            && let Ok(index) = bucket.parse::<usize>()
            && index < l2tunnel_meters::wait::BUCKETS
        {
            if !filter_lower.is_empty() && !base.to_lowercase().contains(filter_lower) {
                continue;
            }
            buckets.entry(base).or_default()[index] = entry.value;
        }
    }
    let mut rows = Vec::new();
    for (base, counts) in buckets {
        let total: u64 = counts.iter().copied().sum();
        if total == 0 {
            continue;
        }
        let hist = l2tunnel_meters::Histogram::from_counts(counts);
        if let (Some(p50), Some(p99)) = (hist.quantile(0.5), hist.quantile(0.99)) {
            rows.push((base.to_owned(), total, p50, p99));
        }
    }
    rows
}

#[cfg(test)]
mod form_tests {
    use super::*;

    #[test]
    fn wait_percentiles_computes_p50_and_p99_from_csr_histograms() {
        use l2tunnel_client_core::local::MeterEntry;
        let base = "runtime.native_ingress.lane0.user.wait.queue_full";
        let entries = vec![
            MeterEntry {
                path: format!("{base}.hist.b03"),
                value: 8,
            },
            MeterEntry {
                path: format!("{base}.hist.b10"),
                value: 2,
            },
            MeterEntry {
                path: "runtime.wire.shared.sent_packets".into(),
                value: 42,
            },
        ];
        let rows = wait_percentiles(&entries, "");
        assert_eq!(rows, vec![(base.to_owned(), 10, 15, 2047)]);
        assert!(wait_percentiles(&entries, "unrelated").is_empty());
        assert_eq!(wait_percentiles(&entries, "queue_full").len(), 1);
    }

    #[test]
    fn forms_build_changes_validated_like_the_cli() {
        let mut form = DeviceForm {
            name: "l2t0".into(),
            addresses: " 10.88.0.2/24 , fd00::2/64,".into(),
            ..DeviceForm::default()
        };
        assert_eq!(
            create_change(&form),
            Ok(DeviceChange::Create {
                name: "l2t0".into(),
                layer: DeviceLayer::Tun,
                mtu: Some(1400),
                addresses: vec!["10.88.0.2/24".into(), "fd00::2/64".into()],
                up: true,
            })
        );
        form.mtu = "big".into();
        assert!(create_change(&form).is_err());
        form.mtu.clear();
        form.name = "bad name".into();
        assert!(create_change(&form).is_err());
        let edit = EditForm {
            name: "l2t0".into(),
            up: Some(false),
            ..EditForm::default()
        };
        assert!(matches!(
            configure_change(&edit),
            Ok(DeviceChange::Configure {
                mtu: None,
                up: Some(false),
                ..
            })
        ));
        let route = RouteForm {
            destination: "10.20.0.0/16".into(),
            device: "l2t0".into(),
            gateway: String::new(),
            metric: "7".into(),
        };
        assert!(matches!(
            route_change(&route),
            Ok(RouteChange::Add {
                metric: Some(7),
                gateway: None,
                ..
            })
        ));
        assert!(route_change(&RouteForm::default()).is_err());
    }
}
