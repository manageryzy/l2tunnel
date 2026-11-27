//! egui window: a persistent top bar, a sidebar of pages and a status line,
//! over the toolkit-independent model (docs/modules/desktop-gui.md).
use crate::model::{Action, Command, Model};
use crate::pages::{self, Page};
use crate::worker::Worker;
use eframe::egui;
use l2tunnel_client_core::local::Feature;
use std::time::{Duration, Instant};

/// Delay before resynchronizing with a lost or restarted service.
const RETRY: Duration = Duration::from_secs(3);
/// Metrics sampling period.
const SAMPLE: Duration = Duration::from_secs(1);
/// Auto-refresh period for the CSR meters panel when enabled.
const METERS_SAMPLE: Duration = Duration::from_secs(2);
/// How long a notice stays in the status line.
const NOTICE: Duration = Duration::from_secs(20);

/// The desktop window.
pub struct App {
    model: Model,
    worker: Worker,
    socket: String,
    retry_at: Option<Instant>,
    sample_at: Instant,
    meters_at: Instant,
    info_loaded: bool,
    info_at: Option<Instant>,
    last_uptime_ms: Option<u64>,
    status_at: Option<Instant>,
    last_connected_ms: Option<u64>,
    page: Page,
    ui: pages::UiState,
    /// The service field is open for editing.
    choosing: bool,
    /// User dismissed the top older-service reminder banner for this attachment.
    update_dismissed: bool,
    /// Notice text and when it first appeared.
    notice: (String, Instant),
}
impl App {
    /// Create the window, attaching at once when `socket` is set.
    pub fn new(worker: Worker, socket: String, page: Page) -> Self {
        let now = Instant::now();
        let mut app = Self {
            model: Model::default(),
            worker,
            socket,
            retry_at: None,
            sample_at: now,
            meters_at: now,
            info_loaded: false,
            info_at: None,
            last_uptime_ms: None,
            status_at: None,
            last_connected_ms: None,
            page,
            ui: pages::UiState::default(),
            choosing: false,
            update_dismissed: false,
            notice: (String::new(), now),
        };
        if !app.socket.is_empty() {
            app.attach();
        }
        let commands = pages::opened(&mut app.model, page);
        app.dispatch(commands);
        app
    }
    /// Pre-populate the Share URI import field (e.g. from a Windows `l2tunnel://` deep link).
    pub fn prefill_share_uri(&mut self, uri: String) {
        self.page = Page::Management;
        self.ui.profiles.share_uri_input = uri;
        self.model.notice =
            "Loaded l2tunnel:// Share URI — review and click Import URI on Management".into();
    }
    fn dispatch(&mut self, commands: Vec<Command>) {
        if !commands.is_empty() && !self.worker.send(commands) {
            self.model.notice = "Background worker unavailable; restart the GUI".into();
        }
    }
    fn clear_confirmations(&mut self) {
        self.ui.confirm = None;
        self.ui.profiles.confirm = None;
    }
    fn switch_page(&mut self, page: Page) {
        if self.page != page {
            self.clear_confirmations();
        }
        self.page = page;
        let commands = pages::opened(&mut self.model, page);
        self.dispatch(commands);
    }
    fn attach(&mut self) {
        self.retry_at = None;
        self.info_loaded = false;
        self.info_at = None;
        self.last_uptime_ms = None;
        self.status_at = None;
        self.last_connected_ms = None;
        self.update_dismissed = false;
        self.ui.service_update = None;
        self.ui.socks = crate::socks_panel::SocksForm::default();
        self.clear_confirmations();
        let commands = self.model.attach(&self.socket);
        self.dispatch(commands);
    }
    fn act(&mut self, action: Action) {
        let commands = self.model.act(action);
        self.dispatch(commands);
    }
    fn top_bar(&mut self, ui: &mut egui::Ui) {
        let view = self.model.view();
        let headline = crate::present::headline(&self.model);
        ui.horizontal(|ui| {
            pages::tone_dot(ui, headline.tone);
            ui.strong(headline.text.as_str());
            if let Some(profile) = crate::present::running_profile(&self.model) {
                ui.label(format!("· {profile}"));
            }
            if let Some(info) = self.model.info() {
                ui.weak(format!("· {}", pages::role_text(info.role)));
            }
            if let Some(carrier) = pages::carrier_text(&self.model) {
                ui.weak(format!("· {carrier}"));
            }
            if let Some(protocol) = pages::active_protocol_short(&self.model) {
                ui.weak(format!("· {protocol}"));
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add_enabled(view.cancel, egui::Button::new("Cancel"))
                    .clicked()
                {
                    self.act(Action::Cancel);
                }
                if ui
                    .add_enabled(view.disconnect, egui::Button::new("Disconnect"))
                    .clicked()
                {
                    self.act(Action::Disconnect);
                }
                let tooltip = if view.connect_label == "Reconnect" {
                    "Reconnect using the running session's plan"
                } else {
                    "Connect using the service's last plan"
                };
                if ui
                    .add_enabled(view.connect, egui::Button::new(view.connect_label))
                    .on_hover_text(tooltip)
                    .clicked()
                {
                    self.act(Action::Reconnect);
                }
            });
        });
        if headline.tone == crate::present::Tone::Bad
            && let Some(detail) = &headline.detail
        {
            ui.colored_label(ui.visuals().warn_fg_color, detail.as_str());
        }
        ui.horizontal_wrapped(|ui| {
            if self.choosing {
                ui.label("Service socket");
                let edit = ui.add(
                    egui::TextEdit::singleline(&mut self.socket)
                        .desired_width(320.0)
                        .hint_text(pages::SOCKET_HINT),
                );
                let entered =
                    edit.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
                if ui.button("Attach").clicked() || entered {
                    self.choosing = false;
                    self.attach();
                }
                if ui.button("Cancel").clicked() {
                    self.choosing = false;
                }
            } else {
                ui.weak(format!(
                    "Service: {}",
                    if self.socket.is_empty() {
                        "none"
                    } else {
                        self.socket.as_str()
                    }
                ));
                if ui.small_button("Change service…").clicked() {
                    self.choosing = true;
                }
            }
        });
    }
}
impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let now = Instant::now();
        while let Ok(message) = self.worker.messages.try_recv() {
            let commands = self.model.handle(message);
            self.dispatch(commands);
        }
        if let Some(socket) = self.model.take_started() {
            self.socket = socket.display().to_string();
        }
        if self.model.notice != self.notice.0 {
            self.notice = (self.model.notice.clone(), now);
        }
        // Track when service metadata and connected duration were read so
        // displayed uptimes tick smoothly without re-querying ServiceInfo.
        match self.model.info().cloned() {
            Some(info) => {
                if self.last_uptime_ms != Some(info.uptime_ms) {
                    self.last_uptime_ms = Some(info.uptime_ms);
                    self.info_at = Some(now);
                    self.ui.service_update =
                        crate::start::check_service_version(&info, self.model.path());
                }
                if !self.info_loaded {
                    self.info_loaded = true;
                    self.update_dismissed = false;
                    let opened = pages::opened(&mut self.model, self.page);
                    self.dispatch(opened);
                    // Sample metrics immediately once capabilities arrive.
                    let first = self.model.poll_metrics();
                    self.dispatch(first);
                    self.sample_at = now.checked_add(SAMPLE).unwrap_or(now);
                }
            }
            None => {
                self.info_loaded = false;
                self.info_at = None;
                self.last_uptime_ms = None;
                self.ui.service_update = None;
            }
        }
        match self.model.status().and_then(|status| status.connected_ms) {
            Some(connected_ms) => {
                if self.last_connected_ms != Some(connected_ms) {
                    self.last_connected_ms = Some(connected_ms);
                    self.status_at = Some(now);
                }
            }
            None => {
                self.status_at = None;
                self.last_connected_ms = None;
            }
        }
        self.ui.info_elapsed_ms = self.info_at.map_or(0, |at| {
            u64::try_from(at.elapsed().as_millis()).unwrap_or(u64::MAX)
        });
        self.ui.status_elapsed_ms = self.status_at.map_or(0, |at| {
            u64::try_from(at.elapsed().as_millis()).unwrap_or(u64::MAX)
        });

        if self.model.retry && self.retry_at.is_none() {
            self.retry_at = now.checked_add(RETRY);
        }
        if let Some(at) = self.retry_at {
            if now >= at {
                self.retry_at = None;
                let commands = self.model.resync();
                self.dispatch(commands);
            } else {
                ctx.request_repaint_after(at - now);
            }
        }
        if now >= self.sample_at {
            self.sample_at = now.checked_add(SAMPLE).unwrap_or(now);
            let commands = self.model.poll_metrics();
            self.dispatch(commands);
        }
        if self.page == Page::Statistics
            && self.ui.meters_auto
            && self.model.capability(Feature::Meters).is_ok()
            && now >= self.meters_at
        {
            self.meters_at = now.checked_add(METERS_SAMPLE).unwrap_or(now);
            let side = self.ui.meters_side;
            let prefix = self.ui.meters_prefix.trim().to_owned();
            let commands = self.model.refresh_meters(side, prefix, None);
            self.dispatch(commands);
        }
        let next_wake = self.sample_at.saturating_duration_since(now);
        ctx.request_repaint_after(next_wake);
    }
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if ui.input(|input| input.key_pressed(egui::Key::Escape)) {
            self.clear_confirmations();
        }
        egui::Panel::top("top").show(ui, |ui| {
            let max_w = ui.available_width().min(1020.0);
            ui.set_max_width(max_w);
            ui.add_space(4.0);
            self.top_bar(ui);
            if !self.update_dismissed
                && let Some(update) = self.ui.service_update.clone()
            {
                ui.add_space(4.0);
                let (commands, dismissed) =
                    crate::start::update_banner(ui, &mut self.model, &update, true);
                self.dispatch(commands);
                if dismissed {
                    self.update_dismissed = true;
                }
            }
            ui.add_space(4.0);
        });
        egui::Panel::bottom("status").show(ui, |ui| {
            ui.horizontal(|ui| {
                if self.notice.1.elapsed() < NOTICE {
                    ui.label(self.notice.0.as_str());
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.weak("Closing this window does not disconnect the tunnel.");
                });
            });
        });
        egui::Panel::left("pages")
            .resizable(false)
            .exact_size(140.0)
            .show(ui, |ui| {
                ui.add_space(6.0);
                for page in Page::ALL {
                    let unavailable = pages::unavailable(&self.model, page).is_some();
                    let text = if unavailable {
                        egui::RichText::new(page.title()).weak()
                    } else {
                        egui::RichText::new(page.title())
                    };
                    if ui.selectable_label(self.page == page, text).clicked() {
                        self.switch_page(page);
                    }
                }
            });
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    let max_w = ui.available_width().min(860.0);
                    ui.set_max_width(max_w);
                    let commands = pages::show(ui, &mut self.model, &mut self.ui, self.page);
                    self.dispatch(commands);
                });
        });
        let context = ui.ctx().clone();
        let commands = crate::profiles::windows(&context, &mut self.model, &mut self.ui.profiles);
        self.dispatch(commands);
        if let Some(page) = self.ui.goto.take() {
            self.switch_page(page);
        }
    }
}
