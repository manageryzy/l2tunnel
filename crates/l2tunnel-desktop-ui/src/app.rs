//! egui window: a persistent top bar, a sidebar of pages and a status line,
//! over the toolkit-independent model (docs/modules/desktop-gui.md).
use crate::model::{Action, Command, Model};
use crate::pages::{self, Page};
use crate::worker::Worker;
use eframe::egui;
use std::time::{Duration, Instant};

/// Delay before resynchronizing with a lost or restarted service.
const RETRY: Duration = Duration::from_secs(3);
/// Metrics sampling period.
const SAMPLE: Duration = Duration::from_secs(1);
/// How long a notice stays in the status line.
const NOTICE: Duration = Duration::from_secs(20);

/// The desktop window.
pub struct App {
    model: Model,
    worker: Worker,
    socket: String,
    retry_at: Option<Instant>,
    sample_at: Instant,
    page: Page,
    ui: pages::UiState,
    /// The service field is open for editing.
    choosing: bool,
    /// Notice text and when it first appeared.
    notice: (String, Instant),
}
impl App {
    /// Create the window, attaching at once when `socket` is set.
    pub fn new(worker: Worker, socket: String, page: Page) -> Self {
        let mut app = Self {
            model: Model::default(),
            worker,
            socket,
            retry_at: None,
            sample_at: Instant::now(),
            page,
            ui: pages::UiState::default(),
            choosing: false,
            notice: (String::new(), Instant::now()),
        };
        if !app.socket.is_empty() {
            app.attach();
        }
        let commands = pages::opened(&mut app.model, page);
        app.dispatch(commands);
        app
    }
    fn dispatch(&mut self, commands: Vec<Command>) {
        if !commands.is_empty() && !self.worker.send(commands) {
            self.model.notice = "Background worker unavailable; restart the GUI".into();
        }
    }
    fn attach(&mut self) {
        self.retry_at = None;
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
        ui.horizontal_wrapped(|ui| {
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
                let label = if view.connect_label == "Connect" {
                    "Reconnect"
                } else {
                    view.connect_label
                };
                if ui
                    .add_enabled(view.connect, egui::Button::new(label))
                    .on_hover_text("Connect again with the last plan")
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
        while let Ok(message) = self.worker.messages.try_recv() {
            let commands = self.model.handle(message);
            self.dispatch(commands);
        }
        if let Some(socket) = self.model.take_started() {
            self.socket = socket.display().to_string();
        }
        if self.model.notice != self.notice.0 {
            self.notice = (self.model.notice.clone(), Instant::now());
        }
        if self.model.retry && self.retry_at.is_none() {
            self.retry_at = Instant::now().checked_add(RETRY);
        }
        let now = Instant::now();
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
        ctx.request_repaint_after(self.sample_at.saturating_duration_since(now));
    }
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::Panel::top("top").show(ui, |ui| {
            ui.add_space(4.0);
            self.top_bar(ui);
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
                        self.page = page;
                        let commands = pages::opened(&mut self.model, page);
                        self.dispatch(commands);
                    }
                }
            });
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    let commands = pages::show(ui, &mut self.model, &mut self.ui, self.page);
                    self.dispatch(commands);
                });
        });
        let context = ui.ctx().clone();
        let commands = crate::profiles::windows(&context, &mut self.model, &mut self.ui.profiles);
        self.dispatch(commands);
        if let Some(page) = self.ui.goto.take() {
            self.page = page;
            let commands = pages::opened(&mut self.model, page);
            self.dispatch(commands);
        }
    }
}
