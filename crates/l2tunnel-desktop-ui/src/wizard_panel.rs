//! Quick Setup Wizard modal for the Desktop GUI:
//! crawls a target cover domain (e.g. `google.com`), generates fresh matched
//! server + client credentials and profiles, and outputs a ready-to-paste
//! `l2tunnel://v1/connect?...` share link + server command.
use crate::model::Model;
use crate::profiles::{Editor, ProfileState};
use eframe::egui;
use l2tunnel_client_core::local::wizard::{
    self, CrawlReport, WizardCarrier, WizardRequest, WizardResult,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

/// State of the Quick Setup Wizard window.
pub struct WizardState {
    /// Whether the wizard window is currently open.
    pub open: bool,
    /// Profile name.
    pub name: String,
    /// Selected carrier string (`quic-like`, `tls-like`, `media-like`, `openvpn-like`, `tcp`, `quic`).
    pub carrier: String,
    /// Target domain whose appearance to crawl/imitate (e.g. `google.com`).
    pub look_like: String,
    /// Public server IP:PORT.
    pub server: String,
    /// Client TUN CIDR (e.g. `10.231.0.2/30`).
    pub tun_client: String,
    /// Optional local client bind IP:PORT for maintained `tcp`/`quic`.
    pub client_bind: String,
    /// Output directory where `server/` and `client/` bundles are written.
    pub output_dir: String,
    /// Whether to crawl `look_like` live during generation.
    pub live_crawl: bool,
    /// In-flight background crawl receiver.
    crawl_rx: Option<Receiver<Result<CrawlReport, String>>>,
    /// Latest crawl result.
    pub crawl_result: Option<CrawlReport>,
    /// Last crawl error.
    pub crawl_error: Option<String>,
    /// In-flight background generation receiver.
    gen_rx: Option<Receiver<Result<WizardResult, String>>>,
    /// Latest generated wizard bundle.
    pub result: Option<WizardResult>,
    /// Last generation error.
    pub error: Option<String>,
}

impl std::fmt::Debug for WizardState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WizardState")
            .field("open", &self.open)
            .field("name", &self.name)
            .field("carrier", &self.carrier)
            .field("look_like", &self.look_like)
            .field("server", &self.server)
            .finish()
    }
}

impl Default for WizardState {
    fn default() -> Self {
        let default_dir = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
            .join("l2tunnel-wizard");
        Self {
            open: false,
            name: "google-tls".to_owned(),
            carrier: "openvpn-like".to_owned(),
            look_like: "google.com".to_owned(),
            server: "192.168.1.10:443".to_owned(),
            tun_client: "10.231.0.2/30".to_owned(),
            client_bind: "127.0.0.1:43101".to_owned(),
            output_dir: default_dir.display().to_string(),
            live_crawl: true,
            crawl_rx: None,
            crawl_result: None,
            crawl_error: None,
            gen_rx: None,
            result: None,
            error: None,
        }
    }
}

impl WizardState {
    fn poll_background(&mut self, ctx: &egui::Context) {
        if let Some(rx) = &self.crawl_rx {
            match rx.try_recv() {
                Ok(Ok(report)) => {
                    self.crawl_result = Some(report);
                    self.crawl_error = None;
                    self.crawl_rx = None;
                }
                Ok(Err(err)) => {
                    self.crawl_error = Some(err);
                    self.crawl_rx = None;
                }
                Err(mpsc::TryRecvError::Empty) => {
                    ctx.request_repaint_after(Duration::from_millis(100));
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.crawl_rx = None;
                }
            }
        }
        if let Some(rx) = &self.gen_rx {
            match rx.try_recv() {
                Ok(Ok(res)) => {
                    if let Some(crawl) = &res.crawl {
                        self.crawl_result = Some(crawl.clone());
                    }
                    self.result = Some(res);
                    self.error = None;
                    self.gen_rx = None;
                }
                Ok(Err(err)) => {
                    self.error = Some(err);
                    self.gen_rx = None;
                }
                Err(mpsc::TryRecvError::Empty) => {
                    ctx.request_repaint_after(Duration::from_millis(100));
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.gen_rx = None;
                }
            }
        }
    }

    fn start_crawl(&mut self, ctx: &egui::Context) {
        let target = self.look_like.trim().to_owned();
        if target.is_empty() {
            self.crawl_error = Some("Enter a cover domain (e.g. google.com) first.".into());
            return;
        }
        self.crawl_error = None;
        let (tx, rx) = mpsc::channel();
        self.crawl_rx = Some(rx);
        let repaint = ctx.clone();
        std::thread::spawn(move || {
            let outcome = wizard::crawl_cover_domain_blocking(&target, Duration::from_secs(5))
                .map_err(|e| e.to_string());
            let _ = tx.send(outcome);
            repaint.request_repaint();
        });
    }

    fn start_generate(&mut self, ctx: &egui::Context) {
        let carrier = match WizardCarrier::parse(&self.carrier) {
            Ok(c) => c,
            Err(e) => {
                self.error = Some(e.to_string());
                return;
            }
        };
        let server_endpoint: SocketAddr = match self.server.trim().parse() {
            Ok(addr) => addr,
            Err(_) => {
                self.error = Some("Server address must be IP:PORT (e.g. 203.0.113.10:443)".into());
                return;
            }
        };
        let out_dir = self.output_dir.trim();
        if out_dir.is_empty() {
            self.error = Some("Output directory is required".into());
            return;
        }
        let look_like =
            (!self.look_like.trim().is_empty()).then(|| self.look_like.trim().to_owned());
        let mut req = WizardRequest::simple(
            self.name.trim().to_owned(),
            carrier,
            server_endpoint,
            look_like,
            PathBuf::from(out_dir),
        );
        req.crawl = self.live_crawl;
        if !self.tun_client.trim().is_empty() {
            req.tun_client_cidr = self.tun_client.trim().to_owned();
        }
        if carrier.uses_maintained_policy() && !self.client_bind.trim().is_empty() {
            match self.client_bind.trim().parse() {
                Ok(bind) => req.client_bind = Some(bind),
                Err(_) => {
                    self.error = Some("Client bind must be IP:PORT".into());
                    return;
                }
            }
        }
        self.error = None;
        let (tx, rx) = mpsc::channel();
        self.gen_rx = Some(rx);
        let repaint = ctx.clone();
        std::thread::spawn(move || {
            let outcome = wizard::generate_pair(&req).map_err(|e| e.to_string());
            let _ = tx.send(outcome);
            repaint.request_repaint();
        });
    }
}

/// Render the Quick Setup Wizard modal when `state.wizard.open` is true.
pub fn show(ctx: &egui::Context, model: &mut Model, state: &mut ProfileState) {
    state.wizard.poll_background(ctx);
    if !state.wizard.open {
        return;
    }
    let mut open = state.wizard.open;
    let mut load_client: Option<(String, l2tunnel_client_core::local::ProfileDocument)> = None;
    let mut load_server: Option<(String, l2tunnel_client_core::local::ProfileDocument)> = None;
    let mut copy_notice: Option<String> = None;

    egui::Window::new("Quick Setup Wizard (Cover Crawl & Auto-Config)")
        .id(egui::Id::new("quick-setup-wizard"))
        .open(&mut open)
        .collapsible(false)
        .resizable(true)
        .default_size([740.0, 560.0])
        .show(ctx, |ui| {
            ui.weak(
                "Crawl a public cover domain (e.g. google.com) for SNI/cover hints, generate fresh \
                 own-server & client keys + pinned TLS cert, and output a server config + one-click \
                 l2tunnel:// client share link.",
            );
            ui.add_space(6.0);

            let busy = state.wizard.crawl_rx.is_some() || state.wizard.gen_rx.is_some();
            egui::Grid::new("wizard-form")
                .num_columns(2)
                .spacing([12.0, 8.0])
                .show(ui, |ui| {
                    ui.label("Profile name");
                    ui.add(
                        egui::TextEdit::singleline(&mut state.wizard.name)
                            .hint_text("google-tls")
                            .desired_width(280.0),
                    );
                    ui.end_row();

                    ui.label("Carrier");
                    egui::ComboBox::from_id_salt("wizard-carrier")
                        .width(280.0)
                        .selected_text(&state.wizard.carrier)
                        .show_ui(ui, |ui| {
                            for (val, desc) in [
                                ("quic-like", "quic-like (UDP QUIC cover, NAT-friendly)"),
                                ("tls-like", "tls-like (UDP TLS cover, NAT-friendly)"),
                                ("media-like", "media-like (UDP RTP/media cover)"),
                                ("openvpn-like", "openvpn-like (UDP + TLS 1.3 SNI + Pin)"),
                                ("tcp", "tcp (TCP/TLS 1.3 + SNI + Pin)"),
                                ("quic", "quic (Genuine Quinn QUIC + Pin)"),
                            ] {
                                ui.selectable_value(&mut state.wizard.carrier, val.to_owned(), desc);
                            }
                        });
                    ui.end_row();

                    ui.label("Look-like domain");
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut state.wizard.look_like)
                                .hint_text("google.com")
                                .desired_width(280.0),
                        );
                        if ui
                            .add_enabled(!busy, egui::Button::new("Crawl Domain"))
                            .clicked()
                        {
                            state.wizard.start_crawl(ctx);
                        }
                    });
                    ui.end_row();

                    ui.label("Server address (IP:port)");
                    ui.add(
                        egui::TextEdit::singleline(&mut state.wizard.server)
                            .hint_text("203.0.113.10:443")
                            .desired_width(280.0),
                    );
                    ui.end_row();

                    if matches!(state.wizard.carrier.as_str(), "tcp" | "quic") {
                        ui.label("Client local bind (IP:port)");
                        ui.add(
                            egui::TextEdit::singleline(&mut state.wizard.client_bind)
                                .hint_text("127.0.0.1:43101")
                                .desired_width(280.0),
                        );
                        ui.end_row();
                    }

                    ui.label("Client TUN CIDR");
                    ui.add(
                        egui::TextEdit::singleline(&mut state.wizard.tun_client)
                            .hint_text("10.231.0.2/30")
                            .desired_width(280.0),
                    );
                    ui.end_row();

                    ui.label("Output directory");
                    ui.add(
                        egui::TextEdit::singleline(&mut state.wizard.output_dir)
                            .desired_width(420.0),
                    );
                    ui.end_row();

                    ui.label("Probe domain live");
                    ui.checkbox(
                        &mut state.wizard.live_crawl,
                        "Crawl target domain TLS 1.3 / ALPN / UDP-QUIC during generation",
                    );
                    ui.end_row();
                });

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!busy, egui::Button::new("Generate Server Config & Client Link"))
                    .clicked()
                {
                    state.wizard.start_generate(ctx);
                }
                if busy {
                    ui.spinner();
                    ui.label("Working…");
                }
            });

            if let Some(err) = &state.wizard.crawl_error {
                ui.colored_label(ui.visuals().warn_fg_color, format!("Crawl notice: {err}"));
            }
            if let Some(err) = &state.wizard.error {
                ui.colored_label(ui.visuals().error_fg_color, err);
            }

            if let Some(report) = &state.wizard.crawl_result {
                ui.add_space(4.0);
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.strong(format!(
                        "Crawled {}:{} ({})",
                        report.domain, report.port, report.resolved_addr
                    ));
                    ui.label(format!(
                        "TLS: {} · ALPN: {} · Cipher: {} · UDP/QUIC: {}",
                        report.tls_version,
                        report.alpn.as_deref().unwrap_or("none"),
                        report.cipher_suite,
                        if report.udp_quic_observed { "active" } else { "no reply" }
                    ));
                    ui.weak(format!(
                        "Recommended SNI: {} · Cover: {} (tunnel auth still uses fresh pinned own-server keys)",
                        report.recommended_sni, report.recommended_cover
                    ));
                });
            }

            if let Some(res) = &state.wizard.result {
                ui.add_space(8.0);
                ui.separator();
                ui.strong("Generated Bundle Ready");
                if let Some(note) = &res.crawl_note {
                    ui.weak(note);
                }
                if let Some(pin) = &res.server_pin {
                    ui.small(format!(
                        "Own-server TLS pin (--server-pin): {pin} · SNI: {}",
                        res.sni.as_deref().unwrap_or("(disabled)")
                    ));
                }

                ui.add_space(4.0);
                ui.label("Client Share Link (paste into Windows / Linux / Android):");
                let mut uri_ro = res.share_uri.clone();
                ui.add(
                    egui::TextEdit::multiline(&mut uri_ro)
                        .desired_rows(3)
                        .desired_width(f32::INFINITY),
                );
                ui.horizontal_wrapped(|ui| {
                    if ui.button("Copy Client Link").clicked() {
                        ctx.copy_text(res.share_uri.clone());
                        copy_notice = Some("Copied full provisioning client share link.".into());
                    }
                    if ui.button("Copy Public Link (No Secrets)").clicked() {
                        ctx.copy_text(res.public_share_uri.clone());
                        copy_notice = Some("Copied public share link.".into());
                    }
                    if ui.button("Load Client Profile into Editor").clicked() {
                        load_client = Some((res.name.clone(), res.client_profile.clone()));
                    }
                    if ui.button("Load Server Profile into Editor").clicked() {
                        load_server = Some((format!("{}-server", res.name), res.server_profile.clone()));
                    }
                });

                ui.add_space(4.0);
                ui.label(format!(
                    "Server Command (saved in {}):",
                    res.server_dir.display()
                ));
                let mut cmd_ro = res.server_command.clone();
                ui.add(
                    egui::TextEdit::multiline(&mut cmd_ro)
                        .desired_rows(3)
                        .desired_width(f32::INFINITY),
                );
                if ui.button("Copy Server Command").clicked() {
                    ctx.copy_text(res.server_command.clone());
                    copy_notice = Some("Copied server command.".into());
                }
            }
        });

    state.wizard.open = open;
    if let Some(notice) = copy_notice {
        model.notice = notice;
    }
    if let Some((name, doc)) = load_client {
        state.editor = Some(Editor::from_document(name, doc));
        state.wizard.open = false;
        model.notice = "Loaded generated client profile into editor; click Save to install.".into();
    } else if let Some((name, doc)) = load_server {
        state.editor = Some(Editor::from_document(name, doc));
        state.wizard.open = false;
        model.notice = "Loaded generated server profile into editor; click Save to install.".into();
    }
}
