//! "Start service" panel, shown on every page while no service answers
//! (owner decisions 2026-11-24: elevated start through an installer).
//!
//! The GUI stays unprivileged: the administrator prompt (pkexec on Linux,
//! UAC on Windows) runs the shared `local::elevate` installer/starter, and the
//! GUI attaches once the service answers. On Linux the installed systemd
//! service runs as this user with only CAP_NET_ADMIN.
use crate::model::{Command, Model};
use eframe::egui;
use l2tunnel_client_core::local::elevate::StartRequest;
use l2tunnel_client_core::local::{OPERATIONS_VERSION, ServiceInfo};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Reminder shown when the attached service is older than this GUI build.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceUpdate {
    /// Plain-language explanation of why the service is older.
    pub reason: String,
    /// When `Some`, clicking the install button runs this elevated reinstall/restart.
    pub install_request: Option<StartRequest>,
}

/// Parse `MAJOR.MINOR.PATCH` (ignoring any `-prerelease` or `+build` suffix).
pub fn parse_semver(text: &str) -> Option<(u64, u64, u64)> {
    let core = text.trim().split(['-', '+']).next()?;
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

/// Compare the local build binary against the installed system binary and the
/// running daemon's approximate start time. Pure helper for unit testing.
pub fn binary_outdated(
    local_mtime: SystemTime,
    local_len: u64,
    installed: Option<(SystemTime, u64)>,
    service_uptime_ms: u64,
    now: SystemTime,
) -> Option<&'static str> {
    let Some((installed_mtime, installed_len)) = installed else {
        return Some("The service binary is not installed in the system path yet.");
    };
    let skew = Duration::from_secs(2);
    if local_mtime
        .duration_since(installed_mtime)
        .is_ok_and(|delta| delta > skew)
        || (local_len != installed_len && local_mtime >= installed_mtime)
    {
        return Some(
            "The installed service binary is older than this build; reinstall to enable newer features.",
        );
    }
    if let Some(started_at) = now.checked_sub(Duration::from_millis(service_uptime_ms))
        && installed_mtime
            .duration_since(started_at)
            .is_ok_and(|delta| delta > skew)
    {
        return Some(
            "The running service started before the installed binary was updated; restart it to use the new version.",
        );
    }
    None
}

/// Check at startup (once `ServiceInfo` arrives) whether the attached service
/// is older than this GUI build.
pub fn check_service_version(info: &ServiceInfo, attached: Option<&Path>) -> Option<ServiceUpdate> {
    let gui_version = env!("CARGO_PKG_VERSION");
    let mut reason: Option<String> = None;

    if let (Some(service_ver), Some(gui_ver)) =
        (parse_semver(&info.version), parse_semver(gui_version))
        && service_ver < gui_ver
    {
        reason = Some(format!(
            "The running service is v{} while this window is v{gui_version}.",
            info.version
        ));
    } else if info.api < OPERATIONS_VERSION {
        reason = Some(format!(
            "The running service uses local API v{} while this window expects v{OPERATIONS_VERSION}.",
            info.api
        ));
    }

    let defaults = StartRequest::defaults().ok();
    let is_managed_local = defaults
        .as_ref()
        .is_some_and(|req| attached.is_some_and(|socket| socket == req.socket.as_path()));

    #[cfg(target_os = "linux")]
    if reason.is_none()
        && is_managed_local
        && let Some(defaults) = &defaults
        && let Ok(local_meta) = std::fs::metadata(&defaults.program)
        && let Ok(local_mtime) = local_meta.modified()
    {
        let installed = std::fs::metadata(l2tunnel_client_core::local::elevate::LINUX_PROGRAM)
            .ok()
            .and_then(|meta| meta.modified().ok().map(|mtime| (mtime, meta.len())));
        if let Some(text) = binary_outdated(
            local_mtime,
            local_meta.len(),
            installed,
            info.uptime_ms,
            SystemTime::now(),
        ) {
            reason = Some(text.to_owned());
        }
    }

    let reason = reason?;
    let install_request = if is_managed_local {
        #[cfg(not(windows))]
        {
            defaults.map(|mut req| {
                req.install = Some(Vec::new());
                req
            })
        }
        #[cfg(windows)]
        {
            None
        }
    } else {
        None
    };
    Some(ServiceUpdate {
        reason,
        install_request,
    })
}

/// Draw the older-service reminder banner with a one-click install button.
/// Returns `(commands, dismissed)`.
pub fn update_banner(
    ui: &mut egui::Ui,
    model: &mut Model,
    update: &ServiceUpdate,
    dismissible: bool,
) -> (Vec<Command>, bool) {
    let mut commands = Vec::new();
    let mut dismissed = false;
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal_wrapped(|ui| {
            ui.colored_label(ui.visuals().warn_fg_color, format!("⚠ {}", update.reason));
            if let Some(req) = &update.install_request {
                if ui
                    .add_enabled(
                        !model.starting(),
                        egui::Button::new("Install & restart service…"),
                    )
                    .on_hover_text(
                        "Installs this build as the system service (administrator prompt) and \
                         restarts it; active tunnels will briefly disconnect.",
                    )
                    .clicked()
                {
                    commands.extend(model.start_service(req.clone()));
                }
                if model.starting() {
                    ui.spinner();
                    ui.weak("Installing and restarting…");
                }
            } else {
                ui.weak("Update and restart that service to match this window.");
            }
            if dismissible && ui.small_button("Dismiss").clicked() {
                dismissed = true;
            }
        });
    });
    (commands, dismissed)
}

/// Start form state.
#[derive(Debug, Default)]
pub struct StartForm {
    loaded: bool,
    /// Service program (absolute).
    pub program: String,
    /// Install (Linux: reinstall from `program`) before starting.
    pub install: bool,
    /// Windows host option `--profile`.
    pub profile_dir: String,
    /// Windows host option `--wintun-dll`.
    pub wintun_dll: String,
    /// Windows host option `--wintun-sha256`.
    pub wintun_sha256: String,
    /// Windows host option `--address`.
    pub address: String,
    /// Why the defaults could not be found.
    pub note: Option<String>,
}
impl StartForm {
    fn load(&mut self) {
        if self.loaded {
            return;
        }
        self.loaded = true;
        match StartRequest::defaults() {
            Ok(defaults) => self.program = defaults.program.display().to_string(),
            Err(error) => self.note = Some(error.to_string()),
        }
    }
}

/// The start request for this form; `attached` is the service field's
/// socket or pipe, used on Windows (Linux serves a fixed per-user socket).
pub fn request(form: &StartForm, attached: Option<&Path>) -> Result<StartRequest, String> {
    let program = PathBuf::from(form.program.trim());
    if !program.is_absolute() {
        return Err("the service program must be an absolute path".into());
    }
    let mut request = StartRequest::new(program);
    if cfg!(windows) {
        if let Some(pipe) = attached {
            request.socket = pipe.to_path_buf();
        }
        if form.install {
            let fields = [
                ("--profile", &form.profile_dir, "profile directory"),
                ("--wintun-dll", &form.wintun_dll, "Wintun DLL"),
                ("--wintun-sha256", &form.wintun_sha256, "Wintun SHA-256"),
                ("--address", &form.address, "tunnel address"),
            ];
            let mut options = Vec::new();
            for (option, value, name) in fields {
                if value.trim().is_empty() {
                    return Err(format!("enter the {name}"));
                }
                options.extend([option.to_owned(), value.trim().to_owned()]);
            }
            if let Some(pipe) = attached {
                options.extend(["--pipe".to_owned(), pipe.display().to_string()]);
            }
            request.install = Some(options);
        }
    } else if form.install {
        request.install = Some(Vec::new());
    }
    Ok(request)
}

/// Draw the panel; returns the start command when clicked.
pub fn panel(ui: &mut egui::Ui, model: &mut Model, form: &mut StartForm) -> Vec<Command> {
    form.load();
    let mut commands = Vec::new();
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.strong("No service answers");
        if cfg!(windows) {
            ui.label(
                "Start the l2tunnel Windows service. Windows asks for administrator \
                 approval (UAC); this window stays unprivileged.",
            );
        } else {
            ui.label(
                "Start the l2tunnel service. Linux asks for an administrator password \
                 (pkexec). The first start installs a systemd service that runs as you \
                 with only the CAP_NET_ADMIN network permission; this window stays \
                 unprivileged.",
            );
        }
        if let Some(note) = &form.note {
            ui.weak(note.as_str());
        }
        // Only needed to install a different build; most people never open it.
        egui::CollapsingHeader::new("Advanced")
            .id_salt("start-advanced")
            .show(ui, |ui| {
                egui::Grid::new("start-form").num_columns(2).show(ui, |ui| {
                    ui.label("Service program");
                    ui.add(egui::TextEdit::singleline(&mut form.program).desired_width(360.0));
                    ui.end_row();
                });
                if !cfg!(windows) {
                    ui.checkbox(&mut form.install, "Reinstall the service from this program");
                }
            });
        if cfg!(windows) {
            ui.checkbox(&mut form.install, "Install the service first");
            if form.install {
                egui::Grid::new("start-install")
                    .num_columns(2)
                    .show(ui, |ui| {
                        for (label, value, hint) in [
                            (
                                "Profile directory",
                                &mut form.profile_dir,
                                r"C:\l2tunnel\profile",
                            ),
                            (
                                "Wintun DLL",
                                &mut form.wintun_dll,
                                r"C:\l2tunnel\wintun.dll",
                            ),
                            ("Wintun SHA-256", &mut form.wintun_sha256, "64 hex digits"),
                            ("Tunnel address", &mut form.address, "10.81.0.2/24"),
                        ] {
                            ui.label(label);
                            ui.add(
                                egui::TextEdit::singleline(value)
                                    .desired_width(360.0)
                                    .hint_text(hint),
                            );
                            ui.end_row();
                        }
                    });
            }
        }
        ui.horizontal(|ui| {
            let clicked = ui
                .add_enabled(!model.starting(), egui::Button::new("Start service…"))
                .clicked();
            if model.starting() {
                ui.spinner();
                ui.weak("Waiting for the administrator prompt and the service…");
            }
            if clicked {
                match request(form, model.path()) {
                    Ok(request) => commands = model.start_service(request),
                    Err(reason) => model.notice = format!("Service not started: {reason}"),
                }
            }
        });
    });
    commands
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_form_builds_the_shared_start_request() {
        let mut form = StartForm {
            program: "relative".into(),
            ..StartForm::default()
        };
        assert!(request(&form, None).is_err());
        form.program = if cfg!(windows) {
            r"C:\l2tunnel\l2tunnel-windows.exe".into()
        } else {
            "/opt/l2tunnel/l2tunnel-linux".into()
        };
        let plain = request(&form, None);
        assert_eq!(plain.as_ref().map(|plain| plain.install.clone()), Ok(None));
        assert_eq!(
            plain.map(|plain| plain.terminal),
            Ok(false),
            "the GUI never prompts on a terminal"
        );
        form.install = true;
        let install = request(&form, None);
        if cfg!(windows) {
            assert!(install.is_err(), "Windows install needs the host options");
        } else {
            assert_eq!(install.map(|install| install.install), Ok(Some(Vec::new())));
        }
    }

    #[test]
    fn a_start_attaches_to_the_started_service_once() {
        let mut model = Model::default();
        assert!(model.offline());
        let request = StartRequest::new(PathBuf::from("/opt/l2tunnel/l2tunnel-linux"));
        let socket = request.socket.clone();
        let commands = model.start_service(request.clone());
        assert_eq!(
            commands,
            vec![Command::StartService(Box::new(request.clone()))]
        );
        assert!(model.starting());
        assert!(
            model.start_service(request).is_empty(),
            "one start at a time"
        );
        let commands = model.handle(crate::model::Message::Started {
            result: Ok(l2tunnel_client_core::local::elevate::Started {
                socket: socket.clone(),
                already_running: false,
                installed: true,
            }),
        });
        assert!(!model.starting());
        assert_eq!(model.path(), Some(socket.as_path()));
        assert!(
            commands
                .iter()
                .any(|command| matches!(command, Command::Status { .. }))
        );
        assert_eq!(model.notice, "Service installed and started; attached");
        assert_eq!(model.take_started(), Some(socket));
        assert_eq!(model.take_started(), None);
        let _ = model.handle(crate::model::Message::Started {
            result: Err("the administrator prompt was dismissed".into()),
        });
        assert!(model.notice.starts_with("Service not started"));
    }

    #[test]
    fn semver_and_binary_freshness_detect_older_service() {
        assert_eq!(parse_semver("0.1.0"), Some((0, 1, 0)));
        assert_eq!(parse_semver("1.2.3-rc1+build"), Some((1, 2, 3)));
        assert_eq!(parse_semver("bad"), None);

        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let newer = base + Duration::from_secs(60);
        // Local build newer than installed binary -> outdated.
        assert!(binary_outdated(newer, 200, Some((base, 200)), 5_000, newer).is_some());
        // Missing installed binary -> outdated.
        assert!(binary_outdated(newer, 200, None, 5_000, newer).is_some());
        // Running daemon started before installed binary was replaced -> outdated.
        assert!(binary_outdated(newer, 200, Some((newer, 200)), 120_000, newer).is_some());
        // Up-to-date binary and freshly started daemon -> None.
        assert_eq!(
            binary_outdated(
                newer,
                200,
                Some((newer, 200)),
                1_000,
                newer + Duration::from_secs(5)
            ),
            None
        );

        let info = ServiceInfo {
            version: "0.0.1".into(),
            role: l2tunnel_client_core::local::Role::Client,
            api: OPERATIONS_VERSION,
            uptime_ms: 100,
            capabilities: Vec::new(),
        };
        let detected = check_service_version(&info, None);
        assert!(
            detected
                .as_ref()
                .is_some_and(|update| update.reason.contains("v0.0.1"))
        );
    }
}
