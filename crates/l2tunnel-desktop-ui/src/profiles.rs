//! Stored profiles in the GUI (DGUI-10): the Management section, the profile
//! editor window and the key files a profile names. A profile is the
//! validated run options (owner decision 2026-11-23). The editor gives the
//! common options labels, groups, choices and a file chooser (usability
//! review 2026-11-24); other options stay raw rows. The service refuses
//! unrunnable saves.
use crate::browse::{self, Browser};
use crate::model::{Command, Model};
use crate::profile_fields::{self, FIELDS, GROUPS, Kind};
use eframe::egui;
use l2tunnel_client_core::local::{
    self, Feature, PROFILE_VERSION, ProfileChange, ProfileDocument, ProfileRole,
    validate_profile_name,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Largest importable document (one save request is at most 4096 bytes).
const IMPORT_LIMIT: u64 = 4096;
/// Width of an editor input.
const INPUT_WIDTH: f32 = 360.0;

/// Editor state.
#[derive(Debug, Default)]
pub struct Editor {
    /// Stored name and revision when replacing; `None` creates.
    pub original: Option<(String, u64)>,
    /// Profile name.
    pub name: String,
    /// Server profile (`serve` options).
    pub serve: bool,
    /// Values of the labeled options.
    pub values: BTreeMap<String, String>,
    /// Other options as raw rows.
    pub extra: Vec<(String, String)>,
    /// Waiting for this profile to load (`duplicate` makes a new one).
    pub waiting: Option<(String, bool)>,
}
impl Editor {
    /// A new client profile with the usual fixed choices filled in.
    pub fn template() -> Self {
        Self {
            values: [
                ("--record-profile", "common"),
                ("--carrier", "quic-like"),
                ("--noise-profile", "ik"),
                ("--layer", "tun"),
                ("--duplex", "full"),
            ]
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect(),
            ..Self::default()
        }
    }
    /// Split a stored document into labeled values and other rows.
    pub fn from_document(name: String, document: ProfileDocument) -> Self {
        let mut editor = Self {
            name,
            serve: document.role == ProfileRole::Serve,
            ..Self::default()
        };
        for (key, value) in document.options {
            if profile_fields::find(&key).is_some() {
                editor.values.insert(key, value);
            } else {
                editor.extra.push((key, value));
            }
        }
        editor
    }
    fn value(&self, option: &str) -> Option<String> {
        self.values.get(option).cloned().or_else(|| {
            self.extra
                .iter()
                .find(|(key, _)| key.trim() == option)
                .map(|(_, value)| value.clone())
        })
    }
    /// The document the editor describes, checked like the service does.
    pub fn document(&self) -> Result<ProfileDocument, String> {
        validate_profile_name(self.name.trim()).map_err(str::to_owned)?;
        let mut options = BTreeMap::new();
        for (key, value) in &self.values {
            // Fields of the other role are kept out of the document.
            let shown = profile_fields::find(key).is_none_or(|field| field.shown(self.serve));
            if shown && !value.trim().is_empty() {
                options.insert(key.clone(), value.trim().to_owned());
            }
        }
        for (key, value) in &self.extra {
            let key = key.trim();
            if key.is_empty() && value.trim().is_empty() {
                continue;
            }
            if options
                .insert(key.to_owned(), value.trim().to_owned())
                .is_some()
            {
                return Err(format!("{key} appears twice"));
            }
        }
        let document = ProfileDocument {
            version: PROFILE_VERSION,
            role: if self.serve {
                ProfileRole::Serve
            } else {
                ProfileRole::Connect
            },
            options,
        };
        document.validate().map_err(str::to_owned)?;
        Ok(document)
    }
    /// What to fix before saving (the service still checks the plan).
    pub fn problems(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if let Err(reason) = validate_profile_name(self.name.trim()) {
            problems.push(format!("Name: {reason}"));
        }
        problems.extend(profile_fields::problems(
            self.serve,
            |option| self.value(option),
            |path| Path::new(path).is_file(),
        ));
        if problems.is_empty()
            && let Err(reason) = self.document()
        {
            problems.push(reason);
        }
        problems
    }
}

/// Profile page state kept by the window.
#[derive(Debug, Default)]
pub struct ProfileState {
    /// Open editor.
    pub editor: Option<Editor>,
    /// Open file chooser.
    pub browser: Option<Browser>,
    /// Import/export file path.
    pub file: String,
    /// Profile awaiting a second click to delete.
    pub confirm: Option<String>,
    /// Connect card selection.
    pub choice: String,
    /// Keys section: profile whose key files are shown.
    pub keys_of: String,
    /// Key generation form.
    pub generate: Generate,
}

/// Local key generation form.
#[derive(Debug, Default)]
pub struct Generate {
    /// 0 member identity, 1 Noise pair, 2 shared secret.
    pub kind: u8,
    /// Private (or output) file.
    pub private: String,
    /// Public file.
    pub public: String,
}

/// Read a document file for import.
pub fn read_document(path: &Path) -> Result<ProfileDocument, String> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut text = String::new();
    file.take(IMPORT_LIMIT + 1)
        .read_to_string(&mut text)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if text.len() as u64 > IMPORT_LIMIT {
        return Err(format!(
            "{} is larger than {IMPORT_LIMIT} bytes",
            path.display()
        ));
    }
    let document: ProfileDocument =
        serde_json::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))?;
    document.validate().map_err(str::to_owned)?;
    Ok(document)
}

/// Open the editor on a new profile.
pub fn open_new(state: &mut ProfileState) {
    state.editor = Some(Editor::template());
}

/// Management "Profiles" section: one card per profile.
pub fn section(ui: &mut egui::Ui, model: &mut Model, state: &mut ProfileState) -> Vec<Command> {
    let mut commands = Vec::new();
    if let Err(reason) = model.capability(Feature::Profiles) {
        ui.weak(format!("Unavailable: {reason}"));
        return commands;
    }
    if model.profiles().is_none() {
        commands.extend(model.refresh_profiles());
    }
    let busy = model.busy();
    let running = crate::present::running_profile(model).map(str::to_owned);
    let list = model.profiles().map(<[_]>::to_vec).unwrap_or_default();
    for profile in &list {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                ui.strong(profile.name.as_str());
                ui.weak(match profile.role {
                    Some(ProfileRole::Connect) => "client",
                    Some(ProfileRole::Serve) => "server",
                    None => "unknown role",
                });
                if profile.default {
                    ui.label("· connects when the service starts");
                }
                if running.as_deref() == Some(profile.name.as_str()) {
                    ui.colored_label(egui::Color32::from_rgb(60, 180, 90), "· running");
                }
                ui.weak(format!("· revision {}", profile.revision));
            });
            ui.label(profile.summary.as_str());
            ui.horizontal_wrapped(|ui| {
                ui.add_enabled_ui(!busy, |ui| {
                    if profile.editable {
                        if ui.button("Edit").clicked() {
                            commands.extend(model.load_profile(profile.name.clone()));
                            state.editor = Some(Editor {
                                waiting: Some((profile.name.clone(), false)),
                                ..Editor::default()
                            });
                        }
                        if ui.button("Duplicate").clicked() {
                            commands.extend(model.load_profile(profile.name.clone()));
                            state.editor = Some(Editor {
                                waiting: Some((profile.name.clone(), true)),
                                ..Editor::default()
                            });
                        }
                        if ui
                            .button("Check")
                            .on_hover_text("Ask the service whether this profile can run")
                            .clicked()
                        {
                            commands.extend(model.check_profile(profile.name.clone()));
                        }
                        let label = if profile.default {
                            "Don't connect at start"
                        } else {
                            "Connect at service start"
                        };
                        if ui.button(label).clicked() {
                            commands.extend(model.change_profile(ProfileChange::Default {
                                name: (!profile.default).then(|| profile.name.clone()),
                            }));
                        }
                    }
                    let confirming = state.confirm.as_deref() == Some(profile.name.as_str());
                    let label = if confirming {
                        "Confirm delete"
                    } else {
                        "Delete"
                    };
                    if ui.button(label).clicked() {
                        if confirming {
                            state.confirm = None;
                            commands.extend(model.change_profile(ProfileChange::Delete {
                                name: profile.name.clone(),
                                expected_revision: profile.revision,
                            }));
                        } else {
                            state.confirm = Some(profile.name.clone());
                        }
                    }
                });
            });
        });
    }
    if model.profiles().is_none() {
        ui.weak("Loading…");
    } else if list.is_empty() {
        ui.label("No profiles yet. A profile holds everything needed to connect.");
    }
    ui.horizontal_wrapped(|ui| {
        if ui
            .add_enabled(!busy, egui::Button::new("➕ New profile"))
            .clicked()
        {
            open_new(state);
        }
        ui.separator();
        ui.label("Import from file");
        ui.add(
            egui::TextEdit::singleline(&mut state.file)
                .hint_text("profile.json")
                .desired_width(260.0),
        );
        if ui.button("Browse…").clicked() {
            state.browser = Some(Browser::open("import", &state.file));
        }
        if ui
            .add_enabled(!state.file.trim().is_empty(), egui::Button::new("Import"))
            .clicked()
        {
            import(model, state);
        }
    });
    ui.weak(
        "A profile holds the service's run options; keys stay files the profile names. \
         Saving needs a runnable plan.",
    );
    commands
}

fn import(model: &mut Model, state: &mut ProfileState) {
    let path = PathBuf::from(state.file.trim());
    match read_document(&path) {
        Ok(document) => {
            let name = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .filter(|stem| validate_profile_name(stem).is_ok())
                .unwrap_or("imported")
                .to_owned();
            state.editor = Some(Editor::from_document(name, document));
            model.notice = "Imported into the editor; review and Save.".into();
        }
        Err(reason) => model.notice = format!("Import failed: {reason}"),
    }
}

/// Draw the editor and file chooser windows (any page); returns exchanges.
pub fn windows(ctx: &egui::Context, model: &mut Model, state: &mut ProfileState) -> Vec<Command> {
    let mut commands = Vec::new();
    if let Some((target, path)) = browse::show(ctx, &mut state.browser) {
        let text = path.display().to_string();
        if target == "import" {
            state.file = text;
            import(model, state);
        } else if let Some(editor) = &mut state.editor {
            editor.values.insert(target, text);
        }
    }
    // Fill an editor whose profile has arrived.
    if let Some(editor) = &mut state.editor
        && let Some((name, duplicate)) = editor.waiting.clone()
        && let Some(entry) = model.loaded_profile().filter(|entry| entry.name == name)
    {
        let mut filled = Editor::from_document(entry.name.clone(), entry.document.clone());
        if duplicate {
            filled.name = format!("{}-copy", entry.name);
        } else {
            filled.original = Some((entry.name.clone(), entry.revision));
        }
        *editor = filled;
    }
    let Some(editor) = &mut state.editor else {
        return commands;
    };
    if model.devices().is_none() && model.capability(Feature::Devices).is_ok() {
        commands.extend(model.refresh_devices());
    }
    let title = match (&editor.waiting, &editor.original) {
        (Some((name, _)), _) => format!("Loading {name}…"),
        (None, Some((name, _))) => format!("Edit profile {name}"),
        (None, None) => "New profile".to_owned(),
    };
    let mut open = true;
    let mut close = false;
    egui::Window::new(title)
        .id(egui::Id::new("profile-editor"))
        .open(&mut open)
        .collapsible(false)
        .resizable(true)
        .default_size([900.0, 640.0])
        .show(ctx, |ui| {
            if editor.waiting.is_some() {
                ui.spinner();
                return;
            }
            egui::ScrollArea::vertical()
                .max_height(ctx.content_rect().height() - 180.0)
                .show(ui, |ui| {
                    form(ui, model, editor, &mut state.browser);
                });
            ui.separator();
            close = footer(ui, model, editor, &state.file, &mut commands);
        });
    if !open || close {
        state.editor = None;
        state.browser = None;
    }
    commands
}

fn form(ui: &mut egui::Ui, model: &Model, editor: &mut Editor, browser: &mut Option<Browser>) {
    egui::Grid::new("profile-head")
        .num_columns(2)
        .spacing([12.0, 8.0])
        .show(ui, |ui| {
            ui.label("Name");
            ui.add_enabled(
                editor.original.is_none(),
                egui::TextEdit::singleline(&mut editor.name)
                    .hint_text("office")
                    .desired_width(INPUT_WIDTH),
            );
            ui.end_row();
            ui.label("This computer is the");
            ui.horizontal(|ui| {
                ui.radio_value(&mut editor.serve, false, "client (connects out)");
                ui.radio_value(&mut editor.serve, true, "server (waits for a client)");
            });
            ui.end_row();
        });
    let devices: Vec<String> = model
        .devices()
        .unwrap_or_default()
        .iter()
        .filter(|device| device.layer.is_some())
        .map(|device| device.name.clone())
        .collect();
    for group in GROUPS {
        ui.add_space(10.0);
        ui.strong(group);
        egui::Grid::new(("profile-group", group))
            .num_columns(3)
            .spacing([12.0, 6.0])
            .min_col_width(170.0)
            .show(ui, |ui| {
                for field in FIELDS
                    .iter()
                    .filter(|field| field.group == group && field.shown(editor.serve))
                {
                    let label = field.label(editor.serve);
                    let text = if field.required {
                        format!("{label} *")
                    } else {
                        label.to_owned()
                    };
                    ui.label(text).on_hover_text(field.option);
                    let value = editor.values.entry(field.option.to_owned()).or_default();
                    input(ui, field, value, &devices, browser);
                    ui.weak(field.help);
                    ui.end_row();
                }
            });
    }
    ui.add_space(10.0);
    let header = format!("Other options ({})", editor.extra.len());
    egui::CollapsingHeader::new(header)
        .id_salt("profile-other")
        .show(ui, |ui| {
            ui.weak("Run options without a field above, as --option and value.");
            let mut remove = None;
            for (index, (key, value)) in editor.extra.iter_mut().enumerate() {
                ui.horizontal(|ui| {
                    ui.add_sized(
                        [220.0, 22.0],
                        egui::TextEdit::singleline(key).hint_text("--option"),
                    );
                    ui.add_sized([INPUT_WIDTH, 22.0], egui::TextEdit::singleline(value));
                    if ui.button("Remove").clicked() {
                        remove = Some(index);
                    }
                });
            }
            if let Some(index) = remove {
                editor.extra.remove(index);
            }
            if ui.button("Add option").clicked() {
                editor.extra.push((String::new(), String::new()));
            }
        });
}

fn input(
    ui: &mut egui::Ui,
    field: &profile_fields::Field,
    value: &mut String,
    devices: &[String],
    browser: &mut Option<Browser>,
) {
    match field.kind {
        Kind::Choice(values) => {
            egui::ComboBox::from_id_salt(field.option)
                .width(INPUT_WIDTH - 8.0)
                .selected_text(if value.is_empty() {
                    "choose…"
                } else {
                    value.as_str()
                })
                .show_ui(ui, |ui| {
                    if !field.required {
                        ui.selectable_value(value, String::new(), "(default)");
                    }
                    for choice in values {
                        ui.selectable_value(value, (*choice).to_owned(), *choice);
                    }
                });
        }
        Kind::File => {
            ui.horizontal(|ui| {
                let hover = if value.is_empty() {
                    "no file chosen".to_owned()
                } else {
                    value.clone()
                };
                ui.add_sized(
                    [INPUT_WIDTH + 60.0, 22.0],
                    egui::TextEdit::singleline(value).hint_text("/path/to/file"),
                )
                .on_hover_text(hover);
                if ui.button("Browse…").clicked() {
                    *browser = Some(Browser::open(field.option, value));
                }
                let path = value.trim();
                if !path.is_empty() {
                    if Path::new(path).is_file() {
                        ui.colored_label(egui::Color32::from_rgb(60, 180, 90), "✔")
                            .on_hover_text("file found");
                    } else {
                        ui.colored_label(ui.visuals().error_fg_color, "✘")
                            .on_hover_text("no such file");
                    }
                }
            });
        }
        Kind::Device => {
            ui.horizontal(|ui| {
                ui.add_sized(
                    [INPUT_WIDTH - 110.0, 22.0],
                    egui::TextEdit::singleline(value).hint_text(field.hint),
                );
                egui::ComboBox::from_id_salt("profile-device-pick")
                    .width(90.0)
                    .selected_text("pick")
                    .show_ui(ui, |ui| {
                        if devices.is_empty() {
                            ui.weak("no TUN/TAP devices");
                        }
                        for device in devices {
                            ui.selectable_value(value, device.clone(), device.as_str());
                        }
                    });
            });
        }
        Kind::Address | Kind::Number | Kind::Text => {
            ui.add_sized(
                [INPUT_WIDTH, 22.0],
                egui::TextEdit::singleline(value).hint_text(field.hint),
            );
        }
    }
}

fn footer(
    ui: &mut egui::Ui,
    model: &mut Model,
    editor: &Editor,
    file: &str,
    commands: &mut Vec<Command>,
) -> bool {
    let mut close = false;
    let problems = editor.problems();
    if problems.is_empty() {
        ui.colored_label(
            egui::Color32::from_rgb(60, 180, 90),
            "✔ Ready to save. The service checks the complete plan when you save.",
        );
    } else {
        ui.colored_label(ui.visuals().warn_fg_color, "Fix before saving:");
        for problem in problems.iter().take(6) {
            ui.label(format!("• {problem}"));
        }
        if problems.len() > 6 {
            ui.weak(format!("… and {} more", problems.len() - 6));
        }
    }
    let document = editor.document();
    ui.horizontal(|ui| {
        let ready = problems.is_empty() && document.is_ok() && !model.busy();
        if ui
            .add_enabled(ready, egui::Button::new("💾 Save"))
            .clicked()
            && let Ok(document) = &document
        {
            commands.extend(model.change_profile(ProfileChange::Save {
                name: editor.name.trim().to_owned(),
                document: document.clone(),
                expected_revision: editor.original.as_ref().map(|(_, revision)| *revision),
            }));
            close = true;
        }
        if ui
            .add_enabled(
                document.is_ok() && !file.trim().is_empty(),
                egui::Button::new("Export to file"),
            )
            .on_hover_text("Writes the profile to the import/export file (must not exist)")
            .clicked()
            && let Ok(document) = &document
        {
            let path = PathBuf::from(file.trim());
            model.notice = match serde_json::to_value(document)
                .map_err(std::io::Error::other)
                .and_then(|value| local::diagnostics::write_new(&path, &value))
            {
                Ok(()) => format!("Exported to {}", path.display()),
                Err(error) => format!("Export failed: {}: {error}", path.display()),
            };
        }
        if ui.button("Cancel").clicked() {
            close = true;
        }
    });
    close
}

/// Management "Keys and trusted peers": local generation and the key files a
/// stored profile names (keys stay files; owner decision 2026-11-23).
pub fn keys(ui: &mut egui::Ui, model: &mut Model, state: &mut ProfileState) -> Vec<Command> {
    use l2tunnel_client_core::local::keys::{KeyGeneration, generate};
    let mut commands = Vec::new();
    if let Err(reason) = model.capability(Feature::Keys) {
        ui.weak(format!("Profile key files: {reason}"));
    } else {
        let names: Vec<String> = model
            .profiles()
            .unwrap_or_default()
            .iter()
            .filter(|profile| profile.editable)
            .map(|profile| profile.name.clone())
            .collect();
        if names.is_empty() {
            ui.weak("No stored profiles to inspect.");
        } else {
            if !names.contains(&state.keys_of) {
                state.keys_of = names[0].clone();
            }
            ui.horizontal(|ui| {
                ui.label("Key files of profile");
                egui::ComboBox::from_id_salt("keys-of")
                    .selected_text(state.keys_of.as_str())
                    .show_ui(ui, |ui| {
                        for name in &names {
                            ui.selectable_value(&mut state.keys_of, name.clone(), name.as_str());
                        }
                    });
                if ui.button("Refresh").clicked() {
                    commands.extend(model.profile_keys(state.keys_of.clone()));
                }
            });
            if model.keys().is_none_or(|(name, _)| *name != state.keys_of) {
                commands.extend(model.profile_keys(state.keys_of.clone()));
            }
            key_table(ui, model, &state.keys_of);
        }
    }
    ui.add_space(8.0);
    egui::CollapsingHeader::new("Generate new key files")
        .id_salt("key-generate-section")
        .show(ui, |ui| {
            ui.weak("Created on this computer; no service needed. The files must not exist yet.");
            let form = &mut state.generate;
            ui.horizontal(|ui| {
                ui.radio_value(&mut form.kind, 0, "member identity (client)");
                ui.radio_value(&mut form.kind, 1, "Noise key pair");
                ui.radio_value(&mut form.kind, 2, "shared secret (32 bytes)");
            });
            egui::Grid::new("key-generate")
                .num_columns(2)
                .show(ui, |ui| {
                    ui.label(if form.kind == 2 {
                        "New file"
                    } else {
                        "New private file"
                    });
                    ui.add_sized(
                        [INPUT_WIDTH, 22.0],
                        egui::TextEdit::singleline(&mut form.private)
                            .hint_text("/home/you/.config/l2tunnel/member.der"),
                    );
                    ui.end_row();
                    if form.kind != 2 {
                        ui.label("New public file");
                        ui.add_sized(
                            [INPUT_WIDTH, 22.0],
                            egui::TextEdit::singleline(&mut form.public)
                                .hint_text("/home/you/.config/l2tunnel/member.pub"),
                        );
                        ui.end_row();
                    }
                });
            let private = form.private.trim();
            let public = form.public.trim();
            let ready = !private.is_empty() && (form.kind == 2 || !public.is_empty());
            if ui
                .add_enabled(ready, egui::Button::new("Generate"))
                .clicked()
            {
                let request = match form.kind {
                    0 => KeyGeneration::Member {
                        private: PathBuf::from(private),
                        public: PathBuf::from(public),
                    },
                    1 => KeyGeneration::Noise {
                        private: PathBuf::from(private),
                        public: PathBuf::from(public),
                    },
                    _ => KeyGeneration::Secret {
                        output: PathBuf::from(private),
                    },
                };
                model.notice = match generate(&request) {
                    Ok(Some(key)) => format!("Generated; public key {key}"),
                    Ok(None) => format!("Wrote 32 random bytes to {private}"),
                    Err(error) => format!("Key generation failed: {error}"),
                };
            }
        });
    commands
}

/// Shortened key text; the full value is on hover and copied on click.
fn short(text: &str) -> String {
    if text.chars().count() > 20 {
        format!("{}…", text.chars().take(16).collect::<String>())
    } else {
        text.to_owned()
    }
}

fn key_table(ui: &mut egui::Ui, model: &mut Model, keys_of: &str) {
    let Some((name, keys)) = model.keys().filter(|(name, _)| name == keys_of).cloned() else {
        ui.weak("Loading…");
        return;
    };
    let mut copied = None;
    egui::Grid::new("profile-keys")
        .striped(true)
        .num_columns(4)
        .spacing([12.0, 4.0])
        .show(ui, |ui| {
            for title in ["key", "file", "state", "public key / certificate SHA-256"] {
                ui.strong(title);
            }
            ui.end_row();
            for key in &keys {
                let label = profile_fields::find(&key.option)
                    .map_or(key.option.as_str(), |field| field.label);
                ui.label(label)
                    .on_hover_text(format!("{} — {}", key.option, key.role.text()));
                let file = Path::new(&key.path).file_name().map_or_else(
                    || key.path.clone(),
                    |name| name.to_string_lossy().into_owned(),
                );
                ui.label(file).on_hover_text(key.path.as_str());
                if key.usable {
                    ui.colored_label(egui::Color32::from_rgb(60, 180, 90), "usable");
                } else {
                    ui.colored_label(ui.visuals().error_fg_color, "unusable")
                        .on_hover_text(key.reason.as_deref().unwrap_or_default());
                }
                match &key.public {
                    Some(public) => {
                        let response = ui
                            .add(
                                egui::Label::new(egui::RichText::new(short(public)).monospace())
                                    .sense(egui::Sense::click()),
                            )
                            .on_hover_text(format!("{public}\nclick to copy"));
                        if response.clicked() {
                            copied = Some(public.clone());
                        }
                    }
                    None => {
                        ui.weak("—");
                    }
                }
                ui.end_row();
            }
        });
    if let Some(public) = copied {
        ui.ctx().copy_text(public);
        model.notice = "Public key copied".into();
    }
    if keys.is_empty() {
        ui.weak(format!("{name} names no key files."));
    }
    ui.weak("Trusted peers are the public keys a profile pins (trusted member, peer Noise key).");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn editor_documents_are_checked_like_the_service() {
        let mut editor = Editor::template();
        editor.name = "office".into();
        assert!(
            editor
                .problems()
                .iter()
                .any(|problem| problem == "Server address is required"),
            "the template names what is missing"
        );
        editor.values.clear();
        editor
            .values
            .insert("--carrier".into(), " quic-like ".into());
        editor.values.insert("--device".into(), String::new());
        editor.extra = vec![(String::new(), String::new())];
        let document = editor.document();
        assert_eq!(
            document.map(|document| document.options.into_iter().collect::<Vec<_>>()),
            Ok(vec![("--carrier".to_owned(), "quic-like".to_owned())])
        );
        editor.extra.push(("--carrier".into(), "tcp".into()));
        assert!(
            editor
                .document()
                .is_err_and(|reason| reason.contains("twice"))
        );
        editor.extra = vec![("--state-dir".into(), "/x".into())];
        assert!(editor.document().is_err());
        editor.extra.clear();
        editor.name = "bad name".into();
        assert!(editor.document().is_err());
    }

    #[test]
    fn documents_split_into_labeled_values_and_other_rows() {
        let mut options = BTreeMap::new();
        options.insert("--carrier".to_owned(), "quic-like".to_owned());
        options.insert("--identity".to_owned(), "/k/member.der".to_owned());
        options.insert("--traffic".to_owned(), "mixed".to_owned());
        let document = ProfileDocument {
            version: PROFILE_VERSION,
            role: ProfileRole::Connect,
            options,
        };
        let mut editor = Editor::from_document("office".into(), document);
        assert_eq!(editor.values.len(), 2);
        assert_eq!(
            editor.extra,
            vec![("--traffic".to_owned(), "mixed".to_owned())]
        );
        // A client-only field is left out of a server document.
        editor.serve = true;
        let options = editor.document().map(|document| document.options);
        assert!(options.is_ok_and(|options| !options.contains_key("--identity")));
        assert_eq!(short("0123456789abcdef0123456789"), "0123456789abcdef…");
        assert_eq!(short("abc"), "abc");
    }
}
