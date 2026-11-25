//! A small file chooser drawn with egui (usability review 2026-11-24). The
//! maintained egui file-dialog crates need a newer egui than the pinned 0.35,
//! and native dialogs would pull desktop-portal or GTK dependencies. It only
//! lists directories; it never reads, creates or changes files.
use eframe::egui;
use std::path::{Path, PathBuf};

/// Directory entries shown at most (large directories are cut).
const ENTRY_LIMIT: usize = 2000;

/// An open chooser for one form field.
#[derive(Debug)]
pub struct Browser {
    /// Field the chosen path belongs to.
    pub target: String,
    directory: PathBuf,
    entries: Vec<(String, bool)>,
    hidden: bool,
    error: Option<String>,
    typed: String,
}
impl Browser {
    /// Open at the directory of `current`, else the home directory.
    pub fn open(target: impl Into<String>, current: &str) -> Self {
        let current = PathBuf::from(current.trim());
        let directory = current
            .parent()
            .filter(|parent| current.is_absolute() && parent.is_dir())
            .map(Path::to_path_buf)
            .or_else(home)
            .unwrap_or_else(|| PathBuf::from("/"));
        let mut browser = Self {
            target: target.into(),
            directory,
            entries: Vec::new(),
            hidden: false,
            error: None,
            typed: String::new(),
        };
        browser.read();
        browser
    }
    fn read(&mut self) {
        self.entries.clear();
        self.error = None;
        self.typed = self.directory.display().to_string();
        match std::fs::read_dir(&self.directory) {
            Ok(entries) => {
                for entry in entries.flatten().take(ENTRY_LIMIT) {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if !self.hidden && name.starts_with('.') {
                        continue;
                    }
                    // Follow symlinks to tell directories from files.
                    let directory = entry.path().is_dir();
                    self.entries.push((name, directory));
                }
                self.entries
                    .sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            }
            Err(error) => self.error = Some(error.to_string()),
        }
    }
    fn enter(&mut self, directory: PathBuf) {
        self.directory = directory;
        self.read();
    }
}

fn home() -> Option<PathBuf> {
    std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .map(PathBuf::from)
        .filter(|home| home.is_dir())
}

/// Draw the chooser; returns `(target, path)` once a file is chosen. Closes
/// itself on choice or cancel.
pub fn show(ctx: &egui::Context, open: &mut Option<Browser>) -> Option<(String, PathBuf)> {
    let browser = open.as_mut()?;
    let mut chosen = None;
    let mut close = false;
    egui::Window::new("Choose a file")
        .id(egui::Id::new("file-chooser"))
        .collapsible(false)
        .resizable(true)
        .default_size([560.0, 460.0])
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("⬆ Up").clicked()
                    && let Some(parent) = browser.directory.parent().map(Path::to_path_buf)
                {
                    browser.enter(parent);
                }
                if ui.button("Home").clicked()
                    && let Some(home) = home()
                {
                    browser.enter(home);
                }
                if ui.checkbox(&mut browser.hidden, "Show hidden").changed() {
                    browser.read();
                }
            });
            ui.horizontal(|ui| {
                ui.label("Folder");
                let edit = ui.add_sized(
                    [ui.available_width(), 22.0],
                    egui::TextEdit::singleline(&mut browser.typed),
                );
                if edit.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter)) {
                    let typed = PathBuf::from(browser.typed.trim());
                    if typed.is_dir() {
                        browser.enter(typed);
                    } else if typed.is_file() {
                        chosen = Some((browser.target.clone(), typed));
                    }
                }
            });
            if let Some(error) = &browser.error {
                ui.colored_label(ui.visuals().error_fg_color, error.as_str());
            }
            ui.separator();
            let mut enter = None;
            egui::ScrollArea::vertical()
                .max_height(320.0)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for (name, directory) in &browser.entries {
                        let label = if *directory {
                            format!("📁 {name}")
                        } else {
                            format!("    {name}")
                        };
                        if ui.selectable_label(false, label).clicked() {
                            let path = browser.directory.join(name);
                            if *directory {
                                enter = Some(path);
                            } else {
                                chosen = Some((browser.target.clone(), path));
                            }
                        }
                    }
                    if browser.entries.is_empty() && browser.error.is_none() {
                        ui.weak("Empty folder.");
                    }
                });
            if let Some(directory) = enter {
                browser.enter(directory);
            }
            ui.separator();
            ui.horizontal(|ui| {
                ui.weak("Click a file to choose it.");
                if ui.button("Cancel").clicked() {
                    close = true;
                }
            });
        });
    if chosen.is_some() || close {
        *open = None;
    }
    chosen
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_chooser_lists_directories_first_and_hides_dotfiles() {
        let root = std::env::temp_dir().join(format!("l2t-browse-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for directory in ["b-dir", ".hidden-dir"] {
            let _ = std::fs::create_dir_all(root.join(directory));
        }
        for file in ["a.key", ".secret"] {
            let _ = std::fs::write(root.join(file), b"x");
        }
        let browser = Browser::open("--identity", &root.join("a.key").display().to_string());
        assert_eq!(browser.directory, root);
        assert_eq!(
            browser.entries,
            vec![("b-dir".to_owned(), true), ("a.key".to_owned(), false)]
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
