//! Live-tuning controls on the Connection page (docs/modules/live-tuning.md,
//! decisions 1 and 10): FEC on or off, the repair rate, the device MTU and
//! the path MTU of the running session. The service lists what the
//! session's authenticated catalog allows and resolves the chosen setting;
//! this panel never builds catalog entries itself.
use crate::model::{Command, Model};
use eframe::egui;
use l2tunnel_client_core::local::{TuningSetting, TuningView};

/// The setting being edited, before Apply.
#[derive(Clone, Debug, Default)]
pub struct TuneForm {
    /// Chosen setting; `None` shows the current one.
    pub chosen: Option<TuningSetting>,
    /// Last repair rate chosen, restored when FEC is turned back on.
    pub rate: Option<String>,
}

/// Repair rates (every choice except `off`).
fn rates(view: &TuningView) -> Vec<&str> {
    view.repair
        .iter()
        .map(String::as_str)
        .filter(|repair| *repair != "off")
        .collect()
}

/// The rate FEC turns on with: the last chosen, the current one, or the
/// lowest available.
fn fec_rate(view: &TuningView, form: &TuneForm) -> Option<String> {
    let rates = rates(view);
    form.rate
        .as_deref()
        .filter(|rate| rates.contains(rate))
        .or_else(|| {
            view.current
                .as_ref()
                .map(|current| current.repair.as_str())
                .filter(|rate| rates.contains(rate))
        })
        .or_else(|| rates.first().copied())
        .map(str::to_owned)
}

/// Whether the session can switch to `setting`.
pub fn reachable(view: &TuningView, setting: &TuningSetting) -> bool {
    view.entries.contains(setting)
}

fn words(repair: &str) -> String {
    if repair == "off" {
        "off (ARQ only)".to_owned()
    } else {
        format!("{repair} repair per source")
    }
}

/// Draw the panel; returns the exchanges it needs.
pub fn show(
    ui: &mut egui::Ui,
    model: &mut Model,
    form: &mut TuneForm,
    connected: bool,
) -> Vec<Command> {
    let mut commands = model.refresh_tuning();
    ui.add_space(12.0);
    ui.heading("Live tuning");
    ui.weak(
        "FEC, repair rate and packet sizes switch live, like any protocol switch. Both \
         sides lower the device MTU before a switch to smaller packets.",
    );
    let Some(view) = model.tuning().cloned() else {
        if connected {
            ui.weak("Loading the tuning choices…");
        } else {
            ui.weak("Connect first; the choices come from the running session.");
        }
        return commands;
    };
    let Some(current) = view.current.clone() else {
        ui.weak("The protocol in use has no tunable FEC or packet sizes.");
        return commands;
    };
    if view.entries.len() <= 1 {
        ui.weak(
            "Only the setting in use is available. Add switchable choices to the client \
             profile (Live tuning group) and connect again to switch live.",
        );
    }
    if form.chosen.as_ref() == Some(&current) {
        form.chosen = None;
    }
    let mut chosen = form.chosen.clone().unwrap_or_else(|| current.clone());
    let rates = rates(&view);
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_width(ui.available_width().min(760.0));
        egui::Grid::new("tuning-controls")
            .num_columns(2)
            .spacing([16.0, 6.0])
            .show(ui, |ui| {
                ui.label("Forward error correction");
                let mut fec = chosen.repair != "off";
                let can_toggle =
                    view.repair.iter().any(|repair| repair == "off") && !rates.is_empty();
                let toggle = ui.add_enabled(can_toggle, egui::Checkbox::new(&mut fec, "on"));
                if toggle.changed() {
                    chosen.repair = if fec {
                        fec_rate(&view, form).unwrap_or_else(|| "off".to_owned())
                    } else {
                        "off".to_owned()
                    };
                }
                ui.end_row();

                ui.label("Repair rate");
                ui.add_enabled_ui(chosen.repair != "off" && rates.len() > 1, |ui| {
                    egui::ComboBox::from_id_salt("tuning-repair")
                        .selected_text(words(&chosen.repair))
                        .show_ui(ui, |ui| {
                            for rate in &rates {
                                if ui
                                    .selectable_label(chosen.repair == *rate, words(rate))
                                    .clicked()
                                {
                                    chosen.repair = (*rate).to_owned();
                                    form.rate = Some((*rate).to_owned());
                                }
                            }
                        });
                });
                ui.end_row();

                ui.label("Device MTU (inner packets)");
                egui::ComboBox::from_id_salt("tuning-device-mtu")
                    .selected_text(format!("{} bytes", chosen.device_mtu))
                    .show_ui(ui, |ui| {
                        for mtu in &view.device_mtu {
                            ui.selectable_value(
                                &mut chosen.device_mtu,
                                *mtu,
                                format!("{mtu} bytes"),
                            );
                        }
                    });
                ui.end_row();

                ui.label("Path MTU (outer packets)");
                egui::ComboBox::from_id_salt("tuning-path-mtu")
                    .selected_text(format!("{} bytes", chosen.path_mtu))
                    .show_ui(ui, |ui| {
                        for mtu in &view.path_mtu {
                            ui.selectable_value(&mut chosen.path_mtu, *mtu, format!("{mtu} bytes"));
                        }
                    });
                ui.end_row();
            });
        if let Some(device) = &view.device {
            let value =
                |mtu: Option<u32>| mtu.map_or_else(|| "—".to_owned(), |mtu| mtu.to_string());
            let mut line = format!(
                "Device MTU set by the service: {} (protocol needs {})",
                value(device.applied),
                value(device.wanted)
            );
            if device.failures > 0 {
                line.push_str(&format!(
                    "; {} change(s) failed{}",
                    device.failures,
                    device
                        .last_error
                        .as_ref()
                        .map_or_else(String::new, |error| format!(", last: {error}"))
                ));
                ui.colored_label(ui.visuals().warn_fg_color, line);
            } else {
                ui.weak(line);
            }
        }
    });
    let changed = chosen != current;
    form.chosen = changed.then(|| chosen.clone());
    let ok = reachable(&view, &chosen);
    ui.add_space(4.0);
    ui.horizontal_wrapped(|ui| {
        let ready = connected && !model.busy() && changed && ok;
        if ui.add_enabled(ready, egui::Button::new("Apply")).clicked() {
            commands.extend(model.tune(chosen.clone()));
        }
        if changed && ui.button("Reset").clicked() {
            form.chosen = None;
        }
        if !changed {
            ui.weak("In use.");
        } else if !ok {
            ui.colored_label(
                ui.visuals().warn_fg_color,
                "This combination is not in the session's catalog.",
            );
        } else if model.busy() {
            ui.weak("Switching… progress shows in the top bar and Events.");
        }
    });
    commands
}

#[cfg(test)]
mod tests {
    use super::*;
    use l2tunnel::live_tuning::{Repair, Setting};

    fn view() -> TuningView {
        let quarter = Repair::Rate {
            numerator: 1,
            denominator: 4,
        };
        let eighth = Repair::Rate {
            numerator: 1,
            denominator: 8,
        };
        let at = |repair, device_mtu| Setting {
            repair,
            device_mtu,
            path_mtu: 1500,
        };
        TuningView::new(
            true,
            Some(at(quarter, 1400)),
            [
                at(quarter, 1400),
                at(Repair::Off, 1400),
                at(eighth, 1400),
                at(quarter, 1280),
            ],
            None,
        )
    }

    #[test]
    fn fec_turns_back_on_with_the_last_rate_then_the_current_one() {
        let view = view();
        assert_eq!(rates(&view), ["1/8", "1/4"]);
        let mut form = TuneForm::default();
        assert_eq!(fec_rate(&view, &form).as_deref(), Some("1/4"));
        form.rate = Some("1/8".into());
        assert_eq!(fec_rate(&view, &form).as_deref(), Some("1/8"));
        form.rate = Some("1/2".into());
        assert_eq!(fec_rate(&view, &form).as_deref(), Some("1/4"));
    }

    #[test]
    fn only_catalog_combinations_are_reachable() {
        let view = view();
        let setting = |repair: &str, device_mtu| TuningSetting {
            repair: repair.into(),
            device_mtu,
            path_mtu: 1500,
        };
        assert!(reachable(&view, &setting("off", 1400)));
        assert!(reachable(&view, &setting("1/4", 1280)));
        assert!(!reachable(&view, &setting("off", 1280)));
    }
}
