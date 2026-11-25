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
    /// Staged upload speed budget (Mbit/s); `None` follows the live session.
    pub upload_mbps: Option<u32>,
    /// Staged download speed budget (Mbit/s); `None` follows the live session.
    pub download_mbps: Option<u32>,
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

/// Draw the quick live-tuning section inside the Connection page's Protocol &
/// Live tuning card; returns the exchanges it needs.
pub fn show(
    ui: &mut egui::Ui,
    model: &mut Model,
    form: &mut TuneForm,
    connected: bool,
) -> Vec<Command> {
    let mut commands = model.refresh_tuning();
    ui.add_space(4.0);
    let Some(view) = model.tuning().cloned() else {
        if !connected {
            ui.weak("Connect first; tuning choices come from the running session.");
        } else if let Some(error) = model.tuning_error().map(str::to_owned) {
            ui.horizontal_wrapped(|ui| {
                ui.colored_label(
                    ui.visuals().warn_fg_color,
                    format!("Live tuning is unavailable: {error}"),
                );
                if ui.button("Retry").clicked() {
                    commands.extend(model.retry_tuning());
                }
            });
        } else if model.tuning_loading() {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.weak("Loading live tuning choices…");
            });
        } else {
            ui.horizontal_wrapped(|ui| {
                ui.weak("Live tuning choices not loaded.");
                if ui.button("Retry").clicked() {
                    commands.extend(model.retry_tuning());
                }
            });
        }
        commands.extend(speed_budget(ui, model, form, connected));
        return commands;
    };
    let Some(current) = view.current.clone() else {
        ui.weak("The active protocol has no tunable FEC or packet-size controls.");
        commands.extend(speed_budget(ui, model, form, connected));
        return commands;
    };
    if form.chosen.as_ref() == Some(&current) {
        form.chosen = None;
    }
    let mut chosen = form.chosen.clone().unwrap_or_else(|| current.clone());
    let rates = rates(&view);
    let mut edited = false;

    egui::Grid::new("tuning-controls")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.label("Forward error correction");
            let mut fec = chosen.repair != "off";
            let can_toggle = view.repair.iter().any(|repair| repair == "off") && !rates.is_empty();
            ui.horizontal_wrapped(|ui| {
                if can_toggle {
                    let fec_label = if fec { "Enabled" } else { "Off (ARQ only)" };
                    let toggle = ui.checkbox(&mut fec, fec_label);
                    if toggle.changed() {
                        edited = true;
                        chosen.repair = if fec {
                            fec_rate(&view, form).unwrap_or_else(|| "off".to_owned())
                        } else {
                            "off".to_owned()
                        };
                    }
                    if fec {
                        if rates.len() > 1 {
                            egui::ComboBox::from_id_salt("tuning-repair")
                                .selected_text(words(&chosen.repair))
                                .show_ui(ui, |ui| {
                                    for rate in &rates {
                                        if ui
                                            .selectable_label(chosen.repair == *rate, words(rate))
                                            .clicked()
                                        {
                                            edited = true;
                                            chosen.repair = (*rate).to_owned();
                                            form.rate = Some((*rate).to_owned());
                                        }
                                    }
                                });
                        } else {
                            ui.weak(format!("· {}", words(&chosen.repair)));
                        }
                    }
                } else {
                    ui.label(words(&chosen.repair));
                    ui.weak("(fixed by plan)");
                }
            });
            ui.end_row();

            ui.label("Device MTU (inner)");
            if view.device_mtu.len() > 1 {
                egui::ComboBox::from_id_salt("tuning-device-mtu")
                    .selected_text(format!("{} bytes", chosen.device_mtu))
                    .show_ui(ui, |ui| {
                        for mtu in &view.device_mtu {
                            if ui
                                .selectable_value(
                                    &mut chosen.device_mtu,
                                    *mtu,
                                    format!("{mtu} bytes"),
                                )
                                .changed()
                            {
                                edited = true;
                            }
                        }
                    });
            } else {
                ui.horizontal(|ui| {
                    ui.label(format!("{} bytes", chosen.device_mtu));
                    ui.weak("(fixed by plan)");
                });
            }
            ui.end_row();

            ui.label("Path MTU (outer)");
            if view.path_mtu.len() > 1 {
                egui::ComboBox::from_id_salt("tuning-path-mtu")
                    .selected_text(format!("{} bytes", chosen.path_mtu))
                    .show_ui(ui, |ui| {
                        for mtu in &view.path_mtu {
                            if ui
                                .selectable_value(
                                    &mut chosen.path_mtu,
                                    *mtu,
                                    format!("{mtu} bytes"),
                                )
                                .changed()
                            {
                                edited = true;
                            }
                        }
                    });
            } else {
                ui.horizontal(|ui| {
                    ui.label(format!("{} bytes", chosen.path_mtu));
                    ui.weak("(fixed by plan)");
                });
            }
            ui.end_row();
        });

    if let Some(device) = &view.device {
        let value = |mtu: Option<u32>| mtu.map_or_else(|| "—".to_owned(), |mtu| mtu.to_string());
        let mut line = format!(
            "Device MTU set by service: {} (protocol needs {})",
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

    if edited {
        // Clear any separate protocol-list radio selection so both controls stay consistent.
        model.select_target(None);
    }
    let changed = chosen != current;
    form.chosen = changed.then(|| chosen.clone());
    let ok = reachable(&view, &chosen);
    if view.entries.len() > 1 {
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            let ready = connected && !model.busy() && changed && ok;
            if ui
                .add_enabled(ready, egui::Button::new("Apply tuning"))
                .clicked()
            {
                commands.extend(model.tune(chosen.clone()));
            }
            if changed && ui.button("Reset").clicked() {
                form.chosen = None;
            }
            if !changed {
                ui.colored_label(egui::Color32::from_rgb(90, 190, 110), "Active");
            } else if !ok {
                ui.colored_label(
                    ui.visuals().warn_fg_color,
                    "This combination is not in the session's catalog.",
                );
            } else if model.busy() {
                ui.spinner();
                ui.weak("Applying tuning…");
            } else {
                ui.colored_label(ui.visuals().selection.bg_fill, "Pending change");
            }
        });
    }
    commands.extend(speed_budget(ui, model, form, connected));
    commands
}

/// Interactive live speed-budget controls (Upload & Download wire caps in Mbit/s),
/// applied to both peers over the authenticated control channel.
fn speed_budget(
    ui: &mut egui::Ui,
    model: &mut Model,
    form: &mut TuneForm,
    connected: bool,
) -> Vec<Command> {
    let mut commands = Vec::new();
    let Some(common) = model
        .status()
        .and_then(|s| s.observation.as_ref())
        .and_then(|o| o.common.as_ref())
    else {
        return commands;
    };
    let (Some(cur_send_bps), Some(cur_recv_bps)) = (common.send_rate, common.receive_rate) else {
        return commands;
    };
    let to_mbps = |bytes_per_sec: u64| -> u32 {
        let mbps = bytes_per_sec.saturating_mul(8).saturating_add(500_000) / 1_000_000;
        u32::try_from(mbps).unwrap_or(10_000).clamp(1, 10_000)
    };
    let cur_up = to_mbps(cur_send_bps);
    let cur_down = to_mbps(cur_recv_bps);
    if form.upload_mbps == Some(cur_up) {
        form.upload_mbps = None;
    }
    if form.download_mbps == Some(cur_down) {
        form.download_mbps = None;
    }
    let mut up = form.upload_mbps.unwrap_or(cur_up);
    let mut down = form.download_mbps.unwrap_or(cur_down);

    ui.add_space(6.0);
    ui.separator();
    ui.add_space(4.0);
    ui.strong("Speed budget");
    egui::Grid::new("tuning-speed-budget")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.label("Upload / Download cap");
            ui.horizontal_wrapped(|ui| {
                ui.label("Up");
                ui.add(
                    egui::DragValue::new(&mut up)
                        .range(1..=10_000)
                        .speed(5.0)
                        .suffix(" Mb/s"),
                );
                ui.label("Down");
                ui.add(
                    egui::DragValue::new(&mut down)
                        .range(1..=10_000)
                        .speed(5.0)
                        .suffix(" Mb/s"),
                );
            });
            ui.end_row();

            ui.label("Presets");
            ui.horizontal_wrapped(|ui| {
                for (label, u, d) in [
                    ("100/10", 100_u32, 10_u32),
                    ("200/20", 200, 20),
                    ("300/30", 300, 30),
                    ("500/50", 500, 50),
                    ("1000/100", 1_000, 100),
                    ("500 sym", 500, 500),
                    ("1 Gb/s sym", 1_000, 1_000),
                ] {
                    if ui.small_button(label).clicked() {
                        up = u;
                        down = d;
                    }
                }
            });
            ui.end_row();
        });

    form.upload_mbps = (up != cur_up).then_some(up);
    form.download_mbps = (down != cur_down).then_some(down);
    let dirty = form.upload_mbps.is_some() || form.download_mbps.is_some();
    let busy = model.rate_budget_busy();

    ui.add_space(4.0);
    ui.horizontal_wrapped(|ui| {
        let ready = connected && dirty && !busy;
        if ui
            .add_enabled(ready, egui::Button::new("Apply budget"))
            .clicked()
        {
            let send_rate = u64::from(up).saturating_mul(125_000);
            let receive_rate = u64::from(down).saturating_mul(125_000);
            commands.extend(model.set_rate_budget(send_rate, receive_rate));
        }
        if dirty && !busy && ui.button("Reset").clicked() {
            form.upload_mbps = None;
            form.download_mbps = None;
        }
        if busy {
            ui.spinner();
            ui.weak("Updating both peers…");
        } else if !dirty {
            ui.colored_label(egui::Color32::from_rgb(90, 190, 110), "Active");
        } else {
            ui.colored_label(ui.visuals().selection.bg_fill, "Pending change");
        }
    });
    if let Some(error) = model.rate_budget_error() {
        ui.colored_label(
            ui.visuals().warn_fg_color,
            format!("Speed budget update failed: {error}"),
        );
    }
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
