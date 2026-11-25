//! "Test the tunnel" panel of the Connection page (TT-04,
//! docs/modules/tunnel-tests.md): speed test (TCP streaming) and ping
//! through the tunnel's own path, never the host network stack.
use crate::model::{Command, Model};
use crate::stats::Rate;
use eframe::egui;
use l2tunnel_client_core::local::Feature;
use l2tunnel_client_core::local::tunnel_test::{
    Direction, MAX_PINGS, MAX_STREAMS, TestPhase, TestRequest, TestState, rate_text,
};
use std::time::{Duration, Instant};

/// Why the buttons are disabled when an older service does not list tests.
pub const OLDER_SERVICE: &str = "This service does not offer tunnel tests; update it to a \
     version that includes them (on both ends of the tunnel).";

/// How often a running test is read.
const POLL: Duration = Duration::from_millis(500);

/// Form values of the panel.
#[derive(Debug)]
pub struct TestForm {
    /// Download instead of upload.
    pub download: bool,
    /// Parallel streams.
    pub streams: u8,
    /// Seconds.
    pub seconds: u32,
    /// Ping probes.
    pub count: u16,
    /// Gap between pings in ms.
    pub interval_ms: u32,
    /// Last read of a running test.
    polled: Option<Instant>,
}
impl Default for TestForm {
    fn default() -> Self {
        Self {
            download: false,
            streams: 1,
            seconds: 10,
            count: 10,
            interval_ms: 200,
            polled: None,
        }
    }
}

/// The speed request the form describes.
pub fn speed_request(form: &TestForm) -> TestRequest {
    TestRequest::Speed {
        direction: if form.download {
            Direction::Download
        } else {
            Direction::Upload
        },
        streams: form.streams.clamp(1, MAX_STREAMS),
        duration_ms: form.seconds.clamp(1, 30) * 1000,
    }
}

/// The ping request the form describes.
pub fn ping_request(form: &TestForm) -> TestRequest {
    TestRequest::Ping {
        count: form.count.clamp(1, MAX_PINGS),
        interval_ms: form.interval_ms.clamp(100, 1000),
    }
}

/// Headline of a test, in words.
pub fn summary(test: &TestState) -> String {
    let phase = match test.state {
        TestPhase::Running => "running",
        TestPhase::Completed => "done",
        TestPhase::Failed => "failed",
        TestPhase::Cancelled => "cancelled",
    };
    match &test.ping {
        Some(ping) => {
            let mut text = format!(
                "Ping {phase}: {}/{} replies, {:.0}% loss",
                ping.received,
                ping.sent,
                ping.loss_percent()
            );
            if let (Some(min), Some(avg), Some(max)) = (ping.min_us, ping.avg_us, ping.max_us) {
                text += &format!(
                    ", round trip {:.1} / {:.1} / {:.1} ms (min / avg / max)",
                    f64::from(min) / 1e3,
                    f64::from(avg) / 1e3,
                    f64::from(max) / 1e3
                );
            }
            text
        }
        None => {
            let direction = match test.direction {
                Some(Direction::Download) => "Download",
                _ => "Upload",
            };
            let streams = test.streams.unwrap_or(1);
            format!(
                "{direction} {phase}: {} over {streams} stream{}, {:.1} MB in {:.1} s",
                rate_text(test.bits_per_second),
                if streams == 1 { "" } else { "s" },
                test.bytes as f64 / 1e6,
                test.elapsed_ms as f64 / 1e3
            )
        }
    }
}

/// Draw the redesigned "Test the tunnel" card.
pub fn panel(ui: &mut egui::Ui, model: &mut Model, form: &mut TestForm) -> Vec<Command> {
    let mut commands = Vec::new();
    let available = model.capability(Feature::Tests);
    let connected = model
        .status()
        .is_some_and(|status| status.phase == "connected");
    let running = model
        .test()
        .is_some_and(|test| test.state == TestPhase::Running);
    let reason = match (&available, connected, running) {
        (Err(reason), _, _) if reason.contains("not offered") => Some(OLDER_SERVICE.to_owned()),
        (Err(reason), _, _) => Some(format!("Unavailable: {reason}")),
        (Ok(()), false, _) => Some("Connect first.".to_owned()),
        (Ok(()), true, true) => Some("A test is running.".to_owned()),
        _ => None,
    };
    let ready = reason.is_none();
    let direction_cap_bps = model
        .status()
        .and_then(|s| s.observation.as_ref())
        .and_then(|o| o.common.as_ref())
        .and_then(|c| {
            if form.download {
                c.receive_rate
            } else {
                c.send_rate
            }
        })
        .map(|bytes_per_sec| bytes_per_sec.saturating_mul(8));

    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            ui.heading("Test the tunnel");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if let Some(cap) = direction_cap_bps {
                    let dir = if form.download { "Down" } else { "Up" };
                    let text = format!(
                        "Plan cap ({dir}): {}",
                        crate::stats::rate_text(Rate::SentBits, Some(cap as f64))
                    );
                    if cap <= 20_000_000 {
                        ui.colored_label(ui.visuals().warn_fg_color, text);
                    } else {
                        ui.weak(text);
                    }
                }
            });
        });
        ui.weak(
            "In-process TCP throughput and ICMP ping across the authenticated tunnel (never \
             reaches TUN/TAP devices or the host stack).",
        );
        ui.add_space(6.0);

        egui::Grid::new("tunnel-tests")
            .num_columns(2)
            .spacing([12.0, 6.0])
            .show(ui, |ui| {
                ui.label("Speed test");
                ui.horizontal_wrapped(|ui| {
                    ui.radio_value(&mut form.download, false, "Upload");
                    ui.radio_value(&mut form.download, true, "Download");
                    ui.label("Streams");
                    ui.add(egui::DragValue::new(&mut form.streams).range(1..=MAX_STREAMS));
                    ui.label("Duration");
                    ui.add(
                        egui::DragValue::new(&mut form.seconds)
                            .range(1..=30)
                            .suffix(" s"),
                    );
                    if ui
                        .add_enabled(ready, egui::Button::new("▶ Start speed test"))
                        .clicked()
                    {
                        commands.extend(model.start_test(speed_request(form)));
                        form.polled = Some(Instant::now());
                    }
                });
                ui.end_row();
                ui.label("Ping");
                ui.horizontal_wrapped(|ui| {
                    ui.label("Probes");
                    ui.add(egui::DragValue::new(&mut form.count).range(1..=MAX_PINGS));
                    ui.label("Interval");
                    ui.add(
                        egui::DragValue::new(&mut form.interval_ms)
                            .range(100..=1000)
                            .suffix(" ms"),
                    );
                    if ui
                        .add_enabled(ready, egui::Button::new("▶ Start ping"))
                        .clicked()
                    {
                        commands.extend(model.start_test(ping_request(form)));
                        form.polled = Some(Instant::now());
                    }
                });
                ui.end_row();
            });
        if let Some(reason) = &reason
            && !running
        {
            ui.add_space(2.0);
            ui.weak(reason);
        }

        // The latest test survives page changes; read it once when unknown.
        if model.test().is_none() && available.is_ok() && connected && form.polled.is_none() {
            commands.extend(model.refresh_test());
            form.polled = Some(Instant::now());
        }
        let Some(test) = model.test().cloned() else {
            return;
        };
        if test.state == TestPhase::Running {
            if form.polled.is_none_or(|at| at.elapsed() >= POLL) {
                commands.extend(model.refresh_test());
                form.polled = Some(Instant::now());
            }
            ui.ctx().request_repaint_after(POLL);
        }

        ui.add_space(8.0);
        ui.separator();
        ui.add_space(6.0);

        // Result header: accurate state badge (spinner while running, never warning yellow).
        ui.horizontal(|ui| {
            match test.state {
                TestPhase::Running => {
                    ui.spinner();
                }
                TestPhase::Completed => crate::pages::tone_dot(ui, crate::present::Tone::Good),
                TestPhase::Failed => crate::pages::tone_dot(ui, crate::present::Tone::Bad),
                TestPhase::Cancelled => crate::pages::tone_dot(ui, crate::present::Tone::Idle),
            }
            let title = match &test.ping {
                Some(_) => "Ping".to_owned(),
                None => {
                    let dir = match test.direction {
                        Some(Direction::Download) => "Download",
                        _ => "Upload",
                    };
                    let streams = test.streams.unwrap_or(1);
                    format!(
                        "{dir} · {streams} stream{}",
                        if streams == 1 { "" } else { "s" }
                    )
                }
            };
            ui.strong(title);
            let (badge_text, badge_color) = match test.state {
                TestPhase::Running => ("Measuring…", ui.visuals().selection.bg_fill),
                TestPhase::Completed => ("Completed", egui::Color32::from_rgb(90, 190, 110)),
                TestPhase::Failed => ("Failed", ui.visuals().error_fg_color),
                TestPhase::Cancelled => ("Cancelled", ui.visuals().weak_text_color()),
            };
            ui.colored_label(badge_color, badge_text);
            if test.state == TestPhase::Running {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Cancel").clicked() {
                        commands.extend(model.cancel_test(test.id));
                    }
                });
            }
        });

        if let Some(error) = &test.error {
            ui.add_space(4.0);
            ui.colored_label(ui.visuals().error_fg_color, error);
        }

        if let Some(ping) = &test.ping {
            ui.add_space(6.0);
            let avg_text = ping
                .avg_us
                .map_or_else(|| "—".into(), |us| format!("{:.1} ms", f64::from(us) / 1e3));
            let minmax_text = match (ping.min_us, ping.max_us) {
                (Some(min), Some(max)) => {
                    format!(
                        "{:.1} / {:.1} ms",
                        f64::from(min) / 1e3,
                        f64::from(max) / 1e3
                    )
                }
                _ => "—".into(),
            };
            kpi_strip(
                ui,
                "ping-kpis",
                &[
                    ("Replies", format!("{} / {}", ping.received, ping.sent)),
                    ("Loss", format!("{:.0}%", ping.loss_percent())),
                    ("Average RTT", avg_text),
                    ("Min / Max RTT", minmax_text),
                ],
            );
            if !ping.rtts_us.is_empty() {
                ui.add_space(6.0);
                ui.horizontal_wrapped(|ui| {
                    ui.weak("Probes (ms):");
                    for rtt in &ping.rtts_us {
                        match rtt {
                            Some(us) => ui.monospace(format!("{:.1}", f64::from(*us) / 1e3)),
                            None => ui.colored_label(ui.visuals().warn_fg_color, "lost"),
                        };
                    }
                });
            }
        } else {
            // Speed test KPI strip + full-width progress bar + aligned throughput chart.
            ui.add_space(6.0);
            let last_sample = test.samples.last().copied();
            let peak_sample = test.samples.iter().copied().max();
            let elapsed_s = test.elapsed_ms as f64 / 1e3;
            let total_s = test
                .duration_ms
                .map(|ms| ms as f64 / 1e3)
                .unwrap_or(elapsed_s);
            let transferred = format!(
                "{:.1} MB · {:.1} / {:.0} s",
                test.bytes as f64 / 1e6,
                elapsed_s,
                total_s
            );
            let fmt_bps = |bps: u64| crate::stats::rate_text(Rate::SentBits, Some(bps as f64));
            kpi_strip(
                ui,
                "speed-kpis",
                &[
                    ("Average", fmt_bps(test.bits_per_second)),
                    ("Last 1 s", last_sample.map_or_else(|| "—".into(), fmt_bps)),
                    ("Peak", peak_sample.map_or_else(|| "—".into(), fmt_bps)),
                    ("Transferred", transferred),
                ],
            );
            if let Some(duration) = test.duration_ms
                && test.state == TestPhase::Running
            {
                ui.add_space(6.0);
                let done = (test.elapsed_ms as f32 / duration.max(1) as f32).clamp(0.0, 1.0);
                let bar_text = format!(
                    "{:.0}%  ({:.1} / {:.0} s)",
                    done * 100.0,
                    elapsed_s,
                    f64::from(duration) / 1e3
                );
                ui.add(
                    egui::ProgressBar::new(done)
                        .desired_width(ui.available_width())
                        .text(bar_text),
                );
            }
            if !test.samples.is_empty() {
                ui.add_space(6.0);
                let count = test.samples.len() as u64;
                let total_secs = test
                    .duration_ms
                    .map_or(count, |ms| u64::from(ms / 1000).max(count))
                    .max(1);
                let values: Vec<(f64, Option<f64>)> = test
                    .samples
                    .iter()
                    .enumerate()
                    .map(|(index, value)| ((index + 1) as f64, Some(*value as f64)))
                    .collect();
                crate::pages::chart(
                    ui,
                    "Throughput per second",
                    Rate::SentBits,
                    crate::pages::ChartAxis::Elapsed {
                        total_secs,
                        elapsed_secs: elapsed_s,
                        running: test.state == TestPhase::Running,
                    },
                    &values,
                );
            }
        }
    });
    commands
}

fn kpi_strip(ui: &mut egui::Ui, id: &str, items: &[(&str, String)]) {
    let col_width = (ui.available_width() / items.len().max(1) as f32 - 8.0).max(110.0);
    egui::Grid::new(id)
        .num_columns(items.len())
        .min_col_width(col_width)
        .spacing([8.0, 2.0])
        .show(ui, |ui| {
            for (label, _) in items {
                ui.weak(*label);
            }
            ui.end_row();
            for (_, value) in items {
                ui.strong(value.as_str());
            }
            ui.end_row();
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use l2tunnel_client_core::local::tunnel_test::PingResult;

    #[test]
    fn form_builds_valid_requests_and_summaries_read_as_words() {
        let mut form = TestForm::default();
        assert!(speed_request(&form).validate().is_ok());
        assert!(ping_request(&form).validate().is_ok());
        form.streams = 99;
        form.seconds = 0;
        form.count = 0;
        form.interval_ms = 5;
        assert!(speed_request(&form).validate().is_ok(), "clamped");
        assert!(ping_request(&form).validate().is_ok(), "clamped");
        let mut state = TestState {
            id: 1,
            kind: "speed".into(),
            state: TestPhase::Completed,
            direction: Some(Direction::Download),
            streams: Some(2),
            duration_ms: Some(10_000),
            elapsed_ms: 10_000,
            bytes: 117_750_000,
            bits_per_second: 94_200_000,
            samples: vec![94_000_000],
            ping: None,
            error: None,
        };
        assert_eq!(
            summary(&state),
            "Download done: 94.2 Mbit/s over 2 streams, 117.8 MB in 10.0 s"
        );
        let mut ping = PingResult {
            sent: 4,
            rtts_us: vec![Some(20_000), None, Some(22_000), Some(24_000)],
            ..PingResult::default()
        };
        ping.summarize();
        state.ping = Some(ping);
        state.kind = "ping".into();
        assert_eq!(
            summary(&state),
            "Ping done: 3/4 replies, 25% loss, round trip 20.0 / 22.0 / 24.0 ms (min / avg / max)"
        );
    }
}
