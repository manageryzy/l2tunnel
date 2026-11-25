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

/// Draw the panel.
pub fn panel(ui: &mut egui::Ui, model: &mut Model, form: &mut TestForm) -> Vec<Command> {
    let mut commands = Vec::new();
    ui.add_space(12.0);
    ui.heading("Test the tunnel");
    ui.weak(
        "Speed (TCP streaming) and ping run inside l2tunnel on both ends: the two ends agree on an \
         unused private address pair first, and the test packets cross the tunnel with your \
         traffic but never reach the tunnel devices or the host network stack.",
    );
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
                ui.label("Seconds");
                ui.add(egui::DragValue::new(&mut form.seconds).range(1..=30));
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
                ui.label("Every");
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
        ui.weak(reason);
    }
    // The latest test survives page changes; read it once when unknown.
    if model.test().is_none() && available.is_ok() && connected && form.polled.is_none() {
        commands.extend(model.refresh_test());
        form.polled = Some(Instant::now());
    }
    let Some(test) = model.test().cloned() else {
        return commands;
    };
    if test.state == TestPhase::Running {
        if form.polled.is_none_or(|at| at.elapsed() >= POLL) {
            commands.extend(model.refresh_test());
            form.polled = Some(Instant::now());
        }
        ui.ctx().request_repaint_after(POLL);
    }
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_width(ui.available_width().min(760.0));
        ui.horizontal_wrapped(|ui| {
            let tone = match test.state {
                TestPhase::Running => crate::present::Tone::Busy,
                TestPhase::Completed => crate::present::Tone::Good,
                TestPhase::Failed => crate::present::Tone::Bad,
                TestPhase::Cancelled => crate::present::Tone::Idle,
            };
            crate::pages::tone_dot(ui, tone);
            ui.strong(summary(&test));
            if test.state == TestPhase::Running && ui.button("Cancel").clicked() {
                commands.extend(model.cancel_test(test.id));
            }
        });
        if let Some(error) = &test.error {
            ui.colored_label(ui.visuals().error_fg_color, error);
        }
        if let Some(duration) = test.duration_ms
            && test.state == TestPhase::Running
        {
            let done = (test.elapsed_ms as f32 / duration as f32).clamp(0.0, 1.0);
            ui.add(egui::ProgressBar::new(done).desired_width(320.0));
        }
        if test.ping.is_none() && !test.samples.is_empty() {
            let values: Vec<Option<f64>> = test
                .samples
                .iter()
                .map(|value| Some(*value as f64))
                .collect();
            crate::pages::chart(ui, "Rate per second", Rate::SentBits, &values);
        }
        if let Some(ping) = &test.ping
            && !ping.rtts_us.is_empty()
        {
            ui.horizontal_wrapped(|ui| {
                for rtt in &ping.rtts_us {
                    match rtt {
                        Some(us) => ui.monospace(format!("{:.1}", f64::from(*us) / 1e3)),
                        None => ui.colored_label(ui.visuals().warn_fg_color, "lost"),
                    };
                }
                ui.weak("ms");
            });
        }
    });
    commands
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
