use super::*;
use l2tunnel_client_core::local::{EventBatch, OPERATIONS_VERSION};

fn status(phase: &str, operation: Option<u64>, cursor: u64) -> ServiceStatus {
    ServiceStatus {
        phase: phase.into(),
        operation,
        generation: None,
        terminal: None,
        next_request_key: Some(1),
        event_cursor: cursor,
        listening: None,
        observation: None,
        profile: None,
        connected_ms: None,
    }
}
fn reply(code: &str, service: u64) -> OperationReply {
    let mut reply = OperationReply::code(true, code, Some(ServiceId(service)));
    reply.version = OPERATIONS_VERSION;
    reply
}
fn status_reply(
    phase: &str,
    operation: Option<u64>,
    cursor: u64,
    service: u64,
) -> Box<OperationReply> {
    let mut value = reply("ok", service);
    value.status = Some(status(phase, operation, cursor));
    Box::new(value)
}
fn event(sequence: u64, event: EventBody) -> EventState {
    EventState { sequence, event }
}
fn follow_of(commands: &[Command]) -> Option<(u64, u64)> {
    commands.iter().find_map(|command| match command {
        Command::Follow {
            follower, after, ..
        } => Some((*follower, *after)),
        _ => None,
    })
}

#[test]
fn attach_status_follow_act_and_events_flow() {
    let mut model = Model::default();
    assert_eq!(model.view().rows[0], "not attached");
    let commands = model.attach("/run/x/api.sock");
    assert_eq!(commands.len(), 2);
    assert!(matches!(
        commands[1],
        Command::Status {
            attach: 1,
            start_follower: true,
            ..
        }
    ));
    // A duplicate refresh while one is in flight is coalesced.
    assert!(
        model.act(Action::Cancel).is_empty(),
        "nothing to cancel yet"
    );

    let commands = model.handle(Message::Status {
        attach: 1,
        start_follower: true,
        result: Ok(status_reply("disconnected", None, 5, 7)),
    });
    // A first follower replays the recent backlog (cursor 5 -> from 0).
    assert_eq!(follow_of(&commands), Some((1, 0)));
    let view = model.view();
    assert_eq!(
        (view.connect, view.disconnect, view.cancel),
        (true, false, false)
    );

    let commands = model.act(Action::Reconnect);
    assert!(matches!(
        commands.as_slice(),
        [Command::Act {
            action: Action::Reconnect,
            service: Some(ServiceId(7)),
            ..
        }]
    ));
    assert!(
        model.act(Action::Disconnect).is_empty(),
        "one action at a time"
    );
    assert!(!model.view().connect);
    let mut accepted = reply("accepted", 7);
    accepted.operation = Some(OperationState {
        id: 1,
        kind: "connect".into(),
        state: "pending".into(),
        deadline_ms: Some(1),
        cancel_requested: false,
        setup: None,
        result: None,
    });
    let commands = model.handle(Message::Action {
        attach: 1,
        action: Action::Reconnect,
        outcome: ActionOutcome::Reply(Box::new(accepted)),
    });
    assert_eq!(model.notice, "Operation 1 accepted (reconnect)");
    assert!(matches!(
        commands.as_slice(),
        [Command::Status {
            start_follower: false,
            ..
        }]
    ));

    // Events from the current follower are logged; completion asks for details;
    // the refresh is coalesced with the one still in flight.
    let mut page = reply("ok", 7);
    page.events = Some(EventBatch {
        events: vec![
            event(
                6,
                EventBody::OperationProgress {
                    operation: 1,
                    stage: "noise".into(),
                },
            ),
            event(
                7,
                EventBody::OperationCompleted {
                    operation: 1,
                    outcome: "connected".into(),
                },
            ),
        ],
        next: 7,
        gap: false,
    });
    let commands = model.handle(Message::Events {
        attach: 1,
        follower: 1,
        reply: Box::new(page),
    });
    assert!(matches!(
        commands.as_slice(),
        [Command::Show { operation: 1, .. }]
    ));
    assert_eq!(
        model.log.back().map(String::as_str),
        Some("#7 operation 1 completed: connected")
    );
    let commands = model.handle(Message::Status {
        attach: 1,
        start_follower: false,
        result: Ok(status_reply("connected", None, 9, 7)),
    });
    assert!(
        matches!(commands.as_slice(), [Command::Status { .. }]),
        "dirty refresh replays"
    );
    let view = model.view();
    assert_eq!((view.connect_label, view.disconnect), ("Reconnect", true));

    // Stale follower and stale attachment messages are ignored.
    let before = model.log.len();
    let mut stale = reply("ok", 7);
    stale.events = Some(EventBatch {
        events: vec![event(
            9,
            EventBody::OperationAccepted {
                operation: 2,
                kind: "x".into(),
            },
        )],
        next: 9,
        gap: false,
    });
    assert!(
        model
            .handle(Message::Events {
                attach: 1,
                follower: 99,
                reply: Box::new(stale)
            })
            .is_empty()
    );
    assert!(
        model
            .handle(Message::FollowerEnded {
                attach: 0,
                follower: 1,
                reason: "x".into()
            })
            .is_empty()
    );
    assert_eq!(model.log.len(), before);
}

#[test]
fn lost_service_retries_and_restart_restarts_follower() {
    let mut model = Model::default();
    model.attach("/run/x/api.sock");
    let commands = model.handle(Message::Status {
        attach: 1,
        start_follower: true,
        result: Err("No such file or directory".into()),
    });
    assert_eq!(commands, vec![Command::StopFollower]);
    assert!(model.retry);
    assert!(model.notice.starts_with("Service unavailable"));
    assert_eq!(model.view().rows[0], "unavailable");
    let commands = model.resync();
    assert!(!model.retry);
    assert!(matches!(
        commands.as_slice(),
        [Command::Status {
            start_follower: true,
            ..
        }]
    ));
    model.handle(Message::Status {
        attach: 1,
        start_follower: true,
        result: Ok(status_reply("disconnected", None, 1, 7)),
    });
    assert!(model.notice.is_empty());
    let commands = model.handle(Message::FollowerEnded {
        attach: 1,
        follower: 1,
        reason: "service_restarted".into(),
    });
    assert_eq!(commands, vec![Command::StopFollower]);
    assert!(model.retry);
    model.resync();
    // A new service instance always gets a fresh follower over its own backlog.
    let commands = model.handle(Message::Status {
        attach: 1,
        start_follower: false,
        result: Ok(status_reply("disconnected", None, 300, 8)),
    });
    assert_eq!(follow_of(&commands), Some((2, 300 - BACKLOG)));
    // After logging up to 310, a resync of the same instance continues there.
    let mut page = reply("ok", 8);
    page.events = Some(EventBatch {
        events: vec![],
        next: 310,
        gap: false,
    });
    model.handle(Message::Events {
        attach: 1,
        follower: 2,
        reply: Box::new(page),
    });
    model.handle(Message::FollowerEnded {
        attach: 1,
        follower: 2,
        reason: "lost".into(),
    });
    model.resync();
    let commands = model.handle(Message::Status {
        attach: 1,
        start_follower: true,
        result: Ok(status_reply("disconnected", None, 320, 8)),
    });
    assert_eq!(follow_of(&commands), Some((3, 310)));
}

#[test]
fn gap_resynchronizes_and_cancel_targets_the_pending_operation() {
    let mut model = Model::default();
    model.attach("/run/x/api.sock");
    model.handle(Message::Status {
        attach: 1,
        start_follower: true,
        result: Ok(status_reply("authenticating", Some(4), 2, 7)),
    });
    let view = model.view();
    assert_eq!((view.connect, view.cancel), (false, true));
    assert_eq!(view.rows[1], "4");
    let commands = model.act(Action::Cancel);
    assert!(matches!(
        commands.as_slice(),
        [Command::Act {
            operation: Some(4),
            ..
        }]
    ));
    let mut gap = reply("gap", 7);
    gap.status = Some(status("disconnected", None, 300));
    gap.events = Some(EventBatch {
        events: vec![],
        next: 2,
        gap: true,
    });
    model.handle(Message::Events {
        attach: 1,
        follower: 1,
        reply: Box::new(gap),
    });
    assert_eq!(model.view().rows[0], "disconnected");
    for index in 0..LOG_LINES + 5 {
        model.append(format!("line {index}"));
    }
    assert_eq!(model.log.len(), LOG_LINES);
}

#[test]
fn failed_terminal_is_shown_without_inventing_carrier_rows() {
    let mut value = status("failed", None, 1);
    value.terminal = Some(TerminalState::Failed {
        error_kind: "timed_out".into(),
    });
    let rows = status_rows(&value);
    assert_eq!(rows[0], "failed (failed (timed_out))");
    assert!(rows[2..].iter().all(|row| row == "—"));
}

#[test]
fn an_opened_session_list_is_resampled_with_metrics() {
    let mut model = Model::default();
    model.attach("/run/x/api.sock");
    model.handle(Message::Status {
        attach: 1,
        start_follower: true,
        result: Ok(status_reply("connected", None, 1, 7)),
    });
    model.handle(Message::Query {
        attach: 1,
        query: Query::Info,
        result: Ok(info(&[Feature::Sessions])),
    });
    assert!(model.poll_metrics().is_empty(), "the list was never opened");
    assert_eq!(model.refresh_sessions().len(), 1);
    model.handle(Message::Query {
        attach: 1,
        query: Query::Sessions,
        result: Ok(Box::new(reply("ok", 7))),
    });
    assert_eq!(model.sessions().map(<[_]>::len), Some(0));
    let polled = model.poll_metrics();
    assert!(polled.iter().any(|command| matches!(
        command,
        Command::Query {
            query: Query::Sessions,
            ..
        }
    )));
    assert!(
        model.poll_metrics().is_empty(),
        "one session query in flight"
    );
}

fn info(available: &[Feature]) -> Box<OperationReply> {
    use l2tunnel_client_core::local::{Capability, Role, ServiceInfo};
    let mut value = reply("ok", 7);
    value.info = Some(ServiceInfo {
        version: "0.1.0".into(),
        role: Role::Client,
        api: OPERATIONS_VERSION,
        uptime_ms: 5,
        capabilities: [
            Feature::Lifecycle,
            Feature::Metrics,
            Feature::Catalog,
            Feature::Devices,
            Feature::Sessions,
        ]
        .into_iter()
        .map(|feature| {
            if available.contains(&feature) {
                Capability::available(feature)
            } else {
                Capability::unavailable(feature, "nope")
            }
        })
        .collect(),
    });
    Box::new(value)
}
fn metrics_reply(sampled_ms: u64, sent: u64) -> Box<OperationReply> {
    use l2tunnel_client_core::local::{Metrics, WireCounters};
    let mut value = reply("ok", 7);
    value.metrics = Some(Box::new(Metrics {
        generation: 1,
        sampled_ms,
        carrier: "udp".into(),
        runtime_micros: None,
        wire: Some(WireCounters {
            sent_bytes: sent,
            ..WireCounters::default()
        }),
        device: None,
        selected_send_rate: None,
        selected_receive_rate: None,
        send_channels: None,
        receive_channels: None,
        rtt_micros: None,
        lanes: Vec::new(),
        channels: Vec::new(),
        flows: Vec::new(),
        unreported: vec!["rtt".into()],
    }));
    Box::new(value)
}

#[test]
fn status_reads_info_and_metrics_follow_capabilities() {
    use crate::stats::Rate;
    let mut model = Model::default();
    model.attach("/run/x/api.sock");
    let commands = model.handle(Message::Status {
        attach: 1,
        start_follower: true,
        result: Ok(status_reply("connected", None, 1, 7)),
    });
    assert!(commands.contains(&Command::Query {
        attach: 1,
        path: "/run/x/api.sock".into(),
        query: Query::Info,
    }));
    // Before capabilities are known, nothing is polled.
    assert!(model.poll_metrics().is_empty());
    assert!(model.capability(Feature::Devices).is_err());
    model.handle(Message::Query {
        attach: 1,
        query: Query::Info,
        result: Ok(info(&[Feature::Metrics])),
    });
    assert_eq!(model.capability(Feature::Devices), Err("nope".into()));
    assert_eq!(model.capability(Feature::Metrics), Ok(()));
    let first = model.poll_metrics();
    assert_eq!(first.len(), 1);
    assert!(
        model.poll_metrics().is_empty(),
        "one metrics query in flight"
    );
    model.handle(Message::Query {
        attach: 1,
        query: Query::Metrics,
        result: Ok(metrics_reply(1_000, 0)),
    });
    assert_eq!(model.poll_metrics().len(), 1);
    model.handle(Message::Query {
        attach: 1,
        query: Query::Metrics,
        result: Ok(metrics_reply(2_000, 1_000)),
    });
    assert_eq!(model.history().latest(Rate::SentBits), Some(8_000.0));
    // A stale attachment's reply is ignored and a reattach clears history.
    model.handle(Message::Query {
        attach: 0,
        query: Query::Info,
        result: Ok(info(&[])),
    });
    assert_eq!(model.capability(Feature::Metrics), Ok(()));
    model.attach("/run/x/api.sock");
    assert!(model.history().is_empty() && model.info().is_none());
}

#[test]
fn switch_needs_a_target_and_clears_it_on_acceptance() {
    let mut model = Model::default();
    model.attach("/run/x/api.sock");
    model.handle(Message::Status {
        attach: 1,
        start_follower: true,
        result: Ok(status_reply("connected", None, 1, 7)),
    });
    assert!(model.act(Action::Switch).is_empty(), "no target selected");
    // Without a Common observation there is no catalog to page.
    assert!(model.catalog_page(0).is_empty());
    let target = crate::fixture::configuration(1_250_001);
    assert!(target.is_ok(), "fixture configuration must parse");
    if let Ok(target) = target {
        assert_eq!(
            l2tunnel_client_core::local::configuration_summary(&target),
            "swift · ARQ + FEC (1/3 repair) · MTU 1500 · full"
        );
        model.select_target(Some(target.clone()));
        let commands = model.act(Action::Switch);
        assert!(matches!(
            commands.as_slice(),
            [Command::Act {
                action: Action::Switch,
                payload: Some(Payload::Switch(_)),
                ..
            }]
        ));
        let mut accepted = reply("accepted", 7);
        accepted.operation = Some(OperationState {
            id: 2,
            kind: "switch".into(),
            state: "pending".into(),
            deadline_ms: None,
            cancel_requested: false,
            setup: None,
            result: None,
        });
        model.handle(Message::Action {
            attach: 1,
            action: Action::Switch,
            outcome: ActionOutcome::Reply(Box::new(accepted)),
        });
        assert_eq!(model.notice, "Operation 2 accepted (switch)");
        assert!(model.target().is_none());
    }
}

#[test]
fn diagnostic_exports_run_one_at_a_time_and_report_the_file() {
    let mut model = Model::default();
    assert!(
        model.export("/x.json".into(), false).is_empty(),
        "not attached"
    );
    model.attach("/run/l2tunnel/api.sock");
    let commands = model.export("/x.json".into(), true);
    assert!(matches!(
        commands.as_slice(),
        [Command::Export {
            include_addresses: true,
            ..
        }]
    ));
    assert!(
        model.export("/y.json".into(), false).is_empty(),
        "single flight"
    );
    model.handle(Message::Exported {
        result: Ok("/x.json".into()),
    });
    assert!(!model.exporting());
    assert_eq!(model.notice, "Diagnostics written to /x.json");
    assert_eq!(model.export("/y.json".into(), false).len(), 1);
}

#[test]
fn short_catalogs_merge_into_one_list_and_others_replace() {
    let entry = crate::fixture::configuration(1_250_001);
    assert!(entry.is_ok(), "fixture configuration must parse");
    let Ok(entry) = entry else { return };
    let page = |generation, offset, total, next, count| CatalogView {
        generation,
        root: [7; 32],
        offset,
        total,
        next,
        entries: vec![entry.clone(); count],
    };
    let first = merge_catalog(None, page(6, 0, 6, Some(4), 4));
    let both = merge_catalog(Some(first.clone()), page(6, 4, 6, None, 2));
    assert_eq!((both.offset, both.entries.len(), both.next), (0, 6, None));
    // A page of another generation, or out of order, replaces the list.
    let other = merge_catalog(Some(first.clone()), page(7, 4, 6, None, 2));
    assert_eq!(
        (other.generation, other.offset, other.entries.len()),
        (7, 4, 2)
    );
    let gap = merge_catalog(Some(first), page(6, 5, 6, None, 1));
    assert_eq!((gap.offset, gap.entries.len()), (5, 1));
    // Large catalogs stay paged.
    let large = merge_catalog(Some(page(6, 0, 40, Some(4), 4)), page(6, 4, 40, Some(8), 4));
    assert_eq!((large.offset, large.entries.len()), (4, 4));
}

#[test]
fn a_refresh_asked_during_the_same_read_is_sent_when_it_answers() {
    let mut model = Model::default();
    model.attach("/run/x/api.sock");
    let is_devices = |commands: &[Command]| {
        commands.iter().any(|command| {
            matches!(
                command,
                Command::Query {
                    query: Query::Devices,
                    ..
                }
            )
        })
    };
    // A device change started: the first read goes out.
    assert!(is_devices(&model.refresh_devices()));
    // The change completes while that read is in flight: coalesced, not lost.
    assert!(model.refresh_devices().is_empty());
    assert!(model.refresh_devices().is_empty());
    // The early (stale) reply arrives: exactly one fresh read follows.
    let mut stale = reply("ok", 7);
    stale.devices = Some(Vec::new());
    let follow = model.handle(Message::Query {
        attach: 1,
        query: Query::Devices,
        result: Ok(Box::new(stale)),
    });
    assert!(is_devices(&follow), "{follow:?}");
    let fresh = model.handle(Message::Query {
        attach: 1,
        query: Query::Devices,
        result: Ok(Box::new(reply("ok", 7))),
    });
    assert!(!is_devices(&fresh), "nothing left to repeat");
    // A transport error also sends the waiting read.
    assert!(is_devices(&model.refresh_devices()));
    assert!(model.refresh_devices().is_empty());
    let retry = model.handle(Message::Query {
        attach: 1,
        query: Query::Devices,
        result: Err("broken pipe".into()),
    });
    assert!(is_devices(&retry));
}

#[test]
fn historical_backlog_completions_do_not_burst_operation_get_or_hijack_notice() {
    let mut model = Model::default();
    model.attach("/run/x/api.sock");
    let commands = model.handle(Message::Status {
        attach: 1,
        start_follower: true,
        result: Ok(status_reply("connected", None, 20, 7)),
    });
    assert_eq!(follow_of(&commands), Some((1, 0)));
    // Second Status refresh for same ServiceId does not re-query Info once Info is loaded.
    model.handle(Message::Query {
        attach: 1,
        query: Query::Info,
        result: Ok(info(&[Feature::Metrics, Feature::Meters])),
    });
    let mut backlog = reply("ok", 7);
    backlog.events = Some(EventBatch {
        events: vec![
            event(
                10,
                EventBody::OperationCompleted {
                    operation: 4,
                    outcome: "failed".into(),
                },
            ),
            event(
                20,
                EventBody::OperationCompleted {
                    operation: 9,
                    outcome: "connected".into(),
                },
            ),
        ],
        next: 20,
        gap: false,
    });
    let commands = model.handle(Message::Events {
        attach: 1,
        follower: 1,
        reply: Box::new(backlog),
    });
    assert!(
        !commands
            .iter()
            .any(|command| matches!(command, Command::Show { .. })),
        "historical completions should not burst OperationGet: {commands:?}"
    );
    assert!(model.notice.is_empty());
    // Subsequent live completion DOES emit Command::Show.
    let mut live = reply("ok", 7);
    live.events = Some(EventBatch {
        events: vec![event(
            21,
            EventBody::OperationCompleted {
                operation: 10,
                outcome: "committed".into(),
            },
        )],
        next: 21,
        gap: false,
    });
    let commands = model.handle(Message::Events {
        attach: 1,
        follower: 1,
        reply: Box::new(live),
    });
    assert!(
        commands
            .iter()
            .any(|command| matches!(command, Command::Show { operation: 10, .. }))
    );
    // Refresh Status for same ServiceId, phase, and generation with Info already loaded skips Query::Info.
    let status_follow = model.handle(Message::Status {
        attach: 1,
        start_follower: false,
        result: Ok(status_reply("connected", None, 21, 7)),
    });
    assert!(
        !status_follow.iter().any(|command| matches!(
            command,
            Command::Query {
                query: Query::Info,
                ..
            }
        )),
        "static Info should not be re-queried when phase and generation are unchanged"
    );
    // Transitioning phase (e.g., disconnected -> connected) MUST refresh Info so
    // dynamic capabilities like Feature::Tests update immediately.
    let phase_changed = model.handle(Message::Status {
        attach: 1,
        start_follower: false,
        result: Ok(status_reply("disconnected", None, 22, 7)),
    });
    assert!(
        phase_changed.iter().any(|command| matches!(
            command,
            Command::Query {
                query: Query::Info,
                ..
            }
        )),
        "phase transitions must refresh dynamic capabilities in ServiceInfo"
    );
}

#[test]
fn tuning_and_catalog_errors_stop_loading_spin_and_support_retry() {
    let mut model = Model::default();
    model.attach("/run/x/api.sock");
    let mut st = status("connected", None, 1);
    let snapshot = crate::fixture::snapshot(5, [9; 32], Some(1));
    assert!(snapshot.is_ok(), "fixture snapshot must build");
    let Ok(snapshot) = snapshot else { return };
    st.observation = Some(snapshot);
    let mut status_msg = reply("ok", 7);
    status_msg.status = Some(st);
    model.handle(Message::Status {
        attach: 1,
        start_follower: true,
        result: Ok(Box::new(status_msg)),
    });

    // Tuning EOF produces a helpful error instead of staying stuck on Loading.
    assert_eq!(model.refresh_tuning().len(), 1);
    assert!(model.tuning_loading());
    model.handle(Message::Query {
        attach: 1,
        query: Query::Tuning,
        result: Err("unexpected end of file".into()),
    });
    assert!(!model.tuning_loading());
    assert!(
        model
            .tuning_error()
            .is_some_and(|text| text.contains("not supported by this service version"))
    );
    assert!(model.refresh_tuning().is_empty(), "no auto retry storm");
    assert_eq!(model.retry_tuning().len(), 1, "manual retry works");

    // Catalog error stops catalog_stale() from spin-retrying every frame.
    assert!(model.catalog_stale());
    assert_eq!(model.catalog_page(0).len(), 1);
    model.handle(Message::Query {
        attach: 1,
        query: Query::Catalog {
            generation: 5,
            catalog: [9; 32],
            offset: 0,
        },
        result: Err("broken pipe".into()),
    });
    assert!(
        !model.catalog_stale(),
        "error must stop frame-by-frame retry"
    );
    assert_eq!(model.catalog_error(), Some("broken pipe"));
    assert_eq!(model.retry_catalog().len(), 1);
}

#[test]
fn meters_paging_rates_and_action_results_work() {
    use l2tunnel_client_core::local::{MeterEntry, MeterPage, MeterSide};

    let mut model = Model::default();
    model.attach("/run/x/api.sock");
    let cmds = model.refresh_meters(MeterSide::Local, "flow_control".into(), None);
    assert_eq!(cmds.len(), 1);
    assert!(model.meters_loading());
    let mut first = reply("ok", 7);
    first.meters = Some(Box::new(MeterPage {
        side: MeterSide::Local,
        generation: 3,
        sampled_ms: 1_000,
        age_ms: Some(12),
        entries: vec![MeterEntry {
            path: "flow_control.tx.accepted".into(),
            value: 100,
        }],
        next: Some("flow_control.tx.accepted".into()),
    }));
    model.handle(Message::Query {
        attach: 1,
        query: Query::Meters {
            side: MeterSide::Local,
            prefix: "flow_control".into(),
            cursor: None,
        },
        result: Ok(Box::new(first)),
    });
    assert_eq!(model.meters().map(|page| page.entries.len()), Some(1));
    assert_eq!(model.meter_rate("flow_control.tx.accepted", 100), None);

    // Second read 2 seconds later yields per-second rate.
    let _ = model.refresh_meters(MeterSide::Local, "flow_control".into(), None);
    let mut second = reply("ok", 7);
    second.meters = Some(Box::new(MeterPage {
        side: MeterSide::Local,
        generation: 3,
        sampled_ms: 3_000,
        age_ms: Some(5),
        entries: vec![MeterEntry {
            path: "flow_control.tx.accepted".into(),
            value: 150,
        }],
        next: None,
    }));
    model.handle(Message::Query {
        attach: 1,
        query: Query::Meters {
            side: MeterSide::Local,
            prefix: "flow_control".into(),
            cursor: None,
        },
        result: Ok(Box::new(second)),
    });
    assert_eq!(
        model.meter_rate("flow_control.tx.accepted", 150),
        Some(25.0)
    );

    // Action refusal is exposed for modals to stay open and display inline.
    let mut refused = OperationReply::code(false, "invalid_profile", Some(ServiceId(7)));
    refused.version = OPERATIONS_VERSION;
    model.handle(Message::Action {
        attach: 1,
        action: Action::Profile,
        outcome: ActionOutcome::Reply(Box::new(refused)),
    });
    assert!(
        model
            .take_action_result(Action::Profile)
            .is_some_and(|res| res.is_err())
    );
    assert!(model.take_action_result(Action::Profile).is_none());
}
