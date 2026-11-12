use super::*;
use crate::{Millis, Role, TcpEngine, TcpIpConfig, TimeWaitResetPolicy};
use std::net::SocketAddr;
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn table_config(limit: usize, role: session::Role) -> session::Config {
    session::Config {
        session: [41; 16],
        epoch: 3,
        role,
        max_flows: limit,
        max_policies: 128,
        native: TcpIpConfig {
            local: SocketAddr::from(([10, 33, 0, 1], 32000)),
            peer: SocketAddr::from(([10, 33, 0, 2], 443)),
            mtu: 1280,
            send_bytes: 4096,
            receive_bytes: 4096,
            packet_slots: 8,
            random_seed: 9,
            ack_delay_millis: 0,
            keepalive_millis: 1000,
            idle_timeout_millis: 30000,
        },
        max_record_bytes: 256,
        maximum: Window {
            bytes: 4096,
            records: 16,
        },
        initial: Window {
            bytes: 512,
            records: 2,
        },
        admission_timeout_ms: 3000,
        time_wait_reset_policy: TimeWaitResetPolicy::Maintained,
    }
}
fn config(table: &session::Table) -> Config {
    let n = table.policy().max_flows as u64;
    let cap = Credit {
        bytes: (n * 512).max(8192),
        records: (n * 2).max(32),
    };
    Config {
        target: TargetConfig {
            initial: Credit {
                bytes: 4096,
                records: 16,
            },
            minimum: Credit {
                bytes: 256,
                records: 1,
            },
            session_cap: cap,
            policy_cap: cap,
            per_flow_cap: Credit {
                bytes: 4096,
                records: 16,
            },
            queue_allowance_bytes: 8192,
            queue_delay_target_micros: 5000,
            many_flow_step: Credit {
                bytes: 256,
                records: 1,
            },
            few_flow_threshold: 4,
            max_flows: table.policy().max_flows,
            bootstrap_rtt_micros: 1000,
            recovery_rtts: 2,
        },
        minimum_per_flow: Window {
            bytes: 256,
            records: 1,
        },
    }
}
fn exchange(a: &mut session::Table, b: &mut session::Table, now: Millis) -> TestResult {
    for id in 1..=a.status().flows as u64 {
        if let Some(bytes) = a.pending_record(id).map(<[u8]>::to_vec) {
            a.confirm_record_sent(id, now)?;
            b.receive_authenticated(&bytes, true, now)?;
        }
    }
    Ok(())
}
struct Lab {
    a: session::Table,
    b: session::Table,
    hosts: Vec<[TcpEngine; 2]>,
    now: u64,
}
impl Lab {
    fn new(count: usize, limit: usize) -> Result<Self, Box<dyn std::error::Error>> {
        let mut a = session::Table::new(table_config(limit, session::Role::Originator), Millis(0))?;
        let mut b = session::Table::new(table_config(limit, session::Role::Acceptor), Millis(0))?;
        let mut hosts = Vec::new();
        for index in 0..count {
            let mut cfg = a.policy().native;
            cfg.local.set_port(32000 + u16::try_from(index)?);
            cfg.random_seed = 51 + index as u64;
            let mut client = TcpEngine::new_ip(cfg, Role::Client, Millis(0))?;
            std::mem::swap(&mut cfg.local, &mut cfg.peer);
            cfg.random_seed += 100;
            let server = TcpEngine::new_ip(cfg, Role::Server, Millis(0))?;
            client.poll(Millis(0), 4)?;
            let syn = client.pop_packet().ok_or("SYN")?;
            assert_eq!(
                a.ingest_native(&syn, true, Millis(0))?,
                session::Disposition::Owned(index as u64 + 1)
            );
            hosts.push([client, server]);
        }
        exchange(&mut a, &mut b, Millis(1))?;
        exchange(&mut b, &mut a, Millis(2))?;
        exchange(&mut a, &mut b, Millis(3))?;
        Ok(Self {
            a,
            b,
            hosts,
            now: 3,
        })
    }
    fn step(&mut self) -> TestResult {
        self.now += 1;
        let now = Millis(self.now);
        for (index, pair) in self.hosts.iter_mut().enumerate() {
            for (side, host) in pair.iter_mut().enumerate() {
                host.poll(now, 8)?;
                let table = if side == 0 { &mut self.a } else { &mut self.b };
                while let Some(bytes) = host.pop_packet() {
                    assert_eq!(
                        table.ingest_native(&bytes, false, now)?,
                        session::Disposition::Owned(index as u64 + 1)
                    );
                }
            }
        }
        self.a.poll(now, 64, 8)?;
        self.b.poll(now, 64, 8)?;
        for (index, pair) in self.hosts.iter_mut().enumerate() {
            for (side, host) in pair.iter_mut().enumerate() {
                let table = if side == 0 { &mut self.a } else { &mut self.b };
                if let Some(bytes) = table.pending_native(index as u64 + 1).map(<[u8]>::to_vec) {
                    host.ingest(&bytes)?;
                    table.confirm_native_written(index as u64 + 1)?;
                }
            }
        }
        exchange(&mut self.a, &mut self.b, now)?;
        exchange(&mut self.b, &mut self.a, now)?;
        Ok(())
    }
    fn establish(&mut self) -> TestResult {
        for _ in 0..100 {
            self.step()?;
            if self
                .hosts
                .iter()
                .flatten()
                .all(|host| host.status().established)
                && (1..=self.hosts.len() as u64).all(|id| {
                    self.a
                        .credit_status(id)
                        .is_some_and(|s| s.granted.bytes > 0)
                        && self
                            .b
                            .credit_status(id)
                            .is_some_and(|s| s.granted.bytes > 0)
                })
            {
                return Ok(());
            }
        }
        Err("native handshake did not establish real grants".into())
    }
    fn time(&self) -> Micros {
        Micros(self.now * 1000)
    }
}
fn planner(table: &session::Table, now: Micros) -> Result<Planner, Error> {
    let mut p = Planner::new(config(table), table, now)?;
    for flow in 1..=table.status().flows as u64 {
        p.bind_flow(FlowWeight { flow, weight: 1 })?;
    }
    Ok(p)
}
fn measured() -> Feedback {
    Feedback {
        rtt_micros: Some(1000),
        delivery_bytes_per_second: Some(10_000_000),
        sender_credit_exhausted: true,
        ..Feedback::default()
    }
}

#[test]
fn table_batch_is_atomic_and_does_not_grant_or_touch_native_rings() -> TestResult {
    let mut lab = Lab::new(2, 4)?;
    lab.establish()?;
    let before = [
        lab.a.relay_status(1).ok_or("leg1")?,
        lab.a.relay_status(2).ok_or("leg2")?,
    ];
    let valid = Window {
        bytes: 2048,
        records: 8,
    };
    for targets in [
        vec![
            (1, valid),
            (
                2,
                Window {
                    bytes: 0,
                    records: 1,
                },
            ),
        ],
        vec![(1, valid), (99, valid)],
        vec![(1, valid), (1, valid)],
    ] {
        assert!(lab.a.set_targets(&targets).is_err());
        assert_eq!(lab.a.relay_status(1), Some(before[0]));
        assert_eq!(lab.a.relay_status(2), Some(before[1]));
    }
    lab.a.set_targets(&[(1, valid), (2, valid)])?;
    for (index, old) in before.iter().enumerate() {
        let next = lab.a.relay_status(index as u64 + 1).ok_or("updated")?;
        assert_eq!(next.target, valid);
        assert_eq!(next.granted, old.granted);
        assert_eq!(next.native, old.native);
        assert_eq!(next.pending_record_bytes, old.pending_record_bytes);
    }
    assert_eq!(lab.a.policy(), table_config(4, session::Role::Originator));
    Ok(())
}

#[test]
fn policy_rejects_unfunded_opening_slots_and_inconsistent_actual_geometry() -> TestResult {
    let table = session::Table::new(table_config(4, session::Role::Originator), Millis(0))?;
    let good = config(&table);
    good.validate(&table)?;
    let mut variants = vec![good; 5];
    variants[0].target.session_cap = Credit {
        bytes: 1024,
        records: 4,
    };
    variants[1].minimum_per_flow.bytes = 255;
    variants[2].target.per_flow_cap.records = 17;
    variants[3].target.max_flows = 5;
    variants[4].target.session_cap = Credit {
        bytes: u64::MAX,
        records: u64::MAX,
    };
    for bad in variants {
        assert!(Planner::new(bad, &table, Micros(0)).is_err());
    }
    assert_eq!(
        multiply(
            Window {
                bytes: u64::MAX,
                records: 1
            },
            2
        ),
        Err(Error::Exhausted)
    );
    let p = planner(&table, Micros(0))?;
    let plan = p.prepare(&table, Feedback::default(), &[], Micros(0))?;
    assert_eq!(
        plan.allocation().reserved,
        Window {
            bytes: 2048,
            records: 8
        }
    );
    assert!(plan.allocation().flows.is_empty());
    Ok(())
}

#[test]
fn weighted_targets_reserve_both_dimensions_and_only_apply_commits_history() -> TestResult {
    let mut lab = Lab::new(2, 4)?;
    lab.establish()?;
    let mut p = Planner::new(config(&lab.a), &lab.a, lab.time())?;
    p.bind_flow(FlowWeight { flow: 1, weight: 1 })?;
    p.bind_flow(FlowWeight { flow: 2, weight: 3 })?;
    let before = p.status();
    let grants = lab.a.credit_status(1).ok_or("credit")?.granted;
    let plan = p.prepare(&lab.a, measured(), &[2, 1], lab.time())?;
    assert_eq!(p.status(), before);
    let rows = &plan.allocation().flows;
    assert_eq!(rows[0].target.bytes, 1152);
    assert_eq!(rows[1].target.bytes, 2944);
    assert_eq!(rows.iter().map(|r| r.target.records).sum::<u64>(), 16);
    assert_eq!(
        plan.allocation().opening_reserved,
        Window {
            bytes: 1024,
            records: 4
        }
    );
    let at = lab.time();
    let applied = p.apply(&mut lab.a, plan, at)?;
    assert_eq!(p.status().revision, before.revision + 1);
    assert_eq!(lab.a.credit_status(1).ok_or("credit")?.granted, grants);
    assert!(fits(
        applied.reserved,
        window(config(&lab.a).target.session_cap)
    ));
    Ok(())
}

#[test]
fn old_unconsumed_grants_survive_pressure_and_cannot_be_reallocated() -> TestResult {
    let mut lab = Lab::new(2, 4)?;
    lab.establish()?;
    lab.a.set_targets(&[
        (
            1,
            Window {
                bytes: 4096,
                records: 16,
            },
        ),
        (
            2,
            Window {
                bytes: 2048,
                records: 8,
            },
        ),
    ])?;
    for _ in 0..4 {
        lab.step()?;
    }
    let g1 = lab.a.credit_status(1).ok_or("credit1")?;
    let g2 = lab.a.credit_status(2).ok_or("credit2")?;
    assert_eq!(g1.granted.bytes, 4096);
    assert_eq!(g1.acknowledged.bytes, 0);
    let mut p = planner(&lab.a, lab.time())?;
    let plan = p.prepare(
        &lab.a,
        Feedback {
            receiver_pressure: true,
            ..measured()
        },
        &[2],
        lab.time(),
    )?;
    assert_eq!(
        plan.allocation().flows[0].target,
        config(&lab.a).minimum_per_flow
    );
    assert_eq!(plan.allocation().flows[0].reserved, g1.granted);
    assert!(plan.allocation().flows[1].reserved.bytes >= g2.granted.bytes);
    assert!(plan.allocation().reserved.bytes <= 8192);
    let at = lab.time();
    p.apply(&mut lab.a, plan, at)?;
    assert_eq!(lab.a.credit_status(1).ok_or("credit")?.granted, g1.granted);
    for _ in 0..4 {
        lab.step()?;
    }
    assert_eq!(lab.a.credit_status(1).ok_or("credit")?.granted, g1.granted);
    Ok(())
}

#[test]
fn same_scope_cross_table_planner_and_stale_plans_cannot_commit() -> TestResult {
    let mut lab = Lab::new(2, 4)?;
    let other = Lab::new(2, 4)?;
    let mut p = planner(&lab.a, lab.time())?;
    assert!(matches!(
        p.prepare(&other.a, Feedback::default(), &[1], lab.time()),
        Err(Error::Owner)
    ));
    let mut second = planner(&lab.a, lab.time())?;
    let plan = p.prepare(&lab.a, Feedback::default(), &[1], lab.time())?;
    let before = second.status();
    let credit = lab.a.credit_status(1);
    let at = lab.time();
    assert!(matches!(
        second.apply(&mut lab.a, plan, at),
        Err(Error::Owner)
    ));
    assert_eq!(second.status(), before);
    assert_eq!(lab.a.credit_status(1), credit);
    let plan = p.prepare(&lab.a, Feedback::default(), &[1], lab.time())?;
    lab.a.set_target(
        2,
        Window {
            bytes: 513,
            records: 2,
        },
    )?;
    let before = p.status();
    let credit = lab.a.credit_status(1);
    let at = lab.time();
    assert!(matches!(
        p.apply(&mut lab.a, plan, at),
        Err(Error::StalePlan)
    ));
    assert_eq!(p.status(), before);
    assert_eq!(lab.a.credit_status(1), credit);
    let plan = p.prepare(&lab.a, Feedback::default(), &[1], lab.time())?;
    let at = Micros(lab.time().0 + 1);
    assert!(matches!(
        p.apply(&mut lab.a, plan, at),
        Err(Error::StalePlan)
    ));
    assert_eq!(p.status(), before);
    let first = p.prepare(&lab.a, Feedback::default(), &[1], lab.time())?;
    let stale = p.prepare(&lab.a, Feedback::default(), &[1], lab.time())?;
    let at = lab.time();
    p.apply(&mut lab.a, first, at)?;
    let committed = p.status();
    assert!(matches!(
        p.apply(&mut lab.a, stale, at),
        Err(Error::StalePlan)
    ));
    assert_eq!(p.status(), committed);
    Ok(())
}

#[test]
fn terminal_credit_survives_abort_output_drop_and_late_planner_attachment() -> TestResult {
    let mut lab = Lab::new(1, 4)?;
    lab.establish()?;
    lab.a.set_target(
        1,
        Window {
            bytes: 4096,
            records: 16,
        },
    )?;
    for _ in 0..4 {
        lab.step()?;
    }
    let before = lab.a.credit_status(1).ok_or("issued credit")?;
    assert_eq!(before.granted.bytes, 4096);
    lab.a.cancel(1, Millis(lab.now))?;
    for _ in 0..5 {
        lab.now += 1;
        lab.a.poll(Millis(lab.now), 4, 8)?;
        if lab.a.pending_native(1).is_some() {
            lab.a.confirm_native_written(1)?;
        }
    }
    assert!(lab.a.flow_status(1).ok_or("terminal")?.native.is_none());
    assert_eq!(lab.a.credit_status(1), Some(before));
    let mut p = planner(&lab.a, lab.time())?;
    let plan = p.prepare(&lab.a, Feedback::default(), &[], lab.time())?;
    assert_eq!(
        plan.allocation().terminal_reserved,
        Window {
            bytes: 4096,
            records: 16
        }
    );
    assert_eq!(
        plan.allocation().opening_reserved,
        Window {
            bytes: 1536,
            records: 6
        }
    );
    let at = lab.time();
    p.apply(&mut lab.a, plan, at)?;
    let mut bad = config(&lab.a);
    bad.target.session_cap = Credit {
        bytes: 4096,
        records: 16,
    };
    assert!(matches!(
        Planner::new(bad, &lab.a, lab.time()),
        Err(Error::Capacity)
    ));
    Ok(())
}

#[test]
fn sixty_four_active_owners_keep_floors_and_record_budget_even_when_idle() -> TestResult {
    let mut lab = Lab::new(64, 64)?;
    let mut p = planner(&lab.a, lab.time())?;
    let demand: Vec<_> = (1..=64).collect();
    let plan = p.prepare(&lab.a, measured(), &demand, lab.time())?;
    assert_eq!(plan.allocation().flows.len(), 64);
    for row in &plan.allocation().flows {
        assert!(row.target.bytes >= 256 && row.target.records >= 1);
    }
    assert_eq!(
        plan.allocation().reserved,
        Window {
            bytes: 16384,
            records: 64
        }
    );
    let at = lab.time();
    p.apply(&mut lab.a, plan, at)?;
    let plan = p.prepare(&lab.a, Feedback::default(), &[], lab.time())?;
    assert_eq!(plan.allocation().candidate, Window::default());
    assert_eq!(
        plan.allocation().reserved,
        Window {
            bytes: 16384,
            records: 64
        }
    );
    Ok(())
}

#[test]
fn invalid_demand_and_time_leave_policy_history_and_table_unchanged() -> TestResult {
    let lab = Lab::new(2, 4)?;
    let p = planner(&lab.a, lab.time())?;
    let before = p.status();
    for ids in [vec![1, 1], vec![0], vec![3], vec![u64::MAX]] {
        assert!(matches!(
            p.prepare(&lab.a, measured(), &ids, lab.time()),
            Err(Error::Flow)
        ));
    }
    assert!(matches!(
        p.prepare(&lab.a, measured(), &[1], Micros(0)),
        Err(Error::Time)
    ));
    assert!(
        p.prepare(
            &lab.a,
            Feedback {
                rtt_micros: Some(0),
                ..measured()
            },
            &[1],
            lab.time()
        )
        .is_err()
    );
    assert_eq!(p.status(), before);
    Ok(())
}

#[test]
fn weighted_fill_handles_caps_maximum_arithmetic_and_rotating_remainders() -> TestResult {
    let mut values = [0, 0, 0];
    fill(&mut values, &[1, 100, 100], &[16, 1, 1], 21, 0)?;
    assert_eq!(values, [1, 10, 10]);
    let mut values = [0, 0];
    fill(&mut values, &[u64::MAX, u64::MAX], &[1, 1], u64::MAX, 1)?;
    assert_eq!(values[0], u64::MAX / 2);
    assert_eq!(values[1], u64::MAX / 2 + 1);
    for cursor in 0..3 {
        let mut values = [0, 0, 0];
        fill(&mut values, &[2, 2, 2], &[1, 1, 1], 1, cursor)?;
        assert_eq!(values[cursor], 1);
        assert_eq!(values.iter().sum::<u64>(), 1);
    }
    Ok(())
}

#[test]
fn one_byte_records_exhaust_count_without_consuming_byte_capacity() -> TestResult {
    let mut lab = Lab::new(1, 4)?;
    lab.establish()?;
    lab.b.set_target(
        1,
        Window {
            bytes: 4096,
            records: 16,
        },
    )?;
    lab.b.poll(Millis(lab.now), 4, 8)?;
    let scope = crate::Scope {
        session: lab.b.policy().session,
        epoch: lab.b.policy().epoch,
        flow: 1,
    };
    assert_eq!(lab.b.credit_status(1).ok_or("grant")?.granted.records, 16);
    for offset in 0..16 {
        let bytes = crate::encode(
            scope,
            2,
            Window {
                bytes: offset,
                records: offset,
            },
            &[0x71],
        );
        lab.b.receive_authenticated(&bytes, true, Millis(lab.now))?;
    }
    let before = lab.b.credit_status(1).ok_or("received")?;
    assert_eq!(
        before.received,
        Window {
            bytes: 16,
            records: 16
        }
    );
    let extra = crate::encode(scope, 2, before.received, &[0x72]);
    assert!(matches!(
        lab.b.receive_authenticated(&extra, true, Millis(lab.now)),
        Err(session::Error::Relay(crate::Error::Credit))
    ));
    assert_eq!(lab.b.credit_status(1), Some(before));
    let p = planner(&lab.b, lab.time())?;
    let plan = p.prepare(
        &lab.b,
        Feedback {
            receiver_pressure: true,
            ..measured()
        },
        &[1],
        lab.time(),
    )?;
    assert_eq!(
        plan.allocation().flows[0].reserved,
        Window {
            bytes: 4096,
            records: 16
        }
    );
    assert!(plan.allocation().flows[0].target.records < 16);
    Ok(())
}

#[test]
fn failed_batch_apply_does_not_commit_cloned_candidate_history() -> TestResult {
    let mut lab = Lab::new(2, 4)?;
    let mut p = planner(&lab.a, lab.time())?;
    let history = format!("{:?}", p.controller);
    let before = p.status();
    let rows = [lab.a.credit_status(1), lab.a.credit_status(2)];
    let mut plan = p.prepare(
        &lab.a,
        Feedback {
            receiver_pressure: true,
            ..measured()
        },
        &[1, 2],
        lab.time(),
    )?;
    // Internal fault injection reaches the table batch's late validation failure;
    // external callers cannot edit this opaque plan or mint an invalid target.
    plan.result.flows[1].target.records = 0;
    let at = lab.time();
    assert!(matches!(
        p.apply(&mut lab.a, plan, at),
        Err(Error::Table(_))
    ));
    assert_eq!(p.status(), before);
    assert_eq!(format!("{:?}", p.controller), history);
    assert_eq!([lab.a.credit_status(1), lab.a.credit_status(2)], rows);
    let next = p.prepare(&lab.a, measured(), &[1, 2], at)?;
    assert_eq!(next.allocation().state, TargetState::Bootstrap);
    assert_eq!(
        next.allocation().candidate,
        Window {
            bytes: 4096,
            records: 16
        }
    );
    Ok(())
}

#[test]
fn clean_retirement_freezes_credit_without_claiming_unused_grants_returned() -> TestResult {
    let mut lab = Lab::new(1, 4)?;
    lab.establish()?;
    for host in &mut lab.hosts[0] {
        host.close();
    }
    let mut frozen = None;
    for _ in 0..30_000 {
        lab.step()?;
        let credit = lab.a.credit_status(1);
        if lab.a.retire_clean(1).is_ok() {
            frozen = credit;
            break;
        }
    }
    let credit = frozen.ok_or("maintained clean retirement")?;
    assert_eq!(
        lab.a.flow_status(1).ok_or("flow")?.phase,
        session::FlowPhase::Retired
    );
    assert_eq!(lab.a.credit_status(1), Some(credit));
    let p = planner(&lab.a, lab.time())?;
    let plan = p.prepare(&lab.a, Feedback::default(), &[], lab.time())?;
    assert_eq!(
        plan.allocation().terminal_reserved,
        maximum(debt(credit, lab.a.policy().maximum)?, credit.target)
    );
    assert_eq!(credit.acknowledged, credit.received);
    assert!(credit.granted.bytes > credit.acknowledged.bytes);
    Ok(())
}

#[test]
fn table_poll_weight_revision_and_clock_exhaustion_invalidate_without_mutation() -> TestResult {
    let mut lab = Lab::new(2, 4)?;
    let mut p = planner(&lab.a, lab.time())?;
    let plan = p.prepare(&lab.a, measured(), &[1, 2], lab.time())?;
    p.bind_flow(FlowWeight { flow: 3, weight: 2 })?;
    let before = p.status();
    let at = lab.time();
    assert!(matches!(
        p.apply(&mut lab.a, plan, at),
        Err(Error::StalePlan)
    ));
    assert_eq!(p.status(), before);
    let plan = p.prepare(&lab.a, measured(), &[1, 2], lab.time())?;
    lab.a.poll(Millis(lab.now + 1), 4, 8)?;
    let before = p.status();
    assert!(matches!(
        p.apply(&mut lab.a, plan, at),
        Err(Error::StalePlan)
    ));
    assert_eq!(p.status(), before);
    assert!(matches!(
        Planner::new(config(&lab.a), &lab.a, Micros(u64::MAX)),
        Err(Error::Time)
    ));
    assert!(matches!(
        p.prepare(&lab.a, measured(), &[1], Micros(u64::MAX)),
        Err(Error::Time)
    ));
    Ok(())
}
