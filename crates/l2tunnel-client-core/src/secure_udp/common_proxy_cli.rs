//! Explicit fixed/measured Common proxy selection through the existing shared service.
use super::*;
use crate::secure_udp::common_transaction_profile::Profile as CommonProfile;
use serde_json::{Value, json};

pub(super) enum Policy {
    Fixed(Box<crate::proxy::Settings>),
    Measured(Box<crate::proxy_measured::Settings>),
}

pub(super) fn selection(
    options: &BTreeMap<String, String>,
    connection: ConnectionConfig,
    common_plan: bool,
    carrier: &Carrier,
) -> io::Result<bool> {
    if !options.contains_key("--traffic")
        && !options.contains_key("--proxy-policy")
        && !options.contains_key("--proxy-close")
    {
        return Ok(false);
    }
    if !common_plan
        || !matches!(
            options.get("--traffic").map(String::as_str),
            Some("proxy" | "proxy-measured")
        )
    {
        return Err(input(
            "Common proxy requires explicit proxy/proxy-measured traffic and complete Common plan",
        ));
    }
    if matches!(carrier, Carrier::OpenVpn)
        || (*carrier == Carrier::OriginalUdp && connection.duplex != Duplex::Full)
        || connection.layer != l2tunnel_device::PacketLayer::Ip
        || connection.compression != Compression::None
    {
        return Err(input(
            "Common proxy requires original UDP, retained TLS/QUIC or raw TCP, TUN and no compression; original UDP requires full duplex",
        ));
    }
    required(options, "--proxy-policy")?;
    let close = retained(options)?;
    if *carrier == Carrier::RawPacket
        && options.get("--traffic").map(String::as_str) == Some("proxy-measured")
    {
        return Err(input(
            "measured Common proxy requires original UDP or retained TLS/QUIC",
        ));
    }
    if options.get("--traffic").map(String::as_str) == Some("proxy-measured") && !close {
        return Err(input(
            "Common measured proxy requires explicit --proxy-close retained",
        ));
    }
    Ok(true)
}
pub(super) fn retained(options: &BTreeMap<String, String>) -> io::Result<bool> {
    match options.get("--proxy-close").map(String::as_str) {
        None => Ok(false),
        Some("retained") => Ok(true),
        _ => Err(input("Common proxy --proxy-close requires retained")),
    }
}
fn backend(retained: bool, measured: bool) -> &'static str {
    if measured {
        "common_proxy_measured_retained_v1"
    } else if retained {
        "common_proxy_fixed_retained_v1"
    } else {
        "common_proxy_fixed_v1"
    }
}
pub(super) fn settings(
    options: &BTreeMap<String, String>,
    connection: ConnectionConfig,
) -> io::Result<Policy> {
    let path = required(options, "--proxy-policy")?;
    if options.get("--traffic").map(String::as_str) == Some("proxy-measured") {
        if !retained(options)? {
            return Err(input(
                "Common measured proxy requires explicit --proxy-close retained",
            ));
        }
        let settings = crate::proxy_measured::Settings::from_json(&bounded_file(
            path,
            crate::proxy_measured::MAX_POLICY_BYTES,
        )?)?;

        crate::proxy_measured::runtime_config(connection, &settings)?;
        return Ok(Policy::Measured(Box::new(settings)));
    }
    let settings =
        crate::proxy::Settings::from_json(&bounded_file(path, crate::proxy::MAX_POLICY_BYTES)?)?;

    crate::proxy::runtime_config(connection, &settings)?;
    Ok(Policy::Fixed(Box::new(settings)))
}

fn measurement_policy(config: &l2tunnel_runtime::proxy::measured::Config) -> Value {
    let allocation = config.measured.allocation;
    let target = allocation.target;
    let owner = config.measured.ownership;
    let observation = config.measured.observation;
    let service = config.service;
    let amount = |bytes, records| json!({"bytes":bytes,"records":records});
    json!({
        "allocation":{"target":{
            "initial":amount(target.initial.bytes,target.initial.records),"minimum":amount(target.minimum.bytes,target.minimum.records),
            "session_cap":amount(target.session_cap.bytes,target.session_cap.records),"per_flow_cap":amount(target.per_flow_cap.bytes,target.per_flow_cap.records),
            "policy_cap":amount(target.policy_cap.bytes,target.policy_cap.records),"queue_allowance_bytes":target.queue_allowance_bytes,
            "queue_delay_target_micros":target.queue_delay_target_micros,"many_flow_step":amount(target.many_flow_step.bytes,target.many_flow_step.records),
            "few_flow_threshold":target.few_flow_threshold,"max_flows":target.max_flows,"bootstrap_rtt_micros":target.bootstrap_rtt_micros,"recovery_rtts":target.recovery_rtts},
            "minimum_per_flow":amount(allocation.minimum_per_flow.bytes,allocation.minimum_per_flow.records)},
        "ownership":{"pending_ttl_micros":owner.pending_ttl_micros,"probe_interval_micros":owner.probe_interval_micros,"probe_timeout_micros":owner.probe_timeout_micros,
            "handoff_timeout_micros":owner.handoff_timeout_micros,"emission_interval_micros":owner.emission_interval_micros,"max_records_per_interval":owner.max_records_per_interval},
        "observation":{"report_interval_micros":observation.report_interval_micros,"sample_ttl_micros":observation.sample_ttl_micros,"demand_idle_micros":observation.demand_idle_micros,
            "rate_interval_micros":observation.rate_interval_micros,"rate_bins":observation.rate_bins},
        "service":{"report_work_per_turn":service.report_work_per_turn,"admission_work_per_turn":service.admission_work_per_turn,"callback_work_per_turn":service.callback_work_per_turn,
            "plan_interval_micros":service.plan_interval_micros,"status_interval_micros":service.status_interval_micros}
    })
}

/// Requested-only inspection; no native device, TLS/Noise or actual runtime facts.
pub(super) fn inspection(profile: &CommonProfile, role: security::Role) -> io::Result<Vec<Value>> {
    let proxy = profile
        .proxy_config()
        .ok_or_else(|| input("inspection lacks explicit Common proxy"))?;
    let mut values = common_cli_output::inspection(profile, role)?;
    values
        .try_reserve_exact(proxy.routes.rules().len().div_ceil(16))
        .map_err(io::Error::other)?;
    let header = values
        .first_mut()
        .ok_or_else(|| input("Common proxy inspection header absent"))?;
    header["event"] = json!("secure_udp_common_proxy_plan");
    header["api_version"] = json!(crate::local::VERSION);
    header["backend"] = json!(backend(
        profile.proxy_retirement(),
        profile.proxy_measured_config().is_some()
    ));
    header["traffic"] = json!(if profile.proxy_measured_config().is_some() {
        "proxy-measured"
    } else {
        "proxy"
    });
    header["proxy_requested"] = json!({
        "version":1,"profile":"fixed_credit","channels":proxy.mux.channels,
        "retained_close":profile.proxy_retirement(),
        "policy_digest":l2tunnel_runtime::proxy::session_config(proxy)?.digest.0,
        "time_wait_reset":match proxy.native.time_wait_reset_policy {crate::proxy::TimeWaitResetPolicy::Maintained=>"maintained",crate::proxy::TimeWaitResetPolicy::IgnoreInTimeWait=>"ignore_in_time_wait"},
        "route_count":proxy.routes.rules().len(),"native_mtu":proxy.native.mtu,
        "native_send_bytes":proxy.native.send_bytes,"native_receive_bytes":proxy.native.receive_bytes,
        "native_packet_slots":proxy.native.packet_slots,"native_ack_delay_millis":proxy.native.ack_delay_millis,
        "native_keepalive_millis":proxy.native.keepalive_millis,"native_idle_timeout_millis":proxy.native.idle_timeout_millis,
        "relay":{"max_flows":proxy.relay.max_flows,"max_policies":proxy.relay.max_policies,
            "max_record_bytes":proxy.relay.max_record_bytes,"maximum_bytes":proxy.relay.maximum.bytes,
            "maximum_records":proxy.relay.maximum.records,"initial_bytes":proxy.relay.initial.bytes,
            "initial_records":proxy.relay.initial.records,"admission_timeout_micros":proxy.relay.admission_timeout.as_micros()},
        "mux":{"max_flow_bindings":proxy.mux.max_flow_bindings,"queue_bytes":proxy.mux.queue_bytes,
            "queue_records":proxy.mux.queue_records,"per_flow_bytes":proxy.mux.per_flow_bytes,
            "per_flow_records":proxy.mux.per_flow_records,"quantum_bytes":proxy.mux.quantum_bytes,
            "dscp_weights":proxy.mux.dscp_weights.as_slice()},
        "delivery":{"transparent_bytes":proxy.delivery.transparent_bytes,"transparent_packets":proxy.delivery.transparent_packets,
            "native_queue_bytes":proxy.delivery.native_queue_bytes,"native_queue_packets":proxy.delivery.native_queue_packets},
        "timeouts_micros":{"startup":proxy.timeouts.startup.as_micros(),"control_idle":proxy.timeouts.control_idle.as_micros(),
            "shutdown":proxy.timeouts.shutdown.as_micros()},
        "flow_poll_work":proxy.flow_poll_work,"stack_poll_work":proxy.stack_poll_work,"control_rate":proxy.control_rate,
    });
    if let Some(measured) = profile.proxy_measured_config() {
        header["proxy_requested"]["profile"] = json!(crate::proxy_measured::PROFILE);
        header["proxy_requested"]["policy_digest"] = json!(
            l2tunnel_runtime::proxy::measured::session_config(measured)?
                .digest
                .0
        );
        header["proxy_requested"]["measurement"] = measurement_policy(measured);
    }
    header["proxy_effective"] = Value::Null;
    header["capabilities"] = json!({"fixed":profile.proxy_measured_config().is_none(),"measured":profile.proxy_measured_config().is_some(),"common_record_composition":false,
        "authenticated":false,"hot_switch":false,"graceful_close":profile.proxy_retirement(),"exact_tcp_rwnd_control":false,
        "native_common_api4":false,"native_qualified":false});
    *header = common_cli_output::bounded(std::mem::take(header))?;
    for (page, rules) in proxy.routes.rules().chunks(16).enumerate() {
        let rules = rules.iter().map(|rule| json!({
            "source":format!("{}/{}",rule.source.address(),rule.source.bits()),
            "destination":format!("{}/{}",rule.destination.address(),rule.destination.bits()),
            "ports":{"first":rule.ports.first,"last":rule.ports.last},
        })).collect::<Vec<_>>();
        values.push(common_cli_output::bounded(json!({"event":"secure_udp_common_proxy_plan_routes","schema":1,
            "requested":true,"authenticated":false,"offset":page*16,"total":proxy.routes.rules().len(),"routes":rules}))?);
    }
    Ok(values)
}

#[cfg(target_os = "linux")]
pub(crate) fn event(
    snapshot: &crate::service::Snapshot,
    event: &crate::cli::proxy_frontend::SharedEvent,
) -> io::Result<Value> {
    use crate::{
        cli::proxy_frontend::SharedEvent,
        service::{Observation, ProxyProfile},
    };
    let (generation, name, outcome, selected, requested_duplex) = match event {
        SharedEvent::Ready {
            generation,
            profile,
            duplex,
        } => (
            *generation,
            "secure_udp_common_proxy_ready",
            None,
            Some(*profile),
            Some(match duplex {
                Duplex::Full => "full",
                Duplex::Half => "half",
            }),
        ),
        SharedEvent::Terminal {
            generation,
            outcome,
        } => (
            *generation,
            "secure_udp_common_proxy_terminal",
            Some(outcome),
            None,
            None,
        ),
    };
    if snapshot.generation != Some(generation) {
        return Err(input("Common proxy event generation differs"));
    }
    let frame = snapshot
        .runtime
        .as_ref()
        .and_then(Observation::proxy)
        .ok_or_else(|| input("actual Proxy observation absent"))?;
    let common = frame
        .common_status()
        .ok_or_else(|| input("actual Common proxy composition absent"))?;
    if matches!(event, SharedEvent::Ready { .. })
        && (selected != Some(frame.requested_profile)
            || frame.effective_profile != frame.requested_profile
            || frame.requested_digest != frame.effective_digest
            || !frame.common_record_composition
            || !common.installed
            || !common.running
            || common.released
            || common.releasing
            || (common.maintained_carrier.is_none()
                && common.requested_configuration != common.effective_configuration)
            || common.requested_carrier != common.effective_carrier
            || common.effective_cover != Some(common.requested_cover)
            || common
                .maintained_carrier
                .as_ref()
                .is_some_and(|value| !value.matches_requested_policy() || value.binding.is_none())
            || frame
                .runtime
                .as_ref()
                .is_none_or(|runtime| runtime.phase != l2tunnel_runtime::proxy::Phase::Forwarding))
    {
        return Err(input(
            "Common proxy readiness lacks actual matching live facts",
        ));
    }
    if matches!(event, SharedEvent::Ready { .. }) {
        match frame.effective_profile {
            ProxyProfile::FixedCredit if frame.measured.is_some() => {
                return Err(input("fixed Common proxy acquired measured observations"));
            }
            ProxyProfile::FixedCredit => {}
            ProxyProfile::MeasuredRelay => {
                use crate::proxy_measured::{
                    Carrier as MeasuredCarrier, Profile as MeasuredProfile, UdpCover,
                };
                let value = frame
                    .measured
                    .as_ref()
                    .ok_or_else(|| input("actual measured Common observation absent"))?;
                let expected = match common.requested_cover {
                    crate::local::ProxyCommonCover::QuicLike => UdpCover::QuicLike,
                    crate::local::ProxyCommonCover::MediaLike => UdpCover::MediaLike,
                };
                let expected_carrier = common.maintained_carrier.as_ref().map_or(
                    MeasuredCarrier::CommonUdp,
                    |value| {
                        if value.requested.carrier == "tcp" {
                            MeasuredCarrier::CommonTls
                        } else {
                            MeasuredCarrier::CommonQuic
                        }
                    },
                );
                if !common.graceful_close
                    || value.capabilities.effective != Some(MeasuredProfile::MeasuredRelayV1)
                    || value.capabilities.requested_carrier != expected_carrier
                    || value.capabilities.effective_carrier != Some(expected_carrier)
                    || value.capabilities.requested_udp_cover != expected
                    || value.capabilities.effective_udp_cover != Some(expected)
                    || !value.capabilities.measured_relay_targets
                {
                    return Err(input(
                        "measured Common readiness lacks actual selected carrier/controller facts",
                    ));
                }
            }
        }
    }
    common_cli_output::bounded(
        json!({"event":name,"schema":1,"api_version":crate::local::VERSION,
        "backend":backend(common.graceful_close,frame.effective_profile==ProxyProfile::MeasuredRelay),"generation":generation.value(),"requested_duplex":requested_duplex,"proxy":frame.status(),"outcome":outcome}),
    )
}

#[cfg(target_os = "linux")]
pub(super) async fn serve_prepared(
    plan: crate::service::Prepared,
    options: &BTreeMap<String, String>,
    connection: ConnectionConfig,
) -> io::Result<()> {
    use crate::{cli::proxy_frontend, service};
    let profile = match options.get("--traffic").map(String::as_str) {
        Some("proxy") => service::ProxyProfile::FixedCredit,
        Some("proxy-measured") if retained(options)? => service::ProxyProfile::MeasuredRelay,
        _ => return Err(input("explicit supported Common proxy policy absent")),
    };
    let api = options
        .get("--control-socket")
        .map(crate::local::Server::bind)
        .transpose()?;
    let (handle, run) = service::channel();
    service::host::attach_state_dir(&handle, options.get("--state-dir")).await?;
    let submit = |error| io::Error::other(format!("Common proxy service: {error:?}"));
    let accepted = handle
        .connect(plan, handle.next_key().map_err(submit)?)
        .map_err(submit)?;
    let observed = handle.clone();
    proxy_frontend::serve_shared(
        handle,
        run,
        accepted,
        api,
        proxy_frontend::SharedPresentation {
            duplex: connection.duplex,
            profile,
            grace: Duration::from_secs(5),
        },
        move |value| match event(&observed.snapshot(), &value)
            .and_then(|value| serde_json::to_string(&value).map_err(io::Error::other))
        {
            Ok(line) => println!("{line}"),
            Err(error) => eprintln!("Common proxy presentation unavailable: {error}"),
        },
    )
    .await
}

#[cfg(test)]
#[path = "common_proxy_cli_tests.rs"]
mod tests;
