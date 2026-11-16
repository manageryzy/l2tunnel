//! Fixed Common proxy selection and presentation over the existing shared service.
use super::*;
use crate::secure_udp::common_transaction_profile::Profile as CommonProfile;
use serde_json::{Value, json};

pub(super) fn selection(
    options: &BTreeMap<String, String>,
    connection: ConnectionConfig,
    common_plan: bool,
    carrier: Carrier,
) -> io::Result<bool> {
    if !options.contains_key("--traffic")
        && !options.contains_key("--proxy-policy")
        && !options.contains_key("--proxy-close")
    {
        return Ok(false);
    }
    if !common_plan || options.get("--traffic").map(String::as_str) != Some("proxy") {
        return Err(input(
            "Common proxy requires explicit fixed --traffic proxy and complete Common plan",
        ));
    }
    if carrier != Carrier::OriginalUdp
        || connection.duplex != Duplex::Full
        || connection.layer != l2tunnel_device::PacketLayer::Ip
        || connection.compression != Compression::None
    {
        return Err(input(
            "Common proxy currently requires original UDP cover, full duplex, TUN and no compression",
        ));
    }
    required(options, "--proxy-policy")?;
    retained(options)?;
    Ok(true)
}
pub(super) fn retained(options: &BTreeMap<String, String>) -> io::Result<bool> {
    match options.get("--proxy-close").map(String::as_str) {
        None => Ok(false),
        Some("retained") => Ok(true),
        _ => Err(input("Common proxy --proxy-close requires retained")),
    }
}
fn backend(retained: bool) -> &'static str {
    if retained {
        "common_proxy_fixed_retained_v1"
    } else {
        "common_proxy_fixed_v1"
    }
}
pub(super) fn settings(
    options: &BTreeMap<String, String>,
    connection: ConnectionConfig,
) -> io::Result<crate::proxy::Settings> {
    let settings = crate::proxy::Settings::from_json(&bounded_file(
        required(options, "--proxy-policy")?,
        crate::proxy::MAX_POLICY_BYTES,
    )?)?;
    if settings.channels != 1 {
        return Err(input(
            "Common proxy currently requires exactly one configured channel",
        ));
    }
    crate::proxy::runtime_config(connection, &settings)?;
    Ok(settings)
}

/// Requested-only inspection; no native device, TLS/Noise or actual runtime facts.
pub(super) fn inspection(profile: &CommonProfile, role: security::Role) -> io::Result<Vec<Value>> {
    let proxy = profile
        .proxy_config()
        .ok_or_else(|| input("inspection lacks explicit fixed proxy"))?;
    let mut values = common_cli_output::inspection(profile, role)?;
    values
        .try_reserve_exact(proxy.routes.rules().len().div_ceil(16))
        .map_err(io::Error::other)?;
    let header = values
        .first_mut()
        .ok_or_else(|| input("Common proxy inspection header absent"))?;
    header["event"] = json!("secure_udp_common_proxy_plan");
    header["api_version"] = json!(crate::local::VERSION);
    header["backend"] = json!(backend(profile.proxy_retirement()));
    header["traffic"] = json!("proxy");
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
    header["proxy_effective"] = Value::Null;
    header["capabilities"] = json!({"fixed":true,"measured":false,"common_record_composition":false,
        "authenticated":false,"hot_switch":false,"graceful_close":profile.proxy_retirement(),"exact_tcp_rwnd_control":false,
        "native_common_api4":false,"native_qualified":false});
    *header = transaction_cli_output::bounded(std::mem::take(header))?;
    for (page, rules) in proxy.routes.rules().chunks(16).enumerate() {
        let rules = rules.iter().map(|rule| json!({
            "source":format!("{}/{}",rule.source.address(),rule.source.bits()),
            "destination":format!("{}/{}",rule.destination.address(),rule.destination.bits()),
            "ports":{"first":rule.ports.first,"last":rule.ports.last},
        })).collect::<Vec<_>>();
        values.push(transaction_cli_output::bounded(json!({"event":"secure_udp_common_proxy_plan_routes","schema":1,
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
    let (generation, name, outcome) = match event {
        SharedEvent::Ready {
            generation,
            profile: ProxyProfile::FixedCredit,
            ..
        } => (*generation, "secure_udp_common_proxy_ready", None),
        SharedEvent::Ready { .. } => {
            return Err(input(
                "fixed Common proxy presentation received a different backend",
            ));
        }
        SharedEvent::Terminal {
            generation,
            outcome,
        } => (
            *generation,
            "secure_udp_common_proxy_terminal",
            Some(outcome),
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
        && (frame.requested_profile != ProxyProfile::FixedCredit
            || frame.effective_profile != ProxyProfile::FixedCredit
            || frame.requested_digest != frame.effective_digest
            || !frame.common_record_composition
            || !common.installed
            || !common.running
            || common.released
            || common.releasing
            || common.requested_configuration != common.effective_configuration
            || common.requested_carrier != common.effective_carrier
            || common.effective_cover != Some(common.requested_cover)
            || frame
                .runtime
                .as_ref()
                .is_none_or(|runtime| runtime.phase != l2tunnel_runtime::proxy::Phase::Forwarding))
    {
        return Err(input(
            "Common proxy readiness lacks actual matching live facts",
        ));
    }
    transaction_cli_output::bounded(
        json!({"event":name,"schema":1,"api_version":crate::local::VERSION,
        "backend":backend(common.graceful_close),"generation":generation.value(),"proxy":frame.status(),"outcome":outcome}),
    )
}

#[cfg(target_os = "linux")]
pub(super) async fn serve_prepared(
    plan: crate::service::Prepared,
    options: &BTreeMap<String, String>,
    connection: ConnectionConfig,
) -> io::Result<()> {
    use crate::{cli::proxy_frontend, service};
    let api = options
        .get("--control-socket")
        .map(crate::local::Server::bind)
        .transpose()?;
    let (handle, run) = service::channel();
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
            profile: service::ProxyProfile::FixedCredit,
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
