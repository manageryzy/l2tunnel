//! Bounded full Common plan pages and actual shared-service events.
use super::transaction_cli_output::bounded;
use crate::secure_udp::{
    common_status::CanonicalConfiguration, common_transaction_profile::Profile,
};
use l2tunnel::record_configuration::Configuration;
use l2tunnel_security::Role;
use serde_json::{Value, json};
use std::io;

pub(super) fn requested_tls(
    mut values: Vec<Value>,
    naming: Option<Value>,
) -> io::Result<Vec<Value>> {
    if let Some(naming) = naming {
        let first = values
            .first_mut()
            .ok_or_else(|| io::Error::other("inspection header absent"))?;
        first
            .as_object_mut()
            .ok_or_else(|| io::Error::other("inspection header is not an object"))?
            .insert("tls_name_policy".into(), naming);
        *first = bounded(std::mem::take(first))?;
    }
    Ok(values)
}

pub(super) fn inspection(profile: &Profile, role: Role) -> io::Result<Vec<Value>> {
    let contract = profile.runtime_contract(role)?;
    let parameters = profile.parameters();
    let mut output = Vec::new();
    output.try_reserve_exact(17).map_err(io::Error::other)?;
    let work = contract
        .resources()
        .rolling_work
        .map(|v| json!({"field":v.field,"copies":v.copies,"metadata":v.metadata}));
    output.push(bounded(json!({"event":"secure_udp_common_plan","schema":1,"api_version":4,
        "backend":"common_records_v2","requested":true,"validated":true,"authenticated":false,
        "role":match role{Role::Initiator=>"initiator",Role::Responder=>"responder"},
        "carrier":match profile.settings().cover.appearance{l2tunnel_cover::Appearance::QuicLike=>"quic-like",l2tunnel_cover::Appearance::MediaLike=>"media-like"},
        "configuration":profile.configuration()?.0,"envelope":profile.envelope().as_bytes(),
        "catalog":profile.catalog().root().as_bytes(),"catalog_members":profile.catalog().descriptors().len(),
        "initial":CanonicalConfiguration::from_configuration(profile.initial())?,
        "rolling_work":work,"rolling_work_semantics":"independent send/receive caps per live epoch per Driver turn; at most four directional caps",
        "resource_preallocation_complete":false,"retained_state_recovery":false,"fresh_rekey":false,
        "parameters":{"retry_ms":parameters.protocol.retry_ms,"phase_timeout_ms":parameters.protocol.phase_timeout_ms,
            "reconcile_timeout_ms":parameters.protocol.reconcile_timeout_ms,"max_operation_ms":parameters.max_operation_ms,
            "retained_bytes":parameters.retained_bytes},
    }))?);
    for (index, page) in profile.catalog().descriptors().chunks(4).enumerate() {
        let configurations = page
            .iter()
            .map(|descriptor| {
                Configuration::new(profile.envelope(), *descriptor)
                    .map_err(io::Error::other)
                    .and_then(CanonicalConfiguration::from_configuration)
            })
            .collect::<io::Result<Vec<_>>>()?;
        output.push(bounded(
            json!({"event":"secure_udp_common_plan_catalog","schema":1,
            "catalog":profile.catalog().root().as_bytes(),"offset":index*4,
            "total":profile.catalog().descriptors().len(),"configurations":configurations}),
        )?);
    }
    Ok(output)
}

pub(super) fn carrier_inspection(
    profile: &Profile,
    role: Role,
    outer: l2tunnel_openvpn::wire_carrier::common::Config,
) -> io::Result<Vec<Value>> {
    if profile.carrier_binding().is_some() {
        return Err(io::Error::other(
            "offline inspection requires an unbound requested profile",
        ));
    }
    let mut output = inspection(profile, role)?;
    let header = output
        .first_mut()
        .and_then(Value::as_object_mut)
        .ok_or_else(|| io::Error::other("Common inspection header absent"))?;
    let cover = header
        .remove("carrier")
        .ok_or_else(|| io::Error::other("Common cover absent"))?;
    header.insert(
        "event".into(),
        json!("secure_udp_common_requested_carrier_plan"),
    );
    header.insert("carrier".into(), json!("openvpn-like"));
    header.insert("udp_cover".into(), cover);
    header.remove("configuration");
    header.remove("envelope");
    let initial = header
        .remove("initial")
        .ok_or_else(|| io::Error::other("Common initial absent"))?;
    header.insert("requested_initial".into(), initial);
    header.insert(
        "requested_configuration".into(),
        json!(profile.requested_configuration()?.0),
    );
    header.insert(
        "requested_envelope".into(),
        json!(profile.requested_envelope().as_bytes()),
    );
    header.insert("configuration_scope".into(), json!("requested_base_E0"));
    header.insert("effective_configuration".into(), Value::Null);
    header.insert("effective_envelope".into(), Value::Null);
    header.insert("effective_catalog".into(), Value::Null);
    header.insert("authenticated_outer_binding_required".into(), json!(true));
    header.insert("outer_tls_trust_validated".into(), json!(false));
    header.insert("outer_policy".into(), json!({
        "version":1,"backend":"openvpn_wire_common",
        "digest":outer.session_config().map_err(io::Error::other)?.digest.0,
        "path_mtu":outer.path_mtu,"outer_overhead_bytes":outer.outer_overhead_bytes,
        "max_record_bytes":outer.max_record_bytes,"packet_slots":outer.packet_slots,
        "stream_bytes":outer.stream_bytes,"work_limit":outer.work_limit,
        "handshake_timeout_micros":outer.handshake_timeout.as_micros(),
        "lifetime_micros":outer.lifetime.as_micros(),"poll_interval_micros":outer.poll_interval.as_micros(),
        "control_arq":{"max_source_bytes":outer.control_arq.max_source_bytes,
            "send_bytes":outer.control_arq.send_bytes,"receive_bytes":outer.control_arq.receive_bytes,
            "send_records":outer.control_arq.send_records,"receive_records":outer.control_arq.receive_records,
            "initial_rto_micros":outer.control_arq.initial_rto.as_micros(),
            "maximum_rto_micros":outer.control_arq.maximum_rto.as_micros(),
            "ack_delay_micros":outer.control_arq.ack_delay.as_micros(),"max_retries":outer.control_arq.max_retries},
        "wire_budget":{"interval_micros":outer.wire_budget.interval.as_micros(),
            "packets":outer.wire_budget.packets,"ip_bytes":outer.wire_budget.ip_bytes,
            "reserved_control_packets":outer.wire_budget.reserved_control_packets,
            "reserved_control_bytes":outer.wire_budget.reserved_control_bytes,
            "maximum_control_packets":outer.wire_budget.maximum_control_packets}
    }));
    for page in output.iter_mut().skip(1) {
        page["configuration_scope"] = json!("requested_base_E0");
        page["authenticated_outer_binding_required"] = json!(true);
    }
    output.into_iter().map(bounded).collect()
}
#[cfg(target_os = "linux")]
pub(super) fn event(
    frame: &crate::service::SecureUdpCommonFrame,
    generation: u64,
    event: super::TransactionEvent,
) -> io::Result<Value> {
    if frame.generation != generation {
        return Err(io::Error::other(
            "Common event belongs to another generation",
        ));
    }
    let status = frame.status()?;
    let (name, outcome) = match event {
        super::TransactionEvent::Ready => {
            if frame.runtime.is_none()
                || !status.running
                || status.terminal.is_some()
                || frame.service_terminal.is_some()
            {
                return Err(io::Error::other("Common readiness has no live report"));
            }
            ("secure_udp_common_ready", None)
        }
        super::TransactionEvent::Status => ("secure_udp_common_status", None),
        super::TransactionEvent::Terminal(outcome) => {
            if frame.service_terminal != Some(outcome) || status.running {
                return Err(io::Error::other(
                    "Common terminal differs from actual release",
                ));
            }
            ("secure_udp_common_terminal", Some(format!("{outcome:?}")))
        }
    };
    bounded(json!({"event":name,"schema":1,"status":status,"outcome":outcome}))
}
