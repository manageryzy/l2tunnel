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
    let resources = if profile.raw_policy().is_some() {
        profile.validate_raw_request()?;
        profile.requested_resources(role)
    } else {
        profile.runtime_contract(role)?.resources()
    };
    let parameters = profile.parameters();
    let mut output = Vec::new();
    output.try_reserve_exact(17).map_err(io::Error::other)?;
    let work = resources
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
    if let Some(requested) = profile.compact_wire() {
        output[0]["compact_wire"] = json!({
            "requested":crate::secure_udp::common_status::CompactWireSelection::from_selection(requested)?,
            "effective":null,"checks":null,"feedback_packet_number":null,
            "appearance":"initial-only","established_mimic":false,
            "control_protection":"chacha20-poly1305","retiring_feedback_protection":"chacha20-poly1305"
        });
        output[0] = bounded(std::mem::take(&mut output[0]))?;
    }
    if let Some(requested) =
        crate::secure_udp::common_status::AckPolicies::from_policies(profile.ack_coalescing())?
    {
        output[0]["ack_coalescing"] = json!({"requested":requested,"effective":null,"observation":null,"pending_read":null,"policy_switching":false});
        output[0] = bounded(std::mem::take(&mut output[0]))?;
    }
    if let Some(requested) =
        crate::secure_udp::common_status::RollingIngressPolicies::from_policies(
            profile.rolling_ingress(),
        )?
    {
        output[0]["rolling_ingress"] = json!({"requested":requested,"effective":null,
            "observation":null,"policy_switching":false});
        output[0] = bounded(std::mem::take(&mut output[0]))?;
    }
    if let Some(requested) =
        crate::secure_udp::common_status::ConnectionIngressPolicies::from_policies(
            profile.connection_ingress(),
        )?
    {
        output[0]["connection_ingress"] = json!({"requested":requested,"effective":null,
            "observation":null,"policy_switching":false});
        output[0] = bounded(std::mem::take(&mut output[0]))?;
    }
    if let Some(requested) = profile.rolling_fragments() {
        output[0]["rolling_fragments"] = json!({"requested": crate::secure_udp::common_status::RollingFragments::from_policy(requested)?,
            "effective":null,"policy_switching":false});
        output[0] = bounded(std::mem::take(&mut output[0]))?;
    }
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

/// Explicit requested raw policy only; no TLS proof, syscall or effective E1.
pub(super) fn raw_inspection(
    profile: &Profile,
    role: Role,
    raw: &crate::raw_packet::common::Settings,
) -> io::Result<Vec<Value>> {
    if profile.raw_binding().is_some() {
        return Err(io::Error::other(
            "offline raw inspection requires an unbound request",
        ));
    }
    let mut output = inspection(profile, role)?;
    let header = output
        .first_mut()
        .and_then(Value::as_object_mut)
        .ok_or_else(|| io::Error::other("raw inspection header absent"))?;
    let cover = header
        .remove("carrier")
        .ok_or_else(|| io::Error::other("raw inner cover absent"))?;
    header.insert(
        "event".into(),
        json!("secure_udp_common_requested_carrier_plan"),
    );
    header.insert("carrier".into(), json!("raw-packet"));
    header.insert("udp_cover".into(), cover);
    header.remove("configuration");
    header.remove("envelope");
    let initial = header
        .remove("initial")
        .ok_or_else(|| io::Error::other("raw requested initial absent"))?;
    header.insert("requested_initial".into(), initial);
    header.insert(
        "requested_configuration".into(),
        json!(profile.requested_configuration()?.0),
    );
    header.insert(
        "requested_envelope".into(),
        json!(profile.requested_envelope().as_bytes()),
    );
    header.insert("configuration_scope".into(), json!("requested_raw_E0"));
    for field in [
        "effective_configuration",
        "effective_envelope",
        "effective_catalog",
    ] {
        header.insert(field.into(), Value::Null);
    }
    header.insert("authenticated_outer_binding_required".into(), json!(true));
    header.insert("outer_tls_trust_validated".into(), json!(false));
    let policy = raw.packet_policy();
    let geometry = policy.record_geometry().map_err(io::Error::other)?;
    let (local, peer) = raw.forward();
    header.insert("outer_policy".into(), json!({"version":1,"backend":"raw-common-carrier-v1",
        "duplex":if raw.duplex()==l2tunnel_core::Duplex::Half {"half"}else{"full"},
        "first_local":local.to_string(),"first_peer":peer.to_string(),
        "path_mtu":geometry.path_mtu,"protection":match policy.protection {l2tunnel_raw_io::handoff::pairing::packet::Protection::ChaCha20Poly1305=>"aead",l2tunnel_raw_io::handoff::pairing::packet::Protection::HmacSha256=>"integrity"},
        "ip_tcp_bytes":geometry.ip_tcp_bytes,"record_overhead_bytes":geometry.record_overhead_bytes,
        "max_record_bytes":geometry.max_record_bytes,
        "policy_digest":policy.configuration_digest(l2tunnel_core::ConfigDigest(profile.requested_configuration()?.0)).map_err(io::Error::other)?,
        "queue_packets":policy.queue_packets,"horizon_bytes":policy.horizon_bytes,"minimum_transfer_bytes":policy.minimum_transfer_bytes,
        "bytes_per_second":policy.bytes_per_second,"packets_per_second":policy.packets_per_second,
        "burst_bytes":policy.burst_bytes,"burst_packets":policy.burst_packets,"max_key_packets":policy.max_key_packets,"max_key_bytes":policy.max_key_bytes,
        "kernel_firewall_ready":false,"native_qualified":false,"congestion_control":false,"clean_close":false}));
    if profile.compact_wire().is_some() {
        header.insert("outer_policy_scope".into(), json!("bootstrap"));
        header.insert("requested_final_framing".into(), json!({
            "ip_tcp_bytes":geometry.ip_tcp_bytes,
            "data_overhead_bytes":geometry.ip_tcp_bytes + l2tunnel::secure_record::compact::DATA_OVERHEAD,
            "control_feedback_overhead_bytes":geometry.ip_tcp_bytes + l2tunnel::secure_record::compact::AUTHENTICATED_OVERHEAD,
            "protection_layers":1,"phase_envelope":false,"raw_datagram_envelope":false
        }));
        header.insert("effective_final_framing".into(), Value::Null);
    }
    output[0] = bounded(std::mem::take(&mut output[0]))?;
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
