//! Bounded full Common plan pages and actual shared-service events.
use super::transaction_cli_output::bounded;
use crate::secure_udp::{
    common_status::CanonicalConfiguration, common_transaction_profile::Profile,
};
use l2tunnel::record_configuration::Configuration;
use l2tunnel_security::Role;
use serde_json::{Value, json};
use std::io;

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
