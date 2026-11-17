//! Complete current runtime input fixture; never a product default.
use l2tunnel_security as security;
use serde_json::{Value, json};
fn direction(forward: bool) -> Value {
    json!({
        "channels": if forward { 2 } else { 3 },
        "layer": "ip", "max_native": 1500,
        "bytes_per_second": if forward { 1_250_001 } else { 625_013 },
        "datagram_bytes": if forward { 1200 } else { 1024 },
        "window": if forward { 7 } else { 11 },
        "repair_numerator": if forward { 1 } else { 2 },
        "repair_denominator": if forward { 3 } else { 7 },
        "flow_sources": 64, "queue_bytes": 8192,
        "max_packet": 1500 + l2tunnel_swift::header::MAX_EXPANSION,
        "flush_micros": if forward { 123 } else { 321 },
        "feedback_micros": if forward { 5003 } else { 5007 },
        "tail_micros": if forward { 10001 } else { 10009 },
        "min_rto_micros": if forward { 20003 } else { 20011 },
        "max_rto_micros": if forward { 1_000_007 } else { 1_000_009 },
    })
}

/// Complete test witness only; this is not a product default or sample fallback.
pub(super) fn template() -> Value {
    let initial = json!({"path_mtu":1500,"forward":direction(true),"reverse":direction(false)});
    let mut target = initial.clone();
    target["path_mtu"] = json!(1600);
    target["forward"]["channels"] = json!(4);
    target["reverse"]["channels"] = json!(1);
    target["forward"]["bytes_per_second"] = json!(1_375_007);
    target["reverse"]["bytes_per_second"] = json!(575_011);
    target["forward"]["datagram_bytes"] = json!(1280);
    target["reverse"]["datagram_bytes"] = json!(1100);
    let message = json!({
        "max_message_bytes":4096,"max_outbound_messages":4,
        "max_outbound_bytes":131072,"max_fragments":32,
        "max_reassembly_bytes":16384,"max_incomplete_messages":2,
        "message_lifetime_micros":5_000_000,"work_per_call":8,
    });
    json!({
        "version":1,"backend":"generic_swift_v1","initial_index":0,
        "catalog":[initial,target],
        "transaction":{"retry_ms":10,"phase_timeout_ms":500,"reconcile_timeout_ms":1000,
            "max_operation_ms":1500,"retained_bytes":64*1024*1024},
        "runtime":{
            "control_epoch":1,"data_epoch":1,
            "legacy_policy":{"transaction_micros":10_000_000,"max_outbound":32},
            "security":{"packets_per_key":security::MAX_PACKETS_PER_KEY,
                "max_body_bytes_per_key":security::MAX_BODY_BYTES_PER_KEY},
            "control":{
                "recovery":{"max_source_bytes":256,"send_bytes":2048,"receive_bytes":2048,
                    "send_records":8,"receive_records":8,"initial_rto_micros":10000,
                    "maximum_rto_micros":100000,"ack_delay_micros":1000,"max_retries":32},
                "interval_micros":10000,"packets_per_interval":4,"bytes_per_interval":4096},
            "streams":{"transaction":message.clone(),"liveness":message.clone(),"data_feedback":message},
            "wire":{"initiator_burst_bytes":8192,"responder_burst_bytes":6144},
            "work":{"receive_interval_micros":1000,"receive_packets":256,
                "send_batch":64,"native_read_batch":64,"native_write_batch":64},
            "native":{"pending_packets":64,"pending_bytes":96000,"stall_timeout_micros":10_000_000},
            "lifetime":{"lease_micros":60_000_000,"ping_interval_micros":1_000_000,
                "pong_timeout_micros":5_000_000},
            "report_interval_micros":null,
        },
    })
}
