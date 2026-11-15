//! Pure schema qualification; no OS socket module or Tokio API is imported.
use super::*;
#[test]
fn legacy_request_and_optional_free_response_bytes_remain_literal() -> Result<(), serde_json::Error>
{
    for (action, expected) in [
        (
            Action::Status {},
            r#"{"version":1,"action":{"command":"status"}}"#,
        ),
        (
            Action::SwitchCompression {
                compression: Compression::Off,
            },
            r#"{"version":1,"action":{"command":"switch_compression","compression":"off"}}"#,
        ),
        (
            Action::DrainProxy {},
            r#"{"version":1,"action":{"command":"drain_proxy"}}"#,
        ),
        (
            Action::DrainOpenVpn {},
            r#"{"version":1,"action":{"command":"drain_open_vpn"}}"#,
        ),
    ] {
        let request = Request {
            version: VERSION,
            action,
        };
        assert_eq!(serde_json::to_string(&request)?, expected);
        assert_eq!(serde_json::from_str::<Request>(expected)?, request);
    }
    let response = Response {
        version: VERSION,
        ok: true,
        code: "ok".into(),
        state: Some(Snapshot {
            epoch: 2,
            phase: "idle".into(),
            compression: Compression::Lz4,
            active: None,
            proxy: None,
            openvpn_drain: None,
            raw_packet: None,
            rolling: None,
            #[cfg(unix)]
            swift: None,
            #[cfg(unix)]
            secure_udp: None,
            transaction: None,
            common: None,
        }),
    };
    let expected = r#"{"version":1,"ok":true,"code":"ok","state":{"epoch":2,"phase":"idle","compression":"lz4"}}"#;
    assert_eq!(serde_json::to_string(&response)?, expected);
    assert_eq!(serde_json::from_str::<Response>(expected)?, response);
    Ok(())
}
#[test]
fn strict_types_reject_unknown_and_duplicate_fields_without_transport() {
    for text in [
        r#"{"version":1,"version":1,"action":{"command":"status"}}"#,
        r#"{"version":1,"action":{"command":"status","extra":0}}"#,
        r#"{"version":1,"action":{"command":"switch_compression","compression":"off","compression":"lz4"}}"#,
    ] {
        assert!(serde_json::from_str::<Request>(text).is_err(), "{text}");
    }
    for text in [
        r#"{"version":1,"ok":true,"code":"ok","state":null,"extra":0}"#,
        r#"{"version":1,"ok":true,"code":"ok","state":{"epoch":1,"phase":"idle","compression":"off","epoch":2}}"#,
    ] {
        assert!(serde_json::from_str::<Response>(text).is_err(), "{text}");
    }
}

#[test]
fn legacy_lifecycle_and_partial_swift_request_bytes_remain_literal() -> Result<(), serde_json::Error>
{
    for (version, action, expected) in [
        (
            VERSION,
            Action::Disconnect {},
            r#"{"version":1,"action":{"command":"disconnect"}}"#,
        ),
        (
            VERSION,
            Action::Reconnect {},
            r#"{"version":1,"action":{"command":"reconnect"}}"#,
        ),
        (
            VERSION,
            Action::SetSwiftPolicy {
                policy: SwiftChange::default(),
            },
            r#"{"version":1,"action":{"command":"set_swift_policy","policy":{}}}"#,
        ),
        (
            SECURE_UDP_VERSION,
            Action::Status {},
            r#"{"version":2,"action":{"command":"status"}}"#,
        ),
        (
            SECURE_UDP_VERSION,
            Action::Disconnect {},
            r#"{"version":2,"action":{"command":"disconnect"}}"#,
        ),
        (
            SECURE_UDP_VERSION,
            Action::Reconnect {},
            r#"{"version":2,"action":{"command":"reconnect"}}"#,
        ),
        (
            SECURE_UDP_VERSION,
            Action::SetSwiftPolicy {
                policy: SwiftChange {
                    forward_kbit: Some(8000),
                    reverse_kbit: None,
                    channels: Some(3),
                    window: None,
                    repair_permille: Some(125),
                    path_mtu: Some(1500),
                },
            },
            r#"{"version":2,"action":{"command":"set_swift_policy","policy":{"forward_kbit":8000,"channels":3,"repair_permille":125,"path_mtu":1500}}}"#,
        ),
    ] {
        let value = Request { version, action };
        assert_eq!(serde_json::to_vec(&value)?, expected.as_bytes());
        assert_eq!(serde_json::from_str::<Request>(expected)?, value);
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn complete_version_two_secure_udp_reply_bytes_remain_literal() -> Result<(), serde_json::Error> {
    use crate::secure_udp::status::{Policy, Status};
    // A serialization fixture, not fabricated authentication/runtime evidence.
    let requested = Policy {
        path_mtu: 1500,
        forward_kbit: 8000,
        reverse_kbit: 4000,
        channels: 2,
        window: 7,
        repair_permille: 125,
    };
    let effective = Policy {
        path_mtu: 1600,
        forward_kbit: 9000,
        reverse_kbit: 3000,
        channels: 3,
        window: 11,
        repair_permille: 250,
    };
    let status = Status {
        generation: 7,
        carrier: "quic-like".into(),
        algorithm: "swift".into(),
        protection: "chacha20-poly1305".into(),
        requested,
        effective,
        maximum_path_mtu: 9000,
        running: true,
        session: [1; 16],
        transcript: [2; 32],
        configuration: [3; 32],
        outer: [4; 32],
        member: [5; 32],
        initiator_noise: [6; 32],
        responder_noise: [7; 32],
        local: "127.0.0.1:41321".into(),
        peer: "127.0.0.1:41322".into(),
        policy_epoch: 9,
        pending_epoch: Some(10),
        elapsed_micros: 12345,
        wire_packets: 11,
        wire_bytes: 1200,
        socket_accepted_packets: 10,
        socket_accepted_ip_bytes: 1100,
        socket_drops: 1,
        socket_receive_errors: 2,
        received_packets: 12,
        rejected_packets: 3,
        replay_rejections: 4,
        native_read: 13,
        native_written: 14,
        native_oversize: 5,
        native_backpressure_drops: 6,
        native_pending_packets: 2,
        native_pending_bytes: 1024,
        swift_unconfirmed: 7,
        control_send_records: 3,
        control_send_bytes: 768,
        control_receive_records: 2,
        control_receive_bytes: 512,
        ping: Some(27),
        ping_deadline_micros: Some(20000),
        last_verified_micros: Some(12000),
        last_pong_micros: Some(11000),
        user_number: Some(31),
        control_number: Some(32),
        user_generation: Some(1),
        control_generation: Some(2),
        terminal: None,
        policy_change: true,
        reconnect: true,
        retained_state_recovery: false,
        cross_profile_switching: false,
        fresh_rekey: false,
    };
    let response = Response {
        version: SECURE_UDP_VERSION,
        ok: true,
        code: "ok".into(),
        state: Some(Snapshot {
            epoch: 9,
            phase: "forwarding".into(),
            compression: Compression::Off,
            active: None,
            proxy: None,
            openvpn_drain: None,
            raw_packet: None,
            rolling: None,
            swift: None,
            secure_udp: Some(status),
            transaction: None,
            common: None,
        }),
    };
    let expected = r#"{"version":2,"ok":true,"code":"ok","state":{"epoch":9,"phase":"forwarding","compression":"off","secure_udp":{"generation":7,"carrier":"quic-like","algorithm":"swift","protection":"chacha20-poly1305","requested":{"path_mtu":1500,"forward_kbit":8000,"reverse_kbit":4000,"channels":2,"window":7,"repair_permille":125},"effective":{"path_mtu":1600,"forward_kbit":9000,"reverse_kbit":3000,"channels":3,"window":11,"repair_permille":250},"maximum_path_mtu":9000,"running":true,"session":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"transcript":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"configuration":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"outer":[4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4],"member":[5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5],"initiator_noise":[6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6],"responder_noise":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],"local":"127.0.0.1:41321","peer":"127.0.0.1:41322","policy_epoch":9,"pending_epoch":10,"elapsed_micros":12345,"wire_packets":11,"wire_bytes":1200,"socket_accepted_packets":10,"socket_accepted_ip_bytes":1100,"socket_drops":1,"socket_receive_errors":2,"received_packets":12,"rejected_packets":3,"replay_rejections":4,"native_read":13,"native_written":14,"native_oversize":5,"native_backpressure_drops":6,"native_pending_packets":2,"native_pending_bytes":1024,"swift_unconfirmed":7,"control_send_records":3,"control_send_bytes":768,"control_receive_records":2,"control_receive_bytes":512,"ping":27,"ping_deadline_micros":20000,"last_verified_micros":12000,"last_pong_micros":11000,"user_number":31,"control_number":32,"user_generation":1,"control_generation":2,"terminal":null,"policy_change":true,"reconnect":true,"retained_state_recovery":false,"cross_profile_switching":false,"fresh_rekey":false}}}"#;
    assert_eq!(serde_json::to_vec(&response)?, expected.as_bytes());
    assert_eq!(serde_json::from_str::<Response>(expected)?, response);
    Ok(())
}
