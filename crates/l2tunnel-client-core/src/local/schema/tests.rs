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
