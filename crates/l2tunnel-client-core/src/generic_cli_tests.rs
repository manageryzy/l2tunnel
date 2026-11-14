//! Fail complete-configuration authority checks before making any IPC request.
use super::*;

#[test]
fn complete_configuration_argument_is_bounded_before_retention() -> io::Result<()> {
    let allowed = ["--configuration"];
    let maximum = "0".repeat(608);
    assert_eq!(
        options(&["--configuration".into(), maximum.clone()], &allowed)?["--configuration"],
        maximum
    );
    assert!(options(&["--configuration".into(), "0".repeat(609)], &allowed).is_err());
    Ok(())
}

#[tokio::test]
async fn complete_configuration_requires_explicit_v3_before_value_or_socket_access()
-> io::Result<()> {
    for version in [None, Some("1"), Some("2"), Some("4"), Some("invalid")] {
        let mut values = BTreeMap::from([
            (
                "--control-socket".into(),
                "/absent/l2tunnel-test-control.sock".into(),
            ),
            ("--configuration".into(), "not-canonical".into()),
        ]);
        if let Some(version) = version {
            values.insert("--api-version".into(), version.into());
        }
        let error = execute_api("switch-swift-configuration", &values)
            .await
            .err()
            .ok_or_else(|| input("unsupported version accepted"))?;
        assert_eq!(
            error.kind(),
            io::ErrorKind::InvalidInput,
            "{version:?}: {error}"
        );
        if version != Some("invalid") {
            assert!(error.to_string().contains("explicit --api-version 3"));
        }
    }
    Ok(())
}

#[tokio::test]
async fn canonical_configuration_rejection_precedes_any_ipc() -> io::Result<()> {
    for text in [
        String::new(),
        "0".repeat(607),
        "0".repeat(609),
        "A".repeat(608),
        "0".repeat(608),
    ] {
        let values = BTreeMap::from([
            (
                "--control-socket".into(),
                "/absent/l2tunnel-test-control.sock".into(),
            ),
            ("--configuration".into(), text),
            ("--api-version".into(), "3".into()),
        ]);
        let error = execute_api("switch-swift-configuration", &values)
            .await
            .err()
            .ok_or_else(|| input("noncanonical value accepted"))?;
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{error}");
    }
    Ok(())
}
