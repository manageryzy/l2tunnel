//! Explicit process-host comparison, separate from peer and service configuration.
use std::{collections::BTreeMap, io};
use tokio::runtime::{Builder, Runtime, RuntimeFlavor};

const OPTION: &str = "--runtime-model";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Model {
    CurrentThread,
    MultiThread,
}

impl Model {
    fn name(self) -> &'static str {
        match self {
            Self::CurrentThread => "current-thread",
            Self::MultiThread => "multi-thread",
        }
    }
}

#[derive(Debug, serde::Serialize)]
pub(super) struct Observation {
    event: &'static str,
    schema: u16,
    requested: &'static str,
    effective: &'static str,
    worker_threads: usize,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// Remove only a fully validated host option; refusal leaves all inputs intact.
pub(super) fn take(options: &mut BTreeMap<String, String>) -> io::Result<Option<Model>> {
    take_for_platform(options, cfg!(target_os = "linux"))
}

fn take_for_platform(
    options: &mut BTreeMap<String, String>,
    linux: bool,
) -> io::Result<Option<Model>> {
    let Some(value) = options.get(OPTION) else {
        return Ok(None);
    };
    let model = match value.as_str() {
        "current-thread" => Model::CurrentThread,
        "multi-thread" => Model::MultiThread,
        _ => {
            return Err(invalid(
                "runtime-model must be current-thread or multi-thread",
            ));
        }
    };
    if !linux
        || !matches!(
            options.get("--carrier").map(String::as_str),
            Some("quic-like" | "media-like")
        )
        || options.get("--record-profile").map(String::as_str) != Some("swift")
    {
        return Err(invalid(
            "runtime-model requires Linux quic-like or media-like Swift connect/serve",
        ));
    }
    options.remove(OPTION);
    Ok(Some(model))
}

/// Keep the omitted and explicit multithread builder identical to the old host.
pub(super) fn build(model: Option<Model>) -> io::Result<(Runtime, Option<Observation>)> {
    let mut builder = match model {
        Some(Model::CurrentThread) => Builder::new_current_thread(),
        None | Some(Model::MultiThread) => Builder::new_multi_thread(),
    };
    let runtime = builder.enable_all().build()?;
    let observation = model
        .map(|requested| {
            let effective = match runtime.handle().runtime_flavor() {
                RuntimeFlavor::CurrentThread => "current-thread",
                RuntimeFlavor::MultiThread => "multi-thread",
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "unsupported actual runtime flavor",
                    ));
                }
            };
            Ok(Observation {
                event: "host_runtime",
                schema: 1,
                requested: requested.name(),
                effective,
                worker_threads: runtime.metrics().num_workers(),
            })
        })
        .transpose()?;
    Ok((runtime, observation))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selected(carrier: &str, model: &str) -> BTreeMap<String, String> {
        [
            ("--carrier", carrier),
            ("--record-profile", "swift"),
            ("--runtime-model", model),
            ("--path-mtu", "1500"),
            ("--noise-profile", "ikpsk2"),
            ("--swift-forward-kbit", "99000"),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
    }

    #[test]
    fn omitted_option_preserves_every_protocol_value_on_any_platform() -> io::Result<()> {
        let mut options = selected("quic-like", "current-thread");
        options.remove(OPTION);
        let original = options.clone();
        assert_eq!(take_for_platform(&mut options, true)?, None);
        assert_eq!(options, original);
        assert_eq!(take_for_platform(&mut options, false)?, None);
        assert_eq!(options, original);
        Ok(())
    }

    #[test]
    fn explicit_models_consume_only_host_field_for_both_carriers() -> io::Result<()> {
        for carrier in ["quic-like", "media-like"] {
            for model in [Model::CurrentThread, Model::MultiThread] {
                let mut options = selected(carrier, model.name());
                let mut expected = options.clone();
                expected.remove(OPTION);
                assert_eq!(take_for_platform(&mut options, true)?, Some(model));
                assert_eq!(options, expected);
            }
        }
        Ok(())
    }

    #[test]
    fn malformed_and_unsupported_host_selections_are_atomic() {
        for value in ["", "current", "CURRENT-THREAD", "multi-thread ", "2"] {
            let mut options = selected("quic-like", value);
            let original = options.clone();
            assert!(take_for_platform(&mut options, true).is_err());
            assert_eq!(options, original);
        }
        for carrier in ["tcp", "udp", "quic", "openvpn-like", "https", ""] {
            let mut options = selected(carrier, "current-thread");
            let original = options.clone();
            assert!(take_for_platform(&mut options, true).is_err());
            assert_eq!(options, original);
        }
        for profile in ["frame", "packed", "rolling", ""] {
            let mut options = selected("media-like", "multi-thread");
            options.insert("--record-profile".into(), profile.into());
            let original = options.clone();
            assert!(take_for_platform(&mut options, true).is_err());
            assert_eq!(options, original);
        }
        for missing in ["--carrier", "--record-profile"] {
            let mut options = selected("quic-like", "current-thread");
            options.remove(missing);
            let original = options.clone();
            assert!(take_for_platform(&mut options, true).is_err());
            assert_eq!(options, original);
        }
        let mut options = selected("quic-like", "current-thread");
        let original = options.clone();
        assert!(take_for_platform(&mut options, false).is_err());
        assert_eq!(options, original);
    }

    #[test]
    fn public_take_observes_actual_platform_without_fallback() -> io::Result<()> {
        let mut options = selected("quic-like", "current-thread");
        let original = options.clone();
        if cfg!(target_os = "linux") {
            assert_eq!(take(&mut options)?, Some(Model::CurrentThread));
            assert!(!options.contains_key(OPTION));
        } else {
            assert!(take(&mut options).is_err());
            assert_eq!(options, original);
        }
        Ok(())
    }

    #[test]
    fn shared_cli_parser_rejects_missing_duplicate_and_non_host_command_options() {
        for args in [
            vec!["--runtime-model"],
            vec!["--runtime-model", "--carrier"],
            vec![
                "--runtime-model",
                "current-thread",
                "--runtime-model",
                "multi-thread",
            ],
        ] {
            let args: Vec<String> = args.into_iter().map(String::from).collect();
            assert!(super::super::options(&args, &[OPTION]).is_err());
        }
        let args = [OPTION.into(), "current-thread".into()];
        for allowed in [&["--control-socket"][..], &["--private", "--public"][..]] {
            assert!(super::super::options(&args, allowed).is_err());
        }
    }

    #[test]
    fn actual_non_host_commands_refuse_selector_before_their_side_effects() {
        for command in [
            "keygen",
            "status",
            "disconnect",
            "reconnect",
            "drain-proxy",
            "common-catalog",
            "switch-common-configuration",
        ] {
            let args = [command, OPTION, "current-thread"].map(String::from);
            assert_eq!(
                super::super::main_entry(args),
                std::process::ExitCode::from(1)
            );
        }
    }

    #[test]
    fn actual_hosts_keep_root_placement_drivers_and_explicit_observation() -> io::Result<()> {
        // Build sequentially: an unmodified default pool can contain many workers.
        for model in [None, Some(Model::MultiThread), Some(Model::CurrentThread)] {
            let caller = std::thread::current().id();
            let (runtime, observation) = build(model)?;
            let expected = if model == Some(Model::CurrentThread) {
                RuntimeFlavor::CurrentThread
            } else {
                RuntimeFlavor::MultiThread
            };
            assert_eq!(runtime.handle().runtime_flavor(), expected);
            let workers = runtime.metrics().num_workers();
            assert!(workers >= 1);
            if model == Some(Model::CurrentThread) {
                assert_eq!(workers, 1);
            }
            runtime.block_on(async {
                assert_eq!(std::thread::current().id(), caller);
                assert_eq!(tokio::runtime::Handle::current().runtime_flavor(), expected);
                tokio::time::timeout(std::time::Duration::from_secs(1), async {
                    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
                    socket.send_to(b"host", socket.local_addr()?).await?;
                    let mut output = [0u8; 4];
                    let (length, _) = socket.recv_from(&mut output).await?;
                    assert_eq!(length, 4);
                    assert_eq!(&output, b"host");
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    Ok::<(), io::Error>(())
                })
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "host driver test deadline"))?
            })?;
            match (model, observation) {
                (None, None) => {}
                (Some(requested), Some(observed)) => {
                    let value = serde_json::to_value(observed).map_err(io::Error::other)?;
                    assert_eq!(value.as_object().map(|object| object.len()), Some(5));
                    assert_eq!(value["event"], "host_runtime");
                    assert_eq!(value["schema"], 1);
                    assert_eq!(value["requested"], requested.name());
                    assert_eq!(value["effective"], requested.name());
                    assert_eq!(value["worker_threads"], workers);
                }
                _ => {
                    return Err(io::Error::other(
                        "host observation did not match explicit selection",
                    ));
                }
            }
            drop(runtime);
        }
        Ok(())
    }
}
