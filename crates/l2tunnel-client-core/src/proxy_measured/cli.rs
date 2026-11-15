//! Explicit measured Linux selection through the shared proxy lifecycle owner.
use super::*;
use crate::proxy_measured as client;

#[cfg(target_os = "linux")]
pub(super) async fn execute(
    command: &str,
    options: &BTreeMap<String, String>,
    config: ConnectionConfig,
    path: &str,
) -> io::Result<()> {
    let settings = client::Settings::from_json(&bounded_file(path, client::MAX_POLICY_BYTES)?)?;
    client::runtime_config(config, &settings)?;
    let device = DeviceSpec::parse(options, config)?;
    super::shared::execute(
        command,
        options,
        config,
        device,
        super::shared::Policy::Measured(settings),
    )
    .await
}
