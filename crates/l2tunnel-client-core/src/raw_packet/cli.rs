//! Explicit migration diagnostic for the retired standalone raw record owner.
use super::*;
pub(super) const OPTIONS: &[&str] = &["--raw-policy", "--raw-mark"];
pub(super) const HELP: &str = "Raw carrier: --carrier raw-packet --record-profile common --common-transaction-plan JSON --raw-policy JSON --raw-mark N. Select Aligned/Packed recovery and the explicit native delivery window in the Common catalog. The standalone raw-packet envelope has been removed.";
pub(super) fn selection(
    options: &BTreeMap<String, String>,
    _config: ConnectionConfig,
) -> io::Result<()> {
    if options.get("--carrier").map(String::as_str) == Some("raw-packet")
        || OPTIONS.iter().any(|key| options.contains_key(*key))
    {
        return Err(input(
            "standalone raw-packet has been removed; use --carrier raw-packet --record-profile common with a Common plan, explicit recovery and native delivery window",
        ));
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retired_raw_selector_requires_current_common_plan() {
        let options = BTreeMap::from([("--carrier".to_owned(), "raw-packet".to_owned())]);
        assert!(
            selection(
                &options,
                configuration(&BTreeMap::new()).expect("default CLI configuration")
            )
            .is_err()
        );
        assert!(
            selection(
                &BTreeMap::new(),
                configuration(&BTreeMap::new()).expect("default CLI configuration")
            )
            .is_ok()
        );
    }
}
