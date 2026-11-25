//! Local API live-tuning controls (docs/modules/live-tuning.md, decision
//! 10): the session's current setting and choices, and resolving a wanted
//! setting to the exact member of the session's authenticated catalog.
use super::Handle;
use crate::local::{TuningSetting, TuningView};
use l2tunnel::live_tuning;
use l2tunnel::record_configuration::{Configuration, Descriptor};

impl Handle {
    /// The live session's catalog and current entry.
    fn tuning_frame(
        &self,
    ) -> Result<(super::SecureUdpCommonFrame, Option<Configuration>), &'static str> {
        let snapshot = self.snapshot();
        let frame = snapshot
            .runtime
            .as_ref()
            .and_then(super::Observation::secure_udp_common)
            .ok_or("closed")?
            .clone();
        let current = frame.runtime.as_ref().map(|runtime| runtime.current);
        Ok((frame, current))
    }

    /// The controls of the live session.
    pub(super) fn tuning_view(&self) -> Result<TuningView, &'static str> {
        let (frame, current) = self.tuning_frame()?;
        let profile = &frame.requested;
        let settings = profile
            .catalog()
            .descriptors()
            .iter()
            .filter_map(|descriptor| live_tuning::setting(descriptor).ok());
        let current = current.and_then(|current| live_tuning::setting(current.descriptor()).ok());
        let device = frame
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.device_mtu)
            .map(crate::secure_udp::common_status::DeviceMtuStatus::from);
        Ok(TuningView::new(
            profile.live_catalog().is_some(),
            current,
            settings,
            device,
        ))
    }

    /// The catalog member a wanted setting names: the current entry with
    /// only the tuned fields changed when the catalog holds it, otherwise
    /// the single entry with that setting.
    pub(super) fn tuning_target(
        &self,
        wanted: &TuningSetting,
    ) -> Result<Configuration, &'static str> {
        let wanted = wanted.setting().map_err(|_| "invalid_setting")?;
        let (frame, current) = self.tuning_frame()?;
        let current = current.ok_or("status_unavailable")?;
        let catalog = frame.requested.catalog().descriptors();
        let exact = live_tuning::tune(current.descriptor(), wanted)
            .ok()
            .filter(|tuned| catalog.contains(tuned));
        let target: Descriptor = match exact {
            Some(tuned) => tuned,
            None => {
                let mut matching = catalog.iter().filter(|descriptor| {
                    live_tuning::setting(descriptor).is_ok_and(|setting| setting == wanted)
                });
                match (matching.next(), matching.next()) {
                    (Some(only), None) => *only,
                    (None, _) => return Err("not_in_catalog"),
                    (Some(_), Some(_)) => return Err("ambiguous_setting"),
                }
            }
        };
        Configuration::new(current.envelope(), target).map_err(|_| "invalid_configuration")
    }
}
