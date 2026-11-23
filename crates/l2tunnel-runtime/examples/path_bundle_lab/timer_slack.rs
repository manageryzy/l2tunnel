//! Optional Linux thread-local wake precision for the established-path experiment.

use rustix::thread::{current_timer_slack, set_current_timer_slack};
use serde::Serialize;
use std::num::NonZeroU64;

#[derive(Serialize)]
pub(super) struct Setting {
    requested_ns: Option<NonZeroU64>,
    before_ns: u64,
    effective_ns: u64,
}

impl Setting {
    pub(super) fn apply(requested_ns: Option<NonZeroU64>) -> super::Result<Self> {
        let before_ns = current_timer_slack()?;
        let mut setting = Self {
            requested_ns,
            before_ns,
            effective_ns: before_ns,
        };
        if let Some(value) = requested_ns {
            set_current_timer_slack(Some(value))?;
            setting.effective_ns = current_timer_slack()?;
            if setting.effective_ns != value.get() {
                return Err("Linux timer slack differs from requested value".into());
            }
        }
        Ok(setting)
    }
}

impl Drop for Setting {
    fn drop(&mut self) {
        if self.requested_ns.is_some() {
            // The adapter owns this thread. Restore on normal and error exits;
            // never alter host timer policy or another thread's scheduling.
            let _ = set_current_timer_slack(NonZeroU64::new(self.before_ns));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_observes_and_selected_precision_restores_the_calling_thread()
    -> super::super::Result<()> {
        let before = current_timer_slack()?;
        {
            let observed = Setting::apply(None)?;
            assert_eq!(
                (observed.before_ns, observed.effective_ns),
                (before, before)
            );
        }
        {
            let selected = Setting::apply(NonZeroU64::new(1))?;
            assert_eq!(selected.before_ns, before);
            assert_eq!(current_timer_slack()?, 1);
        }
        assert_eq!(current_timer_slack()?, before);
        Ok(())
    }
}
