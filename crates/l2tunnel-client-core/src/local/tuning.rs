//! Live-tuning controls of a connected session (docs/modules/live-tuning.md,
//! owner decision 10): read the current setting and what each control can
//! choose, and switch by setting. The service resolves a setting to the
//! exact member of the session's authenticated catalog and runs the normal
//! hot switch; frontends never handle catalog entries themselves.
use crate::secure_udp::live_tuning::{parse_repair, repair_text};
use l2tunnel::live_tuning::{Repair, Setting};
use serde::{Deserialize, Serialize};
use std::io;

/// Most entries in one view (the generated catalog's bound).
pub const TUNING_ENTRIES_LIMIT: usize = l2tunnel::live_tuning::MAX_ENTRIES;

/// One live-tuning setting.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TuningSetting {
    /// FEC repair: `off` or a rate like `1/4` (both directions).
    pub repair: String,
    /// Largest inner packet; the device MTU follows it.
    pub device_mtu: u16,
    /// Outer IP packet ceiling.
    pub path_mtu: u16,
}
impl TuningSetting {
    /// The DTO of a protocol setting.
    pub fn of(setting: Setting) -> Self {
        Self {
            repair: repair_text(setting.repair),
            device_mtu: setting.device_mtu,
            path_mtu: setting.path_mtu,
        }
    }
    /// The protocol setting; refuses a malformed repair text.
    pub fn setting(&self) -> io::Result<Setting> {
        Ok(Setting {
            repair: parse_repair("repair", &self.repair)?,
            device_mtu: self.device_mtu,
            path_mtu: self.path_mtu,
        })
    }
}

/// What the session's controls can choose.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TuningView {
    /// The catalog was generated from this client's live-tuning proposal
    /// (otherwise the entries are the plan's own).
    pub live: bool,
    /// The setting in effect; absent before the runtime reports or when the
    /// current entry is not a tunable Swift profile.
    pub current: Option<TuningSetting>,
    /// Repair choices present in the catalog: `off` first, then rates from
    /// lowest to highest.
    pub repair: Vec<String>,
    /// Device MTU choices present in the catalog, ascending.
    pub device_mtu: Vec<u16>,
    /// Path MTU choices present in the catalog, ascending.
    pub path_mtu: Vec<u16>,
    /// Every reachable combination, in catalog order; a combination not
    /// listed cannot be switched to.
    pub entries: Vec<TuningSetting>,
    /// Device MTU kept in step by the service, when it does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<crate::secure_udp::common_status::DeviceMtuStatus>,
}
impl TuningView {
    /// Build the view from the catalog's settings (entries that are not
    /// tunable Swift profiles are left out).
    pub fn new(
        live: bool,
        current: Option<Setting>,
        settings: impl IntoIterator<Item = Setting>,
        device: Option<crate::secure_udp::common_status::DeviceMtuStatus>,
    ) -> Self {
        let mut entries: Vec<TuningSetting> = Vec::new();
        let mut repairs: Vec<Repair> = Vec::new();
        let mut device_mtu = Vec::new();
        let mut path_mtu = Vec::new();
        for setting in settings.into_iter().take(TUNING_ENTRIES_LIMIT) {
            let entry = TuningSetting::of(setting);
            if !repairs.contains(&setting.repair) {
                repairs.push(setting.repair);
            }
            if !device_mtu.contains(&entry.device_mtu) {
                device_mtu.push(entry.device_mtu);
            }
            if !path_mtu.contains(&entry.path_mtu) {
                path_mtu.push(entry.path_mtu);
            }
            if !entries.contains(&entry) {
                entries.push(entry);
            }
        }
        device_mtu.sort_unstable();
        path_mtu.sort_unstable();
        repairs.sort_by(|a, b| match (a, b) {
            (Repair::Off, Repair::Off) => std::cmp::Ordering::Equal,
            (Repair::Off, _) => std::cmp::Ordering::Less,
            (_, Repair::Off) => std::cmp::Ordering::Greater,
            (
                Repair::Rate {
                    numerator: an,
                    denominator: ad,
                },
                Repair::Rate {
                    numerator: bn,
                    denominator: bd,
                },
            ) => (u64::from(*an) * u64::from(*bd))
                .cmp(&(u64::from(*bn) * u64::from(*ad)))
                .then(ad.cmp(bd)),
        });
        let repair = repairs.into_iter().map(repair_text).collect();
        Self {
            live,
            current: current.map(TuningSetting::of),
            repair,
            device_mtu,
            path_mtu,
            entries,
            device,
        }
    }
}

#[cfg(test)]
#[path = "tuning_tests.rs"]
mod tests;
