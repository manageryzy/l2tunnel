//! Local API live-tuning controls (docs/modules/live-tuning.md, decision
//! 10): the session's current setting and choices, and resolving a wanted
//! setting to the exact member of the session's authenticated catalog.
use super::Handle;
use crate::local::{TuningSetting, TuningView};
use l2tunnel::live_tuning::{self, Repair, Setting};
use l2tunnel::record_configuration::{Configuration, Descriptor, Profile};
use l2tunnel_management::Role;

/// Stable tag grouping catalog entries of the same record protocol family so
/// live-tuning controls toggle FEC/MTU within the active protocol.
fn family_tag(profile: &Profile) -> u8 {
    match profile {
        Profile::Swift { .. } => 1,
        Profile::Aligned { .. } => 2,
        Profile::Packed { .. } => 3,
        Profile::AlignedCompact { .. } => 4,
        Profile::PackedCompact { .. } => 5,
        Profile::Striped { .. } => 6,
        Profile::Research { .. } => 7,
        _ => 0,
    }
}

/// Extract the live-tuning setting of any supported symmetric catalog profile
/// (`Swift`, `Aligned`, `Packed`). Handshake proposal generation still uses
/// [`live_tuning::setting`] (Swift-only); this helper lets the local API and UI
/// tune FEC/MTU across every multi-protocol catalog family.
fn catalog_setting(descriptor: &Descriptor) -> Option<Setting> {
    if let Ok(swift) = live_tuning::setting(descriptor) {
        return Some(swift);
    }
    let repair_of = |repairs: usize, sources: usize| -> Option<Repair> {
        if repairs == 0 {
            Some(Repair::Off)
        } else {
            Some(Repair::Rate {
                numerator: u32::try_from(repairs).ok()?,
                denominator: u32::try_from(sources.max(repairs)).ok()?,
            })
        }
    };
    let repair = match descriptor.profile() {
        Profile::Aligned { forward, reverse }
            if forward.recovery.repair_symbols == reverse.recovery.repair_symbols
                && forward.recovery.fec.block.max_sources
                    == reverse.recovery.fec.block.max_sources =>
        {
            repair_of(
                forward.recovery.repair_symbols,
                forward.recovery.fec.block.max_sources,
            )?
        }
        Profile::Packed { forward, reverse }
            if forward.base.recovery.repair_symbols == reverse.base.recovery.repair_symbols
                && forward.base.recovery.fec.block.max_sources
                    == reverse.base.recovery.fec.block.max_sources =>
        {
            repair_of(
                forward.base.recovery.repair_symbols,
                forward.base.recovery.fec.block.max_sources,
            )?
        }
        _ => return None,
    };
    let client_mtu = descriptor
        .direction(Role::Client)
        .common()
        .pipeline()
        .parse
        .max_packet_bytes;
    let server_mtu = descriptor
        .direction(Role::Server)
        .common()
        .pipeline()
        .parse
        .max_packet_bytes;
    if client_mtu != server_mtu {
        return None;
    }
    Some(Setting {
        repair,
        device_mtu: u16::try_from(client_mtu).ok()?,
        path_mtu: u16::try_from(descriptor.path_mtu()).ok()?,
    })
}

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
        let active_family = current.map(|cfg| family_tag(cfg.descriptor().profile()));
        let settings = profile
            .catalog()
            .descriptors()
            .iter()
            .filter(|descriptor| {
                active_family.is_none_or(|family| family_tag(descriptor.profile()) == family)
            })
            .filter_map(catalog_setting);
        let current = current.and_then(|current| catalog_setting(current.descriptor()));
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
    /// only the tuned fields changed when the catalog holds it, else the
    /// unique entry in the active protocol family matching `wanted`, otherwise
    /// the single catalog entry with that setting.
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
                let family = family_tag(current.descriptor().profile());
                let mut same_family = catalog.iter().filter(|descriptor| {
                    family_tag(descriptor.profile()) == family
                        && catalog_setting(descriptor) == Some(wanted)
                });
                match (same_family.next(), same_family.next()) {
                    (Some(only), None) => *only,
                    (Some(_), Some(_)) => return Err("ambiguous_setting"),
                    (None, _) => {
                        let mut matching = catalog
                            .iter()
                            .filter(|descriptor| catalog_setting(descriptor) == Some(wanted));
                        match (matching.next(), matching.next()) {
                            (Some(only), None) => *only,
                            (None, _) => return Err("not_in_catalog"),
                            (Some(_), Some(_)) => return Err("ambiguous_setting"),
                        }
                    }
                }
            }
        };
        Configuration::new(current.envelope(), target).map_err(|_| "invalid_configuration")
    }
}
