//! Meter CSR export of one owner's collector (`docs/modules/meter-csr.md`).
//!
//! Every site maps to one component root named after the owning Rust
//! component; the key's lane and class become instance segments. Only
//! observed keys and observed reasons are written. Unknown capacity is
//! omitted, never written as zero.

use std::fmt;

use l2tunnel_meters::{Table, TableError, catalog};

use super::{Class, Collector, Gauge, Key, Reason, Site};

/// Component root of one collector site.
pub(crate) const fn root(site: Site) -> &'static str {
    match site {
        Site::NativeIngress => "runtime.native_ingress",
        Site::NativeEgress => "runtime.native_egress",
        Site::CodecAdmission => "runtime.codec.admission",
        Site::CodecDelivery => "runtime.codec.delivery",
        Site::RecoverySend => "runtime.recovery.send",
        Site::RecoveryReceive => "runtime.recovery.receive",
        Site::Management => "runtime.management",
        Site::CommonPrepared => "runtime.common_prepared",
        Site::CarrierSubmission => "runtime.maintained.submission",
        Site::CarrierReceipt => "runtime.maintained.receipt",
        Site::CarrierInput => "runtime.maintained.input",
        Site::TlsWrite => "runtime.retained_tls.write",
        Site::TlsFlush => "runtime.retained_tls.flush",
        Site::TlsSubmission => "runtime.retained_tls.submission",
        Site::TlsInput => "runtime.retained_tls.input",
        Site::TlsReceipt => "runtime.retained_tls.receipt",
        Site::QuicSend => "quic.connection.send",
        Site::RawSend => "runtime.raw_carrier.send",
        Site::RawCredit => "runtime.raw_carrier.credit",
        Site::RawControlSlot => "runtime.raw_carrier.control_slot",
        Site::ProxyAdmission => "runtime.proxy.admission",
        Site::ProxyWriter => "runtime.proxy.writer",
        Site::ProxyPhysicalReceipt => "runtime.proxy.physical_receipt",
        Site::PipelineAdmission => "pipeline.admission",
        Site::NativeOutputQueue => "runtime.native_output.queue",
        Site::NativeDeviceWrite => "runtime.native_output.device_write",
        Site::CommonUserSlot => "runtime.user_slot",
        Site::DeferredFeedback => "runtime.deferred_feedback",
        Site::WireCredit => "runtime.wire_credit",
        Site::CreditWindow => "flow_control.session_credit.window",
    }
}

// The catalog vocabularies must cover every collector class and reason.
const _: () = assert!(Class::ALL.len() == catalog::CLASSES.len());
const _: () = assert!(Reason::ALL.len() == catalog::REASONS.len());
// Every collector site has a component root.
const _: () = {
    let mut index = 0;
    while index < Site::ALL.len() {
        assert!(!root(Site::ALL[index]).is_empty());
        index += 1;
    }
};

/// Catalog class segment.
pub(crate) const fn class(class: Class) -> &'static str {
    catalog::CLASSES[class as usize]
}

/// Catalog reason segment; the order of [`Reason::ALL`] matches
/// [`catalog::REASONS`] (checked by a test).
pub(crate) const fn reason(reason: Reason) -> &'static str {
    catalog::REASONS[reason as usize]
}

struct Base(Key);
impl fmt::Display for Base {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}.{}.{}",
            root(self.0.site),
            self.0.lane.segment(),
            class(self.0.class)
        )
    }
}

fn gauge(table: &mut Table, base: &Base, gauge: Gauge, unit: &str) -> Result<(), TableError> {
    let Some(latest) = gauge.latest else {
        return Ok(());
    };
    table.put(format_args!("{base}.occupancy_{unit}"), latest.used)?;
    table.put(
        format_args!("{base}.high_water_{unit}"),
        gauge.high_water.unwrap_or(latest.used),
    )?;
    if let Some(capacity) = latest.capacity {
        table.put(format_args!("{base}.capacity_{unit}"), capacity)?;
    }
    Ok(())
}

impl Collector {
    /// Write every observed key under its component root, plus the owner
    /// summary under `meta.owner.<owner>`. `now` is the owner's tick.
    pub(crate) fn write_csr(
        &self,
        table: &mut Table,
        owner: &str,
        now: u64,
    ) -> Result<(), TableError> {
        let Ok(summary) = self.owner(now) else {
            // A clock regression leaves the owner unreadable at this tick; the
            // registers stay absent rather than invented.
            return Ok(());
        };
        table.put(format_args!("meta.owner.{owner}.sampled_us"), now)?;
        table.put(
            format_args!("meta.owner.{owner}.slots_used"),
            summary.slots_used as u64,
        )?;
        table.put(
            format_args!("meta.owner.{owner}.slot_capacity"),
            summary.slot_capacity as u64,
        )?;
        table.put(
            format_args!("meta.owner.{owner}.slots_exhausted"),
            summary.slots_exhausted,
        )?;
        table.put(
            format_args!("meta.owner.{owner}.heap_bytes"),
            summary.diagnostic_heap_bytes as u64,
        )?;
        let invalid = summary.invalid;
        let invalid = invalid.clock_regression
            || invalid.occupancy_exceeds_capacity
            || invalid.update_after_finish
            || invalid.counter_overflow
            || invalid.slots_exhausted;
        table.put(
            format_args!("meta.owner.{owner}.invalid"),
            u64::from(invalid),
        )?;
        let blocked = summary.blocked;
        table.put(
            format_args!("meta.owner.{owner}.blocked_episodes"),
            blocked.episodes,
        )?;
        table.put(
            format_args!("meta.owner.{owner}.blocked_completed_us"),
            blocked.completed_us,
        )?;
        table.put(
            format_args!("meta.owner.{owner}.blocked_censored_us"),
            blocked.censored_us,
        )?;
        table.put(
            format_args!("meta.owner.{owner}.blocked_open_us"),
            blocked.open_us.unwrap_or(0),
        )?;
        table.put(
            format_args!("meta.owner.{owner}.blocked_max_us"),
            blocked.maximum_us,
        )?;
        for key in self.keys() {
            let base = Base(key);
            let value = self.key(key);
            let samples = value.bytes.samples.max(value.items.samples);
            if samples > 0 {
                table.put(format_args!("{base}.samples"), samples)?;
            }
            gauge(table, &base, value.bytes, "bytes")?;
            gauge(table, &base, value.items, "items")?;
            let mut totals = [0_u64; 3];
            for cause in Reason::ALL {
                let Ok(state) = self.reason(key, cause, now) else {
                    continue;
                };
                if !state.observed {
                    continue;
                }
                totals[0] = totals[0].saturating_add(state.refusals);
                totals[1] = totals[1].saturating_add(state.untimed_refusals);
                totals[2] = totals[2].saturating_add(state.progress);
                let duration = state.blocked;
                l2tunnel_meters::WaitSnapshot {
                    episodes: duration.episodes,
                    completed_episodes: duration.completed_episodes,
                    censored_episodes: duration.censored_episodes,
                    completed_us: duration.completed_us,
                    censored_us: duration.censored_us,
                    open_us: duration.open_us,
                    max_us: duration.maximum_us,
                    histogram: duration.histogram,
                    invalid: false,
                }
                .write(table, &format_args!("{base}.wait.{}", reason(cause)))?;
            }
            table.put(format_args!("{base}.refusals"), totals[0])?;
            table.put(format_args!("{base}.untimed_refusals"), totals[1])?;
            table.put(format_args!("{base}.progress"), totals[2])?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer_metrics::{Lane, Occupancy};
    use l2tunnel_meters::Limits;

    #[test]
    fn reason_and_class_names_match_the_catalog() {
        for cause in Reason::ALL {
            let debug = format!("{cause:?}");
            let mut snake = String::new();
            for (index, character) in debug.char_indices() {
                if character.is_ascii_uppercase() && index > 0 {
                    snake.push('_');
                }
                snake.push(character.to_ascii_lowercase());
            }
            assert_eq!(reason(cause), snake);
        }
        assert_eq!(class(Class::Management), "management");
    }

    #[test]
    fn every_site_path_is_in_the_catalog() {
        for site in Site::ALL {
            for lane in [Lane::Shared, Lane::at(0), Lane::at(65_535)] {
                let base = Base(Key {
                    site,
                    lane,
                    class: Class::User,
                });
                for suffix in [
                    "samples",
                    "occupancy_bytes",
                    "capacity_items",
                    "refusals",
                    "progress",
                    "wait.recovery_history_capacity.completed_episodes",
                    "wait.io_pending.hist.b23",
                ] {
                    let path = format!("{base}.{suffix}");
                    assert_eq!(l2tunnel_meters::path::validate(&path), Ok(()), "{path}");
                    let descriptor = catalog::lookup(&path);
                    assert!(descriptor.is_some(), "{path}");
                }
            }
        }
    }

    #[test]
    fn written_registers_are_catalogued_and_skip_unknowns() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut collector = Collector::new()?;
        let key = Key {
            site: Site::NativeIngress,
            lane: Lane::at(2),
            class: Class::User,
        };
        let sample = Occupancy {
            bytes: Some(crate::buffer_metrics::Extent {
                used: 10,
                capacity: None,
            }),
            items: None,
        };
        assert_eq!(collector.sample(key, 5, sample), Ok(()));
        assert_eq!(collector.blocked(key, Reason::BufferCapacity, 6), Ok(()));
        assert_eq!(collector.progress(key, Reason::BufferCapacity, 26), Ok(()));
        let mut table = Table::new(Limits::for_entries(256, 96))?;
        collector.write_csr(&mut table, "common", 30)?;
        table.seal()?;
        for (path, _) in table.iter() {
            assert!(catalog::lookup(path).is_some(), "{path}");
        }
        let base = "runtime.native_ingress.lane2.user";
        assert_eq!(table.get(&format!("{base}.occupancy_bytes")), Some(10));
        assert_eq!(table.get(&format!("{base}.capacity_bytes")), None);
        assert_eq!(table.get(&format!("{base}.occupancy_items")), None);
        assert_eq!(table.get(&format!("{base}.refusals")), Some(1));
        assert_eq!(
            table.get(&format!("{base}.wait.buffer_capacity.completed_us")),
            Some(20)
        );
        assert_eq!(
            table.get(&format!("{base}.wait.buffer_capacity.hist.b04")),
            Some(1)
        );
        assert_eq!(table.get(&format!("{base}.wait.queue_full.episodes")), None);
        assert_eq!(table.get("meta.owner.common.slots_used"), Some(1));
        assert_eq!(
            table.get("meta.owner.common.blocked_completed_us"),
            Some(20)
        );
        Ok(())
    }
}
