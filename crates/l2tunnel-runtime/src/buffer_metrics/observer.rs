//! Opt-in terminal export for bounded buffer observations, never protocol authority.
use super::{Class, Collector, DurationSnapshot, Gauge, Key, Lane, Reason, Site};
use std::{
    fs::OpenOptions,
    io::{self, BufWriter, Write},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use tokio::time::Instant;

static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);

pub(crate) struct Observer {
    collector: Collector,
    path: PathBuf,
    label: &'static str,
    origin: Instant,
    finished: Option<u64>,
    // Reserve one slot only when diagnostics are enabled. Keeping this large
    // snapshot inline also enlarges disabled adapters and nested setup futures.
    raw: Vec<crate::secure_udp::raw_buffer_metrics::Snapshot>,
    proxy: Vec<crate::proxy::timing::Snapshot>,
    quic: Vec<crate::secure_udp::maintained_io::quic_metrics::Snapshot>,
}

impl Observer {
    fn proxy_storage(label: &str) -> io::Result<Vec<crate::proxy::timing::Snapshot>> {
        let mut values = Vec::new();
        if label == "proxy_bridge" {
            values.try_reserve_exact(1).map_err(io::Error::other)?;
        }
        Ok(values)
    }
    #[cfg(test)]
    pub(crate) fn for_proxy_test(origin: Instant, path: PathBuf) -> io::Result<Self> {
        let mut value = Self::for_test(origin, path)?;
        value.label = "proxy_bridge";
        value.proxy = Self::proxy_storage("proxy_bridge")?;
        Ok(value)
    }
    pub(crate) fn retain_proxy(&mut self, snapshot: crate::proxy::timing::Snapshot) {
        if self.is_finished() || self.proxy.capacity() == 0 {
            return;
        }
        if let Some(old) = self.proxy.first_mut() {
            *old = snapshot;
        } else {
            self.proxy.push(snapshot);
        }
    }

    fn quic_storage(
        label: &str,
    ) -> io::Result<Vec<crate::secure_udp::maintained_io::quic_metrics::Snapshot>> {
        let mut values = Vec::new();
        if label == "maintained_quic" {
            values.try_reserve_exact(1).map_err(io::Error::other)?;
            values.push(Default::default());
        }
        Ok(values)
    }
    fn raw_storage() -> io::Result<Vec<crate::secure_udp::raw_buffer_metrics::Snapshot>> {
        let mut values = Vec::new();
        values.try_reserve_exact(1).map_err(io::Error::other)?;
        Ok(values)
    }

    #[cfg(test)]
    pub(crate) fn for_test(origin: Instant, path: PathBuf) -> io::Result<Self> {
        Ok(Self {
            collector: Collector::new().map_err(io::Error::other)?,
            path,
            label: "test",
            quic: Self::quic_storage("test")?,
            origin,
            finished: None,
            raw: Self::raw_storage()?,
            proxy: Self::proxy_storage("test")?,
        })
    }

    pub(crate) fn from_environment(label: &'static str) -> io::Result<Option<Self>> {
        Self::from_environment_at(label, Instant::now())
    }

    pub(crate) fn from_environment_at(
        label: &'static str,
        origin: Instant,
    ) -> io::Result<Option<Self>> {
        let Some(mut prefix) = std::env::var_os("L2TUNNEL_BUFFER_METRICS")
            .or_else(|| std::env::var_os("L2TUNNEL_WIRE_METRICS"))
        else {
            return Ok(None);
        };
        if prefix.is_empty()
            || prefix.as_encoded_bytes().len() > 4096
            || label.is_empty()
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer metrics path or owner label",
            ));
        }
        let id = NEXT_OWNER
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| io::Error::other("buffer metrics owner exhausted"))?;
        // A distinct extension prevents the record-histogram reader from silently
        // treating a buffer report as another wire-metric population.
        prefix.push(format!(
            ".buffers.{label}.{}.{id}.bmetrics",
            std::process::id()
        ));
        Ok(Some(Self {
            collector: Collector::new().map_err(io::Error::other)?,
            path: PathBuf::from(prefix),
            label,
            quic: Self::quic_storage(label)?,
            origin,
            finished: None,
            raw: Self::raw_storage()?,
            proxy: Self::proxy_storage(label)?,
        }))
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.finished.is_some()
    }
    pub(crate) fn collector(&mut self) -> &mut Collector {
        &mut self.collector
    }
    pub(crate) fn now(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_micros()).unwrap_or(u64::MAX)
    }
    pub(crate) fn elapsed_at(&self, at: Instant) -> Option<u64> {
        at.checked_duration_since(self.origin)
            .map(|elapsed| elapsed.as_micros().min(u128::from(u64::MAX)) as u64)
    }
    pub(crate) fn retain_raw(&mut self, snapshot: crate::secure_udp::raw_buffer_metrics::Snapshot) {
        if !self.is_finished() {
            if let Some(retained) = self.raw.first_mut() {
                *retained = snapshot;
            } else {
                // Construction reserved this sole slot; observations never allocate.
                self.raw.push(snapshot);
            }
        }
    }
    pub(crate) fn quic_transport_due(&self, lane: usize, now: u64) -> bool {
        !self.is_finished()
            && self
                .quic
                .first()
                .is_some_and(|value| value.transport_due(lane, now))
    }
    pub(crate) fn sample_quic_transport(
        &mut self,
        lane: usize,
        now: u64,
        sample: crate::secure_udp::maintained_io::quic_metrics::TransportSample,
    ) {
        if !self.is_finished()
            && let Some(value) = self.quic.first_mut()
        {
            value.sample_transport(lane, now, sample);
        }
    }
    pub(crate) fn sample_quic(
        &mut self,
        lane: usize,
        snapshot: l2tunnel_quic::common::BufferSnapshot,
    ) {
        if !self.is_finished()
            && let Some(retained) = self.quic.first_mut()
        {
            retained.sample(lane, snapshot);
        }
    }
    pub(crate) fn heap_bytes(&self) -> usize {
        self.collector
            .heap_bytes()
            .saturating_add(
                self.proxy.capacity() * std::mem::size_of::<crate::proxy::timing::Snapshot>(),
            )
            .saturating_add(
                self.proxy
                    .first()
                    .map_or(0, |snapshot| snapshot.owner_heap_bytes),
            )
            .saturating_add(self.path.capacity())
            .saturating_add(
                self.quic.capacity()
                    * std::mem::size_of::<crate::secure_udp::maintained_io::quic_metrics::Snapshot>(
                    ),
            )
            .saturating_add(
                self.raw.capacity()
                    * std::mem::size_of::<crate::secure_udp::raw_buffer_metrics::Snapshot>(),
            )
    }
    pub(crate) fn finish_at(&mut self, now: u64) {
        if self.finished.is_none() && self.collector.finish(now).is_ok() {
            self.finished = Some(now);
        }
    }

    fn write_report(&self, writer: &mut impl Write, now: u64) -> io::Result<()> {
        let owner = self
            .collector
            .owner(now)
            .map_err(|_| io::Error::other("invalid buffer report clock"))?;
        writeln!(writer, "{{\"schema\":1,\"owner\":\"{}\",", self.label)?;
        writeln!(
            writer,
            "\"definition\":\"observed refusal-to-progress intervals include scheduling delay; occupancy does not imply blockage; unobserved sites are unmeasured, not zero; overlapping sites/reasons must not be summed; owner duration is their union; terminal waits are censored, not recovered\","
        )?;
        writeln!(
            writer,
            "\"coverage\":\"partial: inspect observed hooks and docs/modules/buffer-observability.md; provider-private queues and unhooked protocol owners remain unavailable\","
        )?;
        write!(writer, "\"first_observed_us\":")?;
        optional(writer, owner.first_observed_us)?;
        write!(writer, ",\"last_observed_us\":")?;
        optional(writer, owner.last_observed_us)?;
        write!(writer, ",\"observed_span_us\":")?;
        optional(writer, owner.observed_span_us)?;
        write!(writer, ",\"finished_at_us\":")?;
        optional(writer, owner.finished_at_us)?;
        writeln!(
            writer,
            ",\"diagnostic_heap_bytes\":{},\"invalid\":{{\"clock_regression\":{},\"occupancy_exceeds_capacity\":{},\"update_after_finish\":{},\"counter_overflow\":{}}},",
            self.heap_bytes(),
            owner.invalid.clock_regression,
            owner.invalid.occupancy_exceeds_capacity,
            owner.invalid.update_after_finish,
            owner.invalid.counter_overflow
        )?;
        write!(writer, "\"blocked_union\":")?;
        duration(writer, owner.blocked)?;
        write!(writer, ",\"sites\":[")?;
        let mut first = true;
        for site in Site::ALL {
            for lane in Lane::ALL {
                for class in Class::ALL {
                    let key = Key { site, lane, class };
                    let value = self.collector.key(key);
                    if value.first_observed_us.is_none() {
                        continue;
                    }
                    if !first {
                        write!(writer, ",")?;
                    }
                    first = false;
                    write!(
                        writer,
                        "{{\"site\":\"{site:?}\",\"lane\":\"{lane:?}\",\"class\":\"{class:?}\",\"bytes\":"
                    )?;
                    gauge(writer, value.bytes)?;
                    write!(writer, ",\"first_observed_us\":")?;
                    optional(writer, value.first_observed_us)?;
                    write!(writer, ",\"last_observed_us\":")?;
                    optional(writer, value.last_observed_us)?;
                    write!(writer, ",\"items\":")?;
                    gauge(writer, value.items)?;
                    write!(writer, ",\"reasons\":[")?;
                    let mut first_reason = true;
                    for reason in Reason::ALL {
                        let value = self
                            .collector
                            .reason(key, reason, now)
                            .map_err(|_| io::Error::other("invalid buffer reason clock"))?;
                        if !value.observed {
                            continue;
                        }
                        if !first_reason {
                            write!(writer, ",")?;
                        }
                        first_reason = false;
                        write!(
                            writer,
                            "{{\"reason\":\"{reason:?}\",\"refusals\":{},\"untimed_refusals\":{},\"progress\":{},\"blocked\":",
                            value.refusals, value.untimed_refusals, value.progress
                        )?;
                        duration(writer, value.blocked)?;
                        write!(writer, "}}")?;
                    }
                    write!(writer, "]}}")?;
                }
            }
        }
        write!(writer, "],\"raw\":")?;
        if let Some(snapshot) = self.raw.first() {
            snapshot.write(writer)?;
        } else {
            write!(writer, "null")?;
        }
        write!(writer, ",\"quic\":")?;
        if let Some(snapshot) = self.quic.first() {
            snapshot.write(writer)?;
        } else {
            write!(writer, "null")?;
        }
        write!(writer, ",\"proxy\":")?;
        if let Some(snapshot) = self.proxy.first() {
            snapshot.write(writer)?;
        } else {
            write!(writer, "null")?;
        }
        writeln!(writer, "}}")
    }

    fn persist(&self, now: u64) -> io::Result<()> {
        let mut name = self.path.as_os_str().to_owned();
        name.push(".tmp");
        let temporary = PathBuf::from(name);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        let result = (|| {
            let mut writer = BufWriter::new(file);
            self.write_report(&mut writer, now)?;
            writer.flush()?;
            writer.get_ref().sync_all()?;
            std::fs::rename(&temporary, &self.path)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(temporary);
        }
        result
    }
}

impl Drop for Observer {
    fn drop(&mut self) {
        let now = self.finished.unwrap_or_else(|| self.now());
        self.finish_at(now);
        if let Err(error) = self.persist(self.finished.unwrap_or(now)) {
            eprintln!(
                "buffer metrics report failed: owner={} kind={:?}",
                self.label,
                error.kind()
            );
        }
    }
}

fn optional(writer: &mut impl Write, value: Option<u64>) -> io::Result<()> {
    if let Some(value) = value {
        write!(writer, "{value}")
    } else {
        write!(writer, "null")
    }
}
fn duration(writer: &mut impl Write, value: DurationSnapshot) -> io::Result<()> {
    write!(
        writer,
        "{{\"episodes\":{},\"completed_episodes\":{},\"censored_episodes\":{},\"completed_us\":{},\"censored_us\":{},\"open_us\":",
        value.episodes,
        value.completed_episodes,
        value.censored_episodes,
        value.completed_us,
        value.censored_us
    )?;
    optional(writer, value.open_us)?;
    write!(writer, ",\"maximum_us\":{}}}", value.maximum_us)
}
fn gauge(writer: &mut impl Write, value: Gauge) -> io::Result<()> {
    write!(writer, "{{\"samples\":{},\"used\":", value.samples)?;
    optional(writer, value.latest.map(|x| x.used))?;
    write!(writer, ",\"capacity\":")?;
    optional(writer, value.latest.and_then(|x| x.capacity))?;
    write!(writer, ",\"high_water\":")?;
    optional(writer, value.high_water)?;
    write!(writer, ",\"minimum_known_capacity\":")?;
    optional(writer, value.minimum_known_capacity)?;
    write!(writer, ",\"maximum_known_capacity\":")?;
    optional(writer, value.maximum_known_capacity)?;
    write!(writer, "}}")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_report_parses_and_preserves_censored_waits()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "l2tunnel-buffer-report-{}.bmetrics",
            std::process::id()
        ));
        let mut observer = Observer::for_test(Instant::now(), path.clone())?;
        let key = Key {
            site: Site::CommonUserSlot,
            lane: Lane::Shared,
            class: Class::User,
        };
        observer
            .collector()
            .sample(key, 1, super::super::Occupancy::default())
            .map_err(|_| "sample")?;
        for now in [3, 5] {
            observer
                .collector()
                .blocked(key, Reason::SocketWrite, now)
                .map_err(|_| "blocked")?;
        }
        observer
            .collector()
            .progress(key, Reason::SocketWrite, 11)
            .map_err(|_| "progress")?;
        observer
            .collector()
            .blocked(key, Reason::SocketWrite, 15)
            .map_err(|_| "blocked")?;
        observer.finish_at(20);
        observer.finish_at(100);
        let mut bytes = Vec::new();
        observer.write_report(&mut bytes, 100)?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(value["finished_at_us"], 20);
        assert_eq!(value["observed_span_us"], 19);
        let reason = &value["sites"][0]["reasons"][0];
        assert_eq!(reason["refusals"], 3);
        assert_eq!(reason["blocked"]["episodes"], 2);
        assert_eq!(reason["blocked"]["completed_us"], 8);
        assert_eq!(reason["blocked"]["censored_us"], 5);
        assert_eq!(value["blocked_union"]["completed_us"], 8);
        assert_eq!(value["blocked_union"]["censored_us"], 5);
        assert!(
            value["invalid"]
                .as_object()
                .ok_or("invalid object")?
                .values()
                .all(|v| v == false)
        );
        drop(observer);
        let persisted: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        assert_eq!(persisted, value);
        std::fs::remove_file(path)?;
        Ok(())
    }
}
