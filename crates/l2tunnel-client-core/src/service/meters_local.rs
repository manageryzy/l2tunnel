//! `meters_read` and `meters_catalog` over the live backend's meter CSR
//! (`docs/modules/meter-csr.md`). Values are read from the newest table the
//! runtime published with its snapshot; nothing is estimated.
use super::*;
use crate::local::{
    METER_PAGE_BYTES, METER_PAGE_LIMIT, MeterCatalogPage, MeterDescriptor, MeterEntry, MeterPage,
    MeterSide, entry_bytes,
};

impl ObservedBackend {
    /// Newest meter table and its arrival time.
    fn meters(&self) -> Option<(Instant, Arc<l2tunnel_meters::Table>)> {
        match self {
            Self::SecureUdpCommon(backend) => backend.meters(),
            #[cfg(unix)]
            Self::Proxy(backend) => backend.meters(),
            #[cfg(not(unix))]
            Self::Proxy(_) => None,
        }
    }
}

/// One local page from a sealed table: at most `limit` entries and
/// [`METER_PAGE_BYTES`] estimated bytes; `next` is the last path when more
/// registers match.
pub(super) fn page(
    table: &l2tunnel_meters::Table,
    prefix: &str,
    cursor: Option<&str>,
    limit: u16,
) -> (Vec<MeterEntry>, Option<String>) {
    let mut entries = Vec::new();
    let mut bytes = 0_usize;
    let mut more = false;
    for (path, value) in table.matching(prefix, cursor) {
        let cost = entry_bytes(path);
        if entries.len() == usize::from(limit) || bytes + cost > METER_PAGE_BYTES {
            more = true;
            break;
        }
        bytes += cost;
        entries.push(MeterEntry {
            path: path.to_owned(),
            value,
        });
    }
    let next = more
        .then(|| entries.last().map(|entry| entry.path.clone()))
        .flatten();
    (entries, next)
}

impl Handle {
    /// The live backend's newest table, its arrival time and generation.
    pub(super) fn live_meters(&self) -> Option<(u64, Instant, Arc<l2tunnel_meters::Table>)> {
        let state = self.0.lock();
        let generation = state.snapshot.generation?.value();
        let (at, table) = state.backend.as_ref()?.meters()?;
        Some((generation, at, table))
    }

    fn sampled_ms(&self) -> u64 {
        u64::try_from(self.0.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// One page of this session's registers; `Err` carries the refusal code.
    pub fn meters_local(
        &self,
        prefix: &str,
        cursor: Option<&str>,
        limit: u16,
    ) -> Result<MeterPage, &'static str> {
        crate::local::check_request(prefix, cursor, limit)?;
        let (generation, at, table) = self.live_meters().ok_or("not_running")?;
        let (entries, next) = page(&table, prefix, cursor, limit);
        Ok(MeterPage {
            side: MeterSide::Local,
            generation,
            sampled_ms: self.sampled_ms(),
            age_ms: Some(u64::try_from(at.elapsed().as_millis()).unwrap_or(u64::MAX)),
            entries,
            next,
        })
    }

    /// One page of the peer's registers over the in-band `Meters` control stream
    /// (`ProfileTag::MetersV1`, MCSR-09/MCSR-10).
    pub async fn meters_remote(
        &self,
        prefix: &str,
        cursor: Option<&str>,
        limit: u16,
    ) -> Result<MeterPage, &'static str> {
        crate::local::check_request(prefix, cursor, limit)?;
        let switcher = {
            let state = self.0.lock();
            match &state.backend {
                Some(ObservedBackend::SecureUdpCommon(backend)) => backend.switcher.clone(),
                Some(ObservedBackend::Proxy(_)) => return Err("remote_unavailable"),
                None => return Err("not_running"),
            }
        };
        let reply = switcher
            .meters_remote_read(prefix.to_owned(), cursor.map(str::to_owned), limit)
            .await
            .map_err(|error| match error {
                l2tunnel_runtime::secure_udp::transport::RemoteMeterError::Busy => "busy",
                l2tunnel_runtime::secure_udp::transport::RemoteMeterError::Timeout => {
                    "peer_timeout"
                }
                l2tunnel_runtime::secure_udp::transport::RemoteMeterError::PeerRefused(code) => {
                    code.as_str()
                }
                l2tunnel_runtime::secure_udp::transport::RemoteMeterError::Malformed => {
                    "peer_malformed"
                }
                l2tunnel_runtime::secure_udp::transport::RemoteMeterError::Closed => "not_running",
            })?;
        Ok(MeterPage {
            side: MeterSide::Remote,
            generation: reply.generation,
            sampled_ms: self.sampled_ms(),
            age_ms: None,
            entries: reply
                .entries
                .into_iter()
                .map(|(path, value)| MeterEntry { path, value })
                .collect(),
            next: reply.next,
        })
    }

    /// One page of the static catalog.
    pub fn meters_catalog(
        &self,
        prefix: &str,
        cursor: Option<u32>,
        limit: u16,
    ) -> Result<MeterCatalogPage, &'static str> {
        if limit == 0 || limit > METER_PAGE_LIMIT {
            return Err("invalid_limit");
        }
        if l2tunnel_meters::path::validate_prefix(prefix).is_err() {
            return Err("invalid_prefix");
        }
        let start = cursor.unwrap_or(0) as usize;
        let mut entries = Vec::new();
        let mut bytes = 0_usize;
        let mut next = None;
        for (index, descriptor) in l2tunnel_meters::catalog::descriptors()
            .iter()
            .enumerate()
            .skip(start)
        {
            if !l2tunnel_meters::catalog::under(prefix)
                .any(|candidate| std::ptr::eq(candidate, descriptor))
            {
                continue;
            }
            let cost = descriptor.pattern.len() + 160;
            if entries.len() == usize::from(limit) || bytes + cost > METER_PAGE_BYTES {
                next = u32::try_from(index).ok();
                break;
            }
            bytes += cost;
            entries.push(MeterDescriptor::of(descriptor));
        }
        Ok(MeterCatalogPage {
            version: l2tunnel_meters::catalog::VERSION,
            entries,
            next,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_pages_respect_limit_and_cursor() -> Result<(), Box<dyn std::error::Error>> {
        let mut table = l2tunnel_meters::Table::new(l2tunnel_meters::Limits::for_entries(8, 64))?;
        for (path, value) in [
            ("runtime.device.read_packets", 1),
            ("runtime.device.written_packets", 2),
            ("runtime.wire.shared.sent_packets", 3),
        ] {
            table.put_str(path, value)?;
        }
        table.seal()?;
        let (first, next) = page(&table, "runtime.device", None, 1);
        assert_eq!(first.len(), 1);
        assert_eq!(next.as_deref(), Some("runtime.device.read_packets"));
        let (second, next) = page(&table, "runtime.device", next.as_deref(), 1);
        assert_eq!(second[0].path, "runtime.device.written_packets");
        assert_eq!(next, None);
        Ok(())
    }
}
