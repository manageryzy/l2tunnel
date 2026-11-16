//! Opaque ordered records from an explicitly installed existing TCP proxy actor.
//! The actor retains TCP and original-flow MUX ownership. This one-channel ARQ
//! adapter supplies no TCP endpoint, authentication, management or native device.

use super::*;

pub(super) fn selected(configuration: &configuration::Configuration) -> bool {
    [Role::Client, Role::Server].into_iter().any(|role| {
        configuration
            .descriptor()
            .direction(role)
            .common()
            .traffic()
            .tcp
            == TcpControl::SplitTcpProxy
    })
}

pub(super) fn supported(configuration: &configuration::Configuration) -> bool {
    let descriptor = configuration.descriptor();
    if descriptor.duplex() != l2tunnel_core::Duplex::Full {
        return false;
    }
    [Role::Client, Role::Server].into_iter().all(|role| {
        let direction = descriptor.direction(role);
        let configuration::DirectionProfile::Aligned(config) = direction.profile() else {
            return false;
        };
        let body = config.receiver.body;
        direction.common().traffic().tcp == TcpControl::SplitTcpProxy
            && direction.common().traffic().layer == l2tunnel_core::traffic::NetworkLayer::Tun
            && direction.channels() == 1
            && config.native_policy == aligned::NativePolicy::RawIp
            && config.recovery.repair_symbols == 0
            && !body.elide_payload_length
            && !body.predictive
            && !body.timestamp_pair_dictionary
            && body.independent_short_frame_bytes == 0
            && body
                .max_frame_bytes
                .checked_add(6)
                .is_some_and(|length| length <= body.symbol_bytes)
    })
}

impl Engine {
    /// True only for the validated opaque ordered-record adapter. The external
    /// selected runtime must still install the existing TCP proxy actor.
    pub fn proxy_records(&self) -> bool {
        selected(&self.configuration)
    }

    /// Copy one already-arbitrated proxy record into this actual bounded queue.
    /// Native IP parsing is intentionally absent. The original observation and
    /// absolute cap survive backpressure and cannot be renewed by a retry.
    pub fn enqueue_proxy_borrowed(
        &mut self,
        received: Tick,
        now: Tick,
        bytes: &[u8],
        original_deadline: Tick,
    ) -> Result<pipeline::PacketMetadata, Error> {
        if !self.proxy_records() {
            return Err(Error::Unsupported(Capability::TcpProxy));
        }
        if self.ingress.is_some() || self.fragments.is_some() {
            return Err(Error::IngressPolicy);
        }
        self.advance(now)?;
        self.pipeline
            .enqueue_proxy_borrowed(
                bytes,
                duration(received),
                duration(now),
                duration(original_deadline),
            )
            .map_err(Error::Pipeline)
    }
}

#[cfg(test)]
#[path = "proxy_records_tests.rs"]
mod tests;
