//! Explicit post-carrier custody for actual Rolling and Reliable output.
use super::*;

#[derive(Debug, Eq, PartialEq)]
enum Prepared {
    Connections(connections::OutputWitness),
    Rolling(rolling_records::PreparedOutput),
    Research(rolling_records::PreparedOutput),
    Aligned(l2tunnel_reliable::PreparedOutput),
    Packed(l2tunnel_reliable::PreparedOutput),
}

/// Move-only local pending witness, never proof of peer authentication or I/O.
/// A generation Bank additionally binds its exact issuing generation.
#[derive(Debug, Eq, PartialEq)]
pub struct CarrierOutputToken {
    context: Context,
    digest: ConfigDigest,
    emission: Emission,
    prepared: Prepared,
}
impl CarrierOutputToken {
    /// Actual original generation labels, without authentication authority.
    pub const fn context(&self) -> Context {
        self.context
    }
    /// Exact complete configuration of the issuing Engine.
    pub const fn digest(&self) -> ConfigDigest {
        self.digest
    }
    /// Actual retained caller-buffer emission, unchanged through WouldBlock.
    pub const fn emission(&self) -> Emission {
        self.emission
    }
}
impl Engine {
    /// Observe actual pending custody; repeated observations do not hand off output.
    pub fn pending_carrier_output(&self) -> Option<CarrierOutputToken> {
        if self.fragments.is_some() {
            return None;
        }
        self.pending_whole_carrier_output()
    }
    pub(super) fn pending_whole_carrier_output(&self) -> Option<CarrierOutputToken> {
        let (emission, prepared) = match &self.owner {
            Owner::Rolling(endpoint) => {
                let p = endpoint.pending_output()?;
                (
                    Emission {
                        bytes: p.bytes,
                        kind: p.kind,
                        wire_bytes: p.wire_bytes,
                        security_number: p.security_number,
                        witnesses: p.witnesses,
                    },
                    Prepared::Rolling(p),
                )
            }
            Owner::Research(endpoint) => {
                let p = endpoint.pending_output()?;
                (
                    Emission {
                        bytes: p.bytes,
                        kind: p.kind,
                        wire_bytes: p.wire_bytes,
                        security_number: p.security_number,
                        witnesses: p.witnesses,
                    },
                    Prepared::Research(p),
                )
            }
            Owner::Aligned(_) => {
                let (emission, p) = self.reliable_pending?;
                (emission, Prepared::Aligned(p))
            }
            Owner::Packed(_) => {
                let (emission, p) = self.reliable_pending?;
                (emission, Prepared::Packed(p))
            }
            Owner::Connections(owner) => {
                let (emission, witness) = owner.pending_output().ok()??;
                (emission, Prepared::Connections(witness))
            }
            Owner::Swift(_) => return None,
        };
        Some(CarrierOutputToken {
            context: self.context,
            digest: self.digest,
            emission,
            prepared,
        })
    }
    /// Consume a matching witness after caller-observed whole carrier ownership.
    /// Encoding, sealing, local enqueue and partial writes cannot acknowledge it.
    pub fn confirm_carrier_output(
        &mut self,
        now: Tick,
        token: CarrierOutputToken,
    ) -> Result<(), Error> {
        self.confirm_carrier_output_at(now, now, token)
    }
    /// Preserve asynchronous acceptance time for actual source/retry/copy timers.
    pub fn confirm_carrier_output_at(
        &mut self,
        now: Tick,
        accepted: Tick,
        token: CarrierOutputToken,
    ) -> Result<(), Error> {
        if self.fragments.is_some() {
            return Err(Error::FragmentPolicy);
        }
        self.confirm_whole_carrier_output_at(now, accepted, token)
    }
    pub(super) fn confirm_whole_carrier_output_at(
        &mut self,
        now: Tick,
        accepted: Tick,
        token: CarrierOutputToken,
    ) -> Result<(), Error> {
        if self.pending_whole_carrier_output().as_ref() != Some(&token) {
            return Err(Error::Token);
        }
        let timing = self.advance(now);
        // Actual carrier ownership already happened. Consume it exactly once
        // even when later time/deadline validation makes this Engine terminal.
        let result = match (&mut self.owner, token.prepared) {
            (Owner::Connections(owner), Prepared::Connections(witness)) => {
                owner.confirm_output_at(now, accepted, witness)
            }
            (Owner::Rolling(endpoint), Prepared::Rolling(p)) => endpoint
                .confirm_output_at(now, accepted, p)
                .map_err(Error::Rolling),
            (Owner::Research(endpoint), Prepared::Research(p)) => endpoint
                .confirm_output_at(now, accepted, p)
                .map_err(Error::Rolling),
            (Owner::Aligned(endpoint), Prepared::Aligned(p)) => {
                self.reliable_pending = None;
                endpoint
                    .confirm_output_at(duration(now), duration(accepted), p)
                    .map_err(Error::Aligned)
            }
            (Owner::Packed(endpoint), Prepared::Packed(p)) => {
                self.reliable_pending = None;
                endpoint
                    .confirm_output_at(duration(now), duration(accepted), p)
                    .map_err(Error::Aligned)
            }
            _ => Err(Error::Invariant),
        };
        timing?;
        match result {
            Ok(()) => Ok(()),
            Err(error) => self.fail(error),
        }
    }
}
