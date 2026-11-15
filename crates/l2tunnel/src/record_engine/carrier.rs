//! Explicit post-carrier ownership for the actual rolling scheduler output.
use super::*;

/// Move-only local pending witness, never proof of peer authentication or I/O.
/// A generation Bank additionally binds its exact issuing generation.
#[derive(Debug, Eq, PartialEq)]
pub struct CarrierOutputToken {
    context: Context,
    digest: ConfigDigest,
    prepared: rolling_records::PreparedOutput,
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
    pub fn emission(&self) -> Emission {
        let p = &self.prepared;
        Emission {
            bytes: p.bytes,
            kind: p.kind,
            wire_bytes: p.wire_bytes,
            security_number: p.security_number,
            witnesses: p.witnesses,
        }
    }
}
impl Engine {
    /// Observe the actual pending witness; repeated observations do not hand off output.
    pub fn pending_carrier_output(&self) -> Option<CarrierOutputToken> {
        match &self.owner {
            Owner::Rolling(endpoint) => {
                endpoint
                    .pending_output()
                    .map(|prepared| CarrierOutputToken {
                        context: self.context,
                        digest: self.digest,
                        prepared,
                    })
            }
            _ => None,
        }
    }
    /// Consume a matching witness after caller-observed whole carrier ownership.
    /// Encoding, sealing, local enqueue and partial writes cannot acknowledge it.
    pub fn confirm_carrier_output(
        &mut self,
        now: Tick,
        token: CarrierOutputToken,
    ) -> Result<(), Error> {
        if token.context != self.context || token.digest != self.digest {
            return Err(Error::Token);
        }
        match &self.owner {
            Owner::Rolling(endpoint) if endpoint.pending_output() == Some(token.prepared) => {}
            _ => return Err(Error::Token),
        }
        let timing = self.advance(now);
        // Actual carrier ownership has already happened. Let the original owner
        // record it once even when later time validation makes the Engine fatal.
        let result = match &mut self.owner {
            Owner::Rolling(endpoint) => endpoint
                .confirm_output(now, token.prepared)
                .map_err(Error::Rolling),
            _ => Err(Error::Invariant),
        };
        timing?;
        match result {
            Ok(()) => Ok(()),
            Err(error) => self.fail(error),
        }
    }
}
