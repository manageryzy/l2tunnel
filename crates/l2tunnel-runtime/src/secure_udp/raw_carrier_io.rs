//! Same original raw packet owner used by setup, membership and the sole Driver.
//! This adapter grants no Noise/member authority and owns no task or socket clone.
use super::original_datagram::SendReceipt;
use l2tunnel::secure_record::Scope;
use l2tunnel_raw_io::{
    PacketIo,
    handoff::pairing::{
        PairLane,
        packet::{self as raw, PacketCarrier},
    },
};
use l2tunnel_security as security;
use raw::compact::{FinalAcceptance, FinalControl, FinalKind, FinalMetadata, FinalOutputToken};
use std::io;
use std::{
    alloc::Layout,
    net::SocketAddr,
    task::{Context, Poll},
};
use tokio::time::Instant;

/// One exact retained Common ciphertext; labels confer no authentication authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::secure_udp) struct UserIdentity {
    pub(in crate::secure_udp) scope: Scope,
    pub(in crate::secure_udp) number: security::PacketNumber,
    pub(in crate::secure_udp) bytes: usize,
    pub(in crate::secure_udp) deadline: Instant,
}
/// Private carrier-neutral physical receipt; no TCP bytes are labeled UDP.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::secure_udp) struct PhysicalReceipt {
    pub(in crate::secure_udp) record_bytes: usize,
    pub(in crate::secure_udp) udp_bytes: Option<usize>,
    pub(in crate::secure_udp) ip_bytes: usize,
    pub(in crate::secure_udp) accepted_at: Instant,
    pub(in crate::secure_udp) deadline: Instant,
}
impl From<SendReceipt> for PhysicalReceipt {
    fn from(receipt: SendReceipt) -> Self {
        Self {
            record_bytes: receipt.datagram_bytes,
            udp_bytes: Some(receipt.udp_bytes),
            ip_bytes: receipt.ip_bytes,
            accepted_at: receipt.accepted_at,
            deadline: receipt.deadline,
        }
    }
}
/// Physical completion is distinct from local bounded custody.
pub(in crate::secure_udp) enum SendProgress {
    Pending,
    Whole {
        receipt: PhysicalReceipt,
        late: bool,
    },
}

/// The old concrete APIs use this uninhabited default; no dummy raw owner exists.
#[derive(Clone, Copy)]
pub(in crate::secure_udp) enum NoRaw {}

/// Narrow I/O ownership seam; this is not a protocol or authentication state machine.
pub(in crate::secure_udp) trait RawBacking: Send {
    fn geometry(&self) -> raw::RecordGeometry;
    fn final_input_metadata(&self) -> Option<FinalMetadata>;
    fn commit_final_input(
        &mut self,
        metadata: FinalMetadata,
        verdict: Option<FinalAcceptance<()>>,
    ) -> io::Result<()>;
    fn prepare_final(&mut self, kind: FinalKind, bytes: usize)
    -> io::Result<Option<FinalMetadata>>;
    fn prepare_final_control(&mut self) -> io::Result<Option<(FinalMetadata, FinalControl)>>;
    fn cancel_final(&mut self) -> io::Result<()>;
    fn addresses(&self) -> (SocketAddr, SocketAddr);
    fn capacity_bytes(&self) -> io::Result<usize>;
    fn allocations(&self) -> usize;
    fn next_wake(&self) -> io::Result<Instant>;
    fn check_failure(&self) -> io::Result<()>;
    fn begin_turn(&mut self);
    fn user_pending(&self) -> bool;
    fn user_precedes_control(&self) -> bool;
    fn control_pending(&self) -> bool;
    fn receive_ready(&self) -> bool;
    fn deadline(&self) -> Option<Instant>;
    fn try_user(&mut self, identity: UserIdentity, bytes: &[u8]) -> io::Result<SendProgress>;
    fn stage_control(
        &mut self,
        bytes: &[u8],
        cost: usize,
        deadline: Instant,
        bootstrap: bool,
    ) -> io::Result<SendProgress>;
    fn take_control(&mut self) -> io::Result<Option<(SendProgress, usize)>>;
    fn take_user(&mut self) -> io::Result<Option<(UserIdentity, SendProgress)>>;
    fn user_accepted_at(&self) -> Option<Instant>;
    fn earliest_input_for_ordering_at(&self) -> io::Result<Option<Instant>>;
    fn try_user_held(&mut self, identity: UserIdentity, bytes: &[u8]) -> io::Result<SendProgress>;
    fn try_receive(&mut self, output: &mut [u8]) -> io::Result<(usize, Instant)>;
    fn poll_ready(&mut self, cx: &mut Context<'_>, receive: bool) -> Poll<io::Result<()>>;
    fn poll_setup_send(
        &mut self,
        cx: &mut Context<'_>,
        bytes: &[u8],
        deadline: Instant,
    ) -> Poll<io::Result<()>>;
}
impl RawBacking for NoRaw {
    fn final_input_metadata(&self) -> Option<FinalMetadata> {
        match *self {}
    }
    fn commit_final_input(
        &mut self,
        _: FinalMetadata,
        _: Option<FinalAcceptance<()>>,
    ) -> io::Result<()> {
        match *self {}
    }
    fn prepare_final(&mut self, _: FinalKind, _: usize) -> io::Result<Option<FinalMetadata>> {
        match *self {}
    }
    fn prepare_final_control(&mut self) -> io::Result<Option<(FinalMetadata, FinalControl)>> {
        match *self {}
    }
    fn cancel_final(&mut self) -> io::Result<()> {
        match *self {}
    }
    fn geometry(&self) -> raw::RecordGeometry {
        match *self {}
    }
    fn addresses(&self) -> (SocketAddr, SocketAddr) {
        match *self {}
    }
    fn capacity_bytes(&self) -> io::Result<usize> {
        match *self {}
    }
    fn allocations(&self) -> usize {
        match *self {}
    }
    fn next_wake(&self) -> io::Result<Instant> {
        match *self {}
    }
    fn check_failure(&self) -> io::Result<()> {
        match *self {}
    }
    fn begin_turn(&mut self) {
        match *self {}
    }
    fn user_pending(&self) -> bool {
        match *self {}
    }
    fn user_precedes_control(&self) -> bool {
        match *self {}
    }
    fn control_pending(&self) -> bool {
        match *self {}
    }
    fn receive_ready(&self) -> bool {
        match *self {}
    }
    fn deadline(&self) -> Option<Instant> {
        match *self {}
    }
    fn try_user(&mut self, _: UserIdentity, _: &[u8]) -> io::Result<SendProgress> {
        match *self {}
    }
    fn stage_control(
        &mut self,
        _: &[u8],
        _: usize,
        _: Instant,
        _: bool,
    ) -> io::Result<SendProgress> {
        match *self {}
    }
    fn take_control(&mut self) -> io::Result<Option<(SendProgress, usize)>> {
        match *self {}
    }
    fn take_user(&mut self) -> io::Result<Option<(UserIdentity, SendProgress)>> {
        match *self {}
    }
    fn user_accepted_at(&self) -> Option<Instant> {
        match *self {}
    }
    fn earliest_input_for_ordering_at(&self) -> io::Result<Option<Instant>> {
        match *self {}
    }
    fn try_user_held(&mut self, _: UserIdentity, _: &[u8]) -> io::Result<SendProgress> {
        match *self {}
    }
    fn try_receive(&mut self, _: &mut [u8]) -> io::Result<(usize, Instant)> {
        match *self {}
    }
    fn poll_ready(&mut self, _: &mut Context<'_>, _: bool) -> Poll<io::Result<()>> {
        match *self {}
    }
    fn poll_setup_send(
        &mut self,
        _: &mut Context<'_>,
        _: &[u8],
        _: Instant,
    ) -> Poll<io::Result<()>> {
        match *self {}
    }
}

struct Pending {
    bootstrap: bool,
    lane: PairLane,
    token: Option<raw::RecordToken>,
    bytes: usize,
    cost: usize,
    deadline: Instant,
    receipt: Option<PhysicalReceipt>,
}
struct User {
    identity: UserIdentity,
    pending: Pending,
}
struct Input {
    bytes: usize,
    received: Instant,
    final_metadata: Option<(PairLane, FinalMetadata)>,
}

/// Actual bounded backing, including the real inline PacketCarrier header.
/// Nested raw/TLS/backend heaps remain separately retained and not fully qualified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::secure_udp) struct Plan {
    maximum: usize,
    capacity: usize,
}
impl Plan {
    pub(in crate::secure_udp) fn for_packet<I: PacketIo + Send + 'static>(
        carrier: &PacketCarrier<I>,
    ) -> io::Result<Self> {
        let geometry = carrier.geometry().map_err(raw_error)?;
        let maximum = geometry
            .path_mtu
            .checked_sub(geometry.ip_tcp_bytes)
            .ok_or_else(exhausted)?;
        let capacity = Layout::array::<RawAdapter<I>>(1)
            .map_err(invalid)?
            .size()
            .checked_add(maximum.checked_mul(2).ok_or_else(exhausted)?)
            .ok_or_else(exhausted)?;
        Ok(Self { maximum, capacity })
    }
    pub(in crate::secure_udp) fn capacity_bytes(self) -> usize {
        self.capacity
    }
}

/// One actual original raw owner and two independent bounded upper custody cells.
pub(in crate::secure_udp) struct RawAdapter<I: PacketIo + Send + 'static> {
    carrier: PacketCarrier<I>,
    geometry: raw::RecordGeometry,
    bootstrap_geometry: raw::RecordGeometry,
    prepared: Option<(PairLane, FinalOutputToken)>,
    control_cursor: usize,
    addresses: (SocketAddr, SocketAddr),
    lanes: usize,
    client: bool,
    control_bytes: Vec<u8>,
    input_bytes: Vec<u8>,
    input: Option<Input>,
    user: Option<User>,
    control: Option<Pending>,
    failure: Option<raw::Error>,
    polled: bool,
}
impl<I: PacketIo + Send + 'static> RawAdapter<I> {
    fn try_user_inner(
        &mut self,
        identity: UserIdentity,
        bytes: &[u8],
        hold: bool,
    ) -> io::Result<SendProgress> {
        if let Some(user) = &self.user {
            if user.identity != identity {
                return Err(protocol("raw User identity changed while pending"));
            }
        } else {
            let pending = self.pending(self.data_lane(), bytes.len(), identity.deadline)?;
            if identity.bytes != bytes.len() {
                return Err(protocol("raw User byte identity differs"));
            }
            self.user = Some(User { identity, pending });
        }
        let user = self
            .user
            .as_mut()
            .ok_or_else(|| protocol("raw User custody missing"))?;
        if user.pending.receipt.is_none() {
            // Retain the exact User identity and original cap while an older
            // Control owns this lane. The Driver now observes waiting custody
            // and cannot repeatedly replace that Control ahead of this User.
            // Half's distinct data lane remains independently admissible.
            if user.pending.token.is_none()
                && self
                    .control
                    .as_ref()
                    .is_some_and(|control| control.lane == user.pending.lane)
            {
                return Ok(SendProgress::Pending);
            }
            if self.carrier.final_records_enabled() && user.pending.token.is_none() {
                let (lane, token) = self
                    .prepared
                    .take()
                    .ok_or_else(|| protocol("raw final User reservation missing"))?;
                if lane != user.pending.lane {
                    return Err(protocol("raw final User lane changed"));
                }
                user.pending.token = Some(
                    self.carrier
                        .commit_final_record(token, bytes)
                        .map_err(raw_error)?,
                );
            } else {
                Self::stage(
                    &mut self.carrier,
                    &mut user.pending,
                    raw::RecordKind::Data,
                    bytes,
                )?;
            }
            self.fail()?;
            return Ok(SendProgress::Pending);
        }
        if hold {
            return Ok(SendProgress::Pending);
        }
        Self::result(
            self.user
                .take()
                .ok_or_else(|| protocol("raw User custody missing"))?
                .pending,
        )
    }

    pub(in crate::secure_udp) fn new(mut carrier: PacketCarrier<I>) -> io::Result<Self> {
        carrier.check_live().map_err(raw_error)?;
        let plan = Plan::for_packet(&carrier)?;
        let geometry = carrier.geometry().map_err(raw_error)?;
        let addresses = carrier.lane_endpoints().map_err(raw_error)?[0]
            .ok_or_else(|| protocol("raw first original is absent"))?;
        let lanes = carrier.lane_count();
        let client = carrier.info().is_client;
        let control_bytes = buffer(plan.maximum)?;
        let input_bytes = buffer(plan.maximum)?;
        let result = Self {
            carrier,
            geometry,
            bootstrap_geometry: geometry,
            prepared: None,
            control_cursor: 0,
            addresses,
            lanes,
            client,
            control_bytes,
            input_bytes,
            input: None,
            user: None,
            control: None,
            failure: None,
            polled: false,
        };
        if result.capacity_bytes()? != plan.capacity_bytes() {
            return Err(protocol("raw adapter capacity differs"));
        }
        Ok(result)
    }
    pub(in crate::secure_udp) fn enable_final_records(
        &mut self,
        binding: [u8; 32],
        cover: l2tunnel::cover::Config,
    ) -> io::Result<raw::RecordGeometry> {
        if self.user.is_some() || self.control.is_some() || self.input.is_some() {
            return Err(protocol("raw upper custody remains at final handoff"));
        }
        self.carrier
            .enable_final_records(binding, move |packet| {
                cover
                    .decode(packet)
                    .is_ok_and(|decoded| match decoded.phase {
                        l2tunnel::cover::Phase::Handshake => {
                            decoded.protected.first() == Some(&super::establish::CONTROL_TAG)
                        }
                        l2tunnel::cover::Phase::Established => {
                            decoded.protected.first() == Some(&super::member::ROUTE)
                        }
                    })
            })
            .map_err(raw_error)?;
        self.geometry = self.carrier.final_geometry().map_err(raw_error)?;
        Ok(self.geometry)
    }
    fn data_lane(&self) -> PairLane {
        if self.lanes == 1 || self.client {
            PairLane::First
        } else {
            PairLane::Second
        }
    }
    fn control_lane(&self) -> PairLane {
        if self.lanes == 1 || !self.client {
            PairLane::First
        } else {
            PairLane::Second
        }
    }
    fn fail(&self) -> io::Result<()> {
        if let Some(error) = &self.failure {
            Err(raw_error(error.clone()))
        } else {
            Ok(())
        }
    }
    fn pending(&self, lane: PairLane, bytes: usize, deadline: Instant) -> io::Result<Pending> {
        self.fail()?;
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        Ok(Pending {
            bootstrap: false,
            lane,
            token: None,
            bytes,
            cost: self.geometry.ip_bytes(bytes).map_err(raw_error)?,
            deadline,
            receipt: None,
        })
    }
    fn stage(
        carrier: &mut PacketCarrier<I>,
        pending: &mut Pending,
        kind: raw::RecordKind,
        bytes: &[u8],
    ) -> io::Result<()> {
        if pending.token.is_some() || pending.receipt.is_some() {
            return Ok(());
        }
        if bytes.len() != pending.bytes {
            return Err(protocol("raw immutable record length changed"));
        }
        if Instant::now() >= pending.deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let staged = if carrier.final_records_enabled() {
            if !pending.bootstrap {
                return Err(protocol("final ciphertext lacks prepared metadata"));
            }
            carrier.stage_bootstrap_record_tracked(pending.lane, kind, bytes)
        } else {
            carrier.stage_record_tracked(pending.lane, kind, bytes)
        };
        match staged {
            Ok(token) => pending.token = Some(token),
            Err(raw::Error::Busy) => {}
            Err(error) => return Err(raw_error(error)),
        }
        Ok(())
    }
    fn collect_receipts(&mut self) -> io::Result<bool> {
        let mut completed = false;
        let mut first = None;
        // Every occupied lane is observed before any terminal cause propagates.
        for lane in [PairLane::First, PairLane::Second]
            .into_iter()
            .take(self.lanes)
        {
            match self.carrier.take_sent_record_observed(lane) {
                Ok(observation) => {
                    if let Some(sent) = observation.sent {
                        let pending = if self.user.as_ref().is_some_and(|p| {
                            p.pending.lane == lane && p.pending.token == Some(sent.token)
                        }) {
                            self.user.as_mut().map(|p| &mut p.pending)
                        } else if self
                            .control
                            .as_ref()
                            .is_some_and(|p| p.lane == lane && p.token == Some(sent.token))
                        {
                            self.control.as_mut()
                        } else {
                            None
                        };
                        if let Some(pending) = pending {
                            if pending.receipt.is_some() {
                                if first.is_none() {
                                    first = Some(raw::Error::Proof);
                                }
                            } else {
                                pending.token = None;
                                pending.receipt = Some(PhysicalReceipt {
                                    record_bytes: pending.bytes,
                                    udp_bytes: None,
                                    ip_bytes: pending.cost,
                                    accepted_at: sent.sent_at,
                                    deadline: pending.deadline,
                                });
                                completed = true;
                            }
                        } else if first.is_none() {
                            first = Some(raw::Error::Proof);
                        }
                    }
                    if first.is_none() {
                        first = observation.failure;
                    }
                }
                Err(error) => {
                    if first.is_none() {
                        first = Some(error);
                    }
                }
            }
        }
        if self.failure.is_none() {
            self.failure = first;
        }
        Ok(completed)
    }
    fn progress(&mut self, cx: &mut Context<'_>, receive: bool) -> io::Result<bool> {
        if !self.polled && self.failure.is_none() {
            self.polled = true;
            if let Some(control) = &mut self.control {
                let bytes = control.bytes;
                if let Err(error) = Self::stage(
                    &mut self.carrier,
                    control,
                    raw::RecordKind::Feedback,
                    &self.control_bytes[..bytes],
                ) {
                    self.failure = Some(raw::Error::Io {
                        kind: error.kind(),
                        raw_os_error: error.raw_os_error(),
                    });
                }
            }
            if self.failure.is_none()
                && let Poll::Ready(Err(error)) = self.carrier.poll_progress(cx)
            {
                self.failure = Some(error);
            }
        }
        let mut ready = self.collect_receipts()?;
        if self.input.is_none()
            && receive
            && self.failure.is_none()
            && let Some(record) = self.carrier.record()
        {
            let target = self
                .input_bytes
                .get_mut(..record.bytes.len())
                .ok_or_else(|| protocol("raw incoming capacity differs"))?;
            target.copy_from_slice(&record.bytes);
            let input = Input {
                bytes: record.bytes.len(),
                received: record.received_at,
                final_metadata: None,
            };
            self.carrier.consume_record().map_err(raw_error)?;
            self.input = Some(input);
        }
        if self.input.is_none()
            && receive
            && self.failure.is_none()
            && self.carrier.final_records_enabled()
        {
            for lane in [PairLane::First, PairLane::Second]
                .into_iter()
                .take(self.lanes)
            {
                if let Some(candidate) = self.carrier.final_input(lane).map_err(raw_error)? {
                    let bytes = candidate.bytes();
                    self.input_bytes
                        .get_mut(..bytes.len())
                        .ok_or_else(|| protocol("raw final incoming capacity"))?
                        .copy_from_slice(bytes);
                    self.input = Some(Input {
                        bytes: bytes.len(),
                        received: candidate.received_at(),
                        final_metadata: Some((lane, candidate.metadata())),
                    });
                    break;
                }
            }
        }
        ready |= self
            .user
            .as_ref()
            .is_some_and(|u| u.pending.receipt.is_some())
            || self.control.as_ref().is_some_and(|c| c.receipt.is_some())
            || (receive && self.input.is_some());
        if !ready {
            self.fail()?;
        }
        Ok(ready)
    }
    fn result(pending: Pending) -> io::Result<SendProgress> {
        let receipt = pending
            .receipt
            .ok_or_else(|| protocol("raw completion is not physical"))?;
        Ok(SendProgress::Whole {
            late: receipt.accepted_at >= receipt.deadline,
            receipt,
        })
    }
}
impl<I: PacketIo + Send + 'static> RawBacking for RawAdapter<I> {
    fn final_input_metadata(&self) -> Option<FinalMetadata> {
        self.input
            .as_ref()
            .and_then(|input| input.final_metadata.map(|(_, metadata)| metadata))
    }
    fn commit_final_input(
        &mut self,
        metadata: FinalMetadata,
        verdict: Option<FinalAcceptance<()>>,
    ) -> io::Result<()> {
        let input = self
            .input
            .as_ref()
            .ok_or_else(|| protocol("raw final candidate missing"))?;
        let (lane, expected) = input
            .final_metadata
            .ok_or_else(|| protocol("raw final metadata missing"))?;
        if metadata != expected {
            return Err(protocol("raw final candidate changed"));
        }
        let result = self
            .carrier
            .commit_final_input(lane, metadata, verdict)
            .map_err(raw_error);
        self.input = None;
        result
    }
    fn prepare_final(
        &mut self,
        kind: FinalKind,
        bytes: usize,
    ) -> io::Result<Option<FinalMetadata>> {
        self.fail()?;
        if self.prepared.is_some() {
            return Err(protocol("raw reservation already occupied"));
        }
        let lane = if kind == FinalKind::Control {
            self.control_lane()
        } else {
            self.data_lane()
        };
        if self.control.as_ref().is_some_and(|p| p.lane == lane)
            || self.user.as_ref().is_some_and(|u| u.pending.lane == lane)
        {
            return Ok(None);
        }
        match self.carrier.prepare_final_record(lane, kind, bytes) {
            Ok(token) => {
                let metadata = token.metadata();
                self.prepared = Some((lane, token));
                Ok(Some(metadata))
            }
            Err(raw::Error::Busy) => Ok(None),
            Err(error) => Err(raw_error(error)),
        }
    }
    fn prepare_final_control(&mut self) -> io::Result<Option<(FinalMetadata, FinalControl)>> {
        self.fail()?;
        if self.prepared.is_some() || self.control.is_some() {
            return Ok(None);
        }
        for offset in 0..self.lanes {
            let index = (self.control_cursor + offset) % self.lanes;
            let lane = [PairLane::First, PairLane::Second][index];
            if self.user.as_ref().is_some_and(|u| u.pending.lane == lane) {
                continue;
            }
            if let Some(control) = self.carrier.poll_final_control(lane).map_err(raw_error)? {
                let bytes = control
                    .encoded_bytes()
                    .checked_add(l2tunnel::secure_record::compact::AUTHENTICATED_OVERHEAD)
                    .ok_or_else(exhausted)?;
                match self.carrier.prepare_final_control(lane, control, bytes) {
                    Ok(token) => {
                        let metadata = token.metadata();
                        self.prepared = Some((lane, token));
                        self.control_cursor = (index + 1) % self.lanes;
                        return Ok(Some((metadata, control)));
                    }
                    Err(raw::Error::Busy) => {}
                    Err(error) => return Err(raw_error(error)),
                }
            }
        }
        Ok(None)
    }
    fn cancel_final(&mut self) -> io::Result<()> {
        if let Some((_, token)) = self.prepared.take() {
            self.carrier.cancel_final_record(token).map_err(raw_error)?;
        }
        Ok(())
    }
    fn geometry(&self) -> raw::RecordGeometry {
        self.geometry
    }
    fn addresses(&self) -> (SocketAddr, SocketAddr) {
        self.addresses
    }
    fn capacity_bytes(&self) -> io::Result<usize> {
        Layout::array::<Self>(1)
            .map_err(invalid)?
            .size()
            .checked_add(self.control_bytes.capacity())
            .and_then(|n| n.checked_add(self.input_bytes.capacity()))
            .ok_or_else(exhausted)
    }
    fn allocations(&self) -> usize {
        3
    }
    fn next_wake(&self) -> io::Result<Instant> {
        self.carrier.next_wake().map_err(raw_error)
    }
    fn check_failure(&self) -> io::Result<()> {
        self.fail()
    }
    fn begin_turn(&mut self) {
        self.polled = false;
    }
    fn user_pending(&self) -> bool {
        self.user
            .as_ref()
            .is_some_and(|u| u.pending.receipt.is_none())
    }
    fn user_precedes_control(&self) -> bool {
        self.data_lane() == self.control_lane() && self.user_pending()
    }
    fn control_pending(&self) -> bool {
        self.control.is_some()
    }
    fn receive_ready(&self) -> bool {
        self.input.is_some()
    }
    fn deadline(&self) -> Option<Instant> {
        self.user
            .as_ref()
            .map(|u| u.pending.deadline)
            .into_iter()
            .chain(self.control.as_ref().map(|c| c.deadline))
            .min()
    }
    fn try_user(&mut self, identity: UserIdentity, bytes: &[u8]) -> io::Result<SendProgress> {
        self.try_user_inner(identity, bytes, false)
    }
    fn try_user_held(&mut self, identity: UserIdentity, bytes: &[u8]) -> io::Result<SendProgress> {
        self.try_user_inner(identity, bytes, true)
    }
    fn user_accepted_at(&self) -> Option<Instant> {
        self.user
            .as_ref()
            .and_then(|u| u.pending.receipt)
            .map(|r| r.accepted_at)
    }
    fn earliest_input_for_ordering_at(&self) -> io::Result<Option<Instant>> {
        Ok(self
            .input
            .as_ref()
            .map(|i| i.received)
            .into_iter()
            .chain(
                self.carrier
                    .earliest_authenticated_record_at()
                    .map_err(raw_error)?,
            )
            .chain(
                self.carrier
                    .earliest_final_candidate_at()
                    .map_err(raw_error)?,
            )
            .min())
    }
    fn stage_control(
        &mut self,
        bytes: &[u8],
        cost: usize,
        deadline: Instant,
        bootstrap: bool,
    ) -> io::Result<SendProgress> {
        if self.control.is_some() {
            return Err(protocol("raw Control custody already occupied"));
        }
        let lane = self
            .prepared
            .as_ref()
            .map_or_else(|| self.control_lane(), |(lane, _)| *lane);
        let mut pending = self.pending(lane, bytes.len(), deadline)?;
        pending.bootstrap = bootstrap;
        if bootstrap {
            pending.cost = self
                .bootstrap_geometry
                .ip_bytes(bytes.len())
                .map_err(raw_error)?;
        }
        if pending.cost != cost {
            return Err(protocol("raw Control full-IP debit differs"));
        }
        self.control_bytes
            .get_mut(..bytes.len())
            .ok_or_else(|| invalid("raw Control output capacity"))?
            .copy_from_slice(bytes);
        if self.carrier.final_records_enabled() && !bootstrap {
            let (lane, token) = self
                .prepared
                .take()
                .ok_or_else(|| protocol("raw final Control reservation missing"))?;
            if lane != pending.lane {
                return Err(protocol("raw final Control lane changed"));
            }
            pending.token = Some(
                self.carrier
                    .commit_final_record(token, bytes)
                    .map_err(raw_error)?,
            );
        } else {
            Self::stage(
                &mut self.carrier,
                &mut pending,
                raw::RecordKind::Feedback,
                bytes,
            )?;
        }
        self.control = Some(pending);
        Ok(SendProgress::Pending)
    }
    fn take_control(&mut self) -> io::Result<Option<(SendProgress, usize)>> {
        // Read-only physical observation also recovers receipts saved when
        // staging/check_live terminated the other original lane. No I/O/poll.
        self.collect_receipts()?;
        if self.control.as_ref().is_some_and(|p| p.receipt.is_some()) {
            let pending = self
                .control
                .take()
                .ok_or_else(|| protocol("raw Control custody missing"))?;
            let cost = pending.cost;
            return Self::result(pending).map(|p| Some((p, cost)));
        }
        self.fail()?;
        Ok(None)
    }
    fn take_user(&mut self) -> io::Result<Option<(UserIdentity, SendProgress)>> {
        // Read-only physical observation also recovers receipts saved when
        // staging/check_live terminated the other original lane. No I/O/poll.
        self.collect_receipts()?;
        if self
            .user
            .as_ref()
            .is_some_and(|u| u.pending.receipt.is_some())
        {
            let user = self
                .user
                .take()
                .ok_or_else(|| protocol("raw User custody missing"))?;
            return Self::result(user.pending).map(|p| Some((user.identity, p)));
        }
        self.fail()?;
        Ok(None)
    }
    fn try_receive(&mut self, output: &mut [u8]) -> io::Result<(usize, Instant)> {
        let input = self.input.as_ref().ok_or(io::ErrorKind::WouldBlock)?;
        let target = output
            .get_mut(..input.bytes)
            .ok_or_else(|| invalid("raw incoming caller capacity"))?;
        target.copy_from_slice(&self.input_bytes[..input.bytes]);
        let result = (input.bytes, input.received);
        if input.final_metadata.is_none() {
            self.input = None;
        }
        Ok(result)
    }
    fn poll_ready(&mut self, cx: &mut Context<'_>, receive: bool) -> Poll<io::Result<()>> {
        match self.progress(cx, receive) {
            Ok(true) => Poll::Ready(Ok(())),
            Ok(false) => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }
    fn poll_setup_send(
        &mut self,
        cx: &mut Context<'_>,
        bytes: &[u8],
        deadline: Instant,
    ) -> Poll<io::Result<()>> {
        if self.control.is_none() {
            let cost = match self.geometry.ip_bytes(bytes.len()).map_err(raw_error) {
                Ok(n) => n,
                Err(e) => return Poll::Ready(Err(e)),
            };
            if let Err(e) = self.stage_control(bytes, cost, deadline, true) {
                return Poll::Ready(Err(e));
            }
        } else if !self
            .control
            .as_ref()
            .is_some_and(|c| c.deadline == deadline && c.bytes == bytes.len())
            || self.control_bytes.get(..bytes.len()) != Some(bytes)
        {
            return Poll::Ready(Err(protocol(
                "raw setup Control identity changed while pending",
            )));
        }
        self.begin_turn();
        if let Err(e) = self.progress(cx, true) {
            return Poll::Ready(Err(e));
        }
        match self.take_control() {
            Ok(Some((SendProgress::Whole { receipt, late }, _))) => {
                if late || Instant::now() >= receipt.deadline {
                    Poll::Ready(Err(io::ErrorKind::TimedOut.into()))
                } else {
                    Poll::Ready(Ok(()))
                }
            }
            Ok(_) => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}
fn buffer(bytes: usize) -> io::Result<Vec<u8>> {
    let mut result = Vec::new();
    result.try_reserve_exact(bytes).map_err(io::Error::other)?;
    if result.capacity() != bytes {
        return Err(protocol("raw buffer capacity differs"));
    }
    result.resize(bytes, 0);
    Ok(result)
}
pub(in crate::secure_udp) fn raw_error(error: raw::Error) -> io::Error {
    let kind = match &error {
        raw::Error::Io { kind, .. } => *kind,
        raw::Error::Expired => io::ErrorKind::TimedOut,
        raw::Error::Busy => io::ErrorKind::WouldBlock,
        raw::Error::Configuration => io::ErrorKind::InvalidInput,
        _ => io::ErrorKind::InvalidData,
    };
    io::Error::new(kind, error)
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}
fn protocol(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}
fn exhausted() -> io::Error {
    io::Error::other("raw adapter checked capacity exhausted")
}
