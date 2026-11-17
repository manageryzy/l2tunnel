use super::*;
use l2tunnel_device::PacketLayer;

pub(super) const RETAINED: u64 = 16_777_216;
pub(super) const PEAK: u64 = 20_971_520;
pub(super) const METADATA: u64 = 1_048_576;
pub(super) const TRANSCRIPT: usize = 236;
pub(super) const RECORD: usize = 244;
pub(super) const PAIR_MAGIC: &[u8; 4] = b"L2RP";
#[derive(Clone)]
pub(super) struct Profile {
    pub digest: ConfigDigest,
    pub bases: [SessionConfig; 2],
    pub expected: [SessionConfig; 2],
    pub resources: ResourceCharge,
    pub count: usize,
}
fn add(a: u64, b: u64) -> Result<u64, PairError> {
    a.checked_add(b).ok_or(PairError::Capacity)
}
fn mul(a: u64, b: u64) -> Result<u64, PairError> {
    a.checked_mul(b).ok_or(PairError::Capacity)
}
pub(super) fn micros(value: Duration) -> Result<u64, PairError> {
    if !value.subsec_nanos().is_multiple_of(1000) {
        return Err(PairError::Configuration);
    }
    u64::try_from(value.as_micros()).map_err(|_| PairError::Capacity)
}
pub(super) fn geometry(a: Config, b: Config) -> bool {
    a.mtu == b.mtu
        && a.send_bytes == b.send_bytes
        && a.receive_bytes == b.receive_bytes
        && a.packet_slots == b.packet_slots
        && a.ack_delay_millis == b.ack_delay_millis
        && a.keepalive_millis == b.keepalive_millis
        && a.idle_timeout_millis == b.idle_timeout_millis
}
pub(super) fn bulk(count: usize, lane: usize) -> u8 {
    if count == 1 { 0 } else { lane as u8 + 1 }
}
pub(super) fn hash(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0; 32];
    out.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref());
    out
}
pub(super) fn payload_charge(raw: Config, count: usize) -> Result<ResourceCharge, PairError> {
    let (l, m, p) = (count as u64, raw.mtu as u64, raw.packet_slots as u64);
    let mut per = add(raw.send_bytes as u64, raw.receive_bytes as u64)?;
    per = add(per, mul(mul(2, p)?, m)?)?;
    per = add(per, mul(5, m)?)?;
    per = add(per, 65_536 + 2 * 4_104 + 6 * 32)?;
    let retained = add(mul(l, per)?, 236 + 2 * 244)?;
    let peak = add(add(retained, mul(l, add(mul(2, m)?, 6 * 32)?)?)?, 64 + 244)?;
    if retained > RETAINED || peak > PEAK {
        return Err(PairError::Capacity);
    }
    Ok(ResourceCharge {
        retained_payload: retained,
        peak_payload: peak,
        metadata: 0,
    })
}
pub(super) fn encoding(
    config: PairConfig,
    raw: Config,
    count: usize,
) -> Result<Vec<u8>, PairError> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(b"l2tunnel/raw-owned-pair/v1\0");
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&[
        match config.session.layer {
            PacketLayer::Ethernet => 1,
            PacketLayer::Ip => 2,
        },
        if count == 1 { 1 } else { 2 },
        count as u8,
        0,
        0,
        0,
    ]);
    out.extend_from_slice(&config.session.digest.0);
    for n in [raw.mtu, raw.send_bytes, raw.receive_bytes] {
        out.extend_from_slice(
            &u32::try_from(n)
                .map_err(|_| PairError::Capacity)?
                .to_be_bytes(),
        );
    }
    out.extend_from_slice(
        &u16::try_from(raw.packet_slots)
            .map_err(|_| PairError::Capacity)?
            .to_be_bytes(),
    );
    for n in [
        raw.ack_delay_millis,
        raw.keepalive_millis,
        raw.idle_timeout_millis,
    ] {
        out.extend_from_slice(&mul(n, 1000)?.to_be_bytes());
    }
    out.extend_from_slice(
        &u16::try_from(config.driver.work_limit)
            .map_err(|_| PairError::Capacity)?
            .to_be_bytes(),
    );
    for d in [config.driver.max_handoff_duration, config.timeout] {
        out.extend_from_slice(&micros(d)?.to_be_bytes());
    }
    let m = config.messages;
    out.extend_from_slice(&m.max_payload.to_be_bytes());
    out.extend_from_slice(&m.messages_per_direction.to_be_bytes());
    out.extend_from_slice(&m.bytes_per_direction.to_be_bytes());
    for d in [m.records.incoming, m.records.outgoing] {
        out.extend_from_slice(&d.wire_bytes.to_be_bytes());
        out.extend_from_slice(&d.records.to_be_bytes());
    }
    out.extend_from_slice(&m.records.max_payload.to_be_bytes());
    out.extend_from_slice(b"L2RM\x01\0");
    out.extend_from_slice(&8u16.to_be_bytes());
    out.extend_from_slice(PAIR_MAGIC);
    out.push(1);
    for n in [8u16, 244, 236] {
        out.extend_from_slice(&n.to_be_bytes());
    }
    out.extend_from_slice(&[1, 2, 3]);
    out.extend_from_slice(&[0, bulk(count, 0), 1, 0]);
    out.extend_from_slice(if count == 1 {
        &[0, 0, 0, 0]
    } else {
        &[1, 2, 1, 0]
    });
    out.extend_from_slice(&1u16.to_be_bytes());
    for n in [RETAINED, PEAK, METADATA] {
        out.extend_from_slice(&n.to_be_bytes());
    }
    out.extend_from_slice(&1u16.to_be_bytes());
    Ok(out)
}
pub(super) fn validate<I: PacketIo>(
    inputs: &RawInputs<I>,
    config: PairConfig,
) -> Result<Profile, PairError> {
    let (first, second) = inputs.configs();
    validate_configs(first, second, config)
}
pub(super) fn validate_configs(
    a: Config,
    b: Option<Config>,
    config: PairConfig,
) -> Result<Profile, PairError> {
    config.messages.validate().map_err(PairError::Start)?;
    config
        .driver
        .validate()
        .map_err(|_| PairError::Configuration)?;
    let us = micros(config.timeout)?;
    micros(config.driver.max_handoff_duration)?;
    if !(1000..=30_000_000).contains(&us)
        || config.messages.max_payload < RECORD as u16
        || config.messages.messages_per_direction < 3
        || config.messages.bytes_per_direction < 756
    {
        return Err(PairError::Configuration);
    }
    l2tunnel_raw_tcp::IpConfig::from(a)
        .validate()
        .map_err(|_| PairError::Configuration)?;
    if let Some(b) = b {
        l2tunnel_raw_tcp::IpConfig::from(b)
            .validate()
            .map_err(|_| PairError::Configuration)?;
        if !geometry(a, b) || (a.local == b.local && a.peer == b.peer) {
            return Err(PairError::Configuration);
        }
    }
    let count = if b.is_some() { 2 } else { 1 };
    let resources = payload_charge(a, count)?;
    let digest = ConfigDigest(hash(&encoding(config, a, count)?));
    let mut bases = [config.session; 2];
    let mut expected = [config.session; 2];
    for i in 0..count {
        let mut context = b"l2tunnel/raw-owned-pair-lane/v1\0".to_vec();
        context.extend_from_slice(&digest.0);
        context.extend_from_slice(&[i as u8, bulk(count, i)]);
        bases[i].digest = ConfigDigest(hash(&context));
        expected[i] = super::super::tls_owner::message_session_config(bases[i], config.messages)
            .map_err(PairError::Start)?;
    }
    Ok(Profile {
        digest,
        bases,
        expected,
        resources,
        count,
    })
}

// Private canonical serialization only: SessionInfo is not ownership authority.
pub(super) fn transcript_bytes(
    profile: &Profile,
    nonce: [u8; 32],
    lanes: [Option<SessionInfo>; 2],
) -> Result<[u8; TRANSCRIPT], PairError> {
    if !(1..=2).contains(&profile.count) {
        return Err(PairError::Identity);
    }
    let first = lanes[0].ok_or(PairError::Identity)?;
    let mut out = [0; TRANSCRIPT];
    out[..4].copy_from_slice(&[1, profile.count as u8, profile.count as u8, 0]);
    out[4..36].copy_from_slice(&profile.digest.0);
    out[36..68].copy_from_slice(&nonce);
    out[68..100].copy_from_slice(&first.member.0);
    out[100..132].copy_from_slice(&first.server.0);
    for (i, lane) in lanes.iter().enumerate().take(profile.count) {
        let lane = lane.ok_or(PairError::Identity)?;
        let at = 132 + i * 52;
        out[at] = i as u8;
        out[at + 1] = bulk(profile.count, i);
        out[at + 4..at + 20].copy_from_slice(&lane.session_id);
        out[at + 20..at + 52].copy_from_slice(&lane.config.digest.0);
    }
    Ok(out)
}
