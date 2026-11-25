//! Hot switches across a generated live-tuning catalog: FEC on and off, the
//! inner packet size and the path size (docs/modules/live-tuning.md,
//! decisions 1, 7 and 8).
use super::*;
use l2tunnel::live_tuning::{self, Choices, Repair, Setting};
use l2tunnel::record_configuration as c;

/// The fixture's Swift entry with both directions on one datagram size, as
/// the generator requires.
fn symmetric_swift(kind: cover::Appearance) -> Result<c::Descriptor> {
    let base = *udp_values(kind)?[0].descriptor();
    let c::Profile::Swift {
        forward,
        mut reverse,
    } = *base.profile()
    else {
        return Err("fixture entry is not Swift".into());
    };
    reverse.codec.datagram_bytes = forward.codec.datagram_bytes;
    Ok(c::Descriptor::new(
        base.path_mtu(),
        base.duplex(),
        *base.direction(mg::Role::Client).common(),
        *base.direction(mg::Role::Server).common(),
        c::Profile::Swift { forward, reverse },
    )?)
}

/// An Ethernet/IPv4/UDP frame of exactly `size` bytes.
fn sized_frame(port: u16, number: u8, size: usize) -> Vec<u8> {
    let mut packet = frame(port, number);
    packet.resize(size, number);
    let ip_length = u16::try_from(size - 14).unwrap_or(u16::MAX);
    let ip = &mut packet[14..];
    ip[2..4].copy_from_slice(&ip_length.to_be_bytes());
    ip[10..12].fill(0);
    let sum: u32 = ip[..20]
        .chunks_exact(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], pair[1]])))
        .sum();
    let sum = (sum & 0xffff) + (sum >> 16);
    let sum = (sum & 0xffff) + (sum >> 16);
    ip[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    ip[24..26].copy_from_slice(&(ip_length - 20).to_be_bytes());
    packet
}

impl Fixture {
    /// Admit `packet` on `side` and report whether the peer's device got it
    /// unchanged within a bounded number of turns.
    async fn delivered(&mut self, side: usize, packet: &[u8]) -> Result<bool> {
        self.admit(side, packet).await?;
        let mut output = vec![0; READ_BUFFER_BYTES];
        for _ in 0..200 {
            self.turn().await?;
            match self.endpoints[1 - side].host.recv(&mut output) {
                Ok(bytes) => return Ok(output[..bytes] == *packet),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(false)
    }
}

fn entry(catalog: &Catalog, wanted: Setting) -> Result<c::Descriptor> {
    catalog
        .descriptors()
        .iter()
        .copied()
        .find(|descriptor| live_tuning::setting(descriptor).is_ok_and(|s| s == wanted))
        .ok_or_else(|| "generated entry missing".into())
}

#[test]
fn generated_catalog_switches_fec_inner_size_and_path_size_live() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let kind = cover::Appearance::QuicLike;
            let base = symmetric_swift(kind)?;
            let choices = Choices {
                repair: vec![Repair::Rate {
                    numerator: 1,
                    denominator: 2,
                }],
                device_mtu: vec![512],
                path_mtu: vec![1450],
            };
            // The real flow: both ends build the base plan's contract, then
            // switch within the catalog generated from the proposal.
            let plan = Catalog::new(base, &[base])?;
            let catalog = live_tuning::extend(&plan, &choices, &live_tuning::Limits::PROTOCOL)?;
            assert_eq!(catalog.descriptors().len(), 2 * 2 * 2);
            let [client, server] = contracts_with_catalog(kind, plan, 16)?;
            let base_identity = client.expected_configuration();
            let contracts = [
                client.with_live_catalog(catalog.clone())?,
                server.with_live_catalog(catalog.clone())?,
            ];
            for contract in &contracts {
                assert_eq!(contract.expected_configuration(), base_identity);
                assert_eq!(contract.catalog(), &catalog);
            }
            let mut fixture = Fixture::from_contracts(kind, contracts).await?;
            let envelope = fixture.endpoints[0]
                .driver
                .common
                .as_ref()
                .ok_or("common contract absent")?
                .contract
                .envelope();
            let initial = live_tuning::setting(&base)?;
            assert_eq!(initial.device_mtu, 1024);
            fixture.exchange_all_channels(1).await?;
            let large = sized_frame(40_100, 7, 900);
            let medium = sized_frame(40_101, 8, 500);
            assert!(fixture.delivered(0, &large).await?);
            assert!(fixture.delivered(1, &large).await?);

            // FEC on, smaller inner packets, smaller path packets.
            let small = Setting {
                repair: Repair::Rate {
                    numerator: 1,
                    denominator: 2,
                },
                device_mtu: 512,
                path_mtu: 1450,
            };
            let target = C::new(envelope, entry(&catalog, small)?)?;
            let mut epoch = fixture.switch(target).await?.0;
            fixture.exchange_all_channels(2).await?;
            assert!(fixture.delivered(0, &medium).await?);
            assert!(fixture.delivered(1, &medium).await?);
            // A packet above the new inner size is dropped and counted.
            let before = fixture.endpoints[0].driver.counters.native_oversize;
            assert!(!fixture.delivered(0, &large).await?);
            assert_eq!(
                fixture.endpoints[0].driver.counters.native_oversize,
                before + 1
            );
            for endpoint in &fixture.endpoints {
                let snapshot = endpoint.driver.snapshot_common(fixture.now, true)?;
                assert_eq!(snapshot.current, target);
            }

            // FEC off at the small size, then back to the starting entry.
            let off = Setting {
                repair: Repair::Off,
                ..small
            };
            let target = C::new(envelope, entry(&catalog, off)?)?;
            assert_eq!(fixture.switch(target).await?.0, epoch + 1);
            epoch += 1;
            assert!(fixture.delivered(1, &medium).await?);
            let target = C::new(envelope, entry(&catalog, initial)?)?;
            assert_eq!(fixture.switch(target).await?.0, epoch + 1);
            fixture.exchange_all_channels(3).await?;
            assert!(fixture.delivered(0, &large).await?);
            assert!(fixture.delivered(1, &large).await?);
            Ok(())
        })
}

#[test]
fn live_catalog_keeps_the_base_identity_and_its_initial_entry() -> Result {
    let kind = cover::Appearance::QuicLike;
    let base = symmetric_swift(kind)?;
    let plan = Catalog::new(base, &[base])?;
    let choices = Choices {
        device_mtu: vec![512],
        ..Choices::default()
    };
    let catalog = live_tuning::extend(&plan, &choices, &live_tuning::Limits::PROTOCOL)?;
    let [client, _] = contracts_with_catalog(kind, plan.clone(), 16)?;
    // A catalog around another initial entry is refused.
    let other = live_tuning::generate(
        &catalog
            .descriptors()
            .iter()
            .copied()
            .find(|d| *d != base)
            .ok_or("second entry")?,
        &Choices::default(),
        &live_tuning::Limits::PROTOCOL,
    )?;
    assert!(client.clone().with_live_catalog(other).is_err());
    let tuned = client.with_live_catalog(catalog.clone())?;
    assert_eq!(tuned.catalog(), &catalog);
    assert_eq!(tuned.initial().descriptor(), &base);
    Ok(())
}

/// Records each device MTU change; fails the values in `refuse`.
#[derive(Default)]
struct RecordingMtu {
    calls: std::sync::Mutex<Vec<u32>>,
    refuse: Vec<u32>,
}
impl super::device_mtu::DeviceMtu for RecordingMtu {
    fn set(
        &self,
        mtu: u32,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send + '_>> {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(mtu);
        let refused = self.refuse.contains(&mtu);
        Box::pin(async move {
            if refused {
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            } else {
                Ok(())
            }
        })
    }
}

/// Run what the loop would: take the wanted change and report it done.
fn apply(runtime: &tokio::runtime::Runtime, gate: &mut super::device_mtu::Gate) -> Option<u32> {
    let (setter, mtu) = gate.take_wanted()?;
    let result = runtime.block_on(setter.set(mtu));
    gate.done(mtu, result);
    Some(mtu)
}

#[test]
fn device_mtu_is_lowered_before_a_switch_down_and_raised_after_a_switch_up() -> Result {
    use super::device_mtu::{Gate, Readiness};
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    let kind = cover::Appearance::QuicLike;
    let base = symmetric_swift(kind)?;
    let plan = Catalog::new(base, &[base])?;
    let choices = Choices {
        device_mtu: vec![512],
        ..Choices::default()
    };
    let catalog = live_tuning::extend(&plan, &choices, &live_tuning::Limits::PROTOCOL)?;
    let envelope = udp_values(kind)?[0].envelope();
    let large = C::new(envelope, base)?;
    let small_setting = Setting {
        device_mtu: 512,
        ..live_tuning::setting(&base)?
    };
    let small = C::new(envelope, entry(&catalog, small_setting)?)?;
    let setter = std::sync::Arc::new(RecordingMtu::default());
    // The fixture device is TAP: its MTU excludes the Ethernet header.
    let mut gate = Gate::new(setter.clone(), PacketLayer::Ethernet, mg::Role::Client);
    assert_eq!(gate.mtu_of(&large), Some(1024 - 14));
    assert_eq!(gate.mtu_of(&small), Some(512 - 14));

    // The first idle turn sets the current entry's size.
    gate.reconcile(&large, false);
    assert_eq!(apply(&runtime, &mut gate), Some(1010));
    // Switch down: the step waits until the device is lowered.
    assert_eq!(gate.ready_for(&small), Readiness::Wait);
    assert_eq!(apply(&runtime, &mut gate), Some(498));
    assert_eq!(gate.ready_for(&small), Readiness::Ready);
    // While the switch is in flight nothing raises the lowered device.
    gate.reconcile(&large, true);
    assert_eq!(apply(&runtime, &mut gate), None);
    // Committed: the device already fits the new entry.
    gate.reconcile(&small, false);
    assert_eq!(apply(&runtime, &mut gate), None);
    // Switch up: ready at once; the raise waits for the commit.
    assert_eq!(gate.ready_for(&large), Readiness::Ready);
    gate.reconcile(&small, true);
    assert_eq!(apply(&runtime, &mut gate), None);
    gate.reconcile(&large, false);
    assert_eq!(apply(&runtime, &mut gate), Some(1010));
    // An aborted switch down returns to the current entry's size.
    assert_eq!(gate.ready_for(&small), Readiness::Wait);
    assert_eq!(apply(&runtime, &mut gate), Some(498));
    gate.reconcile(&large, false);
    assert_eq!(apply(&runtime, &mut gate), Some(1010));
    assert_eq!(
        *setter
            .calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        [1010, 498, 1010, 498, 1010]
    );
    let snapshot = gate.snapshot();
    assert_eq!(
        (snapshot.applied, snapshot.wanted, snapshot.failures),
        (Some(1010), Some(1010), 0)
    );

    // A failed lowering is reported once and not retried by itself.
    let refusing = std::sync::Arc::new(RecordingMtu {
        refuse: vec![498],
        ..RecordingMtu::default()
    });
    let mut gate = Gate::new(refusing.clone(), PacketLayer::Ethernet, mg::Role::Server);
    gate.reconcile(&large, false);
    assert_eq!(apply(&runtime, &mut gate), Some(1010));
    assert_eq!(gate.ready_for(&small), Readiness::Wait);
    assert_eq!(apply(&runtime, &mut gate), Some(498));
    assert_eq!(gate.ready_for(&small), Readiness::Failed);
    gate.reconcile(&small, false);
    assert_eq!(apply(&runtime, &mut gate), None);
    let snapshot = gate.snapshot();
    assert_eq!(snapshot.failures, 1);
    assert_eq!(snapshot.last_error, Some(io::ErrorKind::PermissionDenied));
    assert_eq!(snapshot.applied, Some(1010));
    Ok(())
}
