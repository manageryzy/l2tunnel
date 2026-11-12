use super::*;
use l2tunnel_device::PacketLayer;
use std::{
    collections::VecDeque,
    future::poll_fn,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::sync::mpsc;
type R<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
fn connection(half: bool, layer: PacketLayer) -> ConnectionConfig {
    ConnectionConfig {
        layer,
        duplex: if half { Duplex::Half } else { Duplex::Full },
        max_packet: 4000,
        compression: crate::Compression::None,
        handshake_timeout: Duration::from_secs(5),
    }
}
fn document(half: bool, server: bool, cauchy: bool, integrity: bool) -> serde_json::Value {
    let endpoints =
        |a, b| serde_json::json!({"local":if server{b}else{a},"peer":if server{a}else{b}});
    serde_json::json!({"version":1,"profile":PROFILE,"forward":endpoints("192.0.2.11:45001","192.0.2.12:45002"),"reverse":if half{endpoints("192.0.2.11:45003","192.0.2.12:45004")}else{serde_json::Value::Null},"channels":4,"packet":{"mtu":576,"protection":if integrity{"integrity"}else{"aead"},"queue_packets":8,"horizon_bytes":32768,"minimum_transfer_bytes":65536,"bytes_per_second":1048576,"packets_per_second":2048,"burst_bytes":16384,"burst_packets":32,"max_key_packets":1048576,"max_key_bytes":1073741824},"recovery":if cauchy{serde_json::json!({"mode":"cauchy","sources":4,"repairs":2,"flush_micros":2000})}else{serde_json::json!({"mode":"selective_repeat"})}})
}
fn settings(half: bool, server: bool, cauchy: bool, integrity: bool) -> R<Settings> {
    Ok(Settings::from_json(&serde_json::to_vec(&document(
        half, server, cauchy, integrity,
    ))?)?)
}
struct Credentials {
    client: ClientTls,
    server: ServerTls,
    member: MemberKey,
    allow: MemberAllowlist,
}
fn credentials() -> R<Credentials> {
    let cert = rcgen::generate_simple_self_signed(vec!["raw-client.test".into()])?;
    let chain = vec![cert.cert.der().to_vec()];
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    Ok(Credentials {
        client: ClientTls::from_der_roots(&chain)?,
        server: ServerTls::from_der(&chain, &cert.signing_key.serialize_der())?,
        allow: MemberAllowlist::new(&[member.public_key()])?,
        member,
    })
}
#[derive(Default)]
struct Probe {
    polls: AtomicUsize,
    drops: AtomicUsize,
}
struct Io {
    incoming: mpsc::Receiver<Vec<u8>>,
    outgoing: mpsc::Sender<Vec<u8>>,
    probe: Arc<Probe>,
}
impl PacketIo for Io {
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        self.probe.polls.fetch_add(1, Ordering::SeqCst);
        match self.incoming.try_recv() {
            Ok(p) => {
                out[..p.len()].copy_from_slice(&p);
                Ok(Some(p.len()))
            }
            Err(_) => Ok(None),
        }
    }
    fn send(&mut self, p: &[u8]) -> io::Result<()> {
        self.probe.polls.fetch_add(1, Ordering::SeqCst);
        self.outgoing
            .try_send(p.to_vec())
            .map_err(|_| io::ErrorKind::WouldBlock.into())
    }
}
impl Drop for Io {
    fn drop(&mut self) {
        self.probe.drops.fetch_add(1, Ordering::SeqCst);
    }
}
fn ios(half: bool) -> (VecDeque<Io>, VecDeque<Io>, Vec<Arc<Probe>>) {
    let (mut a, mut b, mut probes) = (VecDeque::new(), VecDeque::new(), Vec::new());
    for _ in 0..if half { 2 } else { 1 } {
        let (at, br) = mpsc::channel(256);
        let (bt, ar) = mpsc::channel(256);
        let ap = Arc::new(Probe::default());
        let bp = Arc::new(Probe::default());
        probes.extend([ap.clone(), bp.clone()]);
        a.push_back(Io {
            incoming: ar,
            outgoing: at,
            probe: ap,
        });
        b.push_back(Io {
            incoming: br,
            outgoing: bt,
            probe: bp,
        });
    }
    (a, b, probes)
}
fn opener(mut io: VecDeque<Io>, role: Role) -> impl FnMut(RawConfig, Role) -> io::Result<Io> {
    move |config, actual| {
        assert_eq!(actual, role);
        assert_ne!(config.random_seed, 0);
        io.pop_front()
            .ok_or_else(|| invalid("extra fixture opener"))
    }
}
#[test]
fn strict_policy_limits_all_levels_and_runtime_binding() -> R {
    let base = document(false, false, true, false);
    for path in [
        vec!["unknown"],
        vec!["forward", "unknown"],
        vec!["packet", "unknown"],
        vec!["recovery", "unknown"],
    ] {
        let mut value = base.clone();
        let mut at = &mut value;
        for key in &path[..path.len() - 1] {
            at = &mut at[*key];
        }
        at[path[path.len() - 1]] = serde_json::json!(1);
        assert!(Settings::from_json(&serde_json::to_vec(&value)?).is_err());
    }
    for key in [
        "version", "profile", "forward", "channels", "packet", "recovery",
    ] {
        let mut value = base.clone();
        value.as_object_mut().ok_or("object")?.remove(key);
        assert!(Settings::from_json(&serde_json::to_vec(&value)?).is_err());
    }
    for text in ["\"version\":1,", "\"forward\":{},"] {
        let encoded = serde_json::to_string(&base)?;
        let duplicate = format!("{{{text}{}", &encoded[1..]);
        assert!(Settings::from_json(duplicate.as_bytes()).is_err());
    }
    for (needle, replacement) in [
        ("\"mtu\":576", "\"mtu\":576,\"mtu\":576"),
        (
            "\"local\":\"192.0.2.11:45001\"",
            "\"local\":\"192.0.2.11:45001\",\"local\":\"192.0.2.11:45001\"",
        ),
        ("\"sources\":4", "\"sources\":4,\"sources\":4"),
    ] {
        let text = serde_json::to_string(&base)?;
        assert!(text.contains(needle));
        assert!(Settings::from_json(text.replace(needle, replacement).as_bytes()).is_err());
    }
    let mut maximum = serde_json::to_vec(&base)?;
    maximum.resize(MAX_POLICY_BYTES, b' ');
    assert!(Settings::from_json(&maximum).is_ok());
    for (path, value) in [
        (vec!["version"], serde_json::json!(2)),
        (vec!["profile"], serde_json::json!("automatic")),
        (vec!["packet", "mtu"], serde_json::json!(575)),
        (vec!["packet", "queue_packets"], serde_json::json!(0)),
        (vec!["forward", "peer"], serde_json::json!("[::1]:99")),
    ] {
        let mut bad = base.clone();
        let mut at = &mut bad;
        for key in &path[..path.len() - 1] {
            at = &mut at[*key];
        }
        at[path[path.len() - 1]] = value;
        assert!(Settings::from_json(&serde_json::to_vec(&bad)?).is_err());
    }
    assert!(Settings::from_json(&vec![b' '; MAX_POLICY_BYTES + 1]).is_err());
    assert!(Settings::from_json(b"").is_err());
    let config = connection(false, PacketLayer::Ip);
    let base = settings(false, false, false, false)?;
    let digest = base.runtime_config(config)?.session_config()?.digest;
    let mut altered = base.clone();
    altered.0.channels = 3;
    assert_ne!(
        digest,
        altered.runtime_config(config)?.session_config()?.digest
    );
    for change in [0, 257] {
        altered.0.channels = change;
        assert!(altered.runtime_config(config).is_err());
    }
    assert!(
        base.runtime_config(connection(true, PacketLayer::Ip))
            .is_err()
    );
    let mut huge = config;
    huge.handshake_timeout = Duration::from_secs(31);
    assert!(base.runtime_config(huge).is_err());
    Ok(())
}
#[tokio::test]
async fn pre_io_rejection_second_open_failure_and_original_deadline_drop_owners() -> R {
    let credentials = credentials()?;
    let policy = settings(true, false, false, false)?;
    let mut count = 0;
    let invalid_config = connection(false, PacketLayer::Ip);
    let bad = begin_client_with::<Io>(
        &policy,
        invalid_config,
        &credentials.client,
        "raw-client.test",
        &credentials.member,
        |_, _| {
            count += 1;
            Err(io::ErrorKind::PermissionDenied.into())
        },
    );
    assert!(bad.is_err());
    assert_eq!(count, 0);
    for mutation in [0, 1] {
        let mut invalid = policy.clone();
        if mutation == 0 {
            invalid.0.channels = 0;
        } else {
            invalid.0.recovery = Recovery::Cauchy {
                sources: 17,
                repairs: 1,
                flush_micros: 1,
            };
        }
        let mut calls = 0;
        let result = begin_client_with::<Io>(
            &invalid,
            connection(true, PacketLayer::Ip),
            &credentials.client,
            "raw-client.test",
            &credentials.member,
            |_, _| {
                calls += 1;
                Err(io::ErrorKind::PermissionDenied.into())
            },
        );
        assert!(result.is_err());
        assert_eq!(calls, 0);
    }
    let (mut a, _, probes) = ios(true);
    let mut calls = 0;
    let result = begin_client_with(
        &policy,
        connection(true, PacketLayer::Ip),
        &credentials.client,
        "raw-client.test",
        &credentials.member,
        |_, _| {
            calls += 1;
            if calls == 2 {
                Err(io::ErrorKind::PermissionDenied.into())
            } else {
                a.pop_front().ok_or_else(|| invalid("fixture input"))
            }
        },
    );
    assert!(matches!(result,Err(e)if e.kind()==io::ErrorKind::PermissionDenied));
    assert_eq!(probes[0].drops.load(Ordering::SeqCst), 1);
    assert_eq!(probes[0].polls.load(Ordering::SeqCst), 0);
    let full = settings(false, false, false, false)?;
    let (mut a, _, probes) = ios(false);
    let mut config = connection(false, PacketLayer::Ip);
    config.handshake_timeout = Duration::from_millis(100);
    let result = begin_client_with(
        &full,
        config,
        &credentials.client,
        "raw-client.test",
        &credentials.member,
        |_, _| {
            std::thread::sleep(Duration::from_millis(110));
            a.pop_front().ok_or_else(|| invalid("fixture input"))
        },
    );
    assert!(matches!(result,Err(e)if e.kind()==io::ErrorKind::TimedOut));
    assert_eq!(probes[0].drops.load(Ordering::SeqCst), 1);
    assert_eq!(probes[0].polls.load(Ordering::SeqCst), 0);
    let result = begin_client_with::<Io>(
        &full,
        config,
        &credentials.client,
        "raw-client.test",
        &credentials.member,
        |_, _| {
            std::thread::sleep(Duration::from_millis(110));
            Err(io::ErrorKind::PermissionDenied.into())
        },
    );
    assert!(matches!(result,Err(e)if e.kind()==io::ErrorKind::TimedOut));
    Ok(())
}
#[tokio::test]
async fn original_setup_expiry_and_cancellation_release_both_original_lanes() -> R {
    let credentials = credentials()?;
    let settings = settings(true, false, false, false)?;
    for cancel in [false, true] {
        let (a, _b, probes) = ios(true);
        let mut config = connection(true, PacketLayer::Ip);
        config.handshake_timeout = Duration::from_millis(30);
        let mut setup = begin_client_with(
            &settings,
            config,
            &credentials.client,
            "raw-client.test",
            &credentials.member,
            opener(a, Role::Client),
        )?;
        let observed = setup.observer();
        assert!(observed.snapshot().effective.is_none());
        if cancel {
            poll_fn(|cx| {
                assert!(Pin::new(&mut setup).poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            drop(setup);
        } else {
            assert!(matches!(setup.await,Err(e)if e.kind()==io::ErrorKind::TimedOut));
        }
        assert_eq!(observed.snapshot().phase, "Stopped");
        for i in [0, 2] {
            assert_eq!(probes[i].drops.load(Ordering::SeqCst), 1);
        }
    }
    Ok(())
}
#[derive(Default)]
struct Native {
    outgoing: VecDeque<Vec<u8>>,
    delivered: Vec<Vec<u8>>,
}
#[derive(Clone)]
struct Device {
    layer: PacketLayer,
    state: Arc<Mutex<Native>>,
}
impl Device {
    fn change<T>(&self, f: impl FnOnce(&mut Native) -> T) -> io::Result<T> {
        let mut s = self
            .state
            .lock()
            .map_err(|_| invalid("fixture device lock"))?;
        Ok(f(&mut s))
    }
}
impl PacketDevice for Device {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        self.layer
    }
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        self.change(|s| {
            s.outgoing.pop_front().map(|p| {
                out[..p.len()].copy_from_slice(&p);
                p.len()
            })
        })
    }
    fn transmit(&mut self, p: &[u8]) -> io::Result<()> {
        self.change(|s| s.delivered.push(p.to_vec()))
    }
}
fn packet(layer: PacketLayer, tag: u8) -> Vec<u8> {
    let mut p = vec![tag; 1500];
    match layer {
        PacketLayer::Ethernet => {
            p[..12].copy_from_slice(&[2, 1, 2, 3, 4, 5, 2, 6, 7, 8, 9, 10]);
            p[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
        }
        PacketLayer::Ip => {
            p[..40].fill(0);
            p[0] = 0x45;
            p[2..4].copy_from_slice(&1500u16.to_be_bytes());
            p[8] = 64;
            p[9] = 6;
            p[12..16].copy_from_slice(&[10, 0, 0, 1]);
            p[16..20].copy_from_slice(&[10, 0, 0, 2]);
            p[20..22].copy_from_slice(&1000u16.to_be_bytes());
            p[22..24].copy_from_slice(&2000u16.to_be_bytes());
            p[32] = 0x50;
            p[33] = 0x18;
            p[34..36].copy_from_slice(&u16::MAX.to_be_bytes());
        }
    }
    p
}
#[tokio::test]
async fn actual_full_half_tls_transition_common_mux_recovery_and_native_status() -> R {
    let credentials = credentials()?;
    for (half, layer, cauchy, integrity) in [
        (false, PacketLayer::Ip, false, false),
        (true, PacketLayer::Ethernet, false, true),
        (true, PacketLayer::Ip, true, false),
        (false, PacketLayer::Ethernet, true, true),
    ] {
        let config = connection(half, layer);
        let sa = settings(half, false, cauchy, integrity)?;
        let sb = settings(half, true, cauchy, integrity)?;
        let (a, b, probes) = ios(half);
        let mut a = begin_client_with(
            &sa,
            config,
            &credentials.client,
            "raw-client.test",
            &credentials.member,
            opener(a, Role::Client),
        )?;
        let mut b = begin_server_with(
            &sb,
            config,
            &credentials.server,
            &credentials.allow,
            opener(b, Role::Server),
        )?;
        let (mut ar, mut br): (Option<Session<Io>>, Option<Session<Io>>) = (None, None);
        poll_fn(|cx| {
            for (setup, result) in [(&mut a, &mut ar), (&mut b, &mut br)] {
                if let Some(link) = result {
                    if let Poll::Ready(Err(e)) = link.poll_progress(cx) {
                        return Poll::Ready(Err(e));
                    }
                } else if let Poll::Ready(value) = Pin::new(setup).poll(cx) {
                    *result = Some(value?);
                }
            }
            if ar.is_some() && br.is_some() {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        })
        .await?;
        let a = ar.ok_or("client session")?;
        let b = br.ok_or("server session")?;
        let ao = a.observer();
        let bo = b.observer();
        assert_eq!(ao.snapshot().digest, bo.snapshot().digest);
        assert!(ao.snapshot().effective.is_some());
        assert!(!ao.snapshot().capabilities.native_qualified);
        #[cfg(unix)]
        {
            use crate::local::{Action, Request, VERSION};
            let status = crate::cli::raw_packet_response_for_test(
                &ao,
                Request {
                    version: VERSION,
                    action: Action::Status {},
                },
                crate::Compression::None,
            );
            assert!(status.ok);
            assert!(
                status
                    .state
                    .as_ref()
                    .and_then(|s| s.raw_packet.as_ref())
                    .is_some_and(|s| s.effective.is_some())
            );
            let denied = crate::cli::raw_packet_response_for_test(
                &ao,
                Request {
                    version: VERSION,
                    action: Action::DrainProxy {},
                },
                crate::Compression::None,
            );
            assert!(!denied.ok);
            assert_eq!(denied.code, "unsupported");
            assert!(serde_json::to_vec(&status)?.len() < 8192);
        }
        let ad = Device {
            layer,
            state: Arc::new(Mutex::new(Native::default())),
        };
        let bd = Device {
            layer,
            state: Arc::new(Mutex::new(Native::default())),
        };
        let ap = packet(layer, 1);
        let bp = packet(layer, 2);
        ad.change(|s| s.outgoing.push_back(ap.clone()))?;
        bd.change(|s| s.outgoing.push_back(bp.clone()))?;
        let ar = tokio::spawn(a.run(ad.clone()));
        let br = tokio::spawn(b.run(bd.clone()));
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if ad.change(|s| s.delivered.len())? == 1 && bd.change(|s| s.delivered.len())? == 1
                {
                    return Ok::<_, io::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await??;
        assert_eq!(ad.change(|s| s.delivered.clone())?, vec![bp]);
        assert_eq!(bd.change(|s| s.delivered.clone())?, vec![ap]);
        assert_eq!(ao.snapshot().admitted.iter().sum::<u64>(), 1);
        assert_eq!(bo.snapshot().delivered.iter().sum::<u64>(), 1);
        let mut max = ao.snapshot();
        max.admitted = [u64::MAX; 2];
        max.sources = [u64::MAX; 2];
        max.received = [u64::MAX; 2];
        max.delivered = [u64::MAX; 2];
        max.peer_delivered = [u64::MAX; 2];
        max.staged = [u64::MAX; 2];
        assert!(serde_json::to_vec(&max)?.len() < 2048);
        ar.abort();
        br.abort();
        let _ = ar.await;
        let _ = br.await;
        assert_eq!(ao.snapshot().phase, "Stopped");
        assert!(probes.iter().all(|p| p.drops.load(Ordering::SeqCst) == 1));
    }
    Ok(())
}

#[tokio::test]
async fn actual_authenticated_policy_mismatch_releases_original_inputs() -> R {
    let credentials = credentials()?;
    for (half, packet_mismatch) in [(false, false), (true, false), (true, true)] {
        let sa = settings(half, false, false, false)?;
        let mut sb = settings(half, true, false, false)?;
        if packet_mismatch {
            sb.0.packet.bytes_per_second -= 1;
        } else {
            sb.0.channels = 3;
        }
        let (a, b, probes) = ios(half);
        let config = connection(half, PacketLayer::Ip);
        let mut a = begin_client_with(
            &sa,
            config,
            &credentials.client,
            "raw-client.test",
            &credentials.member,
            opener(a, Role::Client),
        )?;
        let mut b = begin_server_with(
            &sb,
            config,
            &credentials.server,
            &credentials.allow,
            opener(b, Role::Server),
        )?;
        let (mut ar, mut br): (Option<Session<Io>>, Option<Session<Io>>) = (None, None);
        let result = poll_fn(|cx| {
            for (setup, result) in [(&mut a, &mut ar), (&mut b, &mut br)] {
                if let Some(link) = result {
                    if let Poll::Ready(Err(e)) = link.poll_progress(cx) {
                        return Poll::Ready(Err(e));
                    }
                } else if let Poll::Ready(value) = Pin::new(setup).poll(cx) {
                    *result = Some(value?);
                }
            }
            if ar.is_some() && br.is_some() {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        })
        .await;
        assert!(matches!(result,Err(e) if e.kind()==io::ErrorKind::InvalidData));
        drop((a, b, ar, br));
        assert!(probes.iter().all(|p| p.drops.load(Ordering::SeqCst) == 1));
    }
    Ok(())
}
