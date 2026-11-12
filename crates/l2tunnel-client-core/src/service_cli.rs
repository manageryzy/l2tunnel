//! Presentation adapter for the managed-TCP and base UDP profiles of the shared
//! lifecycle owner. It parses credentials and prints; it owns no connection state.
use super::*;
use crate::service::{self, Completed, Terminal};
use std::sync::Arc;
fn service_error(error: service::SubmitError) -> io::Error {
    io::Error::other(format!("service request: {error:?}"))
}
pub(super) async fn execute(
    command: &str,
    options: &BTreeMap<String, String>,
    config: ConnectionConfig,
    device: DeviceSpec,
    delivery: Option<l2tunnel_runtime::managed::DeliveryConfig>,
    profile_interval: Option<Duration>,
    udp: Option<(
        crate::udp::Settings,
        l2tunnel_runtime::managed::DeliveryConfig,
    )>,
) -> io::Result<()> {
    let attachment = service::Attachment::new(config.layer, move || device.clone().open(config));
    let settings = service::Options {
        delivery,
        profile_interval,
    };
    let plan = match command {
        "connect" => {
            let remote = required(options, "--remote")?
                .parse()
                .map_err(|_| input("remote requires IP:PORT"))?;
            let tls =
                ClientTls::from_der_roots(&[bounded_file(required(options, "--ca")?, 65536)?])
                    .map_err(auth_error)?;
            let member =
                MemberKey::from_pkcs8(&bounded_file(required(options, "--identity")?, 4096)?)
                    .map_err(auth_error)?;
            let credentials = service::Client {
                remote,
                tls,
                server_name: required(options, "--server-name")?.into(),
                member: Arc::new(member),
            };
            match udp {
                Some((transport, delivery)) => service::Prepared::udp_client(
                    config,
                    credentials,
                    transport,
                    delivery,
                    attachment,
                )?,
                None => service::Prepared::client(config, credentials, attachment, settings)?,
            }
        }
        "serve" => {
            let listen = required(options, "--listen")?
                .parse()
                .map_err(|_| input("listen requires IP:PORT"))?;
            let tls = ServerTls::from_der(
                &[bounded_file(required(options, "--cert")?, 65536)?],
                &bounded_file(required(options, "--key")?, 65536)?,
            )
            .map_err(auth_error)?;
            let key: [u8; 32] = bounded_file(required(options, "--allow-key")?, 32)?
                .try_into()
                .map_err(|_| input("allow-key must contain exactly 32 raw Ed25519 public bytes"))?;
            let members = MemberAllowlist::new(&[MemberPublicKey(key)]).map_err(auth_error)?;
            let credentials = service::Server {
                listen,
                tls,
                members,
            };
            match udp {
                Some((transport, delivery)) => service::Prepared::udp_server(
                    config,
                    credentials,
                    transport,
                    delivery,
                    attachment,
                )?,
                None => service::Prepared::server(config, credentials, attachment, settings)?,
            }
        }
        _ => return Err(input("unsupported managed service command")),
    };
    let api = options
        .get("--control-socket")
        .map(crate::local::Server::bind)
        .transpose()?;
    let (handle, run) = service::channel();
    let accepted = handle
        .connect(plan, handle.next_key().map_err(service_error)?)
        .map_err(service_error)?;
    let life_handle = handle.clone();
    let lifecycle = async move {
        let generation = match life_handle
            .wait(accepted.operation)
            .await
            .map_err(service_error)?
        {
            Completed::Connected { generation } => generation,
            Completed::Failed(failure) => {
                return Err(io::Error::new(failure.kind, "managed service setup failed"));
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "managed service setup cancelled",
                ));
            }
        };
        println!(
            "Authenticated {:?} {:?}; forwarding packet device",
            config.layer, config.duplex
        );
        // The effective profile comes from the authenticated factory through
        // the service, never from re-deriving the requested options here.
        let datagram = match life_handle.snapshot().runtime {
            Some(service::Observation::UdpFrame(frame)) => Some(*frame),
            _ => None,
        };
        if udp.is_some() != datagram.is_some() {
            return Err(io::Error::other(
                "service backend differs from the selected carrier",
            ));
        }
        if let Some(frame) = datagram {
            let profile = frame.effective;
            delivery_frontend::report(frame.delivery);
            println!(
                "Carrier: UDP with retained TCP/TLS bootstrap/control; cover {:?}; protection {:?}; recovery {:?}; compression fixed",
                profile.cover, profile.protection, profile.recovery
            );
            println!(
                "Recovery banks: send {} records/{} bytes; receive {} records/{} bytes; local queue {} packets",
                profile.arq.send_records,
                profile.arq.send_bytes,
                profile.arq.receive_records,
                profile.arq.receive_bytes,
                config.runtime().queue_packets
            );
        } else {
            println!("Carrier: tcp-tls; coordinated compression enabled");
            if let Some(delivery) = delivery {
                delivery_frontend::report(delivery);
            }
        }
        let terminal = async {
            match life_handle
                .wait_stopped(generation)
                .await
                .map_err(service_error)?
            {
                Terminal::Aborted => Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "managed session locally aborted",
                )),
                Terminal::Failed(failure) => {
                    Err(io::Error::new(failure.kind, "managed runtime stopped"))
                }
            }
        };
        if datagram.is_some() {
            let latest = life_handle
                .datagram_observer(generation)
                .map_err(service_error)?
                .ok_or_else(|| io::Error::other("base UDP observation absent"))?;
            return datagram_profiling::observe(
                terminal,
                datagram_profiling::attach(latest, profile_interval),
                datagram_profiling::Runtime::UdpFrame,
            )
            .await;
        }
        profiling::observe(
            terminal,
            life_handle.profile(generation).map_err(service_error)?,
        )
        .await
    };
    let local_handle = handle.clone();
    let ipc = async {
        match &api {
            Some(api) => {
                api.serve(move |request| {
                    let handle = local_handle.clone();
                    async move { handle.request(request).await }
                })
                .await
            }
            None => std::future::pending::<io::Result<()>>().await,
        }
    };
    let mut changes = handle.subscribe();
    let mut listening = false;
    let mut serving = api.is_some();
    tokio::pin!(run, lifecycle, ipc);
    loop {
        tokio::select! {
            result=&mut run=>return result,
            result=&mut lifecycle=>return result,
            result=&mut ipc,if serving=>{
                // Loss of local IPC cannot cancel the accepted tunnel owner.
                if result.is_err(){eprintln!("Local service API stopped; managed tunnel remains owned");}
                serving=false;
            },
            changed=changes.changed()=>{
                if changed.is_err(){return Err(io::Error::new(io::ErrorKind::BrokenPipe,"managed lifecycle stopped"));}
                if !listening && let Some(address)=handle.snapshot().listening {
                    println!("Listening on {}", address.address);listening=true;
                }
            },
        }
    }
}
