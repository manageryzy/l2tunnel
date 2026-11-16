//! Actual shared Common service with explicit v3 data and strong control/feedback.
use super::*;
use crate::secure_udp::common_status::{CompactDataProtection, CompactWireSelection};

fn compact_plans(
    appearance: l2tunnel_cover::Appearance,
    hosts: &[Arc<Host>; 2],
    selection: l2tunnel::secure_record::compact::Selection,
) -> Result<(
    [Prepared; 2],
    common_transaction_profile::Profile,
    [std::net::SocketAddr; 2],
)> {
    let CommonPlans {
        plans,
        profile: old,
        addresses,
        ..
    } = common_plans(appearance, hosts)?;
    let mut resources = [
        old.runtime_contract(Role::Initiator)?.resources(),
        old.runtime_contract(Role::Responder)?.resources(),
    ];
    let physical = if addresses[0].is_ipv6() { 48 } else { 28 };
    for value in &mut resources {
        value.control.wire_overhead =
            physical + l2tunnel::secure_record::compact::AUTHENTICATED_OVERHEAD;
        for stream in &mut value
            .streams
            .as_mut()
            .ok_or("actual explicit streams")?
            .streams
        {
            stream.delivery.wire_overhead =
                value.control.wire_overhead + l2tunnel_management::control_streams::HEADER_BYTES;
        }
    }
    let make = |catalog| {
        common_transaction_profile::Profile::new_compact(
            old.connection(),
            old.settings(),
            old.peers(),
            resources[0],
            resources[1],
            catalog,
            old.parameters(),
            selection,
        )
    };
    // The complete unsupported set is refused, never silently reduced by the API.
    assert!(make(old.catalog().clone()).is_err());
    assert!(
        hosts
            .iter()
            .all(|host| host.opened.load(Ordering::SeqCst) == 0)
    );
    let initial = old.catalog().initial();
    let profile = make(common::Catalog::new(initial, &[initial])?)?;
    assert_ne!(profile.configuration()?, old.configuration()?);
    let convert = |plan: Prepared| -> Result<Prepared> {
        let data =
            Arc::try_unwrap(plan.data).map_err(|_| "unstarted credentials unexpectedly shared")?;
        let prepared::Data {
            endpoint,
            attachment,
            ..
        } = data;
        match endpoint {
            prepared::Endpoint::SecureClient(credentials) => Ok(
                Prepared::secure_udp_common_client(profile.clone(), credentials, attachment)?,
            ),
            prepared::Endpoint::SecureServer(server) => {
                let prepared::SecureServer {
                    credentials,
                    admission,
                } = *server;
                assert!(
                    admission.into_inner().is_none(),
                    "actual authentication must not have begun"
                );
                Ok(Prepared::secure_udp_common_server(
                    profile.clone(),
                    credentials,
                    attachment,
                )?)
            }
            _ => Err("unexpected unstarted Common credentials".into()),
        }
    };
    let [left, right] = plans;
    Ok(([convert(left)?, convert(right)?], profile, addresses))
}

#[tokio::test]
async fn actual_common_compact_wire_service_authenticates_selected_h0_status_and_native() -> Result
{
    timeout(
        Duration::from_secs(30),
        Box::pin(async {
            for appearance in support::appearances() {
                for data_protection in [
                    CompactDataProtection::AesCcm4,
                    CompactDataProtection::ChaCha20Crc32c,
                ] {
                    let requested = CompactWireSelection {
                        version: 3,
                        data_protection,
                        max_forward_packets: 8192,
                        max_failed_checks: 64,
                    };
                    let selection = requested.build()?;
                    let hosts = support::hosts();
                    let ([left, right], profile, addresses) =
                        compact_plans(appearance, &hosts, selection)?;
                    let (client, client_run) = channel();
                    let (server, server_run) = channel();
                    let tasks = [tokio::spawn(client_run), tokio::spawn(server_run)];
                    let accepts = [
                        client
                            .connect(left, client.next_key().map_err(submit)?)
                            .map_err(submit)?,
                        server
                            .connect(right, server.next_key().map_err(submit)?)
                            .map_err(submit)?,
                    ];
                    let (left, right) = tokio::try_join!(
                        connected(&client, accepts[0]),
                        connected(&server, accepts[1])
                    )?;
                    let generations = [left, right];
                    let handles = [client, server];
                    let initial = profile.initial();
                    let first = common_frame(&handles[0])?;
                    let epoch = first
                        .runtime
                        .as_ref()
                        .ok_or("actual compact runtime")?
                        .epoch
                        .0;
                    assert_eq!(
                        first.info.authenticated.configuration,
                        profile.configuration()?.0
                    );
                    assert_eq!(first.info.binding, common_frame(&handles[1])?.info.binding);
                    exchange_stage(&hosts, &handles, initial, epoch, 0).await?;
                    for side in 0..2 {
                        let frame = common_frame(&handles[side])?;
                        let actual = frame.runtime.as_ref().ok_or("actual compact sample")?;
                        assert_eq!(actual.compact_wire, Some(selection));
                        assert_eq!(
                            actual
                                .compact_check_status
                                .ok_or("actual check counters")?
                                .limit,
                            64
                        );
                        assert_eq!(
                            frame.info.authenticated.configuration,
                            profile.configuration()?.0
                        );
                        assert_eq!(frame.info.local_addr, addresses[side]);
                        assert_eq!(frame.info.peer_addr, addresses[1 - side]);
                        assert!(actual.liveness.last_pong_micros.is_some());
                        assert_eq!(hosts[side].opened.load(Ordering::SeqCst), 1);
                        let response = handles[side]
                            .lifecycle_request(local::Request {
                                version: local::COMMON_VERSION,
                                action: local::Action::Status {},
                            })
                            .await;
                        assert!(response.ok, "{response:?}");
                        let status = response
                            .state
                            .as_ref()
                            .and_then(|state| state.common.as_ref())
                            .ok_or("actual API4 Common status")?;
                        let compact = status
                            .compact_wire
                            .as_ref()
                            .ok_or("actual portable compact status")?;
                        assert_eq!(compact.requested, requested);
                        assert_eq!(compact.effective, Some(requested));
                        assert_eq!(
                            compact
                                .checks
                                .ok_or("actual portable check counters")?
                                .limit,
                            64
                        );
                        assert_eq!(status.protection, data_protection.name());
                        assert!(!status.cross_profile_switching);
                        let encoded = serde_json::to_value(status)?;
                        assert_eq!(encoded["compact_wire"]["effective"]["version"], 3);
                        assert_eq!(
                            encoded["configuration"],
                            serde_json::json!(profile.configuration()?.0)
                        );
                    }
                    let stopped = [
                        handles[0]
                            .disconnect(handles[0].next_key().map_err(submit)?)
                            .map_err(submit)?,
                        handles[1]
                            .disconnect(handles[1].next_key().map_err(submit)?)
                            .map_err(submit)?,
                    ];
                    let (a, b) = tokio::try_join!(
                        handles[0].wait(stopped[0].operation),
                        handles[1].wait(stopped[1].operation)
                    )
                    .map_err(submit)?;
                    assert_eq!(a, Completed::Aborted);
                    assert_eq!(b, Completed::Aborted);
                    for side in 0..2 {
                        assert_eq!(
                            handles[side]
                                .wait_stopped(generations[side])
                                .await
                                .map_err(submit)?,
                            Terminal::Aborted
                        );
                        assert_eq!(hosts[side].live.load(Ordering::SeqCst), 0);
                    }
                    support::assert_ports_free(addresses)?;
                    for task in tasks {
                        task.abort();
                        let _ = task.await;
                    }
                }
            }
            Ok::<(), Error>(())
        }),
    )
    .await?
}
