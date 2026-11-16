//! Real APIv4 socket requests target the same authenticated Common service actor.
use super::*;
use crate::secure_udp::common_status::{CanonicalConfiguration, Status};
fn request(action: local::Action) -> local::Request {
    local::Request {
        version: local::COMMON_VERSION,
        action,
    }
}
fn observed(response: &local::Response) -> Result<&Status> {
    assert_eq!(response.version, 4);
    response
        .state
        .as_ref()
        .and_then(|state| state.common.as_ref())
        .ok_or_else(|| "missing actual Common status".into())
}
#[tokio::test]
async fn v4_socket_full_common_status_catalog_key_replay_and_lifecycle() -> Result {
    // Keep this same real lifecycle future out of the harness/timeout value.
    // Its many typed response locals otherwise remain inline across API awaits.
    timeout(
        Duration::from_secs(25),
        Box::pin(async {
            let hosts = support::hosts();
            let CommonPlans {
                plans: [left, right],
                profile,
                configurations,
                outside,
                ..
            } = common_plans(l2tunnel_cover::Appearance::QuicLike, &hosts)?;
            let (client, run) = channel();
            let (server, peer_run) = channel();
            let task = tokio::spawn(run);
            let peer = tokio::spawn(peer_run);
            let a = client
                .connect(left, client.next_key().map_err(submit)?)
                .map_err(submit)?;
            let b = server
                .connect(right, server.next_key().map_err(submit)?)
                .map_err(submit)?;
            let (generation, _) = tokio::try_join!(connected(&client, a), connected(&server, b))?;
            let directory = ApiDirectory::new()?;
            let path = directory.0.join("common.sock");
            let api = local::Server::bind(&path)?;
            let handle = client.clone();
            let api_task = tokio::spawn(async move {
                api.serve(move |request| {
                    let handle = handle.clone();
                    async move { handle.lifecycle_request(request).await }
                })
                .await
            });
            for version in 1..=3 {
                let refusal = local::request(
                    &path,
                    &local::Request {
                        version,
                        action: local::Action::Status {},
                    },
                )
                .await?;
                assert!(!refusal.ok);
                assert_eq!(refusal.code, "requires_version_4");
                assert_eq!(refusal.version, version);
                assert!(refusal.state.is_none());
            }
            let response = local::request(&path, &request(local::Action::Status {})).await?;
            assert!(response.ok);
            let status = observed(&response)?;
            assert_eq!(status.backend, "common_records_v2");
            assert_eq!(status.generation, generation.value());
            assert_eq!(
                status
                    .current
                    .as_ref()
                    .ok_or("missing current")?
                    .configuration()?,
                configurations[0]
            );
            let epoch = status.epoch.ok_or("missing epoch")?;
            let key = client.next_key().map_err(submit)?;
            let page = local::request(
                &path,
                &request(local::Action::CommonCatalog {
                    generation: generation.value(),
                    catalog: *profile.catalog().root().as_bytes(),
                    offset: 0,
                    limit: 4,
                }),
            )
            .await?;
            let catalog = observed(&page)?
                .catalog_page
                .as_ref()
                .ok_or("missing catalog page")?;
            assert_eq!(catalog.total, 3);
            assert_eq!(catalog.next, None);
            assert_eq!(catalog.configurations.len(), 3);
            let expected = profile.catalog().configurations(profile.envelope())?;
            for (actual, expected) in catalog.configurations.iter().zip(expected) {
                assert_eq!(actual.configuration()?, expected);
            }
            assert_eq!(client.next_key().map_err(submit)?, key);
            let stale = local::request(
                &path,
                &request(local::Action::CommonCatalog {
                    generation: generation.value() + 1,
                    catalog: *profile.catalog().root().as_bytes(),
                    offset: 0,
                    limit: 4,
                }),
            )
            .await?;
            assert_eq!(stale.code, "stale_catalog");
            assert_eq!(client.next_key().map_err(submit)?, key);
            let outside = request(local::Action::SwitchCommonConfiguration {
                configuration: CanonicalConfiguration::from_configuration(outside)?,
                request_key: key.value(),
            });
            let refused = local::request(&path, &outside).await?;
            assert_eq!(refused.code, "invalid_configuration");
            assert_eq!(client.next_key().map_err(submit)?, key);
            let target = configurations[1];
            let change = request(local::Action::SwitchCommonConfiguration {
                configuration: CanonicalConfiguration::from_configuration(target)?,
                request_key: key.value(),
            });
            let changed = local::request(&path, &change).await?;
            assert!(changed.ok, "{changed:?}");
            let result = observed(&changed)?
                .result
                .as_ref()
                .ok_or("missing completed actor result")?;
            assert_eq!(result.configuration.configuration()?, target);
            assert_eq!(result.epoch, Some(epoch + 1));
            assert_eq!(result.outcome, "ok");
            assert_eq!(
                changed.state.as_ref().ok_or("missing state")?.phase,
                "forwarding"
            );
            let replay = local::request(&path, &change).await?;
            assert!(replay.ok);
            assert_eq!(observed(&replay)?.result, observed(&changed)?.result);
            let conflict = request(local::Action::SwitchCommonConfiguration {
                configuration: CanonicalConfiguration::from_configuration(configurations[0])?,
                request_key: key.value(),
            });
            assert_eq!(local::request(&path, &conflict).await?.code, "conflict");
            let handles = [client.clone(), server.clone()];
            exchange_stage(&hosts, &handles, target, epoch + 1, 3).await?;
            assert!(
                local::request(&path, &request(local::Action::Disconnect {}))
                    .await?
                    .ok
            );
            assert!(
                server
                    .lifecycle_request(request(local::Action::Disconnect {}))
                    .await
                    .ok
            );
            let stopped = local::request(&path, &request(local::Action::Status {})).await?;
            assert_eq!(
                stopped
                    .state
                    .as_ref()
                    .ok_or("missing released state")?
                    .phase,
                "disconnected"
            );
            assert!(!observed(&stopped)?.running);
            assert_eq!(
                observed(&stopped)?.service_terminal.as_deref(),
                Some("Aborted")
            );
            let reconnect = request(local::Action::Reconnect {});
            let (reconnected, peer_reconnected) = tokio::join!(
                local::request(&path, &reconnect),
                server.lifecycle_request(request(local::Action::Reconnect {}))
            );
            assert!(reconnected?.ok && peer_reconnected.ok);
            let fresh = local::request(&path, &request(local::Action::Status {})).await?;
            assert_ne!(observed(&fresh)?.generation, generation.value());
            assert_eq!(
                observed(&fresh)?
                    .current
                    .as_ref()
                    .ok_or("fresh current")?
                    .configuration()?,
                configurations[0]
            );
            let (a, b) = tokio::join!(
                client.lifecycle_request(request(local::Action::Disconnect {})),
                server.lifecycle_request(request(local::Action::Disconnect {}))
            );
            assert!(a.ok && b.ok);
            api_task.abort();
            task.abort();
            peer.abort();
            let _ = api_task.await;
            let _ = task.await;
            let _ = peer.await;
            Ok::<(), Error>(())
        }),
    )
    .await?
}
