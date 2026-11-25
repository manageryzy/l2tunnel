//! Background exchanges over the shared local API v5 client. One thread runs a
//! single-threaded Tokio runtime; results return over a channel and wake the
//! UI. Dropping the worker aborts its tasks (closing never disconnects).
use crate::model::{Action, ActionOutcome, Command, Message, Payload, Query};
use l2tunnel_client_core::local::{
    self, OperationAction, OperationRequest,
    client::{self, SubmitFailure, Submitted},
};
use std::io;
use std::path::Path;
use std::sync::{Arc, mpsc};
use tokio::sync::mpsc as async_mpsc;

/// Pending commands beyond this are refused instead of queued without bound.
const COMMAND_QUEUE: usize = 256;

type Wake = Arc<dyn Fn() + Send + Sync>;

/// Handle to the worker thread.
pub struct Worker {
    commands: Option<async_mpsc::Sender<Command>>,
    /// Results for the UI thread.
    pub messages: mpsc::Receiver<Message>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Worker {
    /// Start the worker; `wake` is called after each posted message.
    pub fn start(wake: impl Fn() + Send + Sync + 'static) -> io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let (commands, receiver) = async_mpsc::channel(COMMAND_QUEUE);
        let (sender, messages) = mpsc::channel();
        let wake: Wake = Arc::new(wake);
        let thread = std::thread::Builder::new()
            .name("l2tunnel-gui-worker".into())
            .spawn(move || runtime.block_on(serve(receiver, Post { sender, wake })))?;
        Ok(Self {
            commands: Some(commands),
            messages,
            thread: Some(thread),
        })
    }
    /// Queue commands; returns false if the worker is gone or saturated.
    pub fn send(&self, commands: Vec<Command>) -> bool {
        let Some(sender) = &self.commands else {
            return false;
        };
        commands
            .into_iter()
            .all(|command| sender.try_send(command).is_ok())
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        // Closing the command channel ends `serve`, which aborts its tasks.
        drop(self.commands.take());
        if let Some(thread) = self.thread.take() {
            let _joined = thread.join();
        }
    }
}

#[derive(Clone)]
struct Post {
    sender: mpsc::Sender<Message>,
    wake: Wake,
}
impl Post {
    fn send(&self, message: Message) {
        if self.sender.send(message).is_ok() {
            (self.wake)();
        }
    }
}

async fn serve(mut commands: async_mpsc::Receiver<Command>, post: Post) {
    let mut tasks = tokio::task::JoinSet::new();
    let mut follower: Option<tokio::task::AbortHandle> = None;
    loop {
        let command = tokio::select! {
            command = commands.recv() => command,
            // Reap finished exchanges so the set stays bounded by activity.
            Some(_) = tasks.join_next(), if !tasks.is_empty() => continue,
        };
        let Some(command) = command else {
            break;
        };
        let post = post.clone();
        match command {
            Command::Status {
                attach,
                path,
                start_follower,
            } => {
                tasks.spawn(async move {
                    let result = exchange(&path, OperationAction::Status {}).await;
                    post.send(Message::Status {
                        attach,
                        start_follower,
                        result,
                    });
                });
            }
            Command::Act {
                attach,
                path,
                action,
                operation,
                service,
                payload,
            } => {
                tasks.spawn(async move {
                    let outcome = act(&path, action, operation, service, payload).await;
                    post.send(Message::Action {
                        attach,
                        action,
                        outcome,
                    });
                });
            }
            Command::StartService(request) => {
                tasks.spawn(async move {
                    let result = local::elevate::start(&request)
                        .await
                        .map_err(|error| error.to_string());
                    post.send(Message::Started { result });
                });
            }
            Command::Revoke {
                attach,
                path,
                allow_key,
            } => {
                tasks.spawn(async move {
                    let result = match client::revoke_member(&path, &allow_key, 120).await {
                        Ok(revoked) if !revoked.saved.succeeded() => Err(format!(
                            "profile {} not saved: {:?}",
                            revoked.profile, revoked.saved
                        )),
                        Ok(revoked) => match revoked.replaced {
                            Some(result) if result.succeeded() => Ok(format!(
                                "Member revoked: {} saved and the session replaced; only the new key is trusted",
                                revoked.profile
                            )),
                            other => Err(format!(
                                "profile {} saved, but the session was not replaced: {other:?}",
                                revoked.profile
                            )),
                        },
                        Err(failure) => Err(format!("{failure:?}")),
                    };
                    post.send(Message::Revoked { attach, result });
                });
            }
            Command::Export {
                path,
                destination,
                include_addresses,
            } => {
                tasks.spawn(async move {
                    let result = match local::diagnostics::collect(&path, include_addresses).await {
                        Ok(report) => match local::diagnostics::write_new(&destination, &report) {
                            Ok(()) => Ok(destination),
                            Err(error) => Err(format!("{}: {error}", destination.display())),
                        },
                        Err(error) => Err(error.to_string()),
                    };
                    post.send(Message::Exported { result });
                });
            }
            Command::Query {
                attach,
                path,
                query,
            } => {
                tasks.spawn(async move {
                    let action = match &query {
                        Query::Info => OperationAction::ServiceInfo {},
                        Query::Metrics => OperationAction::Metrics {},
                        Query::Devices => OperationAction::DeviceList {},
                        Query::Routes => OperationAction::RouteList {},
                        Query::Profiles => OperationAction::ProfileList {},
                        Query::Profile(name) => OperationAction::ProfileGet { name: name.clone() },
                        Query::Check(name) => {
                            OperationAction::ProfileValidate { name: name.clone() }
                        }
                        Query::Keys(name) => OperationAction::ProfileKeys { name: name.clone() },
                        Query::Sessions => OperationAction::SessionList {},
                        Query::Catalog {
                            generation,
                            catalog,
                            offset,
                        } => OperationAction::Catalog {
                            generation: *generation,
                            catalog: local::Digest(*catalog),
                            offset: *offset,
                            limit: local::CATALOG_LIMIT,
                        },
                        Query::TestStart(test) => OperationAction::TestStart { test: test.clone() },
                        Query::TestGet => OperationAction::TestGet {
                            id: None,
                            timeout_ms: 0,
                        },
                        Query::TestCancel(id) => OperationAction::TestCancel { id: *id },
                        Query::Tuning => OperationAction::TuningGet {},
                    };
                    let result = exchange(&path, action).await;
                    post.send(Message::Query {
                        attach,
                        query,
                        result,
                    });
                });
            }
            Command::Show {
                attach,
                path,
                operation,
                service,
            } => {
                tasks.spawn(async move {
                    let result =
                        exchange(&path, OperationAction::OperationGet { operation, service }).await;
                    post.send(Message::Show { attach, result });
                });
            }
            Command::Follow {
                attach,
                follower: id,
                path,
                after,
                service,
            } => {
                if let Some(previous) = follower.take() {
                    previous.abort();
                }
                follower = Some(tasks.spawn(follow(post, attach, id, path, after, service)));
            }
            Command::StopFollower => {
                if let Some(previous) = follower.take() {
                    previous.abort();
                }
            }
        }
    }
    tasks.abort_all();
}

async fn exchange(
    path: &Path,
    action: OperationAction,
) -> Result<Box<local::OperationReply>, String> {
    local::request_operation(path, &OperationRequest::new(action))
        .await
        .map(Box::new)
        .map_err(|error| error.to_string())
}

async fn act(
    path: &Path,
    action: Action,
    operation: Option<u64>,
    service: Option<local::ServiceId>,
    payload: Option<Payload>,
) -> ActionOutcome {
    let submit = match (action, payload) {
        (Action::Switch, Some(Payload::Switch(configuration))) => {
            client::submit(path, None, |request_key| {
                OperationAction::SwitchCommonConfiguration {
                    configuration,
                    request_key,
                }
            })
            .await
        }
        (Action::Tune, Some(Payload::Tune(setting))) => {
            client::submit(path, None, |request_key| OperationAction::TuningSwitch {
                request_key,
                setting,
            })
            .await
        }
        (Action::Device, Some(Payload::Device(change))) => {
            client::submit(path, None, |request_key| OperationAction::Device {
                request_key,
                change,
            })
            .await
        }
        (Action::Route, Some(Payload::Route(change))) => {
            client::submit(path, None, |request_key| OperationAction::Route {
                request_key,
                change,
            })
            .await
        }
        (Action::Profile, Some(Payload::Profile(change))) => {
            client::submit(path, None, |request_key| OperationAction::Profile {
                request_key,
                change,
            })
            .await
        }
        (Action::ProfileConnect, Some(Payload::ProfileConnect { name, replace })) => {
            client::submit(path, None, |request_key| OperationAction::ProfileConnect {
                request_key,
                name,
                replace,
            })
            .await
        }
        (
            Action::Switch
            | Action::Tune
            | Action::Device
            | Action::Route
            | Action::Profile
            | Action::ProfileConnect,
            _,
        ) => {
            return ActionOutcome::Failed("nothing to submit".into());
        }
        (Action::Cancel, _) => {
            let Some(operation) = operation else {
                return ActionOutcome::Failed("no pending operation".into());
            };
            return match exchange(
                path,
                OperationAction::OperationCancel { operation, service },
            )
            .await
            {
                Ok(reply) => ActionOutcome::Reply(reply),
                Err(error) => ActionOutcome::Failed(format!("service unreachable: {error}")),
            };
        }
        (Action::Reconnect, _) => {
            client::submit(path, None, |request_key| OperationAction::Reconnect {
                request_key,
            })
            .await
        }
        (Action::Disconnect, _) => {
            client::submit(path, None, |request_key| OperationAction::Disconnect {
                request_key,
            })
            .await
        }
        (Action::Kick, _) => {
            client::submit(path, None, |request_key| OperationAction::SessionKick {
                request_key,
            })
            .await
        }
        (Action::Stop, _) => {
            client::submit(path, None, |request_key| OperationAction::ServiceStop {
                request_key,
            })
            .await
        }
    };
    match submit {
        Ok(Submitted { reply, .. }) => ActionOutcome::Reply(Box::new(reply)),
        Err(SubmitFailure::Refused(reply)) => ActionOutcome::Reply(reply),
        Err(SubmitFailure::Unreachable(error)) => {
            ActionOutcome::Failed(format!("service unreachable: {error}"))
        }
        Err(SubmitFailure::NoKey) => ActionOutcome::Failed("service is closed".into()),
        Err(SubmitFailure::OutcomeUnknown { key, error }) => ActionOutcome::Failed(format!(
            "outcome unknown ({error}); request key {key} may have been accepted"
        )),
    }
}

/// Long-poll events until refused or the service is lost.
async fn follow(
    post: Post,
    attach: u64,
    follower: u64,
    path: std::path::PathBuf,
    mut after: u64,
    mut service: Option<local::ServiceId>,
) {
    loop {
        let action = OperationAction::Events {
            after,
            limit: local::EVENTS_LIMIT,
            timeout_ms: local::WAIT_LIMIT_MS,
            service,
        };
        let reason = match exchange(&path, action).await {
            Ok(reply) if reply.ok => {
                if let Some(batch) = &reply.events {
                    after = batch.next;
                }
                service = service.or(reply.service);
                post.send(Message::Events {
                    attach,
                    follower,
                    reply,
                });
                continue;
            }
            Ok(reply) => reply.code,
            Err(error) => error,
        };
        post.send(Message::FollowerEnded {
            attach,
            follower,
            reason,
        });
        return;
    }
}

// Binds a private Unix socket; the Windows pipe endpoint is not executed here.
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::model::Model;
    use std::os::unix::fs::DirBuilderExt;
    use std::time::{Duration, Instant};

    /// Deliver worker results to the model until `done` holds.
    fn pump(worker: &Worker, model: &mut Model, done: impl Fn(&Model) -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if done(model) {
                return true;
            }
            if let Ok(message) = worker.messages.recv_timeout(Duration::from_millis(50)) {
                let commands = model.handle(message);
                assert!(worker.send(commands));
            }
        }
        false
    }

    #[test]
    fn worker_drives_the_model_against_a_real_service_endpoint() -> io::Result<()> {
        let directory = std::env::temp_dir().join(format!("l2t-gui-{}", std::process::id()));
        std::fs::DirBuilder::new().mode(0o700).create(&directory)?;
        let path = directory.join("api.sock");
        let service = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()?;
        let server = {
            let _context = service.enter();
            local::Server::bind(&path)?
        };
        let (handle, run) = l2tunnel_client_core::service::channel();
        let serving = service.spawn(async move { server.serve_service(handle).await });

        let worker = Worker::start(|| {})?;
        let mut model = Model::default();
        assert!(worker.send(model.attach(&path.display().to_string())));
        assert!(pump(&worker, &mut model, |model| model.view().rows[0]
            == "disconnected"));
        assert!(model.view().connect);
        // The idle service has no retained plan: the real service refuses.
        assert!(worker.send(model.act(Action::Reconnect)));
        assert!(pump(&worker, &mut model, |model| model.notice
            == "reconnect refused: state"));

        // Losing the service ends the follower and requests a resynchronization.
        serving.abort();
        drop(service);
        drop(run);
        assert!(pump(&worker, &mut model, |model| model.retry));
        assert!(model.notice.starts_with("Service"), "{}", model.notice);
        assert!(worker.send(model.resync()));
        assert!(pump(&worker, &mut model, |model| model.retry
            && model.view().rows[0] == "unavailable"));
        drop(worker);
        let _cleanup = std::fs::remove_dir_all(&directory);
        Ok(())
    }
}
