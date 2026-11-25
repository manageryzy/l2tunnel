//! Service-owned profile store and profile connects (CL-12, CL-24; owner
//! decisions 2026-11-23: profiles are validated run options, switched in
//! process). Store changes are keyed operations sequenced by the actor; a
//! profile connect prepares the plan only for a new key, so an exact replay
//! never rereads credentials.
use super::*;
use crate::local::{ProfileChange, ProfileCheck, ProfileEntry, ProfileSummary};

/// Platform side of the profile store.
pub trait ProfileStore: Send + Sync + 'static {
    /// Stored profiles, sorted by name.
    fn list(&self) -> io::Result<Vec<ProfileSummary>>;
    /// One profile; `None` when missing.
    fn get(&self, name: &str) -> io::Result<Option<ProfileEntry>>;
    /// Build the profile's plan: read credentials and the transaction plan,
    /// open nothing. `Err` is a bounded reason.
    fn prepare(&self, name: &str) -> Result<Prepared, String>;
    /// Apply one structurally valid change; `Err` leaves the store unchanged.
    fn apply(&self, change: ProfileChange) -> Result<String, String>;
    /// Profile to connect when the service starts.
    fn default_profile(&self) -> Option<String>;
}

/// A profile connect was not accepted.
#[derive(Debug)]
pub enum ProfileConnectError {
    /// Lifecycle refusal (key, state, busy, closed).
    Submit(SubmitError),
    /// The profile could not be prepared; nothing was submitted.
    Invalid(String),
}

impl Handle {
    /// Attach the profile store once; later attachments are refused.
    pub fn attach_profiles(
        &self,
        store: Arc<dyn ProfileStore>,
    ) -> Result<(), Arc<dyn ProfileStore>> {
        self.0.profiles.set(store)
    }
    /// The attached store, if any.
    pub(crate) fn profiles(&self) -> Option<Arc<dyn ProfileStore>> {
        self.0.profiles.get().cloned()
    }
    /// Submit one store change as a keyed operation.
    pub fn profile_change(
        &self,
        change: ProfileChange,
        key: RequestKey,
    ) -> Result<Accepted, SubmitError> {
        self.submit(
            Fingerprint::Profile(change.clone()),
            Command::Profile(change),
            key,
        )
    }
    /// Connect with (or, with `replace`, reconnect to) a stored profile.
    pub fn connect_profile(
        &self,
        name: &str,
        replace: bool,
        key: RequestKey,
    ) -> Result<Accepted, ProfileConnectError> {
        let store = self
            .profiles()
            .ok_or(ProfileConnectError::Submit(SubmitError::Unsupported))?;
        let fingerprint = |reconnect| Fingerprint::ProfileConnect {
            name: name.to_owned(),
            replace,
            reconnect,
        };
        {
            let state = self.0.lock();
            // Retained and future keys never prepare: replay, conflict or
            // refusal is decided before the command is looked at.
            if state.snapshot.phase == Phase::Closed
                || key.0 <= state.last_key
                || state.last_key.checked_add(1) != Some(key.0)
            {
                return self
                    .submit_locked(state, fingerprint(false), Command::Disconnect, key)
                    .map_err(ProfileConnectError::Submit);
            }
            if state.snapshot.operation.is_some() || state.snapshot.phase == Phase::Stopping {
                return Err(ProfileConnectError::Submit(SubmitError::Busy));
            }
            if state.backend.is_some() && !replace {
                return Err(ProfileConnectError::Submit(SubmitError::State));
            }
        }
        let plan = store.prepare(name).map_err(ProfileConnectError::Invalid)?;
        let mut state = self.0.lock();
        let reconnect = replace && state.backend.is_some();
        let command = if reconnect {
            Command::Reconnect(plan)
        } else {
            Command::Connect(plan)
        };
        let previous = state.profile.replace(name.to_owned());
        let accepted = self.submit_locked(state, fingerprint(reconnect), command, key);
        if accepted.is_err() {
            self.0.lock().profile = previous;
        }
        accepted.map_err(ProfileConnectError::Submit)
    }
    /// Let `service_stop` end the hosting process: the receiver turns true
    /// after the stop operation disconnected and completed.
    pub fn enable_stop(&self) -> watch::Receiver<bool> {
        let sender = self.0.stop.get_or_init(|| watch::channel(false).0);
        sender.subscribe()
    }
    /// Submit a stop as a keyed operation.
    pub fn stop(&self, key: RequestKey) -> Result<Accepted, SubmitError> {
        self.submit(Fingerprint::Stop, Command::Stop, key)
    }
    /// Read-only plan check of a stored profile.
    pub(crate) fn profile_check(&self, name: &str) -> io::Result<Option<ProfileCheck>> {
        let Some(store) = self.profiles() else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "no profile store",
            ));
        };
        let Some(entry) = store.get(name)? else {
            return Ok(None);
        };
        Ok(Some(match store.prepare(name) {
            Ok(plan) => ProfileCheck {
                valid: true,
                summary: crate::local::bounded_text(&format!(
                    "{} · {}",
                    match plan.role() {
                        crate::local::Role::Server => "server",
                        crate::local::Role::Client => "client",
                        crate::local::Role::Unconfigured => "unconfigured",
                    },
                    crate::local::describe(&entry.document)
                )),
                reason: None,
            },
            Err(reason) => ProfileCheck {
                valid: false,
                summary: crate::local::describe(&entry.document),
                reason: Some(crate::local::bounded_text(&reason)),
            },
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::{
        Feature, OperationAction, OperationReply, OperationRequest, OperationResult,
        PROFILE_VERSION, ProfileDocument, ProfileRole,
    };
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// In-memory store; `broken` never prepares.
    #[derive(Default)]
    struct MemoryStore {
        profiles: Mutex<BTreeMap<String, (u64, ProfileDocument)>>,
        prepared: Mutex<u32>,
    }
    impl ProfileStore for MemoryStore {
        fn list(&self) -> io::Result<Vec<ProfileSummary>> {
            let profiles = self.profiles.lock().map_err(|_| io::Error::other("lock"))?;
            Ok(profiles
                .iter()
                .map(|(name, (revision, document))| ProfileSummary {
                    name: name.clone(),
                    revision: *revision,
                    version: document.version,
                    role: Some(document.role),
                    summary: crate::local::describe(document),
                    device: document.options.get("--device").cloned(),
                    default: false,
                    editable: true,
                })
                .collect())
        }
        fn get(&self, name: &str) -> io::Result<Option<ProfileEntry>> {
            let profiles = self.profiles.lock().map_err(|_| io::Error::other("lock"))?;
            Ok(profiles.get(name).map(|(revision, document)| ProfileEntry {
                name: name.into(),
                revision: *revision,
                document: document.clone(),
            }))
        }
        fn prepare(&self, name: &str) -> Result<Prepared, String> {
            if let Ok(mut count) = self.prepared.lock() {
                *count += 1;
            }
            Err(format!("{name}: credentials unreadable"))
        }
        fn apply(&self, change: ProfileChange) -> Result<String, String> {
            let mut profiles = self.profiles.lock().map_err(|_| "lock".to_owned())?;
            match change {
                ProfileChange::Save {
                    name,
                    document,
                    expected_revision,
                } => {
                    let current = profiles.get(&name).map(|(revision, _)| *revision);
                    if current != expected_revision {
                        return Err("revision mismatch".into());
                    }
                    let revision = current.unwrap_or(0) + 1;
                    profiles.insert(name.clone(), (revision, document));
                    Ok(format!("saved {name} revision {revision}"))
                }
                ProfileChange::Delete { name, .. } => profiles
                    .remove(&name)
                    .map(|_| format!("deleted {name}"))
                    .ok_or_else(|| "missing".to_owned()),
                ProfileChange::Default { .. } => Ok("default".into()),
            }
        }
        fn default_profile(&self) -> Option<String> {
            None
        }
    }
    fn document() -> ProfileDocument {
        ProfileDocument {
            version: PROFILE_VERSION,
            role: ProfileRole::Connect,
            options: BTreeMap::from([("--carrier".to_owned(), "quic-like".to_owned())]),
        }
    }
    async fn ask(handle: &Handle, action: OperationAction) -> OperationReply {
        handle
            .operations_request(OperationRequest::new(action))
            .await
    }

    #[tokio::test]
    async fn profile_changes_are_keyed_and_invalid_profiles_never_consume_keys() -> io::Result<()> {
        let (handle, run) = channel();
        let owner = tokio::spawn(run);
        let unsupported = ask(&handle, OperationAction::ProfileList {}).await;
        assert_eq!(unsupported.code, "unsupported");
        let store = Arc::new(MemoryStore::default());
        assert!(handle.attach_profiles(store.clone()).is_ok());
        assert!(
            handle
                .service_info()
                .capability(Feature::Profiles)
                .is_some_and(|c| c.available)
        );
        let save = |key, expected_revision| OperationAction::Profile {
            request_key: key,
            change: ProfileChange::Save {
                name: "office".into(),
                document: document(),
                expected_revision,
            },
        };
        assert_eq!(ask(&handle, save(1, None)).await.code, "accepted");
        let done = ask(
            &handle,
            OperationAction::OperationWait {
                operation: 1,
                timeout_ms: 5_000,
                service: None,
            },
        )
        .await;
        let state = done.operation.ok_or_else(|| io::Error::other("no state"))?;
        assert_eq!(state.kind, "profile");
        assert!(matches!(
            state.result,
            Some(OperationResult::ProfileApplied { .. })
        ));
        assert_eq!(ask(&handle, save(1, None)).await.code, "accepted", "replay");
        assert_eq!(ask(&handle, save(1, Some(1))).await.code, "conflict");
        let listed = ask(&handle, OperationAction::ProfileList {}).await;
        assert_eq!(listed.profiles.map(|list| list.len()), Some(1));
        let got = ask(
            &handle,
            OperationAction::ProfileGet {
                name: "office".into(),
            },
        )
        .await;
        assert_eq!(got.profile.map(|entry| entry.revision), Some(1));
        let missing = ask(
            &handle,
            OperationAction::ProfileGet {
                name: "nope".into(),
            },
        )
        .await;
        assert_eq!(missing.code, "unknown_profile");
        let check = ask(
            &handle,
            OperationAction::ProfileValidate {
                name: "office".into(),
            },
        )
        .await;
        assert_eq!(check.check.map(|check| check.valid), Some(false));
        // A profile that cannot be prepared is refused before acceptance and
        // keeps key 2 free.
        let refused = ask(
            &handle,
            OperationAction::ProfileConnect {
                request_key: 2,
                name: "office".into(),
                replace: false,
            },
        )
        .await;
        assert_eq!(
            (refused.ok, refused.code.as_str()),
            (false, "invalid_profile")
        );
        assert!(refused.check.is_some_and(|check| check.reason.is_some()));
        assert_eq!(ask(&handle, save(2, Some(1))).await.code, "accepted");
        // A replayed key never prepares again.
        let prepared = store.prepared.lock().map(|count| *count).unwrap_or(0);
        let replay = ask(
            &handle,
            OperationAction::ProfileConnect {
                request_key: 2,
                name: "office".into(),
                replace: false,
            },
        )
        .await;
        assert_eq!(replay.code, "conflict");
        assert_eq!(
            store.prepared.lock().map(|count| *count).unwrap_or(0),
            prepared
        );
        assert_eq!(handle.snapshot().phase, Phase::Disconnected);
        owner.abort();
        Ok(())
    }
}
