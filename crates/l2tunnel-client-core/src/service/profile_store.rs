//! File-backed profile store in the service state directory:
//! `<state-dir>/profiles/<name>.json` holds `{revision, document}` and
//! `<state-dir>/profiles.json` the default profile. Files are written
//! atomically with mode 0600 in a 0700 directory. A stored document of a
//! newer version is listed and can be deleted, but never rewritten (CL-19).
//! Saving requires that the service can build a runnable plan from it.
use super::Prepared;
use super::profiles::ProfileStore;
use crate::local::{
    PROFILE_LIMIT, PROFILE_VERSION, ProfileChange, ProfileDocument, ProfileEntry, ProfileSummary,
    bounded_text, describe, validate_profile_name,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Largest stored profile file.
const FILE_LIMIT: u64 = 64 * 1024;

/// Builds a plan from a document (reads credentials; opens nothing).
pub type Preparer = Arc<dyn Fn(&ProfileDocument) -> io::Result<Prepared> + Send + Sync>;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    revision: u64,
    /// Kept as JSON so newer versions survive untouched.
    document: Value,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    default: Option<String>,
}

/// The store.
pub struct FileStore {
    directory: PathBuf,
    settings: PathBuf,
    prepare: Preparer,
    /// Serializes read-modify-write; the actor already runs one change at a time.
    lock: Mutex<()>,
}

fn write_private(path: &Path, value: &impl Serialize) -> io::Result<()> {
    let text = serde_json::to_vec_pretty(value).map_err(io::Error::other)?;
    let temporary = path.with_extension("tmp");
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&text)?;
        file.sync_all()?;
    }
    std::fs::rename(&temporary, path)
}
fn read_bounded(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.len() > FILE_LIMIT => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "stored profile file is too large",
        )),
        Ok(_) => std::fs::read(path).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}
fn invalid(error: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

impl FileStore {
    /// Open (creating `profiles/` if needed) in an already checked state directory.
    pub fn open(state_directory: &Path, prepare: Preparer) -> io::Result<Arc<Self>> {
        let directory = state_directory.join("profiles");
        match std::fs::DirBuilder::new().mode(0o700).create(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                if !std::fs::symlink_metadata(&directory)?.is_dir() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "profiles must be a directory",
                    ));
                }
            }
            Err(error) => return Err(error),
        }
        Ok(Arc::new(Self {
            directory,
            settings: state_directory.join("profiles.json"),
            prepare,
            lock: Mutex::new(()),
        }))
    }
    fn path(&self, name: &str) -> io::Result<PathBuf> {
        validate_profile_name(name)
            .map_err(|reason| io::Error::new(io::ErrorKind::InvalidInput, reason))?;
        Ok(self.directory.join(format!("{name}.json")))
    }
    fn load(&self, name: &str) -> io::Result<Option<Stored>> {
        read_bounded(&self.path(name)?)?
            .map(|bytes| serde_json::from_slice(&bytes).map_err(invalid))
            .transpose()
    }
    fn settings(&self) -> io::Result<Settings> {
        read_bounded(&self.settings)?
            .map(|bytes| serde_json::from_slice(&bytes).map_err(invalid))
            .transpose()
            .map(Option::unwrap_or_default)
    }
    fn names(&self) -> io::Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&self.directory)? {
            let file = entry?.file_name();
            let Some(name) = file.to_str().and_then(|text| text.strip_suffix(".json")) else {
                continue;
            };
            if validate_profile_name(name).is_ok() {
                names.push(name.to_owned());
            }
            if names.len() > PROFILE_LIMIT {
                break;
            }
        }
        names.sort();
        names.truncate(PROFILE_LIMIT);
        Ok(names)
    }
    fn document(stored: &Stored) -> Option<ProfileDocument> {
        serde_json::from_value::<ProfileDocument>(stored.document.clone())
            .ok()
            .filter(|document| document.version == PROFILE_VERSION)
    }
    fn guard(&self) -> Result<std::sync::MutexGuard<'_, ()>, String> {
        self.lock
            .lock()
            .map_err(|_| "profile store lock poisoned".to_owned())
    }
    fn change(&self, change: ProfileChange) -> Result<String, String> {
        let _guard = self.guard()?;
        let text = |error: io::Error| bounded_text(&error.to_string());
        match change {
            ProfileChange::Save {
                name,
                document,
                expected_revision,
            } => {
                document.validate().map_err(str::to_owned)?;
                let current = self.load(&name).map_err(text)?;
                if let Some(stored) = &current
                    && Self::document(stored).is_none()
                {
                    return Err(format!(
                        "{name} is stored in a newer or unknown version; it is not rewritten"
                    ));
                }
                let revision = current.as_ref().map(|stored| stored.revision);
                if revision != expected_revision {
                    return Err(match revision {
                        Some(revision) => {
                            format!("{name} is at revision {revision}; reload before saving")
                        }
                        None => format!("{name} does not exist"),
                    });
                }
                if current.is_none() && self.names().map_err(text)?.len() >= PROFILE_LIMIT {
                    return Err(format!("the store holds at most {PROFILE_LIMIT} profiles"));
                }
                (self.prepare)(&document)
                    .map_err(|error| bounded_text(&format!("not runnable: {error}")))?;
                let next = revision.unwrap_or(0).saturating_add(1);
                let stored = Stored {
                    revision: next,
                    document: serde_json::to_value(&document)
                        .map_err(|error| bounded_text(&error.to_string()))?,
                };
                write_private(&self.path(&name).map_err(text)?, &stored).map_err(text)?;
                Ok(format!("saved {name} at revision {next}"))
            }
            ProfileChange::Delete {
                name,
                expected_revision,
            } => {
                let stored = self
                    .load(&name)
                    .map_err(text)?
                    .ok_or_else(|| format!("{name} does not exist"))?;
                if stored.revision != expected_revision {
                    return Err(format!(
                        "{name} is at revision {}; reload before deleting",
                        stored.revision
                    ));
                }
                std::fs::remove_file(self.path(&name).map_err(text)?).map_err(text)?;
                let mut settings = self.settings().map_err(text)?;
                if settings.default.as_deref() == Some(name.as_str()) {
                    settings.default = None;
                    write_private(&self.settings, &settings).map_err(text)?;
                }
                Ok(format!("deleted {name}"))
            }
            ProfileChange::Default { name } => {
                if let Some(name) = &name
                    && self.load(name).map_err(text)?.is_none()
                {
                    return Err(format!("{name} does not exist"));
                }
                let summary = match &name {
                    Some(name) => format!("{name} connects when the service starts"),
                    None => "no profile connects when the service starts".into(),
                };
                write_private(&self.settings, &Settings { default: name }).map_err(text)?;
                Ok(summary)
            }
        }
    }
}

impl ProfileStore for FileStore {
    fn list(&self) -> io::Result<Vec<ProfileSummary>> {
        let default = self.settings()?.default;
        let mut summaries = Vec::new();
        for name in self.names()? {
            let Some(stored) = self.load(&name)? else {
                continue;
            };
            let document = Self::document(&stored);
            summaries.push(ProfileSummary {
                default: default.as_deref() == Some(name.as_str()),
                version: stored
                    .document
                    .get("version")
                    .and_then(Value::as_u64)
                    .and_then(|version| u16::try_from(version).ok())
                    .unwrap_or(0),
                role: document.as_ref().map(|document| document.role),
                summary: document.as_ref().map_or_else(
                    || "newer or unknown version; not editable here".to_owned(),
                    describe,
                ),
                device: document
                    .as_ref()
                    .and_then(|document| document.options.get("--device").cloned()),
                editable: document.is_some(),
                revision: stored.revision,
                name,
            });
        }
        Ok(summaries)
    }
    fn get(&self, name: &str) -> io::Result<Option<ProfileEntry>> {
        let Some(stored) = self.load(name)? else {
            return Ok(None);
        };
        let document = Self::document(&stored).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "stored profile has a newer or unknown version",
            )
        })?;
        Ok(Some(ProfileEntry {
            name: name.to_owned(),
            revision: stored.revision,
            document,
        }))
    }
    fn prepare(&self, name: &str) -> Result<Prepared, String> {
        let entry = self
            .get(name)
            .map_err(|error| bounded_text(&error.to_string()))?
            .ok_or_else(|| format!("{name} does not exist"))?;
        (self.prepare)(&entry.document).map_err(|error| bounded_text(&error.to_string()))
    }
    fn apply(&self, change: ProfileChange) -> Result<String, String> {
        self.change(change)
    }
    fn default_profile(&self) -> Option<String> {
        self.settings().ok().and_then(|settings| settings.default)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::ProfileRole;
    use std::collections::BTreeMap;

    fn document(carrier: &str) -> ProfileDocument {
        ProfileDocument {
            version: PROFILE_VERSION,
            role: ProfileRole::Connect,
            options: BTreeMap::from([("--carrier".to_owned(), carrier.to_owned())]),
        }
    }
    fn refuse_bad(document: &ProfileDocument) -> io::Result<Prepared> {
        Err(io::Error::other(format!(
            "plan refused ({})",
            document.options.get("--carrier").map_or("", String::as_str)
        )))
    }

    #[test]
    fn saves_need_revisions_and_runnable_plans_and_newer_versions_survive() -> io::Result<()> {
        let state = std::env::temp_dir().join(format!("l2t-profiles-{}", std::process::id()));
        std::fs::create_dir_all(&state)?;
        let store = FileStore::open(&state, Arc::new(refuse_bad))?;
        let save = |name: &str, carrier: &str, expected_revision| ProfileChange::Save {
            name: name.into(),
            document: document(carrier),
            expected_revision,
        };
        // Saving needs a runnable plan; this preparer refuses everything.
        let refused = store.apply(save("office", "quic-like", None));
        assert!(refused.is_err_and(|reason| reason.starts_with("not runnable")));
        assert!(store.list()?.is_empty());
        // Write one directly as if a runnable save had happened, then edit it.
        write_private(
            &store.path("office")?,
            &Stored {
                revision: 3,
                document: serde_json::to_value(document("quic-like")).map_err(io::Error::other)?,
            },
        )?;
        let listed = store.list()?;
        assert_eq!(
            (listed.len(), listed[0].revision, listed[0].editable),
            (1, 3, true)
        );
        assert!(
            store
                .apply(save("office", "tcp", Some(2)))
                .is_err_and(|reason| reason.contains("revision 3"))
        );
        assert!(store.apply(save("office", "tcp", None)).is_err());
        // Default only for existing profiles; deleting clears it.
        assert!(
            store
                .apply(ProfileChange::Default {
                    name: Some("nope".into())
                })
                .is_err()
        );
        store
            .apply(ProfileChange::Default {
                name: Some("office".into()),
            })
            .map_err(io::Error::other)?;
        assert_eq!(store.default_profile().as_deref(), Some("office"));
        assert!(store.list()?[0].default);
        // A newer version is listed, not editable, not rewritten, deletable.
        write_private(
            &store.path("future")?,
            &serde_json::json!({"revision": 9, "document": {"version": 2, "anything": true}}),
        )?;
        let future = store.list()?.into_iter().find(|row| row.name == "future");
        assert!(future.is_some_and(|row| !row.editable && row.version == 2));
        assert!(store.get("future").is_err());
        assert!(
            store
                .apply(save("future", "tcp", Some(9)))
                .is_err_and(|reason| reason.contains("not rewritten"))
        );
        store
            .apply(ProfileChange::Delete {
                name: "office".into(),
                expected_revision: 3,
            })
            .map_err(io::Error::other)?;
        assert_eq!(store.default_profile(), None);
        assert!(store.prepare("office").is_err());
        std::fs::remove_dir_all(&state)?;
        Ok(())
    }
}
