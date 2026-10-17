use std::path::PathBuf;

use isideload::util::fs_storage::FsStorage;
use isideload::util::keyring_storage::KeyringStorage;
use isideload::util::storage::SideloadingStorage;
use rootcause::prelude::*;
use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey, pkcs8::EncodePrivateKey};
use sha2::{Digest, Sha256};

/// Keychain service / app data directory written by iLoader.
pub const LOADER_SERVICE: &str = "iloader";
/// Tauri identifier from iLoader's tauri.conf.json, used for the filesystem fallback.
pub const LOADER_BUNDLE_ID: &str = "me.nabdev.iloader";

#[derive(Clone)]
pub enum Backend {
    Keyring,
    Fs(PathBuf),
}

impl Backend {
    pub fn describe(&self) -> String {
        match self {
            Backend::Keyring => format!("keyring service \"{LOADER_SERVICE}\""),
            Backend::Fs(path) => format!("filesystem {}", path.display()),
        }
    }
}

/// iLoader hashes the lowercased email, matching the `apple_email` it hands to `SideloaderBuilder`.
pub fn private_key_entry(apple_id: &str) -> String {
    format!(
        "{}/key",
        hex::encode(Sha256::digest(apple_id.to_lowercase()))
    )
}

pub enum Requested {
    Auto,
    Keyring,
    Fs(PathBuf),
}

impl Requested {
    /// iLoader's own preference order; an unresolvable path stays in the list as an error to report.
    pub fn candidates(&self) -> Vec<Result<Backend, Report>> {
        match self {
            Requested::Keyring => vec![Ok(Backend::Keyring)],
            Requested::Fs(dir) => vec![Ok(Backend::Fs(dir.clone()))],
            Requested::Auto => vec![Ok(Backend::Keyring), default_fs_dir().map(Backend::Fs)],
        }
    }
}

/// Tauri's `app_data_dir` for iLoader, which is where its filesystem fallback storage lives.
pub fn default_fs_dir() -> Result<PathBuf, Report> {
    #[cfg(target_os = "windows")]
    let base = PathBuf::from(
        std::env::var_os("APPDATA")
            .ok_or_else(|| report!("%APPDATA% is not set; pass --storage-dir"))?,
    );

    #[cfg(target_os = "macos")]
    let base = home()?.join("Library").join("Application Support");

    #[cfg(all(unix, not(target_os = "macos")))]
    let base = match std::env::var_os("XDG_DATA_HOME") {
        Some(dir) => PathBuf::from(dir),
        None => home()?.join(".local").join("share"),
    };

    Ok(base.join(LOADER_BUNDLE_ID))
}

#[cfg(not(target_os = "windows"))]
fn home() -> Result<PathBuf, Report> {
    Ok(PathBuf::from(std::env::var_os("HOME").ok_or_else(
        || report!("$HOME is not set; pass --storage-dir"),
    )?))
}

pub fn open(backend: &Backend) -> Box<dyn SideloadingStorage> {
    match backend {
        Backend::Keyring => Box::new(KeyringStorage::new(LOADER_SERVICE.to_string())),
        Backend::Fs(path) => Box::new(FsStorage::new(path.clone())),
    }
}

/// Every write is dropped, so this tool cannot create, replace or delete an entry — including the
/// anisette state the login flow insists on persisting.
pub struct ReadOnly {
    inner: Box<dyn SideloadingStorage>,
}

impl SideloadingStorage for ReadOnly {
    fn store(&self, key: &str, _value: &str) -> Result<(), Report> {
        tracing::info!("Discarded write to \"{key}\"; iLoader's storage is never modified");
        Ok(())
    }

    fn retrieve(&self, key: &str) -> Result<Option<String>, Report> {
        self.inner.retrieve(key)
    }

    // Fs stores raw bytes while the keyring stores base64 except on Windows, so data access
    // has to delegate instead of using the trait's base64 defaults.
    fn store_data(&self, key: &str, _value: &[u8]) -> Result<(), Report> {
        self.store(key, "")
    }

    fn retrieve_data(&self, key: &str) -> Result<Option<Vec<u8>>, Report> {
        self.inner.retrieve_data(key)
    }

    fn delete(&self, key: &str) -> Result<(), Report> {
        self.store(key, "")
    }
}

pub fn read_only_storage(backend: &Backend) -> Box<dyn SideloadingStorage> {
    Box::new(ReadOnly {
        inner: open(backend),
    })
}

/// Skipped locations are printed so a broken credential store cannot silently drop the export onto
/// iLoader's unencrypted filesystem copy. Unlike `CertificateIdentity::retrieve_private_key`, this
/// never generates a key.
pub fn find_private_key(
    apple_id: &str,
    candidates: &[Result<Backend, Report>],
) -> Result<(Backend, RsaPrivateKey), Report> {
    let entry = private_key_entry(apple_id);
    let mut skipped: Vec<String> = Vec::new();

    for candidate in candidates {
        let backend = match candidate {
            Ok(backend) => backend.clone(),
            Err(error) => {
                skipped.push(error.to_string());
                continue;
            }
        };

        match open(&backend).retrieve_data(&entry) {
            Ok(Some(der)) => match RsaPrivateKey::from_pkcs8_der(&der) {
                Ok(private_key) => {
                    for note in &skipped {
                        println!("skipped: {note}");
                    }
                    return Ok((backend, private_key));
                }
                Err(error) => skipped.push(format!(
                    "{}: the stored key is not PKCS#8 DER: {error}",
                    backend.describe()
                )),
            },
            Ok(None) => skipped.push(format!("{}: no private key", backend.describe())),
            Err(error) => skipped.push(format!("{}: {error}", backend.describe())),
        }
    }

    bail!(
        "No private key for {apple_id}, expected an entry named \"{entry}\". Tried:\n  {}\n\
         Nothing was written to these locations. Check that the Apple ID is spelled exactly as \
         iLoader saved it, and pass --storage-dir if its data is not in the default app data \
         directory.",
        skipped.join("\n  ")
    )
}

pub fn load_password(apple_id: &str) -> Option<String> {
    // login_new() saves under the email as typed, so try that before the lowercase form.
    for account in [apple_id.to_string(), apple_id.to_lowercase()] {
        if let Ok(entry) = keyring::Entry::new(LOADER_SERVICE, &account)
            && let Ok(password) = entry.get_password()
            && !password.is_empty()
        {
            return Some(password);
        }
    }
    None
}

pub fn fingerprint(key: &RsaPrivateKey) -> Result<String, Report> {
    let digest = hex::encode(Sha256::digest(key.to_pkcs8_der()?.as_bytes()));
    Ok(digest.chars().take(16).collect::<String>())
}

pub fn inspect(apple_id: &str, candidates: &[Result<Backend, Report>]) {
    let entry = private_key_entry(apple_id);
    println!("private key entry: {entry}");

    for candidate in candidates {
        match candidate {
            Err(error) => println!("filesystem fallback: {error}"),
            Ok(backend) => {
                let storage = open(backend);
                let key = match storage.retrieve_data(&entry) {
                    Ok(Some(der)) => match RsaPrivateKey::from_pkcs8_der(&der) {
                        Ok(key) => format!(
                            "present ({} bytes, sha256:{})",
                            der.len(),
                            fingerprint(&key).unwrap_or_default()
                        ),
                        Err(error) => format!("present but unreadable: {error}"),
                    },
                    Ok(None) => "absent".to_string(),
                    Err(error) => format!("unreadable: {error}"),
                };
                println!("{}: private key {key}", backend.describe());

                let anisette = match storage
                    .retrieve_data(isideload::anisette::remote_v3::ANISETTE_STATE_KEY)
                {
                    Ok(Some(_)) => "present".to_string(),
                    Ok(None) => "absent".to_string(),
                    Err(error) => format!("unreadable: {error}"),
                };
                println!("{}: anisette state {anisette}", backend.describe());
            }
        }
    }

    // iLoader writes the password straight to the credential store, never through a backend.
    println!(
        "keyring password: {}",
        if load_password(apple_id).is_some() {
            "present"
        } else {
            "absent"
        }
    );
}
