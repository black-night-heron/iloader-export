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

/// Reads go to iLoader's storage; every write is dropped, so this tool cannot create,
/// replace or delete an entry. The anisette state the login flow insists on persisting
/// is simply not persisted.
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

/// Read-only: unlike `CertificateIdentity::retrieve_private_key`, this never generates a key.
pub fn load_private_key(apple_id: &str, backend: &Backend) -> Result<RsaPrivateKey, Report> {
    let entry = private_key_entry(apple_id);
    let der = open(backend).retrieve_data(&entry)?.ok_or_else(|| {
        report!(
            "No private key found in {}. Expected an entry named \"{entry}\" for {}",
            backend.describe(),
            apple_id
        )
    })?;
    Ok(RsaPrivateKey::from_pkcs8_der(&der).context("Stored private key is not PKCS#8 DER")?)
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

pub fn inspect(apple_id: &str, backend: &Backend) {
    let entry = private_key_entry(apple_id);
    let status = match open(backend).retrieve_data(&entry) {
        Ok(Some(der)) => match RsaPrivateKey::from_pkcs8_der(&der) {
            Ok(key) => format!(
                "present ({} bytes, sha256:{})",
                der.len(),
                fingerprint(&key).unwrap_or_default()
            ),
            Err(e) => format!("present but unreadable: {e}"),
        },
        Ok(None) => format!("absent (expected entry \"{entry}\")"),
        Err(e) => format!("unreadable: {e}"),
    };
    println!("private key: {status}");

    let anisette = open(backend).retrieve_data(isideload::anisette::remote_v3::ANISETTE_STATE_KEY);
    println!(
        "anisette state: {}",
        match anisette {
            Ok(Some(_)) => "present".to_string(),
            Ok(None) => "absent".to_string(),
            Err(e) => format!("unreadable: {e}"),
        }
    );

    match backend {
        Backend::Keyring => println!(
            "saved password: {}",
            if load_password(apple_id).is_some() {
                "present"
            } else {
                "absent"
            }
        ),
        Backend::Fs(_) => println!("saved password: iLoader never stores it on the filesystem"),
    }
}
