use std::io::Write;
use std::path::Path;
use std::time::SystemTime;

use isideload::dev::certificates::{CertificatesApi, DevelopmentCertificate};
use isideload::dev::developer_session::DeveloperSession;
use isideload::dev::teams::{DeveloperTeam, TeamsApi};
use isideload::sideload::cert_identity::CertificateIdentity;
use rootcause::prelude::*;
use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPublicKey};
use x509_cert::{Certificate, der::Decode};

pub struct Found {
    pub identity: CertificateIdentity,
    pub team: DeveloperTeam,
    pub remote: DevelopmentCertificate,
}

/// Only "Revoked" rejects a match; the rest of Apple's strings are undocumented (a healthy
/// certificate says "Issued", not "Active"), and expiry comes from the signed validity period.
fn reject(
    not_before: SystemTime,
    not_after: SystemTime,
    status: Option<&str>,
    now: SystemTime,
) -> Option<&'static str> {
    if not_after < now {
        return Some("expired");
    }
    if not_before > now {
        return Some("not yet valid");
    }
    if status.is_some_and(|status| status.eq_ignore_ascii_case("revoked")) {
        return Some("revoked");
    }
    None
}

/// Higher is better: a machine ID, then a later expiry.
fn rank(has_machine_id: bool, not_after: SystemTime) -> (bool, SystemTime) {
    (has_machine_id, not_after)
}

fn expiry(certificate: &Certificate) -> SystemTime {
    SystemTime::from(&certificate.tbs_certificate.validity.not_after)
}

/// Like `CertificateIdentity::find_matching`, but without the machine name filter and without
/// the fall-through to `request_certificate`: this only ever reads.
pub async fn find_existing_identity(
    session: &mut DeveloperSession,
    private_key: &RsaPrivateKey,
    team_filter: Option<&str>,
) -> Result<Found, Report> {
    let public_key_der = private_key
        .to_public_key()
        .to_pkcs1_der()?
        .as_bytes()
        .to_vec();

    let teams = session.list_teams().await.context("Failed to list teams")?;
    if teams.is_empty() {
        bail!("This Apple ID has no developer teams");
    }

    let now = SystemTime::now();
    let mut inspected = 0;
    let mut matched = 0;
    let mut unusable: Vec<String> = Vec::new();
    let mut usable: Vec<Found> = Vec::new();

    for team in teams
        .iter()
        .filter(|team| team_filter.is_none_or(|id| team.team_id.eq_ignore_ascii_case(id)))
    {
        for cert in session.list_ios_certs(team).await.context(format!(
            "Failed to list certificates for team {}",
            team.team_id
        ))? {
            inspected += 1;
            let Some(content) = &cert.cert_content else {
                continue;
            };
            let Ok(x509) = Certificate::from_der(content.as_ref()) else {
                tracing::warn!("Skipping {:?}: certificate is not DER", cert.name);
                continue;
            };
            let Some(subject_public_key) = x509
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .as_bytes()
            else {
                continue;
            };
            if subject_public_key != public_key_der.as_slice() {
                continue;
            }

            matched += 1;
            let name = cert
                .name
                .clone()
                .or_else(|| cert.serial_number.clone())
                .unwrap_or_else(|| "unnamed certificate".to_string());
            let validity = &x509.tbs_certificate.validity;
            match reject(
                SystemTime::from(&validity.not_before),
                expiry(&x509),
                cert.status.as_deref(),
                now,
            ) {
                Some(reason) => unusable.push(format!("{name} (team {}): {reason}", team.team_id)),
                None => usable.push(Found {
                    identity: CertificateIdentity {
                        machine_id: cert.machine_id.clone().unwrap_or_default(),
                        machine_name: cert.machine_name.clone().unwrap_or_default(),
                        private_key: private_key.clone(),
                        certificate: x509,
                    },
                    team: team.clone(),
                    remote: cert,
                }),
            }
        }
    }

    if let Some(best) = usable.into_iter().max_by_key(|found| {
        rank(
            !found.identity.machine_id.is_empty(),
            expiry(&found.identity.certificate),
        )
    }) {
        return Ok(best);
    }

    if matched == 0 {
        bail!(
            "No stored private key match among {inspected} iOS development certificates. \
             Nothing was created or revoked. Check the Apple ID, --team, or run --inspect."
        );
    }

    bail!(
        "The {matched} certificate(s) matching the stored private key cannot be exported:\n  {}\n\
         Nothing was created or revoked; renew the certificate in iLoader and run again.",
        unusable.join("\n  ")
    )
}

pub fn summarize(found: &Found) {
    let identity = &found.identity;
    let subject = &identity.certificate.tbs_certificate.subject;

    println!(
        "team:            {} ({})",
        found.team.name.clone().unwrap_or_default(),
        found.team.team_id
    );
    println!("certificate:     {:?}", found.remote.name);
    println!("serial:          {}", identity.get_serial_number());
    println!("subject:         {subject}");
    println!(
        "status:          {} {}",
        found.remote.status.clone().unwrap_or_default(),
        found
            .remote
            .expiration_date
            .as_ref()
            .map(|date| format!("until {}", date.to_xml_format()))
            .unwrap_or_default()
    );
    println!(
        "machine:         {} ({})",
        identity.machine_name, identity.machine_id
    );
}

pub async fn write_p12(found: &Found, password: &str, path: &Path) -> Result<(), Report> {
    let bytes = found
        .identity
        .as_p12(password)
        .await
        .context("Failed to encode the certificate and key as PKCS#12")?;

    let mut file = create_exclusive(path)?;
    let written = file.write_all(&bytes).and_then(|()| file.flush());
    drop(file);
    if written.is_err() {
        let _ = std::fs::remove_file(path);
    }
    written.context(format!("Failed to write {}", path.display()))?;

    println!("Wrote {} ({} bytes)", path.display(), bytes.len());
    Ok(())
}

/// Creates exclusively with owner-only bits, so the no-overwrite guarantee cannot be raced and the
/// key is never briefly world-readable.
fn create_exclusive(path: &Path) -> Result<std::fs::File, Report> {
    match open_exclusive(path) {
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => bail!(
            "{} already exists; pass --out to choose another path",
            path.display()
        ),
        result => Ok(result.context(format!("Failed to create {}", path.display()))?),
    }
}

#[cfg(unix)]
fn open_exclusive(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_exclusive(path: &Path) -> std::io::Result<std::fs::File> {
    // Windows has no create-time mode; the file inherits its directory's ACL.
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}
