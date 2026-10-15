use std::path::Path;

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

    let mut inspected = 0;
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

            if subject_public_key == public_key_der.as_slice() {
                return Ok(Found {
                    identity: CertificateIdentity {
                        machine_id: cert.machine_id.clone().unwrap_or_default(),
                        machine_name: cert.machine_name.clone().unwrap_or_default(),
                        private_key: private_key.clone(),
                        certificate: x509,
                    },
                    team: team.clone(),
                    remote: cert,
                });
            }
        }
    }

    bail!(
        "No stored private key match among {inspected} iOS development certificates. \
         Nothing was created or revoked. Check the Apple ID, --team, or run --inspect."
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

    std::fs::write(path, &bytes).context(format!("Failed to write {}", path.display()))?;
    restrict_permissions(path)?;

    println!("Wrote {} ({} bytes)", path.display(), bytes.len());
    println!("Password for importing: {password}");
    Ok(())
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<(), Report> {
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<(), Report> {
    Ok(())
}
