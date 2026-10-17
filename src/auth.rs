use std::io::Write;

use isideload::anisette::remote_v3::RemoteV3AnisetteProvider;
use isideload::auth::apple_account::{
    AppleAccount, TwoFactorCallbackParams, TwoFactorCallbackResponse,
};
use isideload::dev::developer_session::DeveloperSession;
use isideload::util::storage::SideloadingStorage;
use rootcause::prelude::*;

use crate::store;

pub const DEFAULT_ANISETTE_HOST: &str = "https://ani.jkcoxson.com";

/// There is deliberately no Apple ID password flag: arguments reach every process on the machine
/// and end up in shell history.
pub fn resolve_password(apple_id: &str) -> Result<String, Report> {
    if let Some(password) = std::env::var("ILOADER_PASSWORD")
        .ok()
        .filter(|p| !p.is_empty())
    {
        tracing::info!("Using the password from $ILOADER_PASSWORD");
        return Ok(password);
    }
    if let Some(password) = store::load_password(apple_id) {
        tracing::info!("Using the password iLoader saved in the keychain");
        return Ok(password);
    }
    Ok(rpassword::prompt_password_stderr("Apple ID password: ")?)
}

pub fn require_non_empty(password: &str, source: &str) -> Result<String, Report> {
    if password.is_empty() {
        bail!("{source} was empty; an empty import password leaves the private key unprotected");
    }
    Ok(password.to_string())
}

/// The bool is true only for the machine ID: SideStore and AltStore expect it, and it is the one
/// source here the user has not already seen.
pub fn resolve_p12_password(
    flag: Option<&str>,
    machine_id: &str,
) -> Result<(String, bool), Report> {
    if let Some(password) = flag {
        tracing::warn!("--p12-password is visible to other processes and in shell history");
        return Ok((password.to_string(), false));
    }
    if let Some(password) = std::env::var("ILOADER_P12_PASSWORD")
        .ok()
        .filter(|password| !password.is_empty())
    {
        tracing::info!("Using the import password from $ILOADER_P12_PASSWORD");
        return Ok((password, false));
    }
    if !machine_id.is_empty() {
        return Ok((machine_id.to_string(), true));
    }
    let password = rpassword::prompt_password_stderr("PKCS#12 import password: ")?;
    Ok((
        require_non_empty(&password, "the password you entered")?,
        false,
    ))
}

fn normalize_anisette_url(server: &str) -> String {
    if server.starts_with("http") {
        server.to_string()
    } else {
        format!("https://{server}")
    }
}

async fn prompt_two_factor(
    params: TwoFactorCallbackParams,
) -> Result<TwoFactorCallbackResponse, Report> {
    if let Some(error) = &params.last_error {
        println!("Apple rejected the previous attempt: {error}");
    }

    if params.unknown {
        println!("The last verification method failed; choose another one.");
    } else if params.sms {
        let destination = params
            .numbers
            .iter()
            .find(|n| Some(n.id) == params.selected_number_id)
            .map(|n| n.number_with_dial_code.clone())
            .unwrap_or_else(|| "your devices".to_string());
        println!("Enter the code sent to {destination}:");
    } else {
        println!("Enter the code shown on your devices:");
    }

    let others: Vec<_> = params
        .numbers
        .iter()
        .filter(|n| Some(n.id) != params.selected_number_id)
        .collect();
    if !others.is_empty() {
        println!("Or type p<id> to send it to a different number instead:");
        for number in &others {
            println!("  p{}: {}", number.id, number.number_with_dial_code);
        }
    }
    if !params.unknown {
        println!("Or type r to resend, d to use your devices instead.");
    }
    let _ = std::io::stdout().flush();

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let input = input.trim();

    if input == "r" && !params.unknown {
        return Ok(TwoFactorCallbackResponse::ResendCode);
    }
    if input == "d" {
        return Ok(TwoFactorCallbackResponse::SendToDevices);
    }
    if let Some(id) = input
        .strip_prefix('p')
        .and_then(|rest| rest.parse::<u32>().ok())
    {
        return Ok(TwoFactorCallbackResponse::SendSms(id));
    }

    Ok(TwoFactorCallbackResponse::SubmitCode(input.to_string()))
}

pub async fn login(
    apple_id: &str,
    password: &str,
    anisette_server: &str,
    anisette_serial: &str,
    storage: Box<dyn SideloadingStorage>,
) -> Result<DeveloperSession, Report> {
    let provider = RemoteV3AnisetteProvider::default()?
        .set_serial_number(anisette_serial.to_string())
        .set_storage(storage)
        .set_url(&normalize_anisette_url(anisette_server));

    let mut account = AppleAccount::builder(&apple_id.to_lowercase())
        .anisette_provider(provider)
        .login(password, |params| prompt_two_factor(params))
        .await
        .context("Apple ID login failed")?;

    Ok(DeveloperSession::from_account(&mut account)
        .await
        .context("Failed to create a developer session")?)
}
