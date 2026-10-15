mod auth;
mod export;
mod store;

use clap::{Parser, ValueEnum};
use rootcause::prelude::*;
use std::path::PathBuf;

#[derive(Clone, ValueEnum)]
enum BackendArg {
    /// iLoader's system credential store (Keychain, Credential Manager or Secret Service)
    Keyring,
    /// Plain files in iLoader's app data directory
    Fs,
}

#[derive(Parser)]
#[command(
    version,
    about = "Export the Apple Development certificate and private key that iLoader already uses, packaged as a .p12. Read-only: it never creates, replaces or revokes a certificate."
)]
struct Cli {
    /// Apple ID as configured in iLoader
    apple_id: String,

    #[arg(short, long, default_value = "iloader.p12")]
    out: PathBuf,

    /// Defaults to the certificate's machine ID, which is what SideStore and AltStore expect
    #[arg(long)]
    p12_password: Option<String>,

    /// Restrict the search to this developer team ID
    #[arg(long)]
    team: Option<String>,

    #[arg(long, value_enum, default_value_t = BackendArg::Keyring)]
    backend: BackendArg,

    /// Implies --backend fs; defaults to iLoader's app data directory for this platform
    #[arg(long)]
    storage_dir: Option<PathBuf>,

    #[arg(long, default_value = auth::DEFAULT_ANISETTE_HOST)]
    anisette_server: String,

    /// iLoader authenticates with serial "0"
    #[arg(long, default_value = "0")]
    anisette_serial: String,

    /// Report what is in storage and stop, without touching the network
    #[arg(long)]
    inspect: bool,

    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install the rustls crypto provider");
    isideload::init().expect("Failed to initialize error reporting");

    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_max_level(if cli.verbose {
            tracing::Level::INFO
        } else {
            tracing::Level::WARN
        })
        .with_writer(std::io::stderr)
        .init();

    if let Err(error) = run(&cli).await {
        if cli.verbose {
            eprintln!("{error:?}");
        } else {
            eprintln!("{error}");
        }
        std::process::exit(1);
    }
}

async fn run(cli: &Cli) -> Result<(), Report> {
    let backend = match (&cli.backend, cli.storage_dir.clone()) {
        (BackendArg::Fs, Some(dir)) | (BackendArg::Keyring, Some(dir)) => store::Backend::Fs(dir),
        (BackendArg::Fs, None) => store::Backend::Fs(store::default_fs_dir()?),
        (BackendArg::Keyring, None) => store::Backend::Keyring,
    };
    println!("Reading iLoader data from {}", backend.describe());

    if cli.inspect {
        store::inspect(&cli.apple_id, &backend);
        return Ok(());
    }

    let private_key = store::load_private_key(&cli.apple_id, &backend)?;
    println!(
        "Stored private key: sha256:{}",
        store::fingerprint(&private_key)?
    );

    if cli.out.exists() {
        bail!(
            "{} already exists; pass --out to choose another path",
            cli.out.display()
        );
    }

    let password = auth::resolve_password(&cli.apple_id)?;
    let mut session = auth::login(
        &cli.apple_id,
        &password,
        &cli.anisette_server,
        &cli.anisette_serial,
        store::read_only_storage(&backend),
    )
    .await?;

    let found =
        export::find_existing_identity(&mut session, &private_key, cli.team.as_deref()).await?;
    export::summarize(&found);

    let p12_password = match &cli.p12_password {
        Some(password) => password.clone(),
        None if found.identity.machine_id.is_empty() => {
            bail!("The certificate has no machine ID; pass --p12-password")
        }
        None => found.identity.machine_id.clone(),
    };

    export::write_p12(&found, &p12_password, &cli.out).await
}
