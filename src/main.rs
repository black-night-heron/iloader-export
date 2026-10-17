mod auth;
mod export;
mod store;

use clap::{Parser, ValueEnum};
use rootcause::prelude::*;
use std::path::PathBuf;

#[derive(Clone, ValueEnum)]
enum BackendArg {
    /// Look in iLoader's system credential store first, then its app data directory
    Auto,
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

    /// Defaults to the certificate's machine ID, which is what SideStore and AltStore expect.
    /// Prefer $ILOADER_P12_PASSWORD: a flag value is visible to other processes and in shell history
    #[arg(long)]
    p12_password: Option<String>,

    /// Restrict the search to this developer team ID
    #[arg(long)]
    team: Option<String>,

    #[arg(long, value_enum, default_value_t = BackendArg::Auto)]
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
    // An explicit --storage-dir names the location, so it wins over --backend.
    let requested = match (&cli.backend, cli.storage_dir.clone()) {
        (_, Some(dir)) => store::Requested::Fs(dir),
        (BackendArg::Auto, None) => store::Requested::Auto,
        (BackendArg::Keyring, None) => store::Requested::Keyring,
        (BackendArg::Fs, None) => store::Requested::Fs(store::default_fs_dir()?),
    };
    let candidates = requested.candidates();

    if cli.inspect {
        store::inspect(&cli.apple_id, &candidates);
        return Ok(());
    }

    let (backend, private_key) = store::find_private_key(&cli.apple_id, &candidates)?;
    println!("Reading iLoader data from {}", backend.describe());
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

    // Reject an empty archive password before spending a login on it.
    let p12_password_flag = cli
        .p12_password
        .as_deref()
        .map(|password| auth::require_non_empty(password, "--p12-password"))
        .transpose()?;

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

    let (p12_password, is_machine_id) =
        auth::resolve_p12_password(p12_password_flag.as_deref(), &found.identity.machine_id)?;

    export::write_p12(&found, &p12_password, &cli.out).await?;

    // A password the user supplied is one they already know.
    if is_machine_id {
        println!("Password for importing: {p12_password}");
    }
    Ok(())
}
