use std::io::Write;

use anyhow::Context;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use picrypt_client::config::ClientConfig;
use picrypt_client::{connection, container, daemon, recovery, veracrypt, yubikey_setup};

#[derive(Parser)]
#[command(
    name = "picrypt",
    version,
    about = "VeraCrypt remote key management client"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Path to config file (default: ~/.picrypt/client.toml)
    #[arg(long, global = true)]
    config: Option<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize client config interactively
    Init {
        /// Pi server URL (e.g. http://100.x.y.z:7123)
        #[arg(long)]
        server_url: String,

        /// Additional fallback server URLs (LAN IPs, secondary Pis)
        #[arg(long)]
        fallback: Vec<String>,
    },

    /// Register this device with the Pi key server
    Register {
        /// Human-readable device name
        #[arg(long)]
        name: String,
        /// Admin token (base64). Required if server has admin auth configured.
        /// Can also be set via PICRYPT_ADMIN_TOKEN env var.
        #[arg(long, env = "PICRYPT_ADMIN_TOKEN")]
        admin_token: Option<String>,
    },

    /// Mount encrypted volumes (fetches key from Pi, starts heartbeat daemon)
    Unlock,

    /// Dismount all encrypted volumes and stop the daemon
    Lock,

    /// Show current status (server state, mounted volumes, heartbeat)
    Status,

    /// Send panic lock signal to the Pi (locks ALL devices everywhere)
    #[command(name = "panic")]
    PanicLock {
        /// Lock PIN (if configured on the server)
        #[arg(long)]
        pin: Option<String>,
    },

    /// YubiKey management (setup, backup, recover)
    #[command(subcommand)]
    Yubikey(YubikeyCommand),

    /// Unseal the Pi key server (done after each reboot)
    Unseal {
        /// Server password (if not provided, prompts interactively)
        #[arg(long)]
        password: Option<String>,
        /// Use YubiKey instead of password
        #[arg(long)]
        yubikey: bool,
    },

    /// Create a new VeraCrypt container using the server-managed keyfile
    CreateContainer {
        /// Path for the new container file (e.g. ~/vault.hc)
        #[arg(long)]
        path: String,
        /// Container size (e.g. "10G", "500M")
        #[arg(long, default_value = "10G")]
        size: String,
        /// Mount point — if provided, auto-adds to config
        #[arg(long)]
        mount_point: Option<String>,
        /// Filesystem (exFAT, NTFS, ext4)
        #[arg(long, default_value = "exFAT")]
        filesystem: String,
        /// Encryption algorithm
        #[arg(long, default_value = "AES-Twofish")]
        encryption: String,
        /// Hash algorithm
        #[arg(long, default_value = "SHA-512")]
        hash: String,
    },
}

#[derive(Subcommand)]
enum YubikeyCommand {
    /// Check if YubiKey tools are installed and a key is connected
    Check,
    /// Program HMAC-SHA1 into YubiKey slot 2 (first-time setup)
    Setup,
    /// Program a SECOND YubiKey with the same secret (for redundancy)
    SetupSecond {
        /// The hex secret from the first setup
        #[arg(long)]
        secret: String,
    },
    /// Create an encrypted backup of your keyfile (fetches from server, no CLI args)
    Backup,
    /// Recover and mount volumes using YubiKey backup (when Pi is dead)
    Recover,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Init {
            server_url,
            fallback,
        } => {
            cmd_init(&server_url, fallback).await?;
        }
        Command::Register { name, admin_token } => {
            let config = load_config(cli.config.as_deref())?;
            cmd_register(&config, &name, admin_token.as_deref()).await?;
        }
        Command::Unseal { password, yubikey } => {
            let config = load_config(cli.config.as_deref())?;
            cmd_unseal(&config, password, yubikey).await?;
        }
        Command::Unlock => {
            let config = load_config(cli.config.as_deref())?;
            cmd_unlock(&config).await?;
        }
        Command::Lock => {
            let config = load_config(cli.config.as_deref())?;
            cmd_lock(&config).await?;
        }
        Command::Status => {
            let config = load_config(cli.config.as_deref())?;
            cmd_status(&config).await?;
        }
        Command::PanicLock { pin } => {
            let config = load_config(cli.config.as_deref())?;
            cmd_panic_lock(&config, pin.as_deref()).await?;
        }
        Command::Yubikey(yk_cmd) => {
            match yk_cmd {
                YubikeyCommand::Check => {
                    yubikey_setup::check_prerequisites()?;
                    if yubikey_setup::is_slot2_configured() {
                        println!("HMAC-SHA1 slot 2: configured");
                    } else {
                        println!("HMAC-SHA1 slot 2: NOT configured");
                        println!("Run: picrypt yubikey setup");
                    }
                }
                YubikeyCommand::Setup => {
                    yubikey_setup::check_prerequisites()?;
                    if yubikey_setup::is_slot2_configured() {
                        println!("Slot 2 is already configured.");
                        println!("Re-programming will invalidate existing backups.");
                        // Could add a --force flag, for now just warn.
                    }
                    let secret = yubikey_setup::program_slot2()?;
                    println!();
                    println!("YubiKey programmed successfully.");
                    println!();
                    println!("SAVE THIS SECRET to program a backup YubiKey:");
                    println!("  {secret}");
                    println!();
                    println!("To program a second YubiKey with the same secret:");
                    println!("  picrypt yubikey setup-second --secret {secret}");
                    println!();
                    println!("To create an encrypted backup of your keyfile:");
                    println!("  picrypt yubikey backup");
                }
                YubikeyCommand::SetupSecond { secret } => {
                    yubikey_setup::check_prerequisites()?;
                    println!("Remove the first YubiKey and insert the second one.");
                    println!("Press Enter when ready...");
                    let _ = std::io::stdin().read_line(&mut String::new());
                    yubikey_setup::program_second_key(&secret)?;
                    println!("Second YubiKey programmed with the same secret.");
                }
                YubikeyCommand::Backup => {
                    let config = load_config(cli.config.as_deref())?;
                    yubikey_setup::create_backup_from_server(&config).await?;
                }
                YubikeyCommand::Recover => {
                    let config = load_config(cli.config.as_deref())?;
                    recovery::recover(&config)?;
                }
            }
        }
        Command::CreateContainer {
            path,
            size,
            mount_point,
            filesystem,
            encryption,
            hash,
        } => {
            let config = load_config(cli.config.as_deref())?;
            container::create(
                &config,
                &path,
                &size,
                &filesystem,
                &encryption,
                &hash,
                mount_point.as_deref(),
            )
            .await?;
        }
    }

    Ok(())
}

fn load_config(path: Option<&str>) -> anyhow::Result<ClientConfig> {
    match path {
        Some(p) => ClientConfig::load_from(p),
        None => ClientConfig::load(),
    }
}

async fn cmd_init(server_url: &str, fallback: Vec<String>) -> anyhow::Result<()> {
    let mut config =
        ClientConfig::create_default(server_url).context("failed to create client config")?;

    if !fallback.is_empty() {
        config.fallback_urls = fallback;
        config.save()?;
    }

    println!("Config created at: {}", config.config_path().display());
    println!("Server URL: {server_url}");
    if !config.fallback_urls.is_empty() {
        println!("Fallback URLs: {}", config.fallback_urls.join(", "));
    }
    println!();
    println!("Next: register this device with `picrypt register --name <device-name>`");
    Ok(())
}

async fn cmd_register(
    config: &ClientConfig,
    name: &str,
    admin_token: Option<&str>,
) -> anyhow::Result<()> {
    // For registration, use the admin token if provided.
    let mut reg_config = config.clone();
    if let Some(token) = admin_token {
        reg_config.auth_token = Some(token.to_string());
    }
    let client = connection::ServerClient::new(&reg_config)?;

    let platform = detect_platform();
    let resp = client.register_device(name, platform).await?;

    let mut config = config.clone();
    config.device_id = Some(resp.device_id);
    config.auth_token = Some(resp.auth_token.clone());
    config.save()?;

    println!("Device registered successfully!");
    println!("  Device ID: {}", resp.device_id);
    println!(
        "  Keyfile stored on server. Use `picrypt create-container` or `picrypt yubikey backup`."
    );

    Ok(())
}

async fn cmd_unseal(
    config: &ClientConfig,
    password: Option<String>,
    yubikey: bool,
) -> anyhow::Result<()> {
    let client = connection::ServerClient::new(config)?;

    let resp = match (password, yubikey) {
        (Some(pw), true) => client.unseal_both(&pw).await?,
        (Some(pw), false) => client.unseal(&pw).await?,
        (None, true) => client.unseal_yubikey().await?,
        (None, false) => {
            // Prompt for password interactively.
            eprint!("Unseal password: ");
            std::io::stderr().flush()?;
            let mut pw = String::new();
            std::io::stdin().read_line(&mut pw)?;
            let pw = pw.trim_end();
            if pw.is_empty() {
                anyhow::bail!("password cannot be empty");
            }
            client.unseal(pw).await?
        }
    };

    println!("Server unsealed successfully.");
    println!("  State: {}", resp.state);
    println!("  Devices: {}", resp.device_count);
    Ok(())
}

async fn cmd_unlock(config: &ClientConfig) -> anyhow::Result<()> {
    config.require_registered()?;

    let client = connection::ServerClient::new(config)?;

    let heartbeat = client.heartbeat().await?;
    if heartbeat.state != picrypt_common::protocol::ServerState::Active {
        anyhow::bail!(
            "server is {} — cannot unlock. Unseal the Pi first.",
            heartbeat.state
        );
    }

    daemon::run(config, client).await
}

async fn cmd_lock(config: &ClientConfig) -> anyhow::Result<()> {
    config.require_registered()?;

    for volume in &config.volumes {
        match veracrypt::dismount(&volume.mount_point) {
            Ok(()) => println!("Dismounted: {}", volume.mount_point),
            Err(e) => eprintln!("Failed to dismount {}: {e}", volume.mount_point),
        }
    }

    println!("All local volumes locked.");
    Ok(())
}

async fn cmd_status(config: &ClientConfig) -> anyhow::Result<()> {
    let client = connection::ServerClient::new(config)?;

    match client.heartbeat().await {
        Ok(resp) => {
            println!("Server: {} ({})", resp.state, config.server_url);
            if !config.fallback_urls.is_empty() {
                println!("Fallbacks: {}", config.fallback_urls.join(", "));
            }
            println!("Timestamp: {}", resp.timestamp);
        }
        Err(e) => {
            println!("Server: UNREACHABLE ({})", config.server_url);
            println!("Error: {e}");
        }
    }

    if let Some(ref device_id) = config.device_id {
        println!("Device ID: {device_id}");
    } else {
        println!("Device: not registered");
    }

    for volume in &config.volumes {
        let status = match veracrypt::is_mounted(&volume.mount_point) {
            Ok(true) => "MOUNTED",
            Ok(false) => "locked",
            Err(e) => {
                eprintln!("  Warning: could not check mount status: {e}");
                "UNKNOWN"
            }
        };
        println!(
            "Volume: {} -> {} [{}]",
            volume.container, volume.mount_point, status
        );
    }

    Ok(())
}

async fn cmd_panic_lock(config: &ClientConfig, pin: Option<&str>) -> anyhow::Result<()> {
    let client = connection::ServerClient::new(config)?;

    println!("Sending PANIC LOCK to server...");
    let resp = client.lock_with_pin(pin).await?;
    println!(
        "Server is now {}. {} device(s) notified.",
        resp.state, resp.devices_notified
    );

    for volume in &config.volumes {
        let _ = veracrypt::dismount(&volume.mount_point);
    }

    println!("All local volumes dismounted.");
    Ok(())
}

fn detect_platform() -> picrypt_common::protocol::Platform {
    if cfg!(target_os = "macos") {
        picrypt_common::protocol::Platform::Macos
    } else if cfg!(target_os = "windows") {
        picrypt_common::protocol::Platform::Windows
    } else {
        picrypt_common::protocol::Platform::Linux
    }
}
