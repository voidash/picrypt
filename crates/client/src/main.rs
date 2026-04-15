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

    /// Reveal the admin token by proving you know the master password.
    /// Lets the master password recover everything (i.e. you don't need to
    /// store the admin token separately). Reads the password from --password,
    /// from --password-file, or from stdin (so it works in shell pipes
    /// without leaking the password into argv / process listings).
    AdminToken {
        /// Master password (insecure — visible in `ps`. Prefer --password-file or stdin.)
        #[arg(long)]
        password: Option<String>,
        /// File containing the master password (e.g. ~/.fmw)
        #[arg(long)]
        password_file: Option<String>,
        /// Server URL override (default: server_url from client.toml)
        #[arg(long)]
        server_url: Option<String>,
    },

    /// Enroll the locally-attached YubiKey as a required second unseal
    /// factor on the picrypt-server. After a successful enroll, unseal
    /// requires BOTH the master password AND a touch of this YubiKey
    /// (or any other YubiKey programmed with the same HMAC-SHA1 secret).
    ///
    /// Requires admin token. Leaves the single-factor unseal path in
    /// place until you separately run `picrypt finalize-dual-factor`
    /// to commit — this gives you a rollback window if the new path
    /// is broken for any reason.
    EnrollDualFactor {
        /// Master password (insecure — visible in `ps`). Prefer
        /// --password-file or stdin.
        #[arg(long)]
        password: Option<String>,
        /// File containing the master password (e.g. ~/.fmw)
        #[arg(long)]
        password_file: Option<String>,
        /// Admin token (base64). Also honored via PICRYPT_ADMIN_TOKEN.
        #[arg(long, env = "PICRYPT_ADMIN_TOKEN")]
        admin_token: Option<String>,
        /// Server URL override (default: server_url from client.toml)
        #[arg(long)]
        server_url: Option<String>,
    },

    /// Permanently delete the single-factor master key blobs from the
    /// server. After this runs, dual-factor is the ONLY unseal path —
    /// you can't go back to single-factor without re-initializing the
    /// server from the recovery bundle. Run ONLY after you've verified
    /// dual-factor unseal works end-to-end.
    FinalizeDualFactor {
        /// Admin token (base64). Also honored via PICRYPT_ADMIN_TOKEN.
        #[arg(long, env = "PICRYPT_ADMIN_TOKEN")]
        admin_token: Option<String>,
        /// Server URL override (default: server_url from client.toml)
        #[arg(long)]
        server_url: Option<String>,
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
        Command::AdminToken {
            password,
            password_file,
            server_url,
        } => {
            cmd_admin_token(
                cli.config.as_deref(),
                password,
                password_file.as_deref(),
                server_url.as_deref(),
            )
            .await?;
        }
        Command::EnrollDualFactor {
            password,
            password_file,
            admin_token,
            server_url,
        } => {
            cmd_enroll_dual_factor(
                cli.config.as_deref(),
                password,
                password_file.as_deref(),
                admin_token.as_deref(),
                server_url.as_deref(),
            )
            .await?;
        }
        Command::FinalizeDualFactor {
            admin_token,
            server_url,
        } => {
            cmd_finalize_dual_factor(
                cli.config.as_deref(),
                admin_token.as_deref(),
                server_url.as_deref(),
            )
            .await?;
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
    use picrypt_common::{crypto, yubikey as yk};

    let client = connection::ServerClient::new(config)?;

    // v0.1.7: consult the challenge endpoint FIRST. If the server is
    // configured for dual-factor (either required or just available),
    // we drive the full dual-factor flow. A v0.1.6 server will 404 on
    // this endpoint, in which case we fall back to the legacy paths.
    let dual_factor_info = match client.unseal_challenge().await {
        Ok(info) => Some(info),
        Err(e) => {
            // Not a hard failure — a v0.1.6 server doesn't have this
            // endpoint. Just note it and fall through.
            tracing::debug!("GET /unseal/challenge failed (legacy server?): {e}");
            None
        }
    };

    if let Some(info) = dual_factor_info {
        if info.dual_factor_required || (info.dual_factor_available && !yubikey) {
            // Dual-factor path. `--yubikey` (legacy server-attached mode)
            // is mutually exclusive with this — if the user explicitly
            // asked for the legacy path and the server ALSO requires
            // dual-factor, it's a conflict.
            if yubikey {
                anyhow::bail!(
                    "--yubikey specifies server-attached YubiKey unseal, but this server \
                     is configured for client-held dual-factor unseal. Drop the --yubikey \
                     flag and re-run; your local YubiKey will be prompted automatically."
                );
            }

            // Decode the stored challenge.
            let challenge = crypto::hex_decode(&info.challenge_hex)
                .context("server returned invalid challenge hex")?;
            if challenge.is_empty() {
                anyhow::bail!(
                    "server advertises dual-factor but returned an empty challenge \
                     (missing yubikey_challenge.bin). Re-enroll via \
                     `picrypt enroll-dual-factor`."
                );
            }

            // Get the password (explicit arg or interactive prompt).
            let pw = match password {
                Some(pw) => pw,
                None => {
                    eprint!("Unseal password: ");
                    std::io::stderr().flush()?;
                    let mut pw = String::new();
                    std::io::stdin().read_line(&mut pw)?;
                    let pw = clean_password(&pw);
                    if pw.is_empty() {
                        anyhow::bail!("password cannot be empty");
                    }
                    pw
                }
            };

            // Sanity-check that ykchalresp is around before asking for a touch.
            if !yk::is_available() {
                anyhow::bail!(
                    "`ykchalresp` not found — install yubikey-personalization and \
                     plug in a YubiKey before retrying. The server requires dual-factor \
                     unseal and the client cannot compute the HMAC-SHA1 response without \
                     the local hardware."
                );
            }

            eprintln!("Touch your YubiKey to approve unseal...");
            let response = yk::challenge_response(&challenge).context(
                "YubiKey challenge-response failed — is a YubiKey plugged in \
                 with HMAC-SHA1 configured in slot 2?",
            )?;
            let response_hex = crypto::hex_encode(&response);

            let resp = client.unseal_dual_factor(&pw, &response_hex).await?;
            println!("Server unsealed successfully (dual-factor).");
            println!("  State: {}", resp.state);
            println!("  Devices: {}", resp.device_count);
            return Ok(());
        }
    }

    // Legacy / single-factor path (v0.1.6 server or v0.1.7 server with
    // dual-factor not yet enrolled).
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
            let pw = clean_password(&pw);
            if pw.is_empty() {
                anyhow::bail!("password cannot be empty");
            }
            client.unseal(&pw).await?
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

    // v0.1.9+: don't hard-fail when the server is sealed at startup. The
    // daemon handles sealed-at-boot by entering standby and auto-mounting
    // when the server transitions to Active (via the Unsealed WS broadcast
    // or the HTTP probe backstop). This lets systemd-managed clients like
    // omv's picrypt-unlock.service start before the daily unseal and wait
    // politely rather than exiting and triggering a restart loop.
    //
    // A warning is still logged so an interactive user running `picrypt
    // unlock` sees why their vault isn't mounting yet.
    match client.heartbeat().await {
        Ok(hb) if hb.state == picrypt_common::protocol::ServerState::Active => {
            tracing::info!("server is Active — mounting immediately");
        }
        Ok(hb) => {
            tracing::warn!(
                "server is {} — daemon will start in standby and auto-mount on unseal",
                hb.state
            );
            eprintln!(
                "Note: server is {}. Daemon will wait and auto-mount when you \
                 unseal the Pi.",
                hb.state
            );
        }
        Err(e) => {
            tracing::warn!(
                "initial heartbeat failed ({e}) — daemon will keep retrying"
            );
            eprintln!(
                "Note: server unreachable ({e}). Daemon will keep trying."
            );
        }
    }

    daemon::run(config, client).await
}

async fn cmd_lock(config: &ClientConfig) -> anyhow::Result<()> {
    config.require_registered()?;

    for vol in &config.volumes {
        match picrypt_client::volume::dismount(vol) {
            Ok(()) => println!("Dismounted: {}", vol.mount_point),
            Err(e) => eprintln!("Failed to dismount {}: {e}", vol.mount_point),
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

/// Aggressively normalize a password string read from a file or stdin.
///
/// Strips a leading UTF-8 BOM (some text editors prepend one) and then
/// `.trim()` removes ALL leading and trailing whitespace — spaces, tabs,
/// `\n`, `\r`, vertical tab, form feed, etc. This is the right behavior
/// for password files because:
///   - `echo > file` adds `\n`
///   - Windows editors add `\r\n`
///   - Some editors silently add a UTF-8 BOM
///   - Copy/paste sometimes adds trailing spaces
///
/// A password that genuinely starts or ends with whitespace would be
/// indistinguishable from these accidents and is bad practice anyway.
fn clean_password(raw: &str) -> String {
    raw.strip_prefix('\u{feff}').unwrap_or(raw).trim().to_string()
}

/// Read the master password from (in order): explicit --password,
/// --password-file, piped stdin (only if stdin is NOT a TTY). Mirrors
/// the logic in cmd_admin_token but factored out so the dual-factor
/// commands can share it.
fn resolve_master_password(
    password_arg: Option<String>,
    password_file: Option<&str>,
) -> anyhow::Result<String> {
    use std::io::IsTerminal;
    let password = if let Some(path) = password_file {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read password file {path}"))?;
        clean_password(&raw)
    } else if let Some(pw) = password_arg {
        pw
    } else if !std::io::stdin().is_terminal() {
        let mut buf = String::new();
        std::io::stdin()
            .read_line(&mut buf)
            .context("failed to read password from stdin")?;
        clean_password(&buf)
    } else {
        anyhow::bail!("no password provided. Use --password-file, --password, or pipe via stdin");
    };
    if password.is_empty() {
        anyhow::bail!("password is empty");
    }
    Ok(password)
}

/// Build a ServerClient from an explicit server URL + admin token,
/// bypassing any device-specific auth that might already be in the
/// client.toml. Used by the dual-factor enroll/finalize commands which
/// authenticate as admin, not as a registered device.
fn build_admin_client(
    server_url: &str,
    admin_token: &str,
) -> anyhow::Result<connection::ServerClient> {
    let cfg = picrypt_client::config::ClientConfig {
        loaded_from: None,
        server_url: server_url.trim_end_matches('/').to_string(),
        fallback_urls: vec![],
        device_id: None,
        auth_token: Some(admin_token.to_string()),
        heartbeat_timeout_secs: 60,
        heartbeat_interval_secs: 20,
        sleep_detection: false,
        volumes: vec![],
    };
    connection::ServerClient::new(&cfg)
}

async fn cmd_enroll_dual_factor(
    config_path: Option<&str>,
    password_arg: Option<String>,
    password_file: Option<&str>,
    admin_token_arg: Option<&str>,
    server_url_override: Option<&str>,
) -> anyhow::Result<()> {
    use picrypt_common::{crypto, yubikey};

    // Resolve server URL.
    let server_url = match server_url_override {
        Some(url) => url.to_string(),
        None => {
            let config = load_config(config_path)
                .context("no --server-url given and no client.toml found")?;
            config.server_url.clone()
        }
    };

    // Resolve admin token.
    let admin_token = admin_token_arg.ok_or_else(|| {
        anyhow::anyhow!(
            "no admin token provided. Use --admin-token or set PICRYPT_ADMIN_TOKEN. \
             (You can retrieve it via `picrypt admin-token --password-file <path>` \
             if you've lost it but still know the master password.)"
        )
    })?;

    // Resolve master password.
    let password = resolve_master_password(password_arg, password_file)?;

    // Sanity-check that a YubiKey is reachable before we bother the server.
    if !yubikey::is_available() {
        anyhow::bail!(
            "`ykchalresp` not found in PATH — install yubikey-personalization \
             (brew install ykpers on macOS, apt install yubikey-personalization on Linux) \
             and plug in a YubiKey with HMAC-SHA1 configured in slot 2 before retrying"
        );
    }

    // Generate a fresh 32-byte challenge and drive the local YubiKey.
    eprintln!("[1/3] generating 32-byte challenge...");
    let challenge = yubikey::generate_challenge();
    let challenge_hex = crypto::hex_encode(&challenge);
    eprintln!("      challenge: {challenge_hex}");

    eprintln!("[2/3] touch your YubiKey now (slot 2 HMAC-SHA1 challenge-response)...");
    let response = yubikey::challenge_response(&challenge).context(
        "YubiKey challenge-response failed — is a YubiKey plugged in \
         with HMAC-SHA1 configured in slot 2?",
    )?;
    let response_hex = crypto::hex_encode(&response);
    eprintln!("      response: 20 bytes received ({})", &response_hex[..8]);

    // POST to the enroll endpoint as admin.
    eprintln!("[3/3] POST /admin/dual-factor/enroll on {server_url}...");
    let client = build_admin_client(&server_url, admin_token)?;
    let resp = client
        .enroll_dual_factor(&password, &challenge_hex, &response_hex)
        .await
        .context("enroll request failed")?;

    println!();
    println!("dual-factor enrollment complete.");
    println!("  server state: {}", resp.state);
    if resp.single_factor_still_present {
        println!("  single-factor blob: still present (not yet finalized)");
        println!();
        println!("Next steps:");
        println!("  1. Test dual-factor unseal from a locked server:");
        println!("       picrypt lock              # panic-lock the server");
        println!("       picrypt unseal            # should prompt for both password + YubiKey");
        println!("  2. Once you've verified dual-factor unseal works, finalize:");
        println!("       picrypt finalize-dual-factor");
        println!("     This deletes the single-factor blobs permanently.");
    } else {
        println!("  single-factor blob: already gone (finalized)");
    }

    Ok(())
}

async fn cmd_finalize_dual_factor(
    config_path: Option<&str>,
    admin_token_arg: Option<&str>,
    server_url_override: Option<&str>,
) -> anyhow::Result<()> {
    // Resolve server URL.
    let server_url = match server_url_override {
        Some(url) => url.to_string(),
        None => {
            let config = load_config(config_path)
                .context("no --server-url given and no client.toml found")?;
            config.server_url.clone()
        }
    };

    let admin_token = admin_token_arg.ok_or_else(|| {
        anyhow::anyhow!("no admin token provided. Use --admin-token or set PICRYPT_ADMIN_TOKEN")
    })?;

    eprintln!("POST /admin/dual-factor/finalize on {server_url}...");
    eprintln!("WARNING: this deletes the single-factor master key blobs on the server.");
    eprintln!("         Dual-factor will be the ONLY unseal path after this runs.");
    eprintln!("         Make sure you have verified dual-factor unseal works first.");
    eprintln!();

    let client = build_admin_client(&server_url, admin_token)?;
    let resp = client
        .finalize_dual_factor()
        .await
        .context("finalize request failed")?;

    println!("finalize complete.");
    println!("  server state: {}", resp.state);
    println!(
        "  dual-factor only: {}",
        if resp.dual_factor_only { "YES" } else { "NO" }
    );
    if !resp.dual_factor_only {
        println!();
        println!("WARNING: server still has a single-factor unseal path available.");
        println!("         This is unexpected — inspect the server data dir directly.");
    }

    Ok(())
}

async fn cmd_admin_token(
    config_path: Option<&str>,
    password_arg: Option<String>,
    password_file: Option<&str>,
    server_url_override: Option<&str>,
) -> anyhow::Result<()> {
    use std::io::IsTerminal;

    // Resolve server URL — prefer the override, fall back to client.toml.
    let server_url = match server_url_override {
        Some(url) => url.to_string(),
        None => {
            let config = load_config(config_path)
                .context("no --server-url given and no client.toml found")?;
            config.server_url.clone()
        }
    };

    // Resolve password. Explicit flags always win — stdin is only consulted
    // as a fallback when no flag was given, and only if stdin is a pipe
    // (so an interactive shell doesn't block waiting for the user to type).
    //   1. --password-file
    //   2. --password
    //   3. piped stdin
    let password = if let Some(path) = password_file {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read password file {path}"))?;
        clean_password(&raw)
    } else if let Some(pw) = password_arg {
        pw
    } else if !std::io::stdin().is_terminal() {
        let mut buf = String::new();
        std::io::stdin()
            .read_line(&mut buf)
            .context("failed to read password from stdin")?;
        clean_password(&buf)
    } else {
        anyhow::bail!("no password provided. Use --password-file, --password, or pipe via stdin");
    };

    if password.is_empty() {
        anyhow::bail!("password is empty");
    }

    let url = format!("{}/admin-token", server_url.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("failed to build http client")?;

    let resp = client
        .post(&url)
        .json(&picrypt_common::protocol::AdminTokenRequest { password })
        .send()
        .await
        .context("failed to POST /admin-token")?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("/admin-token returned {status}: {body}");
    }

    let body: picrypt_common::protocol::AdminTokenResponse =
        resp.json().await.context("failed to parse response")?;

    // Pipe-friendly: print just the token to stdout, nothing else.
    // Suitable for `picrypt admin-token >> ~/.fmw` or `picrypt admin-token | pbcopy`.
    println!("{}", body.admin_token);

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

    for vol in &config.volumes {
        let _ = picrypt_client::volume::dismount(vol);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_password_strips_trailing_lf() {
        assert_eq!(clean_password("hunter2\n"), "hunter2");
    }

    #[test]
    fn clean_password_strips_trailing_crlf() {
        assert_eq!(clean_password("hunter2\r\n"), "hunter2");
    }

    #[test]
    fn clean_password_strips_multiple_trailing_newlines() {
        assert_eq!(clean_password("hunter2\n\n\n"), "hunter2");
    }

    #[test]
    fn clean_password_strips_leading_and_trailing_whitespace() {
        assert_eq!(clean_password("  hunter2  "), "hunter2");
        assert_eq!(clean_password("\thunter2\t"), "hunter2");
    }

    #[test]
    fn clean_password_strips_utf8_bom() {
        // \u{FEFF} = UTF-8 BOM; some editors prepend it silently.
        assert_eq!(clean_password("\u{feff}hunter2\n"), "hunter2");
    }

    #[test]
    fn clean_password_strips_utf8_bom_with_only_whitespace_after() {
        // BOM + trailing newline + nothing else = empty (caller bails out).
        assert_eq!(clean_password("\u{feff}\n"), "");
    }

    #[test]
    fn clean_password_preserves_internal_whitespace() {
        // Spaces inside the password must NOT be touched — they're part of
        // the secret, not formatting.
        assert_eq!(clean_password("  multi word pass  \n"), "multi word pass");
    }

    #[test]
    fn clean_password_no_change_for_already_clean() {
        assert_eq!(clean_password("hunter2"), "hunter2");
    }

    #[test]
    fn clean_password_empty_input() {
        assert_eq!(clean_password(""), "");
        assert_eq!(clean_password("   \n\r\t"), "");
    }
}
