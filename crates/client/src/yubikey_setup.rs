//! YubiKey setup and management for picrypt.
//!
//! Handles programming HMAC-SHA1 into slot 2, creating backups,
//! and verifying YubiKey configuration.

use anyhow::Context;

use picrypt_common::yubikey;

/// Check if YubiKey tools are installed and a YubiKey is connected.
pub fn check_prerequisites() -> anyhow::Result<()> {
    if !yubikey::is_available() {
        anyhow::bail!(
            "ykchalresp not found. Install YubiKey tools:\n\
             \n\
             macOS:  brew install ykman\n\
             Linux:  sudo apt install yubikey-manager yubikey-personalization\n\
             Windows: choco install yubikey-manager"
        );
    }

    // Verify a YubiKey is connected by trying a version check.
    let output = std::process::Command::new("ykman").args(["info"]).output();

    match output {
        Ok(o) if o.status.success() => {
            let info = String::from_utf8_lossy(&o.stdout);
            println!("YubiKey detected:");
            for line in info.lines().take(5) {
                println!("  {line}");
            }
            Ok(())
        }
        _ => {
            anyhow::bail!("No YubiKey detected. Plug in your YubiKey and try again.");
        }
    }
}

/// Check if HMAC-SHA1 is already configured in slot 2.
pub fn is_slot2_configured() -> bool {
    // Try a test challenge. If it succeeds, slot 2 is configured.
    let output = std::process::Command::new("ykchalresp")
        .args(["-2", "-H", "0000000000000000"])
        .output();

    matches!(output, Ok(o) if o.status.success())
}

/// Program HMAC-SHA1 into slot 2 with a random secret.
/// Returns the hex-encoded secret (for programming a second YubiKey).
pub fn program_slot2() -> anyhow::Result<String> {
    // Generate 20-byte secret (HMAC-SHA1 key size).
    let mut secret_bytes = [0u8; 20];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut secret_bytes);
    let secret_hex = picrypt_common::crypto::hex_encode(&secret_bytes);

    println!("Programming HMAC-SHA1 into slot 2...");
    println!("Touch your YubiKey when it flashes.");

    let output = std::process::Command::new("ykman")
        .args(["otp", "chalresp", "--force", "--touch", "2", &secret_hex])
        .output()
        .context("failed to run ykman")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to program YubiKey: {}", stderr.trim());
    }

    Ok(secret_hex)
}

/// Program a SECOND YubiKey with the same secret.
pub fn program_second_key(secret_hex: &str) -> anyhow::Result<()> {
    println!("Programming second YubiKey with the same secret...");
    println!("Touch your YubiKey when it flashes.");

    let output = std::process::Command::new("ykman")
        .args(["otp", "chalresp", "--force", "--touch", "2", secret_hex])
        .output()
        .context("failed to run ykman")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to program second YubiKey: {}", stderr.trim());
    }

    Ok(())
}

/// Create a backup by fetching the keyfile from the server (not from CLI args).
pub async fn create_backup_from_server(config: &crate::config::ClientConfig) -> anyhow::Result<()> {
    config.require_registered()?;

    let device_id = config.device_id.unwrap();
    let client = crate::connection::ServerClient::new(config)?;

    // Check server is active.
    let hb = client.heartbeat().await?;
    if hb.state != picrypt_common::protocol::ServerState::Active {
        anyhow::bail!("server is {} — unseal the Pi first", hb.state);
    }

    // Fetch keyfile from server.
    println!("Fetching keyfile from server...");
    let key_resp = client.get_key(&device_id).await?;

    // Create backup using the fetched keyfile.
    let backup_dir = config.backup_dir();
    crate::recovery::create_backup(&key_resp.keyfile, &backup_dir)?;

    Ok(())
}
