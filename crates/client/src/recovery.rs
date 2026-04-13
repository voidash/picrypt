//! YubiKey disaster recovery — mount volumes when the Pi is dead.
//!
//! During device registration, the client can create a YubiKey-encrypted
//! backup of its keyfile. If the Pi is destroyed, the user plugs in a
//! YubiKey and uses this module to decrypt the backup and mount volumes.

use std::path::PathBuf;

use anyhow::Context;
use base64::Engine;
use zeroize::Zeroize;

use picrypt_common::crypto;
use picrypt_common::yubikey;

use crate::config::ClientConfig;

/// Create a YubiKey-encrypted backup of a keyfile.
///
/// Generates a new challenge, performs HMAC-SHA1 with the YubiKey,
/// derives a key from the response, encrypts the keyfile, and saves
/// the encrypted backup + challenge to disk.
pub fn create_backup(keyfile_b64: &str, backup_dir: &PathBuf) -> anyhow::Result<()> {
    if !yubikey::is_available() {
        anyhow::bail!(
            "ykchalresp not found — install yubikey-personalization to enable YubiKey backup"
        );
    }

    let keyfile_bytes = base64::engine::general_purpose::STANDARD
        .decode(keyfile_b64)
        .context("failed to decode keyfile from base64")?;

    // Generate a challenge for this backup.
    let challenge = yubikey::generate_challenge();

    // Get HMAC response and derive encryption key.
    println!("Touch your YubiKey...");
    let yk_key = yubikey::challenge_and_derive(&challenge)
        .context("YubiKey challenge-response failed — is a YubiKey connected?")?;

    // Encrypt the keyfile.
    let encrypted =
        crypto::encrypt(&keyfile_bytes, &yk_key).context("failed to encrypt keyfile for backup")?;

    // Save to disk.
    std::fs::create_dir_all(backup_dir).context(format!(
        "failed to create backup directory: {}",
        backup_dir.display()
    ))?;

    let challenge_path = backup_dir.join("yubikey_challenge.bin");
    let encrypted_path = backup_dir.join("keyfile_backup.enc");

    std::fs::write(&challenge_path, &challenge).context("failed to write YubiKey challenge")?;
    std::fs::write(&encrypted_path, &encrypted)
        .context("failed to write encrypted keyfile backup")?;

    println!("Backup created:");
    println!("  Challenge: {}", challenge_path.display());
    println!("  Encrypted keyfile: {}", encrypted_path.display());
    println!();
    println!("To recover, plug in the same YubiKey and run:");
    println!("  picrypt recover");

    Ok(())
}

/// Recover and mount volumes using a YubiKey-encrypted backup.
pub fn recover(config: &ClientConfig) -> anyhow::Result<()> {
    if !yubikey::is_available() {
        anyhow::bail!("ykchalresp not found — install yubikey-personalization");
    }

    let backup_dir = config.backup_dir();
    let challenge_path = backup_dir.join("yubikey_challenge.bin");
    let encrypted_path = backup_dir.join("keyfile_backup.enc");

    if !challenge_path.exists() || !encrypted_path.exists() {
        anyhow::bail!(
            "no YubiKey backup found in {}. Create one with `picrypt backup`.",
            backup_dir.display()
        );
    }

    let challenge = std::fs::read(&challenge_path).context("failed to read YubiKey challenge")?;
    let encrypted =
        std::fs::read(&encrypted_path).context("failed to read encrypted keyfile backup")?;

    println!("Touch your YubiKey to decrypt the backup...");
    let yk_key =
        yubikey::challenge_and_derive(&challenge).context("YubiKey challenge-response failed")?;

    let mut keyfile_bytes = crypto::decrypt(&encrypted, &yk_key)
        .context("failed to decrypt keyfile — wrong YubiKey or corrupted backup?")?;

    println!("Keyfile decrypted. Mounting volumes...");

    let mut mounted = 0;
    for vol in &config.volumes {
        match crate::volume::mount(vol, &keyfile_bytes) {
            Ok(()) => {
                println!("  Mounted: {} -> {}", vol.container, vol.mount_point);
                mounted += 1;
            }
            Err(e) => {
                eprintln!("  Failed: {} -> {}: {e}", vol.container, vol.mount_point);
            }
        }
    }

    keyfile_bytes.zeroize();

    if mounted == 0 && !config.volumes.is_empty() {
        anyhow::bail!("no volumes mounted — check your config");
    }

    println!("{mounted} volume(s) mounted via YubiKey recovery.");
    println!(
        "WARNING: No heartbeat daemon running — volumes will stay mounted until you manually lock."
    );
    Ok(())
}
