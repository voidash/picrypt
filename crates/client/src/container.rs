//! Helper for creating VeraCrypt containers using the server-managed keyfile.

use anyhow::Context;
use base64::Engine;
use zeroize::Zeroize;

use crate::config::ClientConfig;
use crate::connection::ServerClient;
use crate::veracrypt;

/// Create a new VeraCrypt container.
///
/// Fetches the keyfile from the server, creates the container via the
/// VeraCrypt CLI, and optionally adds it to the client config.
pub async fn create(
    config: &ClientConfig,
    path: &str,
    size: &str,
    filesystem: &str,
    encryption: &str,
    hash: &str,
    mount_point: Option<&str>,
) -> anyhow::Result<()> {
    config.require_registered()?;

    let device_id = config.device_id.unwrap();
    let client = ServerClient::new(config)?;

    // Check server is active.
    let hb = client.heartbeat().await?;
    if hb.state != picrypt_common::protocol::ServerState::Active {
        anyhow::bail!("server is {} — unseal the Pi first", hb.state);
    }

    // Fetch keyfile.
    println!("Fetching keyfile from server...");
    let key_resp = client.get_key(&device_id).await?;
    let mut keyfile_b64 = key_resp.keyfile;
    let mut keyfile_bytes = base64::engine::general_purpose::STANDARD
        .decode(&keyfile_b64)
        .context("failed to decode keyfile")?;
    // Zeroize the base64 string immediately after decoding.
    // Safety: String's as_bytes_mut is safe for zeroing since we're about to drop it.
    unsafe {
        keyfile_b64.as_bytes_mut().zeroize();
    }
    drop(keyfile_b64);

    // Create the container.
    println!("Creating VeraCrypt container at {path} ({size})...");
    let result =
        veracrypt::create_container(path, size, filesystem, encryption, hash, &keyfile_bytes);
    keyfile_bytes.zeroize();
    result?;

    println!("Container created: {path}");

    // Optionally add to config.
    if let Some(mp) = mount_point {
        let mut config = config.clone();
        config.volumes.push(crate::config::VolumeConfig {
            container: path.to_string(),
            mount_point: mp.to_string(),
        });
        config.save()?;
        println!("Added to config: {path} -> {mp}");
    }

    println!();
    println!("Next: `picrypt unlock` to mount the container.");

    Ok(())
}
