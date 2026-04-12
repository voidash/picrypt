use std::path::PathBuf;

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// Top-level server configuration, loaded from `~/.picrypt/server.toml`.
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Address to listen on, e.g. "0.0.0.0:7123".
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,

    /// Directory for persistent data (encrypted keyfiles, device records).
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,

    /// Dead man's switch timeout in seconds. If no authorized activity occurs
    /// for this duration, the server auto-locks. 0 = disabled.
    /// Default: 86400 (24 hours).
    #[serde(default = "default_dead_man_timeout")]
    pub dead_man_timeout_secs: u64,

    /// Admin token for privileged operations (register, revoke, list devices).
    /// Base64-encoded 32-byte random value. Generated on first `POST /unseal`
    /// if not set. Required for device management endpoints.
    pub admin_token: Option<String>,

    /// Optional lock PIN. If set, `POST /lock` requires this PIN in the
    /// request body. If unset, lock is unauthenticated (for panic scenarios
    /// where any device on the network should be able to trigger lock).
    pub lock_pin: Option<String>,
}

impl ServerConfig {
    /// Load config from `~/.picrypt/server.toml`.
    /// Creates a default config file if none exists.
    pub fn load() -> anyhow::Result<Self> {
        let config_dir = config_dir()?;
        let config_path = config_dir.join("server.toml");

        if !config_path.exists() {
            let default = Self::default();
            std::fs::create_dir_all(&config_dir).context("failed to create config directory")?;
            let toml_str =
                toml::to_string_pretty(&default).context("failed to serialize default config")?;
            std::fs::write(&config_path, &toml_str).context(format!(
                "failed to write default config to {}",
                config_path.display()
            ))?;
            tracing::info!("created default config at {}", config_path.display());
            return Ok(default);
        }

        let contents = std::fs::read_to_string(&config_path).context(format!(
            "failed to read config from {}",
            config_path.display()
        ))?;
        let config: Self = toml::from_str(&contents).context("failed to parse server.toml")?;
        Ok(config)
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            data_dir: default_data_dir(),
            dead_man_timeout_secs: default_dead_man_timeout(),
            admin_token: None,
            lock_pin: None,
        }
    }
}

fn default_listen_addr() -> String {
    // Default to localhost — require explicit config for broader exposure.
    // Users should set to their Tailscale IP or 0.0.0.0 if intentional.
    "127.0.0.1:7123".to_string()
}

fn default_data_dir() -> PathBuf {
    config_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("data")
}

fn default_dead_man_timeout() -> u64 {
    86400 // 24 hours
}

fn config_dir() -> anyhow::Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".picrypt"))
}
