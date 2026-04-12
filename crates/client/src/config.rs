use std::path::PathBuf;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Client configuration, stored at `~/.picrypt/client.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Path this config was loaded from (not serialized).
    #[serde(skip)]
    pub loaded_from: Option<PathBuf>,

    /// Primary Pi key server URL (Tailscale, e.g. "http://100.64.0.5:7123").
    pub server_url: String,

    /// Fallback server URLs. Tried in order when the primary is unreachable.
    /// Can include LAN IPs, secondary Pi servers, etc.
    #[serde(default)]
    pub fallback_urls: Vec<String>,

    /// This device's UUID, assigned during registration.
    pub device_id: Option<Uuid>,

    /// Base64-encoded auth token.
    pub auth_token: Option<String>,

    /// Heartbeat timeout in seconds.
    #[serde(default = "default_heartbeat_timeout")]
    pub heartbeat_timeout_secs: u64,

    /// Heartbeat interval in seconds.
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_secs: u64,

    /// Enable platform-specific sleep detection hooks.
    #[serde(default = "default_true")]
    pub sleep_detection: bool,

    /// Volumes to manage.
    #[serde(default)]
    pub volumes: Vec<VolumeConfig>,
}

/// A single VeraCrypt volume to mount/dismount.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeConfig {
    /// Path to the `.hc` container file.
    pub container: String,
    /// Mount point (directory).
    pub mount_point: String,
}

impl ClientConfig {
    pub fn load() -> anyhow::Result<Self> {
        let path = Self::default_path()?;
        Self::load_from(path.to_str().unwrap_or("~/.picrypt/client.toml"))
    }

    pub fn load_from(path: &str) -> anyhow::Result<Self> {
        let contents =
            std::fs::read_to_string(path).context(format!("failed to read config from {path}"))?;
        let mut config: Self =
            toml::from_str(&contents).context(format!("failed to parse config from {path}"))?;
        config.loaded_from = Some(PathBuf::from(path));
        Ok(config)
    }

    pub fn create_default(server_url: &str) -> anyhow::Result<Self> {
        let config = Self {
            loaded_from: None,
            server_url: server_url.to_string(),
            fallback_urls: vec![],
            device_id: None,
            auth_token: None,
            heartbeat_timeout_secs: default_heartbeat_timeout(),
            heartbeat_interval_secs: default_heartbeat_interval(),
            sleep_detection: true,
            volumes: vec![],
        };

        let dir = config_dir()?;
        std::fs::create_dir_all(&dir)
            .context(format!("failed to create config dir: {}", dir.display()))?;

        config.save()?;
        Ok(config)
    }

    pub fn save(&self) -> anyhow::Result<()> {
        // Write to the path this config was loaded from, not the default.
        let path = self
            .loaded_from
            .clone()
            .or_else(|| Self::default_path().ok())
            .ok_or_else(|| anyhow::anyhow!("no config path available"))?;
        let contents = toml::to_string_pretty(self).context("failed to serialize config")?;
        std::fs::write(&path, &contents)
            .context(format!("failed to write config to {}", path.display()))?;
        // Set restrictive permissions on config (contains auth token).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            {
                tracing::warn!("failed to set 0600 on config — may be readable by others: {e}");
            }
        }
        Ok(())
    }

    pub fn config_path(&self) -> PathBuf {
        Self::default_path().unwrap_or_else(|_| PathBuf::from("client.toml"))
    }

    pub fn require_registered(&self) -> anyhow::Result<()> {
        if self.device_id.is_none() || self.auth_token.is_none() {
            anyhow::bail!("device not registered. Run `picrypt register --name <name>` first.");
        }
        Ok(())
    }

    /// Directory for YubiKey backup files.
    pub fn backup_dir(&self) -> PathBuf {
        config_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("backup")
    }

    /// All server URLs in priority order (primary first, then fallbacks).
    pub fn all_server_urls(&self) -> Vec<&str> {
        let mut urls: Vec<&str> = vec![&self.server_url];
        for url in &self.fallback_urls {
            urls.push(url);
        }
        urls
    }

    fn default_path() -> anyhow::Result<PathBuf> {
        Ok(config_dir()?.join("client.toml"))
    }
}

fn config_dir() -> anyhow::Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".picrypt"))
}

fn default_heartbeat_timeout() -> u64 {
    120 // 2 minutes
}

fn default_heartbeat_interval() -> u64 {
    30 // 30 seconds
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_roundtrip_toml() {
        let config = ClientConfig {
            loaded_from: None,
            server_url: "http://100.64.0.5:7123".to_string(),
            fallback_urls: vec![
                "http://192.168.1.50:7123".to_string(),
                "http://10.0.0.2:7123".to_string(),
            ],
            device_id: Some(Uuid::new_v4()),
            auth_token: Some("dGVzdC10b2tlbg==".to_string()),
            heartbeat_timeout_secs: 60,
            heartbeat_interval_secs: 15,
            sleep_detection: false,
            volumes: vec![VolumeConfig {
                container: "/mnt/vault.hc".to_string(),
                mount_point: "/mnt/secure".to_string(),
            }],
        };

        let toml_str = toml::to_string_pretty(&config).expect("serialize failed");
        let deserialized: ClientConfig = toml::from_str(&toml_str).expect("deserialize failed");

        assert_eq!(deserialized.server_url, config.server_url);
        assert_eq!(deserialized.fallback_urls, config.fallback_urls);
        assert_eq!(deserialized.device_id, config.device_id);
        assert_eq!(deserialized.auth_token, config.auth_token);
        assert_eq!(
            deserialized.heartbeat_timeout_secs,
            config.heartbeat_timeout_secs
        );
        assert_eq!(
            deserialized.heartbeat_interval_secs,
            config.heartbeat_interval_secs
        );
        assert_eq!(deserialized.sleep_detection, config.sleep_detection);
        assert_eq!(deserialized.volumes.len(), 1);
        assert_eq!(deserialized.volumes[0].container, "/mnt/vault.hc");
        assert_eq!(deserialized.volumes[0].mount_point, "/mnt/secure");
    }

    #[test]
    fn all_server_urls_ordering() {
        let config = ClientConfig {
            loaded_from: None,
            server_url: "http://primary:7123".to_string(),
            fallback_urls: vec![
                "http://fallback-1:7123".to_string(),
                "http://fallback-2:7123".to_string(),
            ],
            device_id: None,
            auth_token: None,
            heartbeat_timeout_secs: 120,
            heartbeat_interval_secs: 30,
            sleep_detection: true,
            volumes: vec![],
        };

        let urls = config.all_server_urls();
        assert_eq!(urls.len(), 3);
        assert_eq!(urls[0], "http://primary:7123", "primary must be first");
        assert_eq!(urls[1], "http://fallback-1:7123");
        assert_eq!(urls[2], "http://fallback-2:7123");
    }

    #[test]
    fn require_registered_fails_when_missing() {
        let config = ClientConfig {
            loaded_from: None,
            server_url: "http://localhost:7123".to_string(),
            fallback_urls: vec![],
            device_id: None,
            auth_token: None,
            heartbeat_timeout_secs: 120,
            heartbeat_interval_secs: 30,
            sleep_detection: true,
            volumes: vec![],
        };

        let result = config.require_registered();
        assert!(result.is_err(), "should fail when device_id is None");

        // Also fail when only one of the two is set.
        let config_partial = ClientConfig {
            device_id: Some(Uuid::new_v4()),
            auth_token: None,
            ..config
        };
        assert!(
            config_partial.require_registered().is_err(),
            "should fail when auth_token is None"
        );
    }

    #[test]
    fn require_registered_succeeds() {
        let config = ClientConfig {
            loaded_from: None,
            server_url: "http://localhost:7123".to_string(),
            fallback_urls: vec![],
            device_id: Some(Uuid::new_v4()),
            auth_token: Some("dG9rZW4=".to_string()),
            heartbeat_timeout_secs: 120,
            heartbeat_interval_secs: 30,
            sleep_detection: true,
            volumes: vec![],
        };

        assert!(
            config.require_registered().is_ok(),
            "should succeed when both device_id and auth_token are set"
        );
    }
}
