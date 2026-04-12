use anyhow::Context;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};

use picrypt_common::protocol::{
    HeartbeatResponse, KeyResponse, LockResponse, Platform, RegisterDeviceRequest,
    RegisterDeviceResponse, UnsealRequest, UnsealResponse,
};

use crate::config::ClientConfig;

/// HTTP client for communicating with the Pi key server.
/// Supports multiple server URLs with automatic failover.
pub struct ServerClient {
    http: reqwest::Client,
    /// Server URLs in priority order. Primary first, fallbacks after.
    server_urls: Vec<String>,
    auth_token: Option<String>,
}

impl ServerClient {
    pub fn new(config: &ClientConfig) -> anyhow::Result<Self> {
        let mut default_headers = HeaderMap::new();

        if let Some(ref token) = config.auth_token {
            let auth_value = format!("Bearer {token}");
            default_headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&auth_value).context("invalid auth token format")?,
            );
        }

        let http = reqwest::Client::builder()
            .default_headers(default_headers)
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .context("failed to create HTTP client")?;

        let server_urls: Vec<String> = config
            .all_server_urls()
            .iter()
            .map(|u| u.trim_end_matches('/').to_string())
            .collect();

        Ok(Self {
            http,
            server_urls,
            auth_token: config.auth_token.clone(),
        })
    }

    /// Get the auth token for WebSocket connections.
    pub fn auth_token(&self) -> Option<&str> {
        self.auth_token.as_deref()
    }

    /// All server URLs for WebSocket connection attempts.
    pub fn ws_urls(&self) -> Vec<String> {
        self.server_urls
            .iter()
            .map(|url| {
                let ws_base = url
                    .replace("http://", "ws://")
                    .replace("https://", "wss://");
                format!("{ws_base}/ws")
            })
            .collect()
    }

    // -----------------------------------------------------------------------
    // API methods with automatic failover
    // -----------------------------------------------------------------------

    /// GET /heartbeat — check server state. Tries all URLs in order.
    pub async fn heartbeat(&self) -> anyhow::Result<HeartbeatResponse> {
        self.get_json("/heartbeat").await
    }

    /// POST /unseal — unseal with password.
    pub async fn unseal(&self, password: &str) -> anyhow::Result<UnsealResponse> {
        let body = UnsealRequest {
            password: Some(password.to_string()),
            yubikey: false,
        };
        self.post_json("/unseal", &body).await
    }

    /// POST /unseal — unseal with YubiKey only.
    pub async fn unseal_yubikey(&self) -> anyhow::Result<UnsealResponse> {
        let body = UnsealRequest {
            password: None,
            yubikey: true,
        };
        self.post_json("/unseal", &body).await
    }

    /// POST /unseal — unseal with both password and YubiKey (first-time dual setup).
    pub async fn unseal_both(&self, password: &str) -> anyhow::Result<UnsealResponse> {
        let body = UnsealRequest {
            password: Some(password.to_string()),
            yubikey: true,
        };
        self.post_json("/unseal", &body).await
    }

    /// POST /lock — send panic lock signal. Sends to ALL servers (not just first).
    pub async fn lock(&self) -> anyhow::Result<LockResponse> {
        self.lock_with_pin(None).await
    }

    /// POST /lock with optional PIN.
    pub async fn lock_with_pin(&self, pin: Option<&str>) -> anyhow::Result<LockResponse> {
        let mut last_resp = None;
        let mut last_err = None;

        let body = match pin {
            Some(p) => serde_json::json!({"pin": p}),
            None => serde_json::json!({}),
        };

        // Lock ALL servers, not just the first reachable one.
        for url in &self.server_urls {
            let full_url = format!("{url}/lock");
            match self.http.post(&full_url).json(&body).send().await {
                Ok(resp) if resp.status().is_success() => {
                    if let Ok(parsed) = resp.json::<LockResponse>().await {
                        last_resp = Some(parsed);
                    }
                }
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    tracing::warn!("lock failed on {url}: HTTP {status}");
                }
                Err(e) => {
                    tracing::warn!("lock failed on {url}: {e}");
                    last_err = Some(e);
                }
            }
        }

        last_resp.ok_or_else(|| match last_err {
            Some(e) => anyhow::anyhow!("lock failed on all servers: {e}"),
            None => anyhow::anyhow!("lock failed on all servers"),
        })
    }

    /// GET /key/{device_id} — fetch keyfile.
    pub async fn get_key(&self, device_id: &uuid::Uuid) -> anyhow::Result<KeyResponse> {
        let path = format!("/key/{device_id}");
        self.get_json(&path).await
    }

    /// POST /devices/register — register a new device.
    pub async fn register_device(
        &self,
        name: &str,
        platform: Platform,
    ) -> anyhow::Result<RegisterDeviceResponse> {
        let body = RegisterDeviceRequest {
            device_name: name.to_string(),
            platform,
        };
        self.post_json("/devices/register", &body).await
    }

    // -----------------------------------------------------------------------
    // Internal helpers with failover
    // -----------------------------------------------------------------------

    async fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        let mut last_err = None;

        for url in &self.server_urls {
            let full_url = format!("{url}{path}");
            match self.http.get(&full_url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    return resp.json().await.context("failed to parse response");
                }
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let body = resp.text().await.unwrap_or_default();
                    last_err = Some(anyhow::anyhow!("HTTP {status}: {body}"));
                    // Don't failover on 4xx — the request itself is bad.
                    if (400..500).contains(&status) {
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!("request to {full_url} failed: {e}");
                    last_err = Some(anyhow::anyhow!("request failed: {e}"));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no server URLs configured")))
    }

    async fn post_json<B: serde::Serialize, T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> anyhow::Result<T> {
        let mut last_err = None;

        for url in &self.server_urls {
            let full_url = format!("{url}{path}");
            match self.http.post(&full_url).json(body).send().await {
                Ok(resp) if resp.status().is_success() => {
                    return resp.json().await.context("failed to parse response");
                }
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let body = resp.text().await.unwrap_or_default();
                    last_err = Some(anyhow::anyhow!("HTTP {status}: {body}"));
                    if (400..500).contains(&status) {
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!("request to {full_url} failed: {e}");
                    last_err = Some(anyhow::anyhow!("request failed: {e}"));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no server URLs configured")))
    }
}
