use std::sync::Arc;

use base64::Engine;
use reqwest::{Client, Response};
use tokio::net::TcpListener;
use uuid::Uuid;

use picrypt_server::api;
use picrypt_server::config::ServerConfig;
use picrypt_server::state::AppState;

/// A test server instance that binds to a random port and runs in the background.
///
/// Holds the `TempDir` so that it stays alive for the duration of the test.
/// When the struct is dropped, the tempdir is cleaned up.
#[allow(dead_code)]
pub struct TestServer {
    pub base_url: String,
    /// The raw base64 admin token string (same value stored in ServerConfig).
    pub admin_token: String,
    pub client: Client,
    // Hold the tempdir to prevent cleanup until the TestServer is dropped.
    _tempdir: tempfile::TempDir,
}

#[allow(dead_code)]
impl TestServer {
    /// Spin up a new test server with default settings.
    ///
    /// `admin_token_raw` is 32 random bytes that get base64-encoded and stored
    /// in the config. The same base64 string is what clients send as the Bearer token.
    ///
    /// `lock_pin` is an optional plaintext PIN for the lock endpoint.
    pub async fn start(admin_token_raw: &[u8; 32], lock_pin: Option<&str>) -> Self {
        let tempdir = tempfile::TempDir::new().expect("failed to create tempdir");
        let data_dir = tempdir.path().join("data");
        std::fs::create_dir_all(&data_dir).expect("failed to create data_dir");

        let b64 = base64::engine::general_purpose::STANDARD;
        let admin_token_b64 = b64.encode(admin_token_raw);

        let config = ServerConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            data_dir,
            dead_man_timeout_secs: 0, // Disable dead man's switch in tests.
            admin_token: Some(admin_token_b64.clone()),
            lock_pin: lock_pin.map(|s| s.to_string()),
            require_dual_factor: false,
        };

        let state = Arc::new(AppState::new(config).expect("failed to create AppState"));

        let router = api::router(state);

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind TcpListener");
        let addr = listener.local_addr().expect("failed to get local addr");

        tokio::spawn(async move {
            axum::serve(listener, router).await.expect("server crashed");
        });

        let client = Client::builder()
            .build()
            .expect("failed to build reqwest client");

        Self {
            base_url: format!("http://{addr}"),
            admin_token: admin_token_b64,
            client,
            _tempdir: tempdir,
        }
    }

    /// Convenience: start a server with a random admin token and no lock PIN.
    pub async fn start_default() -> Self {
        let mut token = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut token);
        Self::start(&token, None).await
    }

    /// Convenience: start a server with a random admin token and a lock PIN.
    pub async fn start_with_pin(pin: &str) -> Self {
        let mut token = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut token);
        Self::start(&token, Some(pin)).await
    }

    // -----------------------------------------------------------------------
    // Convenience request methods
    // -----------------------------------------------------------------------

    /// POST /unseal with the given password.
    pub async fn unseal(&self, password: &str) -> Response {
        self.client
            .post(format!("{}/unseal", self.base_url))
            .json(&serde_json::json!({ "password": password }))
            .send()
            .await
            .expect("unseal request failed")
    }

    /// POST /devices/register with the admin token.
    /// Returns (device_id, auth_token_b64, keyfile_b64).
    pub async fn register_device(&self, name: &str) -> (Uuid, String, String) {
        let resp = self
            .client
            .post(format!("{}/devices/register", self.base_url))
            .bearer_auth(&self.admin_token)
            .json(&serde_json::json!({
                "device_name": name,
                "platform": "linux"
            }))
            .send()
            .await
            .expect("register_device request failed");

        assert_eq!(
            resp.status().as_u16(),
            200,
            "register_device returned non-200: {}",
            resp.status()
        );

        let body: serde_json::Value = resp
            .json()
            .await
            .expect("failed to parse register response");
        let device_id = Uuid::parse_str(
            body["device_id"]
                .as_str()
                .expect("missing device_id in response"),
        )
        .expect("invalid device_id UUID");
        let auth_token = body["auth_token"]
            .as_str()
            .expect("missing auth_token in response")
            .to_string();
        let keyfile = body["keyfile"]
            .as_str()
            .expect("missing keyfile in response")
            .to_string();

        (device_id, auth_token, keyfile)
    }

    /// GET /key/{device_id} with the given bearer auth token (base64 string).
    pub async fn get_key(&self, device_id: Uuid, auth_token: &str) -> Response {
        self.client
            .get(format!("{}/key/{}", self.base_url, device_id))
            .bearer_auth(auth_token)
            .send()
            .await
            .expect("get_key request failed")
    }

    /// POST /lock with an optional PIN.
    pub async fn lock(&self, pin: Option<&str>) -> Response {
        let body = match pin {
            Some(p) => serde_json::json!({ "pin": p }),
            None => serde_json::json!({}),
        };
        self.client
            .post(format!("{}/lock", self.base_url))
            .json(&body)
            .send()
            .await
            .expect("lock request failed")
    }

    /// GET /heartbeat.
    pub async fn heartbeat(&self) -> Response {
        self.client
            .get(format!("{}/heartbeat", self.base_url))
            .send()
            .await
            .expect("heartbeat request failed")
    }

    /// POST /devices/{device_id}/revoke with the admin token.
    pub async fn revoke_device(&self, device_id: Uuid) -> Response {
        self.client
            .post(format!("{}/devices/{}/revoke", self.base_url, device_id))
            .bearer_auth(&self.admin_token)
            .send()
            .await
            .expect("revoke_device request failed")
    }

    /// POST /admin-token with the given master password.
    pub async fn get_admin_token(&self, password: &str) -> Response {
        self.client
            .post(format!("{}/admin-token", self.base_url))
            .json(&serde_json::json!({ "password": password }))
            .send()
            .await
            .expect("admin_token request failed")
    }

    // -----------------------------------------------------------------------
    // v0.1.7 dual-factor helpers
    // -----------------------------------------------------------------------

    /// GET /unseal/challenge — public endpoint, returns the server's
    /// stored YubiKey challenge hex and the dual-factor status flags.
    pub async fn get_unseal_challenge(&self) -> Response {
        self.client
            .get(format!("{}/unseal/challenge", self.base_url))
            .send()
            .await
            .expect("get_unseal_challenge request failed")
    }

    /// POST /admin/dual-factor/enroll with the admin token. Caller provides
    /// the current master password plus the hex challenge and response
    /// they've driven through their local YubiKey.
    pub async fn enroll_dual_factor(
        &self,
        password: &str,
        yubikey_challenge_hex: &str,
        yubikey_response_hex: &str,
    ) -> Response {
        self.client
            .post(format!("{}/admin/dual-factor/enroll", self.base_url))
            .bearer_auth(&self.admin_token)
            .json(&serde_json::json!({
                "password": password,
                "yubikey_challenge_hex": yubikey_challenge_hex,
                "yubikey_response_hex": yubikey_response_hex,
            }))
            .send()
            .await
            .expect("enroll_dual_factor request failed")
    }

    /// POST /admin/dual-factor/finalize with the admin token.
    pub async fn finalize_dual_factor(&self) -> Response {
        self.client
            .post(format!("{}/admin/dual-factor/finalize", self.base_url))
            .bearer_auth(&self.admin_token)
            .json(&serde_json::json!({}))
            .send()
            .await
            .expect("finalize_dual_factor request failed")
    }

    /// POST /unseal with password + client-supplied YubiKey response hex.
    pub async fn unseal_dual_factor(&self, password: &str, yubikey_response_hex: &str) -> Response {
        self.client
            .post(format!("{}/unseal", self.base_url))
            .json(&serde_json::json!({
                "password": password,
                "yubikey_response_hex": yubikey_response_hex,
            }))
            .send()
            .await
            .expect("unseal_dual_factor request failed")
    }
}
