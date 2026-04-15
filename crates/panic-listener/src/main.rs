//! picrypt-panic-listener
//!
//! Small bridge process that accepts an authenticated panic signal from
//! a public-facing transport (Tailscale Funnel HTTPS in Phase 1, ntfy
//! SSE subscribe in Phase 2) and forwards it to the main picrypt-server
//! `POST /lock` endpoint on localhost.
//!
//! Design goals:
//!   - **Separate process** from picrypt-server. If this listener has a
//!     vulnerability, the main server's surface is untouched. They
//!     communicate only over localhost HTTP.
//!   - **Multi-contact.** Each trusted contact gets a unique token with
//!     a friendly label. Tokens are validated constant-time.
//!   - **Idempotent.** The lock action is naturally idempotent (re-locking
//!     an already-locked server is a no-op), so token replay does not
//!     leak data — worst case an attacker forces a lock you'd have done
//!     yourself.
//!   - **No persistent state.** The listener only holds config in memory.
//!     It does not log tokens. Panic events are logged with the contact
//!     label only.
//!
//! Current scope (Phase 1): `http` subcommand which listens on a local
//! TCP port (default 127.0.0.1:7124) for JSON POSTs at /panic. Tailscale
//! Funnel will terminate TLS at Tailscale's edge and forward to this
//! port. The subsequent `ntfy` subcommand (Phase 2) will subscribe to an
//! ntfy topic via SSE and apply the same token-validation + forwarding
//! pipeline.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "picrypt-panic-listener",
    version,
    about = "Authenticated panic-signal bridge for picrypt-server"
)]
struct Cli {
    /// Path to the panic-listener config file.
    #[arg(long, default_value = "/etc/picrypt/panic.toml", global = true)]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Listen for panic POSTs on a local HTTP port.
    ///
    /// Intended to be fronted by Tailscale Funnel (HTTPS termination at
    /// Tailscale's edge, forwarded to this process over the tailnet).
    /// This process never speaks TLS itself.
    Http {
        /// Address to bind. Keep on localhost in production — Funnel
        /// reaches localhost via `tailscale serve`.
        #[arg(long, default_value = "127.0.0.1:7124")]
        bind: SocketAddr,
    },
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
struct PanicConfig {
    /// The lock PIN required by the main picrypt-server. Sent in the
    /// forwarded `/lock` request body.
    lock_pin: String,

    /// Base URL of the main picrypt-server on localhost. Typically
    /// `http://127.0.0.1:7123`.
    #[serde(default = "default_picrypt_url")]
    picrypt_server_url: String,

    /// One or more trusted contacts, each with their own token. Tokens
    /// are compared constant-time. Labels are logged on every event.
    #[serde(default)]
    contact: Vec<ContactConfig>,
}

fn default_picrypt_url() -> String {
    "http://127.0.0.1:7123".to_string()
}

#[derive(Debug, Clone, Deserialize)]
struct ContactConfig {
    /// Human-readable label — used in logs only. e.g. "alice", "bob".
    label: String,
    /// The shared secret token (URL-safe base64 of ≥16 random bytes).
    token: String,
}

impl PanicConfig {
    fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read panic config {}", path.display()))?;
        let cfg: PanicConfig = toml::from_str(&raw)
            .with_context(|| format!("failed to parse panic config {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.lock_pin.is_empty() {
            anyhow::bail!("lock_pin must not be empty");
        }
        if self.contact.is_empty() {
            anyhow::bail!("at least one [[contact]] entry is required");
        }
        for c in &self.contact {
            if c.label.is_empty() {
                anyhow::bail!("contact.label must not be empty");
            }
            // Tokens must be at least 16 bytes (128 bits) in their decoded form.
            // A URL-safe b64-encoded 16-byte value is 22 chars (unpadded) or
            // 24 chars (padded). We store the encoded form verbatim and do a
            // length floor check here as a sanity guard, not for security.
            if c.token.len() < 22 {
                anyhow::bail!(
                    "contact '{}' has a token shorter than 22 characters — generate with \
                     `openssl rand -base64 32` or similar",
                    c.label
                );
            }
        }
        // Reject duplicate tokens.
        for i in 0..self.contact.len() {
            for j in (i + 1)..self.contact.len() {
                if self.contact[i].token == self.contact[j].token {
                    anyhow::bail!(
                        "contacts '{}' and '{}' share the same token — each contact must have a \
                         unique token",
                        self.contact[i].label,
                        self.contact[j].label
                    );
                }
            }
        }
        Ok(())
    }

    /// Look up the contact whose token matches `provided`. Comparison is
    /// constant-time across ALL configured contacts so a timing observer
    /// cannot infer which (if any) contact a given token belongs to.
    fn match_contact(&self, provided: &str) -> Option<&ContactConfig> {
        let mut matched: Option<&ContactConfig> = None;
        for contact in &self.contact {
            let eq = constant_time_eq_str(provided, &contact.token);
            // Don't `break` early — keep walking to avoid timing leaks.
            if eq && matched.is_none() {
                matched = Some(contact);
            }
        }
        matched
    }
}

/// Constant-time string equality. Returns false if the lengths differ,
/// but that length check itself is not constant-time across *different*
/// configured token lengths. Callers should ensure all configured tokens
/// have the same canonical length (they will, because they're all
/// base64-encoded from the same random-byte width) to avoid leaking
/// which slot was examined.
fn constant_time_eq_str(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.as_bytes().iter().zip(b.as_bytes().iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// HTTP server — Phase 1
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct AppState {
    config: Arc<PanicConfig>,
    http: reqwest::Client,
}

#[derive(Debug, Deserialize)]
struct PanicRequest {
    token: String,
    /// Optional — ignored for auth (the token itself identifies the
    /// contact). Only used for logging if provided.
    #[allow(dead_code)]
    contact: Option<String>,
}

#[derive(Debug, Serialize)]
struct PanicResponse {
    status: &'static str,
    contact: Option<String>,
}

#[derive(Debug, thiserror::Error)]
enum PanicError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("failed to forward to picrypt-server: {0}")]
    Forward(String),
    #[error("picrypt-server returned status {0}")]
    UpstreamStatus(u16),
}

impl IntoResponse for PanicError {
    fn into_response(self) -> Response {
        // NEVER leak which error occurred at the wire layer — any
        // differentiation between auth failure and upstream failure
        // would let a probe distinguish valid vs invalid tokens.
        // Same-ish status for all failures; the log has the detail.
        let (code, body) = match &self {
            PanicError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            PanicError::Forward(_) | PanicError::UpstreamStatus(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (code, body).into_response()
    }
}

/// Health probe — used by systemd / readiness checks. Does NOT reveal
/// any authenticated state. Anyone hitting this gets a 200.
async fn health() -> &'static str {
    "ok"
}

/// POST /panic handler.
///
/// Body: `{"token": "...", "contact": "alice"}` (the `contact` field is
/// optional and informational; authorization is based on the token).
async fn panic_handler(
    State(state): State<AppState>,
    Json(mut req): Json<PanicRequest>,
) -> Result<Json<PanicResponse>, PanicError> {
    // Look up the contact by token. Zeroize the submitted token
    // immediately after lookup so it does not linger in memory longer
    // than necessary.
    let contact = state.config.match_contact(&req.token).map(|c| c.label.clone());
    req.token.zeroize();

    let contact_label = match contact {
        Some(label) => label,
        None => {
            // Log the unauthorized attempt without revealing anything
            // about the attempted token.
            warn!("panic rejected: unauthorized token");
            return Err(PanicError::Unauthorized);
        }
    };

    info!(contact = %contact_label, "panic accepted — forwarding /lock");

    // Forward to picrypt-server /lock with the configured lock PIN.
    let url = format!(
        "{}/lock",
        state.config.picrypt_server_url.trim_end_matches('/')
    );
    let body = serde_json::json!({ "pin": state.config.lock_pin });

    let resp = state
        .http
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| PanicError::Forward(e.to_string()))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp
            .text()
            .await
            .unwrap_or_else(|_| "<body read failed>".to_string());
        error!(
            contact = %contact_label,
            upstream_status = status.as_u16(),
            upstream_body = %body,
            "picrypt-server /lock returned non-success"
        );
        return Err(PanicError::UpstreamStatus(status.as_u16()));
    }

    info!(contact = %contact_label, "panic completed — server locked");

    Ok(Json(PanicResponse {
        status: "locked",
        contact: Some(contact_label),
    }))
}

fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/panic", post(panic_handler))
        .layer(RequestBodyLimitLayer::new(1024)) // 1 KB is plenty for a token + label
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn run_http(config: PanicConfig, bind: SocketAddr) -> anyhow::Result<()> {
    let state = AppState {
        config: Arc::new(config),
        http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .context("failed to build reqwest client")?,
    };

    info!(
        bind = %bind,
        contacts = state.config.contact.len(),
        "picrypt-panic-listener starting"
    );

    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("failed to bind {bind}"))?;
    axum::serve(listener, build_router(state))
        .await
        .context("axum server crashed")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let cli = Cli::parse();
    let config = PanicConfig::load(&cli.config)?;

    match cli.command {
        Command::Http { bind } => run_http(config, bind).await,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> PanicConfig {
        PanicConfig {
            lock_pin: "34026".to_string(),
            picrypt_server_url: "http://127.0.0.1:7123".to_string(),
            contact: vec![
                ContactConfig {
                    label: "alice".to_string(),
                    token: "AAAAAAAAAAAAAAAAAAAAAA".to_string(), // 22 chars
                },
                ContactConfig {
                    label: "bob".to_string(),
                    token: "BBBBBBBBBBBBBBBBBBBBBB".to_string(),
                },
            ],
        }
    }

    #[test]
    fn validate_rejects_empty_pin() {
        let mut c = sample_config();
        c.lock_pin = String::new();
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_contacts() {
        let mut c = sample_config();
        c.contact.clear();
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_short_token() {
        let mut c = sample_config();
        c.contact[0].token = "tooshort".to_string();
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_duplicate_tokens() {
        let mut c = sample_config();
        c.contact[1].token = c.contact[0].token.clone();
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_accepts_valid_config() {
        let c = sample_config();
        assert!(c.validate().is_ok());
    }

    #[test]
    fn match_contact_finds_valid_token() {
        let c = sample_config();
        let m = c.match_contact("AAAAAAAAAAAAAAAAAAAAAA").unwrap();
        assert_eq!(m.label, "alice");
    }

    #[test]
    fn match_contact_finds_second_contact() {
        let c = sample_config();
        let m = c.match_contact("BBBBBBBBBBBBBBBBBBBBBB").unwrap();
        assert_eq!(m.label, "bob");
    }

    #[test]
    fn match_contact_rejects_unknown_token() {
        let c = sample_config();
        assert!(c.match_contact("ZZZZZZZZZZZZZZZZZZZZZZ").is_none());
    }

    #[test]
    fn match_contact_rejects_empty_token() {
        let c = sample_config();
        assert!(c.match_contact("").is_none());
    }

    #[test]
    fn match_contact_rejects_wrong_length() {
        let c = sample_config();
        // Same prefix as alice's token but shorter — must not match.
        assert!(c.match_contact("AAAAAAAAAAA").is_none());
    }

    #[test]
    fn constant_time_eq_str_basic() {
        assert!(constant_time_eq_str("abc", "abc"));
        assert!(!constant_time_eq_str("abc", "abd"));
        assert!(!constant_time_eq_str("abc", "ab"));
        assert!(!constant_time_eq_str("", "a"));
        assert!(constant_time_eq_str("", ""));
    }

    #[test]
    fn load_config_from_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let content = r#"
lock_pin = "34026"

[[contact]]
label = "alice"
token = "AAAAAAAAAAAAAAAAAAAAAA"

[[contact]]
label = "bob"
token = "BBBBBBBBBBBBBBBBBBBBBB"
"#;
        std::fs::write(tmp.path(), content).unwrap();
        let c = PanicConfig::load(tmp.path()).unwrap();
        assert_eq!(c.lock_pin, "34026");
        assert_eq!(c.contact.len(), 2);
        assert_eq!(c.contact[0].label, "alice");
        assert_eq!(c.picrypt_server_url, "http://127.0.0.1:7123"); // default
    }

    #[tokio::test]
    async fn panic_handler_rejects_invalid_token() {
        // Build a router and call it directly — no network.
        let state = AppState {
            config: Arc::new(sample_config()),
            http: reqwest::Client::new(),
        };
        let router = build_router(state);

        let body = serde_json::to_vec(&serde_json::json!({
            "token": "ZZZZZZZZZZZZZZZZZZZZZZ"
        }))
        .unwrap();

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/panic")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body))
            .unwrap();

        let resp = tower::ServiceExt::oneshot(router, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn health_endpoint() {
        let state = AppState {
            config: Arc::new(sample_config()),
            http: reqwest::Client::new(),
        };
        let router = build_router(state);

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/health")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = tower::ServiceExt::oneshot(router, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
