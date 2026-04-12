use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Server state
// ---------------------------------------------------------------------------

/// The three states the key server can be in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerState {
    /// Boot / post-lock. Keyfiles encrypted on disk, not serving.
    Sealed,
    /// Keyfiles decrypted in memory, serving requests.
    Active,
    /// Panic transition — broadcasting dismount, purging memory.
    /// Short-lived: transitions to Sealed once complete.
    Locked,
}

impl std::fmt::Display for ServerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerState::Sealed => write!(f, "sealed"),
            ServerState::Active => write!(f, "active"),
            ServerState::Locked => write!(f, "locked"),
        }
    }
}

// ---------------------------------------------------------------------------
// Device
// ---------------------------------------------------------------------------

/// Platform a device runs on.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Macos,
    Linux,
    Windows,
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Platform::Macos => write!(f, "macos"),
            Platform::Linux => write!(f, "linux"),
            Platform::Windows => write!(f, "windows"),
        }
    }
}

/// Metadata for a registered device. Persisted in the server's data directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub id: Uuid,
    pub name: String,
    pub platform: Platform,
    /// Argon2 hash of the auth token — the raw token is never stored server-side.
    pub token_hash: Vec<u8>,
    /// The device's keyfile, encrypted with the master key (AES-256-GCM).
    pub encrypted_keyfile: Vec<u8>,
    /// Whether this device has been revoked.
    pub revoked: bool,
    pub registered_at: chrono::DateTime<chrono::Utc>,
}

// ---------------------------------------------------------------------------
// HTTP API — Requests
// ---------------------------------------------------------------------------

/// Unseal request — supports password, YubiKey, or both during init.
/// NOTE: Debug intentionally omitted to prevent password appearing in logs.
#[derive(Serialize, Deserialize)]
pub struct UnsealRequest {
    /// Password for unseal. If None and yubikey is true, uses YubiKey only.
    pub password: Option<String>,
    /// If true, server uses the attached YubiKey for challenge-response.
    #[serde(default)]
    pub yubikey: bool,
}

impl std::fmt::Debug for UnsealRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnsealRequest")
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("yubikey", &self.yubikey)
            .finish()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterDeviceRequest {
    pub device_name: String,
    pub platform: Platform,
}

/// Reveal the admin token to anyone who can prove they know the master
/// password. Lets the master password act as the single root secret —
/// you can recover the admin token (and via it, every device-management
/// operation) without storing it separately. Goes through the same rate
/// limiter as `/unseal` so brute force is no easier than guessing the
/// master password directly.
///
/// NOTE: Debug omitted to keep the password out of logs.
#[derive(Serialize, Deserialize)]
pub struct AdminTokenRequest {
    pub password: String,
}

impl std::fmt::Debug for AdminTokenRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminTokenRequest")
            .field("password", &"[REDACTED]")
            .finish()
    }
}

/// Lock request — optional PIN for authenticated lock.
#[derive(Debug, Serialize, Deserialize)]
pub struct LockRequest {
    /// If the server has a lock PIN configured, this must match it.
    #[serde(default)]
    pub pin: Option<String>,
}

// ---------------------------------------------------------------------------
// HTTP API — Responses
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub state: ServerState,
    pub timestamp: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UnsealResponse {
    pub state: ServerState,
    pub device_count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LockResponse {
    pub state: ServerState,
    pub devices_notified: usize,
}

/// NOTE: Debug intentionally redacts the token.
#[derive(Serialize, Deserialize)]
pub struct AdminTokenResponse {
    pub admin_token: String,
}

impl std::fmt::Debug for AdminTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminTokenResponse")
            .field("admin_token", &"[REDACTED]")
            .finish()
    }
}

/// NOTE: Debug intentionally redacts auth_token and keyfile.
#[derive(Serialize, Deserialize)]
pub struct RegisterDeviceResponse {
    pub device_id: Uuid,
    pub auth_token: String,
    pub keyfile: String,
}

/// NOTE: Debug intentionally redacts keyfile.
#[derive(Serialize, Deserialize)]
pub struct KeyResponse {
    pub keyfile: String,
}

impl std::fmt::Debug for KeyResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyResponse")
            .field("keyfile", &"[REDACTED]")
            .finish()
    }
}

impl std::fmt::Debug for RegisterDeviceResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterDeviceResponse")
            .field("device_id", &self.device_id)
            .field("auth_token", &"[REDACTED]")
            .field("keyfile", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceListEntry {
    pub id: Uuid,
    pub name: String,
    pub platform: Platform,
    pub revoked: bool,
    pub connected: bool,
    pub registered_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceListResponse {
    pub devices: Vec<DeviceListEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

// ---------------------------------------------------------------------------
// WebSocket messages
// ---------------------------------------------------------------------------

/// Messages sent from server to client over the WebSocket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsServerMessage {
    /// Panic lock — client must immediately dismount all volumes and purge keys.
    Lock,
    /// Acknowledgement of a client heartbeat.
    HeartbeatAck { timestamp: i64 },
    /// Server is shutting down gracefully — dismount.
    Shutdown,
}

/// Messages sent from client to server over the WebSocket.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsClientMessage {
    /// Periodic heartbeat.
    Heartbeat { device_id: Uuid },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_state_serde_roundtrip() {
        for state in [
            ServerState::Sealed,
            ServerState::Active,
            ServerState::Locked,
        ] {
            let json = serde_json::to_string(&state).expect("serialize failed");
            let deserialized: ServerState =
                serde_json::from_str(&json).expect("deserialize failed");
            assert_eq!(state, deserialized, "roundtrip failed for {state:?}");
        }
    }

    #[test]
    fn unseal_request_debug_redacts_password() {
        let req = UnsealRequest {
            password: Some("super-secret-password-123".to_string()),
            yubikey: false,
        };
        let debug_output = format!("{req:?}");
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug output must contain [REDACTED], got: {debug_output}"
        );
        assert!(
            !debug_output.contains("super-secret-password-123"),
            "Debug output must NOT contain actual password, got: {debug_output}"
        );
    }

    #[test]
    fn register_response_debug_redacts() {
        let resp = RegisterDeviceResponse {
            device_id: Uuid::new_v4(),
            auth_token: "dGhpcyBpcyBhIHNlY3JldCB0b2tlbg==".to_string(),
            keyfile: "c2VjcmV0IGtleWZpbGUgZGF0YQ==".to_string(),
        };
        let debug_output = format!("{resp:?}");
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug must contain [REDACTED], got: {debug_output}"
        );
        assert!(
            !debug_output.contains("dGhpcyBpcyBhIHNlY3JldCB0b2tlbg=="),
            "Debug must NOT contain raw auth token"
        );
        assert!(
            !debug_output.contains("c2VjcmV0IGtleWZpbGUgZGF0YQ=="),
            "Debug must NOT contain raw keyfile"
        );
    }

    #[test]
    fn key_response_debug_redacts() {
        let resp = KeyResponse {
            keyfile: "c2VjcmV0".to_string(),
        };
        let debug_output = format!("{resp:?}");
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug must contain [REDACTED], got: {debug_output}"
        );
        assert!(
            !debug_output.contains("c2VjcmV0"),
            "Debug must NOT contain raw keyfile data"
        );
    }

    #[test]
    fn ws_server_message_lock_format() {
        let msg = WsServerMessage::Lock;
        let json = serde_json::to_string(&msg).expect("serialize failed");
        assert_eq!(json, r#"{"type":"lock"}"#);
    }

    #[test]
    fn lock_request_default_pin_is_none() {
        let req: LockRequest = serde_json::from_str("{}").expect("deserialize failed");
        assert!(req.pin.is_none(), "pin should default to None when absent");
    }
}
