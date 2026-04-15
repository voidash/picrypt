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
///
/// Four valid shapes:
///
///   1. `password: Some(pw)`, `yubikey: false`, `yubikey_response_hex: None`
///      → legacy single-factor password unseal.
///
///   2. `password: None`, `yubikey: true`, `yubikey_response_hex: None`
///      → legacy single-factor YubiKey unseal, YubiKey physically attached
///      to the **server** (server runs `ykchalresp` locally).
///
///   3. `password: Some(pw)`, `yubikey: true`, `yubikey_response_hex: None`
///      → first-time-setup dual-enroll (both blobs written during init).
///      After init, this degrades to password-only unseal behavior on the
///      same endpoint — it does NOT enforce that both factors are required
///      on subsequent unseals. See `yubikey_response_hex` for that.
///
///   4. `password: Some(pw)`, `yubikey: false`, `yubikey_response_hex: Some(hex)`
///      → **dual-factor unseal (v0.1.7+)**. The client has physically
///      touched a YubiKey somewhere *other than* the server (typically
///      their laptop), computed the 20-byte HMAC-SHA1 response to the
///      server's stored challenge, and is sending the response hex as
///      part of the unseal request. The server combines the password-
///      derived key with the yubikey-response-derived key into a single
///      wrapping key and decrypts `encrypted_master_key_pw_yk.bin`. If
///      the server is configured with `require_dual_factor = true`, it
///      rejects shapes 1–3 entirely.
#[derive(Serialize, Deserialize)]
pub struct UnsealRequest {
    /// Password for unseal. If None and yubikey is true, uses YubiKey only.
    pub password: Option<String>,
    /// If true, server uses the attached YubiKey for challenge-response.
    /// Only meaningful when the YubiKey is physically attached to the
    /// server — leave false for the v0.1.7 dual-factor flow.
    #[serde(default)]
    pub yubikey: bool,
    /// Hex-encoded 20-byte HMAC-SHA1 response pre-computed by the client
    /// against the server's stored challenge. When this is present, the
    /// server takes the dual-factor unseal path: derive
    /// `combined_key = kdf(pw_key || yk_key)` and AES-GCM-decrypt the
    /// `encrypted_master_key_pw_yk.bin` blob. Mutually exclusive with
    /// `yubikey: true` — you're either asking the server to run
    /// `ykchalresp` itself (legacy) or you're bringing your own response
    /// (v0.1.7). Send one or the other, not both.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub yubikey_response_hex: Option<String>,
}

impl std::fmt::Debug for UnsealRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnsealRequest")
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("yubikey", &self.yubikey)
            .field(
                "yubikey_response_hex",
                &self.yubikey_response_hex.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Returned by `GET /unseal/challenge` — the client needs this to drive a
/// local YubiKey through HMAC-SHA1 challenge-response before POSTing a
/// dual-factor unseal request.
///
/// The challenge is NOT a secret — knowing it does not help an attacker
/// derive the response without the YubiKey's HMAC key. It can be served
/// unauthenticated; the server uses it as a public advertisement of "here
/// is the nonce I want you to sign." (In fact it has to be served, because
/// the client has no other way to discover it.)
///
/// If the server is still in single-factor mode (no dual-factor blob has
/// been enrolled yet) the response should report `dual_factor_available:
/// false` so the client can fall back to a password-only flow and produce
/// a clear error to the user instead of attempting to compute a response
/// against nothing.
#[derive(Debug, Serialize, Deserialize)]
pub struct UnsealChallengeResponse {
    /// Hex-encoded server-stored challenge (typically 32 bytes). The
    /// client feeds this to its local YubiKey via HMAC-SHA1 challenge-
    /// response and sends back the 20-byte response as
    /// `UnsealRequest.yubikey_response_hex`.
    ///
    /// Empty string when `dual_factor_available = false`.
    pub challenge_hex: String,
    /// True if the server has a dual-factor blob enrolled. When false,
    /// the client must fall back to single-factor (password-only) unseal.
    pub dual_factor_available: bool,
    /// True if the server is configured to REQUIRE dual-factor. When
    /// true, single-factor unseal attempts will be rejected with 400.
    pub dual_factor_required: bool,
}

/// Admin-authenticated request to enroll a dual-factor unseal on an
/// already-unsealed picrypt-server. The caller must provide the current
/// master password (not just the admin token) so that an admin-token-
/// only insider cannot silently rebind the second factor to a YubiKey
/// they control.
///
/// NOTE: Debug omitted to keep password and response hex out of logs.
#[derive(Serialize, Deserialize)]
pub struct EnrollDualFactorRequest {
    /// Current master password, used to verify the caller and to derive
    /// the password-side half of the new wrapping key.
    pub password: String,
    /// Hex-encoded 32-byte challenge the client sent to its local
    /// YubiKey. Stored on the server as `yubikey_challenge.bin` so
    /// subsequent unseal flows can retrieve it. The client picks the
    /// challenge (typically 32 random bytes).
    pub yubikey_challenge_hex: String,
    /// Hex-encoded 20-byte HMAC-SHA1 response from the client's YubiKey
    /// against `yubikey_challenge_hex`.
    pub yubikey_response_hex: String,
}

impl std::fmt::Debug for EnrollDualFactorRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollDualFactorRequest")
            .field("password", &"[REDACTED]")
            .field("yubikey_challenge_hex", &self.yubikey_challenge_hex)
            .field("yubikey_response_hex", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnrollDualFactorResponse {
    /// Current server state after enrollment (should be Active).
    pub state: ServerState,
    /// True if the single-factor blob still exists — i.e. you have not
    /// yet called `/admin/dual-factor/finalize`. Having both blobs is a
    /// temporary state that lets you verify the new dual-factor unseal
    /// works before permanently burning the old one.
    pub single_factor_still_present: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FinalizeDualFactorResponse {
    pub state: ServerState,
    /// Should always be true after a successful finalize.
    pub dual_factor_only: bool,
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
    /// The client keeps the WS connection alive after dismounting so it can
    /// receive a subsequent `Unsealed` message and re-mount without a manual
    /// `picrypt unlock` re-run.
    Lock,
    /// Server transitioned SEALED -> ACTIVE. Clients with dismounted volumes
    /// should re-fetch their keyfile via `GET /key/{device_id}` and remount.
    /// Added in v0.1.9. Pre-v0.1.9 clients ignore unknown variants and will
    /// instead re-mount on the next HTTP heartbeat probe.
    Unsealed,
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
            yubikey_response_hex: None,
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
    fn unseal_request_debug_redacts_yubikey_response() {
        let req = UnsealRequest {
            password: Some("pw".to_string()),
            yubikey: false,
            yubikey_response_hex: Some("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string()),
        };
        let debug_output = format!("{req:?}");
        assert!(
            !debug_output.contains("deadbeef"),
            "Debug output must NOT contain raw yubikey response hex, got: {debug_output}"
        );
        assert!(
            debug_output.contains("yubikey_response_hex") && debug_output.contains("[REDACTED]"),
            "Debug output must mark yubikey_response_hex as REDACTED, got: {debug_output}"
        );
    }

    #[test]
    fn unseal_request_serde_roundtrip_with_yk_response() {
        let req = UnsealRequest {
            password: Some("pw".to_string()),
            yubikey: false,
            yubikey_response_hex: Some("cafebabecafebabecafebabecafebabecafebabe".to_string()),
        };
        let json = serde_json::to_string(&req).expect("serialize");
        let back: UnsealRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.password, req.password);
        assert!(!back.yubikey);
        assert_eq!(back.yubikey_response_hex, req.yubikey_response_hex);
    }

    #[test]
    fn unseal_request_yk_response_omitted_when_none() {
        // skip_serializing_if = "Option::is_none" should mean the field
        // doesn't appear in the JSON at all when None. Legacy clients
        // that don't know about the field must still deserialize cleanly.
        let req = UnsealRequest {
            password: Some("pw".to_string()),
            yubikey: false,
            yubikey_response_hex: None,
        };
        let json = serde_json::to_string(&req).expect("serialize");
        assert!(
            !json.contains("yubikey_response_hex"),
            "None field must be omitted from JSON, got: {json}"
        );
    }

    #[test]
    fn unseal_request_legacy_deserialize_without_yk_response() {
        // Ensure an old v0.1.6 client's serialized UnsealRequest still
        // parses on a v0.1.7 server.
        let legacy_json = r#"{"password":"pw","yubikey":false}"#;
        let parsed: UnsealRequest = serde_json::from_str(legacy_json).expect("legacy deserialize");
        assert_eq!(parsed.password.as_deref(), Some("pw"));
        assert!(!parsed.yubikey);
        assert!(parsed.yubikey_response_hex.is_none());
    }

    #[test]
    fn unseal_challenge_response_serde_roundtrip() {
        let resp = UnsealChallengeResponse {
            challenge_hex: "ad7c1236c65101fb9740579f9e34c533e251ed11464346bed85d75e6ea1f0faa"
                .to_string(),
            dual_factor_available: true,
            dual_factor_required: true,
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        let back: UnsealChallengeResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.challenge_hex, resp.challenge_hex);
        assert_eq!(back.dual_factor_available, resp.dual_factor_available);
        assert_eq!(back.dual_factor_required, resp.dual_factor_required);
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
