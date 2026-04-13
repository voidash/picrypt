use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use std::sync::atomic::{AtomicU32, AtomicU64};

use base64::Engine;
use tokio::sync::{broadcast, Mutex, RwLock};
use uuid::Uuid;
use zeroize::Zeroize;

use picrypt_common::crypto::{self, MasterKey};
use picrypt_common::protocol::{DeviceRecord, Platform, ServerState, WsServerMessage};
use picrypt_common::yubikey;

use crate::config::ServerConfig;
use crate::error::ApiError;
use crate::keystore::KeyStore;

/// Capacity of the broadcast channel for lock signals to WebSocket clients.
const BROADCAST_CAPACITY: usize = 64;

/// Maximum failed unseal attempts before temporary lockout.
const MAX_UNSEAL_ATTEMPTS: u32 = 5;
/// Base backoff in seconds. Actual delay = base * 2^(attempts - MAX).
const UNSEAL_BACKOFF_BASE_SECS: u64 = 5;

/// Shared application state, wrapped in `Arc` and passed to all handlers.
pub struct AppState {
    pub config: ServerConfig,
    /// Current server state.
    state: RwLock<ServerState>,
    /// Serializes state transitions (unseal, lock, initialize).
    /// Any operation that changes `state`, `master_key`, or `decrypted_keyfiles`
    /// must hold this mutex for the entire transition.
    transition_mutex: Mutex<()>,
    /// Device records loaded from disk. Present regardless of server state.
    devices: RwLock<HashMap<Uuid, DeviceRecord>>,
    /// Decrypted keyfiles, indexed by device ID. Only populated when ACTIVE.
    pub(crate) decrypted_keyfiles: RwLock<HashMap<Uuid, Vec<u8>>>,
    /// The master key, only present when ACTIVE.
    pub(crate) master_key: RwLock<Option<MasterKey>>,
    /// Broadcast channel for sending lock/shutdown signals to all WS clients.
    lock_tx: broadcast::Sender<WsServerMessage>,
    /// Persistent storage backend.
    keystore: KeyStore,
    /// KDF parameters for password-based master key derivation.
    kdf_params: RwLock<Option<crypto::KeyDerivationParams>>,
    /// Set of currently connected WebSocket device IDs.
    connected_devices: RwLock<HashMap<Uuid, ()>>,
    /// Unix timestamp of the last authorized activity.
    last_activity: AtomicI64,
    /// Generated admin token (if auto-generated on first unseal).
    generated_admin_token: RwLock<Option<String>>,
    /// Admin token loaded from `{data_dir}/admin_token.txt` at startup.
    file_backed_admin_token: RwLock<Option<String>>,
    /// Pre-computed hash of the lock PIN (if configured). Computed once at
    /// startup to avoid Argon2 work on every /lock request.
    lock_pin_hash: Option<[u8; 32]>,
    /// Unseal rate limiting: consecutive failed attempts.
    unseal_failed_attempts: AtomicU32,
    /// Unseal rate limiting: unix timestamp when lockout expires.
    unseal_lockout_until: AtomicU64,
}

impl AppState {
    pub fn new(config: ServerConfig) -> anyhow::Result<Self> {
        let keystore = KeyStore::new(&config.data_dir)
            .map_err(|e| anyhow::anyhow!("failed to initialize keystore: {e}"))?;

        let devices = keystore
            .load_all_devices()
            .map_err(|e| anyhow::anyhow!("failed to load device records: {e}"))?;

        let kdf_params = keystore
            .load_kdf_params()
            .map_err(|e| anyhow::anyhow!("failed to load KDF params: {e}"))?;

        let (lock_tx, _) = broadcast::channel(BROADCAST_CAPACITY);

        // Load file-backed admin token if config doesn't have one set.
        let file_backed_admin_token = if config.admin_token.is_none() {
            let token_path = config.data_dir.join("admin_token.txt");
            match std::fs::read_to_string(&token_path) {
                Ok(contents) => {
                    let trimmed = contents.trim().to_string();
                    if trimmed.is_empty() {
                        None
                    } else {
                        tracing::info!("loaded admin token from {}", token_path.display());
                        Some(trimmed)
                    }
                }
                Err(_) => None,
            }
        } else {
            None
        };

        // Pre-hash the lock PIN at startup (if configured).
        // MUST NOT silently degrade to None — that disables PIN auth entirely.
        let lock_pin_hash = match &config.lock_pin {
            Some(pin) => {
                let hash = crypto::derive_key_fast(pin.as_bytes(), b"picrypt-pin-compare")
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "failed to hash lock PIN — refusing to start with broken PIN auth: {e}"
                        )
                    })?;
                Some(hash)
            }
            None => None,
        };

        Ok(Self {
            config,
            state: RwLock::new(ServerState::Sealed),
            transition_mutex: Mutex::new(()),
            devices: RwLock::new(devices),
            decrypted_keyfiles: RwLock::new(HashMap::new()),
            master_key: RwLock::new(None),
            lock_tx,
            keystore,
            kdf_params: RwLock::new(kdf_params),
            connected_devices: RwLock::new(HashMap::new()),
            last_activity: AtomicI64::new(chrono::Utc::now().timestamp()),
            generated_admin_token: RwLock::new(None),
            file_backed_admin_token: RwLock::new(file_backed_admin_token),
            lock_pin_hash,
            unseal_failed_attempts: AtomicU32::new(0),
            unseal_lockout_until: AtomicU64::new(0),
        })
    }

    // -----------------------------------------------------------------------
    // State queries
    // -----------------------------------------------------------------------

    pub async fn current_state(&self) -> ServerState {
        *self.state.read().await
    }

    pub async fn require_active(&self) -> Result<(), ApiError> {
        match *self.state.read().await {
            ServerState::Active => Ok(()),
            ServerState::Sealed => Err(ApiError::Sealed),
            ServerState::Locked => Err(ApiError::Locked),
        }
    }

    pub fn subscribe_lock(&self) -> broadcast::Receiver<WsServerMessage> {
        self.lock_tx.subscribe()
    }

    /// Record an authorized activity (resets the dead man's switch timer).
    pub fn touch_activity(&self) {
        self.last_activity
            .store(chrono::Utc::now().timestamp(), Ordering::Relaxed);
    }

    /// Seconds since the last authorized activity.
    pub fn idle_seconds(&self) -> i64 {
        let last = self.last_activity.load(Ordering::Relaxed);
        chrono::Utc::now().timestamp() - last
    }

    /// Get the admin token (base64-decoded bytes).
    /// Priority: config -> file-backed token -> in-memory generated token.
    pub async fn admin_token(&self) -> Option<Vec<u8>> {
        // 1. Try configured token first.
        if let Some(ref t) = self.config.admin_token {
            if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(t) {
                return Some(bytes);
            }
        }
        // 2. Try file-backed token (loaded at startup or saved during activation).
        {
            let file_token = self.file_backed_admin_token.read().await;
            if let Some(ref t) = *file_token {
                if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(t) {
                    return Some(bytes);
                }
            }
        }
        // 3. Fall back to in-memory auto-generated token.
        let gen = self.generated_admin_token.read().await;
        gen.as_ref()
            .and_then(|t| base64::engine::general_purpose::STANDARD.decode(t).ok())
    }

    /// Validate a lock PIN. Returns Ok if no PIN configured or PIN matches.
    /// The expected PIN is hashed once at construction (via `lock_pin_hash`),
    /// and we only hash the provided PIN — one Argon2 call, not two.
    /// This prevents both length leakage and CPU amplification on wrong PINs.
    pub fn validate_lock_pin(&self, provided: Option<&str>) -> Result<(), ApiError> {
        let expected_hash = match &self.lock_pin_hash {
            None => return Ok(()), // No PIN configured.
            Some(h) => h,
        };
        let pin =
            provided.ok_or_else(|| ApiError::Unauthorized("lock PIN required".to_string()))?;
        let provided_hash = crypto::derive_key_fast(pin.as_bytes(), b"picrypt-pin-compare")
            .map_err(|e| ApiError::Internal(e.to_string()))?;

        let mut diff = 0u8;
        for (a, b) in expected_hash.iter().zip(provided_hash.iter()) {
            diff |= a ^ b;
        }
        if diff != 0 {
            return Err(ApiError::Unauthorized("invalid lock PIN".to_string()));
        }
        Ok(())
    }

    /// Check unseal rate limiting. Returns Err with retry-after seconds if locked out.
    fn check_unseal_rate_limit(&self) -> Result<(), ApiError> {
        let lockout_until = self.unseal_lockout_until.load(Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp() as u64;
        if now < lockout_until {
            let wait = lockout_until - now;
            return Err(ApiError::Internal(format!(
                "too many failed unseal attempts — retry in {wait}s"
            )));
        }
        Ok(())
    }

    /// Record a failed unseal attempt. Applies exponential backoff.
    fn record_unseal_failure(&self) {
        let attempts = self.unseal_failed_attempts.fetch_add(1, Ordering::Relaxed) + 1;
        if attempts >= MAX_UNSEAL_ATTEMPTS {
            let exponent = attempts - MAX_UNSEAL_ATTEMPTS;
            let backoff_secs = UNSEAL_BACKOFF_BASE_SECS.saturating_mul(1u64 << exponent.min(10));
            let lockout_until = chrono::Utc::now().timestamp() as u64 + backoff_secs;
            self.unseal_lockout_until
                .store(lockout_until, Ordering::Relaxed);
            tracing::warn!("unseal rate limit: {attempts} failures, locked for {backoff_secs}s");
        }
    }

    /// Reset unseal rate limiting (on successful unseal).
    fn reset_unseal_rate_limit(&self) {
        self.unseal_failed_attempts.store(0, Ordering::Relaxed);
        self.unseal_lockout_until.store(0, Ordering::Relaxed);
    }

    // -----------------------------------------------------------------------
    // Initialization (first-time setup)
    // -----------------------------------------------------------------------

    /// Initialize the server with one or both unseal methods.
    ///
    /// Generates a random master key and encrypts it with:
    /// - The password (via Argon2id) if `password` is Some
    /// - The YubiKey HMAC response if `use_yubikey` is true
    ///
    /// At least one method must be provided.
    pub async fn initialize(
        &self,
        password: Option<&str>,
        use_yubikey: bool,
    ) -> Result<(), ApiError> {
        if self.keystore.is_initialized() {
            return Err(ApiError::Internal(
                "server already initialized — use unseal instead".to_string(),
            ));
        }

        if password.is_none() && !use_yubikey {
            return Err(ApiError::Internal(
                "must provide at least one unseal method (password or yubikey)".to_string(),
            ));
        }

        let master_key = MasterKey::generate();

        // Phase 1: Prepare all encrypted material in memory BEFORE writing
        // anything to disk. This ensures atomicity — if YubiKey fails after
        // password encryption, nothing is persisted.
        let mut pw_data: Option<(crypto::KeyDerivationParams, Vec<u8>)> = None;
        let mut yk_data: Option<(Vec<u8>, Vec<u8>)> = None;

        if let Some(pw) = password {
            let params = crypto::KeyDerivationParams::generate();
            let pw_key = crypto::derive_master_key(pw.as_bytes(), &params)
                .map_err(|e| ApiError::Internal(format!("password key derivation failed: {e}")))?;
            let encrypted = crypto::encrypt(master_key.as_bytes(), pw_key.as_bytes())
                .map_err(|e| ApiError::Internal(format!("master key encryption failed: {e}")))?;
            pw_data = Some((params, encrypted));
        }

        if use_yubikey {
            let challenge = yubikey::generate_challenge();
            let yk_key = yubikey::challenge_and_derive(&challenge)
                .map_err(|e| ApiError::Internal(format!("YubiKey challenge failed: {e}")))?;
            let encrypted = crypto::encrypt(master_key.as_bytes(), &yk_key).map_err(|e| {
                ApiError::Internal(format!("master key encryption (yk) failed: {e}"))
            })?;
            yk_data = Some((challenge, encrypted));
        }

        // Phase 2: All crypto succeeded — now persist to disk.
        if let Some((params, encrypted)) = pw_data {
            self.keystore
                .save_kdf_params(&params)
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            self.keystore
                .save_encrypted_master_key_password(&encrypted)
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            *self.kdf_params.write().await = Some(params);
            tracing::info!("password-based unseal configured");
        }

        if let Some((challenge, encrypted)) = yk_data {
            self.keystore
                .save_yubikey_challenge(&challenge)
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            self.keystore
                .save_encrypted_master_key_yubikey(&encrypted)
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            tracing::info!("YubiKey-based unseal configured");
        }

        // Phase 3: Activate — uses the same path as subsequent unseals,
        // which also handles admin token auto-generation.
        self.activate_with_master_key(master_key).await?;

        tracing::info!("server initialized and unsealed");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Unseal: SEALED -> ACTIVE
    // -----------------------------------------------------------------------

    /// Unseal with a password. Holds the transition mutex for the entire operation.
    pub async fn unseal_password(&self, password: &str) -> Result<usize, ApiError> {
        self.check_unseal_rate_limit()?;
        let _guard = self.transition_mutex.lock().await;
        self.check_not_active().await?;

        // First-time setup: no encrypted master key yet.
        if !self.keystore.is_initialized() {
            let result = self.initialize(Some(password), false).await;
            if result.is_ok() {
                self.reset_unseal_rate_limit();
            }
            return result.map(|_| 0);
        }

        self.unseal_password_inner(password).await
    }

    /// Internal password unseal logic. Caller MUST hold the transition mutex.
    async fn unseal_password_inner(&self, password: &str) -> Result<usize, ApiError> {
        let encrypted_mk = self
            .keystore
            .load_encrypted_master_key_password()
            .map_err(|e| ApiError::Internal(e.to_string()))?
            .ok_or(ApiError::Internal(
                "password-based unseal not configured for this server".to_string(),
            ))?;

        let params = self
            .kdf_params
            .read()
            .await
            .clone()
            .ok_or_else(|| ApiError::Internal("KDF params missing".to_string()))?;

        let pw_key = crypto::derive_master_key(password.as_bytes(), &params)
            .map_err(|e| ApiError::Internal(format!("key derivation failed: {e}")))?;

        let mut mk_bytes = match crypto::decrypt(&encrypted_mk, pw_key.as_bytes()) {
            Ok(bytes) => bytes,
            Err(_) => {
                self.record_unseal_failure();
                return Err(ApiError::InvalidPassword);
            }
        };

        if mk_bytes.len() != 32 {
            mk_bytes.zeroize();
            return Err(ApiError::Internal(
                "decrypted master key has wrong size".to_string(),
            ));
        }

        let mut mk_array = [0u8; 32];
        mk_array.copy_from_slice(&mk_bytes);
        mk_bytes.zeroize();
        let master_key = MasterKey::from_bytes(mk_array);
        mk_array.zeroize();

        self.activate_with_master_key(master_key).await
    }

    /// Unseal with a YubiKey (must be physically connected to the Pi).
    pub async fn unseal_yubikey(&self) -> Result<usize, ApiError> {
        let _guard = self.transition_mutex.lock().await;
        self.check_not_active().await?;

        // First-time setup.
        if !self.keystore.is_initialized() {
            self.initialize(None, true).await?;
            return Ok(0);
        }

        let encrypted_mk = self
            .keystore
            .load_encrypted_master_key_yubikey()
            .map_err(|e| ApiError::Internal(e.to_string()))?
            .ok_or(ApiError::Internal(
                "YubiKey-based unseal not configured for this server".to_string(),
            ))?;

        let challenge = self
            .keystore
            .load_yubikey_challenge()
            .map_err(|e| ApiError::Internal(e.to_string()))?
            .ok_or(ApiError::Internal(
                "YubiKey challenge not found".to_string(),
            ))?;

        let mut yk_key = yubikey::challenge_and_derive(&challenge)
            .map_err(|e| ApiError::Internal(format!("YubiKey challenge-response failed: {e}")))?;

        let decrypt_result = crypto::decrypt(&encrypted_mk, &yk_key);
        yk_key.zeroize(); // Zeroize the YubiKey-derived key immediately after use.

        let mut mk_bytes = decrypt_result.map_err(|_| ApiError::InvalidPassword)?;

        if mk_bytes.len() != 32 {
            mk_bytes.zeroize();
            return Err(ApiError::Internal(
                "decrypted master key has wrong size".to_string(),
            ));
        }

        let mut mk_array = [0u8; 32];
        mk_array.copy_from_slice(&mk_bytes);
        mk_bytes.zeroize();
        let master_key = MasterKey::from_bytes(mk_array);
        mk_array.zeroize();

        self.activate_with_master_key(master_key).await
    }

    /// Verify the master password without changing server state.
    ///
    /// Re-runs the same KDF + AES-GCM decrypt as `unseal_password_inner`
    /// against the on-disk `master_key.enc`, but discards the decrypted
    /// master key immediately. The AES-GCM auth tag is the verification —
    /// if decryption succeeds, the password was correct.
    ///
    /// Goes through the same rate limiter as `unseal_password` so that
    /// brute-force attempts against this endpoint are no easier than
    /// against /unseal directly.
    pub async fn verify_master_password(&self, password: &str) -> Result<(), ApiError> {
        self.check_unseal_rate_limit()?;

        if !self.keystore.is_initialized() {
            return Err(ApiError::Internal(
                "server not initialized — run /unseal first to set the master password".to_string(),
            ));
        }

        let encrypted_mk = self
            .keystore
            .load_encrypted_master_key_password()
            .map_err(|e| ApiError::Internal(e.to_string()))?
            .ok_or(ApiError::Internal(
                "password-based unseal not configured for this server".to_string(),
            ))?;

        let params = self
            .kdf_params
            .read()
            .await
            .clone()
            .ok_or_else(|| ApiError::Internal("KDF params missing".to_string()))?;

        let pw_key = crypto::derive_master_key(password.as_bytes(), &params)
            .map_err(|e| ApiError::Internal(format!("key derivation failed: {e}")))?;

        match crypto::decrypt(&encrypted_mk, pw_key.as_bytes()) {
            Ok(mut mk_bytes) => {
                // Throw away the decrypted master key immediately — we only
                // needed verification, not the key itself.
                mk_bytes.zeroize();
                self.reset_unseal_rate_limit();
                Ok(())
            }
            Err(_) => {
                self.record_unseal_failure();
                Err(ApiError::InvalidPassword)
            }
        }
    }

    /// Unseal with both password and YubiKey (first-time dual setup only).
    /// Holds the transition mutex. Falls back to password-only if already initialized.
    pub async fn unseal_both(&self, password: &str) -> Result<usize, ApiError> {
        self.check_unseal_rate_limit()?;
        let _guard = self.transition_mutex.lock().await;
        self.check_not_active().await?;

        if !self.keystore.is_initialized() {
            let result = self.initialize(Some(password), true).await;
            if result.is_ok() {
                self.reset_unseal_rate_limit();
            } else {
                self.record_unseal_failure();
            }
            return result.map(|_| 0);
        }

        // Already initialized — unseal with password while still holding the mutex.
        self.unseal_password_inner(password).await
    }

    // -----------------------------------------------------------------------
    // Dual-factor unseal (v0.1.7+)
    //
    // The dual-factor path requires BOTH a password AND a pre-computed
    // YubiKey HMAC-SHA1 response. The YubiKey lives on the client box (not
    // on the picrypt-server itself) so the client touches it locally and
    // sends the 20-byte response hex as part of the unseal request. This
    // is the flow that actually defeats a "root on the server + coerced
    // master password" attack: the attacker on the server cannot produce
    // the YubiKey response without physical access to a YubiKey, which is
    // in your pocket or your safe, somewhere else.
    // -----------------------------------------------------------------------

    /// Decode a hex YubiKey response (40 hex chars → 20 bytes) and return
    /// the Argon2id-derived 32-byte key material that v0.1.7 uses as one
    /// half of the dual-factor wrapping key.
    fn derive_yk_key_from_hex_response(response_hex: &str) -> Result<[u8; 32], ApiError> {
        let response_bytes = crypto::hex_decode(response_hex)
            .map_err(|e| ApiError::Internal(format!("invalid yubikey response hex: {e}")))?;
        if response_bytes.len() != 20 {
            return Err(ApiError::Internal(format!(
                "yubikey response must be 20 bytes (HMAC-SHA1 output), got {}",
                response_bytes.len()
            )));
        }
        yubikey::derive_key_from_response(&response_bytes)
            .map_err(|e| ApiError::Internal(format!("yubikey key derivation failed: {e}")))
    }

    /// Unseal with password + client-provided YubiKey HMAC-SHA1 response.
    /// Both factors are required; failure of either reports as
    /// `InvalidPassword` so that timing does not leak which factor was
    /// wrong.
    pub async fn unseal_dual_factor(
        &self,
        password: &str,
        yk_response_hex: &str,
    ) -> Result<usize, ApiError> {
        self.check_unseal_rate_limit()?;
        let _guard = self.transition_mutex.lock().await;
        self.check_not_active().await?;

        if !self.keystore.has_dual_factor_unseal() {
            return Err(ApiError::Internal(
                "dual-factor unseal not configured on this server — \
                 enroll a YubiKey first via `picrypt admin enroll-dual-factor`"
                    .to_string(),
            ));
        }

        self.unseal_dual_factor_inner(password, yk_response_hex)
            .await
    }

    /// Internal dual-factor unseal logic. Caller MUST hold the transition mutex.
    async fn unseal_dual_factor_inner(
        &self,
        password: &str,
        yk_response_hex: &str,
    ) -> Result<usize, ApiError> {
        let encrypted_mk = self
            .keystore
            .load_encrypted_master_key_dual()
            .map_err(|e| ApiError::Internal(e.to_string()))?
            .ok_or_else(|| ApiError::Internal("dual-factor master key blob missing".to_string()))?;

        let params = self
            .kdf_params
            .read()
            .await
            .clone()
            .ok_or_else(|| ApiError::Internal("KDF params missing".to_string()))?;

        // Derive the password-side key (expensive Argon2id).
        let pw_key = crypto::derive_master_key(password.as_bytes(), &params)
            .map_err(|e| ApiError::Internal(format!("password key derivation failed: {e}")))?;

        // Derive the YubiKey-side key from the client-provided response.
        // Bad hex or wrong length here is a client error, not a credential
        // failure — we return it as-is without bumping the rate limiter,
        // because it's not a guessing attempt.
        let yk_key = Self::derive_yk_key_from_hex_response(yk_response_hex)?;

        // Combine the two into the wrapping key.
        let mut combined = crypto::derive_dual_factor_key(pw_key.as_bytes(), &yk_key)
            .map_err(|e| ApiError::Internal(format!("dual-factor key derivation failed: {e}")))?;

        // AES-GCM tag verification is the factor check. If EITHER the
        // password OR the yubikey response is wrong, combined_key is wrong,
        // and decryption fails with a tag mismatch. We surface that as
        // InvalidPassword so timing + error text don't leak which half
        // was the bad one.
        let decrypt_result = crypto::decrypt(&encrypted_mk, &combined);
        combined.zeroize();

        let mut mk_bytes = match decrypt_result {
            Ok(bytes) => bytes,
            Err(_) => {
                self.record_unseal_failure();
                return Err(ApiError::InvalidPassword);
            }
        };

        if mk_bytes.len() != 32 {
            mk_bytes.zeroize();
            return Err(ApiError::Internal(
                "decrypted master key has wrong size".to_string(),
            ));
        }

        let mut mk_array = [0u8; 32];
        mk_array.copy_from_slice(&mk_bytes);
        mk_bytes.zeroize();
        let master_key = MasterKey::from_bytes(mk_array);
        mk_array.zeroize();

        self.reset_unseal_rate_limit();
        self.activate_with_master_key(master_key).await
    }

    /// Upgrade an ALREADY-UNSEALED server from single-factor to dual-factor.
    ///
    /// Preconditions:
    ///   * Server state is Active (master_key is in RAM).
    ///   * Caller has admin authentication (enforced at the API layer).
    ///   * Caller provides the current master password as a belt-and-braces
    ///     check — admin token alone is not sufficient to bind a new
    ///     YubiKey, because admin token + YubiKey would let an insider
    ///     silently replace the second factor.
    ///
    /// Effect: takes the in-memory master key, re-encrypts it under a
    /// wrapping key derived from (password, yubikey_response), writes
    /// `encrypted_master_key_pw_yk.bin` and `yubikey_challenge.bin` to
    /// disk. Does NOT delete the single-factor blob — that's a separate
    /// explicit step (`finalize_dual_factor_migration`) run only after
    /// the admin has verified the new blob opens cleanly.
    pub async fn upgrade_to_dual_factor(
        &self,
        password: &str,
        yk_challenge: &[u8],
        yk_response_hex: &str,
    ) -> Result<(), ApiError> {
        let _guard = self.transition_mutex.lock().await;

        // Must be Active — we need master_key in RAM.
        let current_state = *self.state.read().await;
        if current_state != ServerState::Active {
            return Err(ApiError::Internal(format!(
                "upgrade_to_dual_factor requires Active state, got {current_state}"
            )));
        }

        // Belt-and-braces: verify the password matches the existing
        // single-factor blob. An admin-token-only upgrade would let an
        // insider silently rotate the second factor.
        self.verify_master_password(password).await?;

        // Derive both halves.
        let params = self
            .kdf_params
            .read()
            .await
            .clone()
            .ok_or_else(|| ApiError::Internal("KDF params missing".to_string()))?;
        let pw_key = crypto::derive_master_key(password.as_bytes(), &params)
            .map_err(|e| ApiError::Internal(format!("password key derivation failed: {e}")))?;
        let yk_key = Self::derive_yk_key_from_hex_response(yk_response_hex)?;
        let mut combined = crypto::derive_dual_factor_key(pw_key.as_bytes(), &yk_key)
            .map_err(|e| ApiError::Internal(format!("dual-factor key derivation failed: {e}")))?;

        // Pull the current master key out of RAM so we can re-encrypt it.
        // We clone the 32 bytes through a local array so we don't take a
        // long-held lock on master_key while we do the slow AES work.
        let mut mk_bytes = {
            let mk_guard = self.master_key.read().await;
            let mk_ref = mk_guard.as_ref().ok_or_else(|| {
                ApiError::Internal("master key missing while Active (race?)".to_string())
            })?;
            *mk_ref.as_bytes()
        };

        let encrypted = crypto::encrypt(&mk_bytes, &combined).map_err(|e| {
            ApiError::Internal(format!("dual-factor master key encryption failed: {e}"))
        });
        mk_bytes.zeroize();
        combined.zeroize();
        let encrypted = encrypted?;

        // Persist both the new blob and the challenge the client used.
        // Order matters: write the blob first; if we wrote the challenge
        // first and then crashed, we'd have a challenge without a blob
        // and subsequent unseal attempts would not find what they need.
        self.keystore
            .save_encrypted_master_key_dual(&encrypted)
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        self.keystore
            .save_yubikey_challenge(yk_challenge)
            .map_err(|e| ApiError::Internal(e.to_string()))?;

        tracing::warn!(
            "dual-factor unseal enrolled — existing single-factor blobs left in place. \
             Run `picrypt admin finalize-dual-factor` to delete them."
        );
        Ok(())
    }

    /// Final step of dual-factor migration: permanently delete the old
    /// single-factor blobs (password-only and YubiKey-only) so that
    /// dual-factor is the only unseal path possible. Run this AFTER a
    /// successful `upgrade_to_dual_factor` AND after you have verified
    /// you can unseal with dual-factor in a test cycle — otherwise a bug
    /// in the new path would leave you locked out.
    ///
    /// Requires Active state + admin auth (enforced at the API layer).
    pub async fn finalize_dual_factor_migration(&self) -> Result<(), ApiError> {
        let _guard = self.transition_mutex.lock().await;

        let current_state = *self.state.read().await;
        if current_state != ServerState::Active {
            return Err(ApiError::Internal(format!(
                "finalize_dual_factor_migration requires Active state, got {current_state}"
            )));
        }
        if !self.keystore.has_dual_factor_unseal() {
            return Err(ApiError::Internal(
                "cannot finalize — no dual-factor blob on disk".to_string(),
            ));
        }

        self.keystore
            .delete_encrypted_master_key_password()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        self.keystore
            .delete_encrypted_master_key_yubikey()
            .map_err(|e| ApiError::Internal(e.to_string()))?;

        tracing::warn!(
            "single-factor master key blobs deleted — dual-factor is now the only unseal path"
        );
        Ok(())
    }

    /// Read-only reference to the auto-generated admin token.
    pub async fn generated_admin_token_ref(
        &self,
    ) -> tokio::sync::RwLockReadGuard<'_, Option<String>> {
        self.generated_admin_token.read().await
    }

    /// Common activation path: decrypt all device keyfiles with the master key.
    async fn activate_with_master_key(&self, master_key: MasterKey) -> Result<usize, ApiError> {
        let devices = self.devices.read().await;
        let mut decrypted = HashMap::with_capacity(devices.len());

        for (id, record) in devices.iter() {
            if record.revoked {
                continue;
            }
            match crypto::decrypt(&record.encrypted_keyfile, master_key.as_bytes()) {
                Ok(keyfile) => {
                    decrypted.insert(*id, keyfile);
                }
                Err(e) => {
                    tracing::error!(
                        "failed to decrypt keyfile for device {id}: {e} — \
                         record may be corrupted, skipping"
                    );
                    // Skip corrupted records rather than blocking ALL devices.
                    // If every record fails, we'll catch it below.
                }
            }
        }

        let device_count = decrypted.len();
        let non_revoked = devices.values().filter(|d| !d.revoked).count();

        // If we have non-revoked devices but couldn't decrypt ANY of them,
        // the master key / password is wrong.
        if device_count == 0 && non_revoked > 0 {
            return Err(ApiError::InvalidPassword);
        }

        // All three writes happen while the transition mutex is held by the caller.
        *self.decrypted_keyfiles.write().await = decrypted;
        *self.master_key.write().await = Some(master_key);
        *self.state.write().await = ServerState::Active;
        self.touch_activity();
        self.reset_unseal_rate_limit();

        // Auto-generate admin token if none configured. This runs on every
        // unseal (not just init) so it survives server restarts.
        if self.config.admin_token.is_none() {
            // Check if we already have a file-backed token.
            let has_file_token = self.file_backed_admin_token.read().await.is_some();
            let mut gen = self.generated_admin_token.write().await;
            if gen.is_none() && !has_file_token {
                let token_bytes = crypto::generate_auth_token();
                let token_b64 = base64::engine::general_purpose::STANDARD.encode(token_bytes);

                // Persist to file so it survives server restarts.
                let token_path = self.config.data_dir.join("admin_token.txt");
                if let Err(e) = std::fs::write(&token_path, &token_b64) {
                    tracing::error!(
                        "failed to write admin token to {}: {e}",
                        token_path.display()
                    );
                } else {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let perms = std::fs::Permissions::from_mode(0o600);
                        if let Err(e) = std::fs::set_permissions(&token_path, perms) {
                            tracing::error!(
                                "failed to set permissions on {}: {e}",
                                token_path.display()
                            );
                        }
                    }
                    tracing::info!("admin token saved to {}", token_path.display());
                }

                // Also store in file-backed slot so admin_token() finds it
                // without re-reading the file.
                *self.file_backed_admin_token.write().await = Some(token_b64.clone());
                *gen = Some(token_b64);
            }
        }

        tracing::info!(
            "server unsealed — {} device keyfiles decrypted",
            device_count
        );
        Ok(device_count)
    }

    async fn check_not_active(&self) -> Result<(), ApiError> {
        if *self.state.read().await == ServerState::Active {
            return Err(ApiError::Internal("server is already active".to_string()));
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Lock: ACTIVE -> LOCKED -> SEALED (panic)
    // -----------------------------------------------------------------------

    /// Panic lock. Holds the transition mutex to prevent concurrent unseal.
    /// Broadcasts dismount to all connected clients, purges all decrypted
    /// material from memory, transitions to Sealed.
    pub async fn lock(&self) -> Result<usize, ApiError> {
        let _guard = self.transition_mutex.lock().await;
        *self.state.write().await = ServerState::Locked;

        let notified = self.lock_tx.send(WsServerMessage::Lock).unwrap_or(0);

        tracing::warn!("LOCK broadcast sent to {notified} connected client(s)");

        // Purge all decrypted keyfiles.
        {
            let mut keyfiles = self.decrypted_keyfiles.write().await;
            for (_, mut kf) in keyfiles.drain() {
                kf.zeroize();
            }
        }

        // Purge master key.
        *self.master_key.write().await = None;

        // Purge auto-generated admin token.
        *self.generated_admin_token.write().await = None;

        // Transition to Sealed.
        *self.state.write().await = ServerState::Sealed;

        tracing::warn!("server is now SEALED — all secrets purged from memory");
        Ok(notified)
    }

    // -----------------------------------------------------------------------
    // Dead man's switch
    // -----------------------------------------------------------------------

    /// Start the dead man's switch background task. Auto-locks if no activity
    /// for `timeout` duration. Returns the JoinHandle so the caller can abort.
    pub fn start_dead_man_switch(
        self: &std::sync::Arc<Self>,
        timeout: Duration,
    ) -> tokio::task::JoinHandle<()> {
        let state = std::sync::Arc::clone(self);
        tokio::spawn(async move {
            let check_interval = Duration::from_secs(60); // Check every minute.
            loop {
                tokio::time::sleep(check_interval).await;

                let current = *state.state.read().await;
                if current != ServerState::Active {
                    continue; // Only enforce when active.
                }

                let idle = state.idle_seconds();
                if idle >= timeout.as_secs() as i64 {
                    tracing::warn!(
                        "dead man's switch triggered — idle for {idle}s (threshold: {}s)",
                        timeout.as_secs()
                    );
                    if let Err(e) = state.lock().await {
                        tracing::error!("dead man's switch lock failed: {e}");
                    }
                }
            }
        })
    }

    // -----------------------------------------------------------------------
    // Device management
    // -----------------------------------------------------------------------

    pub async fn register_device(
        &self,
        name: &str,
        platform: Platform,
    ) -> Result<(Uuid, [u8; 32], Vec<u8>), ApiError> {
        self.require_active().await?;
        self.touch_activity();

        let device_id = Uuid::new_v4();
        let raw_keyfile = crypto::generate_keyfile();
        let raw_token = crypto::generate_auth_token();
        let token_hash = hash_token(&raw_token);

        let master_key = self.master_key.read().await;
        let master_key = master_key
            .as_ref()
            .ok_or_else(|| ApiError::Internal("master key not available".to_string()))?;

        let encrypted_keyfile = crypto::encrypt(&raw_keyfile, master_key.as_bytes())
            .map_err(|e| ApiError::Internal(format!("failed to encrypt keyfile: {e}")))?;

        let record = DeviceRecord {
            id: device_id,
            name: name.to_string(),
            platform,
            token_hash,
            encrypted_keyfile,
            revoked: false,
            registered_at: chrono::Utc::now(),
        };

        self.keystore
            .save_device(&record)
            .map_err(|e| ApiError::Internal(e.to_string()))?;

        let platform_display = record.platform.to_string();

        // Hold write lock for both the duplicate check AND the insert to
        // prevent two concurrent registrations with the same name.
        let mut devices = self.devices.write().await;
        if devices.values().any(|d| d.name == name && !d.revoked) {
            return Err(ApiError::DeviceAlreadyExists(name.to_string()));
        }
        devices.insert(device_id, record);
        self.decrypted_keyfiles
            .write()
            .await
            .insert(device_id, raw_keyfile.clone());

        tracing::info!("registered device: {name} ({device_id}) platform={platform_display}");
        Ok((device_id, raw_token, raw_keyfile))
    }

    pub async fn revoke_device(&self, device_id: &Uuid) -> Result<(), ApiError> {
        self.require_active().await?;
        self.touch_activity();

        let mut devices = self.devices.write().await;
        let record = devices
            .get_mut(device_id)
            .ok_or_else(|| ApiError::DeviceNotFound(device_id.to_string()))?;

        if record.revoked {
            return Err(ApiError::DeviceRevoked(device_id.to_string()));
        }

        record.revoked = true;

        self.keystore
            .save_device(record)
            .map_err(|e| ApiError::Internal(e.to_string()))?;

        if let Some(mut kf) = self.decrypted_keyfiles.write().await.remove(device_id) {
            kf.zeroize();
        }

        tracing::info!("revoked device: {} ({})", record.name, device_id);
        Ok(())
    }

    pub async fn authenticate_device(&self, raw_token: &[u8; 32]) -> Result<Uuid, ApiError> {
        let token_hash = hash_token(raw_token);
        let devices = self.devices.read().await;

        for (id, record) in devices.iter() {
            if record.token_hash == token_hash {
                if record.revoked {
                    return Err(ApiError::DeviceRevoked(id.to_string()));
                }
                return Ok(*id);
            }
        }

        Err(ApiError::Unauthorized("invalid auth token".to_string()))
    }

    pub async fn get_keyfile(&self, device_id: &Uuid) -> Result<Vec<u8>, ApiError> {
        self.require_active().await?;
        self.touch_activity();

        let keyfiles = self.decrypted_keyfiles.read().await;
        keyfiles
            .get(device_id)
            .cloned()
            .ok_or_else(|| ApiError::DeviceNotFound(device_id.to_string()))
    }

    // -----------------------------------------------------------------------
    // Keystore introspection (v0.1.7 — needed by the API handlers for
    // routing decisions). These are thin read-only wrappers so the
    // handlers don't need to know about the KeyStore type directly.
    // -----------------------------------------------------------------------

    pub fn keystore_has_password_unseal(&self) -> bool {
        self.keystore.has_password_unseal()
    }

    pub fn keystore_has_yubikey_unseal(&self) -> bool {
        self.keystore.has_yubikey_unseal()
    }

    pub fn keystore_has_dual_factor(&self) -> bool {
        self.keystore.has_dual_factor_unseal()
    }

    /// Load the stored YubiKey challenge so the API can serve it to a
    /// client via `GET /unseal/challenge`. Returns None if no challenge
    /// has been stored yet (i.e. dual-factor has never been enrolled).
    /// Any I/O error becomes None — the handler will report "missing"
    /// which is the same user-visible result.
    pub fn load_yubikey_challenge_for_client(&self) -> Option<Vec<u8>> {
        self.keystore.load_yubikey_challenge().ok().flatten()
    }

    pub async fn list_devices(&self) -> Vec<picrypt_common::protocol::DeviceListEntry> {
        let devices = self.devices.read().await;
        let connected = self.connected_devices.read().await;

        devices
            .values()
            .map(|d| picrypt_common::protocol::DeviceListEntry {
                id: d.id,
                name: d.name.clone(),
                platform: d.platform.clone(),
                revoked: d.revoked,
                connected: connected.contains_key(&d.id),
                registered_at: d.registered_at,
            })
            .collect()
    }

    pub async fn mark_connected(&self, device_id: Uuid) {
        self.connected_devices.write().await.insert(device_id, ());
        tracing::info!("device {device_id} connected via WebSocket");
    }

    pub async fn mark_disconnected(&self, device_id: &Uuid) {
        self.connected_devices.write().await.remove(device_id);
        tracing::info!("device {device_id} disconnected from WebSocket");
    }
}

/// Hash an auth token for storage. Uses Argon2id with minimal cost since the
/// input is a 256-bit random token (not a password).
fn hash_token(token: &[u8; 32]) -> Vec<u8> {
    use argon2::Argon2;

    let salt = b"picrypt-token-hash-salt-v1\0\0\0\0\0\0\0";
    let params = argon2::Params::new(1024, 1, 1, Some(32)).expect("valid argon2 params");
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut hash = vec![0u8; 32];
    argon2
        .hash_password_into(token, salt, &mut hash)
        .expect("token hashing failed");
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;
    use tempfile::TempDir;

    /// Build an AppState backed by a temporary directory.
    fn make_state(tmp: &TempDir) -> AppState {
        let config = ServerConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            data_dir: tmp.path().to_path_buf(),
            dead_man_timeout_secs: 0,
            admin_token: None,
            lock_pin: None,
            require_dual_factor: false,
        };
        AppState::new(config).expect("AppState::new failed")
    }

    fn make_state_with_pin(tmp: &TempDir, pin: &str) -> AppState {
        let config = ServerConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            data_dir: tmp.path().to_path_buf(),
            dead_man_timeout_secs: 0,
            admin_token: None,
            lock_pin: Some(pin.to_string()),
            require_dual_factor: false,
        };
        AppState::new(config).expect("AppState::new failed")
    }

    #[tokio::test]
    async fn initial_state_is_sealed() {
        let tmp = TempDir::new().unwrap();
        let state = make_state(&tmp);
        assert_eq!(state.current_state().await, ServerState::Sealed);
    }

    #[tokio::test]
    async fn unseal_first_time_initializes() {
        let tmp = TempDir::new().unwrap();
        let state = make_state(&tmp);

        let result = state.unseal_password("test-password-123").await;
        assert!(result.is_ok(), "first unseal should initialize: {result:?}");
        assert_eq!(state.current_state().await, ServerState::Active);
    }

    #[tokio::test]
    async fn unseal_wrong_password_fails() {
        let tmp = TempDir::new().unwrap();
        let state = make_state(&tmp);

        // Initialize with a known password.
        state
            .unseal_password("correct-horse-battery")
            .await
            .expect("initialization failed");

        // Lock to go back to Sealed.
        state.lock().await.expect("lock failed");
        assert_eq!(state.current_state().await, ServerState::Sealed);

        // Try to unseal with wrong password.
        let result = state.unseal_password("wrong-password").await;
        assert!(result.is_err(), "wrong password should fail");
    }

    #[tokio::test]
    async fn lock_transitions_to_sealed() {
        let tmp = TempDir::new().unwrap();
        let state = make_state(&tmp);

        state.unseal_password("pw").await.expect("unseal failed");
        assert_eq!(state.current_state().await, ServerState::Active);

        state.lock().await.expect("lock failed");
        assert_eq!(state.current_state().await, ServerState::Sealed);
    }

    #[tokio::test]
    async fn lock_purges_keys() {
        let tmp = TempDir::new().unwrap();
        let state = make_state(&tmp);

        state.unseal_password("pw").await.expect("unseal failed");

        // Register a device so there's a decrypted keyfile in memory.
        state
            .register_device("test-dev", Platform::Linux)
            .await
            .expect("register failed");

        state.lock().await.expect("lock failed");

        // Master key should be None.
        let mk = state.master_key.read().await;
        assert!(mk.is_none(), "master key must be None after lock");
        drop(mk);

        // Decrypted keyfiles should be empty.
        let keyfiles = state.decrypted_keyfiles.read().await;
        assert!(
            keyfiles.is_empty(),
            "decrypted keyfiles must be empty after lock"
        );
    }

    #[tokio::test]
    async fn register_device_while_sealed_fails() {
        let tmp = TempDir::new().unwrap();
        let state = make_state(&tmp);

        let result = state.register_device("sealed-dev", Platform::Macos).await;
        assert!(result.is_err(), "register should fail while sealed");
    }

    #[tokio::test]
    async fn register_and_get_keyfile() {
        let tmp = TempDir::new().unwrap();
        let state = make_state(&tmp);

        state.unseal_password("pw").await.expect("unseal failed");

        let (device_id, _token, raw_keyfile) = state
            .register_device("my-laptop", Platform::Macos)
            .await
            .expect("register failed");

        let fetched = state
            .get_keyfile(&device_id)
            .await
            .expect("get_keyfile failed");

        assert_eq!(
            fetched, raw_keyfile,
            "fetched keyfile must match the one returned at registration"
        );
    }

    // ---------------------------------------------------------------
    // v0.1.7 dual-factor unseal tests
    // ---------------------------------------------------------------
    //
    // These tests build a fake 20-byte YubiKey response. The server
    // doesn't care that it didn't come from real hardware — the server
    // just Argon2id-expands whatever 20 bytes it's handed into a 32-byte
    // key. That's the same derivation path the real ykchalresp output
    // would go through. As long as the test feeds the same "response"
    // bytes at upgrade time and at unseal time, the math works out.

    const TEST_YK_RESPONSE_OK: [u8; 20] = [0xAA; 20];
    const TEST_YK_RESPONSE_BAD: [u8; 20] = [0xBB; 20];
    const TEST_YK_CHALLENGE: [u8; 32] = [0xCC; 32];

    fn yk_hex(response: &[u8; 20]) -> String {
        crypto::hex_encode(response)
    }

    #[tokio::test]
    async fn upgrade_to_dual_factor_from_password_unseal() {
        let tmp = TempDir::new().unwrap();
        let state = make_state(&tmp);

        // Init with password-only.
        state
            .unseal_password("strong-pw-42")
            .await
            .expect("initial unseal");
        assert!(state.keystore.has_password_unseal());
        assert!(!state.keystore.has_dual_factor_unseal());

        // Upgrade.
        state
            .upgrade_to_dual_factor(
                "strong-pw-42",
                &TEST_YK_CHALLENGE,
                &yk_hex(&TEST_YK_RESPONSE_OK),
            )
            .await
            .expect("upgrade failed");

        // Both blobs now exist; we haven't finalized yet.
        assert!(state.keystore.has_password_unseal());
        assert!(state.keystore.has_dual_factor_unseal());
        // Challenge was persisted for the client to fetch at unseal time.
        let stored_challenge = state
            .keystore
            .load_yubikey_challenge()
            .expect("load challenge")
            .expect("challenge should exist after upgrade");
        assert_eq!(stored_challenge, TEST_YK_CHALLENGE);
    }

    #[tokio::test]
    async fn dual_factor_unseal_after_upgrade_succeeds() {
        let tmp = TempDir::new().unwrap();
        let state = make_state(&tmp);

        state
            .unseal_password("strong-pw-42")
            .await
            .expect("initial unseal");
        state
            .upgrade_to_dual_factor(
                "strong-pw-42",
                &TEST_YK_CHALLENGE,
                &yk_hex(&TEST_YK_RESPONSE_OK),
            )
            .await
            .expect("upgrade");
        state.lock().await.expect("lock");

        state
            .unseal_dual_factor("strong-pw-42", &yk_hex(&TEST_YK_RESPONSE_OK))
            .await
            .expect("dual-factor unseal");
        assert_eq!(state.current_state().await, ServerState::Active);
    }

    #[tokio::test]
    async fn dual_factor_unseal_wrong_password_fails() {
        let tmp = TempDir::new().unwrap();
        let state = make_state(&tmp);

        state
            .unseal_password("strong-pw-42")
            .await
            .expect("initial unseal");
        state
            .upgrade_to_dual_factor(
                "strong-pw-42",
                &TEST_YK_CHALLENGE,
                &yk_hex(&TEST_YK_RESPONSE_OK),
            )
            .await
            .expect("upgrade");
        state.lock().await.expect("lock");

        // Correct YK response, wrong password.
        let result = state
            .unseal_dual_factor("wrong-password", &yk_hex(&TEST_YK_RESPONSE_OK))
            .await;
        assert!(matches!(result, Err(ApiError::InvalidPassword)));
        assert_eq!(state.current_state().await, ServerState::Sealed);
    }

    #[tokio::test]
    async fn dual_factor_unseal_wrong_yk_response_fails() {
        let tmp = TempDir::new().unwrap();
        let state = make_state(&tmp);

        state
            .unseal_password("strong-pw-42")
            .await
            .expect("initial unseal");
        state
            .upgrade_to_dual_factor(
                "strong-pw-42",
                &TEST_YK_CHALLENGE,
                &yk_hex(&TEST_YK_RESPONSE_OK),
            )
            .await
            .expect("upgrade");
        state.lock().await.expect("lock");

        // Correct password, wrong YK response.
        let result = state
            .unseal_dual_factor("strong-pw-42", &yk_hex(&TEST_YK_RESPONSE_BAD))
            .await;
        assert!(matches!(result, Err(ApiError::InvalidPassword)));
        assert_eq!(state.current_state().await, ServerState::Sealed);
    }

    #[tokio::test]
    async fn dual_factor_unseal_errors_when_not_enrolled() {
        let tmp = TempDir::new().unwrap();
        let state = make_state(&tmp);

        // Single-factor init, no dual enrollment.
        state
            .unseal_password("strong-pw-42")
            .await
            .expect("initial unseal");
        state.lock().await.expect("lock");

        // Attempt dual-factor unseal — should report "not configured"
        // rather than silently falling back or returning InvalidPassword.
        let result = state
            .unseal_dual_factor("strong-pw-42", &yk_hex(&TEST_YK_RESPONSE_OK))
            .await;
        assert!(result.is_err());
        let err_text = format!("{:?}", result.unwrap_err());
        assert!(
            err_text.contains("dual-factor unseal not configured"),
            "error must name the missing enrollment, got: {err_text}"
        );
    }

    #[tokio::test]
    async fn dual_factor_unseal_rejects_non_hex_response() {
        let tmp = TempDir::new().unwrap();
        let state = make_state(&tmp);

        state
            .unseal_password("strong-pw-42")
            .await
            .expect("initial unseal");
        state
            .upgrade_to_dual_factor(
                "strong-pw-42",
                &TEST_YK_CHALLENGE,
                &yk_hex(&TEST_YK_RESPONSE_OK),
            )
            .await
            .expect("upgrade");
        state.lock().await.expect("lock");

        let result = state
            .unseal_dual_factor("strong-pw-42", "not-hex-at-all")
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn dual_factor_unseal_rejects_wrong_length_response() {
        let tmp = TempDir::new().unwrap();
        let state = make_state(&tmp);

        state
            .unseal_password("strong-pw-42")
            .await
            .expect("initial unseal");
        state
            .upgrade_to_dual_factor(
                "strong-pw-42",
                &TEST_YK_CHALLENGE,
                &yk_hex(&TEST_YK_RESPONSE_OK),
            )
            .await
            .expect("upgrade");
        state.lock().await.expect("lock");

        // 10 bytes instead of 20.
        let result = state
            .unseal_dual_factor("strong-pw-42", "aabbccddeeff00112233")
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn finalize_dual_factor_deletes_old_blobs() {
        let tmp = TempDir::new().unwrap();
        let state = make_state(&tmp);

        state
            .unseal_password("strong-pw-42")
            .await
            .expect("initial unseal");
        state
            .upgrade_to_dual_factor(
                "strong-pw-42",
                &TEST_YK_CHALLENGE,
                &yk_hex(&TEST_YK_RESPONSE_OK),
            )
            .await
            .expect("upgrade");
        assert!(state.keystore.has_password_unseal());
        assert!(state.keystore.has_dual_factor_unseal());

        state
            .finalize_dual_factor_migration()
            .await
            .expect("finalize");

        // Dual-factor blob remains; single-factor blobs are gone.
        assert!(state.keystore.has_dual_factor_unseal());
        assert!(!state.keystore.has_password_unseal());
        assert!(!state.keystore.has_yubikey_unseal());
    }

    #[tokio::test]
    async fn dual_factor_unseal_after_finalize_still_works() {
        let tmp = TempDir::new().unwrap();
        let state = make_state(&tmp);

        state
            .unseal_password("strong-pw-42")
            .await
            .expect("initial unseal");
        state
            .upgrade_to_dual_factor(
                "strong-pw-42",
                &TEST_YK_CHALLENGE,
                &yk_hex(&TEST_YK_RESPONSE_OK),
            )
            .await
            .expect("upgrade");
        state
            .finalize_dual_factor_migration()
            .await
            .expect("finalize");
        state.lock().await.expect("lock");

        // Single-factor blob is gone; only the dual-factor path is
        // possible now.
        state
            .unseal_dual_factor("strong-pw-42", &yk_hex(&TEST_YK_RESPONSE_OK))
            .await
            .expect("dual-factor unseal after finalize");
        assert_eq!(state.current_state().await, ServerState::Active);
    }

    #[tokio::test]
    async fn upgrade_fails_when_sealed() {
        let tmp = TempDir::new().unwrap();
        let state = make_state(&tmp);

        state
            .unseal_password("strong-pw-42")
            .await
            .expect("initial unseal");
        state.lock().await.expect("lock");

        let result = state
            .upgrade_to_dual_factor(
                "strong-pw-42",
                &TEST_YK_CHALLENGE,
                &yk_hex(&TEST_YK_RESPONSE_OK),
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn upgrade_rejects_wrong_password() {
        let tmp = TempDir::new().unwrap();
        let state = make_state(&tmp);

        state
            .unseal_password("strong-pw-42")
            .await
            .expect("initial unseal");

        // Admin-token holder who tries to rotate with the wrong password
        // must be rejected even though the server is Active.
        let result = state
            .upgrade_to_dual_factor(
                "wrong-password",
                &TEST_YK_CHALLENGE,
                &yk_hex(&TEST_YK_RESPONSE_OK),
            )
            .await;
        assert!(matches!(result, Err(ApiError::InvalidPassword)));
        // No blob was written.
        assert!(!state.keystore.has_dual_factor_unseal());
    }

    #[tokio::test]
    async fn revoke_device_removes_keyfile() {
        let tmp = TempDir::new().unwrap();
        let state = make_state(&tmp);

        state.unseal_password("pw").await.expect("unseal failed");

        let (device_id, _token, _keyfile) = state
            .register_device("revokable", Platform::Linux)
            .await
            .expect("register failed");

        state
            .revoke_device(&device_id)
            .await
            .expect("revoke failed");

        let result = state.get_keyfile(&device_id).await;
        assert!(
            result.is_err(),
            "get_keyfile should fail after device is revoked"
        );
    }

    #[tokio::test]
    async fn authenticate_device_valid() {
        let tmp = TempDir::new().unwrap();
        let state = make_state(&tmp);

        state.unseal_password("pw").await.expect("unseal failed");

        let (device_id, raw_token, _keyfile) = state
            .register_device("auth-test", Platform::Windows)
            .await
            .expect("register failed");

        let authenticated_id = state
            .authenticate_device(&raw_token)
            .await
            .expect("authenticate failed");

        assert_eq!(
            authenticated_id, device_id,
            "authenticated device ID must match registered ID"
        );
    }

    #[tokio::test]
    async fn authenticate_device_invalid_token() {
        let tmp = TempDir::new().unwrap();
        let state = make_state(&tmp);

        state.unseal_password("pw").await.expect("unseal failed");

        state
            .register_device("auth-test", Platform::Linux)
            .await
            .expect("register failed");

        let bad_token = [0xFFu8; 32];
        let result = state.authenticate_device(&bad_token).await;
        assert!(result.is_err(), "invalid token should fail authentication");
    }

    #[tokio::test]
    async fn validate_lock_pin_none_configured() {
        let tmp = TempDir::new().unwrap();
        let state = make_state(&tmp);

        // No pin configured — any input (or None) should be Ok.
        assert!(state.validate_lock_pin(None).is_ok());
        assert!(state.validate_lock_pin(Some("anything")).is_ok());
    }

    #[tokio::test]
    async fn validate_lock_pin_correct() {
        let tmp = TempDir::new().unwrap();
        let state = make_state_with_pin(&tmp, "1234");

        assert!(
            state.validate_lock_pin(Some("1234")).is_ok(),
            "correct pin should succeed"
        );
    }

    #[tokio::test]
    async fn validate_lock_pin_wrong() {
        let tmp = TempDir::new().unwrap();
        let state = make_state_with_pin(&tmp, "1234");

        assert!(
            state.validate_lock_pin(Some("9999")).is_err(),
            "wrong pin should fail"
        );
        assert!(
            state.validate_lock_pin(None).is_err(),
            "missing pin should fail when configured"
        );
    }

    #[tokio::test]
    async fn touch_activity_resets_idle() {
        let tmp = TempDir::new().unwrap();
        let state = make_state(&tmp);

        state.touch_activity();
        let idle = state.idle_seconds();
        assert!(
            idle <= 1,
            "idle_seconds should be near zero right after touch, got {idle}"
        );
    }

    // -----------------------------------------------------------------------
    // verify_master_password
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn verify_master_password_correct() {
        let tmp = TempDir::new().unwrap();
        let state = make_state(&tmp);

        // Initialize the keystore by unsealing for the first time.
        state
            .unseal_password("the-real-master-password")
            .await
            .expect("first unseal failed");

        // verify_master_password should accept the same password whether
        // the server is currently active OR sealed.
        state
            .verify_master_password("the-real-master-password")
            .await
            .expect("verify with correct password (active) should succeed");

        // Lock back to sealed and try again.
        state.lock().await.expect("lock failed");
        state
            .verify_master_password("the-real-master-password")
            .await
            .expect("verify with correct password (sealed) should succeed");

        // verify_master_password must NOT change state.
        assert_eq!(state.current_state().await, ServerState::Sealed);
    }

    #[tokio::test]
    async fn verify_master_password_wrong_returns_invalid() {
        let tmp = TempDir::new().unwrap();
        let state = make_state(&tmp);

        state
            .unseal_password("the-real-master-password")
            .await
            .expect("first unseal failed");

        let result = state.verify_master_password("a-wrong-password").await;
        assert!(matches!(result, Err(ApiError::InvalidPassword)));
    }

    #[tokio::test]
    async fn verify_master_password_uninitialized_errors() {
        let tmp = TempDir::new().unwrap();
        let state = make_state(&tmp);

        // Server has never been unsealed — no master_key.enc on disk.
        let result = state.verify_master_password("anything").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn verify_master_password_does_not_change_state() {
        let tmp = TempDir::new().unwrap();
        let state = make_state(&tmp);

        state
            .unseal_password("pw-change-state-test")
            .await
            .expect("first unseal failed");
        state.lock().await.expect("lock failed");
        assert_eq!(state.current_state().await, ServerState::Sealed);

        // Verify with correct password — must NOT transition to Active.
        state
            .verify_master_password("pw-change-state-test")
            .await
            .expect("verify failed");
        assert_eq!(state.current_state().await, ServerState::Sealed);

        // Verify with wrong password — must also NOT transition.
        let _ = state.verify_master_password("wrong").await;
        assert_eq!(state.current_state().await, ServerState::Sealed);
    }
}
