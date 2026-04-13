use std::sync::Arc;

use axum::extract::State;
use axum::Json;

use picrypt_common::crypto;
use picrypt_common::protocol::{
    EnrollDualFactorRequest, EnrollDualFactorResponse, FinalizeDualFactorResponse,
    UnsealChallengeResponse, UnsealRequest, UnsealResponse,
};

use crate::error::ApiError;
use crate::state::AppState;

pub async fn unseal(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UnsealRequest>,
) -> Result<Json<UnsealResponse>, ApiError> {
    // v0.1.7: if the request carries a client-computed YubiKey response,
    // route to the dual-factor path. This is distinct from `yubikey: true`
    // (legacy "YubiKey attached to server" flow) and mutually exclusive
    // with it — either you're bringing your own response hex or you're
    // asking the server to run ykchalresp, not both.
    if let Some(ref yk_resp_hex) = req.yubikey_response_hex {
        if req.yubikey {
            return Err(ApiError::Internal(
                "invalid request: `yubikey: true` and `yubikey_response_hex` are mutually exclusive — use one or the other"
                    .to_string(),
            ));
        }
        let pw = req.password.as_deref().ok_or_else(|| {
            ApiError::Internal(
                "dual-factor unseal requires a password alongside yubikey_response_hex".to_string(),
            )
        })?;

        let device_count = state.unseal_dual_factor(pw, yk_resp_hex).await?;
        if let Some(ref token) = *state.generated_admin_token_ref().await {
            tracing::warn!(
                "AUTO-GENERATED ADMIN TOKEN (save this, add to server.toml as admin_token): {token}"
            );
        }
        return Ok(Json(UnsealResponse {
            state: state.current_state().await,
            device_count,
        }));
    }

    // Single-factor paths. Enforce `require_dual_factor` config here:
    // if the server is configured to require dual-factor, refuse any
    // request that doesn't carry a yubikey_response_hex. We fail-fast
    // BEFORE touching the rate limiter so a misconfigured single-factor
    // client doesn't burn through unseal attempts.
    if state.config.require_dual_factor {
        return Err(ApiError::Internal(
            "server requires dual-factor unseal: include `yubikey_response_hex` in the request \
             (fetch the challenge via GET /unseal/challenge, compute HMAC-SHA1 on a YubiKey, send back the 20-byte response as hex)"
                .to_string(),
        ));
    }

    // ALL unseal paths go through the state machine methods which hold
    // the transition mutex and enforce rate limiting. Never call
    // initialize() directly from here.
    let device_count = match (req.password.as_deref(), req.yubikey) {
        (Some(pw), false) => state.unseal_password(pw).await?,
        (None, true) => state.unseal_yubikey().await?,
        (Some(pw), true) => {
            // Both provided on first setup — route through unseal_password_and_yubikey.
            state.unseal_both(pw).await?
        }
        (None, false) => {
            return Err(ApiError::Internal(
                "must provide either password or yubikey: true".to_string(),
            ));
        }
    };

    // If an admin token was auto-generated, log it (but do NOT consume it —
    // admin_auth_middleware needs it to remain available).
    if let Some(ref token) = *state.generated_admin_token_ref().await {
        tracing::warn!(
            "AUTO-GENERATED ADMIN TOKEN (save this, add to server.toml as admin_token): {token}"
        );
    }

    Ok(Json(UnsealResponse {
        state: state.current_state().await,
        device_count,
    }))
}

/// `GET /unseal/challenge` — serve the stored YubiKey challenge so a
/// client can drive its local YubiKey through HMAC-SHA1 challenge-response
/// before hitting `POST /unseal` with the resulting response hex.
///
/// This is a **public** endpoint. The challenge is not a secret: knowing
/// it does not help an attacker without the YubiKey's HMAC key. It must
/// be public because there's no other way for a pre-unseal client to
/// discover it — the admin-auth middleware depends on server state that
/// only exists post-unseal, and unseal is what the client is trying to
/// do in the first place.
pub async fn challenge(
    State(state): State<Arc<AppState>>,
) -> Result<Json<UnsealChallengeResponse>, ApiError> {
    let dual_factor_available = state.keystore_has_dual_factor();
    let dual_factor_required = state.config.require_dual_factor;

    let challenge_hex = if dual_factor_available {
        let challenge = state.load_yubikey_challenge_for_client().ok_or_else(|| {
            ApiError::Internal(
                "dual-factor blob exists but yubikey_challenge.bin is missing".to_string(),
            )
        })?;
        crypto::hex_encode(&challenge)
    } else {
        String::new()
    };

    Ok(Json(UnsealChallengeResponse {
        challenge_hex,
        dual_factor_available,
        dual_factor_required,
    }))
}

/// `POST /admin/dual-factor/enroll` — admin-authenticated. Bind a client-
/// held YubiKey to the server as a second unseal factor. Requires the
/// current master password as an extra check so that a leaked admin
/// token alone cannot rotate the second factor.
pub async fn enroll_dual_factor(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EnrollDualFactorRequest>,
) -> Result<Json<EnrollDualFactorResponse>, ApiError> {
    let challenge_bytes = crypto::hex_decode(&req.yubikey_challenge_hex)
        .map_err(|e| ApiError::Internal(format!("invalid yubikey_challenge_hex: {e}")))?;
    if challenge_bytes.is_empty() || challenge_bytes.len() > 64 {
        return Err(ApiError::Internal(format!(
            "yubikey_challenge must be 1..=64 bytes, got {}",
            challenge_bytes.len()
        )));
    }

    state
        .upgrade_to_dual_factor(&req.password, &challenge_bytes, &req.yubikey_response_hex)
        .await?;

    Ok(Json(EnrollDualFactorResponse {
        state: state.current_state().await,
        single_factor_still_present: state.keystore_has_password_unseal(),
    }))
}

/// `POST /admin/dual-factor/finalize` — admin-authenticated. Deletes the
/// single-factor master key blobs from disk so dual-factor is the only
/// unseal path possible. Run only after verifying dual-factor unseal
/// works — otherwise you may lock yourself out.
pub async fn finalize_dual_factor(
    State(state): State<Arc<AppState>>,
) -> Result<Json<FinalizeDualFactorResponse>, ApiError> {
    state.finalize_dual_factor_migration().await?;

    Ok(Json(FinalizeDualFactorResponse {
        state: state.current_state().await,
        dual_factor_only: !state.keystore_has_password_unseal()
            && !state.keystore_has_yubikey_unseal()
            && state.keystore_has_dual_factor(),
    }))
}
