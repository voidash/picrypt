use std::sync::Arc;

use axum::extract::State;
use axum::Json;

use picrypt_common::protocol::{AdminTokenRequest, AdminTokenResponse};

use crate::error::ApiError;
use crate::state::AppState;

/// `POST /admin-token`
///
/// Reveals the admin token to anyone who can prove they know the master
/// password. This makes the master password the single root secret —
/// every other server-side credential (the admin token, by extension the
/// device-management surface) is recoverable from it without needing to
/// store the admin token separately.
///
/// Verification re-runs the password KDF and AES-GCM decrypt against the
/// on-disk encrypted master key. The decrypted master key is zeroized
/// immediately; this endpoint never changes server state and never
/// transitions sealed → active. It works in either state.
///
/// The same rate limiter as `/unseal` applies — brute force is no easier
/// here than against `/unseal` directly.
pub async fn admin_token(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AdminTokenRequest>,
) -> Result<Json<AdminTokenResponse>, ApiError> {
    state.verify_master_password(&req.password).await?;

    let token_bytes = state.admin_token().await.ok_or(ApiError::Internal(
        "admin token unavailable — server is not configured with one".to_string(),
    ))?;

    let token_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, token_bytes);

    tracing::info!("admin token revealed via /admin-token (master password verified)");

    Ok(Json(AdminTokenResponse {
        admin_token: token_b64,
    }))
}
