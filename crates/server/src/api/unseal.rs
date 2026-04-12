use std::sync::Arc;

use axum::extract::State;
use axum::Json;

use picrypt_common::protocol::{UnsealRequest, UnsealResponse};

use crate::error::ApiError;
use crate::state::AppState;

pub async fn unseal(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UnsealRequest>,
) -> Result<Json<UnsealResponse>, ApiError> {
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
