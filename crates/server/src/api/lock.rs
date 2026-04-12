use std::sync::Arc;

use axum::extract::State;
use axum::Json;

use picrypt_common::protocol::{LockRequest, LockResponse};

use crate::error::ApiError;
use crate::state::AppState;

pub async fn lock(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LockRequest>,
) -> Result<Json<LockResponse>, ApiError> {
    // Validate lock PIN if configured.
    state.validate_lock_pin(req.pin.as_deref())?;

    let devices_notified = state.lock().await?;

    Ok(Json(LockResponse {
        state: state.current_state().await,
        devices_notified,
    }))
}
