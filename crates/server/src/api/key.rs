use std::sync::Arc;

use axum::extract::{Path, State};
use axum::Json;
use base64::Engine;
use uuid::Uuid;
use zeroize::Zeroize;

use picrypt_common::protocol::KeyResponse;

use crate::error::ApiError;
use crate::state::AppState;

pub async fn get_key(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<Uuid>,
    req: axum::extract::Request,
) -> Result<Json<KeyResponse>, ApiError> {
    state.require_active().await?;

    let authed_device_id = req
        .extensions()
        .get::<Uuid>()
        .ok_or_else(|| ApiError::Unauthorized("missing device context".to_string()))?;

    if *authed_device_id != device_id {
        return Err(ApiError::Unauthorized(
            "cannot access another device's key".to_string(),
        ));
    }

    let mut keyfile = state.get_keyfile(&device_id).await?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(&keyfile);
    keyfile.zeroize(); // Zeroize the cloned Vec immediately after encoding.

    Ok(Json(KeyResponse { keyfile: encoded }))
}
