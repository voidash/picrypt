use std::sync::Arc;

use axum::extract::{Path, State};
use axum::Json;
use base64::Engine;
use uuid::Uuid;
use zeroize::Zeroize;

use picrypt_common::protocol::{DeviceListResponse, RegisterDeviceRequest, RegisterDeviceResponse};

use crate::error::ApiError;
use crate::state::AppState;

pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterDeviceRequest>,
) -> Result<Json<RegisterDeviceResponse>, ApiError> {
    state.require_active().await?;

    let (device_id, mut raw_token, mut raw_keyfile) = state
        .register_device(&req.device_name, req.platform)
        .await?;

    let b64 = &base64::engine::general_purpose::STANDARD;

    let resp = RegisterDeviceResponse {
        device_id,
        auth_token: b64.encode(raw_token),
        keyfile: b64.encode(&raw_keyfile),
    };

    // Zeroize raw secrets before they are dropped.
    raw_token.zeroize();
    raw_keyfile.zeroize();

    Ok(Json(resp))
}

pub async fn list(State(state): State<Arc<AppState>>) -> Json<DeviceListResponse> {
    let devices = state.list_devices().await;
    Json(DeviceListResponse { devices })
}

pub async fn revoke(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state.revoke_device(&device_id).await?;
    Ok(Json(
        serde_json::json!({ "status": "revoked", "device_id": device_id }),
    ))
}
