mod admin_token;
mod devices;
mod heartbeat;
mod key;
mod lock;
mod unseal;
mod ws;

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::middleware;
use axum::routing::{get, post};
use axum::Router;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use crate::state::AppState;

/// Build the full API router.
pub fn router(state: Arc<AppState>) -> Router {
    // Routes that require device token authentication.
    let device_auth = Router::new()
        .route("/key/{device_id}", get(key::get_key))
        .route("/ws", get(ws::ws_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            device_auth_middleware,
        ));

    // Routes that require admin token authentication.
    let admin_auth = Router::new()
        .route("/devices/register", post(devices::register))
        .route("/devices", get(devices::list))
        .route("/devices/{device_id}/revoke", post(devices::revoke))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            admin_auth_middleware,
        ));

    // Public routes — no auth required (each enforces its own rate limit).
    let public = Router::new()
        .route("/heartbeat", get(heartbeat::heartbeat))
        .route("/unseal", post(unseal::unseal))
        .route("/lock", post(lock::lock))
        .route("/admin-token", post(admin_token::admin_token));

    Router::new()
        .merge(device_auth)
        .merge(admin_auth)
        .merge(public)
        // 4KB body limit — prevents DoS via huge passwords/names.
        .layer(RequestBodyLimitLayer::new(4096))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Device auth: extract bearer token, validate against device records.
async fn device_auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: axum::extract::Request,
    next: middleware::Next,
) -> Result<axum::response::Response, StatusCode> {
    let token = extract_bearer_token(&req).ok_or(StatusCode::UNAUTHORIZED)?;

    if token.len() != 32 {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let mut token_arr = [0u8; 32];
    token_arr.copy_from_slice(&token);

    let device_id = state
        .authenticate_device(&token_arr)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    req.extensions_mut().insert(device_id);
    Ok(next.run(req).await)
}

/// Admin auth: extract bearer token, validate against the configured admin token.
async fn admin_auth_middleware(
    State(state): State<Arc<AppState>>,
    req: axum::extract::Request,
    next: middleware::Next,
) -> Result<axum::response::Response, StatusCode> {
    let admin_token = state
        .admin_token()
        .await
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    // Reject empty tokens — an empty admin_token in config would allow
    // an empty Bearer header to bypass auth.
    if admin_token.is_empty() {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let provided = extract_bearer_token(&req).ok_or(StatusCode::UNAUTHORIZED)?;

    // Constant-time comparison.
    if provided.is_empty() || provided.len() != admin_token.len() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let mut diff = 0u8;
    for (a, b) in provided.iter().zip(admin_token.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(req).await)
}

/// Extract a bearer token from the Authorization header, base64-decode it.
fn extract_bearer_token(req: &axum::extract::Request) -> Option<Vec<u8>> {
    let auth_header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;

    let token_b64 = auth_header.strip_prefix("Bearer ")?;

    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, token_b64).ok()
}
