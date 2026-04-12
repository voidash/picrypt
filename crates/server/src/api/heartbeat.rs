use std::sync::Arc;

use axum::extract::State;
use axum::Json;

use picrypt_common::protocol::HeartbeatResponse;

use crate::state::AppState;

pub async fn heartbeat(State(state): State<Arc<AppState>>) -> Json<HeartbeatResponse> {
    Json(HeartbeatResponse {
        state: state.current_state().await,
        timestamp: chrono::Utc::now().timestamp(),
    })
}
