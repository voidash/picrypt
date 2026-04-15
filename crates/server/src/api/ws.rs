use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::response::IntoResponse;
use futures_util::{SinkExt, StreamExt};
use uuid::Uuid;

use picrypt_common::protocol::{WsClientMessage, WsServerMessage};

use crate::state::AppState;

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    req: axum::extract::Request,
) -> Result<impl IntoResponse, axum::http::StatusCode> {
    // The auth middleware already validated the token and injected the device ID.
    let device_id = req
        .extensions()
        .get::<Uuid>()
        .copied()
        .ok_or(axum::http::StatusCode::UNAUTHORIZED)?;

    Ok(ws.on_upgrade(move |socket| handle_socket(socket, state, device_id)))
}

async fn handle_socket(socket: WebSocket, state: Arc<AppState>, device_id: Uuid) {
    state.mark_connected(device_id).await;

    let (mut ws_tx, mut ws_rx) = socket.split();
    let mut lock_rx = state.subscribe_lock();

    // Spawn a task that forwards broadcast messages (lock/unsealed/shutdown)
    // to this client. The task used to close the socket after sending a
    // `Lock` — in v0.1.9+ we keep the socket open so that a subsequent
    // `Unsealed` broadcast can reach the same client, letting it auto-remount
    // without a manual `picrypt unlock` re-run. `Shutdown` still terminates
    // the forwarder because there will be no further messages.
    let tx_handle = tokio::spawn(async move {
        loop {
            match lock_rx.recv().await {
                Ok(msg) => {
                    let json = match serde_json::to_string(&msg) {
                        Ok(j) => j,
                        Err(e) => {
                            tracing::error!("failed to serialize WS message: {e}");
                            continue;
                        }
                    };
                    if ws_tx.send(Message::Text(json.into())).await.is_err() {
                        // Client disconnected.
                        break;
                    }
                    if matches!(msg, WsServerMessage::Shutdown) {
                        let _ = ws_tx.close().await;
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!("device {device_id} lagged {n} messages on broadcast");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    break;
                }
            }
        }
    });

    // Read incoming messages from the client (heartbeats).
    while let Some(msg) = ws_rx.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                match serde_json::from_str::<WsClientMessage>(&text) {
                    Ok(WsClientMessage::Heartbeat { device_id: _id }) => {
                        tracing::debug!("heartbeat from device {device_id}");
                        // Reset the dead man's switch timer.
                        state.touch_activity();
                    }
                    Err(e) => {
                        tracing::warn!("invalid WS message from {device_id}: {e}");
                    }
                }
            }
            Ok(Message::Close(_)) => break,
            Err(e) => {
                tracing::warn!("WS error from device {device_id}: {e}");
                break;
            }
            _ => {}
        }
    }

    // Cleanup: abort the broadcast forwarder and mark device disconnected.
    tx_handle.abort();
    state.mark_disconnected(&device_id).await;
}
