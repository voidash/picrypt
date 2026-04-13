use std::time::{Duration, Instant};

use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite;
use zeroize::Zeroize;

use picrypt_common::protocol::{WsClientMessage, WsServerMessage};

use crate::config::ClientConfig;
use crate::connection::ServerClient;
use crate::platform::{self, PlatformEvent};
use crate::{veracrypt, volume};

/// Run the client daemon: fetch key, mount volumes, maintain heartbeat,
/// listen for lock signals, and monitor for system sleep.
pub async fn run(config: &ClientConfig, client: ServerClient) -> anyhow::Result<()> {
    let device_id = config
        .device_id
        .ok_or_else(|| anyhow::anyhow!("device not registered"))?;

    let auth_token = config
        .auth_token
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("auth token not found"))?
        .clone();

    // Step 1: Fetch the keyfile from the Pi.
    tracing::info!("fetching keyfile from server...");
    let key_resp = client.get_key(&device_id).await?;
    let mut keyfile_bytes = base64::engine::general_purpose::STANDARD
        .decode(&key_resp.keyfile)
        .map_err(|e| anyhow::anyhow!("failed to decode keyfile: {e}"))?;

    // Step 2: Mount each configured volume. Dispatches to a custom
    // `mount_command` if the volume sets one, otherwise falls back to
    // picrypt's built-in veracrypt integration.
    let mut mounted_count = 0;
    for vol in &config.volumes {
        match volume::mount(vol, &keyfile_bytes) {
            Ok(()) => {
                println!("Mounted: {} -> {}", vol.container, vol.mount_point);
                mounted_count += 1;
            }
            Err(e) => {
                eprintln!(
                    "Failed to mount {} -> {}: {e}",
                    vol.container, vol.mount_point
                );
            }
        }
    }

    keyfile_bytes.zeroize();

    if mounted_count == 0 && !config.volumes.is_empty() {
        anyhow::bail!("no volumes mounted successfully");
    }

    if config.volumes.is_empty() {
        tracing::warn!("no volumes configured — running heartbeat only");
    }

    println!("Unlocked. {mounted_count} volume(s) mounted. Starting heartbeat daemon...");
    println!("Press Ctrl+C to lock and exit.");

    // Step 3: Start sleep detection if enabled.
    let mut sleep_rx = if config.sleep_detection {
        tracing::info!("starting platform sleep detection");
        Some(platform::start_sleep_monitor())
    } else {
        None
    };

    // Step 4: Run the heartbeat + WebSocket + sleep monitoring loop.
    let result = heartbeat_loop(config, &auth_token, device_id, &mut sleep_rx).await;

    // Step 5: On exit, dismount everything.
    tracing::warn!("daemon stopping — dismounting all volumes");
    force_dismount_all(config);

    result
}

fn force_dismount_all(config: &ClientConfig) {
    for vol in &config.volumes {
        if let Err(e) = volume::dismount(vol) {
            tracing::error!("failed to dismount {}: {e}", vol.mount_point);
        }
    }
    // Nuclear fallback: dismount every remaining veracrypt volume so a
    // stray one left over from an earlier run doesn't keep the data visible.
    // This only affects volumes that went through the built-in veracrypt
    // path; custom-command volumes are already handled above.
    if let Err(e) = veracrypt::dismount_all() {
        tracing::error!("failed to dismount all: {e}");
    }
}

async fn heartbeat_loop(
    config: &ClientConfig,
    auth_token: &str,
    device_id: uuid::Uuid,
    sleep_rx: &mut Option<tokio::sync::mpsc::Receiver<PlatformEvent>>,
) -> anyhow::Result<()> {
    let ws_urls = {
        let base = config
            .server_url
            .replace("http://", "ws://")
            .replace("https://", "wss://");
        format!("{base}/ws")
    };

    let heartbeat_interval = Duration::from_secs(config.heartbeat_interval_secs);
    let heartbeat_timeout = Duration::from_secs(config.heartbeat_timeout_secs);
    let mut wall_clock = platform::WallClockMonitor::new();

    loop {
        tracing::info!("connecting WebSocket to {ws_urls}...");

        match connect_ws(&ws_urls, auth_token).await {
            Ok(ws_stream) => {
                tracing::info!("WebSocket connected");
                let result = run_ws_loop(
                    ws_stream,
                    device_id,
                    heartbeat_interval,
                    heartbeat_timeout,
                    sleep_rx,
                    &mut wall_clock,
                )
                .await;

                match result {
                    WsLoopResult::LockReceived => {
                        tracing::warn!("LOCK signal received — dismounting immediately");
                        return Ok(());
                    }
                    WsLoopResult::ShutdownReceived => {
                        tracing::warn!("server shutting down — dismounting");
                        return Ok(());
                    }
                    WsLoopResult::SleepDetected => {
                        tracing::warn!("system sleep detected — dismounting");
                        return Ok(());
                    }
                    WsLoopResult::Disconnected => {
                        tracing::warn!("WebSocket disconnected — falling back to HTTP heartbeat");
                    }
                    WsLoopResult::Error(e) => {
                        tracing::error!("WebSocket error: {e}");
                    }
                    WsLoopResult::CtrlC => {
                        tracing::info!("Ctrl+C received — locking");
                        return Ok(());
                    }
                }
            }
            Err(e) => {
                tracing::warn!("WebSocket connection failed: {e}");
            }
        }

        // HTTP heartbeat fallback.
        let fallback_result = http_heartbeat_fallback(
            config,
            heartbeat_interval,
            heartbeat_timeout,
            sleep_rx,
            &mut wall_clock,
        )
        .await;

        match fallback_result {
            FallbackResult::ServerBack => {
                tracing::info!("server reachable again — reconnecting WebSocket");
                continue;
            }
            FallbackResult::Timeout => {
                tracing::error!("heartbeat timeout ({heartbeat_timeout:?}) — dismounting");
                return Ok(());
            }
            FallbackResult::SleepDetected => {
                tracing::warn!("system sleep detected — dismounting");
                return Ok(());
            }
            FallbackResult::CtrlC => {
                tracing::info!("Ctrl+C received — locking");
                return Ok(());
            }
        }
    }
}

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn connect_ws(ws_url: &str, auth_token: &str) -> anyhow::Result<WsStream> {
    // Use tungstenite's IntoClientRequest to build the base request from the
    // URL — this auto-populates Host, Sec-WebSocket-Version, Sec-WebSocket-Key,
    // Connection, and Upgrade. We only need to add the Authorization header
    // on top. Building the request manually via Request::builder() is what
    // caused the "Missing, duplicated or incorrect header host" error prior
    // to v0.1.5 — a custom builder replaces ALL headers and tungstenite does
    // not re-populate Host.
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let mut request = ws_url
        .into_client_request()
        .map_err(|e| anyhow::anyhow!("failed to build WS request from URL: {e}"))?;

    let auth_value = format!("Bearer {auth_token}")
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid Authorization header value: {e}"))?;
    request.headers_mut().insert("Authorization", auth_value);

    let (ws_stream, _response) = tokio_tungstenite::connect_async(request)
        .await
        .map_err(|e| anyhow::anyhow!("WebSocket connect failed: {e}"))?;

    Ok(ws_stream)
}

enum WsLoopResult {
    LockReceived,
    ShutdownReceived,
    SleepDetected,
    Disconnected,
    Error(String),
    CtrlC,
}

async fn run_ws_loop(
    ws_stream: WsStream,
    device_id: uuid::Uuid,
    heartbeat_interval: Duration,
    _heartbeat_timeout: Duration,
    sleep_rx: &mut Option<tokio::sync::mpsc::Receiver<PlatformEvent>>,
    wall_clock: &mut platform::WallClockMonitor,
) -> WsLoopResult {
    let (mut ws_tx, mut ws_rx) = ws_stream.split();

    let mut heartbeat_timer = tokio::time::interval(heartbeat_interval);
    heartbeat_timer.tick().await;

    loop {
        // Build a future for sleep events (or a never-completing future if disabled).
        let sleep_event = async {
            if let Some(ref mut rx) = sleep_rx {
                rx.recv().await
            } else {
                std::future::pending::<Option<PlatformEvent>>().await
            }
        };

        tokio::select! {
            msg = ws_rx.next() => {
                match msg {
                    Some(Ok(tungstenite::Message::Text(text))) => {
                        match serde_json::from_str::<WsServerMessage>(&text) {
                            Ok(WsServerMessage::Lock) => {
                                return WsLoopResult::LockReceived;
                            }
                            Ok(WsServerMessage::Shutdown) => {
                                return WsLoopResult::ShutdownReceived;
                            }
                            Ok(WsServerMessage::HeartbeatAck { .. }) => {
                                tracing::debug!("heartbeat ack received");
                            }
                            Err(e) => {
                                tracing::warn!("failed to parse server WS message: {e}");
                            }
                        }
                    }
                    Some(Ok(tungstenite::Message::Close(_))) => {
                        return WsLoopResult::Disconnected;
                    }
                    Some(Err(e)) => {
                        return WsLoopResult::Error(e.to_string());
                    }
                    None => {
                        return WsLoopResult::Disconnected;
                    }
                    _ => {}
                }
            }

            _ = heartbeat_timer.tick() => {
                // Check wall clock for sleep detection.
                if wall_clock.check(heartbeat_interval.as_secs()).is_some() {
                    return WsLoopResult::SleepDetected;
                }

                let msg = WsClientMessage::Heartbeat { device_id };
                let json = serde_json::to_string(&msg).unwrap_or_default();
                if ws_tx.send(tungstenite::Message::Text(json.into())).await.is_err() {
                    return WsLoopResult::Disconnected;
                }
                tracing::debug!("heartbeat sent");
            }

            event = sleep_event => {
                if let Some(PlatformEvent::SleepImminent) = event {
                    return WsLoopResult::SleepDetected;
                }
                if let Some(PlatformEvent::WokeFromSleep) = event {
                    // On wake, check wall clock — if we were asleep too long, dismount.
                    if wall_clock.check(heartbeat_interval.as_secs()).is_some() {
                        return WsLoopResult::SleepDetected;
                    }
                }
            }

            _ = tokio::signal::ctrl_c() => {
                return WsLoopResult::CtrlC;
            }
        }
    }
}

enum FallbackResult {
    ServerBack,
    Timeout,
    SleepDetected,
    CtrlC,
}

async fn http_heartbeat_fallback(
    config: &ClientConfig,
    poll_interval: Duration,
    timeout: Duration,
    sleep_rx: &mut Option<tokio::sync::mpsc::Receiver<PlatformEvent>>,
    wall_clock: &mut platform::WallClockMonitor,
) -> FallbackResult {
    let start = Instant::now();
    let mut interval = tokio::time::interval(poll_interval);
    interval.tick().await;

    let client = match crate::connection::ServerClient::new(config) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("failed to create HTTP client for fallback: {e}");
            return FallbackResult::Timeout;
        }
    };

    loop {
        let sleep_event = async {
            if let Some(ref mut rx) = sleep_rx {
                rx.recv().await
            } else {
                std::future::pending::<Option<PlatformEvent>>().await
            }
        };

        tokio::select! {
            _ = interval.tick() => {
                let elapsed = start.elapsed();
                if elapsed >= timeout {
                    return FallbackResult::Timeout;
                }

                // Check wall clock.
                if wall_clock.check(poll_interval.as_secs()).is_some() {
                    return FallbackResult::SleepDetected;
                }

                match client.heartbeat().await {
                    Ok(resp) => {
                        if resp.state == picrypt_common::protocol::ServerState::Active {
                            return FallbackResult::ServerBack;
                        }
                        tracing::warn!("server is {} — treating as lock", resp.state);
                        return FallbackResult::Timeout;
                    }
                    Err(_) => {
                        let remaining = timeout.saturating_sub(elapsed);
                        tracing::debug!(
                            "server unreachable — {:.0}s remaining before dismount",
                            remaining.as_secs_f64()
                        );
                    }
                }
            }

            event = sleep_event => {
                if let Some(PlatformEvent::SleepImminent) = event {
                    return FallbackResult::SleepDetected;
                }
            }

            _ = tokio::signal::ctrl_c() => {
                return FallbackResult::CtrlC;
            }
        }
    }
}
