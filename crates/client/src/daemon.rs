use std::time::{Duration, Instant};

use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite;
use zeroize::Zeroize;

use picrypt_common::protocol::{ServerState, WsClientMessage, WsServerMessage};

use crate::config::ClientConfig;
use crate::connection::ServerClient;
use crate::platform::{self, PlatformEvent};
use crate::{veracrypt, volume};

/// Run the client daemon: maintain heartbeat + WebSocket connection,
/// mount volumes whenever the server is Active, dismount on panic/dead-man,
/// and survive lock/unseal cycles without exiting.
///
/// The daemon is a state machine over `mounted: bool`. It keeps running
/// until Ctrl+C or SIGTERM regardless of panic locks, network drops, or
/// server reboots.
///
/// Transitions:
///
/// ```text
/// Mounted   --LOCK msg-->       Dismounted  (waits for Unsealed/HTTP-sees-Active)
/// Mounted   --heartbeat_to-->   Dismounted  (dead-man)
/// Mounted   --sleep detected--> Dismounted  (wake-from-sleep guard)
/// Dismounted--Unsealed msg-->   Mounted     (fast path)
/// Dismounted--HTTP sees Active->Mounted     (slow path, backstop)
/// *          --Ctrl+C-->        EXIT (dismount on the way out)
/// *          --SIGTERM-->       EXIT (dismount on the way out)
/// ```
pub async fn run(config: &ClientConfig, client: ServerClient) -> anyhow::Result<()> {
    let device_id = config
        .device_id
        .ok_or_else(|| anyhow::anyhow!("device not registered"))?;

    let auth_token = config
        .auth_token
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("auth token not found"))?
        .clone();

    // Initial mount attempt. If the server is already Active, mount right
    // away. If it's Sealed (e.g. daemon started before the first unseal),
    // enter Dismounted and wait — subsequent state transitions via the
    // heartbeat loop will promote us to Mounted when the server is ready.
    let mut mounted = match try_mount_all(&client, &device_id, config).await {
        Ok(n) if n > 0 => {
            println!("Unlocked. {n} volume(s) mounted. Starting heartbeat daemon...");
            true
        }
        Ok(_) => {
            if config.volumes.is_empty() {
                tracing::warn!("no volumes configured — running heartbeat only");
            }
            false
        }
        Err(e) => {
            tracing::warn!(
                "initial mount failed ({e}) — entering standby; daemon will retry \
                 on next server state change"
            );
            false
        }
    };

    println!("Press Ctrl+C to lock and exit.");

    // Start sleep detection if enabled. Shared across lock/unseal cycles.
    let mut sleep_rx = if config.sleep_detection {
        tracing::info!("starting platform sleep detection");
        Some(platform::start_sleep_monitor())
    } else {
        None
    };

    // Main persistent loop. Returns only on Ctrl+C/SIGTERM/fatal error.
    let result =
        heartbeat_loop(config, &auth_token, &client, device_id, &mut sleep_rx, &mut mounted).await;

    // On any exit path, dismount if still mounted.
    if mounted {
        tracing::warn!("daemon stopping — dismounting all volumes");
        force_dismount_all(config);
    }

    result
}

/// Fetch the keyfile from the server and mount every configured volume.
/// Returns the number of volumes successfully mounted, or an error if
/// the keyfile fetch itself fails. Zero mounted volumes with a non-empty
/// volume config is reported as a normal Ok(0) — it's not fatal because
/// an individual volume might be transiently broken while others are fine.
async fn try_mount_all(
    client: &ServerClient,
    device_id: &uuid::Uuid,
    config: &ClientConfig,
) -> anyhow::Result<usize> {
    tracing::info!("fetching keyfile from server...");
    let key_resp = client.get_key(device_id).await?;
    let mut keyfile_bytes = base64::engine::general_purpose::STANDARD
        .decode(&key_resp.keyfile)
        .map_err(|e| anyhow::anyhow!("failed to decode keyfile: {e}"))?;

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
        // Not an error — the caller (daemon.rs::run) decides whether to
        // treat this as a hard failure or keep retrying on state changes.
        tracing::warn!(
            "fetched keyfile ok but no volumes mounted — check per-volume logs above"
        );
    }

    Ok(mounted_count)
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
    client: &ServerClient,
    device_id: uuid::Uuid,
    sleep_rx: &mut Option<tokio::sync::mpsc::Receiver<PlatformEvent>>,
    mounted: &mut bool,
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

    // Client-side liveness timer. Any successful HTTP probe resets this;
    // if it exceeds `heartbeat_timeout` while MOUNTED, we dismount
    // regardless of WS state. In Dismounted state the timeout is benign
    // (nothing to protect) so we just keep polling.
    let mut last_http_success = Instant::now();

    loop {
        tracing::info!("connecting WebSocket to {ws_urls}...");

        match connect_ws(&ws_urls, auth_token).await {
            Ok(ws_stream) => {
                tracing::info!("WebSocket connected");
                let result = run_ws_loop(
                    ws_stream,
                    client,
                    &device_id,
                    config,
                    heartbeat_interval,
                    heartbeat_timeout,
                    sleep_rx,
                    &mut wall_clock,
                    &mut last_http_success,
                    mounted,
                )
                .await;

                match result {
                    WsLoopResult::ShutdownReceived => {
                        tracing::warn!("server shutting down — exiting");
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

        // HTTP heartbeat fallback — used when the WS can't be established
        // at all. Reconnects WS whenever it becomes reachable again. The
        // actual remount happens back in `run_ws_loop` once we reconnect,
        // so this function doesn't need the device id.
        let fallback_result = http_heartbeat_fallback(
            client,
            config,
            heartbeat_interval,
            heartbeat_timeout,
            sleep_rx,
            &mut wall_clock,
            &mut last_http_success,
            mounted,
        )
        .await;

        match fallback_result {
            FallbackResult::ServerBack => {
                tracing::info!("server reachable again — reconnecting WebSocket");
                continue;
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
    ShutdownReceived,
    Disconnected,
    Error(String),
    CtrlC,
}

#[allow(clippy::too_many_arguments)]
async fn run_ws_loop(
    ws_stream: WsStream,
    client: &ServerClient,
    device_id: &uuid::Uuid,
    config: &ClientConfig,
    heartbeat_interval: Duration,
    heartbeat_timeout: Duration,
    sleep_rx: &mut Option<tokio::sync::mpsc::Receiver<PlatformEvent>>,
    wall_clock: &mut platform::WallClockMonitor,
    last_http_success: &mut Instant,
    mounted: &mut bool,
) -> WsLoopResult {
    let (mut ws_tx, mut ws_rx) = ws_stream.split();

    let mut heartbeat_timer = tokio::time::interval(heartbeat_interval);
    heartbeat_timer.tick().await;

    // Bound every WS write so a zombie TCP session can't wedge the select
    // branch for minutes at a time waiting on a kernel-level timeout.
    let ws_send_timeout = Duration::from_secs(5);

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
                                // LOCK received. Dismount volumes but stay
                                // subscribed — we'll re-mount when Unsealed
                                // arrives or when an HTTP probe sees Active.
                                if *mounted {
                                    tracing::warn!(
                                        "LOCK signal received — dismounting, staying in standby"
                                    );
                                    force_dismount_all(config);
                                    *mounted = false;
                                } else {
                                    tracing::info!(
                                        "LOCK signal received — already dismounted, no action"
                                    );
                                }
                            }
                            Ok(WsServerMessage::Unsealed) => {
                                // Server just transitioned SEALED -> ACTIVE.
                                // Re-fetch keyfile and re-mount if we're in
                                // standby. If already mounted, this is a
                                // stale broadcast (e.g. a redundant unseal);
                                // ignore.
                                if !*mounted {
                                    tracing::info!(
                                        "UNSEALED signal received — re-fetching keyfile and mounting"
                                    );
                                    match try_mount_all(client, device_id, config).await {
                                        Ok(n) if n > 0 => {
                                            println!(
                                                "Re-unlocked. {n} volume(s) mounted."
                                            );
                                            *mounted = true;
                                            *last_http_success = Instant::now();
                                        }
                                        Ok(_) => {
                                            tracing::warn!(
                                                "UNSEALED received but no volumes mounted — \
                                                 staying in standby"
                                            );
                                        }
                                        Err(e) => {
                                            tracing::warn!(
                                                "UNSEALED received but mount failed: {e} — \
                                                 will retry on next HTTP probe"
                                            );
                                        }
                                    }
                                } else {
                                    tracing::debug!(
                                        "UNSEALED received but already mounted — ignoring"
                                    );
                                }
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
                // Check wall clock for sleep detection. Only acts if mounted —
                // sleeping while already dismounted is a no-op.
                if wall_clock.check(heartbeat_interval.as_secs()).is_some() && *mounted {
                    tracing::warn!("wall clock jump detected (sleep) — dismounting");
                    force_dismount_all(config);
                    *mounted = false;
                }

                // HTTP liveness probe FIRST. This drives `last_http_success`
                // — the real dead-man clock. If we skipped this and relied on
                // WS send alone, a half-open TCP connection (server killed but
                // kernel hasn't torn the socket down yet) would keep us happy
                // for ~15 minutes until TCP keepalive finally notices.
                match client.heartbeat().await {
                    Ok(resp) if resp.state == ServerState::Active => {
                        *last_http_success = Instant::now();
                        tracing::debug!("http heartbeat ok");

                        // Backstop for the Unsealed WS broadcast: if we're
                        // in standby and the server is Active, mount now
                        // (e.g. talking to a v0.1.8 server that doesn't
                        // broadcast Unsealed, or we reconnected WS after
                        // missing the broadcast).
                        if !*mounted && !config.volumes.is_empty() {
                            tracing::info!(
                                "server is Active and we are in standby — re-mounting"
                            );
                            match try_mount_all(client, device_id, config).await {
                                Ok(n) if n > 0 => {
                                    println!("Re-unlocked. {n} volume(s) mounted.");
                                    *mounted = true;
                                }
                                Ok(_) => {
                                    tracing::warn!(
                                        "HTTP probe saw Active but mount produced 0 volumes"
                                    );
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "HTTP probe saw Active but keyfile fetch failed: {e}"
                                    );
                                }
                            }
                        }
                    }
                    Ok(resp) => {
                        tracing::debug!("server state is {} (not Active)", resp.state);
                        // Still a successful reach to the server — the dead
                        // man timer resets so we don't falsely dismount on a
                        // reachable-but-sealed server.
                        *last_http_success = Instant::now();
                        // If we're still mounted but the server is not
                        // Active, some other path (WS Lock) should have
                        // already told us. Log a warning but stay as is —
                        // the WS Lock branch above is the authority.
                        if *mounted {
                            tracing::warn!(
                                "HTTP probe reports {} while daemon still Mounted — \
                                 waiting for WS Lock signal",
                                resp.state
                            );
                        }
                    }
                    Err(e) => {
                        let elapsed = last_http_success.elapsed();
                        tracing::warn!(
                            "http heartbeat probe failed ({e}) — {:.0}s since last success \
                             (timeout {}s)",
                            elapsed.as_secs_f64(),
                            heartbeat_timeout.as_secs()
                        );
                    }
                }

                // Dead-man: only acts when Mounted. In standby the daemon
                // politely keeps trying to reconnect indefinitely.
                if *mounted && last_http_success.elapsed() >= heartbeat_timeout {
                    tracing::error!(
                        "HTTP heartbeat timeout ({heartbeat_timeout:?}) while mounted — \
                         dismounting, staying in standby"
                    );
                    force_dismount_all(config);
                    *mounted = false;
                }

                // THEN send WS heartbeat so the server's own dead-man gets
                // touched. Wrapped in a short timeout so a stuck socket
                // surfaces as a disconnect instead of hanging the select.
                let msg = WsClientMessage::Heartbeat { device_id: *device_id };
                let json = serde_json::to_string(&msg).unwrap_or_default();
                let send_fut = ws_tx.send(tungstenite::Message::Text(json.into()));
                match tokio::time::timeout(ws_send_timeout, send_fut).await {
                    Ok(Ok(())) => {
                        tracing::debug!("ws heartbeat sent");
                    }
                    Ok(Err(e)) => {
                        tracing::warn!("ws heartbeat send failed: {e}");
                        return WsLoopResult::Disconnected;
                    }
                    Err(_) => {
                        tracing::warn!("ws heartbeat send timed out after {ws_send_timeout:?}");
                        return WsLoopResult::Disconnected;
                    }
                }
            }

            event = sleep_event => {
                if let Some(PlatformEvent::SleepImminent) = event {
                    if *mounted {
                        tracing::warn!("sleep imminent — dismounting, staying in standby");
                        force_dismount_all(config);
                        *mounted = false;
                    }
                }
                if let Some(PlatformEvent::WokeFromSleep) = event {
                    // On wake, check wall clock — if we were asleep too long
                    // while mounted, the heartbeat branch above will catch it
                    // on the next tick. Nothing to do here.
                    if wall_clock.check(heartbeat_interval.as_secs()).is_some() && *mounted {
                        tracing::warn!("wall clock indicates long sleep — dismounting");
                        force_dismount_all(config);
                        *mounted = false;
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
    CtrlC,
}

#[allow(clippy::too_many_arguments)]
async fn http_heartbeat_fallback(
    client: &ServerClient,
    config: &ClientConfig,
    poll_interval: Duration,
    timeout: Duration,
    sleep_rx: &mut Option<tokio::sync::mpsc::Receiver<PlatformEvent>>,
    wall_clock: &mut platform::WallClockMonitor,
    last_http_success: &mut Instant,
    mounted: &mut bool,
) -> FallbackResult {
    let mut interval = tokio::time::interval(poll_interval);
    interval.tick().await;

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
                // Check wall clock.
                if wall_clock.check(poll_interval.as_secs()).is_some() && *mounted {
                    tracing::warn!("wall clock jump during fallback — dismounting");
                    force_dismount_all(config);
                    *mounted = false;
                }

                match client.heartbeat().await {
                    Ok(resp) if resp.state == ServerState::Active => {
                        *last_http_success = Instant::now();
                        return FallbackResult::ServerBack;
                    }
                    Ok(resp) => {
                        *last_http_success = Instant::now();
                        tracing::debug!(
                            "server reachable in fallback but state is {} — keeping standby",
                            resp.state
                        );
                        // Don't return — keep polling until state is Active
                        // OR we want to try the WS again. We only return on
                        // Active because a Sealed server can't promote us
                        // back to Mounted anyway.
                    }
                    Err(_) => {
                        let elapsed = last_http_success.elapsed();
                        let remaining = timeout.saturating_sub(elapsed);
                        tracing::debug!(
                            "server unreachable — {:.0}s remaining before dismount (if mounted)",
                            remaining.as_secs_f64()
                        );
                        if *mounted && elapsed >= timeout {
                            tracing::error!("dead-man timeout in fallback — dismounting");
                            force_dismount_all(config);
                            *mounted = false;
                        }
                    }
                }
            }

            event = sleep_event => {
                if let Some(PlatformEvent::SleepImminent) = event {
                    if *mounted {
                        tracing::warn!("sleep imminent during fallback — dismounting");
                        force_dismount_all(config);
                        *mounted = false;
                    }
                }
            }

            _ = tokio::signal::ctrl_c() => {
                return FallbackResult::CtrlC;
            }
        }
    }
}
