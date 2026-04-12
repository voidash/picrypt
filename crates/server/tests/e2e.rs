mod helpers;

use helpers::TestServer;

const TEST_PASSWORD: &str = "test-password-for-e2e";

// ---------------------------------------------------------------------------
// full_server_lifecycle
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_server_lifecycle() {
    let server = TestServer::start_default().await;

    // 1. Heartbeat shows sealed on a fresh server.
    let body: serde_json::Value = server.heartbeat().await.json().await.unwrap();
    assert_eq!(body["state"], "sealed", "fresh server must be sealed");

    // 2. Unseal with password.
    let resp = server.unseal(TEST_PASSWORD).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["state"], "active",
        "server must be active after unseal"
    );

    // 3. Register a device with admin token.
    let (device_id, auth_token, keyfile) = server.register_device("lifecycle-dev").await;

    // 4. Get key for the device — must match registration keyfile.
    let resp = server.get_key(device_id, &auth_token).await;
    assert_eq!(resp.status().as_u16(), 200);
    let key_body: serde_json::Value = resp.json().await.unwrap();
    let fetched_keyfile = key_body["keyfile"].as_str().expect("keyfile missing");
    assert_eq!(
        fetched_keyfile, keyfile,
        "fetched keyfile must match the one returned at registration"
    );

    // 5. Lock the server.
    let resp = server.lock(None).await;
    assert_eq!(resp.status().as_u16(), 200);
    let lock_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        lock_body["state"], "sealed",
        "server must be sealed after lock"
    );

    // 6. Heartbeat confirms sealed.
    let body: serde_json::Value = server.heartbeat().await.json().await.unwrap();
    assert_eq!(body["state"], "sealed");

    // 7. Re-unseal with the same password.
    let resp = server.unseal(TEST_PASSWORD).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["state"], "active",
        "server must be active after re-unseal"
    );

    // 8. Get key again — must be the same keyfile (keys survive lock/unseal).
    let resp = server.get_key(device_id, &auth_token).await;
    assert_eq!(resp.status().as_u16(), 200);
    let key_body: serde_json::Value = resp.json().await.unwrap();
    let keyfile_after = key_body["keyfile"].as_str().expect("keyfile missing");
    assert_eq!(
        keyfile_after, keyfile,
        "keyfile must survive a lock/unseal cycle"
    );
}

// ---------------------------------------------------------------------------
// lock_unseal_cycle_preserves_devices
// ---------------------------------------------------------------------------

#[tokio::test]
async fn lock_unseal_cycle_preserves_devices() {
    let server = TestServer::start_default().await;

    // Unseal.
    let resp = server.unseal(TEST_PASSWORD).await;
    assert_eq!(resp.status().as_u16(), 200);

    // Register 3 devices, store their credentials.
    let (id_a, token_a, keyfile_a) = server.register_device("dev-alpha").await;
    let (id_b, token_b, keyfile_b) = server.register_device("dev-beta").await;
    let (id_c, token_c, keyfile_c) = server.register_device("dev-gamma").await;

    // Lock the server.
    let resp = server.lock(None).await;
    assert_eq!(resp.status().as_u16(), 200);

    // Re-unseal with the correct password.
    let resp = server.unseal(TEST_PASSWORD).await;
    assert_eq!(resp.status().as_u16(), 200);

    // Fetch all 3 keyfiles — they must match the originals.
    for (label, device_id, token, expected_keyfile) in [
        ("alpha", id_a, &token_a, &keyfile_a),
        ("beta", id_b, &token_b, &keyfile_b),
        ("gamma", id_c, &token_c, &keyfile_c),
    ] {
        let resp = server.get_key(device_id, token).await;
        assert_eq!(
            resp.status().as_u16(),
            200,
            "device {label} key fetch should succeed after re-unseal"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        let actual = body["keyfile"].as_str().expect("keyfile missing");
        assert_eq!(
            actual, *expected_keyfile,
            "device {label} keyfile must survive lock/unseal cycle"
        );
    }
}

// ---------------------------------------------------------------------------
// wrong_password_after_init
// ---------------------------------------------------------------------------

#[tokio::test]
async fn wrong_password_after_init() {
    let server = TestServer::start_default().await;

    // Unseal with the correct password (initializes server).
    let resp = server.unseal("correct-password").await;
    assert_eq!(resp.status().as_u16(), 200);

    // Register a device so there are non-revoked devices (needed for wrong password detection).
    let _ = server.register_device("pw-test-device").await;

    // Lock.
    let resp = server.lock(None).await;
    assert_eq!(resp.status().as_u16(), 200);

    // Try unseal with wrong password — should fail with 401.
    let resp = server.unseal("wrong-password").await;
    assert_eq!(
        resp.status().as_u16(),
        401,
        "wrong password must return 401"
    );

    // Unseal with correct password — should succeed.
    let resp = server.unseal("correct-password").await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "correct password must succeed after failed attempt"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["state"], "active");
}

// ---------------------------------------------------------------------------
// rate_limiting_on_failed_unseals
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rate_limiting_on_failed_unseals() {
    let server = TestServer::start_default().await;

    // Initialize with correct password.
    let resp = server.unseal("init-password").await;
    assert_eq!(resp.status().as_u16(), 200);

    // Register a device so wrong passwords are detectable via decryption failure.
    let _ = server.register_device("rate-limit-device").await;

    // Lock.
    let resp = server.lock(None).await;
    assert_eq!(resp.status().as_u16(), 200);

    // Send 5 wrong password attempts. Each should return 401.
    for i in 1..=5 {
        let resp = server.unseal("wrong-password").await;
        assert_eq!(
            resp.status().as_u16(),
            401,
            "attempt {i}: wrong password should return 401"
        );
    }

    // 6th attempt should hit the rate limiter — returns 500.
    // The internal "retry in Ns" message is logged server-side but the HTTP
    // response body is the generic "internal server error" (security hardening
    // prevents leaking rate-limit details to attackers).
    let resp = server.unseal("also-wrong").await;
    let status = resp.status().as_u16();
    assert_eq!(
        status, 500,
        "6th failed attempt should trigger rate limit (500), got {status}"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["error"], "internal server error",
        "rate-limited response should be a generic internal error"
    );
}

// ---------------------------------------------------------------------------
// admin_token_required_for_device_ops
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_token_required_for_device_ops() {
    let server = TestServer::start_default().await;

    // Unseal.
    let resp = server.unseal(TEST_PASSWORD).await;
    assert_eq!(resp.status().as_u16(), 200);

    // POST /devices/register WITHOUT admin token — must be 401.
    let resp = server
        .client
        .post(format!("{}/devices/register", server.base_url))
        .json(&serde_json::json!({
            "device_name": "no-auth-device",
            "platform": "linux"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        401,
        "register without admin token must return 401"
    );

    // GET /devices WITHOUT admin token — must be 401.
    let resp = server
        .client
        .get(format!("{}/devices", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        401,
        "list devices without admin token must return 401"
    );

    // WITH admin token — register succeeds.
    let (_device_id, _auth_token, _keyfile) = server.register_device("authed-device").await;

    // WITH admin token — list succeeds.
    let resp = server
        .client
        .get(format!("{}/devices", server.base_url))
        .bearer_auth(&server.admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "list devices with admin token must return 200"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    let devices = body["devices"]
        .as_array()
        .expect("devices should be an array");
    assert!(
        !devices.is_empty(),
        "device list should contain at least 1 device"
    );
}

// ---------------------------------------------------------------------------
// device_revocation_prevents_key_access
// ---------------------------------------------------------------------------

#[tokio::test]
async fn device_revocation_prevents_key_access() {
    let server = TestServer::start_default().await;

    // Unseal.
    let resp = server.unseal(TEST_PASSWORD).await;
    assert_eq!(resp.status().as_u16(), 200);

    // Register device A and device B.
    let (id_a, token_a, _) = server.register_device("revoke-target").await;
    let (id_b, token_b, _) = server.register_device("survivor").await;

    // Both can access their keys.
    let resp_a = server.get_key(id_a, &token_a).await;
    assert_eq!(
        resp_a.status().as_u16(),
        200,
        "device A key access before revoke"
    );
    let resp_b = server.get_key(id_b, &token_b).await;
    assert_eq!(
        resp_b.status().as_u16(),
        200,
        "device B key access before revoke"
    );

    // Revoke device A.
    let resp = server.revoke_device(id_a).await;
    assert_eq!(resp.status().as_u16(), 200, "revocation should succeed");

    // Device A can no longer access its key — 401.
    let resp = server.get_key(id_a, &token_a).await;
    assert_eq!(resp.status().as_u16(), 401, "revoked device A must get 401");

    // Device B still works.
    let resp = server.get_key(id_b, &token_b).await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "unrevoked device B must still access its key"
    );
}

// ---------------------------------------------------------------------------
// lock_pin_enforcement
// ---------------------------------------------------------------------------

#[tokio::test]
async fn lock_pin_enforcement() {
    let server = TestServer::start_with_pin("123456").await;

    // Unseal.
    let resp = server.unseal(TEST_PASSWORD).await;
    assert_eq!(resp.status().as_u16(), 200);

    // Lock with empty body (no pin) — must fail.
    let resp = server.lock(None).await;
    assert_eq!(
        resp.status().as_u16(),
        401,
        "lock without pin when required must return 401"
    );

    // Lock with wrong pin — must fail.
    let resp = server.lock(Some("wrong")).await;
    assert_eq!(
        resp.status().as_u16(),
        401,
        "lock with wrong pin must return 401"
    );

    // Lock with correct pin — must succeed.
    let resp = server.lock(Some("123456")).await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "lock with correct pin must succeed"
    );

    // Verify sealed.
    let body: serde_json::Value = server.heartbeat().await.json().await.unwrap();
    assert_eq!(
        body["state"], "sealed",
        "server must be sealed after lock with pin"
    );
}

// ---------------------------------------------------------------------------
// websocket_receives_lock_signal
// ---------------------------------------------------------------------------

#[tokio::test]
async fn websocket_receives_lock_signal() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite;

    let server = TestServer::start_default().await;

    // Unseal.
    let resp = server.unseal(TEST_PASSWORD).await;
    assert_eq!(resp.status().as_u16(), 200);

    // Register a device to get a valid auth token.
    let (device_id, auth_token, _) = server.register_device("ws-test-device").await;

    // Build WebSocket URL from the HTTP base URL.
    let ws_url = server
        .base_url
        .replace("http://", "ws://")
        .replace("https://", "wss://");
    let ws_url = format!("{ws_url}/ws");

    // Connect with the device auth token in the Authorization header.
    let request = tungstenite::http::Request::builder()
        .uri(&ws_url)
        .header("Authorization", format!("Bearer {auth_token}"))
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header(
            "Sec-WebSocket-Key",
            tungstenite::handshake::client::generate_key(),
        )
        .header("Host", server.base_url.trim_start_matches("http://"))
        .body(())
        .expect("failed to build WS request");

    let (mut ws_stream, _) = tokio_tungstenite::connect_async(request)
        .await
        .expect("WebSocket connection failed");

    // Send a heartbeat message to verify the connection is alive.
    let heartbeat_msg = serde_json::json!({
        "type": "heartbeat",
        "device_id": device_id.to_string()
    });
    ws_stream
        .send(tungstenite::Message::Text(tungstenite::Utf8Bytes::from(
            heartbeat_msg.to_string(),
        )))
        .await
        .expect("failed to send heartbeat over WS");

    // Small delay so the server processes the heartbeat.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Trigger a lock from another "client" via HTTP.
    let resp = server.lock(None).await;
    assert_eq!(resp.status().as_u16(), 200);

    // Read the lock message from the WebSocket.
    let msg = tokio::time::timeout(std::time::Duration::from_secs(5), ws_stream.next())
        .await
        .expect("timed out waiting for WS lock message")
        .expect("WS stream ended unexpectedly")
        .expect("WS read error");

    match msg {
        tungstenite::Message::Text(text) => {
            let parsed: serde_json::Value =
                serde_json::from_str(&text).expect("lock message should be valid JSON");
            assert_eq!(
                parsed["type"], "lock",
                "expected lock message, got: {parsed}"
            );
        }
        other => panic!("expected Text message with lock signal, got: {other:?}"),
    }

    // The server should close the WebSocket after sending lock.
    // Read next message — should be Close or stream end.
    let close_result =
        tokio::time::timeout(std::time::Duration::from_secs(5), ws_stream.next()).await;
    match close_result {
        Ok(Some(Ok(tungstenite::Message::Close(_)))) => {
            // Expected: server sent a close frame.
        }
        Ok(None) => {
            // Also acceptable: stream ended (server closed without close frame).
        }
        Ok(Some(Err(_))) => {
            // Connection error after close — acceptable.
        }
        Err(_) => {
            panic!("timed out waiting for WebSocket close after lock");
        }
        Ok(Some(Ok(other))) => {
            panic!("expected Close or stream end after lock, got: {other:?}");
        }
    }
}
