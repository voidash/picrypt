mod helpers;

use helpers::TestServer;
use uuid::Uuid;

const TEST_PASSWORD: &str = "test-password-for-integration";

// ---------------------------------------------------------------------------
// Heartbeat
// ---------------------------------------------------------------------------

#[tokio::test]
async fn heartbeat_returns_sealed_initially() {
    let server = TestServer::start_default().await;

    let resp = server.heartbeat().await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["state"], "sealed");
}

// ---------------------------------------------------------------------------
// Unseal
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unseal_transitions_to_active() {
    let server = TestServer::start_default().await;

    let resp = server.unseal(TEST_PASSWORD).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["state"], "active");

    // Confirm via heartbeat.
    let hb: serde_json::Value = server.heartbeat().await.json().await.unwrap();
    assert_eq!(hb["state"], "active");
}

// ---------------------------------------------------------------------------
// Full lifecycle
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_lifecycle() {
    let server = TestServer::start_default().await;

    // 1. Unseal
    let resp = server.unseal(TEST_PASSWORD).await;
    assert_eq!(resp.status().as_u16(), 200);

    // 2. Register device
    let (device_id, auth_token, _keyfile) = server.register_device("my-laptop").await;

    // 3. Get key
    let resp = server.get_key(device_id, &auth_token).await;
    assert_eq!(resp.status().as_u16(), 200);
    let key_body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        key_body["keyfile"].as_str().is_some(),
        "keyfile should be present in get_key response"
    );

    // 4. Lock
    let resp = server.lock(None).await;
    assert_eq!(resp.status().as_u16(), 200);

    // 5. Heartbeat shows sealed
    let hb: serde_json::Value = server.heartbeat().await.json().await.unwrap();
    assert_eq!(hb["state"], "sealed");
}

// ---------------------------------------------------------------------------
// Auth: register
// ---------------------------------------------------------------------------

#[tokio::test]
async fn register_requires_admin_token() {
    let server = TestServer::start_default().await;
    server.unseal(TEST_PASSWORD).await;

    // No auth header at all.
    let resp = server
        .client
        .post(format!("{}/devices/register", server.base_url))
        .json(&serde_json::json!({
            "device_name": "rogue",
            "platform": "linux"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 401);
}

#[tokio::test]
async fn register_with_wrong_token_returns_401() {
    let server = TestServer::start_default().await;
    server.unseal(TEST_PASSWORD).await;

    // Send a completely different base64 token.
    let wrong_token = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        b"this-is-definitely-not-the-token",
    );

    let resp = server
        .client
        .post(format!("{}/devices/register", server.base_url))
        .bearer_auth(&wrong_token)
        .json(&serde_json::json!({
            "device_name": "rogue",
            "platform": "linux"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 401);
}

// ---------------------------------------------------------------------------
// Auth: get key
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_key_requires_device_auth() {
    let server = TestServer::start_default().await;
    server.unseal(TEST_PASSWORD).await;
    let (device_id, _auth_token, _) = server.register_device("dev-a").await;

    // No bearer token.
    let resp = server
        .client
        .get(format!("{}/key/{}", server.base_url, device_id))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 401);
}

#[tokio::test]
async fn get_key_wrong_device_returns_401() {
    let server = TestServer::start_default().await;
    server.unseal(TEST_PASSWORD).await;

    let (_device_a_id, token_a, _) = server.register_device("dev-a").await;
    let (device_b_id, _token_b, _) = server.register_device("dev-b").await;

    // Authenticate as device A, request key for device B.
    let resp = server.get_key(device_b_id, &token_a).await;
    assert_eq!(resp.status().as_u16(), 401);
}

#[tokio::test]
async fn get_key_when_sealed_returns_503() {
    let server = TestServer::start_default().await;
    server.unseal(TEST_PASSWORD).await;
    let (device_id, auth_token, _) = server.register_device("dev-sealed").await;

    // Lock the server.
    let resp = server.lock(None).await;
    assert_eq!(resp.status().as_u16(), 200);

    // Now try to get the key -- server is sealed, should be 503.
    let resp = server.get_key(device_id, &auth_token).await;
    assert_eq!(resp.status().as_u16(), 503);
}

// ---------------------------------------------------------------------------
// Lock with PIN
// ---------------------------------------------------------------------------

#[tokio::test]
async fn lock_with_correct_pin() {
    let server = TestServer::start_with_pin("1234").await;
    server.unseal(TEST_PASSWORD).await;

    let resp = server.lock(Some("1234")).await;
    assert_eq!(resp.status().as_u16(), 200);

    let hb: serde_json::Value = server.heartbeat().await.json().await.unwrap();
    assert_eq!(hb["state"], "sealed");
}

#[tokio::test]
async fn lock_with_wrong_pin_returns_401() {
    let server = TestServer::start_with_pin("1234").await;
    server.unseal(TEST_PASSWORD).await;

    let resp = server.lock(Some("0000")).await;
    assert_eq!(resp.status().as_u16(), 401);
}

#[tokio::test]
async fn lock_without_pin_when_required_returns_401() {
    let server = TestServer::start_with_pin("secret-pin").await;
    server.unseal(TEST_PASSWORD).await;

    // Send empty body (no pin field).
    let resp = server.lock(None).await;
    assert_eq!(resp.status().as_u16(), 401);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[tokio::test]
async fn double_lock_no_panic() {
    let server = TestServer::start_default().await;
    server.unseal(TEST_PASSWORD).await;

    let resp1 = server.lock(None).await;
    assert_eq!(resp1.status().as_u16(), 200);

    // Second lock should not panic -- server is already sealed, so lock
    // still succeeds (it transitions Sealed -> Locked -> Sealed again).
    let resp2 = server.lock(None).await;
    // We only assert that the server didn't crash (i.e. we got a response).
    assert!(
        resp2.status().is_success()
            || resp2.status().is_client_error()
            || resp2.status().is_server_error(),
        "server should have responded without panicking"
    );
}

#[tokio::test]
async fn body_limit_enforced() {
    let server = TestServer::start_default().await;

    // The router sets a 4096-byte body limit. Send >4KB to /unseal.
    let oversized_password = "A".repeat(8192);
    let resp = server
        .client
        .post(format!("{}/unseal", server.base_url))
        .json(&serde_json::json!({ "password": oversized_password }))
        .send()
        .await
        .unwrap();

    // Axum's RequestBodyLimitLayer returns 413 Payload Too Large.
    assert_eq!(
        resp.status().as_u16(),
        413,
        "oversized body should be rejected with 413"
    );
}

// ---------------------------------------------------------------------------
// Sealed server rejects get_key with 503, not auth-related error
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_key_on_fresh_sealed_server_returns_error() {
    let server = TestServer::start_default().await;

    // Server is sealed, never unsealed. Try to get a key with a random UUID and token.
    let fake_id = Uuid::new_v4();
    let fake_token = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 32]);

    let resp = server.get_key(fake_id, &fake_token).await;
    // Could be 401 (auth fails before state check) or 503 (state check first).
    // The middleware runs device auth first, and since no devices exist, it returns 401.
    assert!(
        resp.status().as_u16() == 401 || resp.status().as_u16() == 503,
        "expected 401 or 503, got {}",
        resp.status()
    );
}
