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

// ---------------------------------------------------------------------------
// /admin-token — reveals the admin token to anyone with the master password
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_token_endpoint_returns_token_with_correct_password() {
    let server = TestServer::start_default().await;

    // First-time unseal sets the master password.
    let unseal_resp = server.unseal(TEST_PASSWORD).await;
    assert_eq!(unseal_resp.status().as_u16(), 200);

    // Ask for the admin token.
    let resp = server.get_admin_token(TEST_PASSWORD).await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "/admin-token with correct password must succeed"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    let token = body["admin_token"].as_str().expect("missing admin_token");
    assert!(!token.is_empty(), "admin_token must not be empty");

    // The returned token must actually authorize device management.
    // Use it to register a device — same flow that admin_auth_middleware
    // verifies, so this proves we got the real token.
    let register_resp = reqwest::Client::new()
        .post(format!("{}/devices/register", server.base_url))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "device_name": "registered-via-revealed-token",
            "platform": "linux"
        }))
        .send()
        .await
        .expect("register request failed");
    assert_eq!(
        register_resp.status().as_u16(),
        200,
        "the returned admin token must authorize /devices/register"
    );
}

#[tokio::test]
async fn admin_token_endpoint_rejects_wrong_password() {
    let server = TestServer::start_default().await;

    // Initialize the keystore.
    server.unseal(TEST_PASSWORD).await;

    let resp = server.get_admin_token("the-wrong-password").await;
    assert_eq!(
        resp.status().as_u16(),
        401,
        "wrong password must return 401"
    );

    // Body must NOT contain the actual token.
    let body = resp.text().await.unwrap();
    assert!(
        !body.contains("admin_token"),
        "401 response body must not leak token: {body}"
    );
}

#[tokio::test]
async fn admin_token_endpoint_works_when_sealed() {
    let server = TestServer::start_default().await;

    // Initialize, then lock back to sealed.
    server.unseal(TEST_PASSWORD).await;
    server.lock(None).await;
    let hb: serde_json::Value = server.heartbeat().await.json().await.unwrap();
    assert_eq!(hb["state"], "sealed");

    // Sealed → still works (this is the whole point: master password
    // can recover the admin token without unsealing first).
    let resp = server.get_admin_token(TEST_PASSWORD).await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "/admin-token must work even when server is sealed"
    );

    // After fetching the token, the server must STILL be sealed
    // (the endpoint must not transition state).
    let hb_after: serde_json::Value = server.heartbeat().await.json().await.unwrap();
    assert_eq!(
        hb_after["state"], "sealed",
        "/admin-token must not change server state"
    );
}

#[tokio::test]
async fn admin_token_endpoint_uninitialized_errors() {
    let server = TestServer::start_default().await;

    // Server has never been unsealed — no master_key.enc on disk.
    let resp = server.get_admin_token("anything").await;
    // Either 4xx or 5xx is acceptable; 200 would be a leak.
    assert!(
        resp.status().as_u16() >= 400,
        "fresh-uninstalled server must reject /admin-token, got {}",
        resp.status()
    );
}

// ---------------------------------------------------------------------------
// v0.1.7 dual-factor unseal
//
// These tests fake the YubiKey by passing a deterministic 20-byte
// "response" hex. The server doesn't know or care that it's not from
// real hardware — it Argon2id-expands the 20 bytes into the dual-factor
// wrapping key whether they came from ykchalresp or from a test fixture.
// ---------------------------------------------------------------------------

const TEST_YK_CHALLENGE_HEX: &str =
    "ad7c1236c65101fb9740579f9e34c533e251ed11464346bed85d75e6ea1f0faa";
const TEST_YK_RESPONSE_OK: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // 20 bytes of 0xAA
const TEST_YK_RESPONSE_BAD: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"; // 20 bytes of 0xBB

#[tokio::test]
async fn unseal_challenge_before_enrollment_reports_unavailable() {
    let server = TestServer::start_default().await;

    // Single-factor init so the server has SOMETHING to unseal with later,
    // but no dual-factor blob yet.
    server.unseal(TEST_PASSWORD).await;

    let resp = server.get_unseal_challenge().await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["dual_factor_available"], false);
    assert_eq!(body["dual_factor_required"], false);
    assert_eq!(body["challenge_hex"], "");
}

#[tokio::test]
async fn enroll_dual_factor_success() {
    let server = TestServer::start_default().await;

    // Init with password, then enroll dual factor.
    server.unseal(TEST_PASSWORD).await;

    let resp = server
        .enroll_dual_factor(TEST_PASSWORD, TEST_YK_CHALLENGE_HEX, TEST_YK_RESPONSE_OK)
        .await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "enroll should succeed, got {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["state"], "active");
    // Single-factor blob still on disk until finalize.
    assert_eq!(body["single_factor_still_present"], true);

    // Challenge is now advertised.
    let challenge_resp = server.get_unseal_challenge().await;
    let challenge_body: serde_json::Value = challenge_resp.json().await.unwrap();
    assert_eq!(challenge_body["dual_factor_available"], true);
    assert_eq!(challenge_body["challenge_hex"], TEST_YK_CHALLENGE_HEX);
}

#[tokio::test]
async fn enroll_dual_factor_rejects_wrong_password() {
    let server = TestServer::start_default().await;
    server.unseal(TEST_PASSWORD).await;

    let resp = server
        .enroll_dual_factor("wrong-password", TEST_YK_CHALLENGE_HEX, TEST_YK_RESPONSE_OK)
        .await;
    assert!(resp.status().as_u16() >= 400);
}

#[tokio::test]
async fn enroll_dual_factor_requires_admin_token() {
    let server = TestServer::start_default().await;
    server.unseal(TEST_PASSWORD).await;

    // Bypass the helper to send WITHOUT admin auth.
    let resp = server
        .client
        .post(format!("{}/admin/dual-factor/enroll", server.base_url))
        .json(&serde_json::json!({
            "password": TEST_PASSWORD,
            "yubikey_challenge_hex": TEST_YK_CHALLENGE_HEX,
            "yubikey_response_hex": TEST_YK_RESPONSE_OK,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);
}

#[tokio::test]
async fn dual_factor_unseal_round_trip() {
    let server = TestServer::start_default().await;

    // Phase 1: initial password unseal.
    server.unseal(TEST_PASSWORD).await;

    // Phase 2: enroll dual factor.
    let enroll = server
        .enroll_dual_factor(TEST_PASSWORD, TEST_YK_CHALLENGE_HEX, TEST_YK_RESPONSE_OK)
        .await;
    assert_eq!(enroll.status().as_u16(), 200);

    // Phase 3: lock.
    let lock = server.lock(None).await;
    assert_eq!(lock.status().as_u16(), 200);

    // Phase 4: dual-factor unseal with correct inputs.
    let resp = server
        .unseal_dual_factor(TEST_PASSWORD, TEST_YK_RESPONSE_OK)
        .await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "dual-factor unseal should succeed, got {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["state"], "active");
}

#[tokio::test]
async fn dual_factor_unseal_wrong_password_fails() {
    let server = TestServer::start_default().await;
    server.unseal(TEST_PASSWORD).await;
    server
        .enroll_dual_factor(TEST_PASSWORD, TEST_YK_CHALLENGE_HEX, TEST_YK_RESPONSE_OK)
        .await;
    server.lock(None).await;

    let resp = server
        .unseal_dual_factor("wrong-password", TEST_YK_RESPONSE_OK)
        .await;
    assert!(resp.status().as_u16() >= 400);
}

#[tokio::test]
async fn dual_factor_unseal_wrong_yk_response_fails() {
    let server = TestServer::start_default().await;
    server.unseal(TEST_PASSWORD).await;
    server
        .enroll_dual_factor(TEST_PASSWORD, TEST_YK_CHALLENGE_HEX, TEST_YK_RESPONSE_OK)
        .await;
    server.lock(None).await;

    let resp = server
        .unseal_dual_factor(TEST_PASSWORD, TEST_YK_RESPONSE_BAD)
        .await;
    assert!(resp.status().as_u16() >= 400);
}

#[tokio::test]
async fn finalize_removes_single_factor_blob() {
    let server = TestServer::start_default().await;
    server.unseal(TEST_PASSWORD).await;
    server
        .enroll_dual_factor(TEST_PASSWORD, TEST_YK_CHALLENGE_HEX, TEST_YK_RESPONSE_OK)
        .await;

    let finalize = server.finalize_dual_factor().await;
    assert_eq!(finalize.status().as_u16(), 200);
    let body: serde_json::Value = finalize.json().await.unwrap();
    assert_eq!(body["dual_factor_only"], true);

    // Post-finalize, dual-factor unseal still works after a lock/unseal cycle.
    server.lock(None).await;
    let resp = server
        .unseal_dual_factor(TEST_PASSWORD, TEST_YK_RESPONSE_OK)
        .await;
    assert_eq!(resp.status().as_u16(), 200);

    // Post-finalize, single-factor unseal should fail because the old
    // blob is gone. Server will return an error (either from
    // unseal_password missing the blob, or from require_dual_factor if
    // it was enabled).
    server.lock(None).await;
    let sf_resp = server.unseal(TEST_PASSWORD).await;
    assert!(
        sf_resp.status().as_u16() >= 400,
        "single-factor unseal after finalize should fail, got {}",
        sf_resp.status()
    );
}
