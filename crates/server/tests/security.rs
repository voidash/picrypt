mod helpers;

use helpers::TestServer;
use uuid::Uuid;

const TEST_PASSWORD: &str = "test-password-for-security";

// ---------------------------------------------------------------------------
// Generic error responses
// ---------------------------------------------------------------------------

#[tokio::test]
async fn error_responses_are_generic_for_auth() {
    let server = TestServer::start_default().await;
    server.unseal(TEST_PASSWORD).await;

    let random_uuid = Uuid::new_v4();
    let fake_token =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0xABu8; 32]);

    let resp = server.get_key(random_uuid, &fake_token).await;
    assert_eq!(resp.status().as_u16(), 401);

    let body = resp.text().await.unwrap();

    // The response body must NOT contain the random UUID -- that would leak
    // information about which device IDs exist or don't exist.
    assert!(
        !body.contains(&random_uuid.to_string()),
        "error response must not echo back the requested UUID. Body: {body}"
    );

    // The body should either be empty (middleware bare 401) or a generic JSON error.
    // In either case it must NOT contain device-specific information.
    if !body.is_empty() {
        let parsed: serde_json::Value =
            serde_json::from_str(&body).expect("non-empty 401 body should be valid JSON");
        assert_eq!(
            parsed["error"], "unauthorized",
            "error message should be generic 'unauthorized', got: {parsed}"
        );
    }
    // Empty body on 401 is acceptable -- it reveals nothing.
}

// ---------------------------------------------------------------------------
// Sealed vs locked indistinguishable
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sealed_and_locked_indistinguishable() {
    let server = TestServer::start_default().await;

    // Fresh start: server is sealed.
    let sealed_hb: serde_json::Value = server.heartbeat().await.json().await.unwrap();
    let sealed_state = sealed_hb["state"].as_str().unwrap().to_string();

    // Unseal, then lock.
    server.unseal(TEST_PASSWORD).await;
    let resp = server.lock(None).await;
    assert_eq!(resp.status().as_u16(), 200);

    let locked_hb: serde_json::Value = server.heartbeat().await.json().await.unwrap();
    let locked_state = locked_hb["state"].as_str().unwrap().to_string();

    // Both should show "sealed" -- the lock transitions through Locked back to Sealed.
    // From an external observer's perspective, sealed and post-lock are identical.
    assert_eq!(
        sealed_state, locked_state,
        "sealed and locked states must be indistinguishable to external observers. \
         sealed={sealed_state}, locked={locked_state}"
    );

    // Additionally, verify that attempting to get a key returns the same status
    // code in both scenarios (we can only test post-lock here since the server
    // is the same instance, but the key point is the error type).
    let fake_token =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0xCDu8; 32]);
    let resp = server.get_key(Uuid::new_v4(), &fake_token).await;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap();

    // Middleware checks device auth before state, so 401 is expected.
    // The important thing: no distinction between "sealed" vs "locked" in response.
    assert!(
        status == 401 || status == 503,
        "expected 401 or 503, got {status}"
    );

    // Body must not leak whether the server is locked vs sealed.
    assert!(
        !body.contains("locked"),
        "response body must not reveal 'locked' state: {body}"
    );
    assert!(
        !body.contains("sealed"),
        "response body must not reveal 'sealed' state: {body}"
    );
}

// ---------------------------------------------------------------------------
// Lock purges secrets, unseal re-decrypts from disk
// ---------------------------------------------------------------------------

#[tokio::test]
async fn lock_purges_secrets() {
    let server = TestServer::start_default().await;

    // Unseal and register a device.
    server.unseal(TEST_PASSWORD).await;
    let (device_id, auth_token, keyfile_before) = server.register_device("lock-test").await;

    // Verify we can get the key.
    let resp = server.get_key(device_id, &auth_token).await;
    assert_eq!(resp.status().as_u16(), 200);

    // Lock the server -- this purges all in-memory secrets.
    let resp = server.lock(None).await;
    assert_eq!(resp.status().as_u16(), 200);

    // Unseal again with the same password.
    let resp = server.unseal(TEST_PASSWORD).await;
    assert_eq!(resp.status().as_u16(), 200);

    // Get the key again -- should work because keys are re-decrypted from disk.
    let resp = server.get_key(device_id, &auth_token).await;
    assert_eq!(resp.status().as_u16(), 200);

    let key_body: serde_json::Value = resp.json().await.unwrap();
    let keyfile_after = key_body["keyfile"].as_str().unwrap().to_string();

    // The keyfile must be the same as before the lock/unseal cycle.
    assert_eq!(
        keyfile_before, keyfile_after,
        "keyfile must survive a lock/unseal cycle (re-decrypted from disk)"
    );
}

// ---------------------------------------------------------------------------
// Revoked device cannot get key
// ---------------------------------------------------------------------------

#[tokio::test]
async fn revoked_device_cannot_get_key() {
    let server = TestServer::start_default().await;
    server.unseal(TEST_PASSWORD).await;

    let (device_id, auth_token, _) = server.register_device("revoke-me").await;

    // Verify key access works before revocation.
    let resp = server.get_key(device_id, &auth_token).await;
    assert_eq!(resp.status().as_u16(), 200);

    // Revoke the device.
    let resp = server.revoke_device(device_id).await;
    assert_eq!(resp.status().as_u16(), 200);

    // Attempt to get key -- should fail with 401.
    let resp = server.get_key(device_id, &auth_token).await;
    assert_eq!(resp.status().as_u16(), 401);
}

// ---------------------------------------------------------------------------
// Admin token not leaked in heartbeat
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_token_not_in_heartbeat_response() {
    let server = TestServer::start_default().await;

    let resp = server.heartbeat().await;
    assert_eq!(resp.status().as_u16(), 200);

    let body = resp.text().await.unwrap();

    // The admin token (base64-encoded) must not appear anywhere in the heartbeat body.
    assert!(
        !body.contains(&server.admin_token),
        "heartbeat response must not contain the admin token"
    );
}
