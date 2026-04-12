//! YubiKey HMAC-SHA1 challenge-response via the `ykchalresp` CLI.
//!
//! This shells out to the YubiKey tools rather than using USB HID directly,
//! which is simpler and works across macOS, Linux, and Windows as long as
//! `yubikey-manager` (ykman) or `ykchalresp` is installed.

use std::process::Command;

use rand::RngCore;

use crate::crypto;
use crate::error::{PicryptError, Result};

/// Size of the challenge in bytes. HMAC-SHA1 supports up to 64 bytes.
const CHALLENGE_SIZE: usize = 32;

/// Size of the HMAC-SHA1 response in bytes (SHA-1 output = 20 bytes).
const RESPONSE_SIZE: usize = 20;

/// Context salt for deriving a 256-bit key from the 160-bit HMAC response.
const YUBIKEY_KDF_CONTEXT: &[u8] = b"picrypt-yubikey-kdf-v1";

/// Generate a random challenge for YubiKey HMAC-SHA1.
pub fn generate_challenge() -> Vec<u8> {
    let mut challenge = vec![0u8; CHALLENGE_SIZE];
    rand::thread_rng().fill_bytes(&mut challenge);
    challenge
}

/// Perform HMAC-SHA1 challenge-response with a YubiKey.
///
/// Requires `ykchalresp` to be installed and a YubiKey with HMAC-SHA1
/// configured in slot 2 to be physically connected.
///
/// Returns the 20-byte HMAC-SHA1 response.
pub fn challenge_response(challenge: &[u8]) -> Result<Vec<u8>> {
    let challenge_hex = crypto::hex_encode(challenge);

    // Try `ykchalresp` first (from yubikey-personalization package).
    let output = Command::new("ykchalresp")
        .args(["-2", "-H", &challenge_hex])
        .output()
        .map_err(|e| {
            PicryptError::Encryption(format!(
                "failed to run ykchalresp — is yubikey-personalization installed? {e}"
            ))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(PicryptError::Encryption(format!(
            "ykchalresp failed (is a YubiKey connected with HMAC-SHA1 in slot 2?): {stderr}"
        )));
    }

    let response_hex = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let response = crypto::hex_decode(&response_hex)?;

    if response.len() != RESPONSE_SIZE {
        return Err(PicryptError::Encryption(format!(
            "unexpected HMAC response length: expected {RESPONSE_SIZE}, got {}",
            response.len()
        )));
    }

    Ok(response)
}

/// Derive a 256-bit AES key from a YubiKey HMAC-SHA1 response.
///
/// Uses a fast Argon2id pass (the input is already high-entropy, so
/// expensive key stretching isn't needed — we just need to expand
/// 160 bits to 256 bits deterministically).
pub fn derive_key_from_response(response: &[u8]) -> Result<[u8; 32]> {
    crypto::derive_key_fast(response, YUBIKEY_KDF_CONTEXT)
}

/// Full flow: challenge a YubiKey and derive a 256-bit key.
/// Combines [`challenge_response`] and [`derive_key_from_response`].
pub fn challenge_and_derive(challenge: &[u8]) -> Result<[u8; 32]> {
    let response = challenge_response(challenge)?;
    derive_key_from_response(&response)
}

/// Check if `ykchalresp` is available on this system.
pub fn is_available() -> bool {
    Command::new("ykchalresp")
        .arg("-V")
        .output()
        .is_ok_and(|o| o.status.success())
}
