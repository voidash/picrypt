use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit};
use argon2::Argon2;
use rand::RngCore;
use zeroize::Zeroize;

use crate::error::{PicryptError, Result};

/// Size of a generated keyfile in bytes.
/// VeraCrypt processes up to 1MB of keyfile data through a CRC-based pool.
/// 64 bytes of high-entropy random data is more than sufficient.
const KEYFILE_SIZE: usize = 64;

/// AES-256-GCM nonce size in bytes.
const NONCE_SIZE: usize = 12;

/// Argon2id parameters — tuned for a Raspberry Pi 4 (1-2GB usable RAM).
/// These are conservative to keep unseal time reasonable on constrained hardware.
const ARGON2_TIME_COST: u32 = 3;
const ARGON2_MEMORY_COST: u32 = 65536; // 64 MB
const ARGON2_PARALLELISM: u32 = 2;
const ARGON2_SALT_SIZE: usize = 32;

/// A 256-bit master key. Zeroized on drop.
/// The master key is generated randomly and encrypted at rest with one or
/// more "unseal keys" (password-derived, YubiKey-derived, etc.).
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct MasterKey {
    bytes: [u8; 32],
}

impl MasterKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Create from raw bytes (e.g., after decryption of the stored master key).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Generate a fresh random master key.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self { bytes }
    }
}

/// Salt + parameters needed to re-derive the master key from a password.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct KeyDerivationParams {
    pub salt: Vec<u8>,
    pub time_cost: u32,
    pub memory_cost: u32,
    pub parallelism: u32,
}

impl KeyDerivationParams {
    pub fn generate() -> Self {
        let mut salt = vec![0u8; ARGON2_SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut salt);
        Self {
            salt,
            time_cost: ARGON2_TIME_COST,
            memory_cost: ARGON2_MEMORY_COST,
            parallelism: ARGON2_PARALLELISM,
        }
    }
}

/// Derive a 256-bit master key from a password using Argon2id.
///
/// Returns the derived key. The `params` struct contains the salt and cost
/// parameters — store it alongside the encrypted keyfiles so you can re-derive
/// on unseal.
pub fn derive_master_key(password: &[u8], params: &KeyDerivationParams) -> Result<MasterKey> {
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(
            params.memory_cost,
            params.time_cost,
            params.parallelism,
            Some(32),
        )
        .map_err(|e| PicryptError::KeyDerivation(e.to_string()))?,
    );

    let mut key_bytes = [0u8; 32];
    argon2
        .hash_password_into(password, &params.salt, &mut key_bytes)
        .map_err(|e| PicryptError::KeyDerivation(e.to_string()))?;

    Ok(MasterKey { bytes: key_bytes })
}

/// Generate a random keyfile for a new device.
///
/// Returns raw bytes — the caller is responsible for encrypting before
/// persisting to disk and zeroing after use.
pub fn generate_keyfile() -> Vec<u8> {
    let mut keyfile = vec![0u8; KEYFILE_SIZE];
    rand::thread_rng().fill_bytes(&mut keyfile);
    keyfile
}

/// Generate a random 256-bit auth token for device authentication.
pub fn generate_auth_token() -> [u8; 32] {
    let mut token = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut token);
    token
}

/// Encrypt arbitrary data with AES-256-GCM.
///
/// Returns: `nonce (12 bytes) || ciphertext || tag (16 bytes)`.
/// The master key must be exactly 32 bytes.
pub fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = GenericArray::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| PicryptError::Encryption(e.to_string()))?;

    let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypt data previously encrypted with [`encrypt`].
///
/// Expects input format: `nonce (12 bytes) || ciphertext || tag (16 bytes)`.
pub fn decrypt(encrypted: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    if encrypted.len() < NONCE_SIZE + 16 {
        return Err(PicryptError::Decryption(
            "ciphertext too short — expected at least nonce + tag".into(),
        ));
    }

    let (nonce_bytes, ciphertext) = encrypted.split_at(NONCE_SIZE);
    let nonce = GenericArray::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| PicryptError::Decryption(e.to_string()))
}

/// Encode bytes as lowercase hex string.
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode a hex string to bytes.
pub fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return Err(PicryptError::Decryption("hex string has odd length".into()));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| PicryptError::Decryption(format!("invalid hex: {e}")))
        })
        .collect()
}

/// Low-cost Argon2id derivation for high-entropy inputs (e.g. YubiKey HMAC responses).
/// Not for passwords — use [`derive_master_key`] for those.
pub fn derive_key_fast(input: &[u8], context: &[u8]) -> Result<[u8; 32]> {
    let params = argon2::Params::new(1024, 1, 1, Some(32))
        .map_err(|e| PicryptError::KeyDerivation(e.to_string()))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut output = [0u8; 32];
    // Use context as salt — it doesn't need to be secret for high-entropy inputs.
    let salt = if context.len() >= 8 {
        context.to_vec()
    } else {
        let mut padded = vec![0u8; 8];
        padded[..context.len()].copy_from_slice(context);
        padded
    };

    argon2
        .hash_password_into(input, &salt, &mut output)
        .map_err(|e| PicryptError::KeyDerivation(e.to_string()))?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let key = [0xABu8; 32];
        let plaintext = b"secret keyfile data here";

        let encrypted = encrypt(plaintext, &key).expect("encryption failed");
        assert_ne!(&encrypted[NONCE_SIZE..], plaintext);

        let decrypted = decrypt(&encrypted, &key).expect("decryption failed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let key = [0xABu8; 32];
        let wrong_key = [0xCDu8; 32];
        let plaintext = b"secret";

        let encrypted = encrypt(plaintext, &key).expect("encryption failed");
        let result = decrypt(&encrypted, &wrong_key);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_truncated_input_fails() {
        let key = [0xABu8; 32];
        let result = decrypt(&[0u8; 10], &key);
        assert!(result.is_err());
    }

    #[test]
    fn keyfile_generation_is_random() {
        let k1 = generate_keyfile();
        let k2 = generate_keyfile();
        assert_eq!(k1.len(), KEYFILE_SIZE);
        assert_ne!(k1, k2);
    }

    #[test]
    fn master_key_derivation_deterministic() {
        let params = KeyDerivationParams::generate();
        let k1 = derive_master_key(b"test-password", &params).expect("derivation failed");
        let k2 = derive_master_key(b"test-password", &params).expect("derivation failed");
        assert_eq!(k1.bytes, k2.bytes);
    }

    #[test]
    fn master_key_different_passwords_differ() {
        let params = KeyDerivationParams::generate();
        let k1 = derive_master_key(b"password-a", &params).expect("derivation failed");
        let k2 = derive_master_key(b"password-b", &params).expect("derivation failed");
        assert_ne!(k1.bytes, k2.bytes);
    }

    #[test]
    fn hex_roundtrip() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF];
        let encoded = hex_encode(&data);
        assert_eq!(encoded, "deadbeef00ff");
        let decoded = hex_decode(&encoded).expect("decode failed");
        assert_eq!(decoded, data);
    }

    #[test]
    fn hex_decode_invalid() {
        assert!(hex_decode("zz").is_err());
        assert!(hex_decode("abc").is_err()); // odd length
    }

    #[test]
    fn master_key_generate_is_random() {
        let k1 = MasterKey::generate();
        let k2 = MasterKey::generate();
        assert_ne!(k1.bytes, k2.bytes);
    }

    #[test]
    fn derive_key_fast_deterministic() {
        let input = b"high-entropy-input-here-1234567890";
        let context = b"picrypt-test-context";
        let k1 = derive_key_fast(input, context).expect("derivation failed");
        let k2 = derive_key_fast(input, context).expect("derivation failed");
        assert_eq!(k1, k2);
    }

    #[test]
    fn encrypt_empty_plaintext() {
        let key = [0x42u8; 32];
        let plaintext: &[u8] = b"";

        let encrypted = encrypt(plaintext, &key).expect("encryption of empty slice failed");
        // nonce (12) + tag (16) minimum, no plaintext bytes
        assert!(encrypted.len() >= NONCE_SIZE + 16);

        let decrypted = decrypt(&encrypted, &key).expect("decryption of empty ciphertext failed");
        assert!(decrypted.is_empty());
    }

    #[test]
    fn nonce_uniqueness() {
        let key = [0xAAu8; 32];
        let data = b"same data twice";

        let ct1 = encrypt(data, &key).expect("first encryption failed");
        let ct2 = encrypt(data, &key).expect("second encryption failed");

        // The random nonces must differ, so ciphertext differs even for identical plaintext.
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn decrypt_tampered_ciphertext() {
        let key = [0xBBu8; 32];
        let plaintext = b"tamper target";

        let mut encrypted = encrypt(plaintext, &key).expect("encryption failed");
        // Flip a byte in the ciphertext body (after the nonce, before the tag).
        let mid = NONCE_SIZE + 1;
        encrypted[mid] ^= 0xFF;

        let result = decrypt(&encrypted, &key);
        assert!(
            result.is_err(),
            "decryption should fail on tampered ciphertext"
        );
    }

    #[test]
    fn decrypt_tampered_tag() {
        let key = [0xCCu8; 32];
        let plaintext = b"tag tamper target";

        let mut encrypted = encrypt(plaintext, &key).expect("encryption failed");
        // Flip the very last byte, which is part of the AES-GCM tag.
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xFF;

        let result = decrypt(&encrypted, &key);
        assert!(result.is_err(), "decryption should fail on tampered tag");
    }

    #[test]
    fn derive_master_key_empty_password() {
        let params = KeyDerivationParams::generate();
        // Empty password must not panic — it's a valid (if weak) input to Argon2.
        let result = derive_master_key(b"", &params);
        assert!(result.is_ok(), "empty password should not panic or error");
        assert_eq!(result.unwrap().as_bytes().len(), 32);
    }

    #[test]
    fn derive_key_fast_different_inputs() {
        let context = b"picrypt-test";
        let k1 = derive_key_fast(b"input-alpha", context).expect("derivation 1 failed");
        let k2 = derive_key_fast(b"input-bravo", context).expect("derivation 2 failed");
        assert_ne!(k1, k2, "different inputs must produce different keys");
    }

    #[test]
    fn master_key_from_bytes() {
        let bytes = [0x99u8; 32];
        let mk = MasterKey::from_bytes(bytes);
        assert_eq!(mk.as_bytes(), &bytes);
    }

    #[test]
    fn auth_token_size() {
        let token = generate_auth_token();
        assert_eq!(token.len(), 32, "auth token must be exactly 32 bytes");
    }
}
