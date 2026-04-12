use thiserror::Error;

#[derive(Debug, Error)]
pub enum PicryptError {
    #[error("server is sealed — unseal required before operations")]
    ServerSealed,

    #[error("server is locked — panic lock active, must unseal")]
    ServerLocked,

    #[error("authentication failed: {0}")]
    AuthFailed(String),

    #[error("device not found: {0}")]
    DeviceNotFound(String),

    #[error("device already registered: {0}")]
    DeviceAlreadyExists(String),

    #[error("device has been revoked: {0}")]
    DeviceRevoked(String),

    #[error("encryption error: {0}")]
    Encryption(String),

    #[error("decryption error: {0}")]
    Decryption(String),

    #[error("key derivation error: {0}")]
    KeyDerivation(String),

    #[error("invalid keyfile data: {0}")]
    InvalidKeyfile(String),

    #[error("invalid password")]
    InvalidPassword,

    #[error("storage error: {0}")]
    Storage(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, PicryptError>;
