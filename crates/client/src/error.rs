use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("server unreachable: {0}")]
    ServerUnreachable(String),

    #[error("server returned error: {status} — {message}")]
    ServerError { status: u16, message: String },

    #[error("not registered — run `picrypt register` first")]
    NotRegistered,

    #[error("veracrypt command failed: {0}")]
    VeraCrypt(String),

    #[error("websocket error: {0}")]
    WebSocket(String),

    #[error(
        "heartbeat timeout — server unreachable for {elapsed_secs}s (threshold: {timeout_secs}s)"
    )]
    HeartbeatTimeout {
        elapsed_secs: u64,
        timeout_secs: u64,
    },

    #[error("config error: {0}")]
    Config(String),

    #[error("{0}")]
    Other(String),
}
