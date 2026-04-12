use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use picrypt_common::protocol::ErrorResponse;

/// Server-specific error type that maps to HTTP responses.
/// SECURITY: Error responses must NOT leak internal state (device existence,
/// revocation status, sealed vs locked distinction) to unauthenticated callers.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("server is sealed")]
    Sealed,

    #[error("server is locked")]
    Locked,

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("device not found: {0}")]
    DeviceNotFound(String),

    #[error("device already exists: {0}")]
    DeviceAlreadyExists(String),

    #[error("device revoked: {0}")]
    DeviceRevoked(String),

    #[error("invalid password")]
    InvalidPassword,

    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            // Both sealed and locked return the same generic message.
            ApiError::Sealed | ApiError::Locked => (
                StatusCode::SERVICE_UNAVAILABLE,
                "server unavailable".to_string(),
            ),
            // All auth failures return the same generic message.
            ApiError::Unauthorized(_)
            | ApiError::DeviceNotFound(_)
            | ApiError::DeviceRevoked(_)
            | ApiError::InvalidPassword => (StatusCode::UNAUTHORIZED, "unauthorized".to_string()),
            ApiError::DeviceAlreadyExists(_) => (StatusCode::CONFLICT, "conflict".to_string()),
            ApiError::Internal(msg) => {
                tracing::error!("internal error: {msg}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".to_string(),
                )
            }
        };

        let body = axum::Json(ErrorResponse { error: message });
        (status, body).into_response()
    }
}

impl From<picrypt_common::error::PicryptError> for ApiError {
    fn from(err: picrypt_common::error::PicryptError) -> Self {
        use picrypt_common::error::PicryptError;
        match err {
            PicryptError::ServerSealed => ApiError::Sealed,
            PicryptError::ServerLocked => ApiError::Locked,
            PicryptError::AuthFailed(msg) => ApiError::Unauthorized(msg),
            PicryptError::DeviceNotFound(id) => ApiError::DeviceNotFound(id),
            PicryptError::DeviceAlreadyExists(name) => ApiError::DeviceAlreadyExists(name),
            PicryptError::DeviceRevoked(id) => ApiError::DeviceRevoked(id),
            PicryptError::InvalidPassword => ApiError::InvalidPassword,
            other => ApiError::Internal(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;

    /// Extract the status code and body string from an ApiError response.
    fn response_parts(err: ApiError) -> (StatusCode, String) {
        let response = err.into_response();
        let status = response.status();
        let body = response.into_body();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let body_bytes =
            rt.block_on(async { axum::body::to_bytes(body, usize::MAX).await.unwrap() });
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

        (status, body_str)
    }

    #[test]
    fn sealed_and_locked_same_status_and_message() {
        let (sealed_status, sealed_body) = response_parts(ApiError::Sealed);
        let (locked_status, locked_body) = response_parts(ApiError::Locked);

        assert_eq!(sealed_status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(locked_status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            sealed_body.contains("server unavailable"),
            "Sealed body should say 'server unavailable', got: {sealed_body}"
        );
        assert!(
            locked_body.contains("server unavailable"),
            "Locked body should say 'server unavailable', got: {locked_body}"
        );
        assert_eq!(
            sealed_body, locked_body,
            "Sealed and Locked must produce identical response bodies"
        );
    }

    #[test]
    fn auth_errors_return_generic_401() {
        let variants = vec![
            ApiError::Unauthorized("bad token".to_string()),
            ApiError::DeviceNotFound("abc-123".to_string()),
            ApiError::DeviceRevoked("def-456".to_string()),
            ApiError::InvalidPassword,
        ];

        for err in variants {
            let label = format!("{err:?}");
            let (status, body) = response_parts(err);

            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "{label} should return 401"
            );
            assert!(
                body.contains("unauthorized"),
                "{label} body should say 'unauthorized', got: {body}"
            );
        }
    }

    #[test]
    fn no_error_leaks_device_id() {
        let device_id = "abc-123-secret-device-id";
        let (_status, body) = response_parts(ApiError::DeviceNotFound(device_id.to_string()));

        assert!(
            !body.contains(device_id),
            "response body must NOT contain device ID '{device_id}', got: {body}"
        );
    }
}
