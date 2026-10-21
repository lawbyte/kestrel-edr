//! REST error type: `{"error": {"code": "...", "message": "..."}}`.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    /// Extra fields merged into the `error` object (e.g. `mfa_required`).
    pub extra: Option<serde_json::Value>,
}

pub type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        ApiError {
            status,
            code,
            message: message.into(),
            extra: None,
        }
    }
    pub fn bad_request(m: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", m)
    }
    pub fn unauthorized(m: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", m)
    }
    pub fn forbidden(m: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", m)
    }
    pub fn not_found(m: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", m)
    }
    pub fn conflict(m: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", m)
    }
    pub fn rate_limited(m: impl Into<String>) -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited", m)
    }
    pub fn internal(m: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", m)
    }
    /// 411: a streaming upload without `Content-Length`.
    pub fn length_required(m: impl Into<String>) -> Self {
        Self::new(StatusCode::LENGTH_REQUIRED, "length_required", m)
    }
    /// 413: a transfer above the size limit.
    pub fn payload_too_large(m: impl Into<String>) -> Self {
        Self::new(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large", m)
    }
    /// 503: the endpoint cannot serve the request right now.
    pub fn unavailable(m: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, "unavailable", m)
    }
    /// 504: the agent did not answer in time.
    pub fn gateway_timeout(m: impl Into<String>) -> Self {
        Self::new(StatusCode::GATEWAY_TIMEOUT, "gateway_timeout", m)
    }
    pub fn with_extra(mut self, extra: serde_json::Value) -> Self {
        self.extra = Some(extra);
        self
    }
    /// Add one field to the `error` object (keeps earlier extra fields).
    pub fn with_field(mut self, key: &str, value: impl Into<serde_json::Value>) -> Self {
        let mut obj = match self.extra.take() {
            Some(serde_json::Value::Object(o)) => o,
            _ => serde_json::Map::new(),
        };
        obj.insert(key.to_string(), value.into());
        self.extra = Some(serde_json::Value::Object(obj));
        self
    }
    /// Remote-access failures carry the agent's `RemoteErrorCode` as `remote_code`.
    pub fn with_remote_code(self, code: kestrel_common::remote::RemoteErrorCode) -> Self {
        self.with_field("remote_code", code.as_str())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut err = json!({"code": self.code, "message": self.message});
        if let (Some(serde_json::Value::Object(extra)), Some(obj)) =
            (self.extra, err.as_object_mut())
        {
            for (k, v) in extra {
                obj.insert(k, v);
            }
        }
        (self.status, Json(json!({ "error": err }))).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        if let sqlx::Error::Database(db) = &e {
            match db.code().as_deref() {
                Some("23505") => return ApiError::conflict("already exists"),
                Some("23503") => {
                    return ApiError::conflict(
                        "referenced object does not exist or is still in use",
                    )
                }
                Some("22P02") => return ApiError::bad_request("invalid identifier"),
                _ => {}
            }
        }
        if matches!(e, sqlx::Error::RowNotFound) {
            return ApiError::not_found("not found");
        }
        tracing::error!(error = %e, "database error");
        ApiError::internal("database error")
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(e: serde_json::Error) -> Self {
        tracing::error!(error = %e, "serialization error");
        ApiError::internal("serialization error")
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        tracing::error!(error = %e, "internal error");
        ApiError::internal("internal error")
    }
}

impl From<axum::extract::rejection::JsonRejection> for ApiError {
    fn from(e: axum::extract::rejection::JsonRejection) -> Self {
        ApiError::bad_request(e.body_text())
    }
}

impl From<axum::extract::rejection::QueryRejection> for ApiError {
    fn from(e: axum::extract::rejection::QueryRejection) -> Self {
        ApiError::bad_request(e.body_text())
    }
}

impl From<axum::extract::rejection::PathRejection> for ApiError {
    fn from(e: axum::extract::rejection::PathRejection) -> Self {
        ApiError::bad_request(e.body_text())
    }
}
