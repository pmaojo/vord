//! App-wide error type used by the new branches/portfolios/auth handlers.
//! The existing `WorkflowError` / `StorageError` types live in
//! `yunq_rules_engine` / `yunq_infra_postgres`; this is a thin HTTP-side
//! wrapper so the new modules don't all have to rebuild the same shape.

use axum::Json;
use axum::http::StatusCode;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct AppErrorBody {
    pub error: String,
}

#[derive(Debug)]
pub struct AppError {
    pub status: StatusCode,
    pub body: AppErrorBody,
}

impl AppError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            body: AppErrorBody {
                error: message.into(),
            },
        }
    }
    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            body: AppErrorBody {
                error: message.into(),
            },
        }
    }
    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: AppErrorBody {
                error: message.into(),
            },
        }
    }
}

impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        (self.status, Json(self.body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_request_is_status_400() {
        let e = AppError::bad_request("missing field");
        assert_eq!(e.status, StatusCode::BAD_REQUEST);
        assert_eq!(e.body.error, "missing field");
    }

    #[test]
    fn not_found_is_status_404() {
        let e = AppError::not_found("portfolios/abc");
        assert_eq!(e.status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn internal_is_status_500() {
        let e = AppError::internal("db down");
        assert_eq!(e.status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn app_error_body_serializes_as_object_with_error_field() {
        let e = AppError::bad_request("bad");
        let json = serde_json::to_string(&e.body).unwrap();
        assert!(json.contains("\"error\""));
        assert!(json.contains("bad"));
    }
}
