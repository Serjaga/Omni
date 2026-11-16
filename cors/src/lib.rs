
//! cors.rs — CORS middleware для OmniRS.
//!
//! Политика берётся из `AppState.config.cors_allowed_origins`
//! на каждый запрос (горячее перечитывание — при смене конфига
//! через `SharedState` новое значение подхватится само).

use axum::{
    body::Body,
    http::{Response, StatusCode},
};


const ALLOW_METHODS: &str =
    "GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD";
const ALLOW_HEADERS: &str =
    "content-type, authorization, x-admin-token, x-request-id, x-forwarded-for";

pub fn cors_origin_allowed(origin: &str, allowed: &[String]) -> bool {
    allowed.iter().any(|a| a == "*" || a == origin)
}

pub fn cors_preflight_response(origin: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header("access-control-allow-origin", origin)
        .header("access-control-allow-methods", ALLOW_METHODS)
        .header("access-control-allow-headers", ALLOW_HEADERS)
        .header("access-control-max-age", "86400")
        .header("vary", "origin")
        .body(Body::empty())
        .unwrap_or_else(|_| Response::new(Body::empty()))
}
