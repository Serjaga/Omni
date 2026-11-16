//! HTTP middleware moved here (tightly coupled to AppState/SharedState).

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderName, HeaderValue, Method, Request, Response};
use axum::middleware::Next;

use crate::{resolve_client_ip, SharedState};
use omni_cors::{cors_origin_allowed, cors_preflight_response};

const ALLOW_METHODS: &str = "GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD";
const ALLOW_HEADERS: &str = "content-type, authorization, x-admin-token, x-request-id, x-forwarded-for";

// ── access log middleware (from logger crate) ────────────────────────
pub async fn access_log(
    State(state): State<SharedState>,
    request: Request<Body>,
    next: Next,
) -> Response<Body> {
    let start = Instant::now();
    let _method = request.method().clone();
    let uri = request.uri().clone();
    let _host = request.headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_string();
    let req_id = format!("{:x}", rand::random::<u64>());

    // IP клиента вытаскиваем ДО next.run — после request перемещён.
    let _client_ip = {
        let ci = request.extensions().get::<ConnectInfo<SocketAddr>>().cloned();
        resolve_client_ip(request.headers(), ci.as_ref())
    };

    let metrics = state.read().unwrap().metrics.clone();

    let mut response = next.run(request).await;

    if let Ok(hv) = req_id.parse() {
        response.headers_mut().insert("x-request-id", hv);
    }
    let latency = start.elapsed().as_millis();
    let _ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let _path = uri.path();

    metrics.total_requests.fetch_add(1, Ordering::Relaxed);
    metrics.total_latency_ms.fetch_add(latency as u64, Ordering::Relaxed);


    match response.status().as_u16() {
        200..=299 => { metrics.status_2xx.fetch_add(1, Ordering::Relaxed); }
        300..=399 => { metrics.status_3xx.fetch_add(1, Ordering::Relaxed); }
        400..=499 => { metrics.status_4xx.fetch_add(1, Ordering::Relaxed); }
        500..=599 => { metrics.status_5xx.fetch_add(1, Ordering::Relaxed); }
        _ => {}
    }

    let h = response.headers_mut();
    h.insert(header::STRICT_TRANSPORT_SECURITY, HeaderValue::from_static("max-age=31536000; includeSubDomains"));
    h.insert(HeaderName::from_static("x-content-type-options"), HeaderValue::from_static("nosniff"));
    h.insert(HeaderName::from_static("x-frame-options"), HeaderValue::from_static("SAMEORIGIN"));
    h.insert(HeaderName::from_static("referrer-policy"), HeaderValue::from_static("strict-origin-when-cross-origin"));
    response
}

// ── cors middleware (from cors crate) ────────────────────────────────
pub async fn cors_mw(
    State(state): State<SharedState>,
    request: Request<Body>,
    next: Next,
) -> Response<Body> {
    let allowed = {
        let s = state.read().unwrap().clone();
        s.config.cors_allowed_origins.clone()
    };
    let origin = request
        .headers()
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let ok = origin
        .as_ref()
        .map_or(false, |o| cors_origin_allowed(o, &allowed));

    if ok && request.method() == Method::OPTIONS {
        return cors_preflight_response(origin.as_ref().unwrap());
    }

    let mut resp = next.run(request).await;

    if ok {
        if let Some(o) = origin {
            if let Ok(v) = o.parse() {
                resp.headers_mut().insert("access-control-allow-origin", v);
            }
            resp.headers_mut()
                .insert("vary", HeaderValue::from_static("origin"));
            resp.headers_mut()
                .insert("access-control-allow-methods", HeaderValue::from_static(ALLOW_METHODS));
            resp.headers_mut()
                .insert("access-control-allow-headers", HeaderValue::from_static(ALLOW_HEADERS));
        }
    }
    resp
}