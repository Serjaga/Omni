#![allow(unused_imports, unused_variables, clippy::all)]
use crate::api::*;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use axum::body::{Body, Bytes};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::Response;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use crate::{AppState, ws_active_count};
use omni_db as db;
use omni_dns as dns;
use omni_ssl as ssl;
use omni_vpn as vpn;
use omni_ikev2 as ikev2;
use omni_miraj as miraj;

pub(crate) async fn h_cache_stats(ctx: ApiCtx) -> Response<Body> {
    let cache = match &ctx.state.cache { Some(c) => c, None => return err(StatusCode::SERVICE_UNAVAILABLE, "cache disabled") };
    okj(json!({"entries": cache.entry_count(), "hits": ctx.state.metrics.cache_hits.load(Ordering::Relaxed), "misses": ctx.state.metrics.cache_misses.load(Ordering::Relaxed)}))
}
pub(crate) async fn h_cache_clear(ctx: ApiCtx) -> Response<Body> {
    let cache = match &ctx.state.cache { Some(c) => c, None => return err(StatusCode::SERVICE_UNAVAILABLE, "cache disabled") };
    cache.invalidate_all();
    cache.run_pending_tasks().await;
    push_notif("info", "cache cleared");
    okj(json!({"ok": true}))
}
pub(crate) async fn h_cache_keys(ctx: ApiCtx) -> Response<Body> {
    let cache = match &ctx.state.cache { Some(c) => c, None => return err(StatusCode::SERVICE_UNAVAILABLE, "cache disabled") };
    let pattern = qs(&ctx, "pattern");
    let limit = qi(&ctx, "limit", 100).clamp(1, 1000) as usize;
    let mut keys: Vec<String> = Vec::new();
    for (k, _) in cache.iter() {
        if keys.len() >= limit { break; }
        if pattern.is_empty() || k.contains(&pattern) { keys.push((*k).clone()); }
    }
    okj(json!({"count": keys.len(), "keys": keys}))
}
pub(crate) async fn h_cache_key(ctx: ApiCtx, key: String) -> Response<Body> {
    let cache = match &ctx.state.cache { Some(c) => c, None => return err(StatusCode::SERVICE_UNAVAILABLE, "cache disabled") };
    if ctx.method == Method::DELETE { cache.invalidate(&key).await; return okj(json!({"ok": true, "deleted": key})); }
    match cache.get(&key).await {
        Some(v) => okj(json!({"key": key, "entry": {"status": v.status, "headers": v.headers, "body_size": v.body.len(), "body": if v.body.len() <= 65536 { Some(String::from_utf8_lossy(&v.body).into_owned()) } else { None }}})),
        None => term_404(&ctx, "key not in cache"),
    }
}
pub(crate) async fn h_cache_invalidate_prefix(ctx: ApiCtx) -> Response<Body> {
    let cache = match &ctx.state.cache { Some(c) => c, None => return err(StatusCode::SERVICE_UNAVAILABLE, "cache disabled") };
    let f = form(&ctx);
    let prefix = f.get("prefix").cloned().unwrap_or_else(|| qs(&ctx, "prefix"));
    if prefix.is_empty() { return err(StatusCode::BAD_REQUEST, "prefix required"); }
    let keys: Vec<String> = cache.iter().filter(|(k, _)| k.starts_with(&prefix)).map(|(k, _)| (*k).clone()).collect();
    let mut n = 0;
    for k in keys { cache.invalidate(&k).await; n += 1; }
    cache.run_pending_tasks().await;
    okj(json!({"ok": true, "invalidated": n}))
}
pub(crate) async fn h_cache_policy(ctx: ApiCtx) -> Response<Body> {
    if ctx.method == Method::GET { return okj(json!({"note": "moka cache configured at startup"})); }
    let f = form(&ctx);
    let mut g = runtime().lock().unwrap();
    if let Some(ttl) = f.get("ttl_secs").and_then(|s| s.parse().ok()) { g.cache_ttl_secs = Some(ttl); }
    if let Some(cap) = f.get("max_entries").and_then(|s| s.parse().ok()) { g.cache_max_entries = Some(cap); }
    okj(json!({"ok": true, "note": "runtime policy stored; effect on next restart"}))
}

// ═══════════════════════════════════════════════════════════════════════════
// DNS zones
// ═══════════════════════════════════════════════════════════════════════════
