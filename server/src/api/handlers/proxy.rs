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

pub(crate) async fn h_proxy_backends(ctx: ApiCtx) -> Response<Body> { let health = ctx.state.backend_health.read().unwrap(); let conns = ctx.state.backend_conns.read().unwrap(); let circuits = ctx.state.backend_circuits.read().unwrap(); let mut out = Vec::new(); for b in &ctx.state.config.backends { out.push(json!({"url": b, "healthy": health.get(b).copied().unwrap_or(true), "connections": conns.get(b).map(|c| c.load(Ordering::Relaxed)).unwrap_or(0), "circuit_open": circuits.get(b).map(|c| c.is_open()).unwrap_or(false)})); } okj(json!(out)) }

pub(crate) async fn h_proxy_backends_add(ctx: ApiCtx) -> Response<Body> { let f = form(&ctx); let url = f.get("url").cloned().unwrap_or_default(); if url.is_empty() { return err(StatusCode::BAD_REQUEST, "url required"); } let mut backends = ctx.state.backends.write().unwrap(); if !backends.contains(&url) { backends.push(url.clone()); } drop(backends); let mut health = ctx.state.backend_health.write().unwrap(); health.insert(url.clone(), true); drop(health); let mut conns = ctx.state.backend_conns.write().unwrap(); conns.insert(url.clone(), Arc::new(std::sync::atomic::AtomicUsize::new(0))); drop(conns); push_notif("info", format!("backend added dynamically: {}", url)); okj(json!({ "ok": true, "note": "Backend added to runtime state" })) }

pub(crate) async fn h_proxy_backend_ops(ctx: ApiCtx, rest: &str) -> Response<Body> { let parts: Vec<&str> = rest.split('/').collect(); let b = parts.get(0).copied().unwrap_or(""); let op = parts.get(1).copied().unwrap_or(""); match op { "remove" if ctx.method == Method::POST => { okj(json!({"ok": true, "note": "remove via OmniDB config + restart"})) }, "toggle" if ctx.method == Method::POST => { let mut h = ctx.state.backend_health.write().unwrap(); let cur = h.get(b).copied().unwrap_or(true); h.insert(b.to_string(), !cur); okj(json!({"ok": true, "healthy": !cur})) }, "reset_circuit" if ctx.method == Method::POST => { let circuits = ctx.state.backend_circuits.read().unwrap(); if let Some(c) = circuits.get(b) { c.record_success(); okj(json!({"ok": true})) } else { term_404(&ctx, "backend not found") } }, "stats" => { let health = ctx.state.backend_health.read().unwrap(); let conns = ctx.state.backend_conns.read().unwrap(); let circuits = ctx.state.backend_circuits.read().unwrap(); okj(json!({"url": b, "healthy": health.get(b).copied().unwrap_or(true), "connections": conns.get(b).map(|c| c.load(Ordering::Relaxed)).unwrap_or(0), "circuit_open": circuits.get(b).map(|c| c.is_open()).unwrap_or(false)})) }, _ => term_404(&ctx, format!("unknown backend op: {op}")) } }

pub(crate) async fn h_proxy_vhosts(ctx: ApiCtx) -> Response<Body> { let m: HashMap<String, String> = ctx.state.virtual_hosts.read().unwrap().iter().map(|(k, v)| (k.clone(), v.to_string_lossy().into_owned())).collect(); okj(json!(m)) }

pub(crate) async fn h_proxy_redirects(ctx: ApiCtx) -> Response<Body> { let m = ctx.state.redirects.read().unwrap().clone(); okj(json!(m)) }

pub(crate) async fn h_proxy_vhosts_set(ctx: ApiCtx) -> Response<Body> { let f = form(&ctx); let host = f.get("host").cloned().unwrap_or_default(); let path = f.get("path").cloned().unwrap_or_default(); if host.is_empty() || path.is_empty() { return err(StatusCode::BAD_REQUEST, "host and path required"); } let mut vhosts = ctx.state.virtual_hosts.write().unwrap(); vhosts.insert(host, PathBuf::from(path)); drop(vhosts); okj(json!({ "ok": true, "note": "vhost updated in runtime" })) }

pub(crate) async fn h_proxy_vhosts_delete(ctx: ApiCtx, host: String) -> Response<Body> { let mut vhosts = ctx.state.virtual_hosts.write().unwrap(); let removed = vhosts.remove(&host).is_some(); drop(vhosts); push_notif("warn", format!("vhost deleted: {}", host)); okj(json!({ "ok": removed })) }

pub(crate) async fn h_proxy_redirects_set(ctx: ApiCtx) -> Response<Body> { let f = form(&ctx); let from = f.get("from").cloned().unwrap_or_default(); let to = f.get("to").cloned().unwrap_or_default(); if from.is_empty() || to.is_empty() { return err(StatusCode::BAD_REQUEST, "from and to required"); } let mut redirects = ctx.state.redirects.write().unwrap(); redirects.insert(from, to); drop(redirects); okj(json!({ "ok": true, "note": "redirect updated in runtime" })) }

pub(crate) async fn h_proxy_redirects_delete(ctx: ApiCtx, path: String) -> Response<Body> { let mut redirects = ctx.state.redirects.write().unwrap(); let removed = redirects.remove(&path).is_some(); drop(redirects); push_notif("warn", format!("redirect deleted: {}", path)); okj(json!({ "ok": removed })) }



pub(crate) async fn h_proxy_rate_limits(ctx: ApiCtx) -> Response<Body> { let g = ctx.state.rate_limits.lock().unwrap(); let list: Vec<Value> = g.iter().take(200).map(|(ip, (t, n))| json!({"ip": ip, "window_start_secs_ago": t.elapsed().as_secs(), "count": n})).collect(); okj(json!(list)) }

pub(crate) async fn h_proxy_rate_limits_reset(ctx: ApiCtx) -> Response<Body> { let ip = qs(&ctx, "ip"); let mut g = ctx.state.rate_limits.lock().unwrap(); if ip.is_empty() { let n = g.len(); g.clear(); okj(json!({"ok": true, "cleared": n})) } else { let removed = g.remove(&ip).is_some(); okj(json!({"ok": removed})) } }

pub(crate) async fn h_proxy_grpc(ctx: ApiCtx) -> Response<Body> { okj(json!({"enabled": ctx.state.config.grpc_passthrough})) }

pub(crate) async fn h_proxy_ws_active(_ctx: ApiCtx) -> Response<Body> { let (active, total) = ws_active_count(); okj(json!({ "active_connections": active, "total_connections": total })) }

// ═══════════════════════════════════════════════════════════════════════════
// METRICS
// ═══════════════════════════════════════════════════════════════════════════




// ═══════════════════════════════════════════════════════════════════════════
// LOGS
// ═══════════════════════════════════════════════════════════════════════════





// ═══════════════════════════════════════════════════════════════════════════
// SETTINGS
// ═══════════════════════════════════════════════════════════════════════════
