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

pub(crate) async fn h_settings_get(ctx: ApiCtx) -> Response<Body> { let g = runtime().lock().unwrap(); let c = &ctx.state.config; okj(json!({"cache_ttl_secs": g.cache_ttl_secs.unwrap_or(c.cache_ttl_secs), "cache_max_entries": g.cache_max_entries.unwrap_or(c.cache_max_entries), "rate_limit": g.rate_limit.unwrap_or(100), "cors_origins": g.cors_origins.clone().unwrap_or_else(|| c.cors_allowed_origins.clone()), "sticky_sessions": g.sticky_sessions.unwrap_or(c.sticky_sessions)})) }

pub(crate) async fn h_settings_cache(ctx: ApiCtx) -> Response<Body> { let f = form(&ctx); let mut g = runtime().lock().unwrap(); if let Some(v) = f.get("ttl_secs").and_then(|s| s.parse::<u64>().ok()) { g.cache_ttl_secs = Some(v); } if let Some(v) = f.get("max_entries").and_then(|s| s.parse::<u64>().ok()) { g.cache_max_entries = Some(v); } push_notif("info", "cache settings updated (restart required for moka)"); okj(json!({"ok": true})) }

pub(crate) async fn h_settings_rate_limit(ctx: ApiCtx) -> Response<Body> { let f = form(&ctx); let mut g = runtime().lock().unwrap(); if let Some(v) = f.get("rate_limit").and_then(|s| s.parse::<u64>().ok()) { g.rate_limit = Some(v); } okj(json!({"ok": true})) }

pub(crate) async fn h_settings_slow(ctx: ApiCtx) -> Response<Body> { let f = form(&ctx); let mut g = runtime().lock().unwrap(); if let Some(v) = f.get("threshold_ms").and_then(|s| s.parse::<u64>().ok()) { g.slow_threshold_ms = Some(v); } okj(json!({"ok": true})) }

pub(crate) async fn h_settings_cors(ctx: ApiCtx) -> Response<Body> { let f = form(&ctx); let mut g = runtime().lock().unwrap(); if let Some(v) = f.get("origins") { g.cors_origins = Some(v.split(',').map(|s| s.trim().to_string()).collect()); } okj(json!({"ok": true})) }

pub(crate) async fn h_settings_sticky(ctx: ApiCtx) -> Response<Body> { let f = form(&ctx); let mut g = runtime().lock().unwrap(); if let Some(v) = f.get("enabled") { g.sticky_sessions = Some(v == "true" || v == "1"); } okj(json!({"ok": true})) }

pub(crate) async fn h_settings_security(_ctx: ApiCtx) -> Response<Body> { okj(json!({"hsts": "max-age=31536000; includeSubDomains", "x_content_type_options": "nosniff", "x_frame_options": "SAMEORIGIN", "referrer_policy": "strict-origin-when-cross-origin", "note": "set in access_log middleware (main.rs); restart required to change"})) }

// ═══════════════════════════════════════════════════════════════════════════
// DIAG
// ═══════════════════════════════════════════════════════════════════════════
