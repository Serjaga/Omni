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

pub(crate) async fn h_ui_tabs(ctx: ApiCtx) -> Response<Body> { let mut tabs = vec!["dashboard", "files", "cache", "certs", "metrics", "system", "settings", "diag", "auth"]; if ctx.state.dns.is_some() { tabs.push("dns"); } if !ctx.state.config.backends.is_empty() { tabs.push("proxy"); } okj(json!(tabs)) }

pub(crate) async fn h_ui_features(ctx: ApiCtx) -> Response<Body> { okj(json!({ "dns": ctx.state.dns.is_some(), "cache": ctx.state.cache.is_some(), "certs": ctx.state.ssl.is_some(), "grpc": ctx.state.config.grpc_passthrough, "sticky": ctx.state.config.sticky_sessions, "fastcgi": ctx.state.config.fastcgi_pass.is_some(), "proxy": !ctx.state.config.backends.is_empty() })) }

pub(crate) async fn h_ui_token_prefix(ctx: ApiCtx) -> Response<Body> { okj(json!({"prefix": ctx.state.config.admin_token.chars().take(8).collect::<String>(), "length": ctx.state.config.admin_token.len()})) }

pub(crate) async fn h_ui_notifications(ctx: ApiCtx) -> Response<Body> { let g = notifs().lock().unwrap(); let n = qi(&ctx, "n", 100).clamp(1, 500) as usize; let start = g.len().saturating_sub(n); let list: Vec<Notif> = g[start..].to_vec(); okj(json!(list)) }

// ═══════════════════════════════════════════════════════════════════════════
// EXTENSIONS — Backup / SSE
// ═══════════════════════════════════════════════════════════════════════════
