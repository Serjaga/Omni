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

pub(crate) async fn h_events_sse(ctx: ApiCtx) -> Response<Body> { let rx = ctx.state.metrics.clone(); let stream = futures_util::stream::unfold((), move |_| { let m = rx.clone(); async move { tokio::time::sleep(Duration::from_secs(5)).await; let n = { let g = notifs().lock().unwrap(); let start = g.len().saturating_sub(50); g[start..].to_vec() }; let payload = json!({"requests_total": m.total_requests.load(Ordering::Relaxed), "slow_requests": m.slow_requests.load(Ordering::Relaxed), "notifs": n}); let data = format!("event: snapshot\ndata: {}\n\n", payload); Some((Ok::<bytes::Bytes, std::convert::Infallible>(bytes::Bytes::from(data)), ())) } }); Response::builder().status(StatusCode::OK).header(CONTENT_TYPE, "text/event-stream").header(header::CACHE_CONTROL, "no-cache").header("x-accel-buffering", "no").body(Body::from_stream(stream)).unwrap_or_else(|_| Response::new(Body::empty())) }
