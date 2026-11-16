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

pub(crate) async fn h_files_list(ctx: ApiCtx) -> Response<Body> {
    let path = qs(&ctx, "path");
    let root = &ctx.state.config.admin_root;
    let base = match safe_rel(root, if path.is_empty() { "/" } else { &path }) { Ok(p) => p, Err(s) => return errp(s, "invalid path") };
    let mut items = Vec::new();
    match tokio::fs::read_dir(&base).await {
        Ok(mut rd) => {
            while let Ok(Some(e)) = rd.next_entry().await {
                let meta = match e.metadata().await { Ok(m) => m, Err(_) => continue };
                let kind = if meta.is_dir() { "dir" } else { "file" };
                items.push(json!({"name": e.file_name().to_string_lossy(), "kind": kind, "size": meta.len()}));
            }
        }
        Err(e) => return err(StatusCode::BAD_REQUEST, e.to_string()),
    }
    items.sort_by(|a, b| a.get("name").and_then(|v| v.as_str()).unwrap_or("").cmp(b.get("name").and_then(|v| v.as_str()).unwrap_or("")));
    okj(json!({"path": path, "items": items}))
}
pub(crate) async fn h_files_read(ctx: ApiCtx) -> Response<Body> {
    let path = qs(&ctx, "path");
    let root = &ctx.state.config.admin_root;
    let p = match safe_existing(root, &path).await { Ok(p) => p, Err(s) => return errp(s, "invalid path") };
    match tokio::fs::read_to_string(&p).await { Ok(c) => okj(json!({"path": path, "content": c})), Err(_) => errp(StatusCode::UNSUPPORTED_MEDIA_TYPE, "only UTF-8 text") }
}
pub(crate) async fn h_files_save(ctx: ApiCtx) -> Response<Body> {
    let f = form(&ctx);
    let rel = f.get("path").cloned().unwrap_or_default();
    let content = f.get("content").cloned().unwrap_or_default();
    if rel.is_empty() || content.len() > 2 * 1024 * 1024 { return err(StatusCode::BAD_REQUEST, "path and content required (2MB max)"); }
    let root = &ctx.state.config.admin_root;
    let candidate = match safe_rel(root, &rel) { Ok(p) => p, Err(s) => return errp(s, "invalid path") };
    let parent = match candidate.parent() { Some(p) => p, None => return err(StatusCode::BAD_REQUEST, "no parent") };
    let parent = match tokio::fs::canonicalize(parent).await { Ok(p) if p.starts_with(root) => p, _ => return err(StatusCode::FORBIDDEN, "outside root") };
    let target = parent.join(candidate.file_name().unwrap_or_default());
    if tokio::fs::symlink_metadata(&target).await.map(|m| m.file_type().is_symlink()).unwrap_or(false) { return err(StatusCode::FORBIDDEN, "symlinks forbidden"); }
    match tokio::fs::write(&target, content).await { Ok(_) => okj(json!({"ok": true})), Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()) }
}
pub(crate) async fn h_files_mkdir(ctx: ApiCtx) -> Response<Body> {
    let f = form(&ctx);
    let rel = f.get("path").cloned().unwrap_or_default();
    if rel.is_empty() { return err(StatusCode::BAD_REQUEST, "path required"); }
    let root = &ctx.state.config.admin_root;
    let target = match safe_rel(root, &rel) { Ok(p) => p, Err(s) => return errp(s, "invalid path") };
    let parent = match target.parent().and_then(|p| p.canonicalize().ok()) { Some(p) if p.starts_with(root) => p, _ => return err(StatusCode::FORBIDDEN, "outside root") };
    let target = parent.join(target.file_name().unwrap_or_default());
    match tokio::fs::create_dir(&target).await { Ok(_) => okj(json!({"ok": true})), Err(e) => err(StatusCode::BAD_REQUEST, e.to_string()) }
}
pub(crate) async fn h_files_delete(ctx: ApiCtx) -> Response<Body> {
    let f = form(&ctx);
    let rel = f.get("path").cloned().unwrap_or_default();
    if rel.is_empty() { return err(StatusCode::BAD_REQUEST, "path required"); }
    let root = &ctx.state.config.admin_root;
    let target = match safe_existing(root, &rel).await { Ok(p) => p, Err(s) => return errp(s, "invalid path") };
    if target.as_path() == root.as_path() { return err(StatusCode::FORBIDDEN, "cannot delete root"); }
    let res = if target.is_dir() { tokio::fs::remove_dir(target).await } else { tokio::fs::remove_file(target).await };
    match res { Ok(_) => okj(json!({"ok": true})), Err(e) => err(StatusCode::BAD_REQUEST, format!("(dir must be empty) {e}")) }
}
pub(crate) async fn h_files_rename(ctx: ApiCtx) -> Response<Body> {
    let f = form(&ctx);
    let from = f.get("from").cloned().unwrap_or_default();
    let to = f.get("to").cloned().unwrap_or_default();
    if from.is_empty() || to.is_empty() { return err(StatusCode::BAD_REQUEST, "from and to required"); }
    let root = &ctx.state.config.admin_root;
    let src = match safe_existing(root, &from).await { Ok(p) => p, Err(s) => return errp(s, "invalid from") };
    let dst = match safe_rel(root, &to) { Ok(p) => p, Err(s) => return errp(s, "invalid to") };
    if let Some(parent) = dst.parent() { if !parent.starts_with(root) { return err(StatusCode::FORBIDDEN, "outside root"); } }
    match tokio::fs::rename(&src, &dst).await { Ok(_) => { push_notif("info", format!("renamed {} -> {}", from, to)); okj(json!({"ok": true})) } Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()) }
}
pub(crate) async fn h_files_move(ctx: ApiCtx) -> Response<Body> { h_files_rename(ctx).await }
pub(crate) async fn h_files_copy(ctx: ApiCtx) -> Response<Body> {
    let f = form(&ctx);
    let from = f.get("from").cloned().unwrap_or_default();
    let to = f.get("to").cloned().unwrap_or_default();
    if from.is_empty() || to.is_empty() { return err(StatusCode::BAD_REQUEST, "from and to required"); }
    let root = &ctx.state.config.admin_root;
    let src = match safe_existing(root, &from).await { Ok(p) => p, Err(s) => return errp(s, "invalid from") };
    let dst = match safe_rel(root, &to) { Ok(p) => p, Err(s) => return errp(s, "invalid to") };
    if let Some(parent) = dst.parent() {
        if !parent.starts_with(root) { return err(StatusCode::FORBIDDEN, "outside root"); }
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    let res = if src.is_dir() {
        tokio::process::Command::new("cp").arg("-r").arg(&src).arg(&dst).status().await.map(|s| s.success())
    } else {
        tokio::fs::copy(&src, &dst).await.map(|_| true)
    };
    match res { Ok(true) => okj(json!({"ok": true})), _ => err(StatusCode::INTERNAL_SERVER_ERROR, "copy failed") }
}
pub(crate) async fn h_files_delete_recursive(ctx: ApiCtx) -> Response<Body> {
    let f = form(&ctx);
    let path = f.get("path").cloned().unwrap_or_default();
    if f.get("confirm").map(|s| s.as_str()) != Some("yes") { return err(StatusCode::BAD_REQUEST, "confirm=yes required"); }
    let root = &ctx.state.config.admin_root;
    let p = match safe_existing(root, &path).await { Ok(p) => p, Err(s) => return errp(s, "invalid path") };
    if p == *root { return err(StatusCode::FORBIDDEN, "cannot delete root"); }
    match tokio::fs::remove_dir_all(&p).await { Ok(_) => { push_notif("warn", format!("deleted recursively {}", path)); okj(json!({"ok": true})) } Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()) }
}
pub(crate) async fn h_files_upload(ctx: ApiCtx) -> Response<Body> {
    let ct = ctx.headers.get(CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    if !ct.contains("multipart/form-data") { return err(StatusCode::BAD_REQUEST, "multipart/form-data required"); }
    let boundary = match ct.split("boundary=").nth(1) { Some(b) => b.trim_matches('"').to_string(), None => return err(StatusCode::BAD_REQUEST, "boundary missing") };
    let dir = qs(&ctx, "path");
    let root = &ctx.state.config.admin_root;
    let dir_path = match safe_rel(root, &dir) { Ok(p) => p, Err(s) => return errp(s, "invalid dir") };
    let body = ctx.body.to_vec();
    let mut pos = 0usize;
    let mut saved = Vec::new();
    let delim = format!("--{}", boundary).into_bytes();
    while let Some(i) = find_sub(&body[pos..], &delim) {
        pos += i + delim.len();
        if pos + 1 < body.len() && body[pos] == b'\r' { pos += 2; }
        if pos + 1 < body.len() && body[pos] == b'\n' { pos += 1; }
        if let Some(hdr_end) = find_sub(&body[pos..], b"\r\n\r\n") {
            let hdr_text = String::from_utf8_lossy(&body[pos..pos + hdr_end]).to_string();
            let data_start = pos + hdr_end + 4;
            let data_end = match find_sub(&body[data_start..], &delim) { Some(x) => data_start + x - 2, None => break };
            let mut fname = String::new();
            for line in hdr_text.lines() {
                if let Some(eq) = line.find("filename=\"") {
                    let rest = &line[eq + 10..];
                    if let Some(close) = rest.find('"') { fname = rest[..close].to_string(); }
                }
            }
            if fname.is_empty() { fname = format!("upload_{}", now_ts()); }
            let fname = fname.replace(['/', '\\'], "_");
            let target = dir_path.join(&fname);
            if !target.starts_with(root) { return err(StatusCode::FORBIDDEN, "outside root"); }
            let data = &body[data_start..data_end];
            match tokio::fs::write(&target, data).await {
                Ok(_) => saved.push(json!({"name": fname, "size": data.len()})),
                Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            }
            pos = data_end + 2;
        } else { break; }
    }
    okj(json!({"ok": true, "saved": saved}))
}
pub(crate) async fn h_files_download(ctx: ApiCtx) -> Response<Body> {
    let path = qs(&ctx, "path");
    let root = &ctx.state.config.admin_root;
    let p = match safe_existing(root, &path).await { Ok(p) => p, Err(s) => return errp(s, "invalid path") };
    if !p.is_file() { return err(StatusCode::BAD_REQUEST, "not a file"); }
    match tokio::fs::read(&p).await {
        Ok(d) => {
            let n = p.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
            okb("application/octet-stream", &n, d)
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}
pub(crate) async fn h_files_chmod(ctx: ApiCtx) -> Response<Body> {
    let f = form(&ctx);
    let path = f.get("path").cloned().unwrap_or_default();
    let mode = f.get("mode").cloned().unwrap_or_default();
    let root = &ctx.state.config.admin_root;
    let p = match safe_existing(root, &path).await { Ok(p) => p, Err(s) => return errp(s, "invalid path") };
    let m = match u32::from_str_radix(mode.trim_start_matches('0'), 8) { Ok(m) => m, Err(_) => return err(StatusCode::BAD_REQUEST, "mode must be octal") };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(m);
        match tokio::fs::set_permissions(&p, perms).await {
            Ok(_) => okj(json!({"ok": true, "mode": format!("{:o}", m)})),
            Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        }
    }
    #[cfg(not(unix))]
    { err(StatusCode::NOT_IMPLEMENTED, "chmod only on unix") }
}
pub(crate) async fn h_files_stat(ctx: ApiCtx) -> Response<Body> {
    let path = qs(&ctx, "path");
    let root = &ctx.state.config.admin_root;
    let p = match safe_existing(root, &path).await { Ok(p) => p, Err(s) => return errp(s, "invalid path") };
    match tokio::fs::metadata(&p).await {
        Ok(m) => {
            let kind = if m.is_dir() { "dir" } else if m.is_file() { "file" } else { "other" };
            let mtime = m.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs() as i64).unwrap_or(0);
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                okj(json!({"path": path, "kind": kind, "size": m.len(), "mtime": mtime, "mode": format!("{:o}", m.mode() & 0o777), "uid": m.uid(), "gid": m.gid()}))
            }
            #[cfg(not(unix))]
            { okj(json!({"path": path, "kind": kind, "size": m.len(), "mtime": mtime})) }
        }
        Err(e) => term_404(&ctx, e.to_string()),
    }
}
pub(crate) async fn h_files_search(ctx: ApiCtx) -> Response<Body> {
    let q = qs(&ctx, "q");
    let start = qs(&ctx, "path");
    if q.is_empty() { return err(StatusCode::BAD_REQUEST, "q required"); }
    let root = &ctx.state.config.admin_root;
    let base = match safe_rel(root, if start.is_empty() { "/" } else { &start }) { Ok(p) => p, Err(s) => return errp(s, "invalid path") };
    let mut results = Vec::new();
    search_dir(&base, &q.to_lowercase(), root, &mut results, 500);
    okj(json!({"query": q, "count": results.len(), "results": results}))
}
pub(crate) fn search_dir(dir: &Path, q: &str, root: &Path, out: &mut Vec<Value>, limit: usize) {
    if out.len() >= limit { return; }
    let rd = match std::fs::read_dir(dir) { Ok(r) => r, Err(_) => return };
    for e in rd.flatten() {
        if out.len() >= limit { return; }
        let p = e.path();
        let name = e.file_name().to_string_lossy().to_lowercase();
        if name.contains(q) {
            let rel = p.strip_prefix(root).map(|x| x.to_string_lossy().into_owned()).unwrap_or_default();
            let kind = if p.is_dir() { "dir" } else { "file" };
            out.push(json!({"name": e.file_name().to_string_lossy(), "path": rel, "kind": kind, "size": if p.is_file() { fs_size(&p) } else { 0 }}));
        }
        if p.is_dir() { search_dir(&p, q, root, out, limit); }
    }
}
pub(crate) async fn h_files_disk_usage(ctx: ApiCtx) -> Response<Body> {
    let path = qs(&ctx, "path");
    let root = &ctx.state.config.admin_root;
    let p = match safe_existing(root, &path).await { Ok(p) => p, Err(s) => return errp(s, "invalid path") };
    let size = du_size(&p);
    okj(json!({"path": path, "size": size, "human": human_bytes(size)}))
}
pub(crate) fn du_size(p: &Path) -> u64 {
    if p.is_file() { return fs_size(p); }
    let mut t = 0u64;
    if let Ok(rd) = std::fs::read_dir(p) {
        for e in rd.flatten() { t += du_size(&e.path()); }
    }
    t
}
pub(crate) async fn h_files_tree(ctx: ApiCtx) -> Response<Body> {
    let path = qs(&ctx, "path");
    let depth: usize = qi(&ctx, "depth", 3).clamp(1, 10) as usize;
    let root = &ctx.state.config.admin_root;
    let base = match safe_rel(root, if path.is_empty() { "/" } else { &path }) { Ok(p) => p, Err(s) => return errp(s, "invalid path") };
    okj(build_tree(&base, root, depth))
}
pub(crate) fn build_tree(p: &Path, root: &Path, depth: usize) -> Value {
    let name = p.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "/".into());
    let rel = p.strip_prefix(root).map(|x| x.to_string_lossy().into_owned()).unwrap_or_default();
    let mut obj = serde_json::Map::new();
    obj.insert("name".into(), json!(name));
    obj.insert("path".into(), json!(rel));
    if p.is_dir() {
        obj.insert("kind".into(), json!("dir"));
        if depth > 0 {
            let mut kids = Vec::new();
            if let Ok(rd) = std::fs::read_dir(p) {
                for e in rd.flatten() { kids.push(build_tree(&e.path(), root, depth - 1)); }
            }
            kids.sort_by(|a, b| a.get("name").and_then(|v| v.as_str()).unwrap_or("").cmp(b.get("name").and_then(|v| v.as_str()).unwrap_or("")));
            obj.insert("children".into(), json!(kids));
        }
    } else {
        obj.insert("kind".into(), json!("file"));
        obj.insert("size".into(), json!(fs_size(p)));
    }
    Value::Object(obj)
}
pub(crate) async fn h_files_archive(ctx: ApiCtx) -> Response<Body> {
    let f = form(&ctx);
    let path = f.get("path").cloned().unwrap_or_default();
    let out = f.get("out").cloned().unwrap_or_else(|| format!("archive_{}.tar.gz", now_ts()));
    let root = &ctx.state.config.admin_root;
    let src = match safe_existing(root, &path).await { Ok(p) => p, Err(s) => return errp(s, "invalid path") };
    let dest = match safe_rel(root, &out) { Ok(p) => p, Err(s) => return errp(s, "invalid out") };
    if let Some(parent) = dest.parent() { let _ = tokio::fs::create_dir_all(parent).await; }
    let parent = src.parent().unwrap_or(root);
    let base = src.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let r = tokio::process::Command::new("tar").arg("-czf").arg(&dest).arg("-C").arg(parent).arg(&base).status().await;
    match r { Ok(s) if s.success() => okj(json!({"ok": true, "path": out, "size": fs_size(&dest)})), _ => err(StatusCode::INTERNAL_SERVER_ERROR, "tar failed") }
}
pub(crate) async fn h_files_extract(ctx: ApiCtx) -> Response<Body> {
    let f = form(&ctx);
    let path = f.get("path").cloned().unwrap_or_default();
    let to = f.get("to").cloned().unwrap_or_default();
    let root = &ctx.state.config.admin_root;
    let src = match safe_existing(root, &path).await { Ok(p) => p, Err(s) => return errp(s, "invalid path") };
    let dst = match safe_rel(root, &to) { Ok(p) => p, Err(s) => return errp(s, "invalid to") };
    if let Some(parent) = dst.parent() { let _ = tokio::fs::create_dir_all(parent).await; }
    let name = src.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let r = if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        tokio::process::Command::new("tar").arg("-xzf").arg(&src).arg("-C").arg(&dst).status().await
    } else if name.ends_with(".tar") {
        tokio::process::Command::new("tar").arg("-xf").arg(&src).arg("-C").arg(&dst).status().await
    } else if name.ends_with(".zip") {
        tokio::process::Command::new("unzip").arg("-o").arg(&src).arg("-d").arg(&dst).status().await
    } else {
        return err(StatusCode::BAD_REQUEST, "unsupported archive");
    };
    match r { Ok(s) if s.success() => okj(json!({"ok": true})), _ => err(StatusCode::INTERNAL_SERVER_ERROR, "extract failed") }
}

// ═══════════════════════════════════════════════════════════════════════════
// CACHE
// ═══════════════════════════════════════════════════════════════════════════
