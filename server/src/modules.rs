//! Единный менеджер модулей OmniRS.
//! ZIP-модули компилируются внутрь основного бинарника через server/build.rs.
use std::{path::{Path, PathBuf}, sync::Arc, process::{Command, Stdio}};
use axum::{body::Body, http::{Method, StatusCode}, response::Response};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use crate::AppState;

#[derive(Clone, Debug, Serialize)]
pub struct ModuleRecord {
    pub module_id: String, pub name: String, pub version: String, pub status: String,
    pub src_path: String, pub artifact_path: String, pub build_log: String, pub enabled: bool,
    pub description: String, pub admin_entry: String, pub kind: String,
}
#[derive(Debug, Deserialize)]
struct Manifest {
    id: String, name: String, version: String,
    #[serde(default)] description: String,
    #[serde(default = "default_entry")] entry: String,
    #[serde(default)] admin_entry: String,
    #[serde(default = "default_kind")] kind: String,
}
fn default_kind() -> String { "source".into() }
fn default_entry() -> String { "src/module.rs".into() }
const SYSTEM_MODULES: &[(&str,&str,&str)] = &[
    ("core","Core","Общие примитивы и криптография"),
    ("cors","CORS","Политика CORS"),
    ("security","Security IPS","Защита и обнаружение сетевых атак"),
    ("dns","DNS","DNS-сервер и DNS over TLS/QUIC/HTTPS"),
    ("tunnel","Tunnel","TCP/UDP/SOCKS и туннели"),
    ("db","Database","Встроенная база данных и API"),
    ("ikev2","IKEv2/IPsec","IKEv2 и ESP"),
    ("ssl","SSL/ACME","TLS, сертификаты и ACME"),
    ("miraj","Miraj","Hysteria2 поверх QUIC"),
    ("vpn","VPN","WireGuard"),
    ("server","HTTP Server","HTTP/1.1, HTTP/2, HTTP/3 и админка"),
];
fn root() -> PathBuf { PathBuf::from("./modules") }
fn installed() -> PathBuf { root().join("installed") }
fn state_dir() -> PathBuf { root().join("state") }
fn valid_id(s: &str) -> bool { !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') }
fn json_resp(status: StatusCode, v: Value) -> Response<Body> {
    Response::builder().status(status).header("content-type", "application/json; charset=utf-8")
        .body(Body::from(v.to_string())).unwrap_or_else(|_| Response::new(Body::from("{}")))
}
fn db_call<F,T>(f:F)->Result<T,String> where F:FnOnce(&rusqlite::Connection)->rusqlite::Result<T>+Send+'static,T:Send+'static {
    let c=omni_db::open_omni().map_err(|e|e.to_string())?;
    c.execute_batch("CREATE TABLE IF NOT EXISTS OmniModules (module_id TEXT PRIMARY KEY,name TEXT NOT NULL DEFAULT '',version TEXT NOT NULL DEFAULT '',status TEXT NOT NULL DEFAULT 'pending_build',src_path TEXT,artifact_path TEXT,build_log TEXT,enabled INTEGER NOT NULL DEFAULT 1,created_at DATETIME DEFAULT CURRENT_TIMESTAMP,updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)").map_err(|e|e.to_string())?;
    f(&c).map_err(|e|e.to_string())
}
fn ensure_module_columns(c:&rusqlite::Connection)->rusqlite::Result<()> {
    for (col,ddl) in [("description","ALTER TABLE OmniModules ADD COLUMN description TEXT NOT NULL DEFAULT ''"),("admin_entry","ALTER TABLE OmniModules ADD COLUMN admin_entry TEXT NOT NULL DEFAULT ''"),("kind","ALTER TABLE OmniModules ADD COLUMN kind TEXT NOT NULL DEFAULT 'source'")] {
        let mut stmt=c.prepare("PRAGMA table_info(OmniModules)")?;
        let columns=stmt.query_map([],|r|r.get::<_,String>(1))?;
        let exists=columns.filter_map(Result::ok).any(|x|x==col);
        drop(stmt);
        if !exists { c.execute(ddl,[])?; }
    }
    Ok(())
}
async fn save_record(m: ModuleRecord)->Result<(),String>{
    tokio::task::spawn_blocking(move||db_call(move|c|{
        ensure_module_columns(c)?;
        c.execute("INSERT INTO OmniModules(module_id,name,version,status,src_path,artifact_path,build_log,enabled,description,admin_entry,kind,updated_at) VALUES(?1,?2,?3,?4,?5,'','',?6,?7,?8,?9,CURRENT_TIMESTAMP) ON CONFLICT(module_id) DO UPDATE SET name=excluded.name,version=excluded.version,status=excluded.status,src_path=excluded.src_path,artifact_path=excluded.artifact_path,build_log=excluded.build_log,enabled=excluded.enabled,description=excluded.description,admin_entry=excluded.admin_entry,kind=excluded.kind,updated_at=CURRENT_TIMESTAMP",
        rusqlite::params![m.module_id,m.name,m.version,m.status,m.src_path,if m.enabled{1}else{0},m.description,m.admin_entry,m.kind])?; Ok(())
    })).await.map_err(|e|e.to_string())?
}
async fn records()->Result<Vec<ModuleRecord>,String>{
    tokio::task::spawn_blocking(||db_call(|c|{
        ensure_module_columns(c)?;
        for (id,name,desc) in SYSTEM_MODULES {
            c.execute("INSERT OR IGNORE INTO OmniModules(module_id,name,version,status,enabled,description,admin_entry,kind,updated_at) VALUES(?1,?2,'built-in','built-in',1,?3,'','system',CURRENT_TIMESTAMP)",rusqlite::params![id,name,desc])?;
        }
        let mut st=c.prepare("SELECT module_id,name,version,status,src_path,artifact_path,build_log,enabled,description,admin_entry,kind FROM OmniModules ORDER BY module_id")?;
        let rows=st.query_map([],|r|Ok(ModuleRecord{module_id:r.get(0)?,name:r.get(1)?,version:r.get(2)?,status:r.get(3)?,src_path:r.get::<_,Option<String>>(4)?.unwrap_or_default(),artifact_path:r.get::<_,Option<String>>(5)?.unwrap_or_default(),build_log:r.get::<_,Option<String>>(6)?.unwrap_or_default(),enabled:r.get::<_,i64>(7)?!=0,description:r.get(8)?,admin_entry:r.get(9)?,kind:r.get(10)?}))?;
        let mut result:Vec<ModuleRecord>=rows.filter_map(Result::ok).collect();
        drop(st);
        for module in &mut result {
            if module.kind != "system" {
                if let Ok(status)=std::fs::read_to_string(state_dir().join(format!("{}.status",module.module_id))) {
                    if status != module.status {
                        c.execute("UPDATE OmniModules SET status=?1,updated_at=CURRENT_TIMESTAMP WHERE module_id=?2",rusqlite::params![status,module.module_id])?;
                        module.status=status;
                    }
                }
            }
        }
        Ok(result)
    })).await.map_err(|e|e.to_string())?
}
fn safe_extract(bytes:&[u8], dest:&Path)->Result<(),String>{
    let mut z=zip::ZipArchive::new(std::io::Cursor::new(bytes)).map_err(|e|format!("ZIP: {e}"))?;
    if z.len() > 2000 { return Err("слишком много файлов в ZIP (лимит 2000)".into()); }
    let mut total_size=0u64;
    for i in 0..z.len() { let f=z.by_index(i).map_err(|e|e.to_string())?; total_size=total_size.saturating_add(f.size()); }
    if total_size > 256 * 1024 * 1024 { return Err("распакованный ZIP превышает лимит 256 MiB".into()); }
    std::fs::create_dir_all(dest).map_err(|e|e.to_string())?;
    let base=dest.canonicalize().map_err(|e|e.to_string())?;
    for i in 0..z.len(){
        let mut f=z.by_index(i).map_err(|e|e.to_string())?;
        let name=f.name().replace('\\',"/");
        if name.starts_with('/') || name.split('/').any(|p|p=="..") || name.contains(':') { return Err(format!("Недопустимый путь в ZIP: {name}")); }
        let out=dest.join(&name);
        if !out.starts_with(dest) { return Err("path traversal".into()); }
        if f.is_dir(){std::fs::create_dir_all(&out).map_err(|e|e.to_string())?;}else{
            if let Some(p)=out.parent(){std::fs::create_dir_all(p).map_err(|e|e.to_string())?;}
            let mut w=std::fs::File::create(&out).map_err(|e|e.to_string())?;
            std::io::copy(&mut f,&mut w).map_err(|e|e.to_string())?;
            let canon=out.canonicalize().map_err(|e|e.to_string())?;
            if !canon.starts_with(&base){return Err("ZIP path escaped destination".into());}
        }
    }
    Ok(())
}
fn launch_build(id:&str)->Result<(),String>{
    let exe=std::env::current_exe().map_err(|e|e.to_string())?;
    let workspace=std::env::current_dir().map_err(|e|e.to_string())?;
    std::fs::create_dir_all(state_dir()).map_err(|e|e.to_string())?;
    std::fs::write(state_dir().join(format!("{id}.status")), "pending_build").map_err(|e|e.to_string())?;
    let script=root().join("build-module.sh");
    std::fs::write(&script, BUILD_SCRIPT).map_err(|e|e.to_string())?;
    #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; std::fs::set_permissions(&script,std::fs::Permissions::from_mode(0o700)).map_err(|e|e.to_string())?; }
    let log=state_dir().join(format!("{id}.log"));
    let status=state_dir().join(format!("{id}.status"));
    let unit=format!("omnirs-module-build-{}-{}",id,std::process::id());
    let systemd=Command::new("systemd-run")
        .arg(format!("--unit={unit}" )).arg("--collect").arg("--no-block")
        .arg("--property=Type=oneshot").arg("/bin/sh").arg(&script)
        .arg(&workspace).arg(&exe).arg(id).arg(&log).arg(&status)
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status();
    if matches!(systemd,Ok(s) if s.success()) { return Ok(()); }
    let mut cmd=Command::new("sh");
    cmd.arg(&script).arg(&workspace).arg(&exe).arg(id).arg(&log).arg(&status)
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    #[cfg(unix)] { use std::os::unix::process::CommandExt; cmd.process_group(0); }
    cmd.spawn().map_err(|e|format!("не удалось запустить фоновую сборку: {e}"))?;
    Ok(())
}
const BUILD_SCRIPT:&str=r##"#!/bin/sh
set -eu
ROOT="$1"; EXE="$2"; ID="$3"; LOG="$4"; STATUS="$5"
printf 'building' > "$STATUS"
cd "$ROOT"
if ! cargo build --release -p omni-server > "$LOG" 2>&1; then
  printf 'build_failed' > "$STATUS"
  echo 'Новая версия исходников сохранена для исправления; действующий бинарник не заменён.' >> "$LOG"
  exit 1
fi
NEW="$EXE.omni-new"
cp "$ROOT/target/release/OmniRS" "$NEW"
chmod 0755 "$NEW"
mv -f "$NEW" "$EXE"
rm -rf "$ROOT/modules/staging/$ID.old"
printf 'installed' > "$STATUS"
# Restart is intentionally delegated to systemd; the already-running executable is not modified in-place.
if ! command -v systemctl >/dev/null 2>&1; then printf 'restart_failed' > "$STATUS"; echo 'systemctl не найден; заменённый бинарник требует ручного перезапуска' >> "$LOG"; exit 1; fi
if ! systemctl restart omnirs.service >> "$LOG" 2>&1; then printf 'restart_failed' > "$STATUS"; exit 1; fi
"##;

pub async fn handle(_state:Arc<AppState>,method:Method,endpoint:String,body:Bytes)->Response<Body>{
    let ep=endpoint.trim_start_matches('/').strip_prefix("modules").unwrap_or(endpoint.trim_start_matches('/')).trim_start_matches('/');
    if method==Method::GET && (ep.is_empty()||ep=="list") {
        return match records().await { Ok(list)=>{
            let mut out:Vec<Value>=Vec::with_capacity(list.len());
            for mut m in list {
                if m.kind != "system" { let status_file=state_dir().join(format!("{}.status",m.module_id)); if let Ok(st)=std::fs::read_to_string(status_file){m.status=st;} }
                let source=if m.kind=="system" {"system"} else {"installed"};
                let mut value=serde_json::to_value(m).unwrap_or(Value::Null);
                value["source"]=json!(source);
                out.push(value);
            }
            json_resp(StatusCode::OK,json!({"ok":true,"modules":out,"dir":installed().to_string_lossy()}))
        },Err(e)=>json_resp(StatusCode::INTERNAL_SERVER_ERROR,json!({"ok":false,"error":e})) };
    }
    if method==Method::POST && ep.starts_with("upload/") {
        let id=ep.trim_start_matches("upload/");
        if !valid_id(id){return json_resp(StatusCode::BAD_REQUEST,json!({"ok":false,"error":"invalid module id"}));}
        if body.is_empty(){return json_resp(StatusCode::BAD_REQUEST,json!({"ok":false,"error":"empty ZIP"}));}
        if SYSTEM_MODULES.iter().any(|(system_id,_,_)| *system_id == id) { return json_resp(StatusCode::CONFLICT,json!({"ok":false,"error":"ID зарезервирован системным модулем"})); }
        let temp=root().join("staging").join(format!("{id}.new")); let dest=installed().join(id); let backup=root().join("staging").join(format!("{id}.old"));
        let updating=dest.exists();
        let _=std::fs::remove_dir_all(&temp); let _=std::fs::remove_dir_all(&backup);
        if let Err(e)=safe_extract(&body,&temp){let _=std::fs::remove_dir_all(&temp);return json_resp(StatusCode::BAD_REQUEST,json!({"ok":false,"error":e}));}
        let manifest_path=temp.join("module.toml");
        let manifest=match std::fs::read_to_string(&manifest_path).ok().and_then(|s|toml::from_str::<Manifest>(&s).ok()) {Some(m)=>m,None=>{let _=std::fs::remove_dir_all(&temp);return json_resp(StatusCode::BAD_REQUEST,json!({"ok":false,"error":"module.toml отсутствует или некорректен"}));}};
        if manifest.id!=id || !valid_id(&manifest.id) || manifest.kind!="source" {let _=std::fs::remove_dir_all(&temp);return json_resp(StatusCode::BAD_REQUEST,json!({"ok":false,"error":"manifest.id должен совпадать с ID загрузки; kind должен быть source"}));}
        if !manifest.entry.starts_with("src/") || manifest.entry.contains("..") || !temp.join(&manifest.entry).is_file() || !manifest.entry.ends_with(".rs") {let _=std::fs::remove_dir_all(&temp);return json_resp(StatusCode::BAD_REQUEST,json!({"ok":false,"error":"entry должен указывать на существующий Rust-файл внутри src/, например src/installer.rs"}));}
        if !manifest.admin_entry.is_empty() && (!manifest.admin_entry.starts_with("admin/") || manifest.admin_entry.contains("..")){let _=std::fs::remove_dir_all(&temp);return json_resp(StatusCode::BAD_REQUEST,json!({"ok":false,"error":"admin_entry должен указывать внутрь admin/"}));}
        if dest.exists(){if let Err(e)=std::fs::rename(&dest,&backup){return json_resp(StatusCode::INTERNAL_SERVER_ERROR,json!({"ok":false,"error":e.to_string()}));}}
        if let Err(e)=std::fs::rename(&temp,&dest){if backup.exists(){let _=std::fs::rename(&backup,&dest);}return json_resp(StatusCode::INTERNAL_SERVER_ERROR,json!({"ok":false,"error":e.to_string()}));}
        let rec=ModuleRecord{module_id:id.into(),name:manifest.name,version:manifest.version,status:"pending_build".into(),src_path:dest.to_string_lossy().into_owned(),artifact_path:String::new(),build_log:String::new(),enabled:true,description:manifest.description,admin_entry:manifest.admin_entry,kind:manifest.kind};
        if let Err(e)=save_record(rec).await {let _=std::fs::remove_dir_all(&dest);if backup.exists(){let _=std::fs::rename(&backup,&dest);}return json_resp(StatusCode::INTERNAL_SERVER_ERROR,json!({"ok":false,"error":e}));}
        if let Err(e)=launch_build(id){return json_resp(StatusCode::INTERNAL_SERVER_ERROR,json!({"ok":false,"error":e,"source_installed":true}));}
        return json_resp(StatusCode::ACCEPTED,json!({"ok":true,"module_id":id,"status":"pending_build","updated":updating,"message":"Исходники установлены; выполняется пересборка основного OmniRS"}));
    }
    if method==Method::GET && ep.starts_with("status/"){
        let id=ep.trim_start_matches("status/"); if !valid_id(id){return json_resp(StatusCode::BAD_REQUEST,json!({"ok":false}));}
        let p=state_dir().join(format!("{id}.status")); let s=std::fs::read_to_string(p).unwrap_or_else(|_|"pending_build".into());
        let log=std::fs::read_to_string(state_dir().join(format!("{id}.log"))).unwrap_or_default();
        return json_resp(StatusCode::OK,json!({"ok":true,"module_id":id,"status":s,"build_log":log}));
    }
    if method==Method::GET && ep.starts_with("asset/") {
        return json_resp(StatusCode::BAD_REQUEST,json!({"ok":false,"error":"use /module-assets/<id>/<path>"}));
    }
    if method==Method::POST && ep.starts_with("delete/"){
        let id=ep.trim_start_matches("delete/");if !valid_id(id){return json_resp(StatusCode::BAD_REQUEST,json!({"ok":false,"error":"invalid id"}));}
        let _=std::fs::remove_dir_all(installed().join(id));
        let id_owned=id.to_string();
        let result=tokio::task::spawn_blocking(move||db_call(move|c|c.execute("DELETE FROM OmniModules WHERE module_id=?1",[id_owned]).map(|_|()))).await;
        match result { Ok(Ok(()))=>{}, Ok(Err(e))=>return json_resp(StatusCode::INTERNAL_SERVER_ERROR,json!({"ok":false,"error":e})), Err(e)=>return json_resp(StatusCode::INTERNAL_SERVER_ERROR,json!({"ok":false,"error":e.to_string()})) }
        if let Err(e)=launch_build(id){return json_resp(StatusCode::INTERNAL_SERVER_ERROR,json!({"ok":false,"error":e,"source_deleted":true}));}
        return json_resp(StatusCode::ACCEPTED,json!({"ok":true,"message":"Модуль удалён; выполняется пересборка основного бинарника"}));
    }
    json_resp(StatusCode::NOT_FOUND,json!({"ok":false,"error":"unknown module endpoint"}))
}
