use omni_core::crypto;
// ═══════════════════════════════════════════════════════════════════════════
// OmniRS db.rs — Database Manager (SQLite) — config.toml-free
// ═══════════════════════════════════════════════════════════════════════════
//  • Единственный источник истины: таблица config в ./db/OmniDB
//  • Создаёт ВСЕ системные таблицы:
//      OmniDB  : config, OmniVPN, OmniDNS, OmniProxy, OmniMetrics, OmniSsl
//      OmniVPN : vpn_one_time_links
//  • Bootstrap из env vars, если config пустой
//  • Одноразовая миграция из config.toml (если файл ещё есть)
//  • NOTE: требует `pub mod crypto` в vpn.rs (для ключей в seed OmniVPN id=1)
use axum::{ body::{Body, Bytes}, http::{HeaderMap, Method, StatusCode}, response::Response };
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use rusqlite::OptionalExtension;

fn default_true() -> bool { true }
fn default_rows() -> usize { 1000 }
fn default_timeout() -> u64 { 30 }
fn default_pool() -> u32 { 5 }
fn default_history() -> usize { 200 }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)] #[serde(rename_all = "lowercase")] pub enum DbKind { Sqlite }
impl DbKind { pub fn as_str(&self) -> &'static str { match self { Self::Sqlite => "sqlite" } } }
#[derive(Clone, Debug, Serialize, Deserialize)] pub struct ConnectionConfig { pub id: String, pub name: String, pub kind: DbKind, pub url: String, #[serde(default)] pub readonly: bool, #[serde(default = "default_pool")] pub pool_size: u32, #[serde(default)] pub description: String }
#[derive(Clone, Debug, Serialize, Deserialize)] pub struct DbConfig { #[serde(default = "default_true")] pub enabled: bool, #[serde(default)] pub db_dir: Option<String>, #[serde(default)] pub allow_ddl: bool, #[serde(default)] pub allow_write: bool, #[serde(default = "default_rows")] pub max_rows: usize, #[serde(default = "default_timeout")] pub query_timeout_secs: u64, #[serde(default = "default_history")] pub history_size: usize, #[serde(default)] pub connections: Vec<ConnectionConfig> }
impl Default for DbConfig { fn default() -> Self { Self { enabled: true, db_dir: Some("./db".into()), allow_ddl: false, allow_write: false, max_rows: default_rows(), query_timeout_secs: default_timeout(), history_size: default_history(), connections: Vec::new() } } }
impl DbConfig { pub fn from_env() -> Self { let mut c = Self::default(); if let Ok(v) = std::env::var("OMNIRS_DB_DIR") { c.db_dir = Some(v); } if let Ok(v) = std::env::var("OMNIRS_DB_ENABLED") { c.enabled = matches!(v.as_str(), "1" | "true" | "yes"); } if let Ok(v) = std::env::var("OMNIRS_DB_ALLOW_DDL") { c.allow_ddl = matches!(v.as_str(), "1" | "true" | "yes"); } if let Ok(v) = std::env::var("OMNIRS_DB_ALLOW_WRITE") { c.allow_write = matches!(v.as_str(), "1" | "true" | "yes"); } c } pub fn overlay_from_map(&mut self, m: &HashMap<String, String>) { let b = |k: &str, d: bool| m.get(k).map(|v| matches!(v.as_str(), "1" | "true" | "yes")).unwrap_or(d); let n = |k: &str, d: u64| m.get(k).and_then(|v| v.parse().ok()).unwrap_or(d); self.enabled = b("db.enabled", self.enabled); self.allow_ddl = b("db.allow_ddl", self.allow_ddl); self.allow_write = b("db.allow_write", self.allow_write); self.max_rows = n("db.max_rows", self.max_rows as u64) as usize; self.query_timeout_secs = n("db.query_timeout_secs", self.query_timeout_secs); self.history_size = n("db.history_size", self.history_size as u64) as usize; if let Some(d) = m.get("db.db_dir") { self.db_dir = Some(d.clone()); } } }
#[derive(Clone)] pub enum Pool { Sqlite(Arc<StdMutex<rusqlite::Connection>>) }
#[derive(Default, Debug, Serialize, Clone)] pub struct ConnectionStats { pub queries_total: u64, pub queries_failed: u64, pub total_latency_ms: u64, pub avg_latency_ms: f64 }
pub struct DbConnection { pub config: ConnectionConfig, pub pool: Pool, pub healthy: bool, pub last_check: Instant, pub stats: StdMutex<ConnectionStats> }
#[derive(Clone, Debug, Serialize)] pub struct QueryHistoryEntry { pub ts: i64, pub conn_id: String, pub conn_name: String, pub sql: String, pub ok: bool, pub rows: usize, pub latency_ms: u64, pub error: Option<String>, pub client_ip: String }
pub struct DbManager { pub config: DbConfig, pub conns: RwLock<HashMap<String, Arc<DbConnection>>>, pub history: RwLock<Vec<QueryHistoryEntry>> }

// ─── Global singleton ───────────────────────────────────────────────────────
static GLOBAL_DB: OnceLock<Arc<DbManager>> = OnceLock::new();
pub fn global() -> Option<Arc<DbManager>> { GLOBAL_DB.get().cloned() }
pub async fn init_global() -> Result<Arc<DbManager>, String> { if let Some(m) = GLOBAL_DB.get() { return Ok(m.clone()); } let m = Arc::new(DbManager::from_env().await?); let _ = GLOBAL_DB.set(m.clone()); Ok(GLOBAL_DB.get().cloned().unwrap_or(m)) }

// ─── Пути — публичные, чтобы vpn.rs использовал их ─────────────────────────
pub fn db_dir() -> PathBuf { std::env::var("OMNIRS_DB_DIR").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("./db")) }
pub fn omni_db_path() -> PathBuf { db_dir().join("OmniDB") }
pub fn vpn_db_path() -> PathBuf { db_dir().join("OmniVPN") }
pub fn open_omni() -> rusqlite::Result<rusqlite::Connection> { let _ = std::fs::create_dir_all(db_dir()); let c = rusqlite::Connection::open(omni_db_path())?; c.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;")?; Ok(c) }
pub fn open_vpn() -> rusqlite::Result<rusqlite::Connection> { let _ = std::fs::create_dir_all(db_dir()); let c = rusqlite::Connection::open(vpn_db_path())?; c.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;")?; Ok(c) }

// ─── Схема: config + OmniVPN + OmniDNS + OmniProxy + OmniMetrics + OmniSsl ──
pub fn init_system_schema(c: &rusqlite::Connection) -> rusqlite::Result<()> {
    c.execute_batch(r#"CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);"#)?;
    c.execute_batch(r#"CREATE TABLE IF NOT EXISTS OmniModules (
        module_id TEXT PRIMARY KEY,
        name TEXT NOT NULL DEFAULT '',
        version TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'pending_build',
        src_path TEXT,
        artifact_path TEXT,
        build_log TEXT,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );"#)?;
    c.execute(r#"CREATE TABLE IF NOT EXISTS OmniVPN (
        id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL DEFAULT 0, interface_id TEXT NOT NULL DEFAULT 'vpn0',
        name TEXT NOT NULL DEFAULT 'OmniVPN', password TEXT NOT NULL DEFAULT '',
        ipv4_address TEXT NOT NULL DEFAULT '10.80.0.2', ipv6_address TEXT NOT NULL DEFAULT 'fdcc::80:2',
        vpn_ipv4_address TEXT NOT NULL DEFAULT '10.88.0.2', vpn_ipv6_address TEXT NOT NULL DEFAULT 'fdcc::88:2',
        private_key TEXT NOT NULL DEFAULT '', public_key TEXT NOT NULL DEFAULT '', pre_shared_key TEXT NOT NULL DEFAULT '',
        allowed_ips TEXT, server_allowed_ips TEXT NOT NULL DEFAULT '[]', firewall_ips TEXT,
        persistent_keepalive INTEGER NOT NULL DEFAULT 0, mtu INTEGER NOT NULL DEFAULT 1420,
        dns TEXT, server_endpoint TEXT, expires_at TEXT, enabled INTEGER NOT NULL DEFAULT 1,
        j_c INTEGER, j_min INTEGER, j_max INTEGER, i1 TEXT, i2 TEXT, i3 TEXT, i4 TEXT, i5 TEXT,
        content_padding_addition TEXT, rekey_after_time TEXT, rekey_timeout TEXT,
        reject_after_time TEXT, keepalive_timeout TEXT, max_handshake_attempts TEXT,
        disable_cookies INTEGER, random_trailers INTEGER,
        device TEXT NOT NULL DEFAULT 'eth0', port INTEGER NOT NULL DEFAULT 880,
        vpn_port INTEGER NOT NULL DEFAULT 888,
        ipv4_cidr TEXT NOT NULL DEFAULT '10.80.0.0/24', ipv6_cidr TEXT NOT NULL DEFAULT 'fdcc::80:0/112',
        vpn_ipv4_cidr TEXT NOT NULL DEFAULT '10.88.0.0/24', vpn_ipv6_cidr TEXT NOT NULL DEFAULT 'fdcc::88:0/112',
        iface_mtu INTEGER NOT NULL DEFAULT 1420, routing_table TEXT NOT NULL DEFAULT 'auto',
        iface_enabled INTEGER NOT NULL DEFAULT 1, firewall_enabled INTEGER NOT NULL DEFAULT 0,
        iface_private_key TEXT NOT NULL DEFAULT '', iface_public_key TEXT NOT NULL DEFAULT '',
        iface_j_c INTEGER, iface_j_min INTEGER, iface_j_max INTEGER,
        s1 INTEGER, s2 INTEGER, s3 INTEGER, s4 INTEGER,
        h1 TEXT, h2 TEXT, h3 TEXT, h4 TEXT,
        iface_i1 TEXT, iface_i2 TEXT, iface_i3 TEXT, iface_i4 TEXT, iface_i5 TEXT,
        header_protection_key TEXT,
        default_mtu INTEGER NOT NULL DEFAULT 1420, default_persistent_keepalive INTEGER NOT NULL DEFAULT 0,
        default_dns TEXT NOT NULL DEFAULT '["1.1.1.1","2606:4700:4700::1111"]',
        default_allowed_ips TEXT NOT NULL DEFAULT '["0.0.0.0/0","::/0"]',
        default_j_c INTEGER, default_j_min INTEGER, default_j_max INTEGER,
        default_i1 TEXT, default_i2 TEXT, default_i3 TEXT, default_i4 TEXT, default_i5 TEXT,
        host TEXT NOT NULL DEFAULT '',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )"#, [])?;
    c.execute(r#"CREATE TABLE IF NOT EXISTS OmniDNS (id INTEGER PRIMARY KEY AUTOINCREMENT, zone TEXT, name TEXT, rtype TEXT, ttl INTEGER, rdata TEXT, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)"#, [])?;
    c.execute(r#"CREATE TABLE IF NOT EXISTS OmniProxy (id INTEGER PRIMARY KEY AUTOINCREMENT, host TEXT UNIQUE NOT NULL, path TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)"#, [])?;
    c.execute(r#"CREATE TABLE IF NOT EXISTS OmniMetrics (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, metric TEXT NOT NULL, value REAL NOT NULL, meta TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)"#, [])?;
    c.execute(r#"CREATE TABLE IF NOT EXISTS OmniSsl (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT UNIQUE NOT NULL, cert_pem TEXT NOT NULL, key_pem TEXT NOT NULL, not_before INTEGER, not_after INTEGER, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)"#, [])?;
c.execute(r#"CREATE TABLE IF NOT EXISTS OmniTunnel (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL DEFAULT '',
    path_prefix TEXT NOT NULL UNIQUE,
    allow_targets TEXT NOT NULL DEFAULT '[]',
    enabled INTEGER NOT NULL DEFAULT 1,
    bytes_in INTEGER NOT NULL DEFAULT 0,
    bytes_out INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
)"#, [])?;

// Seed: если таблица пуста — создаём дефолтного клиента, зеркалящего config.*
let tunnel_count: i64 = c
    .query_row("SELECT COUNT(*) FROM OmniTunnel", [], |r| r.get(0))
    .unwrap_or(0);
if tunnel_count == 0 {
    let pw = gen_tunnel_password();
    let _ = c.execute(
        "INSERT INTO OmniTunnel (name, password, path_prefix, allow_targets, enabled) \
         VALUES ('default', ?1, 'v1', ?2, 1)",
        rusqlite::params![pw, r#"["127.0.0.1:443","127.0.0.1:888"]"#],
    );
    eprintln!(
        "[DB] seeded default tunnel client (path_prefix=v1, password={}…)",
        &pw.chars().take(8).collect::<String>()
    );
}
    let has: i64 = c.query_row("SELECT COUNT(*) FROM OmniVPN WHERE id=1", [], |r| r.get(0)).unwrap_or(0);
    if has == 0 {
        let c_sk = crypto::genkey().unwrap_or_default();
        let c_pk = crypto::pubkey(&c_sk).unwrap_or_default();
        let c_psk = crypto::genpsk().unwrap_or_default();
        let s_sk = crypto::genkey().unwrap_or_default();
        let s_pk = crypto::pubkey(&s_sk).unwrap_or_default();

        
let (jc, jmin, jmax, s1, s2, s3, s4, h1, h2, h3, h4) = gen_obfs_defaults_sync();

let _ = c.execute(
    r#"INSERT INTO OmniVPN (
        id, user_id, interface_id, name, private_key, public_key, pre_shared_key,
        iface_private_key, iface_public_key,
        ipv4_address, ipv6_address, ipv4_cidr, ipv6_cidr,
        vpn_ipv4_address, vpn_ipv6_address, vpn_port, vpn_ipv4_cidr, vpn_ipv6_cidr,
        iface_enabled, firewall_enabled, enabled,
        iface_j_c, iface_j_min, iface_j_max, s1, s2, s3, s4,
        h1, h2, h3, h4,
        default_j_c, default_j_min, default_j_max
       )
       VALUES (1, 0, 'vpn0', 'OmniVPN', ?1, ?2, ?3, ?4, ?5,
               '10.80.0.2', 'fdcc::80:2', '10.80.0.0/24', 'fdcc::80:0/112',
               '10.88.0.2', 'fdcc::88:2', 888, '10.88.0.0/24', 'fdcc::88:0/112',
               1, 1, 1,
               ?6, ?7, ?8, ?9, ?10, ?11, ?12,
               ?13, ?14, ?15, ?16,
               ?6, ?7, ?8
       )"#,
    rusqlite::params![c_sk, c_pk, c_psk, s_sk, s_pk,
                      jc, jmin, jmax, s1, s2, s3, s4,
                      h1, h2, h3, h4],
);
eprintln!("[DB] OBFS defaults generated: Jc={jc} Jmin={jmin} Jmax={jmax} S1={s1} S2={s2} S3={s3} S4={s4} H1={h1} H2={h2} H3={h3} H4={h4}");
    }

    migrate_legacy_vpn_tables(c);
resync_iface_keypair(c);
resync_client_keypair(c);
fill_missing_s3s4(c);
Ok(())
}

fn gen_obfs_defaults_sync() -> (i64, i64, i64, i64, i64, i64, i64, String, String, String, String) {
    let mut bytes = [0u8; 32];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut bytes);
    }
    let mut seed = u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
    ]) ^ 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        seed ^= seed >> 12; seed ^= seed << 25; seed ^= seed >> 27;
        seed.wrapping_mul(0x2545F4914F6CDD1D)
    };
    let mut pick = |lo: u64, hi: u64| -> u64 { lo + (next() % (hi - lo + 1)) };

    let jc: i64 = pick(1, 128) as i64;
    let jmin: i64 = pick(0, 1279) as i64;
    let jmax: i64 = pick(jmin as u64, 1280) as i64;
    let s1: i64 = pick(15, 150) as i64;
    let s2: i64 = pick(15, 150) as i64;
    let s3: i64 = pick(15, 150) as i64;
    let s4: i64 = pick(15, 150) as i64;
    let mut hs = std::collections::HashSet::new();
    while hs.len() < 4 { hs.insert(pick(5, 2147483647) as u32); }
    let hs: Vec<u32> = hs.into_iter().collect();

    (jc, jmin, jmax, s1, s2, s3, s4,
     hs[0].to_string(), hs[1].to_string(), hs[2].to_string(), hs[3].to_string())
}


/// Приводит iface_public_key в соответствие с iface_private_key.
/// Идемпотентна — если ключи уже согласованы, ничего не пишет.
fn resync_iface_keypair(c: &rusqlite::Connection) {
    let (sk, pk_stored): (String, String) = match c.query_row(
        "SELECT iface_private_key, iface_public_key FROM OmniVPN WHERE id=1",
        [], |r| Ok((r.get(0)?, r.get(1)?)),
    ) {
        Ok(t) => t,
        Err(_) => return,
    };
    if sk.is_empty() { return; }
    let pk_derived = match crypto::pubkey(&sk) {
        Ok(p) => p,
        Err(_) => return,
    };
    if pk_derived != pk_stored {
        let _ = c.execute(
            "UPDATE OmniVPN SET iface_public_key=?1, updated_at=CURRENT_TIMESTAMP WHERE id=1",
            rusqlite::params![pk_derived],
        );
        eprintln!(
            "[DB] resync iface keypair: {} -> {}",
            &pk_stored[..8.min(pk_stored.len())],
            &pk_derived[..8.min(pk_derived.len())]
        );
    }
}

/// Приводит OmniVPN.public_key (client-строка id=1) в соответствие с private_key.
/// Идемпотентна. Не трогает pre_shared_key — он симметричный, его менять нельзя.
fn resync_client_keypair(c: &rusqlite::Connection) {
    let (sk, pk_stored): (String, String) = match c.query_row(
        "SELECT private_key, public_key FROM OmniVPN WHERE id=1",
        [], |r| Ok((r.get(0)?, r.get(1)?)),
    ) {
        Ok(t) => t,
        Err(_) => return,
    };
    if sk.is_empty() { return; }
    let pk_derived = match crypto::pubkey(&sk) {
        Ok(p) => p,
        Err(_) => return,
    };
    if pk_derived != pk_stored {
        let _ = c.execute(
            "UPDATE OmniVPN SET public_key=?1, updated_at=CURRENT_TIMESTAMP WHERE id=1",
            rusqlite::params![pk_derived],
        );
        eprintln!(
            "[DB] resync client keypair (id=1): {} -> {}",
            &pk_stored[..8.min(pk_stored.len())],
            &pk_derived[..8.min(pk_derived.len())]
        );
    }
}


/// ★ Миграция для существующих БД: дозаполняет s3/s4, если они NULL.
///   До фикса vpn.rs S3/S4 не отправлялись в ядро → было неважно,
///   что они NULL. Теперь vpn.rs шлёт S3/S4 → нужны значения.
///   Идемпотентна: если s3/s4 уже заданы — ничего не делает.
fn fill_missing_s3s4(c: &rusqlite::Connection) {
    let need: bool = c
        .query_row(
            "SELECT iface_j_c IS NOT NULL AND (s3 IS NULL OR s4 IS NULL) FROM OmniVPN WHERE id=1",
            [],
            |r| r.get(0),
        )
        .unwrap_or(false);
    if !need { return; }

    // Генерим как в gen_awg_defaults_sync: 15..150
    let mut bytes = [0u8; 8];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut bytes);
    }
    let s3 = 15 + (bytes[0] as i64 % 136);   // 15..150
    let s4 = 15 + (bytes[1] as i64 % 136);

    let _ = c.execute(
        "UPDATE OmniVPN SET s3 = COALESCE(s3, ?1), s4 = COALESCE(s4, ?2), updated_at=CURRENT_TIMESTAMP WHERE id=1",
        rusqlite::params![s3, s4],
    );
    eprintln!("[DB] filled missing S3={s3} S4={s4}");
}

/// Миграция из legacy-таблиц (очень старые версии). На чистой установке — no-op.
fn migrate_legacy_vpn_tables(c: &rusqlite::Connection) {
    if c.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='vpn_interfaces'", [], |r| r.get::<_, i64>(0)).unwrap_or(0) > 0 {
        let _ = c.execute(r#"UPDATE OmniVPN SET device = COALESCE((SELECT device FROM vpn_interfaces LIMIT 1), device), port = COALESCE((SELECT port FROM vpn_interfaces LIMIT 1), port), iface_private_key = COALESCE((SELECT private_key FROM vpn_interfaces LIMIT 1), iface_private_key), iface_public_key = COALESCE((SELECT public_key FROM vpn_interfaces LIMIT 1), iface_public_key), ipv4_cidr = COALESCE((SELECT ipv4_cidr FROM vpn_interfaces LIMIT 1), ipv4_cidr), ipv6_cidr = COALESCE((SELECT ipv6_cidr FROM vpn_interfaces LIMIT 1), ipv6_cidr), iface_mtu = COALESCE((SELECT mtu FROM vpn_interfaces LIMIT 1), iface_mtu), routing_table = COALESCE((SELECT routing_table FROM vpn_interfaces LIMIT 1), routing_table), iface_enabled = COALESCE((SELECT enabled FROM vpn_interfaces LIMIT 1), iface_enabled), firewall_enabled = COALESCE((SELECT firewall_enabled FROM vpn_interfaces LIMIT 1), firewall_enabled) WHERE id=1"#, []);
        let _ = c.execute("DROP TABLE vpn_interfaces", []);
    }
    if c.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='vpn_user_configs'", [], |r| r.get::<_, i64>(0)).unwrap_or(0) > 0 {
        let _ = c.execute(r#"UPDATE OmniVPN SET default_mtu = COALESCE((SELECT default_mtu FROM vpn_user_configs LIMIT 1), default_mtu), default_persistent_keepalive = COALESCE((SELECT default_persistent_keepalive FROM vpn_user_configs LIMIT 1), default_persistent_keepalive), default_dns = COALESCE((SELECT default_dns FROM vpn_user_configs LIMIT 1), default_dns), default_allowed_ips = COALESCE((SELECT default_allowed_ips FROM vpn_user_configs LIMIT 1), default_allowed_ips), host = COALESCE((SELECT host FROM vpn_user_configs LIMIT 1), host) WHERE id=1"#, []);
        let _ = c.execute("DROP TABLE vpn_user_configs", []);
    }
    let _ = c.execute("DROP TABLE IF EXISTS vpn_users", []);
    let _ = c.execute("DROP TABLE IF EXISTS vpn_hooks", []);
}

pub fn init_vpn_schema(c: &rusqlite::Connection) -> rusqlite::Result<()> {
    c.execute(r#"CREATE TABLE IF NOT EXISTS vpn_one_time_links (id INTEGER PRIMARY KEY, client_id INTEGER NOT NULL, one_time_link TEXT UNIQUE NOT NULL, expires_at TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)"#, [])?;
    // Миграция из legacy-таблицы vpn_clients. На чистой установке — no-op.
    if c.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='vpn_clients'", [], |r| r.get::<_, i64>(0)).unwrap_or(0) > 0 {
        if let Ok(mut stmt) = c.prepare("SELECT id, name, ipv4, ipv6, private_key, public_key, pre_shared_key, COALESCE(enabled,1), COALESCE(password,''), COALESCE(mtu,1420), COALESCE(persistent_keepalive,0) FROM vpn_clients") {
            let rows: Vec<(i64, String, String, String, String, String, String, i64, String, i64, i64)> = stmt.query_map([], |r| Ok((r.get(0).unwrap_or(0), r.get(1).unwrap_or_default(), r.get(2).unwrap_or_default(), r.get(3).unwrap_or_default(), r.get(4).unwrap_or_default(), r.get(5).unwrap_or_default(), r.get(6).unwrap_or_default(), r.get(7).unwrap_or(1), r.get(8).unwrap_or_default(), r.get(9).unwrap_or(1420), r.get(10).unwrap_or(0)))).map(|it| it.filter_map(Result::ok).collect()).unwrap_or_default();
            for (id, name, ipv4, ipv6, sk, pk, psk, en, pwd, mtu, pk2) in rows {
                if name.is_empty() || name == "OmniVPN" { continue; }
                let _ = create_client_table(c, &name);
                let tbl = client_table_name(&name);
                let _ = c.execute(&format!(
                    "INSERT OR IGNORE INTO \"{}\" (\
                        id,user_id,interface_id,name,password,\
                        ipv4_address,ipv6_address,private_key,public_key,pre_shared_key,\
                        allowed_ips,server_allowed_ips,persistent_keepalive,mtu,enabled\
                    ) VALUES (?1,0,'vpn0',?2,?3,?4,?5,?6,?7,?8,NULL,'[]',?9,?10,?11)",
                    tbl
                ), rusqlite::params![id, name, pwd, ipv4, ipv6, sk, pk, psk, pk2, mtu, en]);
            }
        }
        let _ = c.execute("DROP TABLE vpn_clients", []);
    }
    let _ = c.execute("DROP TABLE IF EXISTS OmniVPN", []);
    let _ = c.execute("DROP VIEW IF EXISTS c_OmniVPN_config", []);
    Ok(())
}

// ─── Helpers ───────────────────────────────────────────────────────────────
fn strip_sqlite_prefix(url: &str) -> &str { url.strip_prefix("sqlite://").or_else(|| url.strip_prefix("sqlite:")).unwrap_or(url) }
async fn build_pool(cc: &ConnectionConfig) -> Result<Pool, String> { match cc.kind { DbKind::Sqlite => { let path = strip_sqlite_prefix(&cc.url).to_string(); let conn = tokio::task::spawn_blocking(move || { let c = rusqlite::Connection::open(&path).map_err(|e| format!("sqlite open: {e}"))?; let _ = c.pragma_update(None, "journal_mode", "WAL"); let _ = c.busy_timeout(Duration::from_secs(5)); Ok::<_, String>(c) }).await.map_err(|e| format!("sqlite task: {e}"))??; Ok(Pool::Sqlite(Arc::new(StdMutex::new(conn)))) } } }
fn now() -> i64 { SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0) }
fn strip_sql_comments(s: &str) -> String { let mut out = String::with_capacity(s.len()); let mut chars = s.chars().peekable(); while let Some(c) = chars.next() { if c == '-' && chars.peek() == Some(&'-') { for c2 in chars.by_ref() { if c2 == '\n' { out.push('\n'); break; } } } else if c == '/' && chars.peek() == Some(&'*') { chars.next(); loop { match chars.next() { Some('*') if chars.peek() == Some(&'/') => { chars.next(); break; } Some(_) => {} None => break } } } else { out.push(c); } } out }
fn sql_kind(sql: &str) -> &'static str { let s = strip_sql_comments(sql).trim_start().trim_start_matches(|c: char| c == '(' || c.is_whitespace()).to_uppercase(); let first = s.split_whitespace().next().unwrap_or("").trim_end_matches(';'); match first { "SELECT" | "SHOW" | "DESCRIBE" | "DESC" | "EXPLAIN" | "WITH" | "PRAGMA" | "VALUES" => "read", "INSERT" | "UPDATE" | "DELETE" | "REPLACE" | "MERGE" | "UPSERT" => "write", "CREATE" | "DROP" | "ALTER" | "TRUNCATE" | "RENAME" => "ddl", _ => "other" } }
fn rusqlite_value_to_json(v: Option<&rusqlite::types::ValueRef>) -> serde_json::Value { match v { Some(rusqlite::types::ValueRef::Null) | None => serde_json::Value::Null, Some(rusqlite::types::ValueRef::Integer(i)) => serde_json::Value::from(*i), Some(rusqlite::types::ValueRef::Real(f)) => serde_json::Value::from(*f), Some(rusqlite::types::ValueRef::Text(t)) => serde_json::Value::String(String::from_utf8_lossy(t).into_owned()), Some(rusqlite::types::ValueRef::Blob(b)) => serde_json::Value::String(format!("<blob {} bytes>", b.len())) } }
fn json_ok(v: serde_json::Value) -> Response<Body> { Response::builder().status(StatusCode::OK).header("content-type", "application/json").header("cache-control", "no-store").body(Body::from(v.to_string())).unwrap_or_else(|_| Response::new(Body::empty())) }
fn json_err(status: StatusCode, msg: impl Into<String>) -> Response<Body> { Response::builder().status(status).header("content-type", "application/json").body(Body::from(serde_json::json!({"error": msg.into()}).to_string())).unwrap_or_else(|_| Response::new(Body::empty())) }

fn flatten_toml(prefix: &str, v: &toml::Value, out: &mut Vec<(String, String)>) {
    match v {
        toml::Value::Table(t) => for (k, vv) in t {
            let p = if prefix.is_empty() { k.clone() } else { format!("{}.{}", prefix, k) };
            flatten_toml(&p, vv, out);
        },
        toml::Value::Array(a) => {
            let json_arr: Vec<serde_json::Value> = a.iter().map(toml_to_json_value).collect();
            let s = serde_json::to_string(&json_arr).unwrap_or_else(|_| "[]".into());
            out.push((prefix.to_string(), s));
        }
        other => out.push((prefix.to_string(), toml_to_plain_string(other))),
    }
}

fn toml_to_plain_string(v: &toml::Value) -> String {
    match v {
        toml::Value::String(s) => s.clone(),
        toml::Value::Integer(i) => i.to_string(),
        toml::Value::Float(f) => f.to_string(),
        toml::Value::Boolean(b) => b.to_string(),
        toml::Value::Datetime(d) => d.to_string(),
        other => other.to_string(),
    }
}

fn toml_to_json_value(v: &toml::Value) -> serde_json::Value {
    match v {
        toml::Value::String(s) => serde_json::Value::String(s.clone()),
        toml::Value::Integer(i) => serde_json::Value::Number((*i).into()),
        toml::Value::Float(f) => serde_json::Number::from_f64(*f).map(serde_json::Value::Number).unwrap_or(serde_json::Value::Null),
        toml::Value::Boolean(b) => serde_json::Value::Bool(*b),
        toml::Value::Datetime(d) => serde_json::Value::String(d.to_string()),
        toml::Value::Array(a) => serde_json::Value::Array(a.iter().map(toml_to_json_value).collect()),
        toml::Value::Table(t) => serde_json::Value::Object(t.iter().map(|(k, v)| (k.clone(), toml_to_json_value(v))).collect()),
    }
}

// ─── Query primitives ──────────────────────────────────────────────────────
async fn execute_sqlite(conn: Arc<StdMutex<rusqlite::Connection>>, sql: String, max_rows: usize, kind: String) -> Result<QueryOutcome, String> { tokio::task::spawn_blocking(move || { let start = Instant::now(); let guard = conn.lock().map_err(|e| format!("lock: {e}"))?; if kind == "read" { let mut stmt = guard.prepare(&sql).map_err(|e| e.to_string())?; let columns: Vec<String> = stmt.column_names().map(|s| s.to_string()).collect(); let mut rows_out = Vec::new(); let mut truncated = false; let mut rows = stmt.query([]).map_err(|e| e.to_string())?; while let Some(row) = rows.next().map_err(|e| e.to_string())? { let mut obj = serde_json::Map::with_capacity(columns.len()); for (i, name) in columns.iter().enumerate() { obj.insert(name.clone(), rusqlite_value_to_json(row.get_ref(i).ok().as_ref())); } rows_out.push(serde_json::Value::Object(obj)); if rows_out.len() > max_rows { truncated = true; break; } } Ok(QueryOutcome::Rows { columns, rows: rows_out, elapsed_ms: start.elapsed().as_millis() as u64, truncated }) } else { let affected = guard.execute(&sql, []).map_err(|e| e.to_string())?; Ok(QueryOutcome::Affected { affected: affected as u64, elapsed_ms: start.elapsed().as_millis() as u64 }) } }).await.map_err(|e| format!("task: {e}"))? }
async fn list_tables(pool: &Pool) -> Result<Vec<serde_json::Value>, String> { match pool { Pool::Sqlite(c) => { let c = c.clone(); tokio::task::spawn_blocking(move || { let g = c.lock().map_err(|e| e.to_string())?; let mut stmt = g.prepare("SELECT name, type, sql FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' ORDER BY type ASC, name ASC").map_err(|e| e.to_string())?; let out: Vec<serde_json::Value> = stmt.query_map([], |r| { Ok(serde_json::json!({ "name": r.get::<_, String>(0)?, "kind": r.get::<_, String>(1)?, "schema": r.get::<_, Option<String>>(2).ok().flatten() })) }).map_err(|e| e.to_string())?.filter_map(Result::ok).collect(); Ok::<_, String>(out) }).await.map_err(|e| format!("task: {e}"))? } } }
async fn describe_table(pool: &Pool, table: &str) -> Result<Vec<serde_json::Value>, String> { match pool { Pool::Sqlite(c) => { let c = c.clone(); let table = table.to_string(); tokio::task::spawn_blocking(move || { let g = c.lock().map_err(|e| e.to_string())?; if !table.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '.' || ch == '-') { return Err("invalid table name".to_string()); } let sql = format!("PRAGMA table_info(\"{}\")", table.replace('"', "\"\"")); let mut stmt = g.prepare(&sql).map_err(|e| e.to_string())?; let out: Vec<serde_json::Value> = stmt.query_map([], |r| { Ok(serde_json::json!({ "column": r.get::<_, String>(1)?, "type": r.get::<_, String>(2).unwrap_or_default(), "nullable": r.get::<_, i64>(3).unwrap_or(0) == 0, "default": r.get::<_, Option<String>>(4).ok().flatten(), "primary_key": r.get::<_, i64>(5).unwrap_or(0) > 0 })) }).map_err(|e| e.to_string())?.filter_map(Result::ok).collect(); Ok::<_, String>(out) }).await.map_err(|e| format!("task: {e}"))? } } }
async fn get_rows(
    pool: &Pool,
    table: &str,
    limit: usize,
    offset: usize,
    search: Option<String>,
) -> Result<serde_json::Value, String> {
    let c = match pool { Pool::Sqlite(c) => c.clone() };
    let table = table.to_string();
    let search = search.unwrap_or_default().trim().to_string();
    let search = if search == "undefined" || search == "null" { String::new() } else { search };

    tokio::task::spawn_blocking(move || {
        let g = c.lock().map_err(|e| e.to_string())?;
        let safe_table = table.replace('"', "\"\"");

        let probe = format!("SELECT rowid FROM \"{}\" LIMIT 0", safe_table);
        let has_rowid = g.prepare(&probe).is_ok();
        let rowid_col = if has_rowid { "rowid as __rowid__, " } else { "" };

        // ★ Собираем список реальных колонок, чтобы искать по ним, а не по имени таблицы
        let mut where_clause = String::new();
        if !search.is_empty() {
            let mut col_stmt = g
                .prepare(&format!("PRAGMA table_info(\"{}\")", safe_table))
                .map_err(|e| e.to_string())?;
            let cols: Vec<String> = col_stmt
                .query_map([], |r| r.get::<_, String>(1))
                .map_err(|e| e.to_string())?
                .filter_map(Result::ok)
                .collect();

            if !cols.is_empty() {
                let esc = search.replace('\'', "''");
                let conds: Vec<String> = cols
                    .iter()
                    .map(|c| format!("CAST(\"{}\" AS TEXT) LIKE '%{}%'", c.replace('"', "\"\""), esc))
                    .collect();
                where_clause = format!("WHERE ({})", conds.join(" OR "));
            }
        }

        let sql = format!(
            "SELECT {}* FROM \"{}\" {} LIMIT {} OFFSET {}",
            rowid_col, safe_table, where_clause, limit, offset
        );
        let mut stmt = g.prepare(&sql).map_err(|e| e.to_string())?;
        let columns: Vec<String> = stmt.column_names().map(|s| s.to_string()).collect();
        let mut rows_out = Vec::new();
        let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
        while let Some(row) = rows.next().map_err(|e| e.to_string())? {
            let mut obj = serde_json::Map::new();
            for (i, name) in columns.iter().enumerate() {
                obj.insert(name.clone(), rusqlite_value_to_json(row.get_ref(i).ok().as_ref()));
            }
            rows_out.push(serde_json::Value::Object(obj));
        }
        let count_sql = format!("SELECT COUNT(*) FROM \"{}\" {}", safe_table, where_clause);
        let total: i64 = g.query_row(&count_sql, [], |r| r.get(0)).unwrap_or(0);
        Ok(serde_json::json!({"columns": columns, "rows": rows_out, "total": total}))
    })
    .await
    .map_err(|e| format!("task: {e}"))?
}
async fn create_table(pool: &Pool, name: &str, columns: &[ColumnDef]) -> Result<(), String> { let c = match pool { Pool::Sqlite(c) => c.clone() }; let name = name.to_string(); let cols = columns.to_vec(); tokio::task::spawn_blocking(move || { let g = c.lock().map_err(|e| e.to_string())?; let cols_sql: Vec<String> = cols.iter().map(|c| format!("\"{}\" {} {}", c.name.replace('"', "\"\""), c.r#type, if c.primary_key { "PRIMARY KEY" } else { "" })).collect(); let sql = format!("CREATE TABLE IF NOT EXISTS \"{}\" ({})", name.replace('"', "\"\""), cols_sql.join(", ")); g.execute(&sql, []).map_err(|e| e.to_string())?; Ok(()) }).await.map_err(|e| format!("task: {e}"))? }
async fn drop_table(pool: &Pool, table: &str) -> Result<(), String> { let c = match pool { Pool::Sqlite(c) => c.clone() }; let table = table.to_string(); tokio::task::spawn_blocking(move || { let g = c.lock().map_err(|e| e.to_string())?; g.execute(&format!("DROP TABLE \"{}\"", table.replace('"', "\"\"")), []).map_err(|e| e.to_string())?; Ok(()) }).await.map_err(|e| format!("task: {e}"))? }
async fn export_database(pool: &Pool) -> Result<Vec<u8>, String> { let c = match pool { Pool::Sqlite(c) => c.clone() }; tokio::task::spawn_blocking(move || { let g = c.lock().map_err(|e| e.to_string())?; let temp_path = format!("/tmp/omnirs_export_{}.db", SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)); let _ = std::fs::remove_file(&temp_path); g.execute(&format!("VACUUM INTO '{}'", temp_path.replace('\'', "''")), []).map_err(|e| e.to_string())?; let data = std::fs::read(&temp_path).map_err(|e| e.to_string())?; let _ = std::fs::remove_file(&temp_path); Ok(data) }).await.map_err(|e| format!("task: {e}"))? }
async fn import_database(pool: &Pool, data: Vec<u8>) -> Result<(), String> { let c = match pool { Pool::Sqlite(c) => c.clone() }; tokio::task::spawn_blocking(move || { let g = c.lock().map_err(|e| e.to_string())?; let temp_path = format!("/tmp/omnirs_import_{}.db", SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)); std::fs::write(&temp_path, &data).map_err(|e| e.to_string())?; g.execute(&format!("ATTACH DATABASE '{}' AS source", temp_path.replace('\'', "''")), []).map_err(|e| e.to_string())?; let mut tables: Vec<(String, Option<String>)> = Vec::new(); { let mut stmt = g.prepare("SELECT name, sql FROM source.sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").map_err(|e| e.to_string())?; let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))).map_err(|e| e.to_string())?; for row in rows { if let Ok((name, sql)) = row { tables.push((name, sql)); } } } for (table, create_sql) in tables { let safe_t = table.replace('"', "\"\""); let _ = g.execute(&format!("DROP TABLE IF EXISTS main.\"{}\"", safe_t), []); if let Some(sql) = create_sql { let sql = sql.replace(&format!("CREATE TABLE \"{}\"", safe_t), &format!("CREATE TABLE main.\"{}\"", safe_t)); g.execute(&sql, []).map_err(|e| e.to_string())?; } g.execute(&format!("INSERT INTO main.\"{}\" SELECT * FROM source.\"{}\"", safe_t, safe_t), []).map_err(|e| e.to_string())?; } g.execute("DETACH DATABASE source", []).map_err(|e| e.to_string())?; let _ = std::fs::remove_file(&temp_path); Ok(()) }).await.map_err(|e| format!("task: {e}"))? }
async fn insert_row(pool: &Pool, table: &str, req: RowRequest) -> Result<(), String> {
    let c = match pool { Pool::Sqlite(c) => c.clone() };
    let table = table.to_string();

    // ★ тот же фильтр — не тащим __rowid__ в INSERT
    let vals: Vec<(String, serde_json::Value)> = req
        .values
        .iter()
        .filter(|(k, _)| !k.starts_with("__"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    if vals.is_empty() {
        return Err("no values to insert".into());
    }

    tokio::task::spawn_blocking(move || {
        let g = c.lock().map_err(|e| e.to_string())?;
        let cols: Vec<String> = vals.iter().map(|(k, _)| k.clone()).collect();
        let placeholders: Vec<String> = (1..=cols.len()).map(|i| format!("?{}", i)).collect();
        let sql = format!(
            "INSERT INTO \"{}\" ({}) VALUES ({})",
            table.replace('"', "\"\""),
            cols.iter().map(|c| format!("\"{}\"", c.replace('"', "\"\""))).collect::<Vec<_>>().join(", "),
            placeholders.join(", ")
        );
        let mut stmt = g.prepare(&sql).map_err(|e| e.to_string())?;
        let params: Vec<rusqlite::types::Value> = vals
            .iter()
            .map(|(_, v)| match v {
                serde_json::Value::Null => rusqlite::types::Value::Null,
                serde_json::Value::Bool(b) => rusqlite::types::Value::Integer(if *b { 1 } else { 0 }),
                serde_json::Value::Number(n) => {
                    if let Some(i) = n.as_i64() {
                        rusqlite::types::Value::Integer(i)
                    } else if let Some(f) = n.as_f64() {
                        rusqlite::types::Value::Real(f)
                    } else {
                        rusqlite::types::Value::Null
                    }
                }
                serde_json::Value::String(s) => rusqlite::types::Value::Text(s.clone()),
                _ => rusqlite::types::Value::Null,
            })
            .collect();
        stmt.execute(rusqlite::params_from_iter(params)).map_err(|e| e.to_string())?;
        Ok(())
    })
    .await
    .map_err(|e| format!("task: {e}"))?
}
async fn update_row(pool: &Pool, table: &str, req: RowRequest) -> Result<(), String> {
    let c = match pool { Pool::Sqlite(c) => c.clone() };
    let table = table.to_string();
    let pk = req.pk.ok_or("pk required for update")?;

    // ★ Выкидываем служебные поля вроде __rowid__, которые фронт отправляет обратно
    let vals: Vec<(String, serde_json::Value)> = req
        .values
        .iter()
        .filter(|(k, _)| !k.starts_with("__"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    if vals.is_empty() {
        return Err("no values to update".into());
    }

    tokio::task::spawn_blocking(move || {
        let g = c.lock().map_err(|e| e.to_string())?;
        let set_clause: Vec<String> = vals
            .iter()
            .map(|(k, _)| format!("\"{}\" = ?", k.replace('"', "\"\"")))
            .collect();
        let sql = format!(
            "UPDATE \"{}\" SET {} WHERE rowid = ?",
            table.replace('"', "\"\""),
            set_clause.join(", ")
        );
        let mut stmt = g.prepare(&sql).map_err(|e| e.to_string())?;
        let mut params: Vec<rusqlite::types::Value> = vals
            .iter()
            .map(|(_, v)| match v {
                serde_json::Value::Null => rusqlite::types::Value::Null,
                serde_json::Value::Bool(b) => rusqlite::types::Value::Integer(if *b { 1 } else { 0 }),
                serde_json::Value::Number(n) => {
                    if let Some(i) = n.as_i64() {
                        rusqlite::types::Value::Integer(i)
                    } else if let Some(f) = n.as_f64() {
                        rusqlite::types::Value::Real(f)
                    } else {
                        rusqlite::types::Value::Null
                    }
                }
                serde_json::Value::String(s) => rusqlite::types::Value::Text(s.clone()),
                _ => rusqlite::types::Value::Null,
            })
            .collect();
        params.push(rusqlite::types::Value::Text(pk));
        stmt.execute(rusqlite::params_from_iter(params)).map_err(|e| e.to_string())?;
        Ok(())
    })
    .await
    .map_err(|e| format!("task: {e}"))?
}
async fn delete_row(pool: &Pool, table: &str, pk: &str) -> Result<(), String> { let c = match pool { Pool::Sqlite(c) => c.clone() }; let table = table.to_string(); let pk = pk.to_string(); tokio::task::spawn_blocking(move || { let g = c.lock().map_err(|e| e.to_string())?; let sql = format!("DELETE FROM \"{}\" WHERE rowid = ?", table.replace('"', "\"\"")); g.execute(&sql, rusqlite::params![pk]).map_err(|e| e.to_string())?; Ok(()) }).await.map_err(|e| format!("task: {e}"))? }

// ─── Config table API ──────────────────────────────────────────────────────
impl DbManager {
    pub async fn config_map(&self) -> Result<HashMap<String, String>, String> { let omni = self.conns.read().await.get("OmniDB").cloned().ok_or_else(|| "OmniDB not connected".to_string())?; let Pool::Sqlite(p) = &omni.pool; let p = p.clone(); tokio::task::spawn_blocking(move || { let g = p.lock().map_err(|e| e.to_string())?; let mut stmt = g.prepare("SELECT key, value FROM config").map_err(|e| e.to_string())?; let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))).map_err(|e| e.to_string())?; Ok::<_, String>(rows.filter_map(Result::ok).collect()) }).await.map_err(|e| format!("task: {e}"))? }
    pub async fn config_get(&self, key: &str) -> Result<Option<String>, String> { let omni = self.conns.read().await.get("OmniDB").cloned().ok_or_else(|| "OmniDB not connected".to_string())?; let Pool::Sqlite(p) = &omni.pool; let p = p.clone(); let key = key.to_string(); tokio::task::spawn_blocking(move || { let g = p.lock().map_err(|e| e.to_string())?; g.query_row("SELECT value FROM config WHERE key=?1", rusqlite::params![key], |r| r.get::<_, String>(0)).optional().map_err(|e| e.to_string()) }).await.map_err(|e| format!("task: {e}"))? }
    pub async fn config_set(&self, key: &str, value: &str) -> Result<(), String> { self.config_set_bulk(&[(key.to_string(), value.to_string())]).await }
    pub async fn config_set_bulk(&self, items: &[(String, String)]) -> Result<(), String> { let omni = self.conns.read().await.get("OmniDB").cloned().ok_or_else(|| "OmniDB not connected".to_string())?; let Pool::Sqlite(p) = &omni.pool; let p = p.clone(); let items = items.to_vec(); tokio::task::spawn_blocking(move || { let mut g = p.lock().map_err(|e| e.to_string())?; let tx = g.transaction().map_err(|e| e.to_string())?; { let mut stmt = tx.prepare("INSERT INTO config (key,value) VALUES (?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP").map_err(|e| e.to_string())?; for (k, v) in &items { stmt.execute(rusqlite::params![k, v]).map_err(|e| e.to_string())?; } } tx.commit().map_err(|e| e.to_string()) }).await.map_err(|e| format!("task: {e}"))? }
    pub async fn config_del(&self, key: &str) -> Result<(), String> { let omni = self.conns.read().await.get("OmniDB").cloned().ok_or_else(|| "OmniDB not connected".to_string())?; let Pool::Sqlite(p) = &omni.pool; let p = p.clone(); let key = key.to_string(); tokio::task::spawn_blocking(move || { let g = p.lock().map_err(|e| e.to_string())?; g.execute("DELETE FROM config WHERE key=?1", rusqlite::params![key]).map(|_| ()).map_err(|e| e.to_string()) }).await.map_err(|e| format!("task: {e}"))? }
}

// ─── Bootstrap / migration ─────────────────────────────────────────────────
impl DbManager {
    async fn bootstrap_defaults_if_empty(&self) -> Result<(), String> { let m = self.config_map().await?; if !m.is_empty() { return Ok(()); } let e = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string()); let items: Vec<(String, String)> = vec![
        ("address".into(), e("OMNIRS_ADDR", "0.0.0.0")), ("admin_token".into(), e("OMNIRS_ADMIN_TOKEN", "")), ("root".into(), e("OMNIRS_ROOT", "./public")), ("admin_root".into(), e("OMNIRS_ADMIN_ROOT", ".")), ("acme_mode".into(), e("OMNIRS_ACME_MODE", "all")), ("acme_ip".into(), e("OMNIRS_ACME_IP", "")),  ("acme_domains".into(), e("OMNIRS_ACME_DOMAINS", "")), ("h3_port".into(), e("OMNIRS_H3_PORT", "443")), ("fastcgi_pass".into(), e("OMNIRS_FASTCGI_PASS", "")), ("fastcgi_index".into(), "index.php".into()), ("proxy_prefix".into(), e("OMNIRS_PROXY_PREFIX", "/proxy")), ("backends".into(), e("OMNIRS_BACKENDS", "")), ("cache_enabled".into(), "true".into()), ("cache_ttl_secs".into(), "60".into()), ("cache_max_entries".into(), "1000".into()), ("request_timeout_secs".into(), "30".into()), ("access_log_path".into(), "/var/log/omnirs/access.log".into()), ("access_log_max_size_mb".into(), "1".into()), ("access_log_max_files".into(), "3".into()), ("slow_request_threshold_ms".into(), "1000".into()), ("slow_log_path".into(), "/var/log/omnirs/slow.log".into()), ("sticky_sessions".into(), "true".into()), ("grpc_passthrough".into(), "true".into()), ("cors_allowed_origins".into(), "".into()),
        ("db.enabled".into(), "true".into()), ("db.db_dir".into(), e("OMNIRS_DB_DIR", "./db")), ("db.allow_ddl".into(), "false".into()), ("db.allow_write".into(), "false".into()), ("db.max_rows".into(), "1000".into()), ("db.query_timeout_secs".into(), "30".into()), ("db.history_size".into(), "200".into()),
        ("vpn.enabled".into(), e("OMNIRS_VPN_ENABLED", "true")), ("vpn.interface".into(), "vpn0".into()), ("vpn.default_mtu".into(), "1420".into()), ("vpn.default_dns".into(), r#"["1.1.1.1","2606:4700:4700::1111"]"#.into()), ("vpn.default_allowed_ips".into(), r#"["0.0.0.0/0","::/0"]"#.into()), ("vpn.default_persistent_keepalive".into(), "0".into()), ("vpn.firewall_enabled".into(), "false".into()),
        ("dns.enabled".into(), e("OMNIRS_DNS_ENABLED", "true")), ("dns.addr".into(), "0.0.0.0:53".into()), ("dns.dot_addr".into(), "0.0.0.0:853".into()), ("dns.doq_addr".into(), "0.0.0.0:853".into()), ("dns.doh_path".into(), "/dns-query".into()), ("dns.zone_dir".into(), "./zones".into()), ("dns.forwarders".into(), r#"["1.1.1.1:53","8.8.8.8:53"]"#.into()), ("dns.recursive".into(), "false".into()), ("dns.dnssec_sign_on_load".into(), "false".into()), ("dns.rrl_enabled".into(), "true".into()), ("dns.ixfr_enabled".into(), "true".into()),
        ("tunnel.enabled".into(), e("OMNIRS_TUNNEL_ENABLED", "true")), ("tunnel.path_prefix".into(), e("OMNIRS_TUNNEL_PATH_PREFIX", "v1")), ("tunnel.allow_targets".into(), e("OMNIRS_TUNNEL_ALLOW_TARGETS", "127.0.0.1:443,127.0.0.1:888")),
        // --- IKEv2 ---
        ("ikev2.enabled".into(), "false".into()), ("ikev2.listen".into(), "0.0.0.0:500".into()), ("ikev2.psk".into(), "".into()), ("ikev2.local_id".into(), "omnirs".into()), ("ikev2.remote_id".into(), "%any".into()),
    ]; self.config_set_bulk(&items).await?; println!("[DB] bootstrapped config table with {} defaults", items.len()); Ok(()) }
    async fn migrate_from_toml_if_exists(&self) -> Result<bool, String> { let toml_path = Path::new("config.toml"); if !toml_path.exists() { return Ok(false); } let m = self.config_map().await?; if !m.is_empty() { eprintln!("[DB] config table already populated — leaving config.toml untouched"); return Ok(false); } let content = std::fs::read_to_string(toml_path).map_err(|e| e.to_string())?; let toml_val: toml::Value = content.parse().map_err(|e| format!("toml parse: {e}"))?; let mut flat: Vec<(String, String)> = Vec::new(); flatten_toml("", &toml_val, &mut flat); self.config_set_bulk(&flat).await?; let bak = format!("config.toml.migrated.{}", now()); let _ = std::fs::rename(toml_path, &bak); println!("[DB] config.toml migrated to DB → renamed to {}", bak); Ok(true) }
}

// ─── from_env — единственный конструктор ───────────────────────────────────
impl DbManager {
    pub async fn from_env() -> Result<Self, String> {
        let mut cfg = DbConfig::from_env();
        let dir = cfg.db_dir.clone().unwrap_or_else(|| "./db".into());
        std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {dir}: {e}"))?;
        { let c = open_omni().map_err(|e| format!("open OmniDB: {e}"))?; init_system_schema(&c).map_err(|e| format!("init_system_schema: {e}"))?; }
        { let c = open_vpn().map_err(|e| format!("open OmniVPN: {e}"))?; init_vpn_schema(&c).map_err(|e| format!("init_vpn_schema: {e}"))?; }
        let mut conns: HashMap<String, Arc<DbConnection>> = HashMap::new();
        let make_cc = |id: &str, path: &Path| ConnectionConfig { id: id.into(), name: id.into(), kind: DbKind::Sqlite, url: format!("sqlite://{}", path.display()), readonly: false, pool_size: 5, description: String::new() };
        for (id, path) in [("OmniDB", omni_db_path()), ("OmniVPN", vpn_db_path())] { let cc = make_cc(id, &path); let pool = build_pool(&cc).await?; conns.insert(id.into(), Arc::new(DbConnection { config: cc, pool, healthy: true, last_check: Instant::now(), stats: StdMutex::new(ConnectionStats::default()) })); }
        if let Ok(entries) = std::fs::read_dir(&dir) { for e in entries.flatten() { let p = e.path(); if !p.is_file() { continue; } let fname = p.file_name().and_then(|x| x.to_str()).unwrap_or(""); if fname.ends_with("-wal") || fname.ends_with("-shm") || fname.ends_with("-journal") { continue; } let stem = p.file_stem().and_then(|x| x.to_str()).unwrap_or(""); if stem == "OmniDB" || stem == "OmniVPN" { continue; } let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("").to_lowercase(); if !(ext.is_empty() || ext == "db" || ext == "sqlite" || ext == "sqlite3") { continue; } if conns.contains_key(stem) { continue; } let cc = ConnectionConfig { id: stem.into(), name: stem.into(), kind: DbKind::Sqlite, url: format!("sqlite://{}", p.display()), readonly: false, pool_size: 5, description: String::new() }; if let Ok(pool) = build_pool(&cc).await { conns.insert(stem.into(), Arc::new(DbConnection { config: cc, pool, healthy: true, last_check: Instant::now(), stats: StdMutex::new(ConnectionStats::default()) })); } } }
        let mgr = Self { config: cfg.clone(), conns: RwLock::new(conns), history: RwLock::new(Vec::new()) };
        let migrated = mgr.migrate_from_toml_if_exists().await.unwrap_or(false);
        if !migrated { mgr.bootstrap_defaults_if_empty().await?; }
        let map = mgr.config_map().await?;
        cfg.overlay_from_map(&map);
        Ok(Self { config: cfg, conns: mgr.conns, history: mgr.history })
    }
}

// ─── Connections + stats + history ─────────────────────────────────────────
impl DbManager {
    pub async fn add_connection(&self, cc: ConnectionConfig) -> Result<(), String> { let pool = build_pool(&cc).await?; let mut conns = self.conns.write().await; if conns.contains_key(&cc.id) { return Err(format!("connection '{}' already exists", cc.id)); } conns.insert(cc.id.clone(), Arc::new(DbConnection { config: cc, pool, healthy: true, last_check: Instant::now(), stats: StdMutex::new(ConnectionStats::default()) })); Ok(()) }
    pub async fn remove_connection(&self, id: &str) -> bool { self.conns.write().await.remove(id).is_some() }
    pub async fn test(&self, id: &str) -> Result<u64, String> { let conn = self.get(id).await?; let start = Instant::now(); match &conn.pool { Pool::Sqlite(c) => { let c = c.clone(); tokio::task::spawn_blocking(move || { let g = c.lock().map_err(|e| e.to_string())?; g.query_row("SELECT 1", [], |_| Ok(())).map_err(|e| e.to_string()) }).await.map_err(|e| format!("task: {e}"))??; } } Ok(start.elapsed().as_millis() as u64) }
    async fn get(&self, id: &str) -> Result<Arc<DbConnection>, String> { self.conns.read().await.get(id).cloned().ok_or_else(|| format!("connection '{id}' not found")) }
    async fn reload_from_disk(&self) { let dir = match &self.config.db_dir { Some(d) => d.clone(), None => return }; let entries = match std::fs::read_dir(&dir) { Ok(e) => e, Err(_) => return }; for e in entries.flatten() { let p = e.path(); if !p.is_file() { continue; } let fname = p.file_name().and_then(|x| x.to_str()).unwrap_or(""); if fname.ends_with("-wal") || fname.ends_with("-shm") || fname.ends_with("-journal") { continue; } let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("").to_lowercase(); if !(ext.is_empty() || ext == "db" || ext == "sqlite" || ext == "sqlite3") { continue; } let filename = p.file_stem().and_then(|x| x.to_str()).unwrap_or("unknown").to_string(); if self.conns.read().await.contains_key(&filename) { continue; } let cc = ConnectionConfig { id: filename.clone(), name: filename.clone(), kind: DbKind::Sqlite, url: format!("sqlite://{}", p.display()), readonly: false, pool_size: 5, description: String::new() }; if let Ok(pool) = build_pool(&cc).await { self.conns.write().await.insert(filename.clone(), Arc::new(DbConnection { config: cc, pool, healthy: true, last_check: Instant::now(), stats: StdMutex::new(ConnectionStats::default()) })); println!("[DB] {} ({}): connected (runtime)", filename, filename); } } }
    pub async fn stats(&self) -> serde_json::Value { self.reload_from_disk().await; let conns = self.conns.read().await; let list: Vec<serde_json::Value> = conns.values().map(|c| { let s = c.stats.lock().unwrap().clone(); serde_json::json!({ "id": c.config.id, "name": c.config.name, "kind": c.config.kind.as_str(), "healthy": c.healthy, "readonly": c.config.readonly, "queries_total": s.queries_total, "queries_failed": s.queries_failed, "avg_latency_ms": (s.avg_latency_ms * 100.0).round() / 100.0 }) }).collect(); serde_json::json!({ "enabled": self.config.enabled, "db_dir": self.config.db_dir, "allow_ddl": self.config.allow_ddl, "allow_write": self.config.allow_write, "max_rows": self.config.max_rows, "connections": list }) }
    pub async fn push_history(&self, mut e: QueryHistoryEntry) { if e.sql.len() > 500 { e.sql = format!("{}…", &e.sql[..500]); } let mut h = self.history.write().await; h.push(e); let cap = self.config.history_size; if h.len() > cap { let excess = h.len() - cap; h.drain(0..excess); } }
}

// ─── QueryOutcome + run_query ──────────────────────────────────────────────
pub enum QueryOutcome { Rows { columns: Vec<String>, rows: Vec<serde_json::Value>, elapsed_ms: u64, truncated: bool }, Affected { affected: u64, elapsed_ms: u64 } }
pub async fn run_query(manager: &DbManager, conn_id: &str, sql: &str, client_ip: &str) -> Result<serde_json::Value, String> { let conn = { let conns = manager.conns.read().await; conns.get(conn_id).cloned().ok_or_else(|| format!("connection '{conn_id}' not found"))? }; let kind = sql_kind(sql); if kind == "other" { return Err("unsupported statement".into()); } if conn.config.readonly && kind != "read" { return Err("connection is readonly".into()); } if kind == "write" && !manager.config.allow_write { return Err("writes disabled (allow_write = false)".into()); } if kind == "ddl" && !manager.config.allow_ddl { return Err("DDL disabled (allow_ddl = false)".into()); } let start = Instant::now(); let timeout = Duration::from_secs(manager.config.query_timeout_secs.max(1)); let max_rows = manager.config.max_rows; let sql_owned = sql.to_string(); let kind_owned = kind.to_string(); let fut = async { let Pool::Sqlite(p) = &conn.pool; execute_sqlite(p.clone(), sql_owned, max_rows, kind_owned).await }; let result = tokio::time::timeout(timeout, fut).await; let (ok, rows, err) = match &result { Ok(Ok(QueryOutcome::Rows { rows, .. })) => (true, rows.len(), None), Ok(Ok(QueryOutcome::Affected { .. })) => (true, 0, None), Ok(Err(e)) => (false, 0, Some(e.clone())), Err(_) => (false, 0, Some(format!("query timeout after {}s", manager.config.query_timeout_secs))) }; let latency_ms = start.elapsed().as_millis() as u64; { let mut s = conn.stats.lock().unwrap(); s.queries_total += 1; s.total_latency_ms += latency_ms; if !ok { s.queries_failed += 1; } s.avg_latency_ms = s.total_latency_ms as f64 / s.queries_total.max(1) as f64; } manager.push_history(QueryHistoryEntry { ts: now(), conn_id: conn_id.to_string(), conn_name: conn.config.name.clone(), sql: sql.to_string(), ok, rows, latency_ms, error: err.clone(), client_ip: client_ip.to_string() }).await; match result { Ok(Ok(QueryOutcome::Rows { columns, rows, elapsed_ms, truncated })) => Ok(serde_json::json!({ "kind": "rows", "columns": columns, "rows": rows, "row_count": rows.len(), "truncated": truncated, "elapsed_ms": elapsed_ms })), Ok(Ok(QueryOutcome::Affected { affected, elapsed_ms })) => Ok(serde_json::json!({ "kind": "affected", "affected": affected, "elapsed_ms": elapsed_ms })), Ok(Err(e)) => Err(e), Err(_) => Err(format!("query timeout after {}s", manager.config.query_timeout_secs)) } }

// ─── Request structs ───────────────────────────────────────────────────────
#[derive(Deserialize, Clone)] struct ColumnDef { name: String, r#type: String, primary_key: bool }
#[derive(Deserialize)] struct CreateTableRequest { name: String, columns: Vec<ColumnDef> }
#[derive(Deserialize)] struct CreateDbRequest { name: String }
#[derive(Deserialize)]
pub struct RowRequest {
    pub values: serde_json::Map<String, serde_json::Value>,
    #[serde(default, deserialize_with = "de_opt_pk")]
    pub pk: Option<String>,
}

fn de_opt_pk<'de, D>(d: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    let v = Option::<serde_json::Value>::deserialize(d)?;
    Ok(match v {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(s)) => Some(s),
        Some(serde_json::Value::Number(n)) => Some(n.to_string()),
        Some(serde_json::Value::Bool(b)) => Some(if b { "1".into() } else { "0".into() }),
        Some(other) => Some(other.to_string()),
    })
}


// ─── Tunnel clients ───────────────────────────────────────────────────────
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TunnelClient {
    pub id: i64,
    pub name: String,
    pub password: String,
    pub path_prefix: String,
    pub allow_targets: Vec<String>,
    pub enabled: bool,
    pub bytes_in: i64,
    pub bytes_out: i64,
    pub created_at: String,
    pub updated_at: String,
}

pub fn gen_tunnel_password() -> String {
    use std::io::Read;
    let mut bytes = [0u8; 24];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut bytes);
    }
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn row_to_tunnel_client(r: &rusqlite::Row) -> rusqlite::Result<TunnelClient> {
    let allow_json: String = r
        .get::<_, Option<String>>("allow_targets")?
        .unwrap_or_else(|| "[]".into());
    let allow: Vec<String> = serde_json::from_str(&allow_json).unwrap_or_default();
    Ok(TunnelClient {
        id: r.get("id")?,
        name: r.get("name")?,
        password: r.get::<_, Option<String>>("password")?.unwrap_or_default(),
        path_prefix: r.get("path_prefix")?,
        allow_targets: allow,
        enabled: r.get::<_, i64>("enabled").unwrap_or(0) != 0,
        bytes_in: r.get::<_, i64>("bytes_in").unwrap_or(0),
        bytes_out: r.get::<_, i64>("bytes_out").unwrap_or(0),
        created_at: r.get::<_, Option<String>>("created_at")?.unwrap_or_default(),
        updated_at: r.get::<_, Option<String>>("updated_at")?.unwrap_or_default(),
    })
}

pub fn tunnel_list(c: &rusqlite::Connection) -> rusqlite::Result<Vec<TunnelClient>> {
    let mut stmt = c.prepare("SELECT * FROM OmniTunnel ORDER BY id ASC")?;
    let rows = stmt.query_map([], row_to_tunnel_client)?;
    Ok(rows.filter_map(Result::ok).collect())
}

pub fn tunnel_get(c: &rusqlite::Connection, id: i64) -> rusqlite::Result<Option<TunnelClient>> {
    let mut stmt = c.prepare("SELECT * FROM OmniTunnel WHERE id = ?1")?;
    stmt.query_row(rusqlite::params![id], row_to_tunnel_client)
        .optional()
}

pub fn tunnel_create(
    c: &rusqlite::Connection,
    name: &str,
    password: &str,
    path_prefix: &str,
    allow_targets: &[String],
) -> rusqlite::Result<i64> {
    let allow_json = serde_json::to_string(allow_targets).unwrap_or_else(|_| "[]".into());
    c.execute(
        "INSERT INTO OmniTunnel (name, password, path_prefix, allow_targets, enabled) \
         VALUES (?1, ?2, ?3, ?4, 1)",
        rusqlite::params![name, password, path_prefix, allow_json],
    )?;
    Ok(c.last_insert_rowid())
}

pub fn tunnel_delete(c: &rusqlite::Connection, id: i64) -> rusqlite::Result<()> {
    c.execute("DELETE FROM OmniTunnel WHERE id = ?1", rusqlite::params![id])?;
    Ok(())
}

pub fn tunnel_set_enabled(
    c: &rusqlite::Connection,
    id: i64,
    enabled: bool,
) -> rusqlite::Result<()> {
    c.execute(
        "UPDATE OmniTunnel SET enabled = ?1, updated_at = CURRENT_TIMESTAMP WHERE id = ?2",
        rusqlite::params![if enabled { 1 } else { 0 }, id],
    )?;
    Ok(())
}

pub fn tunnel_reset_password(
    c: &rusqlite::Connection,
    id: i64,
    new_password: &str,
) -> rusqlite::Result<()> {
    c.execute(
        "UPDATE OmniTunnel SET password = ?1, updated_at = CURRENT_TIMESTAMP WHERE id = ?2",
        rusqlite::params![new_password, id],
    )?;
    Ok(())
}

// ─── Tunnel API dispatch ──────────────────────────────────────────────────

mod dispatch;
pub use dispatch::*;
