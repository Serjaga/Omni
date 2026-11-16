use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub ip: String,
    pub role: String,
    pub created: i64,
    pub last_seen: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Notif {
    pub ts: i64,
    pub level: String,
    pub msg: String,
}

#[derive(Default)]
pub struct RuntimeCfg {
    pub cache_ttl_secs: Option<u64>,
    pub cache_max_entries: Option<u64>,
    pub rate_limit: Option<u64>,
    pub slow_threshold_ms: Option<u64>,
    pub cors_origins: Option<Vec<String>>,
    pub sticky_sessions: Option<bool>,
}

pub(crate) static SESSIONS: OnceLock<Mutex<HashMap<String, Session>>> = OnceLock::new();
pub(crate) static NOTIFS: OnceLock<Mutex<Vec<Notif>>> = OnceLock::new();
pub(crate) static RUNTIME: OnceLock<Mutex<RuntimeCfg>> = OnceLock::new();

pub fn sessions() -> &'static Mutex<HashMap<String, Session>> { SESSIONS.get_or_init(|| Mutex::new(HashMap::new())) }
pub fn notifs() -> &'static Mutex<Vec<Notif>> { NOTIFS.get_or_init(|| Mutex::new(Vec::new())) }
pub fn runtime() -> &'static Mutex<RuntimeCfg> { RUNTIME.get_or_init(|| Mutex::new(RuntimeCfg::default())) }

