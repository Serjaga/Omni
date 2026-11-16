
use std::sync::Arc;
use crate::server::ServerConfig;

pub struct TlsReloader;

impl TlsReloader {
    pub fn new_for_server(_config: Arc<ServerConfig>) -> anyhow::Result<Self> { Ok(Self) }
    pub fn should_reload_certificate(&self) -> bool { false }
}
