
//! Встроенный IPS (аналог fail2ban): защита от SSH-брутфорса, HTTP-атак,
//! сканирования портов и SYN-флуда. Мониторит journalctl для всех
//! подсистем (ssh, omnirs, kernel) и банит через iptables/ip6tables.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

#[derive(Clone, Copy, Debug)]
enum Threat {
    SshBrute,
    HttpAuth,
    HttpForbidden,
    HttpRateLimit,
    HttpServerError,
    PortScan,
    SynFlood,
}

impl Threat {
    fn code(self) -> u8 {
        match self {
            Self::SshBrute        => 1,
            Self::HttpAuth        => 2,
            Self::HttpForbidden   => 3,
            Self::HttpRateLimit   => 4,
            Self::HttpServerError => 5,
            Self::PortScan        => 6,
            Self::SynFlood        => 7,
        }
    }
    fn threshold(self) -> (u32, Duration) {
        match self {
            Self::SshBrute        => (2,   Duration::from_secs(3600)),
            Self::HttpAuth        => (5,   Duration::from_secs(3600)),
            Self::HttpForbidden   => (10,  Duration::from_secs(3600)),
            Self::HttpRateLimit   => (20,  Duration::from_secs(60)),
            Self::HttpServerError => (100, Duration::from_secs(60)),
            Self::PortScan        => (10,  Duration::from_secs(60)),
            Self::SynFlood        => (5,   Duration::from_secs(60)),
        }
    }
    fn reason(self) -> &'static str {
        match self {
            Self::SshBrute        => "SSH brute-force",
            Self::HttpAuth        => "HTTP auth failure (401)",
            Self::HttpForbidden   => "HTTP forbidden (403)",
            Self::HttpRateLimit   => "HTTP rate-limit (429)",
            Self::HttpServerError => "HTTP server error (5xx)",
            Self::PortScan        => "port scan",
            Self::SynFlood        => "SYN flood",
        }
    }
}

pub struct IntrusionPrevention {
    bans: Mutex<HashMap<IpAddr, Instant>>,
    failures: Mutex<HashMap<(IpAddr, u8), (u32, Instant)>>,
    ban_duration: Duration,
    pub enabled: bool,
    whitelist_ips: Vec<IpAddr>,
    whitelist_v4_cidrs: Vec<(u32, u8)>,
}

impl IntrusionPrevention {
    pub fn new(ban_secs: u64) -> Arc<Self> {
        let enabled = std::env::var("OMNIRS_IPS")
            .map(|v| v != "0" && v != "false" && v != "off")
            .unwrap_or(true);
        if !enabled {
            println!("🛡️  [IPS] ОТКЛЮЧЕН (OMNIRS_IPS=off)");
        }
        // Whitelist: локальные сети + loopback — чтобы не забанить себя
        let mut whitelist_ips: Vec<IpAddr> = Vec::new();
        let mut whitelist_v4_cidrs: Vec<(u32, u8)> = Vec::new();

        // IPv4 loopback 127.0.0.0/8
        whitelist_v4_cidrs.push(((127u32) << 24, 8));
        // RFC1918
        whitelist_v4_cidrs.push((10u32 << 24, 8));
        whitelist_v4_cidrs.push(((172u32 << 24) | (16u32 << 16), 12));
        whitelist_v4_cidrs.push(((192u32 << 24) | (168u32 << 16), 16));
        // link-local 169.254.0.0/16
        whitelist_v4_cidrs.push(((169u32 << 24) | (254u32 << 16), 16));
        // 0.0.0.0/8
        whitelist_v4_cidrs.push((0u32, 8));

        // IPv6 loopback
        if let Ok(ip) = "::1".parse::<IpAddr>() {
            whitelist_ips.push(ip);
        }
        // IPv6 unspecified
        if let Ok(ip) = "::".parse::<IpAddr>() {
            whitelist_ips.push(ip);
        }

        Arc::new(Self {
            bans: Mutex::new(HashMap::new()),
            failures: Mutex::new(HashMap::new()),
            ban_duration: Duration::from_secs(ban_secs),
            enabled,
            whitelist_ips,
            whitelist_v4_cidrs,
        })
    }

    pub fn is_whitelisted(&self, ip: &IpAddr) -> bool {
        if self.whitelist_ips.iter().any(|w| w == ip) {
            return true;
        }
        match ip {
            IpAddr::V4(v4) => {
                let n = u32::from(*v4);
                for (prefix, len) in &self.whitelist_v4_cidrs {
                    let mask = if *len == 0 { 0 } else { u32::MAX << (32 - *len) };
                    if n & mask == prefix & mask {
                        return true;
                    }
                }
            }
            IpAddr::V6(v6) => {
                let n = u128::from(*v6);
                // ::1
                if n == 1 { return true; }
                // fc00::/7 (ULA) — уникальные локальные
                if (n >> 121) & 0x7f == 0x7e { return true; }
                // fe80::/10 (link-local)
                if (n >> 118) & 0x3ff == 0x3fa { return true; }
            }
        }
        false
    }

    pub fn is_banned(&self, ip: &IpAddr) -> bool {
        let mut bans = self.bans.lock().unwrap();
        if let Some(until) = bans.get(ip) {
            if *until > Instant::now() {
                return true;
            }
            bans.remove(ip);
        }
        false
    }

    pub fn record(&self, ip: IpAddr, threat: Threat, source: &str) {
        if !self.enabled { return; }
        if self.is_whitelisted(&ip) { return; }

        let (threshold, window) = threat.threshold();
        let code = threat.code();

        let count = {
            let mut failures = self.failures.lock().unwrap();
            let entry = failures.entry((ip, code)).or_insert((0, Instant::now()));
            if entry.1.elapsed() > window {
                *entry = (1, Instant::now());
            } else {
                entry.0 += 1;
            }
            entry.0
        };

        if count >= threshold {
            println!("⚠️  [IPS] {} — {} {}/{} ({}), → BAN", ip, threat.reason(), count, threshold, source);
            self.ban(ip, threat.reason());
            self.failures.lock().unwrap().retain(|(i, _), _| *i != ip);
        } else {
            println!("⚠️  [IPS] {} — {} {}/{} ({})", ip, threat.reason(), count, threshold, source);
        }
    }

    /// Legacy entry point — все вызовы вне ssh-монитора считаем SSH-брутфорсом.
    pub fn record_failure(&self, ip: IpAddr, reason: &str) {
        self.record(ip, Threat::SshBrute, reason);
    }

    pub fn ban(&self, ip: IpAddr, reason: &str) {
        if !self.enabled { return; }
        if self.is_whitelisted(&ip) { return; }
        {
            let mut bans = self.bans.lock().unwrap();
            if bans.contains_key(&ip) { return; }
            bans.insert(ip, Instant::now() + self.ban_duration);
        }
        eprintln!("🚫 [IPS] {} забанен на {}s — {}", ip, self.ban_duration.as_secs(), reason);
        let ip_str = ip.to_string();
        let dur = self.ban_duration;
        let is_v6 = ip.is_ipv6();
        tokio::spawn(async move {
            let bin_add = if is_v6 { "ip6tables" } else { "iptables" };
            let bin_del = bin_add;
            let _ = Command::new(bin_add).args(["-I", "INPUT", "-s", &ip_str, "-j", "DROP"]).output().await;
            tokio::time::sleep(dur).await;
            let _ = Command::new(bin_del).args(["-D", "INPUT", "-s", &ip_str, "-j", "DROP"]).output().await;
            eprintln!("✅ [IPS] {} разбанен", ip_str);
        });
    }
}

// ─── Публичная точка входа ─────────────────────────────────────────────────
pub fn start_monitors(ips: Arc<IntrusionPrevention>, mut whitelist: Vec<String>) {
    if !ips.enabled {
        println!("🛡️  [IPS] мониторы ОТКЛЮЧЕНЫ (OMNIRS_IPS=off)");
        return;
    }

    // Авто-whitelist: IP текущей SSH-сессии
    if let Ok(conn) = std::env::var("SSH_CONNECTION") {
        if let Some(ip) = conn.split_whitespace().next() {
            if !whitelist.contains(&ip.to_string()) {
                whitelist.push(ip.to_string());
                println!("🛡️  [IPS] Авто-whitelist: {} (текущий SSH-клиент)", ip);
            }
        }
    }

    start_ssh_monitor(ips.clone(), whitelist);
    start_omnirs_monitor(ips.clone());
    start_kernel_monitor(ips.clone());

    println!("🛡️  [IPS] Все мониторы запущены (SSH, OmniRS, kernel)");
}

// Backward compat — если где-то в main.rs остался вызов start_ssh_monitor,
// он не сломается, но теперь вызывайте start_monitors.
pub fn start_ssh_monitor(ips: Arc<IntrusionPrevention>, whitelist: Vec<String>) {
    if !ips.enabled { return; }
    tokio::spawn(async move {
        let mut child = match Command::new("journalctl")
            .args(["-u", "ssh", "-f", "-o", "cat", "-n", "0"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[IPS] SSH-монитор не стартовал: {}", e);
                return;
            }
        };
        let stdout = child.stdout.take().unwrap();
        let mut lines = BufReader::new(stdout).lines();

        while let Ok(Some(line)) = lines.next_line().await {
            let is_fail = line.contains("Failed password for")
                || line.contains("Invalid user")
                || line.contains("authentication failure")
                || line.contains("pam_unix(sshd:auth): authentication failure")
                || line.contains("error: maximum authentication attempts exceeded")
                || line.contains("Connection closed by authenticating user")
                || line.contains("Unable to negotiate")
                || line.contains("Received disconnect from")
                || line.contains("banner exchange")
                || line.contains("did not receive identification string");
            if !is_fail {
                continue;
            }
            // Формат: "... from 1.2.3.4 port 5 ..."
            if let Some(pos) = line.find(" from ") {
                let rest = &line[pos + 6..];
                let ip_str = rest.split_whitespace().next().unwrap_or("");
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    if whitelist.iter().any(|w| w == &ip.to_string()) {
                        continue;
                    }
                    ips.record(ip, Threat::SshBrute, "sshd");
                }
            }
        }
    });
}

pub fn start_omnirs_monitor(ips: Arc<IntrusionPrevention>) {
    if !ips.enabled { return; }
    tokio::spawn(async move {
        let mut child = match Command::new("journalctl")
            .args(["-u", "omnirs", "-f", "-o", "cat", "-n", "0"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[IPS] OmniRS-монитор не стартовал: {}", e);
                return;
            }
        };
        let stdout = child.stdout.take().unwrap();
        let mut lines = BufReader::new(stdout).lines();

        while let Ok(Some(line)) = lines.next_line().await {
            // 1) access_log (JSON): {"ts":..., "ip":"1.2.3.4", "status":401, ...}
            if line.starts_with('{') && line.contains("\"ip\"") && line.contains("\"status\"") {
                if let Some(ip_str) = extract_json_string(&line, "ip") {
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        if let Some(status) = extract_json_int(&line, "status") {
                            match status {
                                401 => ips.record(ip, Threat::HttpAuth, "omni"),
                                403 => ips.record(ip, Threat::HttpForbidden, "omni"),
                                429 => ips.record(ip, Threat::HttpRateLimit, "omni"),
                                500..=599 => ips.record(ip, Threat::HttpServerError, "omni"),
                                _ => {}
                            }
                        }
                    }
                }
                continue;
            }
            // 2) log_admin_action: "auth_failed from 1.2.3.4"
            if line.contains("auth_failed") {
                if let Some(ip) = extract_ipv4_or_v6(&line) {
                    ips.record(ip, Threat::HttpAuth, "omni-auth");
                }
                continue;
            }
            // 3) rate limit messages (fallback)
            if line.contains("Rate limit exceeded") || line.contains("Too many login attempts") {
                if let Some(ip) = extract_ipv4_or_v6(&line) {
                    ips.record(ip, Threat::HttpRateLimit, "omni-rate");
                }
            }
        }
    });
}

pub fn start_kernel_monitor(ips: Arc<IntrusionPrevention>) {
    if !ips.enabled { return; }
    tokio::spawn(async move {
        let mut child = match Command::new("journalctl")
            .args(["-k", "-f", "-o", "cat", "-n", "0"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[IPS] Kernel-монитор не стартовал: {}", e);
                return;
            }
        };
        let stdout = child.stdout.take().unwrap();
        let mut lines = BufReader::new(stdout).lines();

        while let Ok(Some(line)) = lines.next_line().await {
            // SYN flooding
            if line.contains("Possible SYN flooding") || line.contains("SYN flooding on") {
                if let Some(ip) = extract_src_ip(&line) {
                    ips.record(ip, Threat::SynFlood, "kernel-syn");
                }
                continue;
            }
            // iptables LOG (--log-prefix "OMNIRS: "):
            //   IN=eth0 OUT= ... SRC=1.2.3.4 DST=5.6.7.8 ... DPT=22 ...
            if line.contains("SRC=") && line.contains("DPT=") {
                // Пропускаем известные служебные: UDP 53 от локальных DNS forwarders и т.п.
                if let Some(ip) = extract_src_ip(&line) {
                    ips.record(ip, Threat::PortScan, "iptables-log");
                }
            }
        }
    });
}

// ─── Мини-парсеры (без regex-зависимостей) ────────────────────────────────
fn extract_json_string(s: &str, key: &str) -> Option<String> {
    let pat = format!("\"{}\"", key);
    let idx = s.find(&pat)?;
    let rest = &s[idx + pat.len()..];
    let rest = rest.trim_start().strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn extract_json_int(s: &str, key: &str) -> Option<u16> {
    let pat = format!("\"{}\"", key);
    let idx = s.find(&pat)?;
    let rest = &s[idx + pat.len()..];
    let rest = rest.trim_start().strip_prefix(':')?.trim_start();
    let mut n: u32 = 0;
    let mut found = false;
    for c in rest.chars() {
        if let Some(d) = c.to_digit(10) {
            n = n.saturating_mul(10).saturating_add(d);
            found = true;
        } else if found {
            break;
        } else if c != ' ' {
            return None;
        }
    }
    if found && n <= u16::MAX as u32 { Some(n as u16) } else { None }
}

fn extract_ipv4_or_v6(s: &str) -> Option<IpAddr> {
    for tok in s.split(|c: char| !(c.is_ascii_hexdigit() || c == '.' || c == ':')) {
        if let Ok(ip) = tok.parse::<IpAddr>() { return Some(ip); }
    }
    None
}

fn extract_src_ip(s: &str) -> Option<IpAddr> {
    let idx = s.find("SRC=")?;
    let rest = &s[idx + 4..];
    let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
    rest[..end].parse().ok()
}