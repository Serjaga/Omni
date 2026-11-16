
use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};
async fn run(cmd: &str, args: &[&str]) -> Result<String, String> { let out = Command::new(cmd).args(args).output().await.map_err(|e| format!("spawn {cmd}: {e}"))?; if !out.status.success() { return Err(format!("{cmd} {:?}: {}", args, String::from_utf8_lossy(&out.stderr).trim())); } Ok(String::from_utf8_lossy(&out.stdout).trim().to_string()) }
async fn run_ok(cmd: &str, args: &[&str]) -> bool { Command::new(cmd).args(args).output().await.map(|o| o.status.success()).unwrap_or(false) }
pub async fn iface_exists(name: &str) -> bool { run_ok("ip", &["link", "show", "dev", name]).await }

pub async fn add_if(name: &str) -> Result<(), String> {
    if iface_exists(name).await { return Ok(()); }
    let kind = if name.starts_with("obfs") { "amneziawg" } else { "wireguard" };
    run("ip", &["link", "add", "dev", name, "type", kind]).await?;
    Ok(())
}
pub async fn del_if(name: &str) -> Result<(), String> {
    if iface_exists(name).await {
        run_ok("ip", &["link", "delete", "dev", name]).await;
        for _ in 0..20 { if !iface_exists(name).await { break; } tokio::time::sleep(std::time::Duration::from_millis(100)).await; }
    }
    Ok(())
}
pub async fn set_up(name: &str) -> Result<(), String> { run("ip", &["link", "set", "up", "dev", name]).await?; Ok(()) }
pub async fn set_mtu(name: &str, mtu: i64) -> Result<(), String> { if mtu > 0 { run_ok("ip", &["link", "set", "mtu", &mtu.to_string(), "dev", name]).await; } Ok(()) }
pub fn first_v4_addr(cidr: &str) -> Result<String, String> { let net: Ipv4Net = cidr.parse().map_err(|e| format!("ipv4 cidr {cidr}: {e}"))?; Ok(format!("{}/{}", Ipv4Addr::from(u32::from(net.network()) + 1), net.prefix_len())) }
pub fn first_v6_addr(cidr: &str) -> Result<String, String> { let net: Ipv6Net = cidr.parse().map_err(|e| format!("ipv6 cidr {cidr}: {e}"))?; Ok(format!("{}/{}", Ipv6Addr::from(u128::from(net.network()) + 1), net.prefix_len())) }
pub async fn add_addr(name: &str, addr: &str) -> Result<(), String> {
    let proto = if addr.contains(':') { "-6" } else { "-4" };
    let ip_only = addr.split('/').next().unwrap_or(addr);
    let existing = run("ip", &[proto, "addr", "show", "dev", name]).await.unwrap_or_default();
    if existing.contains(ip_only) { return Ok(()); }
    run_ok("ip", &[proto, "addr", "add", addr, "dev", name]).await;
    Ok(())
}
pub async fn add_route(name: &str, cidr: &str) -> Result<(), String> {
    let proto = if cidr.contains(':') { "-6" } else { "-4" };
    let existing = run("ip", &[proto, "route", "show", "dev", name, "match", cidr]).await.unwrap_or_default();
    if !existing.trim().is_empty() { return Ok(()); }
    if cidr.ends_with("/0") {
        if proto == "-6" { run_ok("ip", &["-6", "route", "add", "::/1", "dev", name]).await; run_ok("ip", &["-6", "route", "add", "8000::/1", "dev", name]).await; }
        else { run_ok("ip", &["-4", "route", "add", "0.0.0.0/1", "dev", name]).await; run_ok("ip", &["-4", "route", "add", "128.0.0.0/1", "dev", name]).await; }
    } else {
        run_ok("ip", &[proto, "route", "add", cidr, "dev", name]).await;
    }
    Ok(())
}
pub async fn enable_forward() { run_ok("sysctl", &["-q", "-w", "net.ipv4.ip_forward=1"]).await; run_ok("sysctl", &["-q", "-w", "net.ipv6.conf.all.forwarding=1"]).await; }
pub async fn set_dns(name: &str, dns: &[String]) { if dns.is_empty() { return; } if !run_ok("bash", &["-c", "systemctl is-active --quiet systemd-resolved || dpkg -l openresolv 2>/dev/null | grep -q '^ii'"]).await { return; } let mut c = String::new(); for s in dns { c.push_str(&format!("nameserver {}\n", s)); } let escaped = c.replace('\'', "'\\''"); let cmd = format!("printf '{}' | resolvconf -a {} -m 0 -x 2>/dev/null || true", escaped, name); let _ = run_ok("bash", &["-c", &cmd]).await; }
pub async fn unset_dns(name: &str) { if !run_ok("bash", &["-c", "systemctl is-active --quiet systemd-resolved || dpkg -l openresolv 2>/dev/null | grep -q '^ii'"]).await { return; } let _ = run_ok("resolvconf", &["-d", name, "-f"]).await; }

pub fn build_device(iface: &VpnInterface, clients: &[Client]) -> netlink::Device {
let mut dev = netlink::Device::default();
dev.name = iface.name.clone();
dev.has_listen_port = true;
dev.listen_port = iface.port as u16;
dev.replace_peers = true;
if let Some(sk) = crypto::key_from_base64(iface.private_key.as_bytes()) { dev.private_key = sk; dev.has_private_key = true; }
if let Some(pk) = crypto::key_from_base64(iface.public_key.as_bytes()) { dev.public_key = pk; dev.has_public_key = true; }

dev.obfs_jc   = iface.j_c.map(|v| v as u32);
dev.obfs_jmin = iface.j_min.map(|v| v as u32);
dev.obfs_jmax = iface.j_max.map(|v| v as u32);
dev.obfs_s1   = iface.s1.and_then(|v| u16::try_from(v).ok());
dev.obfs_s2   = iface.s2.and_then(|v| u16::try_from(v).ok());
dev.obfs_s3   = iface.s3.and_then(|v| u16::try_from(v).ok());
dev.obfs_s4   = iface.s4.and_then(|v| u16::try_from(v).ok());
dev.obfs_h1   = iface.h1.as_deref().and_then(parse_range_lower_bound);
dev.obfs_h2   = iface.h2.as_deref().and_then(parse_range_lower_bound);
dev.obfs_h3   = iface.h3.as_deref().and_then(parse_range_lower_bound);
dev.obfs_h4   = iface.h4.as_deref().and_then(parse_range_lower_bound);
dev.obfs_i1_raw = iface.i1.clone().filter(|s| !s.is_empty());
dev.obfs_i2_raw = iface.i2.clone().filter(|s| !s.is_empty());
dev.obfs_i3_raw = iface.i3.clone().filter(|s| !s.is_empty());
dev.obfs_i4_raw = iface.i4.clone().filter(|s| !s.is_empty());
dev.obfs_i5_raw = iface.i5.clone().filter(|s| !s.is_empty());

for c in clients {
if c.enabled == 0 { continue; }
if c.ipv4_address.is_empty() && c.ipv6_address.is_empty() { continue; }
let mut peer = netlink::Peer::default();
if let Some(pk) = crypto::key_from_base64(c.public_key.as_bytes()) { peer.public_key = pk; }
if let Some(psk) = crypto::key_from_base64(c.pre_shared_key.as_bytes()) {
    peer.preshared_key = psk;
    peer.has_preshared_key = !crypto::key_is_zero(&psk);
}
if c.persistent_keepalive > 0 {
    peer.persistent_keepalive = c.persistent_keepalive as u16;
    peer.has_persistent_keepalive = true;
}
if let Some(ep) = &c.server_endpoint { if let Ok(sa) = ep.parse::<SocketAddr>() { peer.endpoint = Some(sa); } }

let mut ips: Vec<String> = Vec::with_capacity(4);
if !c.ipv4_address.is_empty() { ips.push(format!("{}/32", c.ipv4_address)); }
if !c.ipv6_address.is_empty() { ips.push(format!("{}/128", c.ipv6_address)); }
ips.push("fe80::/10".to_string());
for extra in &c.server_allowed_ips { if !extra.is_empty() { ips.push(extra.clone()); } }
for s in ips { if let Some(a) = netlink::ip_from_cidr(&s) { peer.allowed_ips.push(a); } }

dev.peers.push(peer);
}
dev
}

pub async fn detect_external_iface() -> Option<String> {
    run("ip", &["route", "show", "default"]).await.ok()?.lines().find_map(|line| {
        let p: Vec<&str> = line.split_whitespace().collect();
        p.iter().position(|&x| x == "dev").and_then(|i| p.get(i+1)).map(|s| s.to_string())
    })
}
async fn ensure_rule(bin: &str, add_args: &[&str]) -> bool {
    let mut check_args = add_args.to_vec();
    if check_args.len() > 1 && check_args[0] == "-I" {
        check_args[0] = "-C";
        if check_args.len() > 2 && check_args[2].chars().all(|c| c.is_ascii_digit()) { check_args.remove(2); }
    } else if !check_args.is_empty() && check_args[0] == "-A" { check_args[0] = "-C"; }
    if run_ok(bin, &check_args).await { return true; }
    run_ok(bin, add_args).await
}
pub async fn setup_nat(vpn_iface: &str, v4_cidr: &str, v6_cidr: &str) -> Result<(), String> {
    let ext = detect_external_iface().await.ok_or_else(|| "no default route".to_string())?;
    let ext = ext.as_str();
    let _ = run_ok("sysctl", &["-q", "-w", "net.ipv4.ip_forward=1"]).await;
    let _ = run_ok("sysctl", &["-q", "-w", "net.ipv6.conf.all.forwarding=1"]).await;
    let _ = ensure_rule("iptables", &["-t", "nat", "-A", "POSTROUTING", "-s", v4_cidr, "-o", ext, "-j", "MASQUERADE"]).await;
    let _ = ensure_rule("iptables", &["-A", "FORWARD", "-i", vpn_iface, "-o", ext, "-j", "ACCEPT"]).await;
    let _ = ensure_rule("iptables", &["-A", "FORWARD", "-i", ext, "-o", vpn_iface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"]).await;
    let _ = ensure_rule("ip6tables", &["-t", "nat", "-A", "POSTROUTING", "-s", v6_cidr, "-o", ext, "-j", "MASQUERADE"]).await;
    let _ = ensure_rule("ip6tables", &["-A", "FORWARD", "-i", vpn_iface, "-o", ext, "-j", "ACCEPT"]).await;
    let _ = ensure_rule("ip6tables", &["-A", "FORWARD", "-i", ext, "-o", vpn_iface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"]).await;
    let _ = run_ok("mkdir", &["-p", "/etc/iptables"]).await;
    let _ = run_ok("bash", &["-c", "iptables-save > /etc/iptables/rules.v4 2>/dev/null || true"]).await;
    let _ = run_ok("bash", &["-c", "ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true"]).await;
    Ok(())
}
pub async fn teardown_nat(vpn_iface: &str, v4_cidr: &str, v6_cidr: &str) {
    let Some(ext) = detect_external_iface().await else { return; };
    let ext = ext.as_str();
    for (bin, args) in [
        ("iptables", vec!["-t", "nat", "-D", "POSTROUTING", "-s", v4_cidr, "-o", ext, "-j", "MASQUERADE"]),
        ("iptables", vec!["-D", "FORWARD", "-i", vpn_iface, "-o", ext, "-j", "ACCEPT"]),
        ("iptables", vec!["-D", "FORWARD", "-i", ext, "-o", vpn_iface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"]),
        ("ip6tables", vec!["-t", "nat", "-D", "POSTROUTING", "-s", v6_cidr, "-o", ext, "-j", "MASQUERADE"]),
        ("ip6tables", vec!["-D", "FORWARD", "-i", vpn_iface, "-o", ext, "-j", "ACCEPT"]),
        ("ip6tables", vec!["-D", "FORWARD", "-i", ext, "-o", vpn_iface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"]),
    ] { while run_ok(bin, &args).await {} }
}
pub async fn setup_one(iface: &VpnInterface, hooks: &Hooks, uc: &UserConfig, clients: &[Client]) -> Result<(), String> {
    add_if(&iface.name).await?;
    let dev = build_device(iface, clients);
    let name_c = iface.name.clone();
    tokio::task::spawn_blocking(move || netlink::set_device(&dev).map_err(|e| format!("netlink set {name_c}: {e}"))).await.map_err(|e| e.to_string())??;
    add_addr(&iface.name, &first_v4_addr(&iface.ipv4_cidr)?).await?;
    add_addr(&iface.name, &first_v6_addr(&iface.ipv6_cidr)?).await?;
    set_mtu(&iface.name, iface.mtu).await?;
    set_up(&iface.name).await?;
    let port_str = iface.port.to_string();
    let _ = ensure_rule("iptables", &["-I", "INPUT", "1", "-p", "udp", "--dport", &port_str, "-j", "ACCEPT"]).await;
    for c in clients {
        if c.enabled == 0 { continue; }
        if !c.ipv4_address.is_empty() { add_route(&iface.name, &format!("{}/32", c.ipv4_address)).await?; }
        if !c.ipv6_address.is_empty() { add_route(&iface.name, &format!("{}/128", c.ipv6_address)).await?; }
    }
    enable_forward().await;
    if iface.firewall_enabled != 0 { let _ = setup_nat(&iface.name, &iface.ipv4_cidr, &iface.ipv6_cidr).await; }
    set_dns(&iface.name, &uc.default_dns).await;
    if !hooks.post_up.trim().is_empty() { let cmd = template_replace(&hooks.post_up, iface); run_ok("bash", &["-c", &cmd]).await; }
    Ok(())
}
pub async fn teardown_one(iface: &VpnInterface, hooks: &Hooks) -> Result<(), String> {
    if !hooks.pre_down.trim().is_empty() { let cmd = template_replace(&hooks.pre_down, iface); run_ok("bash", &["-c", &cmd]).await; }
    if iface.firewall_enabled != 0 { teardown_nat(&iface.name, &iface.ipv4_cidr, &iface.ipv6_cidr).await; }
    let port_str = iface.port.to_string();
    while run_ok("iptables", &["-D", "INPUT", "-p", "udp", "--dport", &port_str, "-j", "ACCEPT"]).await {}
    unset_dns(&iface.name).await;
    del_if(&iface.name).await?;
    if !hooks.post_down.trim().is_empty() { let cmd = template_replace(&hooks.post_down, iface); run_ok("bash", &["-c", &cmd]).await; }
    Ok(())
}
pub async fn setup(base: &VpnInterface, hooks: &Hooks, uc: &UserConfig, clients: &[Client]) -> Result<(), String> {
    let vpn = vpn_interface(base);
    let obfs = obfs_interface(base);
    setup_one(&vpn, hooks, uc, &clients_for_mode(clients, IfaceMode::Vpn)).await?;
    setup_one(&obfs, hooks, uc, &clients_for_mode(clients, IfaceMode::Obfs)).await?;
    Ok(())
}
pub async fn teardown(base: &VpnInterface, hooks: &Hooks) -> Result<(), String> {
    let vpn = vpn_interface(base);
    let obfs = obfs_interface(base);
    teardown_one(&vpn, hooks).await?;
    teardown_one(&obfs, hooks).await?;
    Ok(())
}
