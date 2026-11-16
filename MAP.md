# OmniRS — Полная карта проекта

Единый production-сервер в одном бинарнике: HTTP/1.1+HTTP/2(TLS)+HTTP/3(QUIC), обратный прокси
(балансировка/failover/circuit-breaker/sticky), WebSocket/gRPC/FastCGI-прокси, ACME (Let's Encrypt),
mTLS, кэш (moka), rate-limit, метрики Prometheus, веб-админка, hot-reload, полноценный DNS-сервер
(authoritative+recursive+DNSSEC+DoT/DoQ/DoH/DoH3+RPZ+TSIG+GeoDNS+Weighted+RRL+dnstap+Audit+IXFR),
встроенная БД (SQL-подобный язык + протоколы MySQL/PostgreSQL на :1000), WireGuard VPN, IKEv2,
Hysteria2 (miraj), forward-туннели (TCP/UDP/SOCKS5/TProxy), встроенный IPS (fail2ban).

После рефакторинга — Cargo workspace из 11 библиотечных крейтов + 1 бинарный.

---

## 1. Структура workspace

```
Omni/
├── Cargo.toml              # [workspace] + [workspace.dependencies] (единые версии)
├── Cargo.lock
├── ritual.sh               # установка/обновление (systemd unit, swap, seed БД, alias 'ritual')
├── .cargo/config.toml       # линкер + incremental (по умолчанию cc; оригинал — clang+mold)
│
├── core/                   # 155 строк  — общие примитивы (X25519/WireGuard crypto)
│   └── src/{lib.rs, crypto.rs}
├── logger/                 #  73 строки  — RollingLogger (access/slow log, ротация)
├── cors/                   #  36 строк   — чистые CORS-хелперы (origin_allowed, preflight)
├── security/               # 412 строк   — IPS/fail2ban: SSH-брутфорс, HTTP-атаки, port-scan, SYN-flood → iptables
├── dns/                    # 1360 строк  — DNS-сервер (протокол, зоны, DoT/DoQ/DoH, RPZ, TSIG, GeoDNS)
├── tunnel/                 # 1846 строк  — forward-туннели (TCP/UDP/Stdio/SOCKS5/TProxy, JWT, restrictions)
├── db/                     # 1153 строк  — DbManager (rusqlite+bb8), схемы OmniDB/OmniVPN, SQL-dialect, MySQL/PG-протокол
├── ikev2/                  #  849 строк  — IKEv2/IPsec (Ryke: crypto, SA, ESP)
├── ssl/                    #  834 строк  — SslManager (rustls, ACME HTTP-01/TLS-ALPN, self-signed, hot-reload)
├── miraj/                  #  715 строк  — Hysteria2 поверх QUIC (brutal congestion, auth, multiplexed)
├── vpn/                    # 2178 строк  — WireGuard (uapi, netlink, iface, конфиги, клиентские таблицы)
│
└── server/                 # бинарник [[bin]] name = "OmniRS"
    ├── Cargo.toml          # зависит от всех 11 крейтов
    ├── src/
    │   ├── main.rs         # 2074 строки — точка входа, AppState/Config, HTTP/HTTP2/HTTP3-сервер, прокси, статика, оркестрация
    │   ├── api.rs          # 1786 строки — /api/* + /terminal/* диспетчер, сессии, нотификации
    │   └── omni_mw.rs      # 153 строки  — axum-middleware: access_log + cors_mw (привязаны к AppState)
    └── static/             # 23 файла — встроены через include_str!("../static/...")
        ├── admin.html
        ├── terminal.html
        ├── admin/          # app.js dashboard.js db.js dns.js files.js monitoring.js proxy.js settings.js ssl.js vpn.js style.css
        └── terminal/       # api.js app.js console.js hack.js leak.js state.js ui.js utils.js views.js style.css
```

Итого: **~17.6k строк Rust**.

---

## 2. Граф зависимостей (ациклический, снизу вверх)

```
                        ┌──────────────────────────────┐
                        │  server (bin «OmniRS»)       │  main.rs + api.rs + omni_mw.rs + static/
                        └──────────────┬───────────────┘
        ┌──────────┬──────────┬─────────┼─────────┬──────────┬──────────┐
        ▼          ▼          ▼         ▼         ▼          ▼          ▼
      vpn       ssl       miraj     ikev2      db       tunnel     (dns, security,
        │         │          │         │         │          │         logger, cors)
        │         └────┐     │         │         │          │
        │              ▼     ▼         ▼         │          │
        │            dns  (dns)    (db)◄─────────┘          │
        │              ▲     ▲                              │
        └────────► core ◄────┴──────────────────────────────┘
                   (X25519 crypto)
```

| Крейт | Зависит от | Роль в слое |
|---|---|---|
| core | — | низший слой, чистая крипта (std only) |
| logger, cors, security, dns, tunnel | — | автономные, без внутренних зависимостей |
| db | core | БД + схемы (использует core::crypto для генерации WireGuard-ключей при seed) |
| ikev2 | db | — |
| ssl | db, dns | dns — для `extract_sans` / `normalize_dns_name` |
| miraj | db | — |
| vpn | core, db | ре-экспортирует `omni_db::{db_dir, open_omni, open_vpn, client_table_name, create_client_table}` в своём `mod db` |
| server | все 11 | оркестрация, HTTP-слой, статика |

---

## 3. Карта крейтов: ответственность и публичный API

### core (`omni_core`)
- `crypto::genkey() / genpsk() / pubkey(sk) / key_to_base64 / key_from_base64 / key_to_hex / key_from_hex / x25519 / curve25519_generate_public` — чистая реализация X25519 + base64/hex, `/dev/urandom` (без внешних crypto-крейтов).
- Вынесен из `vpn::crypto`, чтобы разорвать цикл `db ↔ vpn`.

### logger (`omni_logger`)
- `RollingLogger::new(path, max_size_mb, max_files)` → `.write(&str)`, ротация `.1..N`.
- Используется в `AppState.access_logger / slow_logger`.

### cors (`omni_cors`)
- `cors_origin_allowed(origin, &[String])`, `cors_preflight_response(origin)`, константы `ALLOW_METHODS / ALLOW_HEADERS`.
- Сам middleware `cors_mw` — в `server::omni_mw` (нужен `SharedState`).

### security (`omni_security`)
- `IntrusionPrevention::new(window_sec)` — бан через `iptables/ip6tables`, мониторинг `journalctl` (ssh, omnirs, kernel). Запуск: `security::start_monitors(ips, ssh_whitelist)` из main.

### dns (`omni_dns`)
- `DnsServer::from_config(DnsConfig)`, `run_udp / run_tcp / run_dot_tls / start_dot_server / start_doq_server / serve_doq_stream`.
- Типы: `DnsConfig`, `DnsError`, `Name`, `Message`, `Record`, `RData`, `Zone`, `ZoneChange`, `AuditLog`.

### tunnel (`omni_tunnel`)
- `TunnelServer::new(TunnelServerConfig, DefaultTokioExecutor)`, `serve`, `handle_tunnel_request`, `RestrictionsRules::from_path_prefix`, `DnsResolver::new_from_urls`, `SoMark`, `LocalProtocol` (Tcp/Udp/Stdio/Socks5/TProxyTcp/Reverse*).
- Внутренние inline-модули: `protocols::dns`, `somark`, `executor`, `restrictions`, `transport`, `server`.

### db (`omni_db`)
- `init_global().await`, `global() -> Option<Arc<DbManager>>`, `DbConfig::from_env()`, `db_dir()`, `open_omni() / open_vpn()`, `Pool` (Sqlite), `run_query`.
- Схемы: `init_system_schema`, `init_vpn_schema`, `client_table_name / create_client_table` (переехали из `vpn::db`).
- HTTP-dispatch: `dispatch_api(db, method, endpoint, qmap, headers, body, client_ip)`, `dispatch_tunnel_api(method, endpoint, ...)`.

### ikev2 (`omni_ikev2`)
- `run(...)`, `start_server(...)`, `dispatch_api(ikev2_enabled, ikev2_listen, ikev2_psk, ikev2_local_id, ikev2_remote_id, method, endpoint, ...)`.

### ssl (`omni_ssl`)
- `SslManager::new()`, `reload_from_db().await`, `generate_self_signed_default()`, `spawn_initial_issuance`, `AcmeMode` (False/Http/Tls/All).
- `dispatch_api(acme_ip: Option<String>, root: PathBuf, ssl: Option<Arc<SslManager>>, method, endpoint, ...)`.

### miraj (`omni_miraj`)
- `MirajConfig::from_map(&HashMap)`, `run(cfg, resolver, shutdown).await`, `is_hysteria_auth`, `handle_auth`, `handle_authorized_connection`, `BrutalFactory`, `AuthResult`.
- `dispatch_api(method, endpoint, ...)` (state не нужен).

### vpn (`omni_vpn`)
- `VpnConfig`, `startup(&VpnConfig).await`, `start_cron()`, `metrics_extra_async()`, `serve_otl(token)`, `dispatch(method, endpoint, query, headers, body, client_ip)` (state не нужен).
- Подмодули: `uapi`, `netlink`, `iface`, `db` (ре-экспорт omni_db + `row_to_client`, `drop_client_table`, `list_client_tables`, `get_interface`).

### server (`omni-server`, bin `OmniRS`)
- **main.rs**: `Config` (toml/json/env/DB), `AppState` (SharedState = `Arc<RwLock<Arc<AppState>>>`), HTTP/1.1+HTTP2 (axum-server rustls), HTTP/3 (h3-axum/quinn), multiplexed QUIC (miraj поверх h3), WebTransport-туннель, обратный прокси (round-robin + health + circuit-breaker + sticky), FastCGI, ACME, статика (include_str!), hot-reload, оркестрация vpn/miraj/dns/ikev2/tunnel/security.
- **api.rs**: `dispatch(state, ...)` — `/api/*` (db, vpn, ssl, dns, ikev2, miraj, tunnel, файлы, бэкапы, мониторинг), `dispatch_terminal(...)` — `/terminal/*`, сессии (`Session`), `push_notif`.
- **omni_mw.rs**: `access_log` (JSON access/slow log + `x-request-id`), `cors_mw` (hot-reload `cors_allowed_origins` из AppState).

---

## 4. Статика (встроена в бинарник через `include_str!`)

| Путь | Что |
|---|---|
| `static/admin.html` + `static/admin/*.{js,css}` | Веб-админка: dashboard, db, dns, files, monitoring, proxy, settings, ssl, vpn |
| `static/terminal.html` + `static/terminal/*.{js,css}` | Web-терминал: api, app, console, hack, leak, state, ui, utils, views |

Пути `include_str!("../static/...")` не менялись при переносе (`server/src/main.rs` → `../static/` = `server/static/`).

---

## 5. Сборка и запуск

```bash
cargo check            # ~0 ошибок
cargo build            # бинарник: target/debug/OmniRS ([[bin]] name = "OmniRS")
cargo build --release  # lto = "thin", codegen-units = 1
./ritual.sh            # установка на сервер: systemd unit omnirs.service, swap 2G, seed БД, alias 'ritual'
```

- Бинарник запускается из `/root/OmniRS/OmniRS`, `OMNIRS_DB_DIR=/root/OmniRS/db` (см. unit в ritual.sh).
- Подкоманды: `OmniRS config test` — seed БД (admin_token, address).

### Слушающие порты (типично)
| Порт | Сервис |
|---|---|
| 80 | HTTP (ACME HTTP-01, редирект) |
| 443 | HTTPS (TLS) + HTTP/3 (QUIC) + multiplexed miraj |
| 53 (udp/tcp) | DNS authoritative/recursive |
| 853 | DoT, 784/853? DoQ (QUIC), DoH/DoH3 поверх HTTPS |
| 500/4500 | IKEv2/IPsec |
| 880 | WireGuard (порт по умолчанию) |
| 1000 | Unified listener: MySQL + PostgreSQL + omni-shell |
| 8080/8443? | внутренние (туннели/админка) |

### Env-переменные (`OMNIRS_*`)
`ADDR, ADMIN_TOKEN, DB_DIR, DB_ENABLED, DB_ALLOW_DDL, DB_ALLOW_WRITE, DNS_ENABLED, DNS_CONFIG, ROOT, ADMIN_ROOT, PROXY_PREFIX, BACKENDS, ACME_MODE, ACME_IP, ACME_DOMAINS, FASTCGI_PASS, CORS_ALLOWED_ORIGINS, ACCESS_LOG_PATH, SLOW_LOG_PATH, AUDIT_LOG, AUDIT_LOG_MAX_MB, ADMIN_ALLOWED_IPS, METRICS_ALLOWED_IPS, TRUST_PROXY, VPN_ENABLED, TUNNEL_ENABLED, TUNNEL_PATH_PREFIX, TUNNEL_ALLOW_TARGETS, IPS, IPS_LOG_PACKETS, SSH_WHITELIST, AUTO_OPEN_PORTS, STICKY_SESSIONS, H3_PORT`.

Приоритет конфига: **DB (config-таблица) > env > дефолты**.

---

## 6. Что было сделано при рефакторинге (заметки)

1. **Цикл `db ↔ vpn` разорван**: `vpn::crypto` (чистые функции) → `core`; `vpn::db::{client_table_name, create_client_table}` (SQL-схема) → `db`. В `vpn::db` остался ре-экспорт + функции, требующие VPN-типов (`row_to_client`, `drop_client_table`, `get_interface`).
2. **Отвязка dispatch-функций от `AppState`**: вместо `Arc<AppState>` domain-крейты принимают только нужные поля (db handle, 5 ikev2-полей, acme_ip/root/ssl). `vpn::dispatch` и `miraj::dispatch_api` state не принимают.
3. **`access_log` + `cors_mw` перенесены в `server::omni_mw`** — они используют `SharedState`/`resolve_client_ip` (server-local). Модуль назван `omni_mw`, чтобы не конфликтовать с `axum::middleware`.
4. **`map.rs` не переносился** — мёртвый файл (0 pub-items, ни на что не ссылается, только комментарии).
5. **`crate::tunnel::` self-ссылки** в tunnel.rs заменены на `crate::` (tunnel теперь и есть крейт).
6. **Виртуальный манифест** не поддерживает `[target.'cfg(...)'.workspace.dependencies]` — `tokio-fd` добавлен как обычная target-зависимость в tunnel/ikev2/server.
7. **Линкер**: оригинал `clang`+`mold`; в `.cargo/config.toml` оставлен `cc` (переносимо) — верните при наличии clang/mold.
8. В lib-крейтах зависимости намеренно избыточны (только warnings `unused dependency`) — можно подчистить.

---

## 7. Обновление v2 (по запросу)

### Независимость модулей
- Domain-крейты (`dns, security, logger, cors, tunnel, ikev2, ssl, miraj, vpn`) больше не зависят друг от друга — только от инфраструктурных `core` + `db`.
- `ssl` больше не зависит от `dns`: `normalize_dns_name` / `extract_sans` заинлайнены в ssl-крейт.
- `vpn` не ре-экспортирует чужой код: `pub use omni_db::{...}` удалён, внутренние вызовы идут через `omni_db::`, в `vpn::mod db` — только `use` (не `pub use`). Каждый крейт содержит только свой код.
- Настоящих блочных комментариев `/* */` в проекте нет (все вхождения `/*` — внутри `//`-строк, напр. `/api/*`).

### Дробление больших файлов
- `vpn/src/`: lib.rs + `uapi.rs`, `netlink.rs`, `iface.rs`, `db.rs` (inline-модули вынесены в файлы).
- `tunnel/src/`: lib.rs + `somark.rs`, `executor.rs`, `protocols.rs`, `restrictions.rs`, `tls_reloader.rs`, `transport.rs`, `server.rs`.
- `db/src/`: lib.rs + `dispatch.rs` (dispatch_api/dispatch_tunnel_api + client_table-хелперы, ре-экспорт через `pub use dispatch::*`).
- `server/src/`: main.rs + `api.rs` + `omni_mw.rs` + `static_assets.rs` (include_str!-константы) + `modules.rs`.
- `api.rs` оставлен единым (сильно связанные приватные хелперы; дальнейший сплит требует их `pub(crate)`).

### Управление модулями в админке (переработано)
- Backend: `server/src/modules.rs` — единый реестр системных и устанавливаемых Rust source-модулей в `OmniModules`.
- `server/build.rs` обнаруживает `modules/installed/<id>/module.toml`, подключает указанный `entry` как модуль основного server crate и генерирует `generated_modules.rs`.
- Каждый source-модуль реализует `start(SharedState)` и `dispatch(ApiCtx)`. `start` запускается при старте сервера; `dispatch` выполняется внутри защищённого `/api/*` pipeline после проверки административной авторизации.
- `POST /api/modules/upload/<id>` принимает ZIP с `module.toml`, `src/*.rs` и необязательным `admin/`. Повторная загрузка того же ID обновляет пакет. После загрузки запускается отдельная фоновая сборка основного `OmniRS`, замена бинарника и перезапуск `omnirs.service`.
- Административный интерфейс модуля подключается через `admin_entry` и экспорт `mount(container)`; ресурсы раздаются через `/module-assets/<id>/...`.
- `native_modules.rs`, C-ABI `.so` loader, `libloading`, старые переключатели и кнопка логов удалены. Формат пакета и контракт описаны в `MODULES.md`.
