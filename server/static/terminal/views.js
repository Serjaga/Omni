import { dom } from './state.js';
import { escapeHtml, docSection, docPageTitle } from './utils.js';

// ── MAP ────────────────────────────────────────────────────────
export function renderMap() {
  const welcome = document.createElement('div');
  welcome.className = 'map-welcome';
  welcome.innerHTML =
    '<h1>добро пожаловать</h1>' +
    '<p>Omni-RS · интерактивная карта сервера</p>';
  dom.terminal.appendChild(welcome);

  const cards = [
    { id:'http',      icon:'🌐',  name:'HTTP Server',   desc:'HTTP/1.1 · HTTP/2 · HTTP/3 (QUIC)' },
    { id:'dns',       icon:'🌍',  name:'DNS',           desc:'Auth + Recursive + DNSSEC + DoT/DoQ/DoH' },
    { id:'db',        icon:'🗄️',  name:'База данных',    desc:'SQLite + MySQL/PostgreSQL протоколы' },
    { id:'vpn',       icon:'🛡️',  name:'VPN',           desc:'WireGuard + AmneziaWG + eBPF (GUT/QUIC)' },
    { id:'proxy',     icon:'🔀',  name:'Reverse Proxy', desc:'Балансировка · failover · sticky' },
    { id:'security',  icon:'🔒',  name:'Безопасность',  desc:'ACME · mTLS · IPS · admin · firewall' },
    { id:'console',   icon:'⚡',  name:'Консоль',       desc:'Интерактивные команды взлома' },
  ];

  const grid = document.createElement('div');
  grid.className = 'map-grid';
  grid.innerHTML = cards.map(c => `
    <div class="map-card" data-open-tab="${c.id}" role="button" tabindex="0">
      <div class="map-card-icon">${c.icon}</div>
      <div class="map-card-name">${escapeHtml(c.name)}</div>
      <div class="map-card-desc">${escapeHtml(c.desc)}</div>
    </div>
  `).join('');
  dom.terminal.appendChild(grid);

  grid.querySelectorAll('[data-open-tab]').forEach(el => {
    el.onclick = () => window.__renderTab && window.__renderTab(el.dataset.openTab);
    el.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); window.__renderTab(el.dataset.openTab); } };
  });
}

// ── HTTP ───────────────────────────────────────────────────────
export function renderHttpDoc() {
  docPageTitle('🌐','HTTP Server','многоуровневый веб-сервер');
  docSection('Протоколы', `<ul>
      <li><b>HTTP/1.1</b> — классический, через axum + tower-http</li>
      <li><b>HTTP/2</b> — TLS ALPN <span class="doc-code">h2</span>, мультиплексирование</li>
      <li><b>HTTP/3 (QUIC)</b> — на <span class="doc-code">udp/:443</span>, ALPN <span class="doc-code">h3</span>, через quinn + h3-axum</li>
      <li>Auto-detect по ALPN в <span class="doc-code">rustls::ServerConfig</span></li>
      <li><b>TLS 1.3</b> + <b>TLS 1.2</b> fallback через ring provider</li>
    </ul>`);
  docSection('Reverse Proxy', `<ul>
      <li>Пул backends из <span class="doc-code">config.backends</span></li>
      <li><b>Least-connections</b> — выбор по <span class="doc-code">AtomicUsize</span> на бэкенд</li>
      <li><b>Failover</b> — при 5xx переключение на следующий (только GET/HEAD, кроме gRPC)</li>
      <li><b>Circuit Breaker</b> — 5 ошибок за 30с → открыт, record_success() закрывает</li>
      <li><b>Sticky sessions</b> — cookie <span class="doc-code">omnirs_backend=…</span>, SameSite=Lax, Max-Age=86400</li>
      <li>Стриминг тела через <span class="doc-code">Body::from_stream</span> + <span class="doc-code">GuardedStream</span> (RAII-счётчик)</li>
      <li>X-Forwarded-For / X-Real-IP / X-Forwarded-Proto / X-Forwarded-Host</li>
      <li>Срезание hop-by-hop + nominated (Connection) заголовков</li>
    </ul>`);
  docSection('WebSocket / gRPC / FastCGI', `<ul>
      <li><b>WebSocket</b> — прозрачный upgrade, <span class="doc-code">copy_bidirectional</span>, счётчик WS_ACTIVE</li>
      <li><b>gRPC</b> — HTTP/2 prior knowledge, отдельный <span class="doc-code">grpc_client</span></li>
      <li><b>FastCGI</b> — Unix socket / TCP, <span class="doc-code">fastcgi_pass</span>, авто-rewrite на index.php</li>
      <li>PHP-FPM параметры: SCRIPT_FILENAME, DOCUMENT_ROOT, REDIRECT_STATUS=200</li>
    </ul>`);
  docSection('Кэш и сжатие', `<ul>
      <li><b>moka</b> — in-memory кэш, TTL + max_entries</li>
      <li>Кэш-ключ: <span class="doc-code">host|path|query</span>, заголовок <span class="doc-code">x-cache: HIT</span></li>
      <li>Не кэшируются: <span class="doc-code">/health</span>, <span class="doc-code">/metrics</span>, POST/PUT/DELETE</li>
      <li><b>CompressionLayer</b> (gzip/br/deflate)</li>
      <li>Пре-сжатые ассеты <span class="doc-code">.br</span> / <span class="doc-code">.gz</span> с Content-Encoding</li>
    </ul>`);
  docSection('Rate limit & Timeouts', `<ul>
      <li><b>HTTP</b>: 100 req/sec per IP → 429 с Alt-Svc</li>
      <li><b>Admin login</b>: 20 попыток/мин per IP → 429</li>
      <li><b>Таймаут запроса</b>: config.request_timeout_secs (default 30s)</li>
      <li><b>Backend connect</b>: 5s, read/write: 120s (gRPC 300s)</li>
    </ul>`);
}

// ── DNS ────────────────────────────────────────────────────────
export function renderDnsDoc() {
  docPageTitle('🌍','DNS Server','auth + recursive + DNSSEC + шифрование');
  docSection('Транспорты', `<ul>
      <li><b>UDP :53</b> — основной, с rate-limit и RRL</li>
      <li><b>TCP :53</b> — для AXFR/IXFR и больших ответов (TC-флаг)</li>
      <li><b>DoT :853/tcp</b> — DNS-over-TLS, ALPN <span class="doc-code">dot</span></li>
      <li><b>DoQ :853/udp</b> — DNS-over-QUIC, ALPN <span class="doc-code">doq</span></li>
      <li><b>DoH</b> — <span class="doc-code">/dns-query</span> POST/GET (base64url), h2/h3</li>
      <li><b>DoH3</b> — тот же путь поверх QUIC</li>
    </ul>`);
  docSection('Authoritative', `<ul>
      <li>Zone storage: <span class="doc-code">BTreeMap&lt;Name, BTreeMap&lt;u16, Vec&lt;Record&gt;&gt;&gt;</span></li>
      <li>Wildcard-записи (<span class="doc-code">*.example.com</span>)</li>
      <li>CNAME-цепочки до 16 уровней</li>
      <li>ALIAS для apex</li>
      <li>Все типы: A/AAAA/CNAME/NS/SOA/MX/TXT/SRV/NAPTR/CAA/DS/DNSKEY/RRSIG/NSEC/NSEC3/TLSA/SVCB/HTTPS/ALIAS</li>
    </ul>`);
  docSection('Recursive', `<ul>
      <li>Forwarders: <span class="doc-code">1.1.1.1:53</span>, <span class="doc-code">8.8.8.8:53</span></li>
      <li>Conditional forwarding по домену</li>
      <li>Root hints (13 root-серверов)</li>
      <li>QName minimization (упрощённая)</li>
      <li>Кэш: LRU 50 000 записей, TTL + stale 24h</li>
    </ul>`);
  docSection('DNSSEC', `<ul>
      <li>Алгоритм: <b>ECDSA P-256 + SHA-256</b> (alg 13)</li>
      <li>KSK (флаг ZONE|SEP) + ZSK (ZONE)</li>
      <li>sign_zone() — DNSKEY + NSEC + RRSIG по всем RRset</li>
      <li>nsec3_hash() для NSEC3-зон</li>
      <li>canonical_rr() + canonical ordering для подписи</li>
      <li>DS-запись по SHA-256 (digest_type 2)</li>
    </ul>`);
  docSection('Политики', `<ul>
      <li><b>RPZ</b> — block-лист в hosts-формате, exact + wildcard</li>
      <li><b>TSIG</b> — HMAC-SHA256, verify + sign</li>
      <li><b>RRL</b> — rate per (prefix|qname|rcode), slip-логика</li>
      <li><b>DNS Cookies</b> (RFC 7873) — HMAC-SHA256(client_cookie, secret)</li>
      <li><b>Views</b> — по CIDR или TSIG-ключу</li>
      <li><b>Tenants</b> — мульти-тенант по CIDR клиента</li>
      <li><b>GeoDNS</b> — Country CSV-база, по префиксу</li>
      <li><b>Weighted</b> — pick_one / pick_n с весами</li>
      <li><b>Rebinding protection</b> — фильтр private IP в ответах</li>
    </ul>`);
  docSection('IXFR / AXFR', `<ul>
      <li>Journal изменений до 1000 <span class="doc-code">ZoneChange</span></li>
      <li>IXFR — через build_ixfr(client_serial)</li>
      <li>Только TCP (UDP → NOTIMP)</li>
      <li>AXFR — по chunks по 50 записей</li>
    </ul>`);
  docSection('Инструменты', `<ul>
      <li><b>dnstap</b> — JSONL фреймы, length-prefixed</li>
      <li><b>Audit</b> — JSONL, append-only</li>
      <li><b>Prometheus metrics</b> — queries/rcode/cache/rrl/axfr/geo/weighted</li>
    </ul>`);
}

// ── DB ─────────────────────────────────────────────────────────
export function renderDbDoc() {
  docPageTitle('🗄️','Database','SQLite + MySQL/PostgreSQL протоколы');
  docSection('Движок', `<ul>
      <li><b>SQLite</b> через rusqlite (WAL mode, busy_timeout=5s)</li>
      <li>Два системных файла: <span class="doc-code">OmniDB</span> + <span class="doc-code">OmniVPN</span></li>
      <li>Директория: <span class="doc-code">OMNIRS_DB_DIR</span> (default <span class="doc-code">./db</span>)</li>
      <li>Автозагрузка пользовательских <span class="doc-code">*.db</span> / <span class="doc-code">*.sqlite</span> из папки</li>
    </ul>`);
  docSection('Системные таблицы OmniDB', `<ul>
      <li><b>config</b> — key/value (единственный источник истины)</li>
      <li><b>OmniVPN</b> — конфиг VPN-интерфейса (id=1)</li>
      <li><b>OmniDNS</b> — зоны/записи (legacy-совместимость)</li>
      <li><b>OmniProxy</b> — vhosts и редиректы</li>
      <li><b>OmniMetrics</b> — временные ряды</li>
      <li><b>OmniSsl</b> — сертификаты + ACME-аккаунт</li>
      <li><b>vpn_one_time_links</b> — одноразовые ссылки в OmniVPN</li>
    </ul>`);
  docSection('Протоколы на :1000', `<ul>
      <li><b>MySQL</b> — handshake с PROTOCOL_41, COM_QUERY/INIT_DB/PING/QUIT</li>
      <li><b>PostgreSQL</b> — StartupMessage (protocol 196608), Query/Sync/Terminate</li>
      <li>Авто-детект по первым 8 байтам (<span class="doc-code">peek[4..8] == [0,3,0,0]</span>)</li>
      <li>Один порт для mysql-client, psql и <span class="doc-code">omni</span>-шелла</li>
      <li>Логин <span class="doc-code">-u root</span> без пароля (демо-режим)</li>
    </ul>`);
  docSection('Клиентский шелл', `<ul>
      <li><span class="doc-code">./OmniRS client</span> или симлинк <span class="doc-code">omni</span></li>
      <li>Флаги: <span class="doc-code">-h &lt;host&gt; -p &lt;port&gt; -u &lt;user&gt;</span></li>
      <li>REPL с поддержкой <span class="doc-code">help</span>, <span class="doc-code">exit</span>, <span class="doc-code">\q</span></li>
    </ul>`);
  docSection('Управление через админку', `<ul>
      <li>REST API: <span class="doc-code">GET /api/db/connections</span></li>
      <li><span class="doc-code">/api/db/config</span> — чтение/запись key-value</li>
      <li><span class="doc-code">/api/db/connections/{db}/tables</span> — список таблиц</li>
      <li><span class="doc-code">…/tables/{tbl}/rows?limit=&amp;offset=&amp;search=</span> — пагинация</li>
      <li>Row CRUD: <span class="doc-code">POST/PUT/DELETE …/row</span></li>
      <li>Экспорт/импорт <span class="doc-code">.db</span> / SQLite файлов</li>
    </ul>`);
}

// ── VPN ────────────────────────────────────────────────────────
export function renderVpnDoc() {
  docPageTitle('🛡️','VPN','WireGuard + AmneziaWG + eBPF');
  docSection('Три интерфейса', `<ul>
      <li><b>vpn0</b> :888 — чистый WireGuard, для клиентов с QR-кодом</li>
      <li><b>obfs0</b> :880 — AmneziaWG (обфускация через S/H/J параметры)</li>
      <li><b>vpn_obfs0</b> :808 — WireGuard + eBPF-обфускатор (GUT/QUIC)</li>
      <li>Все три в одной базе клиентов, IP-адреса разные подсети</li>
      <li>vpn_obfs0 автоматически сдвигает клиентские IP (<span class="doc-code">10.88.0.x → 10.89.0.x</span>)</li>
    </ul>`);
  docSection('eBPF datapath (GUT v1)', `<ul>
      <li><b>TC egress</b> на физическом NIC — маскировка исходящих</li>
      <li><b>TC ingress</b> — демаскировка входящих</li>
      <li><b>ChaCha20</b> маска (раунды 4) для первого блока</li>
      <li>Заголовок: <b>QUIC short</b> (16б) / <b>QUIC long</b> (1200б) / <b>SIP</b> / <b>Syslog</b></li>
      <li>Base64-кодирование inner-пакета для SIP/Syslog</li>
      <li>AES-128-GCM для QUIC long header</li>
      <li>Ballast-паддинг: пакеты &lt; 220 байт → добивка случайным</li>
      <li>Verifier-friendly: без циклов while с data-dependent условием</li>
    </ul>`);
  docSection('Клиенты', `<ul>
      <li>QR-код — рисуется в SVG через <span class="doc-code">qrcode</span> crate</li>
      <li><b>QR</b> → <span class="doc-code">configuration/vpn</span> (vpn0 :888)</li>
      <li><b>Obfs</b> → <span class="doc-code">configuration/obfs</span> (obfs0 :880)</li>
      <li><b>eBPF</b> → <span class="doc-code">configuration/vpn_obfs</span> (vpn_obfs0 :808)</li>
      <li><b>One-time-link</b> — ссылка <span class="doc-code">/cnf/{token}</span> на 5 минут</li>
      <li>AmneziaVPN URL: <span class="doc-code">vpn://</span> base64url(zlib(json))</li>
    </ul>`);
  docSection('Управление', `<ul>
      <li><b>netlink</b> — generic netlink с family <span class="doc-code">wireguard</span> / <span class="doc-code">amneziawg</span></li>
      <li>Fallback уровней UAPI: EXTENDED_V2 → level 1 → level 0 (если ядро не поддерживает)</li>
      <li>NAT через iptables/ip6tables (MASQUERADE + FORWARD)</li>
      <li>Ключи: X25519 (curve25519-dalek вручную на u64-лимбах)</li>
      <li>Автоматическое пересоздание при старте: teardown → save_config</li>
      <li>Cron: каждый 60с → отключение истёкших клиентов + очистка OTL</li>
    </ul>`);
}

// ── PROXY ──────────────────────────────────────────────────────
export function renderProxyDoc() {
  docPageTitle('🔀','Reverse Proxy','балансировка и отказоустойчивость');
  docSection('Backends', `<ul>
      <li>Список в <span class="doc-code">config.backends</span> (через <span class="doc-code">;</span>)</li>
      <li>Health check каждые 10с — GET <span class="doc-code">/</span> на backend</li>
      <li><b>backend_health</b>: <span class="doc-code">RwLock&lt;HashMap&lt;url, bool&gt;&gt;</span></li>
      <li><b>backend_conns</b>: <span class="doc-code">AtomicUsize</span> на бэкенд</li>
      <li><b>backend_circuits</b>: <span class="doc-code">CircuitBreaker</span> на бэкенд</li>
      <li>Динамическое добавление через <span class="doc-code">POST /api/proxy/backends/add</span></li>
    </ul>`);
  docSection('Алгоритмы', `<ul>
      <li><b>Least-connections</b> — выбор по min(AtomicUsize)</li>
      <li><b>Failover</b> — при 5xx перейти на следующий (до failover_attempts)</li>
      <li><b>Sticky</b> — cookie <span class="doc-code">omnirs_backend</span> или hash(client_ip)</li>
      <li><b>Circuit Breaker</b> — 5 failures за 30с → открыт на 30с</li>
    </ul>`);
  docSection('Маршруты', `<ul>
      <li><b>proxy_prefix</b> — префикс, куда проксировать (default <span class="doc-code">/api</span>)</li>
      <li><b>redirects</b> — <span class="doc-code">HashMap&lt;path, url&gt;</span> → 302</li>
      <li><b>virtual_hosts</b> — статика per-host</li>
      <li>Стриминг тела — без буферизации (кроме FastCGI 10MB)</li>
      <li>Срезание <span class="doc-code">Connection</span>-nominated заголовков</li>
      <li>RAII GuardedStream держит счётчик conns до EOF</li>
    </ul>`);
  docSection('Специальные', `<ul>
      <li><b>WebSocket</b> — прозрачный upgrade + copy_bidirectional</li>
      <li><b>gRPC</b> — http2_prior_knowledge + отдельный reqwest-клиент</li>
      <li><b>FastCGI</b> — Unix / TCP php-fpm, index.php-rewrite</li>
      <li><b>Rate limits</b> — <span class="doc-code">HashMap&lt;ip, (Instant, u32)&gt;</span></li>
      <li>RESET через <span class="doc-code">POST /api/proxy/rate_limits/reset</span></li>
    </ul>`);
}

// ── SECURITY ───────────────────────────────────────────────────
export function renderSecurityDoc() {
  docPageTitle('🔒','Безопасность','ACME · mTLS · IPS · admin');
  docSection('ACME / TLS', `<ul>
      <li>Let's Encrypt v2 (directory / newOrder / finalize / cert)</li>
      <li><b>HTTP-01</b> для доменов, challenge в <span class="doc-code">/.well-known/acme-challenge/</span></li>
      <li><b>TLS-ALPN-01</b> для IP (shortlived-профиль)</li>
      <li>AcmeMode: <span class="doc-code">False | Http | Tls | All</span></li>
      <li>Продление раз в 12ч, при остатке &lt; 3 дней</li>
      <li>Сертификаты в БД <span class="doc-code">OmniSsl</span> (domain, cert_pem, key_pem)</li>
      <li>Auto-reload в RustlsConfig через SslManager::reload_from_db()</li>
      <li><b>mTLS</b> — WebPkiClientVerifier, allow_unauthenticated если !required</li>
      <li><b>ALPN</b>: h2, http/1.1, h3, acme-tls/1, dot, doq</li>
    </ul>`);
  docSection('Admin', `<ul>
      <li><b>x-admin-token</b> header или <span class="doc-code">omnirs_admin</span> cookie</li>
      <li>Constant-time compare через XOR-OR</li>
      <li>Сессия: HttpOnly; Secure; SameSite=Strict; Max-Age=86400</li>
      <li>Rate limit login: 20/мин per IP</li>
      <li>admin_allowed_ips — CIDR-фильтр</li>
      <li>log_admin_action() пишет в audit-лог</li>
      <li>X-Frame: DENY в admin_response (перекрывает SAMEORIGIN)</li>
    </ul>`);
  docSection('IPS / Fail2ban', `<ul>
      <li>Мониторит journalctl: ssh, omnirs, kernel</li>
      <li><b>Threats</b>: SshBrute / HttpAuth / HttpForbidden / HttpRateLimit / HttpServerError / PortScan / SynFlood</li>
      <li>Ban через iptables/ip6tables DROP на 3600с</li>
      <li>Whitelist: loopback, RFC1918, link-local, SSH_CONNECTION</li>
      <li>Лог: <span class="doc-code">[IPS] {ip} — {reason} N/M → BAN</span></li>
    </ul>`);
  docSection('Perimeter', `<ul>
      <li><b>Security headers</b>: HSTS / nosniff / X-Frame-SAMEORIGIN / Referrer-Policy</li>
      <li><b>Scanner block</b> — 11 паттернов (wp-admin, .env, phpunit, …) → 404</li>
      <li><b>SSRF-guard</b> — is_ssrf_target() блокирует localhost/private IP</li>
      <li><b>Firewall</b> — auto_open_ports через iptables (если OMNIRS_AUTO_OPEN_PORTS=1)</li>
      <li><b>Audit log</b> — JSONL, OmniRS_AUDIT_LOG</li>
      <li><b>rebinding protection</b> в DNS</li>
    </ul>`);
  docSection('Path Safety', `<ul>
      <li>canonicalize() + starts_with(root) для всех файловых операций</li>
      <li>Symlink write → 403</li>
      <li>admin_root ≠ "/" (проверка при старте)</li>
      <li>Path traversal (<span class="doc-code">../</span>) через Normal-компоненты → 403</li>
    </ul>`);
}