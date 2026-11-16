# OmniRS — полная карта проекта (обновлённая архитектура модулей)

**Основано на фактическом содержимом архива `OmniRS_modules_reworked.zip`.** Документ описывает файлы и связи текущего проекта. Он не является гарантией успешной компиляции: Rust-сборка в рабочем окружении не выполнялась.

## 1. Что изменилось в архитектуре

В этой версии сторонние Rust-модули из ZIP предназначены для встраивания в **основной бинарник `OmniRS`**, а не для загрузки `.so`.

- `server/src/modules.rs` — единый менеджер системных и устанавливаемых модулей.
- `server/build.rs` обнаруживает исходники в `modules/installed/` и генерирует Rust-реестр в `OUT_DIR/generated_modules.rs`.
- `server/src/main.rs` включает сгенерированный реестр через `include!`, запускает `start()` установленных модулей и публикует их административные ресурсы.
- `server/src/api/mod.rs` передаёт API-контекст в `generated_modules::dispatch()` после существующих ранних dispatch-ветвей и до обычных API-обработчиков.
- `server/static/admin/modules.js` предоставляет список, загрузку/обновление ZIP, открытие интерфейса и удаление модулей.
- `server/src/native_modules.rs`, `core/src/module.rs` и зависимость `libloading` отсутствуют в обновлённой структуре. `.so`-режим в этой версии не реализован.

**Важно:** это compile-time подключение. Установка/обновление требует пересборки всего `OmniRS` и перезапуска службы. Модуль не становится исполняемым Rust-кодом в текущем процессе без этого.

## 2. Полное дерево файлов

```text
OmniRS/
├── .cargo/
│   └── config.toml
├── Cargo.toml                 # workspace, версии и общие зависимости
├── Cargo.lock                 # закреплённые версии зависимостей
├── MAP.md                     # этот документ
├── MODULES.md                 # контракт и формат source-модулей
├── ritual.sh                  # исходный Bash-установщик; не изменён
├── public/                    # каталог публичных файлов (в архиве пустой)
├── modules/
│   ├── installed/             # установленные source-модули; в архиве .keep
│   ├── staging/               # временные каталоги обновления/распаковки
│   └── state/                 # статусы и логи фоновой сборки
├── examples/
│   ├── example_module.zip     # пример ZIP-модуля
│   └── module-template/
│       ├── module.toml
│       ├── src/installer.rs
│       └── admin/index.js
├── core/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       └── crypto.rs
├── cors/
│   ├── Cargo.toml
│   └── src/lib.rs
├── security/
│   ├── Cargo.toml
│   └── src/lib.rs
├── dns/
│   ├── Cargo.toml
│   └── src/lib.rs
├── db/
│   ├── Cargo.toml
│   ├── OmniDB                 # runtime SQLite-файл, если включён в поставку
│   ├── OmniDB-shm             # SQLite WAL sidecar
│   ├── OmniDB-wal             # SQLite WAL sidecar
│   ├── OmniVPN                # runtime SQLite-файл, если включён в поставку
│   ├── OmniVPN-shm
│   ├── OmniVPN-wal
│   └── src/
│       ├── lib.rs
│       └── dispatch.rs
├── ikev2/
│   ├── Cargo.toml
│   └── src/lib.rs
├── ssl/
│   ├── Cargo.toml
│   └── src/lib.rs
├── miraj/
│   ├── Cargo.toml
│   └── src/lib.rs
├── tunnel/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── executor.rs
│       ├── protocols.rs
│       ├── restrictions.rs
│       ├── server.rs
│       ├── somark.rs
│       ├── tls_reloader.rs
│       └── transport.rs
├── vpn/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── db.rs
│       ├── iface.rs
│       ├── netlink.rs
│       └── uapi.rs
└── server/
    ├── Cargo.toml
    ├── build.rs               # генерирует compile-time реестр модулей
    ├── src/
    │   ├── main.rs            # основной сервер и orchestration
    │   ├── modules.rs         # единый менеджер модулей; ZIP/build/status/delete
    │   ├── installer.rs       # Rust CLI-установщик
    │   ├── omni_mw.rs         # middleware
    │   ├── static_assets.rs   # встраиваемые HTML/JS/CSS
    │   └── api/
    │       ├── mod.rs         # API dispatch и ApiCtx
    │       ├── auth.rs        # авторизация
    │       ├── helpers.rs     # ответы и разбор параметров
    │       ├── sess.rs        # сессии/runtime-состояние
    │       └── handlers/
    │           ├── mod.rs
    │           ├── cache.rs
    │           ├── dns_h.rs
    │           ├── files.rs
    │           ├── misc.rs
    │           ├── proxy.rs
    │           ├── settings.rs
    │           ├── system.rs
    │           └── ui.rs
    └── static/
        ├── admin.html
        ├── admin/
        │   ├── app.js
        │   ├── dashboard.js
        │   ├── db.js
        │   ├── dns.js
        │   ├── files.js
        │   ├── modules.js
        │   ├── proxy.js
        │   ├── settings.js
        │   ├── ssl.js
        │   ├── vpn.js
        │   └── style.css
        ├── terminal.html
        └── terminal/
            ├── api.js
            ├── app.js
            ├── console.js
            ├── hack.js
            ├── leak.js
            ├── state.js
            ├── style.css
            ├── ui.js
            ├── utils.js
            └── views.js
```

Файлы `OmniDB`, `OmniVPN`, `-wal`, `-shm` — SQLite runtime-данные, а не исходный код. Их включение в архив не означает, что ими следует заменять данные рабочей установки.

## 3. Cargo workspace и сборка

Корневой `Cargo.toml` объявляет workspace с resolver `2`, edition `2024`, `rust-version = 1.100` и 11 пакетами: `core`, `cors`, `security`, `dns`, `tunnel`, `db`, `ikev2`, `ssl`, `miraj`, `vpn`, `server`. Общие версии библиотек централизованы в `[workspace.dependencies]`.

`server/Cargo.toml` задаёт пакет `omni-server`, бинарный target `OmniRS` и зависимости на внутренние crates и сетевые/системные библиотеки.

### `server/build.rs`

1. Просматривает `modules/installed/<id>/`.
2. Проверяет допустимость ID.
3. Читает `module.toml` и извлекает поле `entry` (по умолчанию `src/module.rs`).
4. Убеждается, что entry находится в `src/`, не содержит `..` и указывает на существующий файл.
5. Генерирует `OUT_DIR/generated_modules.rs` с `#[path = "..."] pub mod ...` для найденных модулей.
6. Генерирует общий `start(state)` и `dispatch(ctx)`, вызывающие одноимённые функции каждого source-модуля.
7. Добавляет `cargo:rerun-if-changed` для каталога модулей и файлов внутри него.

Идентификаторы Rust-модулей кодируются в безопасные имена `m_<hex ID>`, поэтому дефисы в ID не становятся дефисами в идентификаторах Rust.

**Граница механизма:** build.rs не превращает произвольный crate из ZIP в новый workspace member и не добавляет автоматически внешние Cargo dependencies. Встраиваемый entry должен быть совместим с типами и зависимостями основного `omni-server`.

## 4. Формат устанавливаемого модуля

Документ контракта: `MODULES.md`. Пример: `examples/module-template/` и `examples/example_module.zip`.

```text
my-module.zip
├── module.toml
├── src/
│   ├── installer.rs
│   └── installer/handlers.rs   # дочерние файлы, если используются mod handlers;
└── admin/
    ├── index.js                # необязательно
    └── style.css               # необязательно
```

Пример манифеста:

```toml
id = "my_module"
name = "My module"
version = "1.0.0"
description = "Описание модуля"
kind = "source"
entry = "src/installer.rs"
admin_entry = "admin/index.js"
```

`id` должен совпадать с ID, указанным при загрузке ZIP. `kind` в текущем менеджере должен быть `source`. Entry должен быть существующим `.rs`-файлом внутри `src/`. `admin_entry` необязателен и должен указывать внутрь `admin/`.

Главный Rust-файл обязан предоставить:

- `pub async fn start(state: crate::SharedState)` — запуск фоновых задач/служб при старте OmniRS;
- `pub async fn dispatch(ctx: crate::api::ApiCtx) -> Option<axum::response::Response<axum::body::Body>>` — обработка API; `None` означает, что модуль не обработал endpoint.

`ApiCtx` содержит `state`, `method`, `endpoint`, `query`, `headers`, `body`, `client_ip`. В API pipeline `dispatch` вызывается после ранних dispatch-ветвей для tunnel, DB, VPN, сертификатов, IKEv2, Miraj и самого менеджера модулей, но до обычных встроенных admin handlers. Следовательно, совпадение endpoint с одной из ранних ветвей не передаёт управление пользовательскому source-модулю.

Административный JS должен экспортировать `mount(container)`. Он динамически загружается из `/module-assets/<id>/<admin_entry>`. Файлы интерфейса хранятся в `modules/installed/<id>/admin/` и отдаются через обработчик `serve_module_asset`, который проверяет путь и ограничивает доступ каталогом конкретного модуля.

## 5. `server/src/modules.rs` — единый менеджер модулей

Функции и ответственность:

- держит метаданные системных модулей в `SYSTEM_MODULES`;
- валидирует ID и манифест source-модуля;
- безопасно извлекает ZIP, блокирует абсолютные пути, `..`, `:` и выход за каталог назначения; ограничивает распакованный размер 256 MiB;
- создаёт/обновляет схему и записи `OmniModules` через `omni_db::open_omni()`;
- хранит файлы в `modules/installed/`, временные файлы в `modules/staging/`, состояние сборки в `modules/state/`;
- запускает фоновую пересборку через `systemd-run`, а при неудаче пробует отдельный процесс `sh`;
- пишет build log и статусные файлы;
- предоставляет список модулей, загрузку/обновление, статус и удаление.

### API менеджера

| Запрос | Назначение |
|---|---|
| `GET /api/modules` или `GET /api/modules/list` | Список системных и установленных модулей |
| `POST /api/modules/upload/<id>` | ZIP в теле запроса; установка или обновление по ID |
| `GET /api/modules/status/<id>` | Статус и журнал сборки |
| `POST /api/modules/delete/<id>` | Удаление исходников и запуск пересборки без модуля |
| `GET /module-assets/<id>/<path>` | Отдача статического ресурса модуля; отдельный route в `main.rs` |

Upload API ограничивает тело 100 MiB; обычные API тела ограничены 10 MiB. ID системных модулей зарезервированы и не могут быть заменены сторонним ZIP через upload.

### Обновление модуля с тем же ID

Если `modules/installed/<id>` уже существует, менеджер временно переименовывает старый каталог в `modules/staging/<id>.old`, размещает новые исходники, обновляет запись БД и запускает сборку. В ответе API `updated` показывает, существовал ли каталог до загрузки. После успешной сборки скрипт удаляет backup-каталог. При ошибке сборки действующий бинарник не заменяется, но новые исходники остаются в каталоге установки для исправления.

**Осторожно:** каталог исходников заменяется до завершения компиляции. При ошибке сборки старый исходный каталог автоматически не восстанавливается в текущем build script, хотя работающий бинарник остаётся прежним. Кроме того, после удаления модуля выполняется пересборка, но поведение при ошибке сборки нужно учитывать: исходники уже удалены.

### Системный список

`SYSTEM_MODULES` перечисляет `core`, `cors`, `security`, `dns`, `tunnel`, `db`, `ikev2`, `ssl`, `miraj`, `vpn`, `server`. Это метаданные для админки, а не динамическая загрузка crates. Эти crates по-прежнему компилируются обычным Cargo workspace.

## 6. База данных `db`

`db/src/lib.rs` реализует SQLite-конфигурацию, подключение, создание системной схемы и операции с данными. `db/src/dispatch.rs` содержит HTTP dispatch для DB и tunnel API.

В `init_system_schema` создаются таблицы `config`, `OmniModules`, `OmniVPN`, `OmniDNS`, `OmniProxy`, `OmniMetrics`, `OmniSsl`, `OmniTunnel`. Модульный менеджер обеспечивает совместимость старой `OmniModules`, добавляя при необходимости поля `description`, `admin_entry`, `kind`.

| Таблица | Назначение |
|---|---|
| `config` | Ключ-значение конфигурации |
| `OmniModules` | ID, имя, версия, статус, пути, build log, enabled и метаданные UI/типа |
| `OmniVPN` | Параметры VPN-конфигурации |
| `OmniDNS` | DNS-записи/зоны в системной БД |
| `OmniProxy` | Proxy host/path/enabled |
| `OmniMetrics` | Временные метки и значения метрик |
| `OmniSsl` | Сертификаты и ключевой материал по доменам |
| `OmniTunnel` | Настройки/учётные данные туннелей |

Путь БД задаётся переменными `OMNIRS_DB_*`, включая `OMNIRS_DB_DIR`, либо значением по умолчанию, реализованным в DB crate. Файлы `-wal` и `-shm` являются sidecar-файлами SQLite и не должны вручную редактироваться.

## 7. Workspace crates

### `core` — `omni-core`
`core/src/lib.rs` экспортирует криптографический модуль; `core/src/crypto.rs` содержит общие криптографические операции, включая X25519/Curve25519. В новой версии `core/src/module.rs` отсутствует: старый C ABI контракт для `.so` удалён.

### `cors` — `omni-cors`
`cors/src/lib.rs` содержит общие CORS-хелперы. Применение middleware с `AppState` находится в `server/src/omni_mw.rs`.

### `security` — `omni-security`
`security/src/lib.rs` содержит IPS-подсистему, анализ событий/журналов, правила угроз и системные блокировки. Реальные пороги и команды следует проверять в исходнике; функциональность зависит от ОС и прав процесса.

### `dns` — `omni-dns`
`dns/src/lib.rs` реализует DNS-типы, запросы, записи и сетевые DNS-сервисы. DNS admin API находится в `server/src/api/handlers/dns_h.rs`.

### `db` — `omni-db`
SQLite, конфигурация, системные таблицы, SQL/DB API и tunnel API dispatch. Основные файлы: `lib.rs`, `dispatch.rs`.

### `ikev2` — `omni-ikev2`
`ikev2/src/lib.rs` содержит реализацию IKEv2/IPsec, конфигурацию, сетевой обмен и API dispatch.

### `ssl` — `omni-ssl`
`ssl/src/lib.rs` управляет TLS-сертификатами, rustls resolver, ACME challenges и циклом обновления сертификатов. Используется HTTPS/QUIC listener и API сертификатов.

### `miraj` — `omni-miraj`
`miraj/src/lib.rs` содержит QUIC/Hysteria-подобную подсистему, аутентификацию, потоки и запуск сервера.

### `tunnel` — `omni-tunnel`
- `lib.rs` — публичные типы и конфигурация;
- `executor.rs` — исполнение задач;
- `protocols.rs` — протокольные/network helpers;
- `restrictions.rs` — ограничения разрешённых целей;
- `server.rs` — серверный lifecycle и подключения;
- `somark.rs` — socket mark;
- `tls_reloader.rs` — TLS reload;
- `transport.rs` — транспортные соединения.

### `vpn` — `omni-vpn`
- `lib.rs` — VPN state, запуск/остановка, клиенты, метрики и API;
- `db.rs` — сохранение параметров и клиентов;
- `iface.rs` — сетевой интерфейс;
- `netlink.rs` — Generic Netlink/WireGuard;
- `uapi.rs` — атрибуты и флаги WireGuard UAPI.

VPN/IKEv2/firewall операции требуют соответствующей поддержки Linux и системных разрешений.

## 8. Основной сервер `server`

### `server/src/main.rs`
Главная точка входа. Содержит конфигурацию и состояние приложения, HTTP routing, static serving, reverse proxy, health/metrics, TLS/HTTPS, QUIC/HTTP/3, ACME routing и запуск DNS, SSL, VPN, IKEv2, Miraj, tunnel и security. В этой версии объявляет `generated_modules` через `include!(concat!(env!("OUT_DIR"), "/generated_modules.rs"))`, вызывает `generated_modules::start(state.clone()).await` и регистрирует `/module-assets/{*name}`.

### `server/src/api/mod.rs`
Определяет `ApiCtx` и центральный dispatch. Размер тела upload — до 100 MiB, для прочих endpoint — до 10 MiB. Сначала выполняются dispatch-ветви DB/tunnel/VPN/certs/IKEv2/Miraj/modules, затем `generated_modules::dispatch(ctx.clone())`, далее обычные endpoint-обработчики.

### `server/src/api/auth.rs`
Вход/выход, проверка токена/сессии, whoami, управление сессиями и связанные административные endpoints.

### `server/src/api/helpers.rs`
Общие функции JSON/text/file responses, ошибки, query/form/body helpers и преобразование параметров.

### `server/src/api/sess.rs`
Сессионное и другое runtime-состояние в памяти процесса (не самостоятельное постоянное хранилище SQLite).

### `server/src/api/handlers/`

| Файл | Область |
|---|---|
| `mod.rs` | Экспорт обработчиков |
| `cache.rs` | Кэш и статистика кэша |
| `dns_h.rs` | DNS admin API |
| `files.rs` | Файловые операции в разрешённом root |
| `misc.rs` | Общие вспомогательные endpoints |
| `proxy.rs` | Proxy/backends/virtual hosts и связанные настройки |
| `settings.rs` | Runtime-настройки и параметры безопасности |
| `system.rs` | Конфигурация, процессы, порты, disk, firewall и системные действия |
| `ui.rs` | Настройки UI, вкладки, feature flags и уведомления |

### `server/src/omni_mw.rs`
Middleware доступа: журналирование запросов, request ID, security headers, метрики и CORS.

### `server/src/static_assets.rs`
Встраивает базовые HTML/JS/CSS через `include_str!`; изменение этих файлов требует пересборки, если файл обслуживается из embedded assets. UI-ресурсы устанавливаемых модулей, напротив, читаются с диска через `/module-assets/`.

### `server/src/installer.rs`
Отдельный Rust CLI-установщик с командами/меню установки, управления systemd, статуса и пароля. Это отдельный путь от `ritual.sh`; Bash-файл не изменён. Конкретные детали поведения определяются исходником.

## 9. Админка и web terminal

### `server/static/admin/`

| Файл | Назначение |
|---|---|
| `admin.html` | HTML-оболочка админки |
| `app.js` | Инициализация, общие UI helpers и навигация |
| `dashboard.js` | Обзор/состояние |
| `db.js` | DB UI |
| `dns.js` | DNS UI |
| `files.js` | Файловый менеджер |
| `modules.js` | Системные/устанавливаемые модули, ZIP upload/update/delete и открытие admin entry; старые кнопки enable/disable и отдельного управления `.so` отсутствуют |
| `proxy.js` | Reverse proxy UI |
| `settings.js` | Общие настройки |
| `ssl.js` | TLS/ACME UI |
| `vpn.js` | VPN UI |
| `style.css` | Стили |

### `server/static/terminal/`
`terminal.html` — оболочка; `app.js` — инициализация; `api.js` — API вызовы; `state.js` — клиентское состояние; `console.js` — консольный вывод; `views.js` — представления; `ui.js` — UI-события; `utils.js` — helpers; `hack.js` и `leak.js` — дополнительные визуальные/интерактивные части; `style.css` — стили. Это веб-терминал проекта, и его полномочия определяются серверным terminal API, а не самим фактом наличия терминального UI.

## 10. Middleware и потоки запросов

### Обычный запрос

```text
Client -> Axum Router (main.rs)
       -> access_log / CORS / compression / timeout
       -> API dispatcher, proxy, static assets, health/metrics или ACME logic
```

### API

```text
/api/* -> auth/session pipeline
       -> ранние DB/tunnel/VPN/certs/IKEv2/Miraj/modules dispatchers
       -> generated_modules::dispatch(ApiCtx)
       -> стандартные API handlers
```

Пользовательский source-модуль не должен считать, что он перехватит endpoint, уже обработанный ранней ветвью dispatch. Пользовательский модуль также не является sandbox: это Rust-код, скомпилированный внутрь процесса сервера, с полномочиями процесса OmniRS.

### Установка/обновление ZIP

```text
Admin UI -> POST /api/modules/upload/<id>
         -> проверка ID + безопасная распаковка во временный каталог
         -> чтение module.toml и проверка entry/admin_entry
         -> перенос исходников в modules/installed/<id>
         -> upsert OmniModules
         -> фоновый cargo build --release -p omni-server
         -> копирование нового target/release/OmniRS
         -> замена исполняемого файла и systemctl restart omnirs.service
```

Сборка запускается через `systemd-run --no-block`, а если это не удаётся — отдельным фоновым процессом. Состояния пишутся в `modules/state/<id>.status`, журнал — в `modules/state/<id>.log`.

### Важные ограничения lifecycle

- Запуск фоновой сборки зависит от наличия Cargo, исходников workspace, прав доступа и systemd/возможности запуска фонового процесса.
- Build script собирает `cargo build --release -p omni-server` и ожидает `target/release/OmniRS`.
- При неудачной сборке действующий бинарник не копируется поверх, но новые исходники уже могут находиться в `modules/installed/<id>`.
- При обновлении старый каталог перемещается в staging backup; текущий build script удаляет backup после успешной сборки. При ошибке сборки автоматический rollback исходников не реализован.
- Удаление исходников требует пересборки, иначе запущенный/сохранённый бинарник может содержать код предыдущей версии до успешной замены.
- В коде нет изоляции source-модулей от процесса сервера.

## 11. Конфигурация и переменные окружения

Основная runtime-конфигурация описана в `server/src/main.rs`; DB параметры — в `db/src/lib.rs` и соответствующих DB helpers. В разных компонентах используются `OMNIRS_*` переменные. Для полного списка нужно сверять текущие обращения к `std::env::var`/`env::var` в исходниках: этот документ перечисляет архитектуру, а не исчерпывающий каталог каждого environment key.

## 12. Установщики

- `ritual.sh` — исходный Bash-установщик в корне; в этом изменении он не модифицировался.
- `server/src/installer.rs` — CLI-установщик, встроенный в бинарник. Он не является менеджером source-модулей; за ZIP-модули отвечает `server/src/modules.rs`.
- Фоновая пересборка source-модулей — отдельный процесс, который создаётся `modules.rs` и использует `systemd-run` или fallback `sh`.

## 13. Внешние зависимости по назначению

Точные зависимости указаны в корневом `Cargo.toml` и в `*/Cargo.toml`. Основные группы:

| Область | Примеры |
|---|---|
| Async runtime | Tokio, tokio-util, tokio-stream, futures-util |
| HTTP | Axum, Hyper, Tower, tower-http, axum-server |
| HTTP/3 / QUIC | Quinn, h3, h3-quinn, h3-axum, WebTransport crates |
| TLS / ACME | rustls, tokio-rustls, rcgen, x509-parser, p256/p384/p521, rsa |
| База данных | rusqlite (bundled), bb8, moka |
| ZIP и манифесты | zip, toml, serde, serde_json, serde_yaml |
| Crypto / hashes | x25519-dalek, aes-gcm, sha2, sha1, hmac, blake2, base64 |
| Networking/system | socket2, ipnet, hickory crates, libc, nix |

Старая зависимость `libloading` и старый C ABI module contract в обновлённом проекте отсутствуют.

## 14. Где менять функциональность

| Задача | Основное место |
|---|---|
| Основной runtime, listeners, proxy | `server/src/main.rs` |
| Генерация реестра встроенных source-модулей | `server/build.rs` |
| Установка, обновление, список, удаление ZIP | `server/src/modules.rs` |
| Контракт устанавливаемого модуля | `MODULES.md`, `examples/module-template/` |
| API dispatch и ApiCtx | `server/src/api/mod.rs` |
| Авторизация | `server/src/api/auth.rs` |
| Схема и DB API | `db/src/lib.rs`, `db/src/dispatch.rs` |
| DNS | `dns/src/lib.rs`, `server/src/api/handlers/dns_h.rs` |
| TLS/ACME | `ssl/src/lib.rs` |
| VPN | `vpn/src/` |
| IKEv2 | `ikev2/src/lib.rs` |
| QUIC/Miraj | `miraj/src/lib.rs` |
| Туннели | `tunnel/src/` |
| IPS/security | `security/src/lib.rs` |
| CORS | `cors/src/lib.rs`, `server/src/omni_mw.rs` |
| Админка | `server/static/admin/` |
| Web terminal | `server/static/terminal/`, `server/src/api/mod.rs` |
| Rust CLI installer | `server/src/installer.rs` |
| Bash installer | `ritual.sh` |

## 15. Проверка и сборка

Команды из корня workspace:

```bash
cargo check --workspace
cargo build -p omni-server
cargo build -p omni-server --release
```

Бинарный target называется `OmniRS`. Для проверки устанавливаемых модулей необходимо, чтобы их исходники уже лежали в `modules/installed/<id>/` до запуска Cargo, поскольку build.rs обнаруживает их во время сборки.

## 16. Итоговая модель

- **Cargo workspace** компилирует встроенные crates и основной сервер.
- **`server/build.rs`** включает source-модули из `modules/installed/` в compile-time Rust registry.
- **`server/src/modules.rs`** управляет ZIP, манифестами, БД, обновлением, удалением и фоновым rebuild.
- **`server/src/main.rs`** запускает установленные модули и отдаёт их admin assets.
- **`server/src/api/mod.rs`** направляет API-контекст в пользовательские `dispatch()` функции.
- **`OmniModules`** хранит метаданные/состояние, но сама по себе не подключает Rust-код.
- **`.so` / `libloading` / `native_modules.rs`** в этой версии не используются.
- **`ritual.sh`** остаётся отдельным Bash-установщиком.
