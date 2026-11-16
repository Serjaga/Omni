# Полноценные Rust-модули OmniRS

ZIP-пакет должен иметь такую структуру:

```text
my-module.zip
├── module.toml
├── src/
│   └── module.rs
└── admin/                 # необязательно
    ├── index.js           # если указан admin_entry
    └── style.css
```

`module.toml`:

```toml
id = "my_module"
name = "My module"
version = "1.0.0"
description = "Описание модуля"
kind = "source"
entry = "src/installer.rs" # главный Rust-файл; по умолчанию src/module.rs
admin_entry = "admin/index.js" # необязательно
```

ID в `module.toml` обязан совпадать с ID, введённым при загрузке ZIP.

Rust-файл, указанный в `entry` (например `src/installer.rs`), подключается build.rs как полноценный Rust-модуль в crate основного бинарника OmniRS. Он обязан предоставить две функции:

```rust
pub async fn start(state: crate::SharedState) {
    // Запуск службы, фоновой задачи или инициализация модуля.
}

pub async fn dispatch(ctx: crate::api::ApiCtx)
    -> Option<axum::response::Response<axum::body::Body>>
{
    if ctx.endpoint == "my-module/health" {
        return Some(axum::response::Response::new(
            axum::body::Body::from("ok")
        ));
    }
    None
}
```

`start` вызывается при запуске OmniRS. `dispatch` вызывается внутри защищённого `/api/*` pipeline после проверки административной авторизации. Поэтому пользовательские API-маршруты модулей не обходят проверку токена/сессии. `ApiCtx` содержит `state`, `method`, `endpoint`, `query`, `headers`, `body` и `client_ip`.

В `src/` разрешены дополнительные `.rs`-файлы. Для `mod handlers;` соблюдай стандартное правило Rust: дочерние файлы размещаются в подкаталоге с именем главного файла (например, для `src/installer.rs` — `src/installer/handlers.rs`). `start` может запускать фоновые задачи через `tokio::spawn` и инициализировать собственные службы.

Административный `admin/index.js` должен экспортировать `mount(container)`, например:

```js
export function mount(container) {
  container.innerHTML = '<h3>Мой модуль</h3>';
}
```

Установка одноимённого ID заменяет исходники существующего модуля и запускает новую сборку. Модули компилируются в основной бинарник, поэтому требуется Cargo и доступ к зависимостям проекта. После успешной сборки установщик заменяет исполняемый файл и запрашивает `systemctl restart omnirs.service`.

Удаление исходников из каталога запускает пересборку основного бинарника; до её завершения уже работающий процесс продолжает использовать предыдущую сборку. ZIP не является песочницей: код модуля получает те же полномочия, что и сам сервер. Устанавливайте только доверенные пакеты.

## Ограничение текущей версии

Этот механизм предназначен для Rust source modules. Динамические `.so`-плагины в этой сборке не используются; `native_modules.rs` и `libloading` удалены. Rust-модуль должен реализовать контракт `start` и `dispatch`, описанный выше.
