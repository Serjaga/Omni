#!/usr/bin/env bash
set -u

# ═════════════════════════════════════════════════════════════════════════════
# ИСПРАВЛЕНИЯ (v2):
#   1. ensure_service() в конце останавливает сервис + reset-failed, чтобы
#      systemd не дёргал restart-loop во время 21-минутной сборки
#      (было 4787 рестартов подряд, exit-code 203/EXEC).
#   2. В unit добавлен ExecStartPre=/bin/test -x (чистый старт, без 203),
#      RestartSec=3 и StartLimit* — защита от бесконечного restart-шторма.
#   3. После копирования бинарника — sync + явная проверка test -x.
#   4. Шаг 5: не `restart`, а `reset-failed` + `start` + цикл ожидания
#      активности до 20с; если не поднялся — логи и exit 1.
# ═════════════════════════════════════════════════════════════════════════════

# ═════════════════════════════════════════════════════════════════════════════
# CLI-флаги
# ═════════════════════════════════════════════════════════════════════════════
NO_CLEAR=0
SKIP_BUILD=0
ASSUME_YES=0
NO_DETACH=0

for arg in "$@"; do
case "$arg" in
--no-clear)   NO_CLEAR=1;;
--skip-build) SKIP_BUILD=1;;
--yes|-y)     ASSUME_YES=1;;
--no-detach)  NO_DETACH=1;;
-h|--help)
cat <<'EOF'
Usage: ritual.sh [OPTIONS]

Опции:
--no-clear    не очищать экран
--skip-build  пропустить сборку (только рестарт)
--yes, -y     без меню (сразу Install; пароль по умолчанию 16121993)
--no-detach   запустить установку на переднем плане (не уходить в фон)
-h, --help    справка
EOF
exit 0
;;
*) echo "❌ неизвестный флаг: $arg (см. --help)"; exit 1;;
esac
done

# ═════════════════════════════════════════════════════════════════════════════
# Утилиты времени
# ═════════════════════════════════════════════════════════════════════════════
elapsed() { echo "$((SECONDS - $1))"; }
fmt_time() {
local s=$1 h m
if [ "$s" -ge 3600 ]; then
h=$((s/3600)); s=$((s%3600))
m=$((s/60));   s=$((s%60))
printf '%dh %02dm %02ds' "$h" "$m" "$s"
elif [ "$s" -ge 60 ]; then
printf '%dm %02ds' $((s/60)) $((s%60))
else
printf '%ds' "$s"
fi
}

# ═════════════════════════════════════════════════════════════════════════════
# Секундомер в заголовке терминала
# ═════════════════════════════════════════════════════════════════════════════
STOPWATCH_START=$SECONDS
SW_ENABLED=0
[ -t 1 ] && [ "${TERM:-dumb}" != "dumb" ] && SW_ENABLED=1

SW_TTY=/dev/tty
[ -w "$SW_TTY" ] || SW_TTY=/dev/stderr

STOPWATCH_PID=""
sw_tick() {
while :; do
local el=$((SECONDS - STOPWATCH_START))
printf '\033]0;⏱ %s — OmniRS ritual\007' "$(fmt_time $el)" > "$SW_TTY"
sleep 1
done
}
sw_start() {
[ "$SW_ENABLED" = "1" ] || return 0
[ -n "$STOPWATCH_PID" ] && return 0
STOPWATCH_START=${1:-$SECONDS}
sw_tick &
STOPWATCH_PID=$!
}
sw_stop() {
if [ -n "$STOPWATCH_PID" ]; then
kill "$STOPWATCH_PID" || true
wait "$STOPWATCH_PID" || true
STOPWATCH_PID=""
[ "$SW_ENABLED" = "1" ] && \
printf '\033]0;✓ OmniRS ritual — %s\007' \
"$(fmt_time $((SECONDS - STOPWATCH_START)))" > "$SW_TTY"
fi
}

# ═════════════════════════════════════════════════════════════════════════════
# LIVE-BAR: рисуется на последней строке терминала
# ═════════════════════════════════════════════════════════════════════════════
LIVE_BAR_PID=""
LIVE_BAR_PCT=0
LIVE_BAR_LABEL=""

_live_bar_render() {
local pct=$LIVE_BAR_PCT label=$LIVE_BAR_LABEL w=32 f i bar="" el
f=$(( pct * w / 100 ))
[ "$f" -gt "$w" ] && f=$w
[ "$f" -lt 0 ]   && f=0
for ((i=0; i<f; i++)); do bar+="="; done
[ "$f" -lt "$w" ] && bar+=">"
while [ ${#bar} -lt $w ]; do bar+=" "; done
el=$((SECONDS - STOPWATCH_START))
local rows=$(tput lines 2>/dev/null || echo 24)
printf '\e7\e[%d;1H\e[K  [%s] %3d%%  %s  ⏱ %s\e8' \
"$rows" "$bar" "$pct" "$label" "$(fmt_time $el)"
}
live_bar_loop() {
while :; do
sleep 1
_live_bar_render
done
}
live_bar_start() {
LIVE_BAR_PCT=$1
LIVE_BAR_LABEL=${2:-}
[ -n "$LIVE_BAR_PID" ] && return
[ -t 2 ] || return
[ "${TERM:-dumb}" = "dumb" ] && return
_live_bar_render
live_bar_loop &
LIVE_BAR_PID=$!
}
live_bar_stop() {
if [ -n "$LIVE_BAR_PID" ]; then
kill "$LIVE_BAR_PID" || true
wait "$LIVE_BAR_PID" || true
LIVE_BAR_PID=""
if [ -t 2 ] && [ "${TERM:-dumb}" != "dumb" ]; then
local rows=$(tput lines 2>/dev/null || echo 24)
printf '\e7\e[%d;1H\e[K\e8' "$rows"
fi
fi
}

# ═════════════════════════════════════════════════════════════════════════════
# LOG-BAR: обычная строка истории (для итога этапа)
# ═════════════════════════════════════════════════════════════════════════════
log_bar() {
local pct=$1 label=${2:-} w=32 f i bar="" el
f=$(( pct * w / 100 ))
[ "$f" -gt "$w" ] && f=$w
[ "$f" -lt 0 ]   && f=0
for ((i=0; i<f; i++)); do bar+="="; done
[ "$f" -lt "$w" ] && bar+=">"
while [ ${#bar} -lt $w ]; do bar+=" "; done
el=$((SECONDS - STOPWATCH_START))
printf '  [%s] %3d%%  %s  ⏱ %s\n' "$bar" "$pct" "$label" "$(fmt_time $el)"
}

trap 'live_bar_stop; sw_stop' EXIT

# ═════════════════════════════════════════════════════════════════════════════
# systemd unit template  (v2 — с защитой от restart-шторма)
#   ★ ExecStartPre проверяет, что бинарник существует и исполняемый
#     (иначе чистый сбой, а не 203/EXEC).
#   ★ StartLimitIntervalSec + StartLimitBurst: после 5 провалов за 10 сек
#     systemd ОСТАНАВЛИВАЕТ перезапуски (вместо бесконечного цикла).
#   ★ RestartSec=3 — передышка между рестартами.
# ═════════════════════════════════════════════════════════════════════════════
read -r -d '' SERVICE_UNIT <<'EOF'
[Unit]
Description=OmniRS
After=network.target
StartLimitIntervalSec=10
StartLimitBurst=5

[Service]
Type=simple
WorkingDirectory=/root/OmniRS
Environment=OMNIRS_DB_DIR=/root/OmniRS/db
Environment=OMNIRS_AUDIT_LOG=/var/log/omnirs/audit.log
ExecStartPre=/bin/mkdir -p /root/OmniRS/db
ExecStartPre=/bin/test -x /root/OmniRS/OmniRS
ExecStart=/root/OmniRS/OmniRS
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# ═════════════════════════════════════════════════════════════════════════════
# Alias 'ritual' в ~/.bashrc
# ═════════════════════════════════════════════════════════════════════════════
ALIAS_MARK_START="# >>> omnirs ritual >>>"
ALIAS_MARK_END="# <<< omnirs ritual <<<"

install_alias() {
local rc="$HOME/.bashrc"

if grep -qF "$ALIAS_MARK_START" "$rc"; then
    echo "  ℹ  команда 'ritual' уже установлена в $rc"
    return 0
fi

echo "  🔧 Установка команды 'ritual' в $rc..."
[ -f "$rc" ] && cp "$rc" "$rc.bak.$(date +%s)" || true
cat >> "$rc" <<'EOF'
# >>> omnirs ritual >>>
ritual() { ~/OmniRS/ritual.sh "$@"; }
# <<< omnirs ritual <<<
EOF
echo "    ✓ добавлена"
}

# ═════════════════════════════════════════════════════════════════════════════
# omnirs.service
#   v2: в конце — ОСТАНОВКА сервиса + reset-failed, чтобы во время долгой
#   сборки (21 мин) systemd не крутил restart-loop.
# ═════════════════════════════════════════════════════════════════════════════
ensure_service() {
local unit=/etc/systemd/system/omnirs.service

if [ -f "$unit" ]; then
    echo "  ℹ  $unit уже на месте"
    # ── миграция старого unit-а ──────────────────────────────────────────
    if sudo grep -q "OMNIRS_DB_PATH" "$unit" 2>/dev/null; then
        echo "  🔧 unit содержит устаревший OMNIRS_DB_PATH=/root/OmniRS/data → обновляю"
        sudo cp "$unit" "$unit.bak.$(date +%s)" || true
        sudo sed -i 's|OMNIRS_DB_PATH=/root/OmniRS/data|OMNIRS_DB_DIR=/root/OmniRS/db|g' "$unit"
        sudo sed -i 's|/root/OmniRS/data|/root/OmniRS/db|g' "$unit"
    fi

    # Всегда приводим ExecStart к новому расположению бинарника.
    if ! sudo grep -qF 'ExecStart=/root/OmniRS/OmniRS' "$unit"; then
        echo "  🔧 Обновляю ExecStart на /root/OmniRS/OmniRS"
        sudo cp "$unit" "$unit.bak.$(date +%s)" || true
        if sudo grep -q '^ExecStart=' "$unit"; then
            sudo sed -i 's|^ExecStart=.*|ExecStart=/root/OmniRS/OmniRS|' "$unit"
        else
            echo "  ⚠  В unit отсутствует ExecStart; заменяю unit целиком"
            printf '%s\n' "$SERVICE_UNIT" | sudo tee "$unit" >/dev/null
        fi
    fi

    sudo systemctl daemon-reload
    sudo systemctl enable omnirs.service >/dev/null || true
else
    echo "  🔧 Установка $unit..."
    printf '%s\n' "$SERVICE_UNIT" | sudo tee "$unit" >/dev/null

    for dropin in override.conf trace.conf; do
        if [ -f "/etc/systemd/system/omnirs.service.d/$dropin" ]; then
            echo "    🗑  удаляю остаточный drop-in: $dropin"
            sudo rm -f "/etc/systemd/system/omnirs.service.d/$dropin"
        fi
    done
    sudo rmdir /etc/systemd/system/omnirs.service.d || true

    sudo systemctl daemon-reload
    sudo systemctl enable omnirs.service >/dev/null || true
    echo "    ✓ unit установлен, enable"
fi

# ── v2: гасим сервис и сбрасываем счётчик провалов перед сборкой ──
echo "  ⏹  Останавливаю omnirs.service на время сборки (без restart-loop)"
sudo systemctl stop omnirs.service 2>/dev/null || true
sudo systemctl reset-failed omnirs.service 2>/dev/null || true
}

# ═════════════════════════════════════════════════════════════════════════════
# Директории
# ═════════════════════════════════════════════════════════════════════════════
ensure_dirs() {
local dirs=( /root/OmniRS/db )
local created=0
for d in "${dirs[@]}"; do
if [ ! -d "$d" ]; then
sudo mkdir -p "$d"
created=1
fi
done
if [ "$created" = "1" ]; then
echo "    ✓ директории созданы"
else
echo "  ℹ  директории уже на месте"
fi
}

# ═════════════════════════════════════════════════════════════════════════════
# Swap — идемпотентная подготовка
# ═════════════════════════════════════════════════════════════════════════════
ensure_swap() {
    local SWAP_TARGET_MB=2048
    local SWAP_TARGET_BYTES=$(( SWAP_TARGET_MB * 1024 * 1024 ))

    local mem_mb=0
    if [ -r /proc/meminfo ]; then
        mem_mb=$(awk '/^MemTotal:/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)
    fi

    local cur_bytes=0
    if [ -f /swapfile ]; then
        cur_bytes=$(stat -c '%s' /swapfile 2>/dev/null || echo 0)
    fi

    local swap_active=0
    if swapon --show --noheadings 2>/dev/null | awk '{print $1}' | grep -qx '/swapfile'; then
        swap_active=1
    fi

    if [ "$swap_active" = "1" ] && ! grep -qE '^\s*/swapfile\s+' /etc/fstab 2>/dev/null; then
        echo "  🔧 /swapfile активен, но НЕТ в /etc/fstab → добавляю"
        echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab >/dev/null
    fi

    local cur_sw
    cur_sw=$(sysctl -n vm.swappiness 2>/dev/null || echo 60)
    if [ "${cur_sw:-60}" -ne 10 ]; then
        sudo sysctl -q -w vm.swappiness=10 2>/dev/null || true
        if ! grep -qF 'vm.swappiness' /etc/sysctl.d/99-swap.conf 2>/dev/null; then
            echo 'vm.swappiness=10' | sudo tee /etc/sysctl.d/99-swap.conf >/dev/null
        fi
        echo "    ✓ vm.swappiness = 10 (было $cur_sw)"
    fi

    if [ "$swap_active" = "1" ] && [ "$cur_bytes" = "$SWAP_TARGET_BYTES" ]; then
        echo "  ℹ  swap уже ${SWAP_TARGET_MB}MB — ничего не меняю"
        swapon --show --noheadings | sed 's/^/    /'
        return 0
    fi

    if [ "$swap_active" = "1" ]; then
        echo "  🔧 swap активен ($((cur_bytes / 1024 / 1024))MB) — пересоздаю в ${SWAP_TARGET_MB}MB"
        sudo swapoff /swapfile
    fi

    if [ -f /swapfile ]; then
        sudo rm -f /swapfile
    fi

    echo "  🔧 Создаю /swapfile ${SWAP_TARGET_MB}MB (RAM=${mem_mb}MB)..."

    if ! sudo fallocate -l "${SWAP_TARGET_MB}M" /swapfile; then
        echo "    fallocate не сработал → dd..."
        if ! sudo dd if=/dev/zero of=/swapfile bs=1M count="$SWAP_TARGET_MB" status=progress; then
            echo "    ⚠  dd провалился — swap не создан"
            sudo rm -f /swapfile
            return 0
        fi
    fi

    sudo chmod 600 /swapfile
    if ! sudo mkswap /swapfile; then
        echo "    ⚠  mkswap провалился — swap не создан"
        sudo rm -f /swapfile
        return 0
    fi

    if ! sudo swapon /swapfile; then
        echo "    ⚠  swapon провалился — swap не активирован"
        return 0
    fi
    echo "    ✓ swap ${SWAP_TARGET_MB}MB активирован"

    if ! grep -qE '^\s*/swapfile\s+' /etc/fstab 2>/dev/null; then
        echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab >/dev/null
    fi

    echo "    итог:"
    swapon --show --noheadings | sed 's/^/      /'
}

# ═════════════════════════════════════════════════════════════════════════════
# Проверка: первая установка или апгрейд
# ═════════════════════════════════════════════════════════════════════════════
DB_IS_FRESH=0
ADMIN_PASSWORD=""
DETECTED_IP=""

detect_fresh_db() {
    local db_file="/root/OmniRS/db/OmniDB"
    local file_exists=0
    if [ "$(id -u)" = "0" ]; then
        [ -f "$db_file" ] && file_exists=1
    else
        sudo test -f "$db_file" 2>/dev/null && file_exists=1
    fi
    if [ "$file_exists" = "0" ]; then
        DB_IS_FRESH=1
        return
    fi
    local token
    token=$(sudo sqlite3 "$db_file" \
        "SELECT value FROM config WHERE key='admin_token';" 2>/dev/null)
    if [ -z "$token" ]; then
        echo "  ⚠  БД есть, но admin_token пустой → считаю как fresh"
        DB_IS_FRESH=1
    else
        DB_IS_FRESH=0
    fi
}

# ═════════════════════════════════════════════════════════════════════════════
# Первичный конфиг
# ═════════════════════════════════════════════════════════════════════════════
ensure_initial_config() {
detect_fresh_db

if [ "$DB_IS_FRESH" = "0" ]; then
    echo "  ℹ  БД уже существует — пароль/IP не перезаписываю"
    echo "     (изменить пароль: POST /api/db/config {\"admin_token\":\"...\"})"
    echo "     (полный сброс:      sudo rm -rf /root/OmniRS/db && ritual.sh)"
    return 0
fi

echo "  🆕 Первая установка — настраиваю пароль администратора и IP"

local pw_input=""
if [ "$ASSUME_YES" = "1" ]; then
    pw_input="16121993"
    echo "    ⏭  --yes: пароль = 16121993 (по умолчанию)"
elif [ -t 0 ]; then
    printf "  🔑 Пароль администратора [Enter = 16121993]: "
    read -r pw_input || true
else
    pw_input="16121993"
    echo "    ⏭  не-TTY: пароль = 16121993 (по умолчанию)"
fi
[ -z "$pw_input" ] && pw_input="16121993"
ADMIN_PASSWORD="$pw_input"
if [ "$pw_input" = "16121993" ]; then
    echo "    → пароль: по умолчанию (16121993)"
else
    echo "    → пароль: задан пользователем"
fi

local detected=""
detected=$(curl -s --max-time 3 https://ifconfig.me 2>/dev/null || true)
[ -z "$detected" ] && detected=$(hostname -I 2>/dev/null | awk '{print $1}')
if [ -n "$detected" ] && ! [[ "$detected" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    detected=""
fi

local ip_input=""
if [ "$ASSUME_YES" = "1" ]; then
    if [ -n "$detected" ]; then ip_input="$detected"; else ip_input="0.0.0.0"; fi
    echo "    ⏭  --yes: IP = $ip_input"
elif [ -t 0 ]; then
    local prompt="  🌐 Публичный IP"
    [ -n "$detected" ] && prompt="$prompt [$detected]"
    printf "%s (Enter = %s): " "$prompt" "${detected:-0.0.0.0}"
    read -r ip_input || true
else
    [ -n "$detected" ] && ip_input="$detected" || ip_input="0.0.0.0"
    echo "    ⏭  не-TTY: IP = $ip_input"
fi

if [ -z "$ip_input" ]; then
    if [ -n "$detected" ]; then
        ip_input="$detected"
        echo "    → автоопределено: $ip_input"
    else
        ip_input="0.0.0.0"
        echo "    → оставлено 0.0.0.0"
    fi
fi

if [[ "$ip_input" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    local o valid=1
    local IFS='.'
    for o in $ip_input; do
        [ "$o" -gt 255 ] && { valid=0; break; }
    done
    if [ "$valid" = "0" ]; then
        echo "    ⚠  октет > 255 в '$ip_input' → 0.0.0.0"
        ip_input="0.0.0.0"
    fi
else
    echo "    ⚠  некорректный IP '$ip_input' → 0.0.0.0"
    ip_input="0.0.0.0"
fi
DETECTED_IP="$ip_input"
echo "    → address: $DETECTED_IP"
}

# ═════════════════════════════════════════════════════════════════════════════
# Seed DB — бинарник из /root/OmniRS/OmniRS
# ═════════════════════════════════════════════════════════════════════════════
seed_db_if_fresh() {
if [ -z "${ADMIN_PASSWORD:-}" ]; then
    echo "  ⏭  апгрейд — БД уже настроена, seed пропущен"
    return 0
fi

local binary="/root/OmniRS/OmniRS"
if [ ! -x "$binary" ]; then
    echo "  ⚠  бинарь не найден или не исполняемый ($binary) — seed пропущен"
    return 0
fi

echo "  🌱 Инициализация БД (admin_token, address)..."
sudo mkdir -p /root/OmniRS/db

local pw_q ip_q bin_q
pw_q=$(printf '%q' "$ADMIN_PASSWORD")
ip_q=$(printf '%q' "${DETECTED_IP:-0.0.0.0}")
bin_q=$(printf '%q' "$binary")

local seed_log=/tmp/omnirs-seed.$$.log
local rc=0
sudo bash -c "cd /root/OmniRS && \
    OMNIRS_DB_DIR=/root/OmniRS/db \
    OMNIRS_ADMIN_TOKEN=$pw_q \
    OMNIRS_ADDR=$ip_q \
    $bin_q config test" > "$seed_log" 2>&1 || rc=$?

if [ "$rc" = "0" ]; then
    echo "    ✓ БД инициализирована (admin_token, address)"
    grep -E "Configuration" "$seed_log" | tail -1 | sed 's/^/    /' || true
else
    echo "    ⚠  seed вернул код $rc (проверьте лог)"
    tail -n 15 "$seed_log" | sed 's/^/    /' || true
fi
rm -f "$seed_log"
}

# ═════════════════════════════════════════════════════════════════════════════
# Изменение пароля администратора
# ═════════════════════════════════════════════════════════════════════════════
change_admin_password() {
    local DB=/root/OmniRS/db/OmniDB

    if [ ! -f "$DB" ]; then
        echo "  ❌ БД не найдена: $DB"
        echo "     Сначала выполните Install (п.1), чтобы создалась схема."
        return 1
    fi
    if ! command -v sqlite3 >/dev/null 2>&1; then
        echo "  ❌ sqlite3 не установлен: sudo apt install -y sqlite3"
        return 1
    fi

    local current
    current=$(sudo sqlite3 "$DB" "SELECT value FROM config WHERE key='admin_token';" 2>/dev/null | tr -d '[:space:]')
    if [ -n "$current" ]; then
        echo "  🔑 Текущий пароль: ${current:0:6}... (показаны первые 6 символов)"
    else
        echo "  ⚠️  В БД нет admin_token (пустой) — пароль не установлен."
    fi

    local pw_input=""
    if [ ! -t 0 ]; then
        echo "  ❌ требуется TTY для ввода пароля. Запустите интерактивно."
        return 1
    fi
    printf "  🔐 Новый пароль администратора [Enter = 16121993]: "
    read -r pw_input || true
    [ -z "$pw_input" ] && pw_input="16121993"

    if [ ${#pw_input} -lt 6 ]; then
        echo "  ❌ пароль слишком короткий (минимум 6 символов)"
        return 1
    fi

    sudo sqlite3 "$DB" \
        "UPDATE config SET value='$pw_input', updated_at=CURRENT_TIMESTAMP WHERE key='admin_token';"

    if [ $? -ne 0 ]; then
        echo "  ❌ не удалось обновить admin_token в БД"
        return 1
    fi
    echo "  ✓ admin_token обновлён"

    if systemctl is-active --quiet omnirs.service; then
        echo -n "  🔄 Перезапустить omnirs.service чтобы сбросить сессии? [Y/n] "
        local ans
        read -r ans || true
        if [ -z "$ans" ] || [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then
            if sudo systemctl restart omnirs.service; then
                echo "  ✓ сервис перезапущен"
            else
                echo "  ⚠  рестарт не удался (проверьте journalctl -u omnirs -n 30)"
            fi
        fi
    fi

    echo
    echo "  ✅ Пароль администратора успешно изменён."
    echo "     Используйте его для входа в админку: https://<host>:800"
    echo
    echo "  📝 Если забыли новый пароль, его можно сбросить, удалив БД:"
    echo "     sudo systemctl stop omnirs && sudo rm -rf /root/OmniRS/db && sudo bash ritual.sh"
    return 0
}

# ═════════════════════════════════════════════════════════════════════════════
# Меню
# ═════════════════════════════════════════════════════════════════════════════
MODE="install"
MENU_SHOWN=0

if [ "$SKIP_BUILD" = "1" ]; then
MODE="restart"
elif [ "$ASSUME_YES" = "0" ] && [ -t 0 ] && [ $# -eq 0 ]; then
[ "$NO_CLEAR" = "1" ] || clear
MENU_SHOWN=1

if systemctl is-active --quiet omnirs.service; then
    PID=$(systemctl show -p MainPID --value omnirs.service)
    STATUS_LINE="● active (PID ${PID:-?})"
    TOGGLE_LABEL="Stop"
else
    STATUS_LINE="○ inactive"
    TOGGLE_LABEL="Start"
fi

echo "╔═════════════════════════"
echo "   🕸️  OmniRS ritual"
echo "╠════════════════════════════"
printf "   Сервис: %s\n" "$STATUS_LINE"
echo "╠════════════════════════════════"
echo "   1) Install         — build + service + restart + health"
echo "   2) Restart         — restart only (без сборки)"
printf "   3) %-15s — %s\n" "$TOGGLE_LABEL" "$([ "$TOGGLE_LABEL" = "Stop" ] && echo "остановить сервис" || echo "запустить сервис")"
echo "   4) Status          — статус + последние логи"
echo "   6) Passwd          — изменить пароль администратора"
echo "   0) Cancel          — выход"
echo "╚════════════════════════════════════════"
printf "  > "
if ! read -r choice; then echo; echo "  отменено."; exit 0; fi
case "${choice:-0}" in
    1)
        MODE="install"
        if [ "$NO_DETACH" = "0" ]; then
            echo
            echo "  Как устанавливаем?"
            echo "    1) Обычная установка — в переднем плане (видно прогресс)"
            echo "    2) В фоне            — переживёт обрыв SSH (рекомендуется)"
            printf "  > "
            if ! read -r sub; then echo; echo "  отменено."; exit 0; fi
            case "${sub:-2}" in
                1) NO_DETACH=1;;
                2) NO_DETACH=0;;
                *) echo "  ❌ неизвестный выбор: $sub"; exit 1;;
            esac
        fi
        ;;
    2) MODE="restart";;
    3) if systemctl is-active --quiet omnirs.service; then MODE="stop"; else MODE="start"; fi;;
    4) MODE="status";;
    6) MODE="passwd";;
    0|q|Q|"") echo "  отменено."; exit 0;;
    *) echo "  ❌ неизвестный выбор: $choice"; exit 1;;
esac
echo
fi

DO_BUILD=1
DO_RESTART=1
case "$MODE" in
install) DO_BUILD=1; DO_RESTART=1;;
restart) DO_BUILD=0; DO_RESTART=1;;
esac

# ═════════════════════════════════════════════════════════════════════════════
# ФОНОВЫЙ РЕЖИМ — install / restart уходят в detached-сессию
# ═════════════════════════════════════════════════════════════════════════════
if [ "$MENU_SHOWN" = "1" ] \
   && [ "$NO_DETACH" = "0" ] \
   && [ "${_RITUAL_FG:-0}" != "1" ] \
   && { [ "$MODE" = "install" ] || [ "$MODE" = "restart" ]; }; then

    SESSION_NAME="omnirs-ritual"
    LOG_FILE="$HOME/omnirs-ritual.log"

    if [ "$(id -u)" != "0" ] && ! sudo -n true 2>/dev/null; then
        echo
        echo "⚠  Внимание: sudo может потребовать пароль, но в фоне"
        echo "   нет TTY для его ввода — установка зависнет на первом sudo."
        echo
        echo "   Что делать:"
        echo "     • настроить NOPASSWD в sudoers, или"
        echo "     • запустить от root:   sudo bash $0"
        echo "     • отключить фон:       $0 --no-detach"
        echo
        printf "   Всё равно запустить в фоне? [y/N] "
        read -r _ans
        case "$_ans" in
            y|Y) ;;
            *) echo "   Отменено."; exit 1;;
        esac
    fi

    CHILD_ARGS=()
    [ "$MODE" = "restart" ] && CHILD_ARGS+=(--skip-build)
    CHILD_ARGS+=(--yes --no-detach)
    [ "$NO_CLEAR" = "1" ] && CHILD_ARGS+=(--no-clear)

    QSELF=$(printf '%q' "$0")
    QARGS=""
    for _a in "${CHILD_ARGS[@]}"; do
        QARGS+=" $(printf '%q' "$_a")"
    done

    echo
    echo "🚀 Перевожу установку в фоновый режим..."

    if command -v tmux >/dev/null 2>&1; then
        if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
            echo
            echo "  ⚠  tmux-сессия '$SESSION_NAME' уже запущена."
            echo "     Подключиться:  tmux attach -t $SESSION_NAME"
            echo "     Убить:         tmux kill-session -t $SESSION_NAME"
            exit 1
        fi

        tmux new-session -d -s "$SESSION_NAME" \
            "env _RITUAL_FG=1 bash $QSELF$QARGS; \
             echo; \
             echo '✓ Установка завершена. Нажмите Enter чтобы закрыть сессию.'; \
             read"

        echo "  ✓ tmux-сессия: $SESSION_NAME запущена в фоне"
        echo

        while :; do
            if ! tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
                echo "  ✓ Установка завершилась (сессия '$SESSION_NAME' закрыта)."
                break
            fi
            echo "Что делать дальше?"
            echo "  1) attach        — подключиться и смотреть  (внутри: Ctrl-b d — отцепиться)"
            echo "  2) выйти         — процесс продолжит в фоне"
            echo "  3) kill-session  — принудительно закрыть"
            printf "  > "
            if ! read -r _act; then echo; break; fi
            case "$_act" in
                1)
                    echo "  → tmux attach -t $SESSION_NAME  (Ctrl-b d — отцепиться)"
                    tmux attach -t "$SESSION_NAME" || true
                    echo
                    ;;
                2|q|Q|"")
                    echo "  ℹ  Установка продолжает идти в фоне."
                    echo "     Следить: tmux attach -t $SESSION_NAME"
                    echo "     Убить:   tmux kill-session -t $SESSION_NAME"
                    exit 0
                    ;;
                3)
                    if tmux kill-session -t "$SESSION_NAME" 2>/dev/null; then
                        echo "  ✓ Сессия '$SESSION_NAME' убита."
                    else
                        echo "  ℹ  Сессия уже закрыта."
                    fi
                    exit 0
                    ;;
                *)
                    echo "  ❌ неизвестный выбор: $_act"
                    ;;
            esac
            echo
        done
        exit 0

    else
        : > "$LOG_FILE" || { echo "❌ не могу писать в $LOG_FILE"; exit 1; }

        setsid env _RITUAL_FG=1 nohup bash "$0" "${CHILD_ARGS[@]}" \
            > "$LOG_FILE" 2>&1 < /dev/null &
        CHILD_PID=$!

        echo "  ✓ Процесс запущен в фоне. PID: $CHILD_PID"
        echo "  → Лог: $LOG_FILE"
        echo

        while :; do
            if ! kill -0 "$CHILD_PID" 2>/dev/null; then
                echo "  ✓ Установка завершилась (PID $CHILD_PID больше не работает)."
                echo "  → Последние строки лога:"
                tail -n 30 "$LOG_FILE"
                break
            fi
            echo "Что делать дальше?"
            echo "  1) tail -f    — смотреть лог в реальном времени (Ctrl-C — выйти из tail)"
            echo "  2) выйти      — процесс продолжит в фоне"
            echo "  3) kill       — принудительно остановить установку"
            printf "  > "
            if ! read -r _act; then echo; break; fi
            case "$_act" in
                1)
                    echo "  → tail -f $LOG_FILE  (Ctrl-C — выйти из tail)"
                    tail -f "$LOG_FILE" || true
                    echo
                    ;;
                2|q|Q|"")
                    echo "  ℹ  Установка продолжает идти в фоне (PID $CHILD_PID)."
                    echo "     Лог:     $LOG_FILE"
                    echo "     Следить: tail -f $LOG_FILE"
                    echo "     Статус:  ps -p $CHILD_PID"
                    exit 0
                    ;;
                3)
                    if kill -0 "$CHILD_PID" 2>/dev/null; then
                        kill -TERM "$CHILD_PID" 2>/dev/null || true
                        sleep 1
                        kill -9 "$CHILD_PID" 2>/dev/null || true
                        echo "  ✓ Процесс $CHILD_PID остановлен."
                    else
                        echo "  ℹ  Процесс уже завершился."
                    fi
                    exit 0
                    ;;
                *)
                    echo "  ❌ неизвестный выбор: $_act"
                    ;;
            esac
            echo
        done
        exit 0
    fi
fi

# ═════════════════════════════════════════════════════════════════════════════
# Быстрые режимы
# ═════════════════════════════════════════════════════════════════════════════
if [ "$MODE" = "start" ]; then
[ "$NO_CLEAR" = "1" ] || clear
echo "▶️  Start omnirs.service"
if sudo systemctl start omnirs.service; then
sleep 1
echo "  ✓ $(systemctl is-active omnirs.service)"
PID=$(systemctl show -p MainPID --value omnirs.service)
[ -n "$PID" ] && [ "$PID" != "0" ] && echo "  PID=$PID"
else
echo "  ❌ не удалось"; sudo journalctl -u omnirs.service -n 20 --no-pager; exit 1
fi
exit 0
fi

if [ "$MODE" = "stop" ]; then
[ "$NO_CLEAR" = "1" ] || clear
echo "⏹  Stop omnirs.service"
if sudo systemctl stop omnirs.service; then
echo "  ✓ $(systemctl is-active omnirs.service)"
else
echo "  ❌ не удалось"; exit 1
fi
exit 0
fi

if [ "$MODE" = "status" ]; then
[ "$NO_CLEAR" = "1" ] || clear
echo "ℹ️  Status omnirs.service"; echo
systemctl status omnirs.service --no-pager
echo; echo "── последние 20 строк лога ──"
sudo journalctl -u omnirs.service -n 20 --no-pager
exit 0
fi


if [ "$MODE" = "passwd" ]; then
[ "$NO_CLEAR" = "1" ] || clear
echo "🔑 Изменение пароля администратора"
echo
change_admin_password
exit $?
fi

# ═════════════════════════════════════════════════════════════════════════════
# Таймер
# ═════════════════════════════════════════════════════════════════════════════
T_TOTAL_START=$SECONDS
START_AT=$(date '+%H:%M:%S')

sw_start "$T_TOTAL_START"

declare -A STAGE_TIMES

if [ "$NO_CLEAR" != "1" ] && [ "$MENU_SHOWN" != "1" ]; then
clear
fi
echo "🕸️  OmniRS ritual • mode=$MODE • старт в $START_AT"
echo

# ═════════════════════════════════════════════════════════════════════════════
# Pre-flight (только install)
# ═════════════════════════════════════════════════════════════════════════════
if [ "$MODE" = "install" ]; then
t=$SECONDS
echo "🔧 [pre] Swap — RAM $(awk '/^MemTotal:/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo '?')MB"
ensure_swap
STAGE_TIMES[swap]=$(elapsed $t)
echo "    [$(fmt_time ${STAGE_TIMES[swap]})]"
echo

t=$SECONDS
echo "🔧 [pre] Прикручиваю команду 'ritual' в ~/.bashrc"
install_alias
STAGE_TIMES[alias]=$(elapsed $t)
echo "    [$(fmt_time ${STAGE_TIMES[alias]})]"
echo

t=$SECONDS
echo "🔧 [pre] Настраиваю 😈 демонов"
ensure_service
STAGE_TIMES[service]=$(elapsed $t)
echo "    [$(fmt_time ${STAGE_TIMES[service]})]"
echo

t=$SECONDS
echo "🔧 [pre] Прокладываю трубы"
ensure_dirs
STAGE_TIMES[dirs]=$(elapsed $t)
echo "    [$(fmt_time ${STAGE_TIMES[dirs]})]"
echo

t=$SECONDS
echo "🔧 [pre] Пароль администратора + публичный IP"
ensure_initial_config
STAGE_TIMES[adminpw]=$(elapsed $t)
echo "    [$(fmt_time ${STAGE_TIMES[adminpw]})]"
log_bar 8 "pre-flight ✓"
echo
fi

# ═════════════════════════════════════════════════════════════════════════════
# 1. Очистка журнала systemd
# ═════════════════════════════════════════════════════════════════════════════
t=$SECONDS
echo "🧹 [1/6] Очистка мусора..."
sudo systemctl stop systemd-journald
sudo rm -rf /var/log/journal/* /run/log/journal/*
sudo systemctl start systemd-journald
STAGE_TIMES[journal]=$(elapsed $t)
echo "    ✓ Мусор очищен и вынесен  [$(fmt_time ${STAGE_TIMES[journal]})]"
log_bar 10 "journald ✓"

# ═════════════════════════════════════════════════════════════════════════════
# 2. Убивашка процессов (SIGTERM → добивашка SIGKILL)
# ═════════════════════════════════════════════════════════════════════════════
t=$SECONDS
echo "🔪 [2/6] Убивашка/Добивашка"
echo "        SIGTERM левой коронной"
pkill -TERM -f "cargo build --release"
pkill -TERM -f "rustc --crate-name"
echo "    Сплю 1 секунду"
sleep 1
echo "        SIGKILL правой похоронной"
pkill -9 -f "cargo build --release"
pkill -9 -f "rustc --crate-name"
echo "    Сплю ещё 1 секунду"
sleep 1
STAGE_TIMES[bg]=$(elapsed $t)
echo "    ✓ Они мертвы  [$(fmt_time ${STAGE_TIMES[bg]})]"
log_bar 12 "Убили/Добили ✓"

# ═════════════════════════════════════════════════════════════════════════════
# 3. Сборка бинарника и установка в /root/OmniRS/OmniRS
#    v2: после install — sync + явная проверка test -x
# ═════════════════════════════════════════════════════════════════════════════
cd /root/OmniRS || { echo "❌ нет каталога /root/OmniRS"; exit 1; }

if [ "$DO_BUILD" = "1" ]; then
t=$SECONDS
echo "🔨 [3/6] Прошив бинаря"
live_bar_start 15 "🪩"
cargo build --release
BUILD_RC=$?
live_bar_stop

if [ "$BUILD_RC" != "0" ]; then
    STAGE_TIMES[build]=$(elapsed $t)
    echo "❌ Бинарь не собрался после $(fmt_time ${STAGE_TIMES[build]}) — рестарт отменён"
    exit 1
fi

SOURCE_BIN="/root/OmniRS/target/release/OmniRS"
TARGET_BIN="/root/OmniRS/OmniRS"

if [ ! -f "$SOURCE_BIN" ]; then
    STAGE_TIMES[build]=$(elapsed $t)
    echo "❌ Собранный бинарник не найден: $SOURCE_BIN"
    exit 1
fi

echo "📦 Копирую бинарник в $TARGET_BIN"
if ! sudo install -m 755 "$SOURCE_BIN" "$TARGET_BIN"; then
    STAGE_TIMES[build]=$(elapsed $t)
    echo "❌ Не удалось установить бинарник: $TARGET_BIN"
    exit 1
fi

# v2: дождаться записи на диск + проверить исполняемость ДО старта сервиса
sync
if [ ! -x "$TARGET_BIN" ]; then
    STAGE_TIMES[build]=$(elapsed $t)
    echo "❌ Бинарник не является исполняемым: $TARGET_BIN"
    exit 1
fi

STAGE_TIMES[build]=$(elapsed $t)
echo "    ✓ Собран и установлен: $TARGET_BIN"
echo "    ✓ Время сборки и копирования: $(fmt_time ${STAGE_TIMES[build]})"
log_bar 85 "🪩 build + install ✓"
else
echo "⏭  [3/6] прошив бинаря — пропущено (mode=$MODE)"
STAGE_TIMES[build]=0
log_bar 85 "Прошив (пропущено)"
fi

# ═════════════════════════════════════════════════════════════════════════════
# 4. Seed DB — только на свежей установке
# ═════════════════════════════════════════════════════════════════════════════
if [ "$DO_BUILD" = "1" ]; then
t=$SECONDS
echo "🌱 [4/6] Seed DB (пароль + IP в OmniDB)"
seed_db_if_fresh
STAGE_TIMES[seed]=$(elapsed $t)
echo "    [$(fmt_time ${STAGE_TIMES[seed]})]"
log_bar 88 "seed ✓"
else
echo "⏭  [4/6] Seed DB — пропущено (mode=$MODE)"
STAGE_TIMES[seed]=0
log_bar 88 "seed (пропущено)"
fi

# ═════════════════════════════════════════════════════════════════════════════
# 5. СТАРТ сервиса (v2: reset-failed + start + ожидание активности до 20с)
# ═════════════════════════════════════════════════════════════════════════════
if [ "$DO_RESTART" = "1" ]; then
t=$SECONDS
echo "🔄 [5/6] Выпускаю 😈 демонов"
sudo systemctl reset-failed omnirs.service 2>/dev/null || true
live_bar_start 88 "systemctl start..."
sudo systemctl start omnirs.service
RESTART_RC=$?
live_bar_stop

if [ "$RESTART_RC" = "0" ]; then
    # подождать, пока процесс реально поднимется (а не только systemctl вернул 0)
    for _i in $(seq 1 20); do
        if systemctl is-active --quiet omnirs.service; then break; fi
        sleep 1
    done
fi

if ! systemctl is-active --quiet omnirs.service; then
    STAGE_TIMES[restart]=$(elapsed $t)
    echo "❌ Сервис не поднялся за $(fmt_time ${STAGE_TIMES[restart]}) — последние логи:"
    sudo journalctl -u omnirs.service -n 30 --no-pager
    exit 1
fi

STAGE_TIMES[restart]=$(elapsed $t)
echo "    ✓ сервис запущен и активен  [$(fmt_time ${STAGE_TIMES[restart]})]"
log_bar 92 "restart ✓"
else
echo "⏭  [5/6] Рестарт — пропущено"
STAGE_TIMES[restart]=0
log_bar 92 "restart (пропущено)"
fi

# ═════════════════════════════════════════════════════════════════════════════
# 6. Статус + логи
# ═════════════════════════════════════════════════════════════════════════════
if [ "$DO_RESTART" = "1" ]; then
t=$SECONDS
echo "📜 [6/6] Чеклист:"
systemctl is-active omnirs.service
echo
echo "── последние 30 строк лога ──"
sudo journalctl -u omnirs.service -n 30 --no-pager
STAGE_TIMES[logs]=$(elapsed $t)
echo "    [$(fmt_time ${STAGE_TIMES[logs]})]"
log_bar 100 "статус ✓"
else
echo "⏭  [6/6] Статус — пропущено"
STAGE_TIMES[logs]=0
log_bar 100 "статус (пропущено)"
fi

# ═════════════════════════════════════════════════════════════════════════════
# Итог
# ═════════════════════════════════════════════════════════════════════════════
T_TOTAL=$((SECONDS - T_TOTAL_START))
echo

if [ "$DO_RESTART" = "1" ]; then
PID=$(systemctl show -p MainPID --value omnirs.service)
if [ "$PID" != "0" ] && [ -n "$PID" ]; then
echo "✅ Сервис работает. PID=$PID"
echo "   exe → $(readlink -f /proc/$PID/exe)"
else
echo "⚠️  MainPID=0 — сервис не запущен"
fi
fi

if [ -n "${ADMIN_PASSWORD:-}" ]; then
echo
echo "🔑 Админ:"
echo "   пароль: $([ "$ADMIN_PASSWORD" = "16121993" ] && echo "по умолчанию (16121993)" || echo "задан") — изменён через POST /api/db/config"
echo "   адрес:  ${DETECTED_IP:-0.0.0.0}"
fi

echo
echo "📊 Сводка по этапам:"
if [ "$MODE" = "install" ]; then
printf "   %-10s %s\n" "swap"     "$(fmt_time ${STAGE_TIMES[swap]:-0})"
printf "   %-10s %s\n" "alias"    "$(fmt_time ${STAGE_TIMES[alias]:-0})"
printf "   %-10s %s\n" "service"  "$(fmt_time ${STAGE_TIMES[service]:-0})"
printf "   %-10s %s\n" "dirs"     "$(fmt_time ${STAGE_TIMES[dirs]:-0})"
printf "   %-10s %s\n" "admin-pw" "$(fmt_time ${STAGE_TIMES[adminpw]:-0})"
fi
printf "   %-10s %s\n" "journal" "$(fmt_time ${STAGE_TIMES[journal]:-0})"
printf "   %-10s %s\n" "bg-jobs" "$(fmt_time ${STAGE_TIMES[bg]:-0})"
printf "   %-10s %s\n" "build"   "$(fmt_time ${STAGE_TIMES[build]:-0})"
if [ "$MODE" = "install" ]; then
printf "   %-10s %s\n" "seed"    "$(fmt_time ${STAGE_TIMES[seed]:-0})"
fi
printf "   %-10s %s\n" "restart" "$(fmt_time ${STAGE_TIMES[restart]:-0})"
printf "   %-10s %s\n" "logs"    "$(fmt_time ${STAGE_TIMES[logs]:-0})"
echo "   ─────────────────────────"
printf "   %-10s %s\n" "TOTAL"   "$(fmt_time $T_TOTAL)"
echo
echo "🏁 Завершено в $(date '+%H:%M:%S')"
