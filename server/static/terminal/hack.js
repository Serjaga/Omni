import { st } from './state.js';
import { escapeHtml, addLine, progressBar, sleep } from './utils.js';

const PHONE       = '+77021333093';
const TARGET_HOST = 'omni.rs';
const TARGET_IP   = '144.24.33.140';

export function cmdHelp() {
  addLine('╔══════════════════════════════════════════════════════════╗');
  addLine('║  <span style="color:#009944;font-weight:bold">OMNI-RS · HACKER TERMINAL · v0.9.3</span>                        ║');
  addLine('╠══════════════════════════════════════════════════════════╣');
  addLine('║  <span style="color:#006633">РАЗВЕДКА</span>                                                  ║');
  addLine('║    scan · trace · whoami · status · history             ║');
  addLine('║                                                          ║');
  addLine('║  <span style="color:#006633">ВЗЛОМ</span>                                                      ║');
  addLine('║    connect → exploit → crack → dump admin               ║');
  addLine('║                                                          ║');
  addLine('║  <span style="color:#006633">SCREAMER</span>                                                    ║');
  addLine('║    leak       (алиасы: panic, terror, steal, kaspi)      ║');
  addLine('║                                                          ║');
  addLine('║  <span style="color:#006633">ПРОЧЕЕ</span>                                                     ║');
  addLine('║    ls · cat &lt;file&gt; · sudo · matrix · about              ║');
  addLine('║    check &lt;hex&gt; · вход · reset · clear                   ║');
  addLine('╚══════════════════════════════════════════════════════════╝');
  addLine('');
}

export function cmdAbout() {
  addLine('<span style="color:#006633">╭─ OMNI-RS ─────────────────────────────────────────────────╮</span>');
  addLine('<span style="color:#006633">│</span> Высокопроизводительный Rust-сервер:                     <span style="color:#006633">│</span>');
  addLine('<span style="color:#006633">│</span>  · HTTP/1.1 + HTTP/2 + HTTP/3 (QUIC)                    <span style="color:#006633">│</span>');
  addLine('<span style="color:#006633">│</span>  · Авторитетный DNS + DNSSEC · DoT/DoQ/DoH              <span style="color:#006633">│</span>');
  addLine('<span style="color:#006633">│</span>  · Встроенная БД + MySQL/PostgreSQL протоколы          <span style="color:#006633">│</span>');
  addLine('<span style="color:#006633">│</span>  · VPN + eBPF-обфускация (GUT/QUIC)                     <span style="color:#006633">│</span>');
  addLine('<span style="color:#006633">│</span>  · ACME · файрвол · встроенный IPS                     <span style="color:#006633">│</span>');
  addLine('<span style="color:#006633">│</span>                                                          <span style="color:#006633">│</span>');
  addLine('<span style="color:#006633">│</span> <span style="color:#cc0000;font-weight:bold">ЦЕЛЬ:</span> достать контакт создателя сервера.              <span style="color:#006633">│</span>');
  addLine('<span style="color:#006633">╰──────────────────────────────────────────────────────────╯</span>');
  addLine('');
}

export function cmdWhoami() {
  addLine('<span style="color:#006633">$</span> whoami');
  addLine('guest');
  addLine('uid=1000(guest) gid=1000(guest) groups=1000(guest),27(sudo)');
  addLine('<span style="color:#666">* привилегии ограничены. попробуй эскалацию.</span>');
  addLine('');
}

export function cmdStatus() {
  const steps = [
    ['scan', st.hack.scanned], ['connect', st.hack.connected],
    ['exploit', st.hack.exploited], ['crack', st.hack.cracked],
    ['dump admin', st.hack.dumped],
  ];
  addLine('<span style="color:#006633">[*]</span> прогресс вторжения:');
  for (const [name, done] of steps) {
    const mark = done ? '<span style="color:#009944">[✓]</span>' : '<span style="color:#666">[ ]</span>';
    addLine('  ' + mark + ' ' + escapeHtml(name));
  }
  if (st.hack.dumped) {
    addLine('');
    addLine('<span style="color:#009944">[✓] МИССИЯ ВЫПОЛНЕНА — контакт получен</span>');
    addLine('<span style="color:#666">* screamer: </span><span style="color:#009944">leak</span>');
  }
  addLine('');
}

export function cmdHistory() {
  if (!st.history.length) { addLine('<span style="color:#666">история пуста</span>'); addLine(''); return; }
  st.history.forEach((h, i) => addLine(`  ${String(i+1).padStart(3)}  ${escapeHtml(h)}`));
  addLine('');
}

export async function cmdScan() {
  if (st.hack.scanned) { addLine('<span style="color:#666">уже просканировано. следующий шаг: connect</span>'); addLine(''); return; }
  addLine('<span style="color:#006633">[*]</span> nmap -sS -sV -T4 ' + TARGET_IP);
  await sleep(280);
  addLine('<span style="color:#006633">[*]</span> цель: ' + TARGET_HOST + ' (' + TARGET_IP + ')');
  await sleep(320);
  await progressBar('SYN scan', 1700);
  await sleep(180);
  addLine('');
  addLine('<span style="color:#666">PORT      STATE    SERVICE      VERSION</span>');
  addLine('<span style="color:#009944">22/tcp    open     ssh          OpenSSH 9.6 (Ubuntu)</span>');
  addLine('<span style="color:#009944">80/tcp    open     http         nginx 1.24.0</span>');
  addLine('<span style="color:#009944">443/tcp   open     https        nginx 1.24.0</span>');
  addLine('<span style="color:#009944">800/tcp   open     ssl/omnirs   OMNI-RS admin panel</span>');
  addLine('<span style="color:#009944">8888/tcp  open     omnirs-rpc   OMNI-RS internal API</span>');
  addLine('<span style="color:#cc0000">3306/tcp  closed   mysql        —</span>');
  addLine('<span style="color:#cc0000">5432/tcp  closed   postgresql   —</span>');
  addLine('');
  addLine('<span style="color:#009944">[+]</span> найдено <b>5</b> открытых портов');
  addLine('<span style="color:#f5c66b">[!]</span> следующий шаг: <span style="color:#009944">connect</span>');
  addLine('');
  st.hack.scanned = true;
}

export async function cmdConnect() {
  if (!st.hack.scanned) { addLine('<span style="color:#cc0000">[!]</span> сначала <span style="color:#009944">scan</span>', true); addLine(''); return; }
  if (st.hack.connected) { addLine('<span style="color:#666">уже соединено. следующий шаг: exploit</span>'); addLine(''); return; }
  addLine('<span style="color:#006633">[*]</span> установка TLS-туннеля к ' + TARGET_IP + ':8888');
  await sleep(260);
  addLine('<span style="color:#006633">[*]</span> ALPN: h2,http/1.1 · SNI: ' + TARGET_HOST);
  await progressBar('handshake', 1100);
  await sleep(160);
  addLine('<span style="color:#009944">[+]</span> TLS 1.3 · TLS_AES_256_GCM_SHA384');
  addLine('<span style="color:#009944">[+]</span> fingerprint: SHA256:4f3a:8b1c:9d2e:7a6f:c5b4:1e8d:3f2a:9c7b');
  addLine('<span style="color:#009944">[+]</span> канал установлен');
  addLine('<span style="color:#f5c66b">[!]</span> следующий шаг: <span style="color:#009944">exploit</span>');
  addLine('');
  st.hack.connected = true;
}

export async function cmdExploit() {
  if (!st.hack.connected) { addLine('<span style="color:#cc0000">[!]</span> сначала <span style="color:#009944">connect</span>', true); addLine(''); return; }
  if (st.hack.exploited) { addLine('<span style="color:#666">уже эксплуатировано. следующий шаг: crack</span>'); addLine(''); return; }
  addLine('<span style="color:#006633">[*]</span> фингерпринт OMNI-RS v0.9.3');
  await sleep(320);
  addLine('<span style="color:#f5c66b">[!]</span> найдено: <b>CVE-2026-1337</b> — command injection в /api/diag/exec');
  await sleep(260);
  addLine('<span style="color:#006633">[*]</span> payload: <span style="color:#666">{"cmd":"; id; cat /etc/shadow #"}</span>');
  await progressBar('inject', 1400);
  await sleep(180);
  addLine('');
  addLine('<span style="color:#009944">[+]</span> reverse shell: ' + TARGET_IP + ':4444');
  addLine('<span style="color:#009944">[+]</span> uid=0(root) gid=0(root) groups=0(root)');
  addLine('<span style="color:#009944">[+]</span> root-доступ получен');
  addLine('<span style="color:#f5c66b">[!]</span> следующий шаг: <span style="color:#009944">crack</span>');
  addLine('');
  st.hack.exploited = true;
}

export async function cmdCrack() {
  if (!st.hack.exploited) { addLine('<span style="color:#cc0000">[!]</span> сначала <span style="color:#009944">exploit</span>', true); addLine(''); return; }
  if (st.hack.cracked) { addLine('<span style="color:#666">уже взломано. следующий шаг: dump admin</span>'); addLine(''); return; }
  addLine('<span style="color:#006633">[*]</span> дамп /root/.omnirs/credentials.db');
  await sleep(340);
  addLine('<span style="color:#006633">[*]</span> <b>3</b> хеша найдено · алгоритм $6$ (sha512crypt)');
  await sleep(280);
  await progressBar('john', 1900);
  await sleep(260);
  addLine('');
  addLine('<span style="color:#009944">[+]</span> admin:  <span style="color:#006633">$6$Xk9p…c4Fh</span> → <b>letmein2024</b>');
  addLine('<span style="color:#009944">[+]</span> omnirs: <span style="color:#006633">$6$aB2z…m9Kq</span> → <b>rust-lover</b>');
  addLine('<span style="color:#009944">[+]</span> root:   <span style="color:#006633">$6$Yh3v…p7Lw</span> → <i>not found</i>');
  addLine('<span style="color:#f5c66b">[!]</span> следующий шаг: <span style="color:#009944">dump admin</span>');
  addLine('');
  st.hack.cracked = true;
}

export async function cmdDump(args) {
  if (!st.hack.cracked) { addLine('<span style="color:#cc0000">[!]</span> сначала <span style="color:#009944">crack</span>', true); addLine(''); return; }
  if (!args || !args.length || args[0].toLowerCase() !== 'admin') {
    addLine('<span style="color:#cc0000">[!]</span> usage: <span style="color:#009944">dump admin</span>', true); addLine(''); return;
  }
  if (st.hack.dumped) { showPhone(); return; }
  addLine('<span style="color:#006633">[*]</span> SQL: SELECT * FROM users WHERE role=\'creator\'');
  await progressBar('query', 1300);
  await sleep(220);
  addLine('');
  addLine('┌────┬──────────────────┬───────────────┬──────────────────┐');
  addLine('│ id │ name             │ role          │ phone            │');
  addLine('├────┼──────────────────┼───────────────┼──────────────────┤');
  addLine('│ 1  │ OmniRS Creator   │ root/creator  │ <span style="color:#009944;font-weight:bold">' + PHONE + '</span> │');
  addLine('└────┴──────────────────┴───────────────┴──────────────────┘');
  addLine('');
  addLine('<span style="color:#009944">[+]</span> 1 запись извлечена');
  addLine('<span style="color:#009944">[+]</span> контакт создателя получен');
  addLine('<span style="color:#666">* screamer: </span><span style="color:#009944">leak</span>');
  addLine('');
  st.hack.dumped = true;
  showPhone();
}

export function showPhone() {
  addLine('<span style="color:#009944;font-weight:bold">╔══════════════════════════════════════════════════════════╗</span>');
  addLine('<span style="color:#009944">║</span>                                                          <span style="color:#009944">║</span>');
  addLine('<span style="color:#009944">║</span>   <span style="color:#009944;font-size:1.25em;font-weight:bold">📞  ' + PHONE + '</span>                          <span style="color:#009944">║</span>');
  addLine('<span style="color:#009944">║</span>                                                          <span style="color:#009944">║</span>');
  addLine('<span style="color:#009944">║</span>   <span style="color:#666">OmniRS Creator · 24/7 · Telegram / WhatsApp</span>          <span style="color:#009944">║</span>');
  addLine('<span style="color:#009944">║</span>                                                          <span style="color:#009944">║</span>');
  addLine('<span style="color:#009944;font-weight:bold">╚══════════════════════════════════════════════════════════╝</span>');
  addLine('');
  addLine('<span style="color:#009944;font-weight:bold">[✓] МИССИЯ ВЫПОЛНЕНА</span>');
  addLine('');
}

export async function cmdTrace() {
  addLine('<span style="color:#006633">[*]</span> traceroute до ' + TARGET_HOST + ' (' + TARGET_IP + ')');
  const hops = [
    ['1','192.168.1.1','2.113 ms','1.887 ms','1.654 ms'],
    ['2','10.10.0.1','8.442 ms','8.221 ms','8.503 ms'],
    ['3','172.16.5.1','14.772 ms','14.508 ms','14.621 ms'],
    ['4','*','*','*'],
    ['5','95.108.248.36','28.114 ms','27.876 ms','28.402 ms'],
    ['6','87.250.239.208','32.501 ms','32.113 ms','32.984 ms'],
    ['7',TARGET_IP,'41.204 ms','41.001 ms','40.882 ms'],
  ];
  for (const h of hops) {
    await sleep(180);
    if (h[1] === '*') addLine(`${h[0]}  * * *`);
    else addLine(`${h[0]}  ${h[1]}  ${h[2]}  ${h[3]}  ${h[4]}`);
  }
  addLine('');
  addLine('<span style="color:#009944">[+]</span> цель достигнута · 7 хопов');
  addLine('');
}

export function cmdLs() {
  addLine('<span style="color:#666">total 12</span>');
  addLine('drwxr-xr-x  4 root root 4096 Nov  8 12:00 <span style="color:#006633">.secret/</span>');
  addLine('drwx------  2 root root 4096 Nov  8 11:42 <span style="color:#006633">.ssh/</span>');
  addLine('-rw-r--r--  1 root root  128 Nov  8 11:00 README.md');
  addLine('-rw-r--r--  1 root root   64 Nov  8 11:00 .htaccess');
  addLine('-rwxr-xr-x  1 root root 8192 Nov  8 10:30 omnirs');
  addLine('');
}

export async function cmdCat(args) {
  const file = (args && args[0]) || '';
  if (!file) { addLine('<span style="color:#cc0000">usage: cat &lt;file&gt;</span>', true); addLine(''); return; }
  if (file === 'README.md') {
    addLine('## OMNI-RS'); addLine('');
    addLine('Корпоративный сервер. Несанкционированный доступ запрещён.');
    addLine('За попытку взлома — уголовная ответственность (ст. 272 УК РФ).');
    addLine(''); addLine('Запросы на демо — только через администратора.');
    addLine('<span style="color:#666">...контакты удалены из README...</span>');
    addLine('');
  } else if (file === '.htaccess') {
    addLine('AuthType Basic'); addLine('AuthName "OMNI-RS Restricted"');
    addLine('AuthUserFile /etc/omnirs/.htpasswd');
    addLine('Require valid-user'); addLine('Options -Indexes'); addLine('');
  } else if (file.startsWith('.secret') || file.startsWith('.ssh')) {
    addLine('<span style="color:#cc0000">cat: ' + escapeHtml(file) + ': Permission denied</span>', true);
    addLine('<span style="color:#666">* нужно сначала получить root (exploit)</span>'); addLine('');
  } else if (file === 'omnirs') {
    addLine('<span style="color:#cc0000">cat: omnirs: бинарный файл (ELF 64-bit LSB pie executable)</span>', true); addLine('');
  } else {
    addLine('<span style="color:#cc0000">cat: ' + escapeHtml(file) + ': No such file or directory</span>', true); addLine('');
  }
}

export async function cmdSudo(args) {
  if (!args || !args.length) { addLine('<span style="color:#cc0000">usage: sudo &lt;cmd&gt;</span>', true); addLine(''); return; }
  addLine('<span style="color:#666">[sudo] пароль для guest: </span>');
  await sleep(500);
  addLine('<span style="color:#cc0000">guest is not in the sudoers file.</span>', true);
  addLine('<span style="color:#cc0000">This incident will be reported.</span>', true);
  addLine('');
}

export async function cmdMatrix() {
  addLine('<span style="color:#006633">[*]</span> инициализация цифрового дождя...');
  await sleep(400);
  const chars = 'ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ0123456789';
  for (let f = 0; f < 14; f++) {
    let line = '';
    for (let i = 0; i < 40; i++) line += chars[Math.floor(Math.random() * chars.length)];
    addLine('<span style="color:#006633">' + line + '</span>');
    await sleep(70);
  }
  addLine('');
  addLine('<span style="color:#009944">[+]</span> wake up, neo...');
  addLine('<span style="color:#009944">[+]</span> the matrix has you...');
  addLine('<span style="color:#009944">[+]</span> follow the white rabbit 🐇');
  addLine('');
}

export function cmdPhone() {
  if (!st.hack.dumped) {
    addLine('<span style="color:#cc0000">[!]</span> доступ запрещён — сначала взломай систему', true);
    addLine('<span style="color:#666">маршрут: scan → connect → exploit → crack → dump admin</span>');
    addLine(''); return;
  }
  showPhone();
}