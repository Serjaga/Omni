//! Native Rust implementation of the former ritual.sh installer.
//! This module is independent: it never reads, executes, creates or modifies ritual.sh.
use std::{
    env,
    fs::{self, OpenOptions},
    io::{self, IsTerminal, Write},
    net::Ipv4Addr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const ROOT: &str = "/root/OmniRS";
const BIN: &str = "/root/OmniRS/OmniRS";
const DB: &str = "/root/OmniRS/db/OmniDB";
const UNIT: &str = "/etc/systemd/system/omnirs.service";
const DEFAULT_PASSWORD: &str = "16121993";
const SERVICE_UNIT: &str = "[Unit]\nDescription=OmniRS\nAfter=network.target\nStartLimitIntervalSec=10\nStartLimitBurst=5\n\n[Service]\nType=simple\nWorkingDirectory=/root/OmniRS\nEnvironment=OMNIRS_DB_DIR=/root/OmniRS/db\nEnvironment=OMNIRS_AUDIT_LOG=/var/log/omnirs/audit.log\nExecStartPre=/bin/mkdir -p /root/OmniRS/db\nExecStartPre=/bin/test -x /root/OmniRS/OmniRS\nExecStart=/root/OmniRS/OmniRS\nRestart=on-failure\nRestartSec=3\n\n[Install]\nWantedBy=multi-user.target\n";

#[derive(Clone, Copy, PartialEq, Eq)] enum Mode { Install, Restart, Start, Stop, Status, Passwd }
struct Options { no_clear: bool, yes: bool }
struct Context { admin_password: Option<String>, detected_ip: Option<String>, fresh: bool }
struct Stage { name: &'static str, seconds: u64 }

fn run(program: &str, args: &[&str]) -> io::Result<std::process::Output> {
    Command::new(program).args(args).output()
}
fn sudo(args: &[&str]) -> io::Result<std::process::Output> { run("sudo", args) }
fn command_ok(program: &str, args: &[&str]) -> bool { run(program, args).map(|o| o.status.success()).unwrap_or(false) }
fn sudo_ok(args: &[&str]) -> bool { sudo(args).map(|o| o.status.success()).unwrap_or(false) }
fn output(program: &str, args: &[&str]) -> String {
    run(program, args).ok().filter(|o| o.status.success()).map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default()
}
fn sudo_output(args: &[&str]) -> String {
    sudo(args).ok().filter(|o| o.status.success()).map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default()
}
fn fmt_time(mut s: u64) -> String {
    if s >= 3600 { let h=s/3600; s%=3600; let m=s/60; let sec=s%60; format!("{h}h {m:02}m {sec:02}s") }
    else if s >= 60 { format!("{}m {:02}s", s/60, s%60) } else { format!("{s}s") }
}
fn clear(no_clear: bool) { if !no_clear { let _=io::stdout().write_all(b"\x1b[2J\x1b[H\x1b[3J"); let _=io::stdout().flush(); } }
fn read_line(prompt: &str) -> io::Result<String> { print!("{prompt}"); io::stdout().flush()?; let mut s=String::new(); io::stdin().read_line(&mut s)?; Ok(s.trim_end_matches(['\r','\n']).to_string()) }
fn is_active() -> bool { command_ok("systemctl", &["is-active", "--quiet", "omnirs.service"]) }
fn pid() -> String { output("systemctl", &["show", "-p", "MainPID", "--value", "omnirs.service"]) }
fn logs(n: &str) { let o=sudo(&["journalctl","-u","omnirs.service","-n",n,"--no-pager"]); if let Ok(o)=o { print!("{}",String::from_utf8_lossy(&o.stdout)); } }
fn ensure_binary() -> Result<(), String> {
    let p=Path::new(BIN);
    if !p.is_file() { return Err(format!("Бинарник не найден: {BIN}\nКомпиляция не выполняется. Соберите и скопируйте бинарник вручную.")); }
    if fs::metadata(p).map(|m|m.permissions().mode()&0o111==0).unwrap_or(true) { return Err(format!("Бинарник не исполняемый: {BIN} (chmod +x {BIN})")); }
    println!("  ✓ бинарник на месте: {BIN}"); Ok(())
}
fn backup(path: &str) { let suffix=SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(); let _=sudo(&["cp",path,&format!("{path}.bak.{suffix}")]); }
fn install_alias() -> Result<(),String> {
    let home=env::var("HOME").unwrap_or_else(|_|"/root".into()); let rc=PathBuf::from(home).join(".bashrc");
    let content=fs::read_to_string(&rc).unwrap_or_default(); let start="# >>> omnirs 0 >>>"; let end="# <<< omnirs 0 <<<";
    if content.contains(start) { println!("  ℹ  команда '0' уже установлена в {}",rc.display()); return Ok(()); }
    let self_path=env::current_exe().map_err(|e|e.to_string())?;
    if rc.exists() { let suffix=SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(); fs::copy(&rc,rc.with_extension(format!("bashrc.bak.{suffix}"))).ok(); }
    let mut f=OpenOptions::new().create(true).append(true).open(&rc).map_err(|e|e.to_string())?;
    writeln!(f,"\n{start}\n0() {{ \"{}\" installer \"$@\"; }}\n{end}",self_path.display()).map_err(|e|e.to_string())?;
    println!("    ✓ добавлена команда 0 в {}",rc.display()); Ok(())
}
fn ensure_service() -> Result<(),String> {
    if Path::new(UNIT).exists() {
        println!("  ℹ  {UNIT} уже на месте");
        let old=sudo_output(&["cat",UNIT]);
        if old.contains("OMNIRS_DB_PATH") || !old.contains("ExecStart=/root/OmniRS/OmniRS") || !old.contains("OMNIRS_DB_DIR=/root/OmniRS/db") {
            backup(UNIT);
            let mut c=Command::new("sudo").args(["tee",UNIT]).stdin(Stdio::piped()).stdout(Stdio::null()).spawn().map_err(|e|e.to_string())?;
            c.stdin.take().ok_or("stdin unavailable")?.write_all(SERVICE_UNIT.as_bytes()).map_err(|e|e.to_string())?;
            if !c.wait().map_err(|e|e.to_string())?.success(){return Err("Не удалось обновить systemd unit".into());}
        }
    } else {
        println!("  🔧 Установка {UNIT}...");
        let mut c=Command::new("sudo").args(["tee",UNIT]).stdin(Stdio::piped()).stdout(Stdio::null()).spawn().map_err(|e|e.to_string())?;
        c.stdin.take().ok_or("stdin unavailable")?.write_all(SERVICE_UNIT.as_bytes()).map_err(|e|e.to_string())?;
        if !c.wait().map_err(|e|e.to_string())?.success(){return Err("Не удалось записать systemd unit".into());}
        for name in ["override.conf","trace.conf"] { let p=format!("/etc/systemd/system/omnirs.service.d/{name}"); if Path::new(&p).exists(){println!("    🗑  удаляю остаточный drop-in: {name}"); let _=sudo(&["rm","-f",&p]);} }
        let _=sudo(&["rmdir","/etc/systemd/system/omnirs.service.d"]);
        println!("    ✓ unit установлен, enable");
    }
    if !sudo_ok(&["systemctl","daemon-reload"]) { return Err("systemctl daemon-reload завершился ошибкой".into()); }
    let _=sudo(&["systemctl","enable","omnirs.service"]);
    println!("  ⏹  Останавливаю omnirs.service перед рестартом");
    let _=sudo(&["systemctl","stop","omnirs.service"]); let _=sudo(&["systemctl","reset-failed","omnirs.service"]); Ok(())
}
fn ensure_dirs() -> Result<(),String> {
    if Path::new("/root/OmniRS/db").is_dir(){println!("  ℹ  директории уже на месте");}
    else { if !sudo_ok(&["mkdir","-p","/root/OmniRS/db"]){return Err("Не удалось создать /root/OmniRS/db".into());} println!("    ✓ директории созданы"); }
    Ok(())
}
fn ensure_swap() {
    const MB:u64=2048; let target=MB*1024*1024;
    let mem=fs::read_to_string("/proc/meminfo").ok().and_then(|s|s.lines().find(|l|l.starts_with("MemTotal:")).and_then(|l|l.split_whitespace().nth(1)?.parse::<u64>().ok())).map(|k|k/1024).unwrap_or(0);
    let size=fs::metadata("/swapfile").map(|m|m.len()).unwrap_or(0);
    let active=output("swapon", &["--show","--noheadings"]).lines().any(|l|l.split_whitespace().next()==Some("/swapfile"));
    if active && !fs::read_to_string("/etc/fstab").unwrap_or_default().lines().any(|l|l.split_whitespace().next()==Some("/swapfile")) { println!("  🔧 /swapfile активен, но отсутствует в /etc/fstab → добавляю"); append_root("/etc/fstab","/swapfile none swap sw 0 0\n"); }
    let sw=output("sysctl", &["-n","vm.swappiness"]).parse::<u32>().unwrap_or(60);
    if sw!=10 { let _=sudo(&["sysctl","-q","-w","vm.swappiness=10"]); let p="/etc/sysctl.d/99-swap.conf"; if !fs::read_to_string(p).unwrap_or_default().contains("vm.swappiness") { write_root(p,"vm.swappiness=10\n"); } println!("    ✓ vm.swappiness = 10 (было {sw})"); }
    if active && size==target { println!("  ℹ  swap уже 2048MB — ничего не меняю"); println!("{}",output("swapon", &["--show","--noheadings"])); return; }
    if active { println!("  🔧 swap активен ({}MB) — пересоздаю в 2048MB",size/1024/1024); let _=sudo(&["swapoff","/swapfile"]); }
    if Path::new("/swapfile").exists(){let _=sudo(&["rm","-f","/swapfile"]);}
    println!("  🔧 Создаю /swapfile 2048MB (RAM={mem}MB)...");
    if !sudo_ok(&["fallocate","-l","2048M","/swapfile"]) { println!("    fallocate не сработал → dd..."); if !sudo_ok(&["dd","if=/dev/zero","of=/swapfile","bs=1M","count=2048","status=progress"]) {println!("    ⚠  dd провалился — swap не создан");let _=sudo(&["rm","-f","/swapfile"]);return;} }
    let _=sudo(&["chmod","600","/swapfile"]);
    if !sudo_ok(&["mkswap","/swapfile"]) {println!("    ⚠  mkswap провалился — swap не создан");let _=sudo(&["rm","-f","/swapfile"]);return;}
    if !sudo_ok(&["swapon","/swapfile"]) {println!("    ⚠  swapon провалился — swap не активирован");return;}
    println!("    ✓ swap 2048MB активирован");
    if !fs::read_to_string("/etc/fstab").unwrap_or_default().lines().any(|l|l.split_whitespace().next()==Some("/swapfile")){append_root("/etc/fstab","/swapfile none swap sw 0 0\n");}
    println!("    итог:\n{}",output("swapon", &["--show","--noheadings"]));
}
fn write_root(path:&str,data:&str) { if let Ok(mut c)=Command::new("sudo").args(["tee",path]).stdin(Stdio::piped()).stdout(Stdio::null()).spawn(){if let Some(mut i)=c.stdin.take(){let _=i.write_all(data.as_bytes());}let _=c.wait();} }
fn append_root(path:&str,data:&str) { if let Ok(mut c)=Command::new("sudo").args(["tee","-a",path]).stdin(Stdio::piped()).stdout(Stdio::null()).spawn(){if let Some(mut i)=c.stdin.take(){let _=i.write_all(data.as_bytes());}let _=c.wait();} }
fn valid_ipv4(s:&str)->bool { s.parse::<Ipv4Addr>().is_ok() }
fn detect_ip() -> String { let ip=output("curl", &["-4","-s","--max-time","3","https://ifconfig.me"]); if valid_ipv4(&ip){return ip;} let local=output("hostname", &["-I"]); let first=local.split_whitespace().next().unwrap_or(""); if valid_ipv4(first){first.into()}else{"0.0.0.0".into()} }
fn detect_fresh_db() -> bool {
    if !Path::new(DB).is_file(){return true;}
    let conn=match rusqlite::Connection::open(DB){Ok(c)=>c,Err(e)=>{println!("  ⚠  Не удалось прочитать БД ({e}) — считаю как fresh");return true;}};
    let token=conn.query_row("SELECT value FROM config WHERE key='admin_token'",[],|r|r.get::<_,String>(0)).unwrap_or_default();
    if token.is_empty(){println!("  ⚠  БД есть, но admin_token пустой → считаю как fresh");true}else{false}
}
fn ensure_initial_config(yes:bool)->Context {
    let fresh=detect_fresh_db(); if !fresh {println!("  ℹ  БД уже существует — пароль/IP не перезаписываю");println!("     (изменить пароль: POST /api/db/config {{\"admin_token\":\"...\"}})");println!("     (полный сброс:      sudo rm -rf /root/OmniRS/db && повторный Install)");return Context{admin_password:None,detected_ip:None,fresh};}
    println!("  🆕 Первая установка — настраиваю пароль администратора и IP");
    let pw=if yes||!io::stdin().is_terminal(){println!("    ⏭  пароль = {DEFAULT_PASSWORD} (по умолчанию)");DEFAULT_PASSWORD.to_string()}else{let v=read_line("  🔑 Пароль администратора [Enter = 16121993]: ").unwrap_or_default();if v.is_empty(){DEFAULT_PASSWORD.into()}else{v}};
    if pw==DEFAULT_PASSWORD{println!("    → пароль: по умолчанию (16121993)");}else{println!("    → пароль: задан пользователем");}
    let detected=detect_ip(); let ip=if yes||!io::stdin().is_terminal(){println!("    ⏭  IP = {detected}");detected.clone()}else{let prompt=if detected=="0.0.0.0"{format!("  🌐 Публичный IP (Enter = {detected}): ")}else{format!("  🌐 Публичный IP [{detected}] (Enter = {detected}): ")};let v=read_line(&prompt).unwrap_or_default();if v.is_empty(){detected.clone()}else{v}};
    let ip=if valid_ipv4(&ip){ip}else{println!("    ⚠  некорректный IP '{ip}' → 0.0.0.0");"0.0.0.0".into()}; println!("    → address: {ip}"); Context{admin_password:Some(pw),detected_ip:Some(ip),fresh}
}
fn seed_db(ctx:&Context) {
    let Some(pw)=ctx.admin_password.as_ref() else {println!("  ⏭  апгрейд — БД уже настроена, seed пропущен");return;};
    if !Path::new(BIN).is_file(){println!("  ⚠  бинарь не найден — seed пропущен");return;}
    println!("  🌱 Инициализация БД (admin_token, address)...");let _=sudo(&["mkdir","-p","/root/OmniRS/db"]);
    let ip=ctx.detected_ip.as_deref().unwrap_or("0.0.0.0");
    let log=std::env::temp_dir().join(format!("omnirs-seed-{}.log",std::process::id()));
    let file=match fs::File::create(&log){Ok(f)=>f,Err(e)=>{println!("    ⚠  не удалось создать seed log: {e}");return;}};
    let status=Command::new("sudo").arg("-E").arg(BIN).args(["config","test"]).current_dir(ROOT).env("OMNIRS_DB_DIR","/root/OmniRS/db").env("OMNIRS_ADMIN_TOKEN",pw).env("OMNIRS_ADDR",ip).stdout(Stdio::from(file)).stderr(Stdio::null()).status();
    match status {Ok(s) if s.success()=>{println!("    ✓ БД инициализирована (admin_token, address)");if let Ok(t)=fs::read_to_string(&log){if let Some(l)=t.lines().filter(|l|l.contains("Configuration")).last(){println!("    {l}");}}},Ok(s)=>{println!("    ⚠  seed вернул код {} (проверьте лог)",s.code().unwrap_or(-1));if let Ok(t)=fs::read_to_string(&log){for l in t.lines().rev().take(15).collect::<Vec<_>>().into_iter().rev(){println!("    {l}");}}},Err(e)=>println!("    ⚠  seed не запустился: {e}")};let _=fs::remove_file(log);
}
fn change_password()->Result<(),String>{
    if !Path::new(DB).is_file(){return Err(format!("БД не найдена: {DB}\nСначала выполните Install."));}
    let c=rusqlite::Connection::open(DB).map_err(|e|e.to_string())?;
    let current=c.query_row("SELECT value FROM config WHERE key='admin_token'",[],|r|r.get::<_,String>(0)).unwrap_or_default();
    if !current.is_empty(){println!("  🔑 Текущий пароль: {}... (показаны первые 6 символов)",current.chars().take(6).collect::<String>());}else{println!("  ⚠️  В БД нет admin_token (пустой) — пароль не установлен.");}
    if !io::stdin().is_terminal(){return Err("требуется TTY для ввода пароля. Запустите интерактивно.".into());}
    let mut pw=read_line("  🔐 Новый пароль администратора [Enter = 16121993]: ").map_err(|e|e.to_string())?;if pw.is_empty(){pw=DEFAULT_PASSWORD.into();}if pw.chars().count()<6{return Err("пароль слишком короткий (минимум 6 символов)".into());}
    c.execute("INSERT INTO config(key,value,updated_at) VALUES('admin_token',?1,CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP",[pw]).map_err(|e|format!("не удалось обновить admin_token: {e}"))?;println!("  ✓ admin_token обновлён");
    if is_active(){let ans=read_line("  🔄 Перезапустить omnirs.service чтобы сбросить сессии? [Y/n] ").unwrap_or_default();if ans.is_empty()||ans.eq_ignore_ascii_case("y"){if sudo_ok(&["systemctl","restart","omnirs.service"]){println!("  ✓ сервис перезапущен");}else{println!("  ⚠  рестарт не удался (проверьте journalctl -u omnirs -n 30)");}}}
    println!("\n  ✅ Пароль администратора успешно изменён.\n     Используйте его для входа в админку: https://<host>:800\n\n     Сброс: sudo systemctl stop omnirs && sudo rm -rf /root/OmniRS/db");Ok(())
}
fn parse_args(args:&[String])->Result<Options,String>{let mut o=Options{no_clear:false,yes:false};for a in args{match a.as_str(){"--no-clear"=>o.no_clear=true,"--yes"|"-y"=>o.yes=true,"-h"|"--help"=>{println!("Usage: OmniRS installer [OPTIONS]\n\n--no-clear  не очищать экран\n--yes, -y   без меню (Install; пароль 16121993)\n-h, --help  справка\n\nКомпиляция не выполняется. Бинарник {BIN} должен существовать и быть исполняемым. ritual.sh не используется и не изменяется.");std::process::exit(0)},_=>return Err(format!("❌ неизвестный флаг: {a} (см. --help)"))}}Ok(o)}
fn menu()->Option<Mode>{let (status,toggle)=if is_active(){(format!("● active (PID {})",pid()),"Stop")}else{("○ inactive".into(),"Start")};println!("╔═════════════════════════\n   🕸️  OmniRS\n╠════════════════════════════\n   Сервис: {status}\n╠════════════════════════════════\n   1) Install         — pre-flight + seed + start + health\n   2) Restart         — только рестарт сервиса\n   3) {toggle:<15} — {}\n   4) Status          — статус + последние логи\n   6) Passwd          — изменить пароль администратора\n   0) Cancel          — выход\n╚════════════════════════════════════════",if toggle=="Stop"{"остановить сервис"}else{"запустить сервис"});match read_line("  > ").unwrap_or_default().as_str(){"1"=>Some(Mode::Install),"2"=>Some(Mode::Restart),"3"=>Some(if is_active(){Mode::Stop}else{Mode::Start}),"4"=>Some(Mode::Status),"6"=>Some(Mode::Passwd),"0"|"q"|"Q"|""=>None,v=>{println!("  ❌ неизвестный выбор: {v}");None}}}
fn bar(pct:u64,label:&str,elapsed:u64){let n=(pct.min(100)*32/100) as usize;let mut b="=".repeat(n);if n<32{b.push('>');}while b.len()<32{b.push(' ');}println!("  [{b}] {:3}%  {label}  ⏱ {}",pct.min(100),fmt_time(elapsed));}
fn stopwatch(start:Instant)->Option<thread::JoinHandle<()>>{if !io::stdout().is_terminal()||env::var("TERM").unwrap_or_default()=="dumb"{return None;}Some(thread::spawn(move||loop{print!("\x1b]0;⏱ {} — OmniRS\x07",fmt_time(start.elapsed().as_secs()));let _=io::stdout().flush();thread::sleep(Duration::from_secs(1));}))}
fn stop_watch(h:Option<thread::JoinHandle<()>>,elapsed:u64){if let Some(h)=h{ // thread is intentionally detached from process lifetime; process exits after installer returns
    let _=h.thread().id();print!("\x1b]0;✓ OmniRS — {}\x07",fmt_time(elapsed));let _=io::stdout().flush();}}
fn print_status(){println!("ℹ️  Status omnirs.service\n");let o=run("systemctl", &["status","omnirs.service","--no-pager"]);if let Ok(o)=o{print!("{}",String::from_utf8_lossy(&o.stdout));}println!("\n── последние 20 строк лога ──");logs("20");}

/// Entry point called by `OmniRS installer [--no-clear] [--yes|-y]`.
pub fn run_installer(args:&[String])->i32{
    let opts=match parse_args(args){Ok(v)=>v,Err(e)=>{eprintln!("{e}");return 1;}};
    let mut menu_shown=false;
    let mode=if !opts.yes&&io::stdin().is_terminal()&&args.is_empty(){clear(opts.no_clear);menu_shown=true;match menu(){Some(m)=>m,None=>{println!("  отменено.");return 0;}}}else{Mode::Install};
    match mode{Mode::Start=>{clear(opts.no_clear);println!("▶️  Start omnirs.service");if sudo_ok(&["systemctl","start","omnirs.service"]){thread::sleep(Duration::from_secs(1));println!("  ✓ {}",output("systemctl", &["is-active","omnirs.service"]));let p=pid();if !p.is_empty()&&p!="0"{println!("  PID={p}");}0}else{println!("  ❌ не удалось");logs("20");1}},Mode::Stop=>{clear(opts.no_clear);println!("⏹  Stop omnirs.service");if sudo_ok(&["systemctl","stop","omnirs.service"]){println!("  ✓ {}",output("systemctl", &["is-active","omnirs.service"]));0}else{println!("  ❌ не удалось");1}},Mode::Status=>{clear(opts.no_clear);print_status();0},Mode::Passwd=>{clear(opts.no_clear);println!("🔑 Изменение пароля администратора\n");match change_password(){Ok(())=>0,Err(e)=>{eprintln!("  ❌ {e}");1}}},_=>{
        let total=Instant::now();let started=chrono::Local::now().format("%H:%M:%S").to_string();let sw=stopwatch(total);let mut stages:Vec<Stage>=Vec::new();let ctx;
        if mode==Mode::Install{
            clear(opts.no_clear||menu_shown);println!("🕸️  OmniRS • mode=install • старт в {started}\n");
            let t=Instant::now();println!("🔧 [pre] Проверка бинарника (сборка больше не выполняется)");if let Err(e)=ensure_binary(){eprintln!("{e}");stop_watch(sw, total.elapsed().as_secs());return 1;}stages.push(Stage{name:"binary",seconds:t.elapsed().as_secs()});println!("    [{}]\n",fmt_time(t.elapsed().as_secs()));
            let t=Instant::now();let ram=fs::read_to_string("/proc/meminfo").ok().and_then(|s|s.lines().find(|l|l.starts_with("MemTotal:")).and_then(|l|l.split_whitespace().nth(1)?.parse::<u64>().ok())).map(|v|v/1024).unwrap_or(0);println!("🔧 [pre] Swap — RAM {ram}MB");ensure_swap();stages.push(Stage{name:"swap",seconds:t.elapsed().as_secs()});println!("    [{}]\n",fmt_time(t.elapsed().as_secs()));
            let t=Instant::now();println!("🔧 [pre] Прикручиваю команду '0' в ~/.bashrc");if let Err(e)=install_alias(){println!("  ⚠  {e}");}stages.push(Stage{name:"alias",seconds:t.elapsed().as_secs()});println!("    [{}]\n",fmt_time(t.elapsed().as_secs()));
            let t=Instant::now();println!("🔧 [pre] Настраиваю 😈 демонов");if let Err(e)=ensure_service(){eprintln!("  ❌ {e}");stop_watch(sw,total.elapsed().as_secs());return 1;}stages.push(Stage{name:"service",seconds:t.elapsed().as_secs()});println!("    [{}]\n",fmt_time(t.elapsed().as_secs()));
            let t=Instant::now();println!("🔧 [pre] Прокладываю трубы");if let Err(e)=ensure_dirs(){eprintln!("  ❌ {e}");stop_watch(sw,total.elapsed().as_secs());return 1;}stages.push(Stage{name:"dirs",seconds:t.elapsed().as_secs()});println!("    [{}]\n",fmt_time(t.elapsed().as_secs()));
            let t=Instant::now();println!("🔧 [pre] Пароль администратора + публичный IP");ctx=ensure_initial_config(opts.yes);stages.push(Stage{name:"admin-pw",seconds:t.elapsed().as_secs()});println!("    [{}]",fmt_time(t.elapsed().as_secs()));bar(8,"pre-flight ✓",total.elapsed().as_secs());println!();
        }else{ctx=Context{admin_password:None,detected_ip:None,fresh:false};}
        let t=Instant::now();println!("🧹 [1/4] Очистка мусора...");let _=sudo(&["systemctl","stop","systemd-journald"]);let _=sudo(&["find","/var/log/journal","-mindepth","1","-delete"]);let _=sudo(&["find","/run/log/journal","-mindepth","1","-delete"]);let _=sudo(&["systemctl","start","systemd-journald"]);stages.push(Stage{name:"journal",seconds:t.elapsed().as_secs()});println!("    ✓ Мусор очищен и вынесен  [{}]",fmt_time(t.elapsed().as_secs()));bar(10,"journald ✓",total.elapsed().as_secs());
        let t=Instant::now();if mode==Mode::Install{println!("🌱 [2/4] Seed DB (пароль + IP в OmniDB)");seed_db(&ctx);}else{println!("⏭  [2/4] Seed DB — пропущено (mode=restart)");}stages.push(Stage{name:"seed",seconds:t.elapsed().as_secs()});println!("    [{}]",fmt_time(t.elapsed().as_secs()));bar(55,if mode==Mode::Install{"seed ✓"}else{"seed (пропущено)"},total.elapsed().as_secs());
        let t=Instant::now();println!("🔄 [3/4] Выпускаю 😈 демонов");let _=sudo(&["systemctl","reset-failed","omnirs.service"]);let started_ok=sudo_ok(&["systemctl","start","omnirs.service"]);if started_ok{for _ in 0..20{if is_active(){break;}thread::sleep(Duration::from_secs(1));}}
        if !is_active(){stages.push(Stage{name:"restart",seconds:t.elapsed().as_secs()});eprintln!("❌ Сервис не поднялся за {} — последние логи:",fmt_time(t.elapsed().as_secs()));logs("30");stop_watch(sw,total.elapsed().as_secs());return 1;}
        stages.push(Stage{name:"restart",seconds:t.elapsed().as_secs()});println!("    ✓ сервис запущен и активен  [{}]",fmt_time(t.elapsed().as_secs()));bar(92,"restart ✓",total.elapsed().as_secs());
        let t=Instant::now();println!("📜 [4/4] Чеклист:\n{}\n\n── последние 30 строк лога ──",output("systemctl", &["is-active","omnirs.service"]));logs("30");stages.push(Stage{name:"logs",seconds:t.elapsed().as_secs()});println!("    [{}]",fmt_time(t.elapsed().as_secs()));bar(100,"статус ✓",total.elapsed().as_secs());
        let elapsed=total.elapsed().as_secs();println!();let p=pid();if !p.is_empty()&&p!="0"{println!("✅ Сервис работает. PID={p}");println!("   exe → {}",fs::read_link(format!("/proc/{p}/exe")).map(|p|p.display().to_string()).unwrap_or_default());}else{println!("⚠️  MainPID=0 — сервис не запущен");}
        if let Some(pw)=ctx.admin_password.as_ref(){println!("\n🔑 Админ:\n   пароль: {} — изменён через POST /api/db/config\n   адрес:  {}",if pw==DEFAULT_PASSWORD{"по умолчанию (16121993)"}else{"задан"},ctx.detected_ip.as_deref().unwrap_or("0.0.0.0"));}
        println!("\n📊 Сводка по этапам:");for s in &stages{println!("   {:<10} {}",s.name,fmt_time(s.seconds));}println!("   ─────────────────────────\n   {:<10} {}\n\n🏁 Завершено в {}", "TOTAL",fmt_time(elapsed),chrono::Local::now().format("%H:%M:%S"));stop_watch(sw,elapsed);0
    }}
}
