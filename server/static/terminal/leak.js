import { st, dom } from './state.js';
import { escapeHtml, addLine, sleep } from './utils.js';
import { fetchVisitorIP } from './api.js';

function getKZTime() {
  try {
    return new Intl.DateTimeFormat('ru-RU', {
      timeZone: 'Asia/Almaty', hour12: false,
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    }).format(new Date());
  } catch(_) {
    return new Date().toLocaleTimeString('ru-RU', { hour12: false });
  }
}

function leakAddLine(text, color) {
  const ts = getKZTime();
  return addLine(`<span style="color:#666">[${ts}]</span> <span style="color:${color||'#f00'}">${escapeHtml(text)}</span>`);
}

function showLeakIntro() {
  return new Promise(resolve => {
    const overlay = document.createElement('div');
    overlay.style.cssText = [
      'position:absolute','inset:0','background:#fff','z-index:100',
      'display:flex','flex-direction:column','justify-content:center',
      'align-items:center','text-align:center','padding:16px',
      "font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif",
      'transition:opacity 0.6s ease-out',
    ].join(';');
    overlay.innerHTML =
      '<h1 style="color:#333;margin:8px 0;font-size:clamp(16px,4.5vw,28px);opacity:0.9;line-height:1.3;font-weight:bold;">' +
      'вы думаете это обычная страница</h1>' +
      '<h2 style="color:#333;margin:8px 0;font-size:clamp(16px,4.5vw,28px);opacity:0.9;line-height:1.3;font-weight:bold;">' +
      'но вот что происходит в невидимом фоновом режиме</h2>';
    dom.terminalContainer.appendChild(overlay);
    setTimeout(() => {
      overlay.style.opacity = '0';
      setTimeout(() => { overlay.remove(); resolve(); }, 600);
    }, 2500);
  });
}

export async function cmdLeak(renderTab) {
  if (st.leakRunning) return;
  st.leakRunning = true;
  st.leakCancelled = false;
  dom.inputEl.value = '';

  const checkCancel = () => { if (st.leakCancelled) throw new Error('cancelled'); };

  try {
    await showLeakIntro();
    checkCancel();

    dom.terminal.classList.add('leak-mode');
    dom.terminal.innerHTML = '';
    st.consoleOutput = null;

    addLine('<div style="text-align:center;color:#f00;font-size:clamp(18px,4vw,32px);font-weight:bold;text-shadow:0 0 16px #f00;animation:leak-pulse 2s infinite;letter-spacing:1px;margin-bottom:8px;">⚠ ВНИМАНИЕ! ДАННЫЕ УТЕКАЮТ ПРЯМО СЕЙЧАС ⚠</div>');
    addLine('<div style="text-align:center;color:#ff0;text-shadow:0 0 10px #ff0;margin-bottom:14px;">Дата: ' + new Date().toLocaleDateString('ru-RU') + '</div>');

    const opening = [
      ['[СИСТЕМА] Обнаружена несанкционированная активность...',800,''],
      ['[ХАКЕР] Установка удалённого соединения...',1000,''],
      ['[ПОДКЛЮЧЕНИЕ] Ожидание ответа от устройства жертвы...',1200,''],
      ['[УСПЕХ] Подключение к устройству установлено',1500,'#0f0'],
      ['[ИНФИЛЬТРАЦИЯ] Подключение к WhatsApp...',1200,'#0ff'],
      ['[УСПЕХ] Сессия WhatsApp захвачена',1200,'#0f0'],
      ['[ЭКСФИЛЬТРАЦИЯ] Извлекаются чаты, медиа, контактные данные...',1000,'#ff0'],
      ['[ИНФИЛЬТРАЦИЯ] Подключение к Telegram...',1100,'#0ff'],
      ['[УСПЕХ] Telegram-сессия скомпрометирована',1300,'#0f0'],
      ['[ЭКСФИЛЬТРАЦИЯ] Перехват переписок, каналов, личных данных...',1100,'#ff0'],
    ];
    for (const [text, delay, color] of opening) {
      await sleep(delay); checkCancel();
      leakAddLine(text, color);
    }

    await sleep(1000); checkCancel();
    const phonesCount = 150 + Math.floor(Math.random() * 751);
    leakAddLine(`[ДАННЫЕ] Извлечено номеров телефонов из WhatsApp и Telegram: ${phonesCount}`, '#ff0');

    await sleep(1400); checkCancel();
    leakAddLine('[ВЗЛОМ] Попытка доступа к Kaspi Bank...', '#0ff');
    await sleep(1500); checkCancel();
    leakAddLine('[ДОСТУП] Успешная аутентификация через уязвимость в приложении', '#0f0');
    await sleep(1200); checkCancel();
    leakAddLine('[ДАННЫЕ] Извлекается банковская карта...', '#ff0');
    await sleep(1000); checkCancel();
    leakAddLine('[РЕЗУЛЬТАТ] Найдена банковская карта в Kaspi: 1', '#0f0');

    await sleep(1200); checkCancel();
    leakAddLine('[ПЕРЕДАЧА] Начата передача данных...', '#0f0');
    dom.terminalContainer.classList.add('leak-shake');

    await sleep(800); checkCancel();
    leakAddLine('[ПЕРЕДАЧА] Передача телефонных номеров...', '');

    let displayed = 0;
    while (displayed < phonesCount) {
      await sleep(300); checkCancel();
      const batch = Math.min(30 + Math.floor(Math.random() * 51), phonesCount - displayed);
      displayed += batch;
      leakAddLine(`[ПЕРЕДАЧА] Загружено номеров: ${displayed} из ${phonesCount} (+${batch})`, '#ff0');
    }

    await sleep(500); checkCancel();
    leakAddLine('[ГОТОВО] Все телефонные номера переданы', '#0f0');
    await sleep(800); checkCancel();
    leakAddLine('[ПЕРЕДАЧА] Передача данных Kaspi Bank...', '#0f0');
    await sleep(1200); checkCancel();
    leakAddLine('[ГОТОВО] Передача данных банковской карты завершена', '#0f0');
    await sleep(1000); checkCancel();
    leakAddLine('[СООБЩЕНИЕ] Все данные успешно переданы', '#0f0');

    await sleep(2000); checkCancel();
    leakAddLine('[ОТКЛЮЧЕНИЕ] Отключение от устройства...', '');
    await sleep(500); checkCancel();
    leakAddLine('[ОЧИСТКА] Удаление временных файлов и логов...', '');
    await sleep(500); checkCancel();
    leakAddLine('[ОЧИСТКА] Полная очистка следов проникновения...', '#0f0');

    dom.terminalContainer.classList.remove('leak-shake');
    dom.terminalContainer.classList.add('leak-intense');
    await sleep(1500); checkCancel();

    const allLines = Array.from(dom.terminal.querySelectorAll('.line'));
    const totalLines = allLines.length;
    const fadeDuration = 3000;
    const interval = totalLines ? fadeDuration / totalLines : 0;
    allLines.forEach((line, i) => {
      setTimeout(() => { line.classList.add('leak-fadeout'); }, i * interval);
    });
    await sleep(fadeDuration + 400); checkCancel();

    dom.terminalContainer.classList.remove('leak-shake', 'leak-intense');
    dom.terminal.innerHTML = '';

    addLine('<div style="text-align:center;color:#0f0;font-size:clamp(28px,4.5vw,40px);margin-top:8vh;">спасибо :)</div>');
    await sleep(900); checkCancel();

    addLine('<div style="text-align:center;color:#ff0;font-size:clamp(14px,1.6vw,20px);text-shadow:0 0 10px #ff0;line-height:1.4;">СЛИШКОМ ПОЗДНО. ЗАКРЫВАТЬ СТРАНИЦУ — ВАШИ ДАННЫЕ В НАДЁЖНЫХ РУКАХ.</div>');
    await sleep(500); checkCancel();

    const ip = await fetchVisitorIP();
    checkCancel();
    addLine('<div style="text-align:center;color:#0ff;font-size:clamp(14px,1.7vw,18px);text-shadow:0 0 10px #0ff;">Ваш IP: ' + escapeHtml(ip) + '</div>');

    const wrap = document.createElement('div');
    wrap.className = 'leak-return-wrap';
    wrap.innerHTML = '<button class="leak-return-btn" id="leakReturnBtn">🏠 На главный экран</button>';
    dom.terminal.appendChild(wrap);
    document.getElementById('leakReturnBtn').onclick = () => renderTab('map');
    dom.terminal.scrollTop = dom.terminal.scrollHeight;
  } catch(e) {
    // cancelled — тихо игнорируем
  } finally {
    st.leakRunning = false;
    st.leakCancelled = false;
    dom.inputEl.focus();
  }
}