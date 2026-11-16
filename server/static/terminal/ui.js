import { dom } from './state.js';

export function positionWeb() {
  const bannerRect = dom.banner.getBoundingClientRect();
  const headerRect = document.querySelector('.header').getBoundingClientRect();
  const rightOffset = headerRect.right - bannerRect.right;
  dom.webEl.style.right = (rightOffset - 10) + 'px';
  dom.webEl.style.top = '5px';
}

export function startRain() {
  const SYM = ['$','€','£','¥','₹','₽','₿','Ξ','Ł','₳','₸','₡','＄','￠','￡','￥','￦'];
  setInterval(() => {
    if (dom.rainBox.children.length > 110) return;
    const d = document.createElement('div');
    d.className = 'raindrop';
    d.textContent = SYM[Math.floor(Math.random() * SYM.length)];
    d.style.left = (Math.random() * 100).toFixed(2) + '%';
    d.style.setProperty('--o', (Math.random() * 0.4 + 0.3).toFixed(2));
    d.style.fontSize = (Math.random() * 10 + 15).toFixed(0) + 'px';
    const dx = () => ((Math.random() - 0.5) * 80).toFixed(1) + 'px';
    ['--dx1','--dx2','--dx3','--dx4'].forEach(v => d.style.setProperty(v, dx()));
    const rot = () => ((Math.random() - 0.5) * 720).toFixed(0) + 'deg';
    ['--r1','--r2','--r3','--r4'].forEach(v => d.style.setProperty(v, rot()));
    const dur = Math.random() * 7 + 3.5;
    d.style.animationDuration = dur.toFixed(2) + 's';
    d.style.animationDelay = (Math.random() * 0.6).toFixed(2) + 's';
    dom.rainBox.appendChild(d);
    setTimeout(() => { if (d.parentNode === dom.rainBox) dom.rainBox.removeChild(d); }, dur * 1000 + 1000);
  }, 90);
}

export function startClock() {
  const tick = () => {
    const d = new Date();
    dom.clockEl.textContent = d.toLocaleTimeString('ru-RU', { hour12: false }) + ' · ' + d.toLocaleDateString('ru-RU');
  };
  tick(); setInterval(tick, 1000);
}

export function syncViewport() {
  const vv = window.visualViewport;
  const h = vv ? vv.height : window.innerHeight;
  const t = vv ? vv.offsetTop : 0;
  document.documentElement.style.setProperty('--app-height', h + 'px');
  document.documentElement.style.setProperty('--app-top', t + 'px');
  requestAnimationFrame(() => { dom.terminal.scrollTop = dom.terminal.scrollHeight; });
}

export function preventZoom() {
  ['gesturestart','gesturechange','gestureend'].forEach(ev =>
    document.addEventListener(ev, e => e.preventDefault(), { passive: false }));
  document.addEventListener('touchstart', e => { if (e.touches && e.touches.length > 1) e.preventDefault(); }, { passive: false });
  document.addEventListener('touchmove', e => { if (e.touches && e.touches.length > 1) e.preventDefault(); }, { passive: false });
  document.addEventListener('wheel', e => { if (e.ctrlKey) e.preventDefault(); }, { passive: false });
  document.addEventListener('dblclick', e => e.preventDefault(), { passive: false });
}