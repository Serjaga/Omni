import { $, esc, spinner, errBox } from './app.js';

export async function mount(c){
  c.innerHTML=`<div class="welcome"><div><h2>OmniRS</h2><p>Панель управления · готово к настройке</p></div><div class="welcome-art">🕸</div></div>`;
}