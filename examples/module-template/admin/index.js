export function mount(container) {
  container.innerHTML = `
    <section class="card">
      <h3>Example module</h3>
      <p>Административный интерфейс загружен из ZIP-пакета.</p>
      <button class="button" id="exampleHealth">Проверить модуль</button>
      <pre id="exampleResult"></pre>
    </section>`;
  container.querySelector('#exampleHealth').onclick = async () => {
    const out = container.querySelector('#exampleResult');
    try {
      const response = await fetch('/api/example-module/health', { credentials: 'same-origin' });
      out.textContent = await response.text();
    } catch (error) { out.textContent = error.message; }
  };
}
