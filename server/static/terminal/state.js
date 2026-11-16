// Shared mutable state + cached DOM references
export const st = {
  mode: 'shell',
  activeTab: 'map',
  consoleOutput: null,
  leakRunning: false,
  leakCancelled: false,
  hack: { scanned:false, connected:false, exploited:false, cracked:false, dumped:false },
  history: [],
};

export const dom = {
  terminal:           document.getElementById('terminal'),
  terminalContainer:  document.getElementById('terminal-container'),
  inputEl:            document.getElementById('input'),
  inputLineEl:        document.getElementById('inputLine'),
  promptEl:           document.getElementById('prompt'),
  rainBox:            document.getElementById('money-rain'),
  clockEl:            document.getElementById('clock'),
  webEl:              document.getElementById('web'),
  borderEl:           document.getElementById('ascii-border'),
  navDock:            document.getElementById('navDock'),
  banner:             document.getElementById('banner'),
};