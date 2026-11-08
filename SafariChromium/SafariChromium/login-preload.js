const { ipcRenderer } = require('electron');

const loginFieldSelector = [
  'input[type="password"]',
  'input[autocomplete="username"]',
  'input[autocomplete="current-password"]',
  'input[type="email"]',
  'input[name*="user" i]',
  'input[name*="login" i]',
].join(',');

document.addEventListener('focusin', (event) => {
  const field = event.target;
  if (!(field instanceof HTMLInputElement) || !field.matches(loginFieldSelector)) return;
  const bounds = field.getBoundingClientRect();
  if (!bounds.width || !bounds.height) return;
  ipcRenderer.send('login-field-focus', {
    x: Math.round(bounds.left),
    y: Math.round(bounds.bottom),
  });
}, true);