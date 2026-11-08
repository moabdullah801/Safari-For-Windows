// Safari (Chromium) - main process.
// Each window hosts its own Chromium tabs (WebContentsView), tab groups and
// a privacy layer (tracker blocking, Do Not Track / GPC headers).
const { app, BrowserWindow, WebContentsView, ipcMain, session, clipboard, Menu, dialog, safeStorage, shell } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { fileURLToPath } = require('url');

const CHROME_HEIGHT = 92;   // toolbar (52px) + tab strip (40px), must match styles.css
const HOME_PAGE = 'safari://newtab';
const SEARCH_ENGINES = {
  google: 'https://www.google.com/search?q=',
  duckduckgo: 'https://duckduckgo.com/?q=',
  bing: 'https://www.bing.com/search?q=',
};
const GROUP_COLORS = ['#ff453a', '#ff9f0a', '#ffd60a', '#32d74b', '#64d2ff', '#0a84ff', '#bf5af2', '#ff375f'];
const SETTINGS_DEFAULTS = {
  theme: 'system',
  searchEngine: 'google',
  javascriptEnabled: true,
  ublockEnabled: true,
  webAssemblyEnabled: true,
  hardwareAcceleration: true,
};

// Packaged apps keep files in app.asar, but Chromium can only load extensions
// from real folders, so use the unpacked copy when running from an installer.
const appDir = __dirname.replace('app.asar', 'app.asar.unpacked');
const UBLOCK_DIR = path.join(appDir, 'extensions', 'ublock0');

// Tracker / ad / malware hosts, generated from uBlock Origin's own filter lists
// (run `node tools/build-blocklist.js` to rebuild). Requests to them are
// cancelled; page navigations are never blocked.
const BLOCKED_HOSTS = new Set();
try {
  const file = path.join(__dirname, 'blocklist.txt');
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    if (line) BLOCKED_HOSTS.add(line);
  }
} catch (_) { /* blocklist.txt missing: only the extension will block */ }

// Loaded uBlock Origin extension per session (null if it failed to load).
const ublockIds = new WeakMap();

let blockerOn = true;
let trackersBlocked = 0;
let lastBlockedSent = -1;
let nextTabId = 1;
let nextGroupId = 1;
const windows = new Set();
const settingsWindows = new Set();
const configuredSessions = new WeakSet();

const settingsFile = path.join(app.getPath('userData'), 'settings.json');
let settings = { ...SETTINGS_DEFAULTS };
try {
  const saved = JSON.parse(fs.readFileSync(settingsFile, 'utf8'));
  settings = { ...settings, ...saved };
} catch (_) { /* first run */ }
if (settings.theme === 'light' || settings.theme === 'dark' || settings.theme === 'system') {
  // Keep the saved theme selection.
} else {
  settings.theme = SETTINGS_DEFAULTS.theme;
}
if (!Object.hasOwn(SEARCH_ENGINES, settings.searchEngine)) settings.searchEngine = 'google';
if (settings.hardwareAcceleration === false) app.disableHardwareAcceleration();
if (settings.webAssemblyEnabled === false) app.commandLine.appendSwitch('js-flags', '--no-expose-wasm');

const vaultFile = path.join(app.getPath('userData'), 'passwords.enc');

function saveSettings() {
  try {
    fs.mkdirSync(path.dirname(settingsFile), { recursive: true });
    fs.writeFileSync(settingsFile, JSON.stringify(settings, null, 2));
    return true;
  } catch (err) {
    console.warn('Could not save settings:', err && err.message);
    return false;
  }
}

// ---------- history (normal windows only) ----------
const historyFile = path.join(app.getPath('userData'), 'history.json');
let history = [];
try { history = JSON.parse(fs.readFileSync(historyFile, 'utf8')); } catch (_) { /* first run */ }

function recordHistory(url, title) {
  if (history.length && history[history.length - 1].url === url) return;
  history.push({ url, title, time: Date.now() });
  history = history.slice(-500);
  try { fs.writeFileSync(historyFile, JSON.stringify(history)); } catch (_) { /* best effort */ }
}

function clearHistory() {
  history = [];
  try { fs.writeFileSync(historyFile, '[]'); } catch (_) { /* best effort */ }
}

// ---------- privacy ----------
// True if host, or any parent domain of it, is on the blocklist.
function hostListed(host) {
  const parts = host.split('.');
  for (let i = 0; i < parts.length - 1; i++) {
    if (BLOCKED_HOSTS.has(parts.slice(i).join('.'))) return true;
  }
  return false;
}

// Rough "same site" test so a site's own subdomains are never blocked.
function sameSite(a, b) {
  if (a === b || a.endsWith('.' + b) || b.endsWith('.' + a)) return true;
  const tail = (h) => h.split('.').slice(-2).join('.');
  return tail(a) === tail(b);
}

function isTracker(details) {
  if (details.resourceType === 'mainFrame') return false;
  let host;
  try { host = new URL(details.url).hostname; } catch (_) { return false; }
  if (!hostListed(host)) return false;
  try {
    if (details.referrer && sameSite(new URL(details.referrer).hostname, host)) return false;
  } catch (_) { /* no referrer */ }
  return true;
}

// Loads the bundled uBlock Origin extension into a session (best effort).
async function loadUBlock(ses) {
  if (!settings.ublockEnabled || ublockIds.has(ses)) return;
  try {
    const loader = ses.extensions && ses.extensions.loadExtension
      ? ses.extensions
      : ses;
    const ext = await loader.loadExtension(UBLOCK_DIR, { allowFileAccess: true });
    ublockIds.set(ses, ext.id);
  } catch (err) {
    console.warn('uBlock Origin extension did not load:', err && err.message);
  }
}

function removeUBlock(ses) {
  const id = ublockIds.get(ses);
  if (!id) return;
  try {
    ses.extensions.removeExtension(id);
    ublockIds.delete(ses);
  } catch (err) {
    console.warn('uBlock Origin could not be disabled:', err && err.message);
  }
}

function configureSession(ses) {
  if (configuredSessions.has(ses)) return;
  configuredSessions.add(ses);

  // Deny permission prompts (camera, location, notifications...) by default.
  ses.setPermissionRequestHandler((_wc, permission, callback) => {
    callback(['fullscreen', 'clipboard-sanitized-write'].includes(permission));
  });

  ses.webRequest.onBeforeRequest((details, callback) => {
    if (blockerOn && isTracker(details)) {
      trackersBlocked += 1;
      return callback({ cancel: true });
    }
    callback({ cancel: false });
  });

  if (settings.ublockEnabled) loadUBlock(ses);

  // Always ask sites not to track.
  ses.webRequest.onBeforeSendHeaders((details, callback) => {
    details.requestHeaders['DNT'] = '1';
    details.requestHeaders['Sec-GPC'] = '1';
    callback({ requestHeaders: details.requestHeaders });
  });
}

// ---------- helpers ----------
function windowFor(webContents) {
  const bw = BrowserWindow.fromWebContents(webContents);
  return [...windows].find((w) => w.win === bw);
}

function activeTab(w) {
  return w.tabs.find((t) => t.id === w.activeId) || null;
}

function safe(fn, fallback) {
  try { return fn(); } catch (_) { return fallback; }
}

// Navigation history API differs between Electron versions; this works with both.
const navOf = (wc) => wc.navigationHistory || wc;

function normalizeInput(input) {
  const text = (input || '').trim();
  if (!text) return HOME_PAGE;
  if (/^(https?|chrome-extension):\/\//i.test(text)) return text;
  if (/^safari:\/\/newtab$/i.test(text)) return HOME_PAGE;
  if (/^[^\s/]+\.[a-z]{2,}(:\d+)?(\/\S*)?$/i.test(text)) return `https://${text}`;
  if (/^localhost(:\d+)?(\/\S*)?$/i.test(text)) return `http://${text}`;
  return SEARCH_ENGINES[settings.searchEngine] + encodeURIComponent(text);
}

function loadTabURL(tab, url) {
  const wc = tab.view.webContents;
  if (url === HOME_PAGE) {
    tab.isStartPage = true;
    tab.url = HOME_PAGE;
    wc.loadFile(path.join(__dirname, 'ui', 'start.html'), {
      query: { theme: settings.theme, search: settings.searchEngine },
    }).catch(() => {});
    return;
  }
  tab.isStartPage = false;
  wc.loadURL(url).catch(() => {});
}

// ---------- windows & layout ----------
function createWindow({ isPrivate = false, url } = {}) {
  const ses = isPrivate ? session.fromPartition(`private-${Date.now()}`) : session.defaultSession;
  configureSession(ses);

  const win = new BrowserWindow({
    width: 1200,
    height: 820,
    minWidth: 640,
    minHeight: 420,
    frame: false,
    icon: path.join(__dirname, 'assets', 'safari.ico'),
    backgroundColor: isPrivate || settings.theme === 'dark' ? '#1f1f24' : '#f6f6f6',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      sandbox: true,
    },
  });
  win.setMenuBarVisibility(false);

  const w = { win, isPrivate, ses, tabs: [], groups: [], activeId: null };
  windows.add(w);

  win.on('resize', () => layout(w));
  win.on('enter-full-screen', () => layout(w));
  win.on('leave-full-screen', () => layout(w));
  win.on('maximize', () => { layout(w); push(w); });
  win.on('unmaximize', () => { layout(w); push(w); });
  win.on('focus', () => { setMenu(w); push(w); });
  win.on('closed', () => {
    windows.delete(w);
    if (isPrivate) {
      // Private windows use an in-memory partition; clear anything left anyway.
      ses.clearStorageData().catch(() => {});
      ses.clearCache().catch(() => {});
    }
  });

  win.webContents.on('did-finish-load', () => {
    if (w.tabs.length === 0) createTab(w, url || HOME_PAGE);
    else push(w);
  });

  win.loadFile(path.join(__dirname, 'ui', 'index.html'));
  return w;
}

function layout(w) {
  if (w.win.isDestroyed()) return;
  const [width, height] = w.win.getContentSize();
  const tab = activeTab(w);
  if (tab) {
    tab.view.setBounds({ x: 0, y: CHROME_HEIGHT, width, height: Math.max(0, height - CHROME_HEIGHT) });
  }
}

// ---------- tabs ----------
function createTab(w, url, activateNow = true) {
  const tab = { id: nextTabId++, view: null, title: 'New Tab', url: '', favicon: '', loading: false, groupId: null };
  w.tabs.push(tab);
  attachTabView(w, tab);

  if (activateNow) activate(w, tab.id);
  else push(w);
  loadTabURL(tab, normalizeInput(url));
  return tab;
}

function attachTabView(w, tab) {
  tab.view = new WebContentsView({
    webPreferences: {
      session: w.ses,
      contextIsolation: true,
      sandbox: true,
      javascript: settings.javascriptEnabled,
      backgroundThrottling: true,
    },
  });
  const wc = tab.view.webContents;

  // Links that try to open a new window open a new tab instead.
  wc.setWindowOpenHandler(({ url: target }) => {
    if (/^https?:/i.test(target)) createTab(w, target, true);
    return { action: 'deny' };
  });
  wc.on('page-title-updated', (_e, title) => { tab.title = title; push(w); });
  wc.on('page-favicon-updated', (_e, icons) => { tab.favicon = icons[0] || ''; push(w); });
  wc.on('did-start-loading', () => { tab.loading = true; push(w); });
  wc.on('did-stop-loading', () => {
    tab.loading = false;
    if (!w.isPrivate && /^https?:/i.test(tab.url)) recordHistory(tab.url, tab.title);
    push(w);
  });
  const startPagePath = path.join(__dirname, 'ui', 'start.html');
  const onNavigate = (_e, newUrl) => {
    let isStartPage = false;
    try { isStartPage = fileURLToPath(newUrl) === startPagePath; } catch (_) { /* external URL */ }
    tab.isStartPage = isStartPage;
    tab.url = tab.isStartPage ? HOME_PAGE : newUrl;
    push(w);
  };
  wc.on('did-navigate', onNavigate);
  wc.on('did-navigate-in-page', onNavigate);
}

function reloadTabWithSettings(w, tab) {
  const index = w.tabs.indexOf(tab);
  if (index < 0) return;
  const wasActive = w.activeId === tab.id;
  const oldView = tab.view;
  const replacement = { ...tab, view: null, loading: false };
  if (wasActive) w.win.contentView.removeChildView(oldView);
  safe(() => oldView.webContents.close());
  w.tabs[index] = replacement;
  attachTabView(w, replacement);
  if (wasActive) {
    w.win.contentView.addChildView(replacement.view);
    layout(w);
  }
  loadTabURL(replacement, normalizeInput(tab.url || HOME_PAGE));
  push(w);
}

function activate(w, id) {
  const current = activeTab(w);
  if (current && current.id === id) { push(w); return; }
  if (current) w.win.contentView.removeChildView(current.view);

  const tab = w.tabs.find((t) => t.id === id);
  if (!tab) return;
  w.activeId = id;
  w.win.contentView.addChildView(tab.view);
  layout(w);
  push(w);
  tab.view.webContents.focus();
}

function closeTab(w, id) {
  const index = w.tabs.findIndex((t) => t.id === id);
  if (index === -1) return;
  const [tab] = w.tabs.splice(index, 1);
  const wasActive = w.activeId === id;
  if (wasActive) {
    w.win.contentView.removeChildView(tab.view);
    w.activeId = null;
  }
  safe(() => tab.view.webContents.close());
  regroup(w);

  if (wasActive) {
    const next = w.tabs[Math.min(index, w.tabs.length - 1)];
    if (next) activate(w, next.id);
    else createTab(w, HOME_PAGE);
  } else {
    push(w);
  }
}

function cycleTab(w, step) {
  if (!w.tabs.length) return;
  const i = w.tabs.findIndex((t) => t.id === w.activeId);
  const next = w.tabs[(i + step + w.tabs.length) % w.tabs.length];
  activate(w, next.id);
}

function navigate(w, action, value) {
  const tab = activeTab(w);
  if (!tab) return;
  const wc = tab.view.webContents;
  switch (action) {
    case 'go': loadTabURL(tab, normalizeInput(value)); break;
    case 'back': if (navOf(wc).canGoBack()) navOf(wc).goBack(); break;
    case 'forward': if (navOf(wc).canGoForward()) navOf(wc).goForward(); break;
    case 'reload': wc.reload(); break;
    case 'stop': wc.stop(); break;
  }
}

// ---------- tab groups ----------
// Keeps tabs of the same group next to each other, in first-seen order.
function regroup(w) {
  const order = [];
  const buckets = new Map();
  for (const tab of w.tabs) {
    const key = tab.groupId || 0;
    if (!buckets.has(key)) { buckets.set(key, []); order.push(key); }
    buckets.get(key).push(tab);
  }
  w.tabs = order.flatMap((key) => buckets.get(key));
  w.groups = w.groups.filter((g) => buckets.has(g.id)); // drop empty groups
}

function moveTab(w, tabId, groupId) {
  const tab = w.tabs.find((t) => t.id === tabId);
  if (!tab) return;
  tab.groupId = groupId || null;
  regroup(w);
  push(w);
}

function newGroup(w, tabId) {
  const group = {
    id: nextGroupId,
    name: `Group ${w.groups.length + 1}`,
    color: GROUP_COLORS[(nextGroupId - 1) % GROUP_COLORS.length],
  };
  nextGroupId += 1;
  w.groups.push(group);
  if (tabId) moveTab(w, tabId, group.id);
  else push(w);
}

function renameGroup(w, id, name) {
  const group = w.groups.find((g) => g.id === id);
  const clean = (name || '').trim().slice(0, 40);
  if (group && clean) group.name = clean;
  push(w);
}

let settingsWindow = null;

function openSettings(w) {
  if (settingsWindow && !settingsWindow.isDestroyed()) {
    settingsWindow.focus();
    return;
  }
  settingsWindow = new BrowserWindow({
    width: 820,
    height: 760,
    minWidth: 620,
    minHeight: 560,
    title: 'Safari Settings',
    parent: w && !w.win.isDestroyed() ? w.win : undefined,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      sandbox: true,
    },
  });
  settingsWindows.add(settingsWindow);
  settingsWindow.setMenuBarVisibility(false);
  settingsWindow.on('closed', () => {
    settingsWindows.delete(settingsWindow);
    settingsWindow = null;
  });
  settingsWindow.loadFile(path.join(__dirname, 'ui', 'settings.html'));
}

function isSettingsSender(sender) {
  return [...settingsWindows].some((win) => !win.isDestroyed() && win.webContents === sender);
}

function setDefaultWebProtocols() {
  if (app.isPackaged) {
    app.setAsDefaultProtocolClient('http');
    app.setAsDefaultProtocolClient('https');
    return;
  }
  const projectPath = path.resolve(process.argv[1] || '.');
  app.setAsDefaultProtocolClient('http', process.execPath, [projectPath]);
  app.setAsDefaultProtocolClient('https', process.execPath, [projectPath]);
}

function isDefaultWebProtocol(protocol) {
  if (app.isPackaged) return app.isDefaultProtocolClient(protocol);
  return app.isDefaultProtocolClient(protocol, process.execPath, [path.resolve(process.argv[1] || '.')]);
}

function parseCSV(text) {
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;
  for (let index = 0; index < text.length; index++) {
    const char = text[index];
    if (quoted) {
      if (char === '"' && text[index + 1] === '"') { field += '"'; index++; }
      else if (char === '"') quoted = false;
      else field += char;
    } else if (char === '"') {
      quoted = true;
    } else if (char === ',') {
      row.push(field);
      field = '';
    } else if (char === '\n') {
      row.push(field.replace(/\r$/, ''));
      if (row.some((cell) => cell)) rows.push(row);
      row = [];
      field = '';
    } else {
      field += char;
    }
  }
  row.push(field.replace(/\r$/, ''));
  if (row.some((cell) => cell)) rows.push(row);
  if (!rows.length) return [];

  const headers = rows.shift().map((header) => header.replace(/^\uFEFF/, '').trim().toLowerCase());
  const column = (...names) => headers.findIndex((header) => names.includes(header));
  const urlColumn = column('url', 'website');
  const usernameColumn = column('username', 'user name');
  const passwordColumn = column('password');
  const nameColumn = column('name', 'title');
  if (urlColumn < 0 || usernameColumn < 0 || passwordColumn < 0) return [];

  return rows.map((cells) => ({
    id: crypto.randomUUID(),
    name: (cells[nameColumn] || '').trim(),
    url: (cells[urlColumn] || '').trim(),
    username: (cells[usernameColumn] || '').trim(),
    password: cells[passwordColumn] || '',
  })).filter((entry) => {
    try { return ['http:', 'https:'].includes(new URL(entry.url).protocol) && !!entry.password; }
    catch (_) { return false; }
  });
}

function readPasswordVault() {
  if (!isVaultEncryptionAvailable()) throw new Error('OS-backed encryption is unavailable. Set up a system keychain/keyring to use the password vault.');
  if (!fs.existsSync(vaultFile)) return [];
  return JSON.parse(safeStorage.decryptString(fs.readFileSync(vaultFile)));
}

function writePasswordVault(entries) {
  if (!isVaultEncryptionAvailable()) throw new Error('OS-backed encryption is unavailable. Set up a system keychain/keyring to use the password vault.');
  fs.mkdirSync(path.dirname(vaultFile), { recursive: true });
  fs.writeFileSync(vaultFile, safeStorage.encryptString(JSON.stringify(entries)), { mode: 0o600 });
}

function isVaultEncryptionAvailable() {
  if (!safeStorage.isEncryptionAvailable()) return false;
  if (process.platform !== 'linux') return true;
  const backend = safe(() => safeStorage.getSelectedStorageBackend(), 'unknown');
  return backend !== 'basic_text' && backend !== 'unknown';
}

// ---------- state & menus ----------
function push(w) {
  if (w.win.isDestroyed()) return;
  const tab = activeTab(w);
  const wc = tab ? tab.view.webContents : null;
  const state = {
    isPrivate: w.isPrivate,
    maximized: w.win.isMaximized(),
    activeId: w.activeId,
    url: tab ? tab.url : '',
    loading: tab ? tab.loading : false,
    canBack: wc ? safe(() => navOf(wc).canGoBack(), false) : false,
    canForward: wc ? safe(() => navOf(wc).canGoForward(), false) : false,
    groups: w.groups,
    trackersBlocked,
    blockerOn,
    theme: settings.theme,
    tabs: w.tabs.map((t) => ({
      id: t.id, title: t.title, favicon: t.favicon, loading: t.loading, groupId: t.groupId,
    })),
  };
  lastBlockedSent = trackersBlocked;
  w.win.webContents.send('state', state);
  if (w.win.isFocused()) setMenu(w);
}

function tabGroupItems(w) {
  const tab = activeTab(w);
  return [
    { label: 'New Tab Group with This Tab', click: () => newGroup(w, tab && tab.id) },
    {
      label: 'Move This Tab to Group',
      enabled: !!tab,
      submenu: [
        ...w.groups.map((g) => ({
          label: g.name,
          type: 'checkbox',
          checked: !!tab && tab.groupId === g.id,
          click: () => tab && moveTab(w, tab.id, g.id),
        })),
        ...(w.groups.length ? [{ type: 'separator' }] : []),
        {
          label: 'Remove from Group',
          enabled: !!(tab && tab.groupId),
          click: () => tab && moveTab(w, tab.id, null),
        },
      ],
    },
  ];
}

function privacyItems(w) {
  const ublockId = ublockIds.get(w.ses);
  return [
    {
      label: 'Block Trackers and Ads',
      type: 'checkbox',
      checked: blockerOn,
      click: () => toggleBlocker(),
    },
    { label: `Trackers blocked: ${trackersBlocked}`, enabled: false },
    {
      label: 'uBlock Origin Dashboard',
      enabled: !!ublockId,
      click: () => w && ublockId && createTab(w, `chrome-extension://${ublockId}/dashboard.html`),
    },
    { label: 'Do Not Track and Global Privacy Control: On', enabled: false },
    { type: 'separator' },
    {
      label: 'Clear History',
      click: () => { clearHistory(); },
    },
  ];
}

function toggleBlocker() {
  blockerOn = !blockerOn;
  windows.forEach(push);
}

// Menu bar (used for keyboard shortcuts; the bar itself is hidden).
function menuTemplate(w) {
  const tab = activeTab(w);
  const wc = tab ? tab.view.webContents : null;
  return [
    {
      label: 'File',
      submenu: [
        { label: 'New Tab', accelerator: 'CmdOrCtrl+T', click: () => createTab(w, HOME_PAGE) },
        { label: 'New Window', accelerator: 'CmdOrCtrl+N', click: () => createWindow() },
        { label: 'New Private Window', accelerator: 'CmdOrCtrl+Shift+N', click: () => createWindow({ isPrivate: true }) },
        { type: 'separator' },
        { label: 'Close Tab', accelerator: 'CmdOrCtrl+W', click: () => tab && closeTab(w, tab.id) },
        { label: 'Print...', accelerator: 'CmdOrCtrl+P', click: () => wc && wc.print() },
        { type: 'separator' },
        { label: 'Quit', accelerator: 'CmdOrCtrl+Q', click: () => app.quit() },
      ],
    },
    {
      label: 'Edit',
      submenu: [
        { role: 'undo' }, { role: 'redo' }, { type: 'separator' },
        { role: 'cut' }, { role: 'copy' }, { role: 'paste' }, { role: 'selectAll' },
        { type: 'separator' },
        {
          label: 'Focus Address Bar',
          accelerator: 'CmdOrCtrl+L',
          click: () => { w.win.webContents.focus(); w.win.webContents.send('focus-address'); },
        },
      ],
    },
    {
      label: 'View',
      submenu: [
        { label: 'Reload Page', accelerator: 'CmdOrCtrl+R', click: () => wc && wc.reload() },
        { label: 'Show Next Tab', accelerator: 'Ctrl+Tab', click: () => cycleTab(w, 1) },
        { label: 'Show Previous Tab', accelerator: 'Ctrl+Shift+Tab', click: () => cycleTab(w, -1) },
        { type: 'separator' },
        { role: 'togglefullscreen' },
        { label: 'Developer Tools', accelerator: 'CmdOrCtrl+Alt+I', click: () => wc && wc.toggleDevTools() },
      ],
    },
  ];
}

// The "..." menu in the top-right corner.
function dotsTemplate(w) {
  const tab = activeTab(w);
  const wc = tab ? tab.view.webContents : null;
  return [
    { label: 'New Tab', click: () => createTab(w, HOME_PAGE) },
    { label: 'New Private Window', click: () => createWindow({ isPrivate: true }) },
    { type: 'separator' },
    { label: 'Settings...', click: () => openSettings(w) },
    { label: 'Tab Groups', submenu: tabGroupItems(w) },
    { label: 'Privacy', submenu: privacyItems(w) },
    { type: 'separator' },
    { label: 'Copy Link', enabled: !!tab, click: () => tab && clipboard.writeText(tab.url) },
    { label: 'Reload Page', enabled: !!wc, click: () => wc && wc.reload() },
    { label: 'Print...', enabled: !!wc, click: () => wc && wc.print() },
    { type: 'separator' },
    { role: 'togglefullscreen' },
  ];
}

function setMenu(w) {
  if (w.win.isDestroyed()) return;
  Menu.setApplicationMenu(Menu.buildFromTemplate(menuTemplate(w)));
}

function showDotsMenu(w, x, y) {
  Menu.buildFromTemplate(dotsTemplate(w)).popup({
    window: w.win,
    x: Math.round(x),
    y: Math.round(y),
  });
}

ipcMain.handle('settings:get', (event) => {
  if (!isSettingsSender(event.sender)) return null;
  return {
    ...settings,
    defaultBrowser: process.platform === 'win32' && isDefaultWebProtocol('http'),
    secureStorageAvailable: isVaultEncryptionAvailable(),
  };
});

ipcMain.handle('settings:save', (event, updates = {}) => {
  if (!isSettingsSender(event.sender)) return { ok: false };
  const previous = { ...settings };
  if (['system', 'light', 'dark'].includes(updates.theme)) settings.theme = updates.theme;
  if (Object.hasOwn(SEARCH_ENGINES, updates.searchEngine)) settings.searchEngine = updates.searchEngine;
  for (const key of ['javascriptEnabled', 'ublockEnabled', 'webAssemblyEnabled', 'hardwareAcceleration']) {
    if (typeof updates[key] === 'boolean') settings[key] = updates[key];
  }
  const saved = saveSettings();
  if (!saved) {
    settings = previous;
    return { ok: false, saved: false };
  }

  if (previous.javascriptEnabled !== settings.javascriptEnabled) {
    windows.forEach((browserWindow) => browserWindow.tabs.slice().forEach((tab) => {
      reloadTabWithSettings(browserWindow, tab);
    }));
  }
  if (previous.ublockEnabled !== settings.ublockEnabled) {
    const sessions = new Set([...windows].map((browserWindow) => browserWindow.ses));
    sessions.forEach((ses) => settings.ublockEnabled ? loadUBlock(ses) : removeUBlock(ses));
  }
  if (previous.theme !== settings.theme) {
    windows.forEach((browserWindow) => browserWindow.tabs.forEach((tab) => {
      if (tab.isStartPage) loadTabURL(tab, HOME_PAGE);
    }));
  }
  windows.forEach(push);
  return {
    ok: saved,
    saved,
    restartRequired: previous.webAssemblyEnabled !== settings.webAssemblyEnabled
      || previous.hardwareAcceleration !== settings.hardwareAcceleration,
  };
});

ipcMain.handle('settings:set-default-browser', async (event) => {
  if (!isSettingsSender(event.sender) || process.platform !== 'win32') return { ok: false };
  setDefaultWebProtocols();
  await shell.openExternal('ms-settings:defaultapps');
  return { ok: true };
});

ipcMain.handle('passwords:list', (event) => {
  if (!isSettingsSender(event.sender)) return [];
  try {
    return readPasswordVault().map(({ id, name, url, username }) => ({ id, name, url, username }));
  } catch (err) {
    return { error: err.message };
  }
});

ipcMain.handle('passwords:import', async (event) => {
  if (!isSettingsSender(event.sender)) return { ok: false, error: 'Not allowed.' };
  if (!isVaultEncryptionAvailable()) return { ok: false, error: 'OS-backed encryption is unavailable. Set up a system keychain/keyring to use the password vault.' };
  const owner = BrowserWindow.fromWebContents(event.sender);
  const selection = await dialog.showOpenDialog(owner, {
    title: 'Import passwords',
    properties: ['openFile'],
    filters: [{ name: 'CSV password export', extensions: ['csv'] }],
  });
  if (selection.canceled || !selection.filePaths[0]) return { ok: false, canceled: true };
  try {
    const imported = parseCSV(fs.readFileSync(selection.filePaths[0], 'utf8'));
    if (!imported.length) return { ok: false, error: 'No supported password rows were found in that CSV.' };
    const existing = readPasswordVault();
    const keys = new Set(existing.map((entry) => `${entry.url}\n${entry.username}`));
    const additions = imported.filter((entry) => !keys.has(`${entry.url}\n${entry.username}`));
    writePasswordVault([...existing, ...additions]);
    return { ok: true, imported: additions.length, skipped: imported.length - additions.length };
  } catch (err) {
    return { ok: false, error: err.message };
  }
});

ipcMain.handle('passwords:add', (event, entry = {}) => {
  if (!isSettingsSender(event.sender)) return { ok: false };
  const url = String(entry.url || '').trim().slice(0, 2048);
  const username = String(entry.username || '').trim().slice(0, 512);
  const password = String(entry.password || '').slice(0, 4096);
  if (!url || !username || !password) return { ok: false, error: 'Website, username, and password are required.' };
  try {
    if (!['http:', 'https:'].includes(new URL(url).protocol)) throw new Error();
  } catch (_) {
    return { ok: false, error: 'Enter a valid website URL.' };
  }
  try {
    const entries = readPasswordVault();
    entries.push({ id: crypto.randomUUID(), name: '', url, username, password });
    writePasswordVault(entries);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
});

ipcMain.handle('passwords:copy', (event, id) => {
  if (!isSettingsSender(event.sender)) return { ok: false };
  try {
    const entry = readPasswordVault().find((item) => item.id === id);
    if (!entry) return { ok: false };
    clipboard.writeText(entry.password);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
});

ipcMain.handle('passwords:delete', (event, id) => {
  if (!isSettingsSender(event.sender)) return { ok: false };
  try {
    writePasswordVault(readPasswordVault().filter((entry) => entry.id !== id));
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
});

// ---------- IPC from the toolbar UI ----------
ipcMain.on('cmd', (event, name, p = {}) => {
  const w = windowFor(event.sender);
  if (!w) return;
  switch (name) {
    case 'tab:new': createTab(w, HOME_PAGE); break;
    case 'group:new-active': { const tab = activeTab(w); newGroup(w, tab && tab.id); break; }
    case 'open-settings': openSettings(w); break;
    case 'tab:select': activate(w, p.id); break;
    case 'tab:close': closeTab(w, p.id); break;
    case 'nav': navigate(w, p.action, p.value); break;
    case 'group:new': newGroup(w, null); break;
    case 'group:rename': renameGroup(w, p.id, p.name); break;
    case 'menu': showDotsMenu(w, p.x || 0, p.y || 0); break;
    case 'copy-link': { const t = activeTab(w); if (t) clipboard.writeText(t.url); break; }
    case 'toggle-blocker': toggleBlocker(); break;
    case 'win':
      if (p.action === 'min') w.win.minimize();
      else if (p.action === 'max') (w.win.isMaximized() ? w.win.unmaximize() : w.win.maximize());
      else if (p.action === 'close') w.win.close();
      break;
  }
});

// Keep the shield counter fresh while pages load.
setInterval(() => {
  if (trackersBlocked !== lastBlockedSent) windows.forEach(push);
}, 1000);

// ---------- app lifecycle ----------
app.whenReady().then(() => {
  if (process.platform === 'win32') {
    app.setAppUserModelId('com.safari.chromium');
    setDefaultWebProtocols();
  }
  const startupUrl = process.argv.find((arg) => /^https?:\/\//i.test(arg));
  createWindow({ url: startupUrl || HOME_PAGE });
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => app.quit());
