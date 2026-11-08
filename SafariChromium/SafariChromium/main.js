// Safari (Chromium) - main process.
// Each window hosts its own Chromium tabs (WebContentsView), tab groups and
// a privacy layer (tracker blocking, Do Not Track / GPC headers).
const { app, BrowserWindow, WebContentsView, ipcMain, session, clipboard, Menu, dialog, safeStorage, shell } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const os = require('os');
const { execFile } = require('child_process');
const { promisify } = require('util');
const { fileURLToPath } = require('url');
const { autoUpdater } = require('electron-updater');

const CHROME_HEIGHT = 92;   // toolbar (52px) + tab strip (40px), must match styles.css
const execFileAsync = promisify(execFile);
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
  cookiesEnabled: true,
  cacheEnabled: true,
  extraExtensions: [],
  downloadSafetyScanEnabled: true,
  memoryBudgetGB: 'auto',
  backgroundPolicy: 'balanced',
  backgroundSuspendMinutes: 10,
  sendPrivacyHeaders: true,
  developerToolsEnabled: true,
  suppressUpdateNotices: false,
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
const userExtensionIds = new WeakMap();
const downloads = new Map();
const downloadWindows = new Map();

let blockerOn = true;
let trackersBlocked = 0;
let lastBlockedSent = -1;
let nextTabId = 1;
let nextGroupId = 1;
const windows = new Set();
const settingsWindows = new Set();
const configuredSessions = new WeakSet();
let updateStatus = 'Updates are checked when Safari starts.';
let updateCheckPromise = null;
let updatePromptOpen = false;

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
if (!Array.isArray(settings.extraExtensions)) settings.extraExtensions = [];
if (typeof settings.suppressUpdateNotices !== 'boolean') settings.suppressUpdateNotices = false;
if (settings.cacheEnabled === false) app.commandLine.appendSwitch('disable-http-cache');
if (!['auto', 2, 4, 6, 8].includes(settings.memoryBudgetGB)) settings.memoryBudgetGB = 'auto';
if (!['balanced', 'conserve'].includes(settings.backgroundPolicy)) settings.backgroundPolicy = 'balanced';
if (![0, 5, 10, 20, 30].includes(settings.backgroundSuspendMinutes)) settings.backgroundSuspendMinutes = 10;
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

const bookmarksFile = path.join(app.getPath('userData'), 'bookmarks.json');
let bookmarks = [];
try { bookmarks = JSON.parse(fs.readFileSync(bookmarksFile, 'utf8')); } catch (_) { /* first run */ }

function saveBookmarks() {
  try {
    fs.mkdirSync(path.dirname(bookmarksFile), { recursive: true });
    fs.writeFileSync(bookmarksFile, JSON.stringify(bookmarks, null, 2));
    return true;
  } catch (err) {
    console.warn('Could not save bookmarks:', err && err.message);
    return false;
  }
}

function toggleBookmark(w) {
  const tab = activeTab(w);
  if (!tab || !/^https?:\/\//i.test(tab.url)) return;
  const previous = bookmarks.slice();
  const index = bookmarks.findIndex((bookmark) => bookmark.url === tab.url);
  if (index >= 0) bookmarks.splice(index, 1);
  else bookmarks.unshift({ title: tab.title || tab.url, url: tab.url });
  if (!saveBookmarks()) {
    bookmarks = previous;
    return;
  }
  windows.forEach(push);
}

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

async function loadUserExtensions(ses, directories = settings.extraExtensions) {
  let loaded = userExtensionIds.get(ses);
  if (!loaded) {
    loaded = new Map();
    userExtensionIds.set(ses, loaded);
  }
  for (const directory of directories) {
    const resolved = path.resolve(directory);
    if (loaded.has(resolved) || !fs.existsSync(path.join(resolved, 'manifest.json'))) continue;
    try {
      const extension = await ses.extensions.loadExtension(resolved, { allowFileAccess: true });
      loaded.set(resolved, extension.id);
    } catch (err) {
      console.warn(`Extension did not load from ${resolved}:`, err && err.message);
    }
  }
}

function configureSession(ses) {
  if (configuredSessions.has(ses)) return;
  configuredSessions.add(ses);

  // Deny permission prompts (camera, location, notifications...) by default.
  ses.setPermissionRequestHandler((_wc, permission, callback) => {
    callback(['fullscreen', 'clipboard-sanitized-write', 'publickey-credentials-get', 'publickey-credentials-create'].includes(permission));
  });

  ses.webRequest.onBeforeRequest((details, callback) => {
    if (blockerOn && isTracker(details)) {
      trackersBlocked += 1;
      return callback({ cancel: true });
    }
    callback({ cancel: false });
  });

  if (settings.ublockEnabled) loadUBlock(ses);
  if (ses === session.defaultSession) loadUserExtensions(ses);

  ses.webRequest.onBeforeSendHeaders((details, callback) => {
    if (!settings.cookiesEnabled) {
      for (const name of Object.keys(details.requestHeaders)) {
        if (['cookie', 'cookie2'].includes(name.toLowerCase())) delete details.requestHeaders[name];
      }
    }
    if (settings.sendPrivacyHeaders) {
      details.requestHeaders['DNT'] = '1';
      details.requestHeaders['Sec-GPC'] = '1';
    }
    callback({ requestHeaders: details.requestHeaders });
  });

  ses.webRequest.onHeadersReceived((details, callback) => {
    if (settings.cookiesEnabled) return callback({ responseHeaders: details.responseHeaders });
    const responseHeaders = { ...details.responseHeaders };
    for (const name of Object.keys(responseHeaders)) {
      if (['set-cookie', 'set-cookie2'].includes(name.toLowerCase())) delete responseHeaders[name];
    }
    callback({ responseHeaders });
  });

  ses.on('will-download', (event, item, webContents) => {
    handleDownload(ses, event, item, webContents);
  });
}

const flaggedDownloadExtensions = new Set([
  '.exe', '.msi', '.dll', '.scr', '.com', '.bat', '.cmd', '.ps1', '.psm1', '.vbs', '.vbe', '.js', '.jse', '.hta', '.lnk', '.reg', '.jar', '.chm', '.docm', '.xlsm', '.pptm',
]);

function downloadOwner(ses, webContents) {
  const browser = [...windows].find((candidate) => candidate.ses === ses
    && candidate.tabs.some((tab) => tab.view.webContents === webContents));
  return {
    window: browser ? browser.win : BrowserWindow.fromWebContents(webContents),
    isPrivate: !!(browser && browser.isPrivate),
  };
}

function downloadSnapshot(download, isPrivate) {
  if (download.isPrivate !== isPrivate) return null;
  return {
    id: download.id,
    filename: download.filename,
    url: download.url,
    status: download.status,
    receivedBytes: download.receivedBytes,
    totalBytes: download.totalBytes,
    percent: download.totalBytes ? Math.floor(download.receivedBytes / download.totalBytes * 100) : 0,
    scanStatus: download.scanStatus,
    scanDetail: download.scanDetail,
    sha256: download.sha256,
    path: download.status === 'Complete' ? download.targetPath : '',
  };
}

function publishDownloads() {
  for (const browser of windows) push(browser);
  for (const entry of downloadWindows.values()) {
    if (entry.win.isDestroyed()) continue;
    entry.win.webContents.send('downloads-state', [...downloads.values()]
      .filter((download) => download.isPrivate === entry.isPrivate)
      .map((download) => downloadSnapshot(download, entry.isPrivate)));
  }
}

function handleDownloadCommand(isPrivate, name, id) {
  if (name === 'clear') {
    for (const [downloadId, download] of downloads) {
      if (download.isPrivate === isPrivate && !['Downloading', 'Scanning', 'Choose save location'].includes(download.status)) downloads.delete(downloadId);
    }
    publishDownloads();
    return;
  }
  const download = downloads.get(id);
  if (!download || download.isPrivate !== isPrivate) return;
  if (name === 'cancel' && download.item) download.item.cancel();
  else if (name === 'open' && download.status === 'Complete') shell.openPath(download.targetPath);
  else if (name === 'show' && download.status === 'Complete') shell.showItemInFolder(download.targetPath);
}

function defenderCliPath() {
  if (process.platform !== 'win32') return null;
  const candidates = [];
  if (process.env.ProgramFiles) candidates.push(path.join(process.env.ProgramFiles, 'Windows Defender', 'MpCmdRun.exe'));
  if (process.env.ProgramData) {
    const platformDirectory = path.join(process.env.ProgramData, 'Microsoft', 'Windows Defender', 'Platform');
    try {
      const versions = fs.readdirSync(platformDirectory).sort().reverse();
      for (const version of versions) candidates.push(path.join(platformDirectory, version, 'MpCmdRun.exe'));
    } catch (_) { /* Defender platform directory is optional */ }
  }
  return candidates.find((candidate) => fs.existsSync(candidate)) || null;
}

async function scanDownloadFile(filePath) {
  if (!settings.downloadSafetyScanEnabled) return { status: 'disabled', detail: 'File scanning is disabled in Advanced settings.' };
  const scanner = defenderCliPath();
  if (!scanner) return { status: 'unavailable', detail: 'Windows Defender command-line scanner was not found.' };
  try {
    const result = await execFileAsync(scanner, ['-Scan', '-ScanType', '3', '-File', filePath, '-DisableRemediation'], {
      timeout: 5 * 60 * 1000,
      maxBuffer: 1024 * 1024,
      windowsHide: true,
    });
    const output = `${result.stdout || ''}\n${result.stderr || ''}`;
    if (/threat\s+(was\s+)?detected|malware\s+(was\s+)?detected|virus\s+(was\s+)?detected/i.test(output)) {
      return { status: 'detected', detail: 'Windows Defender reported a threat.' };
    }
    return { status: 'clean', detail: 'Windows Defender completed a scan without reporting a threat.' };
  } catch (err) {
    const output = `${err.stdout || ''}\n${err.stderr || ''}`;
    if (/threat\s+(was\s+)?detected|malware\s+(was\s+)?detected|virus\s+(was\s+)?detected/i.test(output)) {
      return { status: 'detected', detail: 'Windows Defender reported a threat.' };
    }
    return { status: 'unverified', detail: `Windows Defender could not verify this file (${err.code || 'scan error'}).` };
  }
}

async function hashFile(filePath) {
  const digest = crypto.createHash('sha256');
  for await (const chunk of fs.createReadStream(filePath)) digest.update(chunk);
  return digest.digest('hex');
}

function moveQuarantinedFile(source, destination) {
  try {
    fs.renameSync(source, destination);
  } catch (err) {
    if (err.code !== 'EXDEV') throw err;
    fs.copyFileSync(source, destination, fs.constants.COPYFILE_EXCL);
    fs.unlinkSync(source);
  }
}

async function finishDownload(download, state) {
  if (state !== 'completed') {
    download.status = state === 'cancelled' ? 'Canceled' : 'Interrupted';
    try { if (download.tempPath) fs.rmSync(download.tempPath, { force: true }); } catch (_) { /* best effort */ }
    publishDownloads();
    return;
  }

  download.status = 'Scanning';
  publishDownloads();
  const scan = await scanDownloadFile(download.tempPath);
  download.scanStatus = scan.status;
  download.scanDetail = scan.detail;
  try { download.sha256 = await hashFile(download.tempPath); }
  catch (err) { download.scanStatus = 'unverified'; download.scanDetail = `Could not read the file for verification: ${err.message}`; }

  const extension = path.extname(download.filename).toLowerCase();
  const dangerousType = flaggedDownloadExtensions.has(extension);
  const requiresConfirmation = scan.status !== 'clean' || dangerousType;
  if (requiresConfirmation) {
    const reason = scan.status === 'detected'
      ? 'Windows Defender reported a threat.'
      : scan.status === 'clean' && dangerousType
        ? `This file type (${extension}) can run code or contain active content. The antivirus scan did not report a threat.`
        : scan.detail;
    download.status = 'Flagged';
    download.scanDetail = reason;
    publishDownloads();
    const options = {
      type: 'warning',
      title: 'Review flagged download',
      message: `Safari flagged ${download.filename}.`,
      detail: `${reason}\n\nSHA-256: ${download.sha256 || 'unavailable'}\n\nKeep this file only if you trust its source.`,
      buttons: ['Keep anyway', 'Delete'],
      defaultId: 1,
      cancelId: 1,
    };
    const result = download.window && !download.window.isDestroyed()
      ? await dialog.showMessageBox(download.window, options)
      : await dialog.showMessageBox(options);
    if (result.response !== 0) {
      try { fs.rmSync(download.tempPath, { force: true }); } catch (_) { /* best effort */ }
      download.status = 'Deleted after warning';
      publishDownloads();
      return;
    }
  }

  try {
    moveQuarantinedFile(download.tempPath, download.targetPath);
    download.status = 'Complete';
  } catch (err) {
    download.status = 'Could not save';
    download.scanDetail = err.message;
  }
  publishDownloads();
}

async function handleDownload(ses, event, item, webContents) {
  const owner = downloadOwner(ses, webContents);
  const filename = path.basename(item.getFilename() || 'download');
  const id = crypto.randomUUID();
  const download = {
    id,
    filename,
    url: item.getURL(),
    status: 'Choose save location',
    scanStatus: 'pending',
    scanDetail: '',
    receivedBytes: 0,
    totalBytes: item.getTotalBytes(),
    targetPath: '',
    tempPath: '',
    webContentsId: webContents.id,
    item,
    window: owner.window,
    isPrivate: owner.isPrivate,
  };
  downloads.set(id, download);
  download.tempPath = path.join(app.getPath('temp'), `safari-${id}.quarantine`);
  item.setSavePath(download.tempPath);
  item.pause();
  publishDownloads();

  item.on('updated', (_event, state) => {
    download.receivedBytes = item.getReceivedBytes();
    download.totalBytes = item.getTotalBytes();
    download.status = state === 'interrupted' ? 'Interrupted' : 'Downloading';
    publishDownloads();
  });
  item.once('done', (_event, state) => { finishDownload(download, state).catch((err) => {
    download.status = 'Scan failed';
    download.scanStatus = 'unverified';
    download.scanDetail = err.message;
    publishDownloads();
  }); });

  try {
    const selection = await dialog.showSaveDialog(owner.window, {
      title: 'Save download',
      defaultPath: path.join(app.getPath('downloads'), filename),
    });
    if (selection.canceled || !selection.filePath) {
      item.cancel();
      return;
    }
    download.targetPath = selection.filePath;
    download.status = 'Downloading';
    item.resume();
    publishDownloads();
  } catch (err) {
    item.cancel();
    download.status = 'Canceled';
    download.scanDetail = err.message;
    publishDownloads();
  }
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

function installedSiteLaunch() {
  const urlArg = process.argv.find((arg) => arg.startsWith('--safari-app-url='));
  if (!urlArg) return null;
  try {
    const url = Buffer.from(urlArg.slice('--safari-app-url='.length), 'base64url').toString('utf8');
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) return null;
    const nameArg = process.argv.find((arg) => arg.startsWith('--safari-app-name='));
    const name = nameArg
      ? Buffer.from(nameArg.slice('--safari-app-name='.length), 'base64url').toString('utf8')
      : parsed.hostname;
    return { url: parsed.href, name: name.slice(0, 100) };
  } catch (_) {
    return null;
  }
}

function createInstalledSiteWindow(url, name) {
  configureSession(session.defaultSession);
  const win = new BrowserWindow({
    width: 1180,
    height: 820,
    minWidth: 520,
    minHeight: 420,
    title: name,
    icon: path.join(__dirname, 'assets', 'safari.ico'),
    webPreferences: {
      contextIsolation: true,
      sandbox: true,
      backgroundThrottling: true,
      javascript: settings.javascriptEnabled,
    },
  });
  win.webContents.setWindowOpenHandler(({ url: target }) => {
    if (/^https?:/i.test(target)) shell.openExternal(target);
    return { action: 'deny' };
  });
  win.loadURL(url).catch(() => {});
  return win;
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

  win.webContents.on('did-finish-load', () => push(w));

  win.loadFile(path.join(__dirname, 'ui', 'index.html'));
  createTab(w, url || HOME_PAGE);
  return w;
}

function layout(w) {
  if (w.win.isDestroyed()) return;
  const [width, height] = w.win.getContentSize();
  const tab = activeTab(w);
  if (tab && tab.view) {
    tab.view.setBounds({ x: 0, y: CHROME_HEIGHT, width, height: Math.max(0, height - CHROME_HEIGHT) });
  }
}

// ---------- tabs ----------
function createTab(w, url, activateNow = true) {
  const tab = { id: nextTabId++, view: null, title: 'New Tab', url: '', favicon: '', loading: false, groupId: null, lastActivatedAt: Date.now(), hibernated: false };
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
      preload: path.join(__dirname, 'login-preload.js'),
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
  wc.on('page-title-updated', (_e, title) => {
    tab.title = title;
    const bookmark = bookmarks.find((item) => item.url === tab.url);
    if (bookmark) { bookmark.title = title; saveBookmarks(); }
    push(w);
  });
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
  wc.on('context-menu', (event, params) => showPageContextMenu(w, tab, event, params));
}

function reloadTabWithSettings(w, tab) {
  const index = w.tabs.indexOf(tab);
  if (index < 0 || tab.hibernated) return;
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
  if (tab.hibernated) {
    tab.hibernated = false;
    attachTabView(w, tab);
    loadTabURL(tab, normalizeInput(tab.url || HOME_PAGE));
  }
  w.activeId = id;
  tab.lastActivatedAt = Date.now();
  w.win.contentView.addChildView(tab.view);
  layout(w);
  push(w);
  tab.view.webContents.focus();
}

function hibernateTab(w, tab) {
  if (!tab || tab.id === w.activeId || !tab.view || tab.view.webContents.isCurrentlyAudible()) return false;
  const view = tab.view;
  tab.view = null;
  tab.hibernated = true;
  safe(() => view.webContents.close());
  push(w);
  return true;
}

function recommendedPerformance() {
  const memoryGB = os.totalmem() / (1024 ** 3);
  const cpuCores = os.cpus().length;
  if (memoryGB < 8 || cpuCores < 4) {
    return { memoryBudgetGB: 2, backgroundPolicy: 'conserve', backgroundSuspendMinutes: 5, memoryGB: Math.round(memoryGB * 10) / 10, cpuCores };
  }
  if (memoryGB < 16 || cpuCores < 8) {
    return { memoryBudgetGB: 4, backgroundPolicy: 'balanced', backgroundSuspendMinutes: 10, memoryGB: Math.round(memoryGB * 10) / 10, cpuCores };
  }
  return { memoryBudgetGB: 8, backgroundPolicy: 'balanced', backgroundSuspendMinutes: 20, memoryGB: Math.round(memoryGB * 10) / 10, cpuCores };
}

function performanceSnapshot() {
  const metrics = app.getAppMetrics();
  const workingSetBytes = metrics.reduce((total, metric) => total + (metric.memory.workingSetSize || 0), 0);
  const cpuPercent = metrics.reduce((total, metric) => total + (metric.cpu.percentCPUUsage || 0), 0);
  return {
    memoryMB: Math.round(workingSetBytes / (1024 ** 2)),
    cpuPercent: Math.round(cpuPercent * 10) / 10,
    ...recommendedPerformance(),
  };
}

function backgroundDownloadActive(tab) {
  if (!tab || !tab.view) return false;
  const webContentsId = tab.view.webContents.id;
  return [...downloads.values()].some((download) => download.webContentsId === webContentsId
    && ['Downloading', 'Choose save location', 'Scanning'].includes(download.status));
}

function enforcePerformanceSettings() {
  const metrics = performanceSnapshot();
  const budgetGB = settings.memoryBudgetGB === 'auto'
    ? recommendedPerformance().memoryBudgetGB
    : Number(settings.memoryBudgetGB);
  const overBudget = metrics.memoryMB > budgetGB * 1024;
  const idleLimit = settings.backgroundPolicy === 'conserve'
    ? settings.backgroundSuspendMinutes * 60 * 1000
    : 0;
  const now = Date.now();
  const candidates = [...windows].flatMap((w) => w.tabs
    .filter((tab) => tab.id !== w.activeId && tab.view && !backgroundDownloadActive(tab)
      && (overBudget || (idleLimit > 0 && now - tab.lastActivatedAt >= idleLimit)))
    .map((tab) => ({ w, tab })));
  candidates.sort((a, b) => a.tab.lastActivatedAt - b.tab.lastActivatedAt);
  if (candidates.length) hibernateTab(candidates[0].w, candidates[0].tab);
}

function closeTab(w, id) {
  const index = w.tabs.findIndex((t) => t.id === id);
  if (index === -1) return;
  const [tab] = w.tabs.splice(index, 1);
  const wasActive = w.activeId === id;
  if (wasActive && tab.view) {
    w.win.contentView.removeChildView(tab.view);
    w.activeId = null;
  }
  safe(() => tab.view && tab.view.webContents.close());
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

function dropTab(w, sourceId, targetId, groupId) {
  const source = w.tabs.find((tab) => tab.id === sourceId);
  const target = w.tabs.find((tab) => tab.id === targetId);
  if (!source || target === source) return;

  if (target && target !== source) {
    let destinationGroupId = target.groupId || source.groupId;
    if (!destinationGroupId) {
      const group = {
        id: nextGroupId++,
        name: `Group ${w.groups.length + 1}`,
        color: GROUP_COLORS[(nextGroupId - 2) % GROUP_COLORS.length],
      };
      w.groups.push(group);
      destinationGroupId = group.id;
    }
    if (source.groupId && target.groupId && source.groupId !== target.groupId) {
      w.tabs.forEach((tab) => { if (tab.groupId === source.groupId) tab.groupId = destinationGroupId; });
    }
    source.groupId = destinationGroupId;
    target.groupId = destinationGroupId;
    w.tabs.splice(w.tabs.indexOf(source), 1);
    w.tabs.splice(w.tabs.indexOf(target) + 1, 0, source);
  } else {
    source.groupId = groupId || source.groupId || null;
    w.tabs.splice(w.tabs.indexOf(source), 1);
    if (source.groupId) {
      const lastGroupTab = w.tabs.reduce((last, tab, index) => tab.groupId === source.groupId ? index : last, -1);
      w.tabs.splice(lastGroupTab + 1, 0, source);
    } else {
      w.tabs.push(source);
    }
  }
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

function openDownloads(w) {
  const existing = [...downloadWindows.values()].find((entry) => entry.isPrivate === w.isPrivate);
  if (existing && !existing.win.isDestroyed()) {
    existing.win.focus();
    return;
  }
  const win = new BrowserWindow({
    width: 720,
    height: 640,
    minWidth: 480,
    minHeight: 420,
    title: 'Downloads - Safari',
    parent: w && !w.win.isDestroyed() ? w.win : undefined,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      sandbox: true,
    },
  });
  const entry = { win, isPrivate: w.isPrivate, owner: w };
  downloadWindows.set(win.webContents.id, entry);
  win.setBackgroundColor(settings.theme === 'dark' ? '#171d20' : '#f3f5f4');
  win.setMenuBarVisibility(false);
  win.on('closed', () => downloadWindows.delete(win.webContents.id));
  win.webContents.on('did-finish-load', () => {
    win.webContents.send('downloads-state', [...downloads.values()]
      .filter((download) => download.isPrivate === entry.isPrivate)
      .map((download) => downloadSnapshot(download, entry.isPrivate)));
  });
  win.loadFile(path.join(__dirname, 'ui', 'downloads.html'), { query: { theme: settings.theme } });
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

function loginHost(url) {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(parsed.hostname))) return null;
    return parsed.hostname.toLowerCase().replace(/^www\./, '');
  } catch (_) {
    return null;
  }
}

function passwordsForTab(tab) {
  const host = loginHost(tab && tab.url);
  if (!host) return [];
  try {
    return readPasswordVault().filter((entry) => loginHost(entry.url) === host);
  } catch (err) {
    console.warn('Could not read password vault:', err && err.message);
    return [];
  }
}

function fillPassword(tab, id) {
  const entry = passwordsForTab(tab).find((item) => item.id === id);
  if (!entry || !tab || tab.view.webContents.isDestroyed()) return;
  const payload = JSON.stringify({ username: entry.username, password: entry.password });
  const script = `(() => {
    const saved = ${payload};
    const visible = (input) => input && !input.disabled && input.getClientRects().length > 0;
    const user = [...document.querySelectorAll('input[autocomplete="username"], input[type="email"], input[name*="user" i], input[name*="login" i]')].find(visible);
    const pass = [...document.querySelectorAll('input[type="password"]')].find(visible);
    const setValue = (input, value) => {
      if (!input) return;
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
      setter.call(input, value);
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.dispatchEvent(new Event('change', { bubbles: true }));
    };
    setValue(user, saved.username);
    setValue(pass, saved.password);
    return !!pass;
  })()`;
  tab.view.webContents.executeJavaScript(script, true).catch(() => {});
}

function passwordMenuTemplate(w, tab) {
  const matches = passwordsForTab(tab);
  return [
    ...(matches.length
      ? matches.map((entry) => ({
        label: `${entry.username}${entry.name ? ` (${entry.name})` : ''}`,
        click: () => fillPassword(tab, entry.id),
      }))
      : [{ label: 'No saved passwords for this site', enabled: false }]),
    { type: 'separator' },
    { label: 'Manage Passwords...', click: () => openSettings(w) },
  ];
}

function showPasswordsMenu(w, x, y) {
  const tab = activeTab(w);
  if (!tab) return;
  Menu.buildFromTemplate(passwordMenuTemplate(w, tab)).popup({
    window: w.win,
    x: Math.round(x || 0),
    y: Math.round(y || 0),
  });
}

function showLoginPasswordMenu(w, tab, bounds = {}) {
  if (!tab || activeTab(w) !== tab || !passwordsForTab(tab).length) return;
  const [width, height] = w.win.getContentSize();
  const x = Math.max(0, Math.min(Number(bounds.x) || 0, width - 220));
  const y = Math.max(CHROME_HEIGHT, Math.min(CHROME_HEIGHT + (Number(bounds.y) || 0), height - 80));
  Menu.buildFromTemplate(passwordMenuTemplate(w, tab)).popup({ window: w.win, x, y });
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
    isBookmarked: !!(tab && bookmarks.some((bookmark) => bookmark.url === tab.url)),
    downloads: [...downloads.values()]
      .filter((download) => download.isPrivate === w.isPrivate)
      .map((download) => downloadSnapshot(download, w.isPrivate)),
    trackersBlocked,
    blockerOn,
    theme: settings.theme,
    tabs: w.tabs.map((t) => ({
      id: t.id, title: t.title, favicon: t.favicon, loading: t.loading, groupId: t.groupId, hibernated: !!t.hibernated,
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

function bookmarkItems(w) {
  const tab = activeTab(w);
  const isBookmarked = !!(tab && bookmarks.some((bookmark) => bookmark.url === tab.url));
  return [
    {
      label: isBookmarked ? 'Remove Bookmark' : 'Bookmark This Page',
      enabled: !!(tab && /^https?:\/\//i.test(tab.url)),
      click: () => toggleBookmark(w),
    },
    ...(bookmarks.length ? [{ type: 'separator' }] : []),
    ...(bookmarks.length
      ? bookmarks.map((bookmark) => ({
        label: bookmark.title || bookmark.url,
        click: () => createTab(w, bookmark.url),
      }))
      : [{ label: 'No Bookmarks', enabled: false }]),
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

function pageContextMenuItems(w, tab, params) {
  const wc = tab.view.webContents;
  const items = [];
  const webLink = /^https?:\/\//i.test(params.linkURL || '');

  if (webLink) {
    items.push(
      { label: 'Open Link in New Tab', click: () => createTab(w, params.linkURL) },
      { label: 'Open Link in This Tab', click: () => wc.loadURL(params.linkURL).catch(() => {}) },
      { label: 'Copy Link Address', click: () => clipboard.writeText(params.linkURL) },
      { label: 'Download Linked File...', click: () => wc.downloadURL(params.linkURL) },
      { type: 'separator' },
    );
  }

  if (params.mediaType === 'image' && params.srcURL) {
    items.push(
      { label: 'Open Image in New Tab', click: () => createTab(w, params.srcURL) },
      { label: 'Copy Image', click: () => wc.copyImageAt(params.x, params.y) },
      { label: 'Save Image...', click: () => wc.downloadURL(params.srcURL) },
      { type: 'separator' },
    );
  }

  if (params.isEditable) {
    const flags = params.editFlags || {};
    items.push(
      { label: 'Undo', role: 'undo', enabled: !!flags.canUndo },
      { label: 'Redo', role: 'redo', enabled: !!flags.canRedo },
      { type: 'separator' },
      { label: 'Cut', role: 'cut', enabled: !!flags.canCut },
      { label: 'Copy', role: 'copy', enabled: !!flags.canCopy },
      { label: 'Paste', role: 'paste', enabled: !!flags.canPaste },
      { label: 'Select All', role: 'selectAll', enabled: !!flags.canSelectAll },
      { type: 'separator' },
    );
  } else if (params.selectionText) {
    const selection = params.selectionText;
    items.push(
      { label: 'Copy', click: () => clipboard.writeText(selection) },
      { label: `Search for “${selection.slice(0, 40)}”`, click: () => createTab(w, SEARCH_ENGINES[settings.searchEngine] + encodeURIComponent(selection)) },
      { type: 'separator' },
    );
  }

  items.push(
    { label: 'Back', enabled: safe(() => navOf(wc).canGoBack(), false), click: () => safe(() => navOf(wc).goBack()) },
    { label: 'Forward', enabled: safe(() => navOf(wc).canGoForward(), false), click: () => safe(() => navOf(wc).goForward()) },
    { label: 'Reload', click: () => wc.reload() },
  );

  if (/^https?:\/\//i.test(tab.url)) {
    const isBookmarked = bookmarks.some((bookmark) => bookmark.url === tab.url);
    items.push({ label: isBookmarked ? 'Remove Bookmark' : 'Bookmark This Page', click: () => toggleBookmark(w) });
  }
  if (settings.developerToolsEnabled) {
    items.push({ type: 'separator' }, { label: 'Inspect', click: () => wc.inspectElement(params.x, params.y) });
  }
  return items;
}

function showPageContextMenu(w, tab, event, params) {
  if (!w || w.win.isDestroyed() || w.activeId !== tab.id || !params) return;
  event.preventDefault();
  Menu.buildFromTemplate(pageContextMenuItems(w, tab, params)).popup({
    window: w.win,
    x: Math.round(params.x || 0),
    y: Math.round((params.y || 0) + CHROME_HEIGHT),
  });
}

function toggleBlocker() {
  blockerOn = !blockerOn;
  windows.forEach(push);
}

function installWebsiteAsApp(w) {
  const tab = activeTab(w);
  if (!tab || !/^https?:\/\//i.test(tab.url)) return;
  if (process.platform !== 'win32') {
    dialog.showMessageBox(w.win, { type: 'info', message: 'Website shortcuts are currently supported on Windows.' });
    return;
  }

  const name = (tab.title || new URL(tab.url).hostname)
    .replace(/[<>:"/\\|?*\x00-\x1f]/g, '')
    .trim()
    .slice(0, 80) || 'Website';
  const desktop = app.getPath('desktop');
  let shortcutPath = path.join(desktop, `${name}.lnk`);
  for (let suffix = 2; fs.existsSync(shortcutPath); suffix++) {
    shortcutPath = path.join(desktop, `${name} (${suffix}).lnk`);
  }

  const appArgs = [];
  if (!app.isPackaged) appArgs.push(path.resolve(process.argv[1] || '.'));
  appArgs.push(`--safari-app-url=${Buffer.from(tab.url).toString('base64url')}`);
  appArgs.push(`--safari-app-name=${Buffer.from(name).toString('base64url')}`);
  const args = appArgs.map((value) => `"${value.replace(/"/g, '\\"')}"`).join(' ');
  const created = shell.writeShortcutLink(shortcutPath, 'create', {
    target: process.execPath,
    args,
    cwd: path.dirname(process.execPath),
    description: `Open ${name} in Safari`,
    icon: process.execPath,
    iconIndex: 0,
  });
  if (!created) {
    dialog.showMessageBox(w.win, { type: 'error', message: 'Safari could not create the desktop shortcut.' });
    return;
  }
  dialog.showMessageBox(w.win, { type: 'info', message: `${name} was added to your desktop.` });
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
        ...(settings.developerToolsEnabled ? [{ label: 'Developer Tools', accelerator: 'CmdOrCtrl+Alt+I', click: () => wc && wc.toggleDevTools() }] : []),
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
    { label: 'Install This Site as an App...', enabled: !!(tab && /^https?:\/\//i.test(tab.url)), click: () => installWebsiteAsApp(w) },
    { type: 'separator' },
    { label: 'Settings...', click: () => openSettings(w) },
    { label: 'Bookmarks', submenu: bookmarkItems(w) },
    { label: 'Extensions', submenu: extensionsMenuItems(w) },
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

function extensionsMenuItems(w) {
  return [
    { label: 'Chrome Web Store', click: () => createTab(w, 'https://chromewebstore.google.com/') },
    { label: 'Manage Extensions...', click: () => openSettings(w) },
  ];
}

function showExtensionsMenu(w, x, y) {
  Menu.buildFromTemplate(extensionsMenuItems(w)).popup({
    window: w.win,
    x: Math.round(x || 0),
    y: Math.round(y || 0),
  });
}

ipcMain.handle('settings:get', (event) => {
  if (!isSettingsSender(event.sender)) return null;
  const { extraExtensions: _directories, ...publicSettings } = settings;
  return {
    ...publicSettings,
    appVersion: app.getVersion(),
    electronVersion: process.versions.electron,
    hardwareInfo: { memoryGB: Math.round(os.totalmem() / (1024 ** 3) * 10) / 10, cpuCores: os.cpus().length },
    updateStatus,
    defaultBrowser: process.platform === 'win32' && isDefaultWebProtocol('http'),
    secureStorageAvailable: isVaultEncryptionAvailable(),
    extensions: session.defaultSession.extensions.getAllExtensions().map((extension) => ({
      id: extension.id,
      name: extension.name,
      version: extension.version,
      bundled: path.resolve(extension.path) === path.resolve(UBLOCK_DIR),
    })),
  };
});

ipcMain.handle('settings:save', (event, updates = {}) => {
  if (!isSettingsSender(event.sender)) return { ok: false };
  const previous = { ...settings };
  if (['system', 'light', 'dark'].includes(updates.theme)) settings.theme = updates.theme;
  if (Object.hasOwn(SEARCH_ENGINES, updates.searchEngine)) settings.searchEngine = updates.searchEngine;
  for (const key of ['javascriptEnabled', 'ublockEnabled', 'cookiesEnabled', 'cacheEnabled', 'webAssemblyEnabled', 'hardwareAcceleration', 'suppressUpdateNotices', 'sendPrivacyHeaders', 'developerToolsEnabled', 'downloadSafetyScanEnabled']) {
    if (typeof updates[key] === 'boolean') settings[key] = updates[key];
  }
  if (['auto', 2, 4, 6, 8].includes(updates.memoryBudgetGB)) settings.memoryBudgetGB = updates.memoryBudgetGB;
  if (['balanced', 'conserve'].includes(updates.backgroundPolicy)) settings.backgroundPolicy = updates.backgroundPolicy;
  if ([0, 5, 10, 20, 30].includes(updates.backgroundSuspendMinutes)) settings.backgroundSuspendMinutes = updates.backgroundSuspendMinutes;
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
      || previous.hardwareAcceleration !== settings.hardwareAcceleration
      || previous.cacheEnabled !== settings.cacheEnabled,
  };
});

ipcMain.handle('performance:sample', (event) => {
  if (!isSettingsSender(event.sender)) return { ok: false };
  return {
    ok: true,
    ...performanceSnapshot(),
    targetGB: settings.memoryBudgetGB === 'auto' ? recommendedPerformance().memoryBudgetGB : settings.memoryBudgetGB,
  };
});

ipcMain.handle('performance:recommend', (event) => {
  if (!isSettingsSender(event.sender)) return { ok: false, error: 'Not allowed.' };
  return { ok: true, recommendation: recommendedPerformance() };
});

ipcMain.handle('settings:set-default-browser', async (event) => {
  if (!isSettingsSender(event.sender) || process.platform !== 'win32') return { ok: false };
  setDefaultWebProtocols();
  await shell.openExternal('ms-settings:defaultapps');
  return { ok: true };
});

ipcMain.handle('settings:clear-data', async (event, kind) => {
  if (!isSettingsSender(event.sender)) return { ok: false, error: 'Not allowed.' };
  try {
    if (kind === 'cookies') await session.defaultSession.clearStorageData({ storages: ['cookies'] });
    else if (kind === 'cache') await session.defaultSession.clearCache();
    else return { ok: false, error: 'Unknown browser data type.' };
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
});

ipcMain.handle('updates:check', (event) => {
  if (!isSettingsSender(event.sender)) return { ok: false, error: 'Not allowed.' };
  return checkForUpdates();
});

ipcMain.handle('extensions:load-unpacked', async (event) => {
  if (!isSettingsSender(event.sender)) return { ok: false, error: 'Not allowed.' };
  const owner = BrowserWindow.fromWebContents(event.sender);
  const selection = await dialog.showOpenDialog(owner, {
    title: 'Select an unpacked extension folder',
    properties: ['openDirectory'],
  });
  if (selection.canceled || !selection.filePaths[0]) return { ok: false, canceled: true };
  const directory = path.resolve(selection.filePaths[0]);
  if (directory === path.resolve(UBLOCK_DIR)) return { ok: false, error: 'uBlock Origin is already managed by Safari settings.' };
  try {
    const manifest = JSON.parse(fs.readFileSync(path.join(directory, 'manifest.json'), 'utf8'));
    if (!manifest.name || !manifest.version) return { ok: false, error: 'The selected folder has no valid extension manifest.' };
    const existing = session.defaultSession.extensions.getAllExtensions().find((extension) => path.resolve(extension.path) === directory);
    if (existing) return { ok: true, extension: { id: existing.id, name: existing.name, version: existing.version } };
    const extension = await session.defaultSession.extensions.loadExtension(directory, { allowFileAccess: true });
    const previousDirectories = settings.extraExtensions;
    settings.extraExtensions = [...new Set([...settings.extraExtensions, directory])];
    if (!saveSettings()) {
      settings.extraExtensions = previousDirectories;
      session.defaultSession.extensions.removeExtension(extension.id);
      return { ok: false, error: 'The extension loaded but its folder could not be saved.' };
    }
    userExtensionIds.get(session.defaultSession)?.set(directory, extension.id);
    return { ok: true, extension: { id: extension.id, name: extension.name, version: extension.version } };
  } catch (err) {
    return { ok: false, error: err.message };
  }
});

ipcMain.handle('extensions:remove', (event, extensionId) => {
  if (!isSettingsSender(event.sender)) return { ok: false, error: 'Not allowed.' };
  const extensions = session.defaultSession.extensions;
  const extension = extensions.getAllExtensions().find((item) => item.id === extensionId);
  if (!extension) return { ok: false, error: 'Extension is no longer loaded.' };
  if (path.resolve(extension.path) === path.resolve(UBLOCK_DIR)) return { ok: false, error: 'Manage uBlock Origin with its Settings toggle.' };
  const directory = path.resolve(extension.path);
  const previous = settings.extraExtensions;
  settings.extraExtensions = previous.filter((item) => path.resolve(item) !== directory);
  if (!saveSettings()) {
    settings.extraExtensions = previous;
    return { ok: false, error: 'Could not save extension settings.' };
  }
  extensions.removeExtension(extension.id);
  userExtensionIds.get(session.defaultSession)?.delete(directory);
  return { ok: true };
});

ipcMain.handle('extensions:open-store', (event) => {
  if (!isSettingsSender(event.sender)) return { ok: false };
  const w = [...windows].find((browserWindow) => !browserWindow.win.isDestroyed());
  if (!w) return { ok: false };
  createTab(w, 'https://chromewebstore.google.com/');
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
ipcMain.on('login-field-focus', (event, bounds) => {
  for (const w of windows) {
    const tab = w.tabs.find((item) => item.view.webContents === event.sender);
    if (tab && activeTab(w) === tab) {
      showLoginPasswordMenu(w, tab, bounds);
      return;
    }
  }
});

ipcMain.on('downloads-command', (event, name, payload = {}) => {
  const entry = downloadWindows.get(event.sender.id);
  if (!entry || entry.win.isDestroyed()) return;
  handleDownloadCommand(entry.isPrivate, name, payload.id);
});

ipcMain.on('cmd', (event, name, p = {}) => {
  const w = windowFor(event.sender);
  if (!w) return;
  switch (name) {
    case 'tab:new': createTab(w, HOME_PAGE); break;
    case 'tab:drop': dropTab(w, p.sourceId, p.targetId, p.groupId); break;
    case 'bookmark:toggle': toggleBookmark(w); break;
    case 'passwords:menu': showPasswordsMenu(w, p.x, p.y); break;
    case 'extensions:menu': showExtensionsMenu(w, p.x, p.y); break;
    case 'extensions:store': createTab(w, 'https://chromewebstore.google.com/'); break;
    case 'open-downloads': openDownloads(w); break;
    case 'download:cancel':
    case 'download:open':
    case 'download:show':
    case 'download:clear': handleDownloadCommand(w.isPrivate, name.slice('download:'.length), p.id); break;
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

function sendUpdateStatus(message) {
  updateStatus = message;
  for (const win of settingsWindows) {
    if (!win.isDestroyed()) win.webContents.send('update-status', message);
  }
}

async function offerUpdate(info) {
  if (settings.suppressUpdateNotices) {
    sendUpdateStatus(`Version ${info.version} is available. Update notices are suppressed.`);
    return;
  }
  if (updatePromptOpen) return;
  updatePromptOpen = true;
  const owner = BrowserWindow.getAllWindows().find((win) => !win.isDestroyed());
  const options = {
    type: 'info',
    title: 'Safari update available',
    message: `Safari ${info.version} is available.`,
    detail: 'Would you like to download and install this update now?',
    buttons: ['Update', 'Do not update'],
    defaultId: 0,
    cancelId: 1,
    checkboxLabel: "Don't show update notices again",
    checkboxChecked: false,
  };
  try {
    const result = owner
      ? await dialog.showMessageBox(owner, options)
      : await dialog.showMessageBox(options);
    updatePromptOpen = false;
    if (result.checkboxChecked) {
      settings.suppressUpdateNotices = true;
      saveSettings();
    }
    if (result.response !== 0) {
      sendUpdateStatus(`Version ${info.version} is available.`);
      return;
    }
    sendUpdateStatus('Downloading update...');
    await autoUpdater.downloadUpdate();
  } catch (err) {
    updatePromptOpen = false;
    sendUpdateStatus(`Update download failed: ${err.message}`);
  }
}

async function offerRestart(info) {
  if (settings.suppressUpdateNotices) {
    sendUpdateStatus(`Version ${info.version} is ready and will install when Safari next closes.`);
    return;
  }
  const owner = BrowserWindow.getAllWindows().find((win) => !win.isDestroyed());
  const options = {
    type: 'info',
    title: 'Update ready',
    message: `Safari ${info.version} has finished downloading.`,
    detail: 'Restart Safari now to finish installing the update, or continue browsing and install when you next quit.',
    buttons: ['Restart now', 'Later'],
    defaultId: 0,
    cancelId: 1,
  };
  const result = owner
    ? await dialog.showMessageBox(owner, options)
    : await dialog.showMessageBox(options);
  if (result.response === 0) autoUpdater.quitAndInstall();
  else sendUpdateStatus(`Version ${info.version} will install when Safari next closes.`);
}

function checkForUpdates() {
  if (!app.isPackaged || process.platform !== 'win32' || process.env.PORTABLE_EXECUTABLE_DIR) {
    const error = 'Automatic updates are available in the installed Windows version.';
    sendUpdateStatus(error);
    return Promise.resolve({ ok: false, error });
  }
  if (updateCheckPromise) return updateCheckPromise;
  sendUpdateStatus('Checking for updates...');
  updateCheckPromise = autoUpdater.checkForUpdates()
    .then(() => ({ ok: true }))
    .catch((err) => {
      const error = `Could not check for updates: ${err.message}`;
      sendUpdateStatus(error);
      return { ok: false, error };
    })
    .finally(() => { updateCheckPromise = null; });
  return updateCheckPromise;
}

function setupAutoUpdater() {
  if (!app.isPackaged || process.platform !== 'win32' || process.env.PORTABLE_EXECUTABLE_DIR) {
    if (process.platform === 'win32') sendUpdateStatus('Automatic updates require the installed Windows version; portable builds update manually.');
    return;
  }
  autoUpdater.autoDownload = false;
  autoUpdater.autoInstallOnAppQuit = true;
  autoUpdater.on('checking-for-update', () => sendUpdateStatus('Checking for updates...'));
  autoUpdater.on('update-available', (info) => { offerUpdate(info); });
  autoUpdater.on('update-not-available', (info) => sendUpdateStatus(`Safari ${info.version} is up to date.`));
  autoUpdater.on('download-progress', (progress) => sendUpdateStatus(`Downloading update: ${Math.floor(progress.percent)}%`));
  autoUpdater.on('update-downloaded', (info) => { offerRestart(info).catch((err) => sendUpdateStatus(err.message)); });
  autoUpdater.on('error', (err) => {
    console.warn('Update check failed:', err && err.message);
    sendUpdateStatus(`Update check failed: ${err.message}`);
  });
  checkForUpdates();
}

// Keep the shield counter fresh while pages load.
setInterval(() => {
  if (trackersBlocked !== lastBlockedSent) windows.forEach(push);
}, 1000);

setInterval(enforcePerformanceSettings, 30000);

// ---------- app lifecycle ----------
app.whenReady().then(() => {
  if (process.platform === 'win32') {
    app.setAppUserModelId('com.safari.chromium');
    setDefaultWebProtocols();
  }
  const installedSite = installedSiteLaunch();
  if (installedSite) {
    createInstalledSiteWindow(installedSite.url, installedSite.name);
  } else {
    const startupUrl = process.argv.find((arg) => /^https?:\/\//i.test(arg));
    createWindow({ url: startupUrl || HOME_PAGE });
  }
  setupAutoUpdater();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => app.quit());
