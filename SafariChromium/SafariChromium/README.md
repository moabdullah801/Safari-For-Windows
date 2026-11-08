# Safari (Chromium)

A Safari-style privacy browser for Windows, built on Chromium using Electron.

## What's included

- **Safari-inspired start page:** favorites, quick links, and a search box. Google is the default search engine; Google, DuckDuckGo, and Bing can be selected in Settings.
- **Safari look:** unified toolbar, original compass app mark, rounded tabs, and system/light/dark themes.
- **Tab groups:** group the current tab with the toolbar button, rename a group by double-clicking its label, and move tabs between groups from the "..." menu.
- **Settings:** toggle JavaScript and uBlock Origin, control WebAssembly and hardware acceleration (restart required), and set the search engine and appearance.
- **Windows integration:** the installer creates Start Menu and desktop shortcuts and registers HTTP/HTTPS and HTML handling. Choose Safari in Windows Settings > Default apps to make it the default browser.
- **Password vault:** add passwords manually or import a Chrome/Edge CSV export. Entries are stored using Electron safeStorage and can be copied or removed from Settings. The app does not yet auto-save or autofill passwords.
- **Privacy:**
  - Blocks about 96,000 ad, tracker and malware hosts, generated from uBlock Origin's bundled filter lists (EasyList, EasyPrivacy, uBlock filters, Peter Lowe's list, URLhaus). Rebuild with `node tools/build-blocklist.js`.
  - Loads the bundled uBlock Origin 1.75.4 extension (`extensions/ublock0`) when enabled in Settings. See "uBlock Origin" below.
  - Sends Do Not Track and Global Privacy Control headers.
  - Denies camera, microphone, location and notification prompts by default.
  - Private windows keep no history and clear their data when closed.
  - Search behavior is configurable in Settings.
- **"..." menu** at the top right, with settings, tab groups, privacy settings, copy link, print and full screen.
- **Keyboard shortcuts:** Ctrl+T new tab, Ctrl+W close tab, Ctrl+L focus address bar, Ctrl+N new window, Ctrl+Shift+N private window, Ctrl+R reload, Ctrl+Tab next tab.

## Build it on Windows

You need Node.js LTS from https://nodejs.org.

```bat
cd safari-chromium
npm install
npm start            :: run it right away to test
npm run build        :: creates an installer and a portable .exe in dist\
```

Electron includes a full Chromium engine, so you get Chromium's rendering and JavaScript.

## Files

| File | Purpose |
|---|---|
| `main.js` | Windows, tabs, tab groups, privacy filters, menus |
| `preload.js` | Safe bridge between the toolbar and the main process |
| `ui/index.html`, `ui/styles.css`, `ui/app.js` | Toolbar and tab strip |
| `ui/start.html`, `ui/start.css`, `ui/start.js` | Safari-inspired new-tab page |
| `ui/settings.html`, `ui/settings.css`, `ui/settings.js` | Preferences and password vault UI |
| `assets/safari-night.svg`, `assets/safari.ico` | Original compass mark for the start page and Windows shortcut |
| `package.json` | Dependencies and build settings |

## uBlock Origin

The extension is loaded with Electron's extension support, which only implements part of Chrome's extension API. uBlock Origin is a Manifest V2 extension that depends on `webRequest` blocking and on Chrome's tab APIs, so its network blocking, cosmetic filtering and popup may be partial or not work here. The host blocklist built from its lists works on its own, whether or not the extension loads.

- Open the extension's settings from the "..." menu: Privacy, then "uBlock Origin Dashboard" (greyed out if the extension did not load).
- If the extension fails to load, the reason is printed in the terminal when you run `npm start`.
- The toolbar popup button is not available.

## Known limits

- Only host-level rules are used from the filter lists. Path rules, resource-type rules and cosmetic (element hiding) filters need the extension.
- There is no history panel yet. History is saved to `history.json` in the app data folder, and "Clear History" is in the "..." menu.
- Passwords are not automatically captured or filled into websites. Import requires a CSV export from Chrome or Edge; direct profile migration is not implemented.
- Hardware acceleration is enabled by default and background pages are throttled, but actual CPU, GPU, and memory use depends on the sites and device. Cloud gaming performance cannot be guaranteed by the browser.
- Windows requires the user to select Safari from Default apps; an installer cannot silently override the user's browser choice.
- Electron 33 is pinned in `package.json`. You can update it, but test afterwards.
- This is not a copy of Apple's Safari code. It copies the look and feature set, not Apple's engine or source.
