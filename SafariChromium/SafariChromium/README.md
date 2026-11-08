# Safari (Chromium)

A Safari-style privacy browser for Windows, built on Chromium using Electron.

## What's included

- **Safari look:** unified toolbar with a centered address pill, rounded tabs, light and dark themes.
- **Tab groups:** group tabs with a colored label. Double-click a label to rename it. Use the "..." menu to move tabs into groups.
- **Privacy:**
  - Blocks about 96,000 ad, tracker and malware hosts, generated from uBlock Origin's bundled filter lists (EasyList, EasyPrivacy, uBlock filters, Peter Lowe's list, URLhaus). Rebuild with `node tools/build-blocklist.js`.
  - Loads the bundled uBlock Origin 1.75.4 extension (`extensions/ublock0`) into every window. See "uBlock Origin" below.
  - Sends Do Not Track and Global Privacy Control headers.
  - Denies camera, microphone, location and notification prompts by default.
  - Private windows keep no history and clear their data when closed.
  - Search goes to DuckDuckGo by default (change `HOME_PAGE` and `SEARCH_URL` in `main.js`).
- **"..." menu** at the top right, with tab groups, privacy settings, copy link, print and full screen.
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
| `package.json` | Dependencies and build settings |

## uBlock Origin

The extension is loaded with Electron's extension support, which only implements part of Chrome's extension API. uBlock Origin is a Manifest V2 extension that depends on `webRequest` blocking and on Chrome's tab APIs, so its network blocking, cosmetic filtering and popup may be partial or not work here. The host blocklist built from its lists works on its own, whether or not the extension loads.

- Open the extension's settings from the "..." menu: Privacy, then "uBlock Origin Dashboard" (greyed out if the extension did not load).
- If the extension fails to load, the reason is printed in the terminal when you run `npm start`.
- The toolbar popup button is not available.

## Known limits

- Only host-level rules are used from the filter lists. Path rules, resource-type rules and cosmetic (element hiding) filters need the extension.
- There is no history panel yet. History is saved to `history.json` in the app data folder, and "Clear History" is in the "..." menu.
- Electron 33 is pinned in `package.json`. You can update it, but test afterwards.
- This is not a copy of Apple's Safari code. It copies the look and feature set, not Apple's engine or source.
