# Safari (Chromium)

A Safari-style privacy browser for Windows, built on Chromium using Electron.

## What's included

- **Safari-inspired start page:** favorites, quick links, and a search box. Google is the default search engine; Google, DuckDuckGo, and Bing can be selected in Settings.
- **Safari look:** unified toolbar, original compass app mark, rounded tabs, and system/light/dark themes.
- **Tab groups:** drag tabs onto each other to create a group, onto a group label to join it, or use the toolbar and menu. Tabs animate as they move; New Tab sits at the end of the strip.
- **Bookmarks:** use the star button to save or remove the current page; open saved pages from the Bookmarks menu.
- **Install websites:** choose "Install This Site as an App" from the top-right menu to add a Windows desktop shortcut that opens the site in its own browser window.
- **Cookies and cache:** cookies are enabled by default and can be disabled in Settings. Clear cookies or cached files separately from the Cookies & Cache section.
- **Extensions:** open the Extensions button to visit the Chrome Web Store or manage extensions. Extracted extensions can be loaded and removed in Settings.
- **Settings:** toggle JavaScript and uBlock Origin, control WebAssembly and hardware acceleration (restart required), and set the search engine and appearance.
- **Updates:** installed Windows builds check GitHub Releases at startup and can check manually in Settings. Available updates ask before downloading; notices can be suppressed in Settings while checks continue.
- **Windows integration:** the installer creates Start Menu and desktop shortcuts and registers HTTP/HTTPS and HTML handling. Choose Safari in Windows Settings > Default apps to make it the default browser.
- **Password vault:** add passwords manually or import a Chrome/Edge CSV export. Entries are encrypted with Electron safeStorage. On a matching secure site, focus a login field or use the key button to choose a saved password and fill the form.
- **Passkeys:** supported HTTPS sites can use Chromium WebAuthn with Windows Hello or a security key. Passkeys are created and managed by the site and Windows credential provider, not stored in the browser vault.
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

To publish an auto-updating Windows installer, increment the package version, commit the change, then push a matching `v` tag (for example `v1.0.2`). The release workflow publishes the NSIS installer and update metadata to GitHub Releases. Portable builds do not self-update and must be replaced manually.

Both build workflows accept the GitHub Actions secrets `WINDOWS_CERTIFICATE_BASE64` (a trusted Windows code-signing certificate encoded as base64) and `WINDOWS_CERTIFICATE_PASSWORD`. Without a trusted signing certificate, downloaded executables are unsigned and Chrome or Windows SmartScreen may warn or block them; signing and download reputation can reduce those warnings but cannot guarantee immediate Safe Browsing approval. CI also publishes `SHA256SUMS.txt` so users can verify a download's integrity. A checksum is not a signature and does not establish that a file is safe.

Electron includes a full Chromium engine, so you get Chromium's rendering and JavaScript.

## Files

| File | Purpose |
|---|---|
| `main.js` | Windows, tabs, tab groups, privacy filters, menus |
| `preload.js` | Safe bridge between the toolbar and the main process |
| `login-preload.js` | Detects focused login fields and sends coordinates only to the main process |
| `ui/index.html`, `ui/styles.css`, `ui/app.js` | Toolbar and tab strip |
| `ui/start.html`, `ui/start.css`, `ui/start.js` | Safari-inspired new-tab page |
| `ui/settings.html`, `ui/settings.css`, `ui/settings.js` | Preferences, site data, extensions, and password vault UI |
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
- Passwords are not automatically captured; autofill requires choosing an entry. Import requires a CSV export from Chrome or Edge; direct profile migration is not implemented.
- Passkey creation and selection depend on supported websites, Chromium WebAuthn, and Windows Hello or a security key. The app does not export or store passkey private keys.
- Website desktop shortcuts are currently Windows-only. Chrome Web Store extensions can be browsed, but the store's install flow is not supported by Electron; load unpacked extension folders from Settings instead.
- Automatic updates require the installed NSIS build and a matching tagged GitHub Release. Portable builds and unpackaged development runs do not auto-update.
- Hardware acceleration is enabled by default and background pages are throttled, but actual CPU, GPU, and memory use depends on the sites and device. Cloud gaming performance cannot be guaranteed by the browser.
- Windows requires the user to select Safari from Default apps; an installer cannot silently override the user's browser choice.
- Electron 33 is pinned in `package.json`. You can update it, but test afterwards.
- This is not a copy of Apple's Safari code. It copies the look and feature set, not Apple's engine or source.
