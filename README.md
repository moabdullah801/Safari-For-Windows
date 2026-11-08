# 🍎 Safari for Windows

**A Safari-inspired web browser for Windows, powered by Chromium and Electron.**

Safari brings the look and feel of Apple's Safari browser to Windows computers, while using Chromium to provide modern web compatibility and browsing performance.

## ✨ Features

- **Safari-inspired interface** – A Windows browser inspired by Apple's Safari design.
- **Chromium engine** – Uses Chromium through Electron to render websites.
- **Built-in uBlock Origin** – uBlock Origin (uBO) is injected into the browser to provide ad and content blocking.
- **Privacy-focused browsing** – Integrated content-blocking functionality.
- **Windows support** – Designed to run on Windows computers.
- **Portable version** – Run the browser using a standalone `.exe` without a traditional installation.

## 🛡️ Built-in uBlock Origin

This browser includes **uBlock Origin (uBO)** integration.

uBlock Origin is a content blocker that helps block:
- Advertisements
- Trackers
- Unwanted website content
- Other filter-list-defined network requests

The extension is integrated into the browser rather than requiring users to install it separately.

Original project: https://github.com/gorhill/uBlock

## ⚙️ Built With

| Technology | Purpose |
|---|---|
| Electron | Desktop application framework |
| Chromium | Browser rendering engine |
| JavaScript | Application functionality |
| HTML & CSS | Browser interface |
| uBlock Origin | Ad and content blocking |
| electron-builder | Windows application packaging |

## 💻 Installation

### Portable Windows Version

1. Open the repository's **Releases** or **Actions** page.
2. Download the portable Windows executable.
3. Open the `.exe` file.
4. Start browsing!

No separate Chrome installation is required.

## 🛠️ Development

To run the project locally:

1. Install Node.js.
2. Clone this repository.
3. Open the project folder.
4. Install dependencies:

```bash
npm install
```

5. Start Safari:

```bash
npm start
```

## 📦 Building

This project uses electron-builder.

To build the portable Windows version:

```bash
npx electron-builder --win portable
```

The generated application will be placed in the `dist` folder.

GitHub Actions can also be used to build the Windows executable in the cloud.

## 📋 Project Information

- **Name:** Safari
- **Platform:** Windows
- **Framework:** Electron
- **Engine:** Chromium
- **Version:** 1.0.0
- **Packaging:** electron-builder

## ⚖️ Credits & Licensing

This project is an independent Safari-inspired browser for Windows. It is not an official Apple product and is not affiliated with or endorsed by Apple.

Safari is an Apple trademark.

uBlock Origin is an independent open-source project by Raymond Hill (gorhill). It retains its own licensing and attribution requirements.

Electron and Chromium are open-source projects maintained by their respective communities.

---

**Made for Windows. Inspired by Safari. Powered by Chromium. Protected with uBlock Origin.** 🍎
