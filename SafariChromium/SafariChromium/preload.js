// Preload for the toolbar UI. Exposes a small, explicit API to the page.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('browser', {
  send: (name, payload) => ipcRenderer.send('cmd', name, payload),
  onState: (callback) => ipcRenderer.on('state', (_event, state) => callback(state)),
  onFocusAddress: (callback) => ipcRenderer.on('focus-address', () => callback()),
  settings: {
    get: () => ipcRenderer.invoke('settings:get'),
    save: (updates) => ipcRenderer.invoke('settings:save', updates),
    setDefaultBrowser: () => ipcRenderer.invoke('settings:set-default-browser'),
    listPasswords: () => ipcRenderer.invoke('passwords:list'),
    importPasswords: () => ipcRenderer.invoke('passwords:import'),
    addPassword: (entry) => ipcRenderer.invoke('passwords:add', entry),
    copyPassword: (id) => ipcRenderer.invoke('passwords:copy', id),
    deletePassword: (id) => ipcRenderer.invoke('passwords:delete', id),
  },
});
