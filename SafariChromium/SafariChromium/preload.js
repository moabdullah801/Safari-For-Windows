// Preload for the toolbar UI. Exposes a small, explicit API to the page.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('browser', {
  send: (name, payload) => ipcRenderer.send('cmd', name, payload),
  onState: (callback) => ipcRenderer.on('state', (_event, state) => callback(state)),
  onFocusAddress: (callback) => ipcRenderer.on('focus-address', () => callback()),
  settings: {
    get: () => ipcRenderer.invoke('settings:get'),
    save: (updates) => ipcRenderer.invoke('settings:save', updates),
    checkUpdates: () => ipcRenderer.invoke('updates:check'),
    onUpdateStatus: (callback) => ipcRenderer.on('update-status', (_event, message) => callback(message)),
    setDefaultBrowser: () => ipcRenderer.invoke('settings:set-default-browser'),
    clearData: (kind) => ipcRenderer.invoke('settings:clear-data', kind),
    loadUnpackedExtension: () => ipcRenderer.invoke('extensions:load-unpacked'),
    removeExtension: (id) => ipcRenderer.invoke('extensions:remove', id),
    openExtensionStore: () => ipcRenderer.invoke('extensions:open-store'),
    listPasswords: () => ipcRenderer.invoke('passwords:list'),
    importPasswords: () => ipcRenderer.invoke('passwords:import'),
    addPassword: (entry) => ipcRenderer.invoke('passwords:add', entry),
    copyPassword: (id) => ipcRenderer.invoke('passwords:copy', id),
    deletePassword: (id) => ipcRenderer.invoke('passwords:delete', id),
  },
});
