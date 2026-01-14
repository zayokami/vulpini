const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('vulpiniAPI', {
  getStats: () => ipcRenderer.invoke('get-stats'),
  getIPs: () => ipcRenderer.invoke('get-ips'),
  getAnomalies: () => ipcRenderer.invoke('get-anomalies'),
  getHealth: () => ipcRenderer.invoke('get-health'),
  reloadConfig: () => ipcRenderer.invoke('reload-config'),
  addIP: (ipData) => ipcRenderer.invoke('add-ip', ipData),
  deleteIP: (address) => ipcRenderer.invoke('delete-ip', address)
});
