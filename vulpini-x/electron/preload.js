const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('vulpiniAPI', {
  getStats: () => ipcRenderer.invoke('get-stats'),
  getIPs: () => ipcRenderer.invoke('get-ips'),
  getAnomalies: () => ipcRenderer.invoke('get-anomalies'),
  getHealth: () => ipcRenderer.invoke('get-health')
});
