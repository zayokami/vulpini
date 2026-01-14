const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');

let mainWindow = null;
let rustProcess = null;

const API_BASE_URL = 'http://127.0.0.1:9090';

async function fetchApi(endpoint) {
  try {
    const response = await fetch(`${API_BASE_URL}${endpoint}`);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    return await response.json();
  } catch (error) {
    console.error(`API Error: ${endpoint}`, error.message);
    return null;
  }
}

async function startRustBackend() {
  const rustPath = path.join(__dirname, '../../vulpini/target/release/vulpini.exe');
  
  try {
    const { spawn } = require('child_process');
    rustProcess = spawn(rustPath, [], {
      cwd: path.join(__dirname, '../../vulpini'),
      stdio: 'pipe'
    });
    
    rustProcess.stdout.on('data', (data) => {
      console.log(`[Rust] ${data}`);
    });
    
    rustProcess.stderr.on('data', (data) => {
      console.error(`[Rust Error] ${data}`);
    });
    
    rustProcess.on('close', (code) => {
      console.log(`Rust process exited with code ${code}`);
    });
    
    // Wait for API server to be ready
    await new Promise(resolve => setTimeout(resolve, 2000));
    
  } catch (error) {
    console.error('Failed to start Rust backend:', error);
  }
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js')
    },
    frame: true,
    titleBarStyle: 'default'
  });
  
  mainWindow.loadFile(path.join(__dirname, 'renderer/index.html'));
  
  mainWindow.on('closed', () => {
    mainWindow = null;
  });
  
  mainWindow.webContents.openDevTools();
}

app.whenReady().then(async () => {
  createWindow();
  
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
  
  // Start Rust backend
  await startRustBackend();
});

app.on('window-all-closed', () => {
  if (rustProcess) {
    rustProcess.kill();
  }
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// IPC handlers for stats
ipcMain.handle('get-stats', async () => {
  return await fetchApi('/api/stats');
});

ipcMain.handle('get-ips', async () => {
  return await fetchApi('/api/ips');
});

ipcMain.handle('get-anomalies', async () => {
  return await fetchApi('/api/anomalies');
});

ipcMain.handle('get-health', async () => {
  return await fetchApi('/api/health');
});
