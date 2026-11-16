const { app, BrowserWindow, shell, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const net = require('net');
const http = require('http');
const { spawn } = require('child_process');

let win;
let serverProcess;
let shuttingDown = false;

function availablePort() {
  return new Promise((resolve, reject) => {
    const socket = net.createServer();
    socket.on('error', reject);
    socket.listen(0, '127.0.0.1', () => {
      const port = socket.address().port;
      socket.close(() => resolve(port));
    });
  });
}

function waitUntilReady(port) {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const probe = () => {
      if (serverProcess && serverProcess.exitCode !== null) return reject(new Error('Serwer zakończył działanie.'));
      http.get({ host: '127.0.0.1', port, path: '/', timeout: 1000 }, res => {
        res.resume();
        if (res.statusCode === 200) resolve();
        else setTimeout(probe, 250);
      }).on('error', () => {
        if (Date.now() - started > 20000) reject(new Error('Nie można uruchomić lokalnego serwera VILO.'));
        else setTimeout(probe, 250);
      });
    };
    probe();
  });
}

async function start() {
  const port = await availablePort();
  const userDir = path.join(app.getPath('userData'), 'local-data');
  fs.mkdirSync(userDir, { recursive: true });

  // Packaged backend is a frozen Python process with dependencies included.
  // Development mode requires a local Python installation with requirements.
  let command, args;
  if (app.isPackaged) {
    command = path.join(process.resourcesPath, 'backend', 'vilo-server.exe');
    args = [];
  } else {
    command = process.platform === 'win32' ? 'python' : 'python3';
    args = [path.join(__dirname, 'backend', 'backend_entry.py')];
  }
  serverProcess = spawn(command, args, {
    cwd: app.isPackaged ? process.resourcesPath : path.join(__dirname, 'backend'),
    env: { ...process.env, VILO_PORT: String(port), VILO_DATA_DIR: userDir },
    windowsHide: true,
    stdio: 'ignore'
  });
  serverProcess.on('error', err => {
    if (!shuttingDown) dialog.showErrorBox('Nie można uruchomić VILO', String(err.message));
  });
  await waitUntilReady(port);
  const localUrl = `http://127.0.0.1:${port}`;
  win = new BrowserWindow({
    width: 1240, height: 800, minWidth: 790, minHeight: 540,
    title: 'VILO', backgroundColor: '#10131e',
    icon: path.join(__dirname, 'backend', 'static', 'vilo-icon.png'),
    webPreferences: { nodeIntegration: false, contextIsolation: true, sandbox: true, webSecurity: true }
  });
  // Never allow a page to navigate away from the local app origin.
  win.webContents.on('will-navigate', (event, url) => {
    if (!url.startsWith(localUrl + '/')) {
      event.preventDefault();
      if (url.startsWith('https://')) shell.openExternal(url);
    }
  });
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('https://')) shell.openExternal(url);
    return { action: 'deny' };
  });
  await win.loadURL(localUrl);
}

app.whenReady().then(() => start().catch(err => {
  dialog.showErrorBox('VILO — błąd uruchamiania', err.message);
  app.quit();
}));
app.on('window-all-closed', () => app.quit());
app.on('before-quit', () => {
  shuttingDown = true;
  if (serverProcess && serverProcess.exitCode === null) serverProcess.kill();
});
