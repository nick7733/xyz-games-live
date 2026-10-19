/**
 * XYZ Games — Zero-Dependency Multi-Device Real-Time Cloud Sync Server (server.js)
 * Works out of the box with pure Node.js (v16+ / v18+ / v20+):
 *   node server.js
 *
 * Features:
 * - Serves Customer Webapp (`index.html`) at `/` and `/index.html`
 * - Serves Super Admin Panel (`admin_panel.html`) at `/admin` and `/admin_panel.html`
 * - Real-time bidirectional state sync across all mobiles & laptops across India:
 *   - GET  /api/xyz-state   -> Fetch master shared state
 *   - POST /api/xyz-state   -> Conflict-free merge & persist state to xyz_cloud_state.json
 *   - PUT  /api/xyz-state   -> Conflict-free merge & persist state
 *   - GET  /api/xyz-stream  -> Server-Sent Events (SSE) <50ms real-time broadcast to all devices
 * - Full CORS enabled so static frontends (Netlify, Vercel, GitHub Pages) can also use this server as their Cloud Sync URL.
 */

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const url = require('node:url');

const PORT = Number(process.env.PORT || 4000);
const STATE_FILE = path.join(__dirname, 'xyz_cloud_state.json');

let masterState = {};
try {
  if (fs.existsSync(STATE_FILE)) {
    masterState = JSON.parse(fs.readFileSync(STATE_FILE, 'utf-8'));
  }
} catch (e) {
  masterState = {};
}

function saveStateToDisk() {
  try {
    fs.writeFileSync(STATE_FILE, JSON.stringify(masterState), 'utf-8');
  } catch (e) {}
}

function mergeArrayById(localArr, remoteArr, idField, preferRemoteOnConflict) {
  const a = Array.isArray(localArr) ? localArr : [];
  const b = Array.isArray(remoteArr) ? remoteArr : [];
  if (a.length === 0) return b;
  if (b.length === 0) return a;
  const map = new Map();
  const order = [];
  const primaryList = preferRemoteOnConflict ? b : a;
  const secondaryList = preferRemoteOnConflict ? a : b;

  primaryList.forEach(item => {
    if (!item || typeof item !== 'object') return;
    const k = item[idField] || item.id || item.userId || item.code;
    if (k) {
      map.set(String(k), Object.assign({}, item));
      order.push(String(k));
    }
  });
  secondaryList.forEach(item => {
    if (!item || typeof item !== 'object') return;
    const k = item[idField] || item.id || item.userId || item.code;
    if (!k) return;
    const sk = String(k);
    if (!map.has(sk)) {
      map.set(sk, Object.assign({}, item));
      order.push(sk);
    } else {
      const existing = map.get(sk);
      const exTs = Number(existing.updatedAt || existing.confirmedAt || existing.resultDeclaredAt || existing.lastAdminBalanceUpdateAt || existing.lastUserBalanceUpdateAt || existing.timestamp || existing.createdAt || 0);
      const itTs = Number(item.updatedAt || item.confirmedAt || item.resultDeclaredAt || item.lastAdminBalanceUpdateAt || item.lastUserBalanceUpdateAt || item.timestamp || item.createdAt || 0);
      if (itTs > exTs) {
        map.set(sk, Object.assign({}, existing, item));
      } else {
        map.set(sk, Object.assign({}, item, existing));
      }
    }
  });
  return order.map(k => map.get(k));
}

function mergeServerState(currentSt, incomingSt) {
  if (!incomingSt || typeof incomingSt !== 'object') return currentSt || {};
  if (!currentSt || typeof currentSt !== 'object' || Object.keys(currentSt).length === 0) {
    return incomingSt;
  }

  const curAdminTs = Number(currentSt.adminUpdatedAt || 0);
  const incAdminTs = Number(incomingSt.adminUpdatedAt || 0);
  const incomingAdminIsNewer = incAdminTs >= curAdminTs;

  const base = Object.assign({}, currentSt, incomingSt);

  const adminKeys = [
    'websiteConfig', 'paymentGatewayConfig', 'upiId', 'usdtAddress', 'currencyConfig',
    'wingoModesConfig', 'wingoRules', 'manualOverrides', 'ludoConfig', 'unoConfig',
    'mathConfig', 'aviatorConfig', 'promoConfig', 'quizQuestions', 'staffAdmins',
    'superAdminConfigured', 'systemToggles', 'auditModalConfig'
  ];
  adminKeys.forEach(k => {
    if (incomingAdminIsNewer && incomingSt[k] !== undefined) {
      base[k] = incomingSt[k];
    } else if (!incomingAdminIsNewer && currentSt[k] !== undefined) {
      base[k] = currentSt[k];
    }
  });
  base.adminUpdatedAt = Math.max(curAdminTs, incAdminTs);

  base.adminUsersList = mergeArrayById(currentSt.adminUsersList, incomingSt.adminUsersList, 'userId', incomingAdminIsNewer);
  base.registeredAccounts = mergeArrayById(currentSt.registeredAccounts, incomingSt.registeredAccounts, 'userId', incomingAdminIsNewer);

  const balByUid = {};
  (base.adminUsersList || []).forEach(u => {
    if (u && u.userId) balByUid[u.userId] = u.cashBalanceInr;
  });
  (base.registeredAccounts || []).forEach(a => {
    if (a && a.userId && balByUid[a.userId] !== undefined) {
      a.cashBalanceInr = balByUid[a.userId];
    }
  });

  base.adminDeposits = mergeArrayById(currentSt.adminDeposits, incomingSt.adminDeposits, 'depositId', true);
  base.adminWithdrawals = mergeArrayById(currentSt.adminWithdrawals, incomingSt.adminWithdrawals, 'withdrawalId', true);
  base.transactions = mergeArrayById(currentSt.transactions, incomingSt.transactions, 'id', true);
  base.myBets = mergeArrayById(currentSt.myBets, incomingSt.myBets, 'id', true);
  base.aviatorMyBets = mergeArrayById(currentSt.aviatorMyBets, incomingSt.aviatorMyBets, 'roundId', true);
  base.lotteryDraws = mergeArrayById(currentSt.lotteryDraws, incomingSt.lotteryDraws, 'drawId', incomingAdminIsNewer);
  base.lotteryTickets = mergeArrayById(currentSt.lotteryTickets, incomingSt.lotteryTickets, 'ticketId', true);
  base.adminNotifications = mergeArrayById(currentSt.adminNotifications, incomingSt.adminNotifications, 'notifId', true);
  base.lotteryNotifications = mergeArrayById(currentSt.lotteryNotifications, incomingSt.lotteryNotifications, 'id', true);
  base.ludoManualMatches = mergeArrayById(currentSt.ludoManualMatches, incomingSt.ludoManualMatches, 'matchId', incomingAdminIsNewer);
  base.ludoTournaments = mergeArrayById(currentSt.ludoTournaments, incomingSt.ludoTournaments, 'tournamentId', incomingAdminIsNewer);
  base.unoManualMatches = mergeArrayById(currentSt.unoManualMatches, incomingSt.unoManualMatches, 'matchId', incomingAdminIsNewer);
  base.unoTournaments = mergeArrayById(currentSt.unoTournaments, incomingSt.unoTournaments, 'tournamentId', incomingAdminIsNewer);
  base.mathManualMatches = mergeArrayById(currentSt.mathManualMatches, incomingSt.mathManualMatches, 'matchId', incomingAdminIsNewer);
  base.mathTournaments = mergeArrayById(currentSt.mathTournaments, incomingSt.mathTournaments, 'tournamentId', incomingAdminIsNewer);
  base.adminPromotions = mergeArrayById(currentSt.adminPromotions, incomingSt.adminPromotions, 'code', incomingAdminIsNewer);
  base.referralMembers = mergeArrayById(currentSt.referralMembers, incomingSt.referralMembers, 'memberId', true);
  base.commissionLedger = mergeArrayById(currentSt.commissionLedger, incomingSt.commissionLedger, 'ledgerId', true);
  base.adminLedger = mergeArrayById(currentSt.adminLedger, incomingSt.adminLedger, 'txCode', true);
  base.supportTickets = mergeArrayById(currentSt.supportTickets, incomingSt.supportTickets, 'ticketId', true);
  base.wingoPeriods = mergeArrayById(currentSt.wingoPeriods, incomingSt.wingoPeriods, 'periodId', true);
  base.wingoSettlements = mergeArrayById(currentSt.wingoSettlements, incomingSt.wingoSettlements, 'settlementId', true);
  base.remoteCommandsQueue = mergeArrayById(currentSt.remoteCommandsQueue, incomingSt.remoteCommandsQueue, 'cmdId', true);
  base.connectedDevices = Object.assign({}, currentSt.connectedDevices || {}, incomingSt.connectedDevices || {});

  return base;
}

const sseClients = new Set();

function broadcastStateToSseClients() {
  const payload = `data: ${JSON.stringify({ type: 'SYNC', state: masterState, ts: Date.now() })}\n\n`;
  sseClients.forEach(res => {
    try {
      res.write(payload);
    } catch (e) {
      sseClients.delete(res);
    }
  });
}

const MIME_MAP = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.svg': 'image/svg+xml'
};

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, apikey, Prefer');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const parsedUrl = url.parse(req.url || '/', true);
  const pathname = parsedUrl.pathname || '/';

  // 1. Real-Time SSE Stream Endpoint
  if (pathname === '/api/xyz-stream' && req.method === 'GET') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive'
    });
    res.write(`data: ${JSON.stringify({ type: 'SYNC', state: masterState, ts: Date.now() })}\n\n`);
    sseClients.add(res);
    req.on('close', () => sseClients.delete(res));
    return;
  }

  // 2. REST State Get / Merge Endpoint (Also supports Firebase-like /xyz_games_state.json path)
  if (pathname === '/api/xyz-state' || pathname === '/xyz_games_state.json') {
    if (req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify(masterState));
      return;
    }
    if (req.method === 'POST' || req.method === 'PUT') {
      let body = '';
      req.on('data', chunk => {
        body += chunk;
        if (body.length > 25 * 1024 * 1024) req.destroy();
      });
      req.on('end', () => {
        try {
          const incoming = JSON.parse(body || '{}');
          const unwrapped = (incoming && incoming.state && typeof incoming.state === 'object') ? incoming.state : incoming;
          masterState = mergeServerState(masterState, unwrapped);
          saveStateToDisk();
          broadcastStateToSseClients();
          res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify(masterState));
        } catch (err) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid JSON payload' }));
        }
      });
      return;
    }
  }

  // 3. Serve Static HTML & Assets
  let targetFile = 'index.html';
  if (pathname === '/admin' || pathname === '/admin/' || pathname === '/admin_panel.html') {
    targetFile = 'admin_panel.html';
  } else if (pathname !== '/' && pathname !== '/index.html') {
    const cleanRel = pathname.replace(/^\/+/, '');
    if (fs.existsSync(path.join(__dirname, cleanRel)) && fs.statSync(path.join(__dirname, cleanRel)).isFile()) {
      targetFile = cleanRel;
    }
  }

  const fullPath = path.join(__dirname, targetFile);
  if (fs.existsSync(fullPath) && fs.statSync(fullPath).isFile()) {
    const ext = path.extname(fullPath).toLowerCase();
    res.writeHead(200, { 'Content-Type': MIME_MAP[ext] || 'application/octet-stream' });
    fs.createReadStream(fullPath).pipe(res);
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
  }
});

if (require.main === module) {
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`=============================================================`);
    console.log(`🚀 XYZ Games Multi-Device Cloud Server running on port ${PORT}`);
    console.log(`📱 Customer Webapp : http://localhost:${PORT}/`);
    console.log(`🛡️ Super Admin     : http://localhost:${PORT}/admin`);
    console.log(`🌐 Live Sync API   : http://localhost:${PORT}/api/xyz-state`);
    console.log(`=============================================================`);
  });
}

module.exports = { server };