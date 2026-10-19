/**
 * XYZ Games — Zero-Dependency Multi-Device Real-Time Cloud Sync Server (server.js)
 * Works out of the box with pure Node.js (v16+ / v18+ / v20+):
 *   node server.js
 *
 * Features:
 * - Serves Customer Webapp (`index.html`) at `/` and `/index.html`
 * - Serves Super Admin Panel (`admin_panel.html`) at `/admin` and `/admin_panel.html`
 * - Authoritative Role-Separated State Sync across all mobiles & laptops:
 *   - Customer pushes (`isAdminPush: false`) ONLY update customer collections (registrations, deposits,
 *     withdrawals, bets, tickets, heartbeats) and can NEVER overwrite Admin configurations (Banners,
 *     UPI IDs, USDT Addresses, Super Admin credentials, Game Rules, or Tournaments).
 *   - Admin pushes (`isAdminPush: true`) authoritatively update Admin configurations (Banners, UPI IDs,
 *     QR codes, Game Rules, Draws, Tournaments, Staff Admins) using server-side timestamps.
 *   - Once Super Admin registers once on ANY device (`superAdminConfigured: true`), it is permanently
 *     locked on the server so every device opening `/admin` sees ONLY the Login screen.
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
    const raw = fs.readFileSync(STATE_FILE, 'utf-8');
    if (raw && raw.trim()) {
      masterState = JSON.parse(raw);
    }
  }
} catch (e) {
  masterState = {};
}

function saveStateToDisk() {
  try {
    fs.writeFileSync(STATE_FILE, JSON.stringify(masterState), 'utf-8');
  } catch (e) {}
}

function mergeArrayById(localArr, remoteArr, idField, preferIncomingOnConflict) {
  const a = Array.isArray(localArr) ? localArr : [];
  const b = Array.isArray(remoteArr) ? remoteArr : [];
  if (a.length === 0) return b;
  if (b.length === 0) return a;
  const map = new Map();
  const order = [];
  const primaryList = preferIncomingOnConflict ? b : a;
  const secondaryList = preferIncomingOnConflict ? a : b;

  primaryList.forEach(item => {
    if (!item || typeof item !== 'object') return;
    const k = item[idField] || item.id || item.userId || item.code;
    if (k !== undefined && k !== null && k !== '') {
      const sk = String(k);
      map.set(sk, Object.assign({}, item));
      order.push(sk);
    }
  });
  secondaryList.forEach(item => {
    if (!item || typeof item !== 'object') return;
    const k = item[idField] || item.id || item.userId || item.code;
    if (k === undefined || k === null || k === '') return;
    const sk = String(k);
    if (!map.has(sk)) {
      map.set(sk, Object.assign({}, item));
      order.push(sk);
    } else {
      const existing = map.get(sk);
      const exTs = Math.max(
        Number(existing.updatedAt || 0),
        Number(existing.confirmedAt || 0),
        Number(existing.resultDeclaredAt || 0),
        Number(existing.lastAdminBalanceUpdateAt || 0),
        Number(existing.lastUserBalanceUpdateAt || 0),
        Number(existing.timestamp || 0),
        Number(existing.createdAt || 0)
      );
      const itTs = Math.max(
        Number(item.updatedAt || 0),
        Number(item.confirmedAt || 0),
        Number(item.resultDeclaredAt || 0),
        Number(item.lastAdminBalanceUpdateAt || 0),
        Number(item.lastUserBalanceUpdateAt || 0),
        Number(item.timestamp || 0),
        Number(item.createdAt || 0)
      );
      if (itTs > exTs) {
        map.set(sk, Object.assign({}, existing, item));
      } else {
        map.set(sk, Object.assign({}, item, existing));
      }
    }
  });
  return order.map(k => map.get(k));
}

// Keys that belong strictly to device-local UI state and should never pollute global masterState
const DEVICE_LOCAL_UI_KEYS = [
  'darkMode', 'activeSlot', 'isLoggedIn', 'activeUserId', 'username', 'userIdOrEmail'
];

// Keys that are authoritatively controlled by the Admin Panel
const ADMIN_EXCLUSIVE_KEYS = [
  'websiteConfig', 'paymentGatewayConfig', 'upiId', 'usdtAddress', 'currencyConfig',
  'wingoModesConfig', 'wingoRules', 'manualOverrides', 'ludoConfig', 'unoConfig',
  'mathConfig', 'aviatorConfig', 'promoConfig', 'quizQuestions', 'staffAdmins',
  'superAdminConfigured', 'systemToggles', 'auditModalConfig'
];

function mergeServerState(currentSt, incomingSt, isAdminPush) {
  if (!incomingSt || typeof incomingSt !== 'object') return currentSt || {};
  const cur = (currentSt && typeof currentSt === 'object') ? currentSt : {};

  // Start from current master state so customer pushes never clobber admin keys
  const base = Object.assign({}, cur);

  // Check if Super Admin is already configured on the server
  const serverHasSuperAdmin = Boolean(
    cur.superAdminConfigured &&
    Array.isArray(cur.staffAdmins) &&
    cur.staffAdmins.some(a => a && (a.isMasterSuperAdmin || a.roleKey === 'SUPER_ADMIN'))
  );

  // Check if incoming payload is registering or updating Super Admin
  const incomingHasSuperAdmin = Boolean(
    incomingSt.superAdminConfigured &&
    Array.isArray(incomingSt.staffAdmins) &&
    incomingSt.staffAdmins.some(a => a && (a.isMasterSuperAdmin || a.roleKey === 'SUPER_ADMIN'))
  );

  if (isAdminPush) {
    // Authoritative Admin update: apply all admin keys directly from Admin Panel
    ADMIN_EXCLUSIVE_KEYS.forEach(k => {
      if (incomingSt[k] !== undefined) {
        base[k] = incomingSt[k];
      }
    });

    // Permanent lock: once Super Admin is configured on the server, never allow an unconfigured state to wipe it
    if (serverHasSuperAdmin && !incomingHasSuperAdmin) {
      base.superAdminConfigured = true;
      base.staffAdmins = cur.staffAdmins;
    } else if (incomingHasSuperAdmin) {
      base.superAdminConfigured = true;
    }

    base.adminUpdatedAt = Date.now();

    // For Admin-managed collections where Admin can delete or edit items, trust Admin's array if provided,
    // while preserving any brand-new customer registrations/requests
    if (Array.isArray(incomingSt.adminPromotions)) base.adminPromotions = incomingSt.adminPromotions;
    if (Array.isArray(incomingSt.adminNotifications)) base.adminNotifications = incomingSt.adminNotifications;
    if (Array.isArray(incomingSt.lotteryDraws)) base.lotteryDraws = incomingSt.lotteryDraws;
    if (Array.isArray(incomingSt.ludoManualMatches)) base.ludoManualMatches = incomingSt.ludoManualMatches;
    if (Array.isArray(incomingSt.ludoTournaments)) base.ludoTournaments = incomingSt.ludoTournaments;
    if (Array.isArray(incomingSt.unoManualMatches)) base.unoManualMatches = incomingSt.unoManualMatches;
    if (Array.isArray(incomingSt.unoTournaments)) base.unoTournaments = incomingSt.unoTournaments;
    if (Array.isArray(incomingSt.mathManualMatches)) base.mathManualMatches = incomingSt.mathManualMatches;
    if (Array.isArray(incomingSt.mathTournaments)) base.mathTournaments = incomingSt.mathTournaments;
    if (Array.isArray(incomingSt.remoteCommandsQueue)) base.remoteCommandsQueue = incomingSt.remoteCommandsQueue;
    if (Array.isArray(incomingSt.adminAuditLogs)) {
      base.adminAuditLogs = mergeArrayById(cur.adminAuditLogs, incomingSt.adminAuditLogs, 'auditId', true);
    }

    // If Admin explicitly deleted a user, respect Admin's deletion; otherwise merge
    if (Array.isArray(incomingSt.adminUsersList)) {
      base.adminUsersList = incomingSt.adminUsersList;
    }
    if (Array.isArray(incomingSt.registeredAccounts)) {
      base.registeredAccounts = mergeArrayById(cur.registeredAccounts, incomingSt.registeredAccounts, 'userId', true);
    }
  } else {
    // Customer Webapp push:
    // 1. NEVER overwrite ADMIN_EXCLUSIVE_KEYS if server already has them initialized
    ADMIN_EXCLUSIVE_KEYS.forEach(k => {
      if (cur[k] === undefined && incomingSt[k] !== undefined && k !== 'superAdminConfigured' && k !== 'staffAdmins') {
        base[k] = incomingSt[k];
      }
    });

    // 2. Merge customer accounts & balances safely
    base.adminUsersList = mergeArrayById(cur.adminUsersList, incomingSt.adminUsersList, 'userId', false);
    base.registeredAccounts = mergeArrayById(cur.registeredAccounts, incomingSt.registeredAccounts, 'userId', false);

    // 3. Merge tournament participant joins from customer into server tournaments without overwriting Admin tournament setup
    ['ludoTournaments', 'unoTournaments', 'mathTournaments'].forEach(tKey => {
      if (Array.isArray(cur[tKey]) && Array.isArray(incomingSt[tKey])) {
        base[tKey] = cur[tKey].map(srvTr => {
          const incTr = incomingSt[tKey].find(x => x && x.tournamentId === srvTr.tournamentId);
          if (!incTr) return srvTr;
          const mergedTr = Object.assign({}, srvTr);
          if (Number(incTr.joinedPlayersCount || 0) > Number(srvTr.joinedPlayersCount || 0)) {
            mergedTr.joinedPlayersCount = incTr.joinedPlayersCount;
          }
          if (incTr.userJoined) mergedTr.userJoined = true;
          return mergedTr;
        });
      }
    });
  }

  // Synchronize user balances across adminUsersList and registeredAccounts
  const balByUid = {};
  (base.adminUsersList || []).forEach(u => {
    if (u && u.userId) balByUid[u.userId] = u.cashBalanceInr;
  });
  (base.registeredAccounts || []).forEach(a => {
    if (a && a.userId && balByUid[a.userId] !== undefined) {
      a.cashBalanceInr = balByUid[a.userId];
    }
  });

  // Merge shared operational collections by ID
  base.adminDeposits = mergeArrayById(cur.adminDeposits, incomingSt.adminDeposits, 'depositId', isAdminPush);
  base.adminWithdrawals = mergeArrayById(cur.adminWithdrawals, incomingSt.adminWithdrawals, 'withdrawalId', isAdminPush);
  base.transactions = mergeArrayById(cur.transactions, incomingSt.transactions, 'id', isAdminPush);
  base.myBets = mergeArrayById(cur.myBets, incomingSt.myBets, 'id', true);
  base.aviatorMyBets = mergeArrayById(cur.aviatorMyBets, incomingSt.aviatorMyBets, 'roundId', true);
  base.lotteryTickets = mergeArrayById(cur.lotteryTickets, incomingSt.lotteryTickets, 'ticketId', isAdminPush);
  base.lotteryNotifications = mergeArrayById(cur.lotteryNotifications, incomingSt.lotteryNotifications, 'id', true);
  base.referralMembers = mergeArrayById(cur.referralMembers, incomingSt.referralMembers, 'memberId', true);
  base.commissionLedger = mergeArrayById(cur.commissionLedger, incomingSt.commissionLedger, 'ledgerId', isAdminPush);
  base.adminLedger = mergeArrayById(cur.adminLedger, incomingSt.adminLedger, 'txCode', true);
  base.supportTickets = mergeArrayById(cur.supportTickets, incomingSt.supportTickets, 'ticketId', isAdminPush);
  base.wingoPeriods = mergeArrayById(cur.wingoPeriods, incomingSt.wingoPeriods, 'periodId', isAdminPush);
  base.wingoSettlements = mergeArrayById(cur.wingoSettlements, incomingSt.wingoSettlements, 'settlementId', isAdminPush);
  base.ludoPlayerTournamentHistory = mergeArrayById(cur.ludoPlayerTournamentHistory, incomingSt.ludoPlayerTournamentHistory, 'matchId', true);
  base.unoPlayerTournamentHistory = mergeArrayById(cur.unoPlayerTournamentHistory, incomingSt.unoPlayerTournamentHistory, 'matchId', true);
  base.mathPlayerTournamentHistory = mergeArrayById(cur.mathPlayerTournamentHistory, incomingSt.mathPlayerTournamentHistory, 'matchId', true);
  base.mathHistory = mergeArrayById(cur.mathHistory, incomingSt.mathHistory, 'matchId', true);

  if (Array.isArray(cur.claimedCodes) || Array.isArray(incomingSt.claimedCodes)) {
    base.claimedCodes = Array.from(new Set([...(cur.claimedCodes || []), ...(incomingSt.claimedCodes || [])]));
  }
  if (Array.isArray(cur.processedDepositEventIds) || Array.isArray(incomingSt.processedDepositEventIds)) {
    base.processedDepositEventIds = Array.from(new Set([...(cur.processedDepositEventIds || []), ...(incomingSt.processedDepositEventIds || [])]));
  }

  // Merge connectedDevices map
  base.connectedDevices = Object.assign({}, cur.connectedDevices || {}, incomingSt.connectedDevices || {});

  // Clean out device-local UI keys so one device's dark mode or active tab never overwrites another device
  DEVICE_LOCAL_UI_KEYS.forEach(k => {
    delete base[k];
  });

  return base;
}

const sseClients = new Set();

function broadcastStateToSseClients(sourceDeviceId, isAdminPush) {
  const payload = `data: ${JSON.stringify({
    type: 'SYNC',
    sourceDeviceId: sourceDeviceId || '',
    isAdminPush: Boolean(isAdminPush),
    state: masterState,
    ts: Date.now()
  })}\n\n`;
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
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, apikey, Prefer, X-XYZ-Source');

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
    res.write(`data: ${JSON.stringify({ type: 'SYNC', sourceDeviceId: 'SERVER_INIT', state: masterState, ts: Date.now() })}\n\n`);
    sseClients.add(res);
    req.on('close', () => sseClients.delete(res));
    return;
  }

  // 2. Fast Admin Auth Status Check Endpoint
  if (pathname === '/api/xyz-auth-status' && req.method === 'GET') {
    const isConfigured = Boolean(
      masterState.superAdminConfigured &&
      Array.isArray(masterState.staffAdmins) &&
      masterState.staffAdmins.some(a => a && (a.isMasterSuperAdmin || a.roleKey === 'SUPER_ADMIN'))
    );
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify({
      superAdminConfigured: isConfigured,
      staffAdminsCount: Array.isArray(masterState.staffAdmins) ? masterState.staffAdmins.length : 0
    }));
    return;
  }

  // 3. REST State Get / Merge Endpoint (Also supports Firebase-like /xyz_games_state.json path)
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
          const isAdminPush = Boolean(
            incoming && (incoming.isAdminPush === true || req.headers['x-xyz-source'] === 'ADMIN_PANEL')
          );
          const sourceDeviceId = (incoming && incoming.sourceDeviceId) ? String(incoming.sourceDeviceId) : '';
          const unwrapped = (incoming && incoming.state && typeof incoming.state === 'object')
            ? incoming.state
            : incoming;

          masterState = mergeServerState(masterState, unwrapped, isAdminPush);
          saveStateToDisk();
          broadcastStateToSseClients(sourceDeviceId, isAdminPush);

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

  // 4. Serve Static HTML & Assets
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