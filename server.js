/**
 * XYZ Games — Zero-Dependency Multi-Device Real-Time Cloud Sync Server (server.js v8.0)
 * Works out of the box with pure Node.js (v16+ / v18+ / v20+):
 *   node server.js
 *
 * Key Features:
 * 1. Serves Customer Webapp (`index.html`) at `/`, `/index.html`, `/register`, `/signup`, `/login`
 *    (so referral invite links like `/?ref=CODE` or `/register?ref=CODE` always open cleanly).
 * 2. Serves Admin Panel (`admin_panel.html`) at `/admin`, `/admin/`, and `/admin_panel.html`.
 * 3. Admin Concurrent Device Session Limiter (`/api/xyz-admin-session`):
 *    - Super Admin: max 5 concurrent devices (6th device login auto-logs out the 1st/oldest device).
 *    - Role Admin: max 30 concurrent devices (31st device login auto-logs out the 1st/oldest device).
 * 4. Real-Time 1vs1 Matchmaking Queue (`/api/xyz-matchmaking`) for UNO, Ludo, and Quiz:
 *    - Matches two real online players if both search within the 2-minute window; otherwise times out after 120s.
 * 5. Authoritative Role-Separated State Sync & WinGo Least-Bet-Exposure (House Profit) Auto-Result Engine.
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

// Active Admin Device Sessions Map:
// { SUPER_ADMIN: [ { sessionId, loginId, deviceId, createdAt, lastSeenAt } ], ROLE_<loginId>: [ ... ] }
if (!masterState.adminActiveSessions || typeof masterState.adminActiveSessions !== 'object') {
  masterState.adminActiveSessions = {};
}
if (!Array.isArray(masterState.evictedAdminSessions)) {
  masterState.evictedAdminSessions = [];
}
// Live 1vs1 Matchmaking Queue: { UNO: [], LUDO: [], QUIZ: [] }
if (!masterState.liveMatchmakingLobby || typeof masterState.liveMatchmakingLobby !== 'object') {
  masterState.liveMatchmakingLobby = { UNO: [], LUDO: [], QUIZ: [] };
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

// Keys that belong strictly to device-local UI state and must NEVER pollute global masterState
const DEVICE_LOCAL_UI_KEYS = [
  'darkMode', 'isLoggedIn', 'activeUserId', 'username', 'userIdOrEmail', 'balance'
];

// Keys that are authoritatively controlled by the Admin Panel
const ADMIN_EXCLUSIVE_KEYS = [
  'websiteConfig', 'paymentGatewayConfig', 'upiId', 'usdtAddress', 'currencyConfig',
  'firstDepositBonusConfig', 'withdrawalConfig', 'depositMinConfig',
  'wingoModesConfig', 'wingoRules', 'manualOverrides', 'settledPeriodResults',
  'ludoConfig', 'unoConfig', 'mathConfig', 'aviatorConfig', 'promoConfig',
  'quizQuestions', 'staffAdmins', 'superAdminConfigured', 'systemToggles', 'auditModalConfig',
  'deletedDeviceIds'
];

function mergeServerState(currentSt, incomingSt, isAdminPush) {
  if (!incomingSt || typeof incomingSt !== 'object') return currentSt || {};
  const cur = (currentSt && typeof currentSt === 'object') ? currentSt : {};

  const base = Object.assign({}, cur);

  const serverHasSuperAdmin = Boolean(
    cur.superAdminConfigured &&
    Array.isArray(cur.staffAdmins) &&
    cur.staffAdmins.some(a => a && (a.isMasterSuperAdmin || a.roleKey === 'SUPER_ADMIN'))
  );

  const incomingHasSuperAdmin = Boolean(
    incomingSt.superAdminConfigured &&
    Array.isArray(incomingSt.staffAdmins) &&
    incomingSt.staffAdmins.some(a => a && (a.isMasterSuperAdmin || a.roleKey === 'SUPER_ADMIN'))
  );

  if (isAdminPush) {
    ADMIN_EXCLUSIVE_KEYS.forEach(k => {
      if (incomingSt[k] !== undefined) {
        base[k] = incomingSt[k];
      }
    });

    if (serverHasSuperAdmin && !incomingHasSuperAdmin) {
      base.superAdminConfigured = true;
      base.staffAdmins = cur.staffAdmins;
    } else if (incomingHasSuperAdmin) {
      base.superAdminConfigured = true;
    }

    base.adminUpdatedAt = Date.now();

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

    if (Array.isArray(incomingSt.adminUsersList)) {
      base.adminUsersList = incomingSt.adminUsersList;
    }
    if (Array.isArray(incomingSt.registeredAccounts)) {
      base.registeredAccounts = mergeArrayById(cur.registeredAccounts, incomingSt.registeredAccounts, 'userId', true);
    }
  } else {
    ADMIN_EXCLUSIVE_KEYS.forEach(k => {
      if (cur[k] === undefined && incomingSt[k] !== undefined && k !== 'superAdminConfigured' && k !== 'staffAdmins') {
        base[k] = incomingSt[k];
      }
    });

    // Allow settledPeriodResults from auto-settled WinGo rounds to merge so all clients see the same least-bet outcome
    if (incomingSt.settledPeriodResults && typeof incomingSt.settledPeriodResults === 'object') {
      base.settledPeriodResults = Object.assign({}, incomingSt.settledPeriodResults, cur.settledPeriodResults || {});
    }

    // Merge customer readByUids on notifications without overwriting Admin notifications list
    if (Array.isArray(cur.adminNotifications) && Array.isArray(incomingSt.adminNotifications)) {
      base.adminNotifications = cur.adminNotifications.map(srvN => {
        const incN = incomingSt.adminNotifications.find(x => x && (x.notifId || x.id) === (srvN.notifId || srvN.id));
        if (!incN) return srvN;
        const mergedRead = Array.from(new Set([...(srvN.readByUids || []), ...(incN.readByUids || [])]));
        return Object.assign({}, srvN, { readByUids: mergedRead });
      });
    }

    base.adminUsersList = mergeArrayById(cur.adminUsersList, incomingSt.adminUsersList, 'userId', false);
    base.registeredAccounts = mergeArrayById(cur.registeredAccounts, incomingSt.registeredAccounts, 'userId', false);

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

  // Merge live 1vs1 matchmaking queues
  if (incomingSt.liveMatchmakingLobby && typeof incomingSt.liveMatchmakingLobby === 'object') {
    if (!base.liveMatchmakingLobby || typeof base.liveMatchmakingLobby !== 'object') {
      base.liveMatchmakingLobby = { UNO: [], LUDO: [], QUIZ: [] };
    }
    ['UNO', 'LUDO', 'QUIZ'].forEach(gKey => {
      base.liveMatchmakingLobby[gKey] = mergeArrayById(
        base.liveMatchmakingLobby[gKey],
        incomingSt.liveMatchmakingLobby[gKey],
        'queueId',
        true
      ).filter(q => q && (Date.now() - Number(q.joinedAt || 0) < 180000));
    });
  }

  // Preserve server-side adminActiveSessions and evictedAdminSessions
  base.adminActiveSessions = cur.adminActiveSessions || {};
  base.evictedAdminSessions = cur.evictedAdminSessions || [];

  base.deletedDeviceIds = Object.assign({}, cur.deletedDeviceIds || {}, incomingSt.deletedDeviceIds || {});
  if (isAdminPush && incomingSt.connectedDevices && typeof incomingSt.connectedDevices === 'object') {
    base.connectedDevices = Object.assign({}, incomingSt.connectedDevices);
  } else {
    base.connectedDevices = Object.assign({}, cur.connectedDevices || {}, incomingSt.connectedDevices || {});
  }
  Object.keys(base.deletedDeviceIds).forEach(delId => {
    const delAt = Number(base.deletedDeviceIds[delId] || 0);
    const devEntry = base.connectedDevices[delId];
    if (devEntry && Number(devEntry.lastSeenAt || 0) <= delAt) {
      delete base.connectedDevices[delId];
    }
  });
  if (Array.isArray(cur.remoteCommandsQueue) || Array.isArray(incomingSt.remoteCommandsQueue)) {
    base.remoteCommandsQueue = mergeArrayById(cur.remoteCommandsQueue, incomingSt.remoteCommandsQueue, 'cmdId', isAdminPush)
      .filter(c => c && (Date.now() - Number(c.createdAt || 0) < 120000))
      .slice(0, 40);
  }

  const curSlotTs = Number(cur.webappActiveWingoUpdatedAt || 0);
  const incSlotTs = Number(incomingSt.webappActiveWingoUpdatedAt || 0);
  if (incSlotTs >= curSlotTs && (incomingSt.webappActiveWingoSlot || incomingSt.activeSlot)) {
    base.activeSlot = incomingSt.webappActiveWingoSlot || incomingSt.activeSlot;
    base.webappActiveWingoSlot = base.activeSlot;
    base.webappActiveWingoPeriodId = incomingSt.webappActiveWingoPeriodId || cur.webappActiveWingoPeriodId || '';
    base.webappActiveWingoUpdatedAt = incSlotTs || Date.now();
  } else if (cur.webappActiveWingoSlot || cur.activeSlot) {
    base.activeSlot = cur.webappActiveWingoSlot || cur.activeSlot;
    base.webappActiveWingoSlot = base.activeSlot;
    base.webappActiveWingoPeriodId = cur.webappActiveWingoPeriodId || '';
    base.webappActiveWingoUpdatedAt = curSlotTs;
  }
  base.serverNowMs = Date.now();

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

  // 2. Admin Concurrent Device Session Endpoint (Super Admin = Max 5 Devices, Role Admin = Max 30 Devices)
  if (pathname === '/api/xyz-admin-session' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        const data = JSON.parse(body || '{}');
        const action = data.action || 'CHECK';
        const loginId = String(data.loginId || '').trim().toLowerCase();
        const isSuperAdmin = Boolean(data.isSuperAdmin);
        const sessionId = String(data.sessionId || '').trim();
        const deviceId = String(data.deviceId || '').trim();
        const bucketKey = isSuperAdmin ? 'SUPER_ADMIN_POOL' : `ROLE_${loginId}`;
        const maxDevices = isSuperAdmin ? 5 : 30;

        if (!masterState.adminActiveSessions) masterState.adminActiveSessions = {};
        if (!Array.isArray(masterState.adminActiveSessions[bucketKey])) {
          masterState.adminActiveSessions[bucketKey] = [];
        }
        if (!Array.isArray(masterState.evictedAdminSessions)) {
          masterState.evictedAdminSessions = [];
        }

        let list = masterState.adminActiveSessions[bucketKey];

        if (action === 'LOGIN') {
          list = list.filter(s => s && s.sessionId !== sessionId);
          list.push({
            sessionId,
            loginId,
            deviceId,
            isSuperAdmin,
            createdAt: Date.now(),
            lastSeenAt: Date.now()
          });
          list.sort((a, b) => Number(a.createdAt || 0) - Number(b.createdAt || 0));

          const evictedNow = [];
          while (list.length > maxDevices) {
            const oldest = list.shift();
            if (oldest && oldest.sessionId) {
              evictedNow.push(oldest.sessionId);
              masterState.evictedAdminSessions.unshift(oldest.sessionId);
            }
          }
          if (masterState.evictedAdminSessions.length > 200) {
            masterState.evictedAdminSessions = masterState.evictedAdminSessions.slice(0, 200);
          }
          masterState.adminActiveSessions[bucketKey] = list;
          saveStateToDisk();
          broadcastStateToSseClients(deviceId, true);

          res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({
            ok: true,
            activeCount: list.length,
            maxDevices,
            evictedSessionIds: evictedNow,
            sessions: list
          }));
          return;
        }

        if (action === 'LOGOUT') {
          masterState.adminActiveSessions[bucketKey] = list.filter(s => s && s.sessionId !== sessionId);
          saveStateToDisk();
          res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ ok: true }));
          return;
        }

        // Action === 'CHECK' / Heartbeat
        const wasEvicted = masterState.evictedAdminSessions.includes(sessionId) ||
                           (sessionId && !list.some(s => s && s.sessionId === sessionId));
        if (!wasEvicted) {
          list.forEach(s => {
            if (s && s.sessionId === sessionId) s.lastSeenAt = Date.now();
          });
        }
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({
          ok: true,
          valid: !wasEvicted,
          activeCount: list.length,
          maxDevices
        }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid JSON' }));
      }
    });
    return;
  }

  // 3. Fast Admin Auth Status Check Endpoint
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

  // 4. REST State Get / Merge Endpoint
  if (pathname === '/api/xyz-state' || pathname === '/xyz_games_state.json') {
    if (req.method === 'GET') {
      masterState.serverNowMs = Date.now();
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

  // 5. Serve Static HTML & SPA Routes (/register, /signup, /login -> index.html; /admin -> admin_panel.html)
  let targetFile = 'index.html';
  if (pathname === '/admin' || pathname === '/admin/' || pathname === '/admin_panel.html') {
    targetFile = 'admin_panel.html';
  } else if (pathname === '/' || pathname === '/index.html' || pathname === '/register' || pathname === '/register/' || pathname === '/signup' || pathname === '/login') {
    targetFile = 'index.html';
  } else {
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
    console.log(`🚀 XYZ Games Multi-Device Cloud Server v8.0 running on port ${PORT}`);
    console.log(`📱 Customer Webapp : http://localhost:${PORT}/`);
    console.log(`🎁 Invite Register : http://localhost:${PORT}/register?ref=XYZ7L108`);
    console.log(`🛡️ Super Admin     : http://localhost:${PORT}/admin`);
    console.log(`🌐 Live Sync API   : http://localhost:${PORT}/api/xyz-state`);
    console.log(`=============================================================`);
  });
}

module.exports = { server };