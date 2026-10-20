/**
 * XYZ Games — Zero-Dependency Multi-Device Real-Time Cloud Sync Server (server.js v11.0)
 * Works out of the box with pure Node.js (v16+ / v18+ / v20+):
 *   node server.js
 *
 * Key Features (v11.0):
 * 1. Serves Customer Webapp (`index.html`) at `/`, `/index.html`, `/register`, `/signup`, `/login`.
 * 2. Serves Admin Panel (`admin_panel.html`) at `/admin`, `/admin/`, and `/admin_panel.html`.
 * 3. Rock-Solid Admin Session Persistence (`/api/xyz-admin-session`):
 *    - Never falsely evicts active Admin sessions; auto-re-registers valid sessions across reloads/restarts.
 * 4. Authoritative Real-Time UTC Clock (`/api/xyz-time`) without polluting localStorage with static timestamps.
 * 5. Instant User Force-Logout (`forceLogoutMap`) & Block Enforcement (`status === 'BLOCKED'`) via SSE & REST.
 * 6. Full All-Games Betting Record Sync (`myBets`, `lotteryTickets`, `unoHistory`, `ludoHistory`, `mathHistory`, `aviatorMyBets`, `allGameBets`).
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

// Clean any legacy static serverNowMs from persisted state so it never freezes client clocks
delete masterState.serverNowMs;

if (!masterState.adminActiveSessions || typeof masterState.adminActiveSessions !== 'object') {
  masterState.adminActiveSessions = {};
}
if (!Array.isArray(masterState.evictedAdminSessions)) {
  masterState.evictedAdminSessions = [];
}
if (!masterState.liveMatchmakingLobby || typeof masterState.liveMatchmakingLobby !== 'object') {
  masterState.liveMatchmakingLobby = { UNO: [], LUDO: [], QUIZ: [] };
}
if (!masterState.forceLogoutMap || typeof masterState.forceLogoutMap !== 'object') {
  masterState.forceLogoutMap = {};
}

function saveStateToDisk() {
  try {
    delete masterState.serverNowMs;
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
    const k = item[idField] || item.id || item.matchId || item.ticketId || item.roundId || item.userId || item.code;
    if (k !== undefined && k !== null && k !== '') {
      const sk = String(k);
      map.set(sk, Object.assign({}, item));
      order.push(sk);
    }
  });
  secondaryList.forEach(item => {
    if (!item || typeof item !== 'object') return;
    const k = item[idField] || item.id || item.matchId || item.ticketId || item.roundId || item.userId || item.code;
    if (k === undefined || k === null || k === '') return;
    const sk = String(k);
    if (!map.has(sk)) {
      map.set(sk, Object.assign({}, item));
      order.push(sk);
    } else {
      const existing = map.get(sk);
      const exTs = Math.max(
        Number(existing.updatedAt || 0),
        Number(existing.statusUpdatedAt || 0),
        Number(existing.forceLogoutAt || 0),
        Number(existing.confirmedAt || 0),
        Number(existing.resultDeclaredAt || 0),
        Number(existing.lastAdminBalanceUpdateAt || 0),
        Number(existing.lastUserBalanceUpdateAt || 0),
        Number(existing.timestamp || 0),
        Number(existing.createdAt || 0)
      );
      const itTs = Math.max(
        Number(item.updatedAt || 0),
        Number(item.statusUpdatedAt || 0),
        Number(item.forceLogoutAt || 0),
        Number(item.confirmedAt || 0),
        Number(item.resultDeclaredAt || 0),
        Number(item.lastAdminBalanceUpdateAt || 0),
        Number(item.lastUserBalanceUpdateAt || 0),
        Number(item.timestamp || 0),
        Number(item.createdAt || 0)
      );
      if (itTs > exTs) {
        map.set(sk, Object.assign({}, existing, item));
      } else if (itTs === exTs && preferIncomingOnConflict) {
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
  'darkMode', 'isLoggedIn', 'activeUserId', 'username', 'userIdOrEmail', 'balance', 'serverNowMs'
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

  // Merge forceLogoutMap authoritatively (keep highest timestamp per userId)
  const mergedForceLogout = Object.assign({}, cur.forceLogoutMap || {});
  if (incomingSt.forceLogoutMap && typeof incomingSt.forceLogoutMap === 'object') {
    Object.keys(incomingSt.forceLogoutMap).forEach(uid => {
      const ts = Number(incomingSt.forceLogoutMap[uid] || 0);
      if (ts > Number(mergedForceLogout[uid] || 0)) {
        mergedForceLogout[uid] = ts;
      }
    });
  }
  base.forceLogoutMap = mergedForceLogout;

  // Sync active WinGo slot between Webapp and Admin Panel based on timestamp
  const curSlotTs = Number(cur.webappActiveWingoUpdatedAt || 0);
  const incSlotTs = Number(incomingSt.webappActiveWingoUpdatedAt || 0);
  if (incSlotTs >= curSlotTs && (incomingSt.webappActiveWingoSlot || incomingSt.activeSlot)) {
    base.webappActiveWingoSlot = incomingSt.webappActiveWingoSlot || incomingSt.activeSlot;
    base.activeSlot = base.webappActiveWingoSlot;
    base.webappActiveWingoPeriodId = incomingSt.webappActiveWingoPeriodId || cur.webappActiveWingoPeriodId || '';
    base.webappActiveWingoUpdatedAt = incSlotTs || Date.now();
  }

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
    if (Array.isArray(incomingSt.remoteCommandsQueue)) {
      base.remoteCommandsQueue = mergeArrayById(cur.remoteCommandsQueue, incomingSt.remoteCommandsQueue, 'cmdId', true);
    }
    if (Array.isArray(incomingSt.adminAuditLogs)) {
      base.adminAuditLogs = mergeArrayById(cur.adminAuditLogs, incomingSt.adminAuditLogs, 'auditId', true);
    }

    if (Array.isArray(incomingSt.adminUsersList)) {
      base.adminUsersList = mergeArrayById(cur.adminUsersList, incomingSt.adminUsersList, 'userId', true);
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

    if (incomingSt.settledPeriodResults && typeof incomingSt.settledPeriodResults === 'object') {
      base.settledPeriodResults = Object.assign({}, incomingSt.settledPeriodResults, cur.settledPeriodResults || {});
    }
    if (incomingSt.manualOverrides && typeof incomingSt.manualOverrides === 'object') {
      base.manualOverrides = Object.assign({}, incomingSt.manualOverrides, cur.manualOverrides || {});
    }

    if (Array.isArray(cur.adminNotifications) && Array.isArray(incomingSt.adminNotifications)) {
      base.adminNotifications = cur.adminNotifications.map(srvN => {
        const incN = incomingSt.adminNotifications.find(x => x && (x.notifId || x.id) === (srvN.notifId || srvN.id));
        if (!incN) return srvN;
        const mergedRead = Array.from(new Set([...(srvN.readByUids || []), ...(incN.readByUids || [])]));
        return Object.assign({}, srvN, { readByUids: mergedRead });
      });
    }

    // Merge users while strictly preserving Admin's status (BLOCKED/ACTIVE) & forceLogoutAt
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

  // Synchronize user balances, status (ACTIVE/BLOCKED), and forceLogoutAt across adminUsersList and registeredAccounts
  const userMetaByUid = {};
  (base.adminUsersList || []).forEach(u => {
    if (!u || !u.userId) return;
    if (base.forceLogoutMap[u.userId] && Number(base.forceLogoutMap[u.userId]) > Number(u.forceLogoutAt || 0)) {
      u.forceLogoutAt = Number(base.forceLogoutMap[u.userId]);
    }
    userMetaByUid[u.userId] = {
      cashBalanceInr: u.cashBalanceInr,
      status: u.status,
      statusUpdatedAt: u.statusUpdatedAt,
      forceLogoutAt: u.forceLogoutAt
    };
  });
  (base.registeredAccounts || []).forEach(a => {
    if (!a || !a.userId) return;
    const meta = userMetaByUid[a.userId];
    if (meta) {
      if (meta.cashBalanceInr !== undefined) a.cashBalanceInr = meta.cashBalanceInr;
      if (meta.status) a.status = meta.status;
      if (meta.statusUpdatedAt) a.statusUpdatedAt = meta.statusUpdatedAt;
      if (meta.forceLogoutAt) a.forceLogoutAt = Math.max(Number(a.forceLogoutAt || 0), Number(meta.forceLogoutAt || 0));
    }
    if (base.forceLogoutMap[a.userId] && Number(base.forceLogoutMap[a.userId]) > Number(a.forceLogoutAt || 0)) {
      a.forceLogoutAt = Number(base.forceLogoutMap[a.userId]);
    }
  });

  base.adminDeposits = mergeArrayById(cur.adminDeposits, incomingSt.adminDeposits, 'depositId', isAdminPush);
  base.adminWithdrawals = mergeArrayById(cur.adminWithdrawals, incomingSt.adminWithdrawals, 'withdrawalId', isAdminPush);
  base.transactions = mergeArrayById(cur.transactions, incomingSt.transactions, 'id', isAdminPush);
  base.myBets = mergeArrayById(cur.myBets, incomingSt.myBets, 'id', true);
  base.aviatorMyBets = mergeArrayById(cur.aviatorMyBets, incomingSt.aviatorMyBets, 'id', true);
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
  base.unoHistory = mergeArrayById(cur.unoHistory, incomingSt.unoHistory, 'matchId', true);
  base.ludoHistory = mergeArrayById(cur.ludoHistory, incomingSt.ludoHistory, 'matchId', true);
  base.allGameBets = mergeArrayById(cur.allGameBets, incomingSt.allGameBets, 'id', true);

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
    base.connectedDevices = Object.assign({}, cur.connectedDevices || {}, incomingSt.connectedDevices);
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
      .slice(0, 60);
  }

  DEVICE_LOCAL_UI_KEYS.forEach(k => {
    delete base[k];
  });

  return base;
}

const sseClients = new Set();

function broadcastStateToSseClients(sourceDeviceId, isAdminPush) {
  delete masterState.serverNowMs;
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

  // 0. Lightweight Authoritative UTC Time Endpoint
  if (pathname === '/api/xyz-time' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify({ ok: true, serverNowMs: Date.now() }));
    return;
  }

  // 1. Real-Time SSE Stream Endpoint
  if (pathname === '/api/xyz-stream' && req.method === 'GET') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive'
    });
    delete masterState.serverNowMs;
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
          // Remove from evictedAdminSessions if re-logging in
          masterState.evictedAdminSessions = masterState.evictedAdminSessions.filter(id => id !== sessionId);
          list = list.filter(s => s && s.sessionId !== sessionId && s.deviceId !== deviceId);
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

          res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({
            ok: true,
            valid: true,
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

        // Action === 'CHECK' / Heartbeat:
        // Only invalidate if explicitly in evictedAdminSessions!
        // If not in list yet (e.g. after server restart or tab reload), auto-register it so Admin NEVER gets falsely logged out.
        const wasExplicitlyEvicted = Boolean(sessionId && masterState.evictedAdminSessions.includes(sessionId));
        if (!wasExplicitlyEvicted && sessionId) {
          const existing = list.find(s => s && s.sessionId === sessionId);
          if (existing) {
            existing.lastSeenAt = Date.now();
          } else {
            list.push({
              sessionId,
              loginId,
              deviceId: deviceId || 'ADM-DEV',
              isSuperAdmin,
              createdAt: Date.now(),
              lastSeenAt: Date.now()
            });
            masterState.adminActiveSessions[bucketKey] = list;
          }
        }
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({
          ok: true,
          valid: !wasExplicitlyEvicted,
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
      delete masterState.serverNowMs;
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
          delete masterState.serverNowMs;
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
    console.log(`🚀 XYZ Games Multi-Device Cloud Server v11.0 running on port ${PORT}`);
    console.log(`📱 Customer Webapp : http://localhost:${PORT}/`);
    console.log(`🎁 Invite Register : http://localhost:${PORT}/register?ref=XYZ7L108`);
    console.log(`🛡️ Super Admin     : http://localhost:${PORT}/admin`);
    console.log(`🌐 Live Sync API   : http://localhost:${PORT}/api/xyz-state`);
    console.log(`=============================================================`);
  });
}

module.exports = { server };