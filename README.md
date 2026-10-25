# XYZ Games — Production Full-Stack Platform (v14.0)

Production-ready full-stack gaming webapp and Super Admin operations suite engineered for **20,000+ Daily Active Users (DAU)** with zero external npm runtime dependencies.

## Quick Start (Local Development & Automated Testing)

```bash
# 1. Run the 25-test automated security, financial concurrency & load benchmark suite
npm test

# 2. Start the production server (defaults to port 4000)
npm start
```

* **Customer Webapp**: `http://localhost:4000/`
* **Super Admin Panel**: `http://localhost:4000/admin`
* **Health & WAL Database Telemetry**: `http://localhost:4000/api/health`
* **WinGo Provably Fair Verification**: `http://localhost:4000/api/wingo/verify?slotKey=1MIN`

## Key Production Architecture Highlights (v14.0)

1. **Purpose-Bound JWT Authentication & RBAC (`security.js` + `server.js`)**:
   - Passwords hashed with `scrypt` (`N=16384, r=8, p=1, 64B`) + 16-byte CSPRNG salt and verified via `crypto.timingSafeEqual`.
   - Separate JWT audiences for Admin (`aud: 'xyz-admin'`) and Customer (`aud: 'xyz-customer'`) sessions with `HttpOnly; SameSite=Lax; Secure` cookies and instant JTI revocation (`/api/auth/logout`).
   - Strict server-side RBAC on `/api/admin/wallet-adjust`, `/api/admin/gift-code`, `/api/admin/deposit-resolve`, `/api/admin/withdraw-resolve`, `/api/admin/reconcile`, `/api/xyz-admin-session`, and `POST /api/xyz-state`.
2. **Role-Scoped State Privacy (`redactStateForClient`)**:
   - `GET /api/xyz-state` and `/api/xyz-stream` SSE strip all password hashes and isolate customer records so users never receive other users' balances, bets, or admin data.
3. **Atomic Integer-Paise Financial Engine (`database.js`)**:
   - All balances and transactions are calculated in integer paise (`1 INR = 100 paise`) inside `BEGIN IMMEDIATE` SQLite3 WAL transactions (and mirrored to Supabase PostgreSQL RPCs) with idempotency keys and `CHECK (>= 0)` constraints.
4. **Provably Fair Commit-Reveal WinGo Engine**:
   - Pre-commits `commitHash = sha256(serverSeed)` prior to period cutoff and derives outcomes deterministically via `HMAC-SHA256` independent of player bets, protected by `wingo_settlement_locks` to guarantee single settlement per period.

See [`BUG_FIX_AND_DEPLOYMENT_REPORT.md`](./BUG_FIX_AND_DEPLOYMENT_REPORT.md) for the complete security audit, concurrency test report, and GitHub + Render + Supabase deployment steps.
