# XYZ Games — V15 Production Bug-Fix, Cross-Device Sync & Zero-Flicker Report

## 1. Root Causes Identified & Fixed in V15

### A. Why the Admin Panel Was Flickering By Itself

* **Root Cause 1**: In `admin_panel.html`, `onExternalWebappSlotChanged(newSlot)` compared `selectedManualMode !== newSlot`. Whenever a customer had a different WinGo timer tab open (e.g., `30SEC` while the Admin was viewing `1MIN`), every 3-second poll or SSE broadcast triggered `renderCurrentAdminView()`, rebuilding `#admViewContainer.innerHTML` continuously and causing the screen to flicker.

* **Root Cause 2**: In `tickAdminClocks` (running every 1000ms), whenever any of the 5 WinGo modes rolled over (every 30s), `renderCurrentAdminView()` was invoked across all `wingo-*` pages even though the live exposure analyzer (`#wingoLiveExposureWrapper`) and `[data-live-clock]` / `[data-live-period]` spans already update in-place.

* **Root Cause 3**: On the `cloud-devices` page, both the 1800ms in-place table updater and the 3000ms state poll called `renderCurrentAdminView()`.

* **V15 Fix**:

  * Replaced full-DOM rebuilds with `applyRemoteStateToAdminZeroFlicker()`, which computes a deterministic sorted fingerprint (`computeStableAdminFingerprint`) and preserves scroll position (`window.scrollY`), active form inputs, dropdown selections, and open modals.

  * Stopped `onExternalWebappSlotChanged` from overwriting `selectedManualMode` or calling `renderCurrentAdminView()` once the Admin has selected a mode.

### B. Why Deposit & Withdrawal Requests from Another Mobile Were Not Appearing in Admin Panel

* **Root Cause 1**: When a customer on a separate mobile submitted a deposit (`handleProceedToPayment`) or withdrawal (`submitWithdrawalRequest`), the frontend only wrote to local state and called `POST /api/xyz-state` instead of calling the dedicated atomic server endpoints (`POST /api/deposit/submit` and `POST /api/withdraw/submit`).

* **Root Cause 2**: If the customer's browser had an expired or missing JWT token, `mergeServerState()` in `server.js` dropped `incomingSt.adminDeposits` and `incomingSt.adminWithdrawals` silently.

* **Root Cause 3**: If a single network poll in `index.html` or `admin_panel.html` failed on mobile data, `serverApiAvailable = false` caused `buildCloudRequestInfo` / `buildAdminCloudReq` to fall back to the direct Supabase REST URL (`https://acpzrkazjoeylyamdrrq.supabase.co/rest/v1/kv_master_state`) with an empty anon key—which returned `401 Unauthorized` now that RLS is enabled on Supabase!

* **V15 Fix**:

  * Removed the broken direct-Supabase fallback from `index.html` and `admin_panel.html` so both apps **always** communicate through your Render Node.js server (`/api/xyz-state`, `/api/deposit/submit`, `/api/withdraw/submit`, `/api/admin/deposit-resolve`, `/api/admin/withdraw-resolve`), and your Render server syncs with Supabase in the background using your `SUPABASE_SERVICE_ROLE_KEY`.

  * Wired `handleProceedToPayment` directly to `POST /api/deposit/submit` (including `utrNumber`, `paidToId`, `usdtAmount`, `appliedRate`, and `providerRef`) and `submitWithdrawalRequest` directly to `POST /api/withdraw/submit`.

  * Updated `admin_panel.html` so `applyRemoteStateToAdminZeroFlicker` always merges incoming `adminDeposits`, `adminWithdrawals`, `adminUsersList`, and `adminPromotions` even when `db.adminUpdatedAt` is newer locally.

  * Wired Admin Deposit Approve/Reject (`resolveDepositRequest`) to `POST /api/admin/deposit-resolve` and Admin Withdrawal Approve/Reject (`reviewWithdrawalRequest`) to `POST /api/admin/withdraw-resolve`.

### C. Why Admin Controls Worked on the Same Laptop Browser (Tab-to-Tab) But Not on a Separate Mobile Device

* **Root Cause 1**: Same-laptop tabs shared `localStorage` and `BroadcastChannel('xyz_games_live_channel')`, which bypassed the server. A separate mobile phone only talks to the Render server over HTTP/SSE.

* **Root Cause 2**: In `security.js`, `redactStateForClient()` filtered `remoteCommandsQueue` with:

  ```
  if (cmd.targetDeviceId === 'ALL' && !cmd.targetUid) return true;
  if (callerUid && String(cmd.targetUid || '').toUpperCase() === callerUid.toUpperCase()) return true;
  return false;
  
  ```

  When the Admin clicked **🎯 Go (Switch Screen)** or **📢 Alert** on a specific mobile device (`targetDeviceId: 'DEV-123456'`), `targetDeviceId` was not `'ALL'` and `targetUid` was not set—so `redactStateForClient()` stripped the command and the mobile phone never received it!

* **Root Cause 3**: Browser `new EventSource('/api/xyz-stream')` did not attach the `Authorization: Bearer <jwt>` header, so the SSE stream was treated as unauthenticated if third-party cookies were restricted.

* **V15 Fix**:

  * Updated `security.js` (`redactStateForClient`) and `server.js` (`POST /api/device/heartbeat`) so device-targeted commands (`targetDeviceId: 'DEV-...'` or `IND-...`), user-targeted commands (`targetUid`), and broadcast commands (`ALL`) are always delivered to the mobile device both via SSE (`/api/xyz-stream?token=...`) and via the 2-second `/api/device/heartbeat` response.

  * Updated `/api/device/heartbeat` to also return the user's live authoritative `userBalanceInr`, `userPromoInr`, `userStatus`, and `forceLogoutAt` every 2 seconds so any wallet credit/debit, deposit approval, or block/logout from the Admin Panel reflects on the customer's mobile within 1–2 seconds.

## 2. Files to Upload to GitHub (and Auto-Deploy on Render)

Upload these updated files to your GitHub repository:

1. `server.js`

2. `security.js`

3. `database.js`

4. `index.html`

5. `admin_panel.html` (and `super_admin_panel.html` if used)

6. `package.json`

7. `supabase_schema_and_rls.sql`

8. `test_suite_v14.js`

Once pushed to GitHub, click **Manual Deploy -> Deploy latest commit** in your Render dashboard.