# Option 1 Deployment Guide: Render + Supabase + Cloudflare (20,000+ Daily Traffic)

This guide walks you step-by-step through deploying **XYZ Games (`index.html`, `admin_panel.html`, and `server.js`)** using **Render** (Backend & Web Service), **Supabase** (Cloud PostgreSQL Database & Real-Time Sync), and **Cloudflare** (Global CDN, SSL, DDoS Protection & Custom Domain).

---

## Step 1: Set Up Supabase Cloud Database (2 Minutes)

Your project is already pre-configured for your Supabase project (`https://acpzrkazjoeylyamdrrq.supabase.co`).

1. Open your [Supabase Dashboard](https://supabase.com/dashboard/project/acpzrkazjoeylyamdrrq).
2. In the left sidebar, click **SQL Editor** → **New query**.
3. Open `supabase_schema_and_rls.sql` from this package, copy the entire SQL script, paste it into the SQL Editor, and click **Run**.
4. **What this does**:
   - Creates all **30 normalized tables** (`users`, `wallets`, `deposits`, `withdrawals`, `ledger_transactions`, `game_periods`, `game_results`, `settlements`, `commission_ledger`, `admin_users`, `admin_audit_logs`, etc.).
   - Creates `kv_master_state` for instant cloud state hydration across Render restarts and multi-device sync.
   - Enables **Row-Level Security (RLS)** policies and adds `kv_master_state` to `supabase_realtime`.

---

## Step 2: Deploy to Render.com (3 Minutes)

Your package includes `render.yaml` (Render Blueprint) and `package.json` with zero external npm dependencies required, so builds finish in under 15 seconds.

### Method A: 1-Click Render Blueprint (Recommended)
1. Create a new **Private GitHub Repository** and upload the files from this package:
   - `server.js`
   - `database.js`
   - `security.js`
   - `index.html`
   - `admin_panel.html`
   - `package.json`
   - `render.yaml`
   - `supabase_schema_and_rls.sql`
   - `.gitignore`
2. Log in to your [Render Dashboard](https://dashboard.render.com/).
3. Click **New +** → **Blueprint** and connect your GitHub repository.
4. Render will automatically detect `render.yaml`, configure the **Singapore region** (lowest latency for India traffic), set `/api/health` as the health check, and populate all your Supabase and security environment variables.
5. Click **Apply** to deploy.

### Method B: Manual Render Web Service Setup
If you prefer creating a standard Web Service in Render instead of a Blueprint:
1. Click **New +** → **Web Service** → Connect your GitHub repository.
2. Configure the service settings:
   - **Region**: `Singapore (Southeast Asia)` (best for India users)
   - **Runtime**: `Node`
   - **Build Command**: `npm install`
   - **Start Command**: `node server.js`
   - **Instance Type**: **Starter ($7/mo)** or **Standard** (recommended for 20,000+ daily traffic so the container never sleeps and handles 2,000+ concurrent SSE connections).
3. Under **Environment Variables**, add the variables from `.env` (or click **Add from .env** and paste the contents of `.env`).
4. Under **Advanced** → **Health Check Path**, enter `/api/health`.
5. Click **Create Web Service**.

Once live, verify your Render URL:
- **Customer Webapp**: `https://your-service.onrender.com/`
- **Super Admin Panel**: `https://your-service.onrender.com/admin`
- **Live Health & DB Telemetry**: `https://your-service.onrender.com/api/health`

> **How Persistence Works on Render**: Even though Render containers have an ephemeral filesystem on redeploy, `server.js` automatically runs `pullMasterStateFromSupabaseCloud()` on startup to hydrate the latest state from Supabase `kv_master_state` into the local high-speed SQLite3 WAL cache, and pushes every state change back to Supabase in real time.

---

## Step 3: Put Cloudflare in Front of Render (5 Minutes)

Adding Cloudflare gives you a custom domain, global edge caching, DDoS protection, rate limiting, and WebSocket/SSE streaming support for 20,000+ daily users.

### 3A. Connect Custom Domain on Render & Cloudflare DNS
1. In your **Render Web Service** → **Settings** → **Custom Domains**, click **Add Custom Domain** and enter your domain (e.g., `xyzgames.com` and `www.xyzgames.com`).
2. In your **Cloudflare Dashboard** → **DNS** → **Records**, add:
   - **Type**: `CNAME` | **Name**: `@` | **Target**: `your-service.onrender.com` | **Proxy status**: **Proxied (Orange Cloud ON)**
   - **Type**: `CNAME` | **Name**: `www` | **Target**: `your-service.onrender.com` | **Proxy status**: **Proxied (Orange Cloud ON)**

### 3B. Cloudflare SSL/TLS Settings (Crucial to Prevent Redirect Loops)
1. In Cloudflare, go to **SSL/TLS** → **Overview**.
2. Set encryption mode to **Full (strict)**.
3. Go to **SSL/TLS** → **Edge Certificates** and enable:
   - **Always Use HTTPS**: `ON`
   - **Minimum TLS Version**: `TLS 1.2`
   - **Automatic HTTPS Rewrites**: `ON`

### 3C. Cloudflare Cache Rules (Protect Real-Time API & SSE Stream)
To ensure WinGo timers, live balances, and Server-Sent Events (`/api/xyz-stream`) are never cached by Cloudflare's edge:
1. Go to **Caching** → **Cache Rules** → **Create rule**.
2. **Rule Name**: `Bypass API and Admin Cache`
3. **If incoming requests match**:
   - URI Path **starts with** `/api/` **OR**
   - URI Path **starts with** `/admin`
4. **Then**:
   - **Cache eligibility**: `Bypass cache`
5. Click **Deploy**.

### 3D. Cloudflare Speed & Network Settings for 20,000+ DAU
1. Go to **Network** and ensure:
   - **HTTP/2** and **HTTP/3 (with QUIC)**: `ON`
   - **WebSockets**: `ON`
   - **0-RTT Connection Resumption**: `ON`
2. Go to **Security** → **Settings**:
   - **Security Level**: `Medium`
   - **Browser Integrity Check**: `ON`
   - **Bot Fight Mode**: `ON`

---

## Step 4: Post-Deployment Verification Checklist

1. **Check Health Endpoint**: Visit `https://yourdomain.com/api/health` — confirm `"status": "HEALTHY_PRODUCTION"` and `"walMode": true`.
2. **First-Time Super Admin Setup**: Visit `https://yourdomain.com/admin` — create your primary Super Admin Login ID & Password.
3. **Verify Multi-Device Sync**: Log into `https://yourdomain.com/` on a mobile phone and `https://yourdomain.com/admin` on a laptop; confirm the device appears immediately under **Multi-Device Cloud Sync (`🌐 India Sync`)** in the Admin Panel.
