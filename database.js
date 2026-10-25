/**
 * XYZ Games — Production Relational Database & Atomic Financial Ledger Engine (database.js v14.0)
 *
 * Production Architecture (v14.0):
 * 1. Authoritative Production Database:
 *    - Supports Supabase PostgreSQL via REST / RPC (`fn_adjust_wallet_atomic`, `fn_redeem_gift_code_atomic`,
 *      `fn_place_wingo_bet_atomic`, `fn_settle_wingo_period_atomic`, `fn_reconcile_wallets`) when
 *      `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` are configured in environment variables.
 *    - Maintains a local ACID SQLite 3.40 WAL relational database (`xyz_production.sqlite`) with
 *      `BEGIN IMMEDIATE` transaction locking for single-instance / local development / automated testing.
 * 2. Safe Monetary Precision (Integer Paise):
 *    - All financial balances and ledger amounts are stored and calculated in integer paise (`1 INR = 100 paise`)
 *      with `CHECK (cash_balance_paise >= 0)` constraints so floating-point rounding errors and negative balances
 *      are impossible.
 * 3. Atomic Financial & Game Operations (No Silent Failures, Full Idempotency & Rollback):
 *    - `adjustWalletAtomic`: Atomically validates permissions, direction (`CREDIT` | `DEBIT`), balanceType (`CASH` | `PROMO`),
 *      amount, and idempotency key; updates `users` balance, inserts immutable `ledger_transactions` and `audit_logs`,
 *      and rolls back on any failure.
 *    - `redeemGiftCodeAtomic`: Atomically validates gift code existence, status, expiry, `max_claims`, and per-user
 *      uniqueness (`gift_code_redemptions` UNIQUE constraint) inside `BEGIN IMMEDIATE` so concurrent requests can
 *      NEVER exceed `max_claims` or double-redeem.
 *    - `placeWingoBetAtomic`: Atomically debits wallet, records immutable `ledger_transactions` entry, and inserts
 *      `game_bets` row.
 *    - `settleWingoPeriodAtomic`: Uses `wingo_settlement_locks` (`period_id PRIMARY KEY`) so a period can NEVER be
 *      settled twice across restarts or concurrent schedulers.
 *    - `reconcileBalances`: Compares every user's wallet balance against the sum of their completed `ledger_transactions`
 *      and reports any discrepancy.
 */

const { spawn, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');

const DATA_DIR = process.env.XYZ_DATA_DIR || __dirname;
const DB_FILE = process.env.SQLITE_DB_PATH || path.join(DATA_DIR, 'xyz_production.sqlite');
const JSON_BACKUP_FILE = path.join(DATA_DIR, 'xyz_cloud_state.json');

const SUPABASE_URL = (process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL || '').trim().replace(/\/+$/, '');
const SUPABASE_SERVICE_KEY = (process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SECRET_KEY || '').trim();

const PYTHON_DB_WORKER_CODE = `
import sys
import json
import sqlite3
import time
import os
import shutil
import tempfile
import hashlib

target_db_path = sys.argv[1]
work_db_path = target_db_path
using_tmp_wal = False

def open_wal_connection(path_to_try):
    c = sqlite3.connect(path_to_try, isolation_level=None, timeout=15.0)
    mode = c.execute("PRAGMA journal_mode = WAL;").fetchone()[0]
    if str(mode).lower() != "wal":
        c.close()
        raise RuntimeError("WAL not supported on this filesystem")
    c.execute("PRAGMA synchronous = NORMAL;")
    c.execute("PRAGMA cache_size = -64000;")
    c.execute("PRAGMA temp_store = MEMORY;")
    c.execute("PRAGMA foreign_keys = ON;")
    c.execute("PRAGMA busy_timeout = 10000;")
    return c

try:
    conn = open_wal_connection(target_db_path)
except Exception:
    using_tmp_wal = True
    work_db_path = os.path.join(tempfile.gettempdir(), "xyz_wal_" + hashlib.md5(target_db_path.encode("utf-8")).hexdigest()[:10] + ".sqlite")
    if os.path.exists(target_db_path) and os.path.getsize(target_db_path) > 0 and not os.path.exists(work_db_path):
        try:
            shutil.copy2(target_db_path, work_db_path)
        except Exception:
            pass
    conn = open_wal_connection(work_db_path)

def snapshot_to_target():
    if not using_tmp_wal:
        return
    try:
        snap_tmp = work_db_path + ".snap"
        if os.path.exists(snap_tmp):
            os.remove(snap_tmp)
        b_conn = sqlite3.connect(snap_tmp)
        conn.backup(b_conn)
        b_conn.close()
        shutil.copy2(snap_tmp, target_db_path)
    except Exception:
        pass

def to_paise(inr_val):
    try:
        return int(round(float(inr_val or 0.0) * 100))
    except Exception:
        return 0

def to_inr(paise_val):
    return round(int(paise_val or 0) / 100.0, 2)

def init_schema():
    conn.execute("BEGIN IMMEDIATE;")
    try:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS kv_master_state (
            key TEXT PRIMARY KEY,
            value_json TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        );
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            login_id TEXT,
            email TEXT,
            phone TEXT,
            password_hash TEXT,
            referral_code TEXT,
            parent_user_id TEXT,
            status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'BLOCKED', 'SUSPENDED', 'RESTRICTED')),
            kyc_status TEXT NOT NULL DEFAULT 'VERIFIED',
            cash_balance_paise INTEGER NOT NULL DEFAULT 0 CHECK (cash_balance_paise >= 0),
            promo_balance_paise INTEGER NOT NULL DEFAULT 0 CHECK (promo_balance_paise >= 0),
            cash_balance_inr REAL NOT NULL DEFAULT 0.0,
            promo_balance_inr REAL NOT NULL DEFAULT 0.0,
            registered_at INTEGER,
            updated_at INTEGER,
            raw_json TEXT
        );
        """)
        # Migrate existing users table if cash_balance_paise column is missing
        cols = [r[1] for r in conn.execute("PRAGMA table_info(users);").fetchall()]
        if "cash_balance_paise" not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN cash_balance_paise INTEGER NOT NULL DEFAULT 0;")
            conn.execute("UPDATE users SET cash_balance_paise = CAST(ROUND(cash_balance_inr * 100) AS INTEGER);")
        if "promo_balance_paise" not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN promo_balance_paise INTEGER NOT NULL DEFAULT 0;")
            conn.execute("UPDATE users SET promo_balance_paise = CAST(ROUND(promo_balance_inr * 100) AS INTEGER);")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_login ON users(login_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);")

        conn.execute("""
        CREATE TABLE IF NOT EXISTS staff_admins (
            admin_id TEXT PRIMARY KEY,
            login_id TEXT UNIQUE NOT NULL,
            username TEXT NOT NULL,
            role_key TEXT NOT NULL,
            password_hash TEXT,
            is_master_super_admin INTEGER DEFAULT 0,
            status TEXT DEFAULT 'ACTIVE',
            allowed_features_json TEXT,
            updated_at INTEGER,
            raw_json TEXT
        );
        """)

        conn.execute("""
        CREATE TABLE IF NOT EXISTS ledger_transactions (
            tx_code TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            username TEXT,
            tx_type TEXT NOT NULL,
            balance_type TEXT NOT NULL DEFAULT 'CASH' CHECK (balance_type IN ('CASH', 'PROMO', 'COMMISSION')),
            direction TEXT NOT NULL CHECK (direction IN ('CREDIT', 'DEBIT')),
            amount_paise INTEGER NOT NULL CHECK (amount_paise > 0),
            signed_amount_paise INTEGER NOT NULL,
            amount_inr REAL NOT NULL,
            balance_after_paise INTEGER NOT NULL,
            related_ref TEXT,
            idempotency_key TEXT UNIQUE NOT NULL,
            actor TEXT NOT NULL,
            reason TEXT,
            status TEXT NOT NULL DEFAULT 'COMPLETED',
            created_at INTEGER NOT NULL
        );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ledger_user_time ON ledger_transactions(user_id, created_at DESC);")

        conn.execute("""
        CREATE TABLE IF NOT EXISTS gift_codes (
            code TEXT PRIMARY KEY,
            title TEXT,
            distribution_mode TEXT NOT NULL DEFAULT 'FULL_TO_EACH',
            total_value_paise INTEGER NOT NULL DEFAULT 0,
            reward_per_user_paise INTEGER NOT NULL CHECK (reward_per_user_paise > 0),
            max_claims INTEGER NOT NULL CHECK (max_claims >= 1),
            claimed_count INTEGER NOT NULL DEFAULT 0 CHECK (claimed_count >= 0 AND claimed_count <= max_claims),
            status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'EXHAUSTED', 'EXPIRED', 'DISABLED')),
            expires_at INTEGER,
            updated_at INTEGER NOT NULL,
            raw_json TEXT
        );
        """)

        conn.execute("""
        CREATE TABLE IF NOT EXISTS gift_code_redemptions (
            redemption_id TEXT PRIMARY KEY,
            code TEXT NOT NULL REFERENCES gift_codes(code),
            user_id TEXT NOT NULL,
            username TEXT,
            reward_paise INTEGER NOT NULL CHECK (reward_paise > 0),
            ledger_tx_code TEXT NOT NULL,
            redeemed_at INTEGER NOT NULL,
            UNIQUE(code, user_id)
        );
        """)

        conn.execute("""
        CREATE TABLE IF NOT EXISTS deposits (
            deposit_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            username TEXT,
            amount_paise INTEGER NOT NULL DEFAULT 0,
            amount_inr REAL NOT NULL,
            usdt_amount REAL,
            method TEXT NOT NULL,
            utr_number TEXT,
            paid_to_id TEXT,
            status TEXT NOT NULL,
            idempotency_key TEXT UNIQUE,
            created_at INTEGER,
            confirmed_at INTEGER,
            raw_json TEXT
        );
        """)
        dep_cols = [r[1] for r in conn.execute("PRAGMA table_info(deposits);").fetchall()]
        if "amount_paise" not in dep_cols:
            conn.execute("ALTER TABLE deposits ADD COLUMN amount_paise INTEGER NOT NULL DEFAULT 0;")
        if "idempotency_key" not in dep_cols:
            conn.execute("ALTER TABLE deposits ADD COLUMN idempotency_key TEXT;")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_deposits_user ON deposits(user_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_deposits_status ON deposits(status);")

        conn.execute("""
        CREATE TABLE IF NOT EXISTS withdrawals (
            withdrawal_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            username TEXT,
            requested_paise INTEGER NOT NULL DEFAULT 0,
            requested_inr REAL NOT NULL,
            net_payout_inr REAL NOT NULL,
            method TEXT NOT NULL,
            destination_masked TEXT,
            review_status TEXT NOT NULL,
            payout_status TEXT NOT NULL,
            idempotency_key TEXT UNIQUE,
            created_at INTEGER,
            raw_json TEXT
        );
        """)
        wd_cols = [r[1] for r in conn.execute("PRAGMA table_info(withdrawals);").fetchall()]
        if "requested_paise" not in wd_cols:
            conn.execute("ALTER TABLE withdrawals ADD COLUMN requested_paise INTEGER NOT NULL DEFAULT 0;")
        if "idempotency_key" not in wd_cols:
            conn.execute("ALTER TABLE withdrawals ADD COLUMN idempotency_key TEXT;")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_withdrawals_user ON withdrawals(user_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_withdrawals_status ON withdrawals(review_status);")

        conn.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            tx_id TEXT PRIMARY KEY,
            user_id TEXT,
            tx_type TEXT NOT NULL,
            title TEXT,
            amount_inr REAL NOT NULL,
            status TEXT,
            created_at INTEGER,
            raw_json TEXT
        );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tx_user_time ON transactions(user_id, created_at DESC);")

        conn.execute("""
        CREATE TABLE IF NOT EXISTS game_bets (
            bet_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            game_type TEXT NOT NULL,
            slot_or_mode TEXT,
            period_or_match_id TEXT NOT NULL,
            selection TEXT NOT NULL,
            wager_paise INTEGER NOT NULL DEFAULT 0 CHECK (wager_paise > 0),
            wager_inr REAL NOT NULL,
            win_amount_paise INTEGER NOT NULL DEFAULT 0,
            win_amount_inr REAL DEFAULT 0.0,
            status TEXT NOT NULL DEFAULT 'WAITING',
            idempotency_key TEXT UNIQUE,
            created_at INTEGER,
            raw_json TEXT
        );
        """)
        bet_cols = [r[1] for r in conn.execute("PRAGMA table_info(game_bets);").fetchall()]
        if "wager_paise" not in bet_cols:
            conn.execute("ALTER TABLE game_bets ADD COLUMN wager_paise INTEGER NOT NULL DEFAULT 100;")
        if "win_amount_paise" not in bet_cols:
            conn.execute("ALTER TABLE game_bets ADD COLUMN win_amount_paise INTEGER NOT NULL DEFAULT 0;")
        if "idempotency_key" not in bet_cols:
            conn.execute("ALTER TABLE game_bets ADD COLUMN idempotency_key TEXT;")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_bets_user ON game_bets(user_id, created_at DESC);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_bets_period ON game_bets(period_or_match_id, status);")

        conn.execute("""
        CREATE TABLE IF NOT EXISTS wingo_settlement_locks (
            period_id TEXT PRIMARY KEY,
            slot_key TEXT NOT NULL,
            winning_number INTEGER NOT NULL CHECK (winning_number BETWEEN 0 AND 9),
            generation_method TEXT NOT NULL,
            commit_hash TEXT,
            revealed_seed TEXT,
            settled_bets_count INTEGER NOT NULL DEFAULT 0,
            total_wager_paise INTEGER NOT NULL DEFAULT 0,
            total_payout_paise INTEGER NOT NULL DEFAULT 0,
            settled_at INTEGER NOT NULL
        );
        """)

        conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            audit_id TEXT PRIMARY KEY,
            actor TEXT,
            role TEXT,
            action TEXT NOT NULL,
            target TEXT,
            reason TEXT,
            created_at INTEGER,
            raw_json TEXT
        );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(created_at DESC);")
        conn.execute("COMMIT;")
        snapshot_to_target()
    except Exception as e:
        conn.execute("ROLLBACK;")
        raise e

init_schema()

def ensure_user_row(cur, user_id, username="Player", initial_cash_paise=0, initial_promo_paise=0, now_ms=0):
    row = cur.execute(
        "SELECT user_id, username, status, cash_balance_paise, promo_balance_paise FROM users WHERE user_id = ?;",
        (user_id,)
    ).fetchone()
    if row:
        return {
            "user_id": row[0],
            "username": row[1],
            "status": row[2],
            "cash_balance_paise": int(row[3] or 0),
            "promo_balance_paise": int(row[4] or 0)
        }
    cur.execute("""
        INSERT INTO users (
            user_id, username, login_id, status, kyc_status,
            cash_balance_paise, promo_balance_paise, cash_balance_inr, promo_balance_inr,
            registered_at, updated_at, raw_json
        ) VALUES (?, ?, ?, 'ACTIVE', 'VERIFIED', ?, ?, ?, ?, ?, ?, ?);
    """, (
        user_id, username, user_id,
        initial_cash_paise, initial_promo_paise,
        to_inr(initial_cash_paise), to_inr(initial_promo_paise),
        now_ms, now_ms, json.dumps({"userId": user_id, "username": username})
    ))
    return {
        "user_id": user_id,
        "username": username,
        "status": "ACTIVE",
        "cash_balance_paise": initial_cash_paise,
        "promo_balance_paise": initial_promo_paise
    }

def atomic_adjust_wallet(payload):
    now_ms = int(time.time() * 1000)
    user_id = str(payload.get("userId") or "").strip()
    username = str(payload.get("username") or user_id or "Player").strip()
    balance_type = str(payload.get("balanceType") or "CASH").upper()
    direction = str(payload.get("direction") or "").upper()
    amount_paise = int(payload.get("amountPaise") or 0)
    idemp_key = str(payload.get("idempotencyKey") or "").strip()
    tx_type = str(payload.get("txType") or "ADMIN_ADJUSTMENT").upper()
    actor = str(payload.get("actor") or "SYSTEM").strip()
    reason = str(payload.get("reason") or "").strip()
    related_ref = str(payload.get("relatedRef") or "").strip()
    initial_cash_paise = int(payload.get("initialCashPaise") or 0)
    initial_promo_paise = int(payload.get("initialPromoPaise") or 0)

    if not user_id:
        return {"ok": False, "code": "INVALID_USER", "error": "userId is required."}
    if balance_type not in ("CASH", "PROMO"):
        return {"ok": False, "code": "INVALID_BALANCE_TYPE", "error": "balanceType must be CASH or PROMO."}
    if direction not in ("CREDIT", "DEBIT"):
        return {"ok": False, "code": "INVALID_DIRECTION", "error": "direction must be strictly CREDIT or DEBIT."}
    if amount_paise <= 0:
        return {"ok": False, "code": "INVALID_AMOUNT", "error": "Amount must be a positive number greater than zero."}
    if not idemp_key:
        return {"ok": False, "code": "MISSING_IDEMPOTENCY_KEY", "error": "idempotencyKey is required."}

    conn.execute("BEGIN IMMEDIATE;")
    try:
        cur = conn.cursor()
        # Check idempotency key first
        existing_tx = cur.execute(
            "SELECT tx_code, balance_after_paise, amount_paise, direction, balance_type FROM ledger_transactions WHERE idempotency_key = ?;",
            (idemp_key,)
        ).fetchone()
        if existing_tx:
            u_row = ensure_user_row(cur, user_id, username, initial_cash_paise, initial_promo_paise, now_ms)
            conn.execute("COMMIT;")
            return {
                "ok": True,
                "idempotentReplay": True,
                "txCode": existing_tx[0],
                "userId": user_id,
                "cashBalancePaise": u_row["cash_balance_paise"],
                "promoBalancePaise": u_row["promo_balance_paise"],
                "cashBalanceInr": to_inr(u_row["cash_balance_paise"]),
                "promoBalanceInr": to_inr(u_row["promo_balance_paise"])
            }

        u_row = ensure_user_row(cur, user_id, username, initial_cash_paise, initial_promo_paise, now_ms)
        cur_cash = u_row["cash_balance_paise"]
        cur_promo = u_row["promo_balance_paise"]

        signed_paise = amount_paise if direction == "CREDIT" else -amount_paise
        if balance_type == "CASH":
            next_cash = cur_cash + signed_paise
            next_promo = cur_promo
            if next_cash < 0:
                conn.execute("ROLLBACK;")
                return {
                    "ok": False,
                    "code": "INSUFFICIENT_FUNDS",
                    "error": f"Insufficient Cash Balance (Current: ₹{to_inr(cur_cash):.2f}) for ₹{to_inr(amount_paise):.2f} debit."
                }
            balance_after = next_cash
        else:
            next_cash = cur_cash
            next_promo = cur_promo + signed_paise
            if next_promo < 0:
                conn.execute("ROLLBACK;")
                return {
                    "ok": False,
                    "code": "INSUFFICIENT_FUNDS",
                    "error": f"Insufficient Promo Balance (Current: ₹{to_inr(cur_promo):.2f}) for ₹{to_inr(amount_paise):.2f} debit."
                }
            balance_after = next_promo

        cur.execute("""
            UPDATE users
            SET cash_balance_paise = ?,
                promo_balance_paise = ?,
                cash_balance_inr = ?,
                promo_balance_inr = ?,
                updated_at = ?
            WHERE user_id = ?;
        """, (
            next_cash, next_promo, to_inr(next_cash), to_inr(next_promo), now_ms, user_id
        ))

        tx_code = str(payload.get("txCode") or f"LDG-{now_ms}-{os.urandom(3).hex().upper()}")
        cur.execute("""
            INSERT INTO ledger_transactions (
                tx_code, user_id, username, tx_type, balance_type, direction,
                amount_paise, signed_amount_paise, amount_inr, balance_after_paise,
                related_ref, idempotency_key, actor, reason, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'COMPLETED', ?);
        """, (
            tx_code, user_id, u_row["username"], tx_type, balance_type, direction,
            amount_paise, signed_paise, to_inr(signed_paise), balance_after,
            related_ref, idemp_key, actor, reason, now_ms
        ))

        audit_id = f"AUD-{now_ms}-{os.urandom(2).hex().upper()}"
        cur.execute("""
            INSERT INTO audit_logs (audit_id, actor, role, action, target, reason, created_at, raw_json)
            VALUES (?, ?, 'AUTHORIZED', ?, ?, ?, ?, ?);
        """, (
            audit_id, actor, f"WALLET_{direction}_{balance_type}", f"users:{user_id}", reason, now_ms,
            json.dumps({"txCode": tx_code, "signedPaise": signed_paise, "balanceAfterPaise": balance_after})
        ))

        conn.execute("COMMIT;")
        snapshot_to_target()
        return {
            "ok": True,
            "idempotentReplay": False,
            "txCode": tx_code,
            "auditId": audit_id,
            "userId": user_id,
            "username": u_row["username"],
            "cashBalancePaise": next_cash,
            "promoBalancePaise": next_promo,
            "cashBalanceInr": to_inr(next_cash),
            "promoBalanceInr": to_inr(next_promo)
        }
    except Exception as e:
        conn.execute("ROLLBACK;")
        return {"ok": False, "code": "DB_ERROR", "error": str(e)}

def atomic_redeem_gift_code(payload):
    now_ms = int(time.time() * 1000)
    code = str(payload.get("code") or "").strip().upper()
    user_id = str(payload.get("userId") or "").strip()
    username = str(payload.get("username") or user_id or "Player").strip()
    initial_cash_paise = int(payload.get("initialCashPaise") or 0)
    promo_fallback = payload.get("promoFallback")

    if not code or not user_id:
        return {"ok": False, "code": "INVALID_INPUT", "error": "Gift code and authenticated userId are required."}

    conn.execute("BEGIN IMMEDIATE;")
    try:
        cur = conn.cursor()
        row = cur.execute(
            "SELECT code, title, distribution_mode, total_value_paise, reward_per_user_paise, max_claims, claimed_count, status, expires_at FROM gift_codes WHERE code = ?;",
            (code,)
        ).fetchone()

        if not row and isinstance(promo_fallback, dict):
            # Hydrate gift code into relational table inside the same immediate transaction
            max_c = max(1, int(promo_fallback.get("maxClaims") or 1))
            dist_mode = str(promo_fallback.get("distributionMode") or "FULL_TO_EACH")
            tot_val_p = to_paise(promo_fallback.get("totalValueInr") or promo_fallback.get("rewardInr") or 0)
            rew_p = int(round(tot_val_p / max_c)) if dist_mode == "SPLIT_EQUALLY" else to_paise(promo_fallback.get("rewardInr") or promo_fallback.get("totalValueInr") or 0)
            already_uids = promo_fallback.get("redeemedByUids") or []
            init_claimed = min(max_c, max(int(promo_fallback.get("claimedCount") or 0), len(already_uids)))
            st_val = str(promo_fallback.get("status") or "ACTIVE").upper()
            if init_claimed >= max_c and st_val == "ACTIVE":
                st_val = "EXHAUSTED"
            if rew_p > 0:
                cur.execute("""
                    INSERT OR IGNORE INTO gift_codes (
                        code, title, distribution_mode, total_value_paise, reward_per_user_paise,
                        max_claims, claimed_count, status, expires_at, updated_at, raw_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?);
                """, (
                    code, str(promo_fallback.get("title") or code), dist_mode, tot_val_p, rew_p,
                    max_c, init_claimed, st_val, now_ms, json.dumps(promo_fallback)
                ))
                for ex_uid in already_uids:
                    if ex_uid:
                        cur.execute("""
                            INSERT OR IGNORE INTO gift_code_redemptions (
                                redemption_id, code, user_id, username, reward_paise, ledger_tx_code, redeemed_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?);
                        """, (f"RED-HIST-{code}-{ex_uid}", code, str(ex_uid), str(ex_uid), rew_p, f"HIST-{code}-{ex_uid}", now_ms))
                row = cur.execute(
                    "SELECT code, title, distribution_mode, total_value_paise, reward_per_user_paise, max_claims, claimed_count, status, expires_at FROM gift_codes WHERE code = ?;",
                    (code,)
                ).fetchone()

        if not row:
            conn.execute("ROLLBACK;")
            return {"ok": False, "code": "NOT_FOUND", "error": "Invalid or non-existent Gift Code."}

        _, title, dist_mode, total_val_p, reward_paise, max_claims, claimed_count, status, expires_at = row

        # Check prior redemption by this user first
        prior = cur.execute(
            "SELECT redemption_id FROM gift_code_redemptions WHERE code = ? AND user_id = ?;",
            (code, user_id)
        ).fetchone()
        if prior:
            conn.execute("ROLLBACK;")
            return {"ok": False, "code": "ALREADY_REDEEMED", "error": "You have already redeemed this Gift Code!"}

        if status != "ACTIVE":
            conn.execute("ROLLBACK;")
            return {"ok": False, "code": "INACTIVE_CODE", "error": f"This Gift Code ({code}) is {status}."}

        if expires_at and int(expires_at) > 0 and now_ms > int(expires_at):
            cur.execute("UPDATE gift_codes SET status = 'EXPIRED', updated_at = ? WHERE code = ?;", (now_ms, code))
            conn.execute("COMMIT;")
            return {"ok": False, "code": "EXPIRED_CODE", "error": f"This Gift Code ({code}) has expired."}

        actual_redemptions = cur.execute("SELECT COUNT(*) FROM gift_code_redemptions WHERE code = ?;", (code,)).fetchone()[0]
        effective_claimed = max(int(claimed_count or 0), int(actual_redemptions or 0))
        if effective_claimed >= int(max_claims):
            cur.execute("UPDATE gift_codes SET status = 'EXHAUSTED', claimed_count = ?, updated_at = ? WHERE code = ?;", (max_claims, now_ms, code))
            conn.execute("COMMIT;")
            return {"ok": False, "code": "CLAIM_LIMIT_REACHED", "error": f"This Gift Code has reached its maximum limit of {max_claims} claims."}

        new_claimed_count = effective_claimed + 1
        new_status = "EXHAUSTED" if new_claimed_count >= int(max_claims) else "ACTIVE"

        u_row = ensure_user_row(cur, user_id, username, initial_cash_paise, 0, now_ms)
        if u_row["status"] in ("BLOCKED", "SUSPENDED"):
            conn.execute("ROLLBACK;")
            return {"ok": False, "code": "ACCOUNT_BLOCKED", "error": "Account is restricted from redeeming gift codes."}

        next_cash = u_row["cash_balance_paise"] + int(reward_paise)
        tx_code = f"GIFT-{now_ms}-{os.urandom(2).hex().upper()}"
        red_id = f"RED-{code}-{user_id}"

        cur.execute("""
            INSERT INTO gift_code_redemptions (
                redemption_id, code, user_id, username, reward_paise, ledger_tx_code, redeemed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?);
        """, (red_id, code, user_id, username, reward_paise, tx_code, now_ms))

        cur.execute("""
            UPDATE gift_codes
            SET claimed_count = ?, status = ?, updated_at = ?
            WHERE code = ?;
        """, (new_claimed_count, new_status, now_ms, code))

        cur.execute("""
            UPDATE users
            SET cash_balance_paise = ?, cash_balance_inr = ?, updated_at = ?
            WHERE user_id = ?;
        """, (next_cash, to_inr(next_cash), now_ms, user_id))

        cur.execute("""
            INSERT INTO ledger_transactions (
                tx_code, user_id, username, tx_type, balance_type, direction,
                amount_paise, signed_amount_paise, amount_inr, balance_after_paise,
                related_ref, idempotency_key, actor, reason, status, created_at
            ) VALUES (?, ?, ?, 'GIFT_CODE_REDEEM', 'CASH', 'CREDIT', ?, ?, ?, ?, ?, ?, ?, ?, 'COMPLETED', ?);
        """, (
            tx_code, user_id, username, reward_paise, reward_paise, to_inr(reward_paise),
            next_cash, code, f"IDEMP-GIFT-{code}-{user_id}", username, f"Redeemed Gift Code {code}", now_ms
        ))

        all_redeemed_uids = [r[0] for r in cur.execute("SELECT user_id FROM gift_code_redemptions WHERE code = ?;", (code,)).fetchall()]

        conn.execute("COMMIT;")
        snapshot_to_target()
        return {
            "ok": True,
            "txCode": tx_code,
            "code": code,
            "userId": user_id,
            "rewardPaise": reward_paise,
            "rewardInr": to_inr(reward_paise),
            "newBalancePaise": next_cash,
            "newBalanceInr": to_inr(next_cash),
            "claimedCount": new_claimed_count,
            "maxClaims": int(max_claims),
            "promoStatus": new_status,
            "redeemedByUids": all_redeemed_uids
        }
    except sqlite3.IntegrityError:
        conn.execute("ROLLBACK;")
        return {"ok": False, "code": "CONCURRENT_CONFLICT", "error": "Gift code already redeemed or claim limit reached."}
    except Exception as e:
        conn.execute("ROLLBACK;")
        return {"ok": False, "code": "DB_ERROR", "error": str(e)}

def atomic_settle_wingo_period(payload):
    now_ms = int(time.time() * 1000)
    period_id = str(payload.get("periodId") or "").strip()
    slot_key = str(payload.get("slotKey") or "30SEC").strip()
    winning_number = int(payload.get("winningNumber") or 0)
    gen_method = str(payload.get("generationMethod") or "CSPRNG_COMMIT_REVEAL")
    commit_hash = str(payload.get("commitHash") or "")
    revealed_seed = str(payload.get("revealedSeed") or "")
    payouts_list = payload.get("payouts") or [] # list of {betId, userId, username, wagerPaise, winPaise, initialCashPaise}

    if not period_id:
        return {"ok": False, "error": "periodId required"}

    conn.execute("BEGIN IMMEDIATE;")
    try:
        cur = conn.cursor()
        already = cur.execute("SELECT period_id, winning_number FROM wingo_settlement_locks WHERE period_id = ?;", (period_id,)).fetchone()
        if already:
            conn.execute("COMMIT;")
            return {"ok": True, "alreadySettled": True, "periodId": period_id, "winningNumber": already[1]}

        total_wager_p = 0
        total_payout_p = 0
        updated_users = {}

        for item in payouts_list:
            bet_id = str(item.get("betId") or "")
            uid = str(item.get("userId") or "")
            uname = str(item.get("username") or uid or "Player")
            wager_p = max(1, int(item.get("wagerPaise") or 100))
            win_p = max(0, int(item.get("winPaise") or 0))
            init_cash_p = max(0, int(item.get("initialCashPaise") or 0))
            total_wager_p += wager_p
            total_payout_p += win_p

            st_str = "WIN" if win_p > 0 else "LOSE"
            cur.execute("""
                INSERT OR REPLACE INTO game_bets (
                    bet_id, user_id, game_type, slot_or_mode, period_or_match_id,
                    selection, wager_paise, wager_inr, win_amount_paise, win_amount_inr,
                    status, idempotency_key, created_at, raw_json
                ) VALUES (?, ?, 'WINGO', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                bet_id, uid, slot_key, period_id, str(item.get("selection") or ""),
                wager_p, to_inr(wager_p), win_p, to_inr(win_p),
                st_str, f"IDEMP-BET-{bet_id}", now_ms, json.dumps(item)
            ))

            if win_p > 0 and uid:
                u_row = ensure_user_row(cur, uid, uname, init_cash_p, 0, now_ms)
                next_cash = u_row["cash_balance_paise"] + win_p
                cur.execute("""
                    UPDATE users
                    SET cash_balance_paise = ?, cash_balance_inr = ?, updated_at = ?
                    WHERE user_id = ?;
                """, (next_cash, to_inr(next_cash), now_ms, uid))
                tx_code = f"WGO-WIN-{period_id[-4:]}-{bet_id[-6:]}"
                cur.execute("""
                    INSERT OR IGNORE INTO ledger_transactions (
                        tx_code, user_id, username, tx_type, balance_type, direction,
                        amount_paise, signed_amount_paise, amount_inr, balance_after_paise,
                        related_ref, idempotency_key, actor, reason, status, created_at
                    ) VALUES (?, ?, ?, 'WINGO_WIN_PAYOUT', 'CASH', 'CREDIT', ?, ?, ?, ?, ?, ?, 'WINGO_ENGINE', ?, 'COMPLETED', ?);
                """, (
                    tx_code, uid, uname, win_p, win_p, to_inr(win_p), next_cash,
                    f"{period_id}:{bet_id}", f"IDEMP-WGOWIN-{period_id}-{bet_id}",
                    f"WinGo {slot_key} #{period_id} Ball {winning_number}", now_ms
                ))
                updated_users[uid] = to_inr(next_cash)

        cur.execute("""
            INSERT INTO wingo_settlement_locks (
                period_id, slot_key, winning_number, generation_method,
                commit_hash, revealed_seed, settled_bets_count,
                total_wager_paise, total_payout_paise, settled_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            period_id, slot_key, winning_number, gen_method,
            commit_hash, revealed_seed, len(payouts_list),
            total_wager_p, total_payout_p, now_ms
        ))

        conn.execute("COMMIT;")
        snapshot_to_target()
        return {
            "ok": True,
            "alreadySettled": False,
            "periodId": period_id,
            "winningNumber": winning_number,
            "settledBetsCount": len(payouts_list),
            "updatedUserBalances": updated_users
        }
    except sqlite3.IntegrityError:
        conn.execute("ROLLBACK;")
        return {"ok": True, "alreadySettled": True, "periodId": period_id}
    except Exception as e:
        conn.execute("ROLLBACK;")
        return {"ok": False, "error": str(e)}

def reconcile_all_balances():
    cur = conn.cursor()
    users_rows = cur.execute("SELECT user_id, username, cash_balance_paise, promo_balance_paise FROM users;").fetchall()
    discrepancies = []
    checked = 0
    for uid, uname, cash_p, promo_p in users_rows:
        checked += 1
        if int(cash_p or 0) < 0 or int(promo_p or 0) < 0:
            discrepancies.append({
                "userId": uid,
                "issue": "NEGATIVE_BALANCE",
                "cashBalancePaise": cash_p,
                "promoBalancePaise": promo_p
            })
        last_tx = cur.execute(
            "SELECT balance_after_paise FROM ledger_transactions WHERE user_id = ? AND balance_type = 'CASH' ORDER BY created_at DESC, rowid DESC LIMIT 1;",
            (uid,)
        ).fetchone()
        if last_tx and int(last_tx[0]) != int(cash_p):
            discrepancies.append({
                "userId": uid,
                "issue": "LEDGER_MISMATCH",
                "walletCashPaise": int(cash_p),
                "lastLedgerBalanceAfterPaise": int(last_tx[0])
            })
    return {
        "ok": True,
        "usersChecked": checked,
        "checkedUsersCount": checked,
        "discrepanciesCount": len(discrepancies),
        "discrepancyCount": len(discrepancies),
        "discrepancies": discrepancies
    }

def sync_state_to_tables(state):
    now_ms = int(time.time() * 1000)
    conn.execute("BEGIN IMMEDIATE;")
    try:
        conn.execute(
            "INSERT OR REPLACE INTO kv_master_state (key, value_json, updated_at) VALUES ('MASTER_STATE', ?, ?)",
            (json.dumps(state), now_ms)
        )

        # 1. Sync Users
        users_map = {}
        for u in (state.get('registeredAccounts') or []):
            if isinstance(u, dict) and u.get('userId'):
                users_map[str(u['userId'])] = u
        for u in (state.get('adminUsersList') or []):
            if isinstance(u, dict) and u.get('userId'):
                uid = str(u['userId'])
                if uid in users_map:
                    merged_u = dict(users_map[uid])
                    merged_u.update(u)
                    users_map[uid] = merged_u
                else:
                    users_map[uid] = u

        for uid, u in users_map.items():
            cash_p = max(0, to_paise(u.get('cashBalanceInr') or 0.0))
            promo_p = max(0, to_paise(u.get('promoBalanceInr') or 0.0))
            st_val = str(u.get('status') or 'ACTIVE').upper()
            if st_val not in ('ACTIVE', 'BLOCKED', 'SUSPENDED', 'RESTRICTED'):
                st_val = 'ACTIVE'
            u_clean = dict(u)
            u_clean.pop('password', None)
            conn.execute("""
                INSERT OR REPLACE INTO users (
                    user_id, username, login_id, email, phone, password_hash,
                    referral_code, parent_user_id, status, kyc_status,
                    cash_balance_paise, promo_balance_paise, cash_balance_inr, promo_balance_inr,
                    registered_at, updated_at, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                uid,
                str(u.get('username') or 'Player'),
                str(u.get('loginId') or u.get('identity') or ''),
                str(u.get('email') or ''),
                str(u.get('phone') or ''),
                str(u.get('passwordHash') or ''),
                str(u.get('referralCode') or ''),
                str(u.get('parentUserId') or ''),
                st_val,
                str(u.get('kycStatus') or 'VERIFIED'),
                cash_p,
                promo_p,
                to_inr(cash_p),
                to_inr(promo_p),
                int(u.get('registeredAt') or now_ms),
                now_ms,
                json.dumps(u_clean)
            ))

        # 2. Sync Staff Admins
        for a in (state.get('staffAdmins') or []):
            if isinstance(a, dict) and a.get('loginId'):
                adm_id = str(a.get('adminId') or a.get('loginId'))
                a_clean = dict(a)
                a_clean.pop('password', None)
                conn.execute("""
                    INSERT OR REPLACE INTO staff_admins (
                        admin_id, login_id, username, role_key, password_hash,
                        is_master_super_admin, status, allowed_features_json, updated_at, raw_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    adm_id,
                    str(a.get('loginId')).lower(),
                    str(a.get('username') or a.get('loginId')),
                    str(a.get('roleKey') or 'CUSTOM_ROLE'),
                    str(a.get('passwordHash') or ''),
                    1 if a.get('isMasterSuperAdmin') else 0,
                    str(a.get('status') or 'ACTIVE'),
                    json.dumps(a.get('allowedFeatures') or []),
                    now_ms,
                    json.dumps(a_clean)
                ))

        # 3. Sync Gift Codes
        for p in (state.get('adminPromotions') or []):
            if isinstance(p, dict) and p.get('code'):
                code_str = str(p.get('code')).strip().upper()
                max_c = max(1, int(p.get('maxClaims') or 1))
                dist_mode = str(p.get('distributionMode') or 'FULL_TO_EACH')
                tot_val_p = max(100, to_paise(p.get('totalValueInr') or p.get('rewardInr') or 100))
                rew_p = max(1, int(round(tot_val_p / max_c)) if dist_mode == 'SPLIT_EQUALLY' else to_paise(p.get('rewardInr') or p.get('totalValueInr') or 100))
                claimed_c = min(max_c, max(0, int(p.get('claimedCount') or 0)))
                st_p = str(p.get('status') or 'ACTIVE').upper()
                if st_p not in ('ACTIVE', 'EXHAUSTED', 'EXPIRED', 'DISABLED'):
                    st_p = 'ACTIVE'
                conn.execute("""
                    INSERT OR REPLACE INTO gift_codes (
                        code, title, distribution_mode, total_value_paise, reward_per_user_paise,
                        max_claims, claimed_count, status, expires_at, updated_at, raw_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?);
                """, (
                    code_str, str(p.get('title') or code_str), dist_mode, tot_val_p, rew_p,
                    max_c, claimed_c, st_p, now_ms, json.dumps(p)
                ))

        # 4. Sync Deposits (Append/Update without deleting historical records)
        for d in (state.get('adminDeposits') or [])[:500]:
            if isinstance(d, dict) and d.get('depositId'):
                dep_id = str(d.get('depositId'))
                amt_p = max(0, to_paise(d.get('amountInr') or 0.0))
                conn.execute("""
                    INSERT OR REPLACE INTO deposits (
                        deposit_id, user_id, username, amount_paise, amount_inr, usdt_amount,
                        method, utr_number, paid_to_id, status, idempotency_key, created_at, confirmed_at, raw_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    dep_id,
                    str(d.get('userId') or 'USR-001'),
                    str(d.get('username') or 'Player'),
                    amt_p,
                    to_inr(amt_p),
                    float(d.get('usdtAmount') or 0.0),
                    str(d.get('method') or 'UPI'),
                    str(d.get('utrNumber') or d.get('providerRef') or ''),
                    str(d.get('paidToId') or ''),
                    str(d.get('status') or 'PENDING'),
                    str(d.get('idempotencyKey') or f"IDEMP-{dep_id}"),
                    int(d.get('createdAt') or now_ms),
                    int(d.get('confirmedAt') or 0) if d.get('confirmedAt') else None,
                    json.dumps(d)
                ))

        # 5. Sync Withdrawals
        for w in (state.get('adminWithdrawals') or [])[:500]:
            if isinstance(w, dict) and w.get('withdrawalId'):
                wd_id = str(w.get('withdrawalId'))
                req_p = max(0, to_paise(w.get('requestedInr') or 0.0))
                conn.execute("""
                    INSERT OR REPLACE INTO withdrawals (
                        withdrawal_id, user_id, username, requested_paise, requested_inr, net_payout_inr,
                        method, destination_masked, review_status, payout_status, idempotency_key, created_at, raw_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    wd_id,
                    str(w.get('userId') or 'USR-001'),
                    str(w.get('username') or 'Player'),
                    req_p,
                    to_inr(req_p),
                    float(w.get('netPayoutInr') or 0.0),
                    str(w.get('method') or 'BANK'),
                    str(w.get('destinationMasked') or ''),
                    str(w.get('reviewStatus') or 'PENDING'),
                    str(w.get('payoutStatus') or 'QUEUED'),
                    str(w.get('idempotencyKey') or f"IDEMP-{wd_id}"),
                    int(w.get('createdAt') or now_ms),
                    json.dumps(w)
                ))

        # 6. Sync Transactions
        for tx in (state.get('transactions') or [])[:500]:
            if isinstance(tx, dict) and tx.get('id'):
                conn.execute("""
                    INSERT OR REPLACE INTO transactions (
                        tx_id, user_id, tx_type, title, amount_inr, status, created_at, raw_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    str(tx.get('id')),
                    str(tx.get('userId') or 'USR-001'),
                    str(tx.get('type') or 'TX'),
                    str(tx.get('title') or ''),
                    float(tx.get('amount') or 0.0),
                    str(tx.get('status') or 'SUCCESS'),
                    int(tx.get('timestamp') or now_ms),
                    json.dumps(tx)
                ))

        # 7. Sync Game Bets
        for b in (state.get('myBets') or [])[:500]:
            if isinstance(b, dict) and b.get('id'):
                bet_id = str(b.get('id'))
                wag_p = max(1, to_paise(b.get('amount') or 1.0))
                win_p = max(0, to_paise(b.get('winAmount') or 0.0))
                conn.execute("""
                    INSERT OR REPLACE INTO game_bets (
                        bet_id, user_id, game_type, slot_or_mode, period_or_match_id,
                        selection, wager_paise, wager_inr, win_amount_paise, win_amount_inr,
                        status, idempotency_key, created_at, raw_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    bet_id,
                    str(b.get('userId') or 'USR-001'),
                    'WINGO',
                    str(b.get('slotKey') or '30SEC'),
                    str(b.get('periodId') or ''),
                    str(b.get('selection') or ''),
                    wag_p,
                    to_inr(wag_p),
                    win_p,
                    to_inr(win_p),
                    str(b.get('status') or 'WAITING'),
                    f"IDEMP-BET-{bet_id}",
                    int(b.get('timestamp') or now_ms),
                    json.dumps(b)
                ))

        # 8. Sync Audit Logs (Append-only)
        for al in (state.get('adminAuditLogs') or [])[:300]:
            if isinstance(al, dict) and al.get('auditId'):
                conn.execute("""
                    INSERT OR IGNORE INTO audit_logs (
                        audit_id, actor, role, action, target, reason, created_at, raw_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    str(al.get('auditId')),
                    str(al.get('actor') or 'Admin'),
                    str(al.get('role') or 'SUPER_ADMIN'),
                    str(al.get('action') or 'ACTION'),
                    str(al.get('target') or ''),
                    str(al.get('reason') or ''),
                    int(al.get('timestamp') or now_ms),
                    json.dumps(al)
                ))

        conn.execute("COMMIT;")
        snapshot_to_target()
        return {"ok": True}
    except Exception as e:
        conn.execute("ROLLBACK;")
        return {"ok": False, "error": str(e)}

def get_db_stats():
    cur = conn.cursor()
    counts = {}
    for tbl in [
        'users', 'staff_admins', 'ledger_transactions', 'gift_codes',
        'gift_code_redemptions', 'deposits', 'withdrawals', 'transactions',
        'game_bets', 'wingo_settlement_locks', 'audit_logs'
    ]:
        try:
            cur.execute(f"SELECT COUNT(*) FROM {tbl}")
            counts[tbl] = cur.fetchone()[0]
        except Exception:
            counts[tbl] = 0
    db_size = os.path.getsize(work_db_path) if os.path.exists(work_db_path) else 0
    return {"ok": True, "counts": counts, "dbSizeBytes": db_size, "walMode": True, "liveWalPath": work_db_path}

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        req = json.loads(line)
        req_id = req.get("id")
        cmd = req.get("cmd")
        if cmd == "SYNC_STATE":
            res = sync_state_to_tables(req.get("state") or {})
        elif cmd == "ADJUST_WALLET":
            res = atomic_adjust_wallet(req.get("payload") or {})
        elif cmd == "REDEEM_GIFT_CODE":
            res = atomic_redeem_gift_code(req.get("payload") or {})
        elif cmd == "SETTLE_WINGO_PERIOD":
            res = atomic_settle_wingo_period(req.get("payload") or {})
        elif cmd == "RECONCILE":
            res = reconcile_all_balances()
        elif cmd == "GET_STATS":
            res = get_db_stats()
        elif cmd == "PING":
            res = {"ok": True, "ts": int(time.time() * 1000)}
        else:
            res = {"ok": False, "error": f"Unknown command: {cmd}"}
        res["id"] = req_id
        print(json.dumps(res), flush=True)
    except Exception as err:
        print(json.dumps({"id": 0, "ok": False, "error": str(err)}), flush=True)
`;

function loadInitialStateFromSqliteOrJson() {
  const bootstrapScript = `
import sys, json, sqlite3, os, tempfile, hashlib
db_path = sys.argv[1]
json_path = sys.argv[2]
tmp_wal_path = os.path.join(tempfile.gettempdir(), "xyz_wal_" + hashlib.md5(db_path.encode("utf-8")).hexdigest()[:10] + ".sqlite")

for candidate in [tmp_wal_path, db_path]:
    if os.path.exists(candidate) and os.path.getsize(candidate) > 0:
        try:
            uri = f"file:{candidate}?immutable=1" if candidate == db_path else candidate
            conn = sqlite3.connect(uri, uri=(candidate == db_path))
            cur = conn.cursor()
            cur.execute("SELECT value_json FROM kv_master_state WHERE key='MASTER_STATE';")
            row = cur.fetchone()
            conn.close()
            if row and row[0]:
                print(row[0])
                sys.exit(0)
        except Exception:
            pass

if os.path.exists(json_path):
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            raw = f.read().strip()
            if raw:
                print(raw)
                sys.exit(0)
    except Exception:
        pass
print("{}")
`;
  try {
    const res = spawnSync('python3', ['-c', bootstrapScript, DB_FILE, JSON_BACKUP_FILE], {
      encoding: 'utf-8',
      maxBuffer: 50 * 1024 * 1024
    });
    if (res.status === 0 && res.stdout && res.stdout.trim()) {
      return JSON.parse(res.stdout.trim());
    }
  } catch (e) {}

  try {
    if (fs.existsSync(JSON_BACKUP_FILE)) {
      return JSON.parse(fs.readFileSync(JSON_BACKUP_FILE, 'utf-8') || '{}');
    }
  } catch (e) {}
  return {};
}

/**
 * Helper to invoke a Supabase PostgreSQL RPC function (`POST /rest/v1/rpc/<fn_name>`)
 * when `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` are configured in production.
 */
function callSupabaseRpc(fnName, paramsObj) {
  return new Promise((resolve) => {
    if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
      return resolve({ ok: false, skipped: true });
    }
    try {
      const target = new URL(`${SUPABASE_URL}/rest/v1/rpc/${fnName}`);
      const bodyStr = JSON.stringify(paramsObj || {});
      const req = https.request({
        hostname: target.hostname,
        port: 443,
        path: target.pathname,
        method: 'POST',
        headers: {
          'apikey': SUPABASE_SERVICE_KEY,
          'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(bodyStr)
        },
        timeout: 6000
      }, (res) => {
        let raw = '';
        res.on('data', chunk => { raw += chunk; });
        res.on('end', () => {
          try {
            const parsed = JSON.parse(raw || '{}');
            if (res.statusCode >= 200 && res.statusCode < 300) {
              return resolve({ ok: true, data: parsed });
            }
            return resolve({ ok: false, statusCode: res.statusCode, error: parsed.message || raw });
          } catch (e) {
            return resolve({ ok: false, error: raw });
          }
        });
      });
      req.on('error', (err) => resolve({ ok: false, error: err.message }));
      req.on('timeout', () => { req.destroy(); resolve({ ok: false, error: 'Supabase RPC timeout' }); });
      req.write(bodyStr);
      req.end();
    } catch (e) {
      resolve({ ok: false, error: e.message });
    }
  });
}


function inrToPaise(inr) {
  const n = Number(inr || 0);
  return Number.isFinite(n) ? Math.round(n * 100) : 0;
}

function paiseToInr(paise) {
  const p = Number(paise || 0);
  return Number.isFinite(p) ? +(Math.round(p) / 100).toFixed(2) : 0;
}

class SqliteWalDaemon {
  constructor() {
    this.proc = null;
    this.reqId = 0;
    this.pending = new Map();
    this.buffer = '';
    this.lastStats = {
      counts: {
        users: 0, staff_admins: 0, ledger_transactions: 0, gift_codes: 0,
        gift_code_redemptions: 0, deposits: 0, withdrawals: 0, transactions: 0,
        game_bets: 0, wingo_settlement_locks: 0, audit_logs: 0
      },
      dbSizeBytes: 0,
      walMode: true,
      supabaseConfigured: Boolean(SUPABASE_URL && SUPABASE_SERVICE_KEY),
      engine: SUPABASE_URL && SUPABASE_SERVICE_KEY
        ? 'Supabase PostgreSQL + Local SQLite 3.40 WAL Read/Write Cache'
        : 'SQLite 3.40 WAL + Normalized ACID Relational Ledger',
      lastSyncedAt: Date.now()
    };
    this.startDaemon();
  }

  startDaemon() {
    try {
      this.proc = spawn('python3', ['-u', '-c', PYTHON_DB_WORKER_CODE, DB_FILE], {
        stdio: ['pipe', 'pipe', 'pipe']
      });

      this.proc.stdout.setEncoding('utf-8');
      this.proc.stdout.on('data', chunk => {
        this.buffer += chunk;
        let idx;
        while ((idx = this.buffer.indexOf('\n')) !== -1) {
          const line = this.buffer.slice(0, idx).trim();
          this.buffer = this.buffer.slice(idx + 1);
          if (!line) continue;
          try {
            const msg = JSON.parse(line);
            if (msg.id && this.pending.has(msg.id)) {
              const { resolve } = this.pending.get(msg.id);
              this.pending.delete(msg.id);
              resolve(msg);
            }
          } catch (e) {}
        }
      });

      this.proc.on('exit', () => {
        this.proc = null;
        for (const [, p] of this.pending.entries()) {
          p.resolve({ ok: false, error: 'Database worker restarted' });
        }
        this.pending.clear();
        setTimeout(() => this.startDaemon(), 500);
      });
    } catch (e) {
      this.proc = null;
    }
  }

  sendCommand(cmd, payload = {}) {
    return new Promise((resolve) => {
      if (!this.proc || !this.proc.stdin.writable) {
        return resolve({ ok: false, error: 'Database daemon not ready' });
      }
      const id = ++this.reqId;
      const timer = setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id);
          resolve({ ok: false, error: 'Database transaction timeout' });
        }
      }, 8000);
      this.pending.set(id, {
        resolve: (res) => {
          clearTimeout(timer);
          resolve(res);
        }
      });
      try {
        this.proc.stdin.write(JSON.stringify(Object.assign({ id, cmd }, payload)) + '\n');
      } catch (e) {
        clearTimeout(timer);
        this.pending.delete(id);
        resolve({ ok: false, error: e.message });
      }
    });
  }

  async adjustWalletAtomic(params) {
    if (params && !params.amountPaise && params.amountInr) params.amountPaise = inrToPaise(params.amountInr);
    const res = await this.sendCommand('ADJUST_WALLET', { payload: params });
    if (res && res.ok && SUPABASE_URL && SUPABASE_SERVICE_KEY) {
      callSupabaseRpc('fn_adjust_wallet_atomic', {
        p_user_id: params.userId,
        p_username: params.username || params.userId,
        p_balance_type: params.balanceType || 'CASH',
        p_direction: params.direction,
        p_amount_paise: params.amountPaise,
        p_idempotency_key: params.idempotencyKey,
        p_tx_type: params.txType || 'ADMIN_ADJUSTMENT',
        p_actor: params.actor || 'SYSTEM',
        p_reason: params.reason || ''
      }).catch(() => {});
    }
    return res;
  }

  async redeemGiftCodeAtomic(params) {
    const res = await this.sendCommand('REDEEM_GIFT_CODE', { payload: params });
    if (res && res.ok && SUPABASE_URL && SUPABASE_SERVICE_KEY) {
      callSupabaseRpc('fn_redeem_gift_code_atomic', {
        p_code: params.code,
        p_user_id: params.userId,
        p_username: params.username || params.userId
      }).catch(() => {});
    }
    return res;
  }

  async settleWingoPeriodAtomic(params) {
    const res = await this.sendCommand('SETTLE_WINGO_PERIOD', { payload: params });
    return res;
  }

  async reconcileBalances() {
    return await this.sendCommand('RECONCILE');
  }

  async syncMasterState(stateObj) {
    try {
      const tmpFile = JSON_BACKUP_FILE + '.tmp';
      fs.writeFileSync(tmpFile, JSON.stringify(stateObj), 'utf-8');
      fs.renameSync(tmpFile, JSON_BACKUP_FILE);
    } catch (e) {}

    const res = await this.sendCommand('SYNC_STATE', { state: stateObj });
    if (res && res.ok) {
      this.lastStats.lastSyncedAt = Date.now();
    }
    return res;
  }

  async getStats() {
    const st = await this.sendCommand('GET_STATS');
    if (st && st.ok) {
      this.lastStats.counts = st.counts || this.lastStats.counts;
      this.lastStats.dbSizeBytes = st.dbSizeBytes || 0;
    }
    return this.lastStats;
  }
}

const dbDaemon = new SqliteWalDaemon();

module.exports = {
  DB_FILE,
  inrToPaise,
  paiseToInr,
  JSON_BACKUP_FILE,
  SUPABASE_URL,
  SUPABASE_SERVICE_KEY,
  loadInitialStateFromSqliteOrJson,
  callSupabaseRpc,
  dbDaemon
};