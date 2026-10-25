-- ============================================================================
-- PROJECT: ADVANCED GAMING WEBAPP — SUPER ADMIN PANEL
-- DATABASE: Supabase PostgreSQL Normalized Schema (30 Tables) + RLS + Triggers
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. ADMIN ROLES, PERMISSIONS, USERS & IMMUTABLE AUDIT LOGS
CREATE TABLE IF NOT EXISTS admin_roles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  role_key TEXT UNIQUE NOT NULL,
  role_name TEXT NOT NULL,
  description TEXT,
  is_system_role BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS admin_permissions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  role_id UUID NOT NULL REFERENCES admin_roles(id) ON DELETE CASCADE,
  permission_key TEXT NOT NULL,
  allowed BOOLEAN NOT NULL DEFAULT TRUE,
  UNIQUE(role_id, permission_key)
);

CREATE TABLE IF NOT EXISTS admin_users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  auth_user_id UUID UNIQUE,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  role_id UUID NOT NULL REFERENCES admin_roles(id),
  mfa_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'SUSPENDED', 'LOCKED')),
  last_login_at TIMESTAMPTZ,
  last_login_ip INET,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS admin_audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_admin_id UUID REFERENCES admin_users(id),
  actor_role TEXT NOT NULL,
  action_type TEXT NOT NULL,
  target_table TEXT NOT NULL,
  target_record_id TEXT NOT NULL,
  previous_values JSONB,
  new_values JSONB,
  reason TEXT NOT NULL,
  approval_reference TEXT,
  ip_address TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON admin_audit_logs(created_at DESC);

CREATE OR REPLACE FUNCTION prevent_audit_modification()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'Append-only table cannot be altered or deleted.';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_immutable_audit_logs ON admin_audit_logs;
CREATE TRIGGER trg_immutable_audit_logs
BEFORE UPDATE OR DELETE ON admin_audit_logs
FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- 2. USERS & USER PROFILES (WITH RESPONSIBLE GAMING CONTROLS)
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  uid_code TEXT UNIQUE NOT NULL,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE,
  phone TEXT UNIQUE,
  account_status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (account_status IN ('ACTIVE', 'SUSPENDED', 'RESTRICTED', 'SELF_EXCLUDED')),
  kyc_status TEXT NOT NULL DEFAULT 'PENDING' CHECK (kyc_status IN ('UNVERIFIED', 'PENDING', 'VERIFIED', 'REJECTED')),
  referred_by_user_id UUID REFERENCES users(id),
  referral_code TEXT UNIQUE NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_profiles (
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  preferred_currency TEXT NOT NULL DEFAULT 'INR' CHECK (preferred_currency IN ('INR', 'USDT')),
  preferred_language TEXT NOT NULL DEFAULT 'English',
  daily_deposit_limit_inr NUMERIC(14,2) DEFAULT 50000.00,
  daily_loss_limit_inr NUMERIC(14,2) DEFAULT 25000.00,
  self_exclusion_until TIMESTAMPTZ,
  cooling_off_until TIMESTAMPTZ,
  bank_holder_name TEXT,
  bank_name TEXT,
  bank_account_masked TEXT,
  bank_ifsc TEXT,
  usdt_network TEXT,
  usdt_address_masked TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. WALLETS & APPEND-ONLY FINANCIAL LEDGER
CREATE TABLE IF NOT EXISTS wallets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  cash_balance_inr NUMERIC(14,2) NOT NULL DEFAULT 0.00 CHECK (cash_balance_inr >= 0),
  promo_bonus_balance_inr NUMERIC(14,2) NOT NULL DEFAULT 0.00 CHECK (promo_bonus_balance_inr >= 0),
  locked_withdrawal_inr NUMERIC(14,2) NOT NULL DEFAULT 0.00 CHECK (locked_withdrawal_inr >= 0),
  commission_balance_inr NUMERIC(14,2) NOT NULL DEFAULT 0.00 CHECK (commission_balance_inr >= 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ledger_accounts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  account_code TEXT UNIQUE NOT NULL,
  account_name TEXT NOT NULL,
  account_type TEXT NOT NULL CHECK (account_type IN ('ASSET', 'LIABILITY', 'REVENUE', 'EXPENSE')),
  balance_inr NUMERIC(16,2) NOT NULL DEFAULT 0.00,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ledger_transactions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tx_code TEXT UNIQUE NOT NULL,
  user_id UUID REFERENCES users(id),
  wallet_id UUID REFERENCES wallets(id),
  tx_type TEXT NOT NULL,
  amount_inr NUMERIC(14,2) NOT NULL,
  currency TEXT NOT NULL DEFAULT 'INR',
  balance_type TEXT NOT NULL DEFAULT 'CASH' CHECK (balance_type IN ('CASH', 'PROMO', 'COMMISSION')),
  related_reference_id TEXT,
  reversal_of_tx_id UUID REFERENCES ledger_transactions(id),
  idempotency_key TEXT UNIQUE NOT NULL,
  status TEXT NOT NULL DEFAULT 'COMPLETED' CHECK (status IN ('PENDING', 'COMPLETED', 'REVERSED', 'FAILED')),
  authorized_actor TEXT NOT NULL,
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DROP TRIGGER IF EXISTS trg_immutable_ledger_tx ON ledger_transactions;
CREATE TRIGGER trg_immutable_ledger_tx
BEFORE DELETE ON ledger_transactions
FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- 4. DEPOSITS & WITHDRAWALS
CREATE TABLE IF NOT EXISTS deposits (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  deposit_code TEXT UNIQUE NOT NULL,
  user_id UUID NOT NULL REFERENCES users(id),
  amount_inr NUMERIC(14,2) NOT NULL CHECK (amount_inr > 0),
  usdt_equivalent NUMERIC(14,2),
  payment_method TEXT NOT NULL CHECK (payment_method IN ('UPI', 'USDT', 'BANK')),
  provider_reference TEXT NOT NULL,
  webhook_signature_verified BOOLEAN NOT NULL DEFAULT FALSE,
  status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'CONFIRMED', 'FAILED', 'REVERSED', 'UNDER_REVIEW')),
  reviewed_by UUID REFERENCES admin_users(id),
  review_reason TEXT,
  idempotency_key TEXT UNIQUE NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  confirmed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS withdrawals (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  withdrawal_code TEXT UNIQUE NOT NULL,
  user_id UUID NOT NULL REFERENCES users(id),
  requested_amount_inr NUMERIC(14,2) NOT NULL CHECK (requested_amount_inr > 0),
  fee_amount_inr NUMERIC(14,2) NOT NULL DEFAULT 0.00,
  net_payout_inr NUMERIC(14,2) NOT NULL,
  payout_method TEXT NOT NULL CHECK (payout_method IN ('BANK', 'USDT')),
  destination_masked TEXT NOT NULL,
  review_status TEXT NOT NULL DEFAULT 'PENDING' CHECK (review_status IN ('PENDING', 'APPROVED', 'REJECTED', 'UNDER_REVIEW')),
  payout_status TEXT NOT NULL DEFAULT 'QUEUED' CHECK (payout_status IN ('QUEUED', 'PROCESSING', 'PAID', 'FAILED', 'REVERSED')),
  reviewed_by UUID REFERENCES admin_users(id),
  review_reason TEXT,
  provider_payout_ref TEXT,
  idempotency_key TEXT UNIQUE NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 5. GAMES, WINGO MODES, PERIODS, ENTRIES, RESULTS, APPROVALS & SETTLEMENTS
CREATE TABLE IF NOT EXISTS games (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  game_key TEXT UNIQUE NOT NULL,
  display_name TEXT NOT NULL,
  subtitle TEXT,
  category TEXT NOT NULL,
  sort_order INT NOT NULL DEFAULT 1,
  is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  maintenance_mode BOOLEAN NOT NULL DEFAULT FALSE,
  config_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS game_modes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  game_id UUID NOT NULL REFERENCES games(id) ON DELETE CASCADE,
  mode_key TEXT UNIQUE NOT NULL CHECK (mode_key IN ('30SEC', '1MIN', '2MIN', '3MIN', '5MIN')),
  mode_name TEXT NOT NULL,
  duration_sec INT NOT NULL CHECK (duration_sec IN (30, 60, 120, 180, 300)),
  cutoff_sec INT NOT NULL CHECK (cutoff_sec > 0 AND cutoff_sec < duration_sec),
  period_prefix_code TEXT NOT NULL,
  min_entry_inr NUMERIC(12,2) NOT NULL DEFAULT 10.00,
  max_entry_inr NUMERIC(12,2) NOT NULL DEFAULT 50000.00,
  is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  maintenance_mode BOOLEAN NOT NULL DEFAULT FALSE,
  status_message TEXT,
  rules_version TEXT NOT NULL DEFAULT 'v2.4',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS game_settings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  mode_key TEXT NOT NULL REFERENCES game_modes(mode_key) ON DELETE CASCADE,
  version_tag TEXT NOT NULL,
  payout_table_json JSONB NOT NULL,
  result_schedule_mode TEXT NOT NULL DEFAULT 'AUTO_CSPRNG',
  settlement_rule_mode TEXT NOT NULL DEFAULT 'ATOMIC_AUTO',
  created_by UUID REFERENCES admin_users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(mode_key, version_tag)
);

CREATE TABLE IF NOT EXISTS game_periods (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  period_id TEXT UNIQUE NOT NULL,
  mode_key TEXT NOT NULL REFERENCES game_modes(mode_key),
  opening_at TIMESTAMPTZ NOT NULL,
  entry_cutoff_at TIMESTAMPTZ NOT NULL,
  closing_at TIMESTAMPTZ NOT NULL,
  result_published_at TIMESTAMPTZ,
  period_status TEXT NOT NULL DEFAULT 'OPEN' CHECK (period_status IN (
    'SCHEDULED', 'OPEN', 'CLOSED', 'AWAITING_RESULT', 'RESULT_PUBLISHED',
    'SETTLING', 'SETTLED', 'CANCELLED', 'UNDER_REVIEW'
  )),
  entry_count INT NOT NULL DEFAULT 0,
  total_entry_amount_inr NUMERIC(14,2) NOT NULL DEFAULT 0.00,
  result_status TEXT NOT NULL DEFAULT 'PENDING',
  settlement_status TEXT NOT NULL DEFAULT 'PENDING',
  commit_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS game_entries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  entry_code TEXT UNIQUE NOT NULL,
  period_id TEXT NOT NULL REFERENCES game_periods(period_id),
  mode_key TEXT NOT NULL,
  user_id UUID NOT NULL REFERENCES users(id),
  selection TEXT NOT NULL,
  amount_inr NUMERIC(14,2) NOT NULL CHECK (amount_inr > 0),
  odds NUMERIC(6,2) NOT NULL,
  status TEXT NOT NULL DEFAULT 'WAITING' CHECK (status IN ('WAITING', 'WIN', 'LOSE', 'REFUNDED')),
  payout_inr NUMERIC(14,2) NOT NULL DEFAULT 0.00,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS game_results (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  period_id TEXT UNIQUE NOT NULL REFERENCES game_periods(period_id),
  mode_key TEXT NOT NULL,
  winning_number INT NOT NULL CHECK (winning_number BETWEEN 0 AND 9),
  winning_colors TEXT[] NOT NULL,
  winning_size TEXT NOT NULL CHECK (winning_size IN ('Small', 'Big')),
  generation_method TEXT NOT NULL CHECK (generation_method IN ('CSPRNG_COMMIT_REVEAL', 'MANUAL_AUTHORIZED', 'APPROVED_CORRECTION')),
  publication_status TEXT NOT NULL DEFAULT 'PUBLISHED',
  correction_status TEXT NOT NULL DEFAULT 'NONE',
  authored_by UUID REFERENCES admin_users(id),
  reason TEXT,
  evidence_ref TEXT,
  audit_ref TEXT NOT NULL,
  published_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS result_approvals (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  period_id TEXT NOT NULL REFERENCES game_periods(period_id),
  previous_number INT NOT NULL,
  proposed_number INT NOT NULL CHECK (proposed_number BETWEEN 0 AND 9),
  requested_by UUID NOT NULL REFERENCES admin_users(id),
  approved_by UUID REFERENCES admin_users(id),
  reason TEXT NOT NULL,
  evidence_ref TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'PENDING_SECOND_APPROVAL' CHECK (status IN ('PENDING_SECOND_APPROVAL', 'APPROVED', 'REJECTED')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  resolved_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS result_verification_records (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  period_id TEXT UNIQUE NOT NULL REFERENCES game_periods(period_id),
  commit_hash_sha256 TEXT NOT NULL,
  revealed_server_seed TEXT,
  client_seed TEXT NOT NULL,
  verified BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS settlements (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  settlement_code TEXT UNIQUE NOT NULL,
  period_id TEXT UNIQUE NOT NULL REFERENCES game_periods(period_id),
  mode_key TEXT NOT NULL,
  winning_number INT NOT NULL,
  eligible_entries_count INT NOT NULL DEFAULT 0,
  total_wagered_inr NUMERIC(14,2) NOT NULL DEFAULT 0.00,
  total_payout_inr NUMERIC(14,2) NOT NULL DEFAULT 0.00,
  total_refund_inr NUMERIC(14,2) NOT NULL DEFAULT 0.00,
  discrepancy_amount_inr NUMERIC(14,2) NOT NULL DEFAULT 0.00,
  rules_version TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'SETTLED' CHECK (status IN ('SETTLING', 'SETTLED', 'REVERSED', 'FLAGGED')),
  idempotency_key TEXT UNIQUE NOT NULL,
  settled_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS settlement_items (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  settlement_id UUID NOT NULL REFERENCES settlements(id) ON DELETE CASCADE,
  entry_id UUID NOT NULL REFERENCES game_entries(id),
  user_id UUID NOT NULL REFERENCES users(id),
  wager_inr NUMERIC(14,2) NOT NULL,
  payout_inr NUMERIC(14,2) NOT NULL,
  outcome TEXT NOT NULL CHECK (outcome IN ('WIN', 'LOSE', 'REFUND')),
  ledger_tx_id UUID REFERENCES ledger_transactions(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 6. AGENTS, 7-LEVEL REFERRALS & COMMISSION LEDGER
CREATE TABLE IF NOT EXISTS agents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID UNIQUE NOT NULL REFERENCES users(id),
  agent_code TEXT UNIQUE NOT NULL,
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'SUSPENDED', 'UNDER_FRAUD_REVIEW')),
  direct_referrals_count INT NOT NULL DEFAULT 0,
  total_downline_count INT NOT NULL DEFAULT 0,
  pending_commission_inr NUMERIC(14,2) NOT NULL DEFAULT 0.00,
  approved_commission_inr NUMERIC(14,2) NOT NULL DEFAULT 0.00,
  paid_commission_inr NUMERIC(14,2) NOT NULL DEFAULT 0.00,
  fraud_flag BOOLEAN NOT NULL DEFAULT FALSE,
  fraud_notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS referrals (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ancestor_user_id UUID NOT NULL REFERENCES users(id),
  descendant_user_id UUID NOT NULL REFERENCES users(id),
  relative_level INT NOT NULL CHECK (relative_level BETWEEN 1 AND 7),
  chain_path TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(ancestor_user_id, descendant_user_id),
  CHECK (ancestor_user_id <> descendant_user_id)
);

CREATE TABLE IF NOT EXISTS commission_rules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  version_tag TEXT UNIQUE NOT NULL,
  qualifying_tx_type TEXT NOT NULL CHECK (qualifying_tx_type IN ('FIRST_DEPOSIT_ONLY', 'EVERY_ELIGIBLE', 'NET_ELIGIBLE')),
  min_qualifying_deposit_inr NUMERIC(12,2) NOT NULL DEFAULT 100.00,
  level_1_pct NUMERIC(5,2) NOT NULL DEFAULT 7.00,
  level_2_pct NUMERIC(5,2) NOT NULL DEFAULT 6.00,
  level_3_pct NUMERIC(5,2) NOT NULL DEFAULT 5.00,
  level_4_pct NUMERIC(5,2) NOT NULL DEFAULT 4.00,
  level_5_pct NUMERIC(5,2) NOT NULL DEFAULT 3.00,
  level_6_pct NUMERIC(5,2) NOT NULL DEFAULT 2.00,
  level_7_pct NUMERIC(5,2) NOT NULL DEFAULT 1.00,
  legal_compliance_approved BOOLEAN NOT NULL DEFAULT TRUE,
  approved_by UUID REFERENCES admin_users(id),
  effective_from TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  is_active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS commission_ledger (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ledger_code TEXT UNIQUE NOT NULL,
  source_deposit_event_id TEXT NOT NULL,
  depositing_user_id UUID NOT NULL REFERENCES users(id),
  beneficiary_agent_id UUID NOT NULL REFERENCES agents(id),
  relative_level INT NOT NULL CHECK (relative_level BETWEEN 1 AND 7),
  rate_pct NUMERIC(5,2) NOT NULL,
  qualifying_deposit_inr NUMERIC(14,2) NOT NULL,
  commission_amount_inr NUMERIC(14,2) NOT NULL,
  rule_version TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'PAID', 'REVERSED')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(source_deposit_event_id, relative_level)
);

-- 7. QUIZ GAME, BANNERS, PROMOTIONS, SUPPORT, NOTIFICATIONS & SETTINGS
CREATE TABLE IF NOT EXISTS quiz_categories (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  category_name TEXT UNIQUE NOT NULL,
  description TEXT,
  is_active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS quiz_questions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  question_code TEXT UNIQUE NOT NULL,
  category_id UUID REFERENCES quiz_categories(id),
  difficulty TEXT NOT NULL CHECK (difficulty IN ('EASY', 'MEDIUM', 'HARD')),
  question_text TEXT NOT NULL,
  explanation TEXT,
  time_limit_sec INT NOT NULL DEFAULT 10,
  version_num INT NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'PUBLISHED' CHECK (status IN ('DRAFT', 'PUBLISHED', 'ARCHIVED')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS quiz_options (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  question_id UUID NOT NULL REFERENCES quiz_questions(id) ON DELETE CASCADE,
  option_label TEXT NOT NULL,
  option_value TEXT NOT NULL,
  is_correct BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS quiz_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_code TEXT UNIQUE NOT NULL,
  player_a_id UUID REFERENCES users(id),
  player_b_name TEXT NOT NULL,
  entry_fee_inr NUMERIC(12,2) NOT NULL,
  platform_fee_pct NUMERIC(5,2) NOT NULL DEFAULT 10.00,
  net_prize_inr NUMERIC(12,2) NOT NULL,
  player_a_correct INT NOT NULL,
  player_a_time_sec NUMERIC(8,2) NOT NULL,
  player_b_correct INT NOT NULL,
  player_b_time_sec NUMERIC(8,2) NOT NULL,
  winner TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS quiz_answers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id UUID NOT NULL REFERENCES quiz_sessions(id) ON DELETE CASCADE,
  question_id UUID NOT NULL REFERENCES quiz_questions(id),
  selected_value TEXT,
  is_correct BOOLEAN NOT NULL,
  response_ms INT NOT NULL
);

CREATE TABLE IF NOT EXISTS banners (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  banner_title TEXT NOT NULL,
  placement TEXT NOT NULL,
  target_view TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'PUBLISHED',
  sort_order INT NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS promotions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  promo_code TEXT UNIQUE NOT NULL,
  title TEXT NOT NULL,
  reward_inr NUMERIC(12,2) NOT NULL,
  credit_type TEXT NOT NULL DEFAULT 'PROMO_RESTRICTED' CHECK (credit_type IN ('PROMO_RESTRICTED', 'CASH_WITHDRAWABLE')),
  max_claims INT NOT NULL DEFAULT 500,
  claimed_count INT NOT NULL DEFAULT 0,
  starts_at TIMESTAMPTZ,
  ends_at TIMESTAMPTZ,
  status TEXT NOT NULL DEFAULT 'ACTIVE'
);

CREATE TABLE IF NOT EXISTS support_tickets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ticket_code TEXT UNIQUE NOT NULL,
  user_id UUID REFERENCES users(id),
  category TEXT NOT NULL,
  subject TEXT NOT NULL,
  description TEXT NOT NULL,
  priority TEXT NOT NULL DEFAULT 'HIGH' CHECK (priority IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
  status TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'IN_PROGRESS', 'WAITING_FOR_USER', 'ESCALATED', 'RESOLVED')),
  assigned_admin TEXT,
  internal_notes TEXT,
  resolution_reason TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS notifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  target_scope TEXT NOT NULL DEFAULT 'ALL_USERS',
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS platform_settings (
  setting_key TEXT PRIMARY KEY,
  setting_value JSONB NOT NULL,
  version_num INT NOT NULL DEFAULT 1,
  updated_by UUID REFERENCES admin_users(id),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE admin_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE wallets ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger_transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE deposits ENABLE ROW LEVEL SECURITY;
ALTER TABLE withdrawals ENABLE ROW LEVEL SECURITY;
ALTER TABLE game_periods ENABLE ROW LEVEL SECURITY;
ALTER TABLE game_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE settlements ENABLE ROW LEVEL SECURITY;
ALTER TABLE commission_ledger ENABLE ROW LEVEL SECURITY;


-- ============================================================================
-- 8. REAL-TIME MULTI-DEVICE SYNC STATE TABLE (kv_master_state)
--    Used by Customer Webapp (index.html), Super Admin Panel (admin_panel.html),
--    and Backend Server (server.js) for instant cloud synchronization
-- ============================================================================
CREATE TABLE IF NOT EXISTS kv_master_state (
  key TEXT PRIMARY KEY,
  value_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT
);

INSERT INTO kv_master_state (key, value_json, updated_at)
VALUES ('MASTER_STATE', '{}'::jsonb, (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT)
ON CONFLICT (key) DO NOTHING;

-- ============================================================================
-- 9. SEED DEFAULT SYSTEM ROLES (9 RBAC ROLES)
-- ============================================================================
INSERT INTO admin_roles (role_key, role_name, description, is_system_role) VALUES
  ('SUPER_ADMIN',       'Super Admin',                 'Full platform authority across all modules, RBAC, security, and ledger adjustments.', TRUE),
  ('OPS_MANAGER',       'Operations Manager',          'Approves result corrections, game catalog availability, and website publication.', TRUE),
  ('WINGO_OPS',         'Wingo Operations',            'Manages Wingo 30s/1m/2m/3m/5m timers, periods, manual result entry, and settlement.', TRUE),
  ('FINANCE_MANAGER',   'Finance Manager',             'Approves withdrawals, issues documented ledger adjustments, and reconciles webhooks.', TRUE),
  ('FINANCE_REVIEWER',  'Finance Reviewer',            'Reviews deposit UTR/TXID references and flags suspicious withdrawals.', TRUE),
  ('AGENT_MANAGER',     'Agent Manager',               'Configures 7-level referral commission rules and approves agent statements.', TRUE),
  ('QUIZ_MANAGER',      'Quiz Manager',                'Creates, validates, versions, and schedules Quiz Game / 1vs1 Math questions.', TRUE),
  ('CUSTOMER_SUPPORT',  'Customer Support',            'Resolves support tickets, complaints, and posts support announcements.', TRUE),
  ('READ_ONLY_AUDITOR', 'Read-Only Auditor',           'Read-only inspection of all financial ledgers, draw verifications, and audit logs.', TRUE)
ON CONFLICT (role_key) DO NOTHING;

-- ============================================================================
-- 10. SUPABASE ROW-LEVEL SECURITY (RLS) POLICIES & REALTIME PUBLICATION
-- ============================================================================
ALTER TABLE kv_master_state ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
  DROP POLICY IF EXISTS "Allow anon and service_role access to kv_master_state" ON kv_master_state;
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE tablename = 'kv_master_state' AND policyname = 'Service role exclusive access to kv_master_state'
  ) THEN
    CREATE POLICY "Service role exclusive access to kv_master_state"
      ON kv_master_state
      FOR ALL
      TO service_role
      USING (true)
      WITH CHECK (true);
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE tablename = 'users' AND policyname = 'Service role full access on users'
  ) THEN
    CREATE POLICY "Service role full access on users" ON users FOR ALL TO service_role USING (true) WITH CHECK (true);
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE tablename = 'wallets' AND policyname = 'Service role full access on wallets'
  ) THEN
    CREATE POLICY "Service role full access on wallets" ON wallets FOR ALL TO service_role USING (true) WITH CHECK (true);
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE tablename = 'deposits' AND policyname = 'Service role full access on deposits'
  ) THEN
    CREATE POLICY "Service role full access on deposits" ON deposits FOR ALL TO service_role USING (true) WITH CHECK (true);
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE tablename = 'withdrawals' AND policyname = 'Service role full access on withdrawals'
  ) THEN
    CREATE POLICY "Service role full access on withdrawals" ON withdrawals FOR ALL TO service_role USING (true) WITH CHECK (true);
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE tablename = 'ledger_transactions' AND policyname = 'Service role full access on ledger_transactions'
  ) THEN
    CREATE POLICY "Service role full access on ledger_transactions" ON ledger_transactions FOR ALL TO service_role USING (true) WITH CHECK (true);
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE tablename = 'game_periods' AND policyname = 'Public read and service role write on game_periods'
  ) THEN
    CREATE POLICY "Public read on game_periods" ON game_periods FOR SELECT TO anon, authenticated USING (true);
    CREATE POLICY "Service role write on game_periods" ON game_periods FOR ALL TO service_role USING (true) WITH CHECK (true);
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE tablename = 'game_results' AND policyname = 'Public read and service role write on game_results'
  ) THEN
    CREATE POLICY "Public read on game_results" ON game_results FOR SELECT TO anon, authenticated USING (true);
    CREATE POLICY "Service role write on game_results" ON game_results FOR ALL TO service_role USING (true) WITH CHECK (true);
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE tablename = 'settlements' AND policyname = 'Service role full access on settlements'
  ) THEN
    CREATE POLICY "Service role full access on settlements" ON settlements FOR ALL TO service_role USING (true) WITH CHECK (true);
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE tablename = 'commission_ledger' AND policyname = 'Service role full access on commission_ledger'
  ) THEN
    CREATE POLICY "Service role full access on commission_ledger" ON commission_ledger FOR ALL TO service_role USING (true) WITH CHECK (true);
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE tablename = 'admin_users' AND policyname = 'Service role full access on admin_users'
  ) THEN
    CREATE POLICY "Service role full access on admin_users" ON admin_users FOR ALL TO service_role USING (true) WITH CHECK (true);
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE tablename = 'admin_audit_logs' AND policyname = 'Service role full access on admin_audit_logs'
  ) THEN
    CREATE POLICY "Service role full access on admin_audit_logs" ON admin_audit_logs FOR ALL TO service_role USING (true) WITH CHECK (true);
  END IF;
END
$$;

-- ============================================================================
-- 11. ENABLE SUPABASE REALTIME FOR INSTANT MULTI-DEVICE SYNC
-- ============================================================================
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime') THEN
    IF NOT EXISTS (
      SELECT 1 FROM pg_publication_tables
      WHERE pubname = 'supabase_realtime' AND tablename = 'kv_master_state'
    ) THEN
      ALTER PUBLICATION supabase_realtime ADD TABLE kv_master_state;
    END IF;
  END IF;
END
$$;


-- ============================================================================
-- 11. V14.0 ATOMIC INTEGER-PAISE FINANCIAL TABLES & PL/pgSQL RPC FUNCTIONS
--     (1 INR = 100 Paise • Row-Level FOR UPDATE Locks • Idempotency Enforcement)
-- ============================================================================

ALTER TABLE wallets ADD COLUMN IF NOT EXISTS cash_balance_paise BIGINT NOT NULL DEFAULT 0 CHECK (cash_balance_paise >= 0);
ALTER TABLE wallets ADD COLUMN IF NOT EXISTS promo_balance_paise BIGINT NOT NULL DEFAULT 0 CHECK (promo_balance_paise >= 0);
ALTER TABLE ledger_transactions ADD COLUMN IF NOT EXISTS amount_paise BIGINT NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS gift_codes (
  code TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  distribution_mode TEXT NOT NULL DEFAULT 'FULL_TO_EACH' CHECK (distribution_mode IN ('FULL_TO_EACH', 'SPLIT_EQUALLY')),
  total_value_paise BIGINT NOT NULL DEFAULT 0 CHECK (total_value_paise >= 0),
  reward_per_user_paise BIGINT NOT NULL DEFAULT 0 CHECK (reward_per_user_paise >= 0),
  max_claims INT NOT NULL DEFAULT 1 CHECK (max_claims >= 1),
  claimed_count INT NOT NULL DEFAULT 0 CHECK (claimed_count >= 0 AND claimed_count <= max_claims),
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'EXHAUSTED', 'DISABLED', 'EXPIRED')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS gift_code_redemptions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  code TEXT NOT NULL REFERENCES gift_codes(code) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  reward_paise BIGINT NOT NULL CHECK (reward_paise > 0),
  ledger_tx_code TEXT NOT NULL,
  redeemed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(code, user_id)
);

CREATE TABLE IF NOT EXISTS wingo_settlement_locks (
  period_id TEXT PRIMARY KEY,
  slot_key TEXT NOT NULL,
  winning_number INT NOT NULL CHECK (winning_number BETWEEN 0 AND 9),
  commit_hash TEXT NOT NULL,
  server_seed TEXT NOT NULL,
  total_bets INT NOT NULL DEFAULT 0,
  total_wager_paise BIGINT NOT NULL DEFAULT 0,
  total_payout_paise BIGINT NOT NULL DEFAULT 0,
  settled_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE gift_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE gift_code_redemptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE wingo_settlement_locks ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Service role full access on gift_codes" ON gift_codes;
CREATE POLICY "Service role full access on gift_codes" ON gift_codes FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role full access on gift_code_redemptions" ON gift_code_redemptions;
CREATE POLICY "Service role full access on gift_code_redemptions" ON gift_code_redemptions FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role full access on wingo_settlement_locks" ON wingo_settlement_locks;
CREATE POLICY "Service role full access on wingo_settlement_locks" ON wingo_settlement_locks FOR ALL TO service_role USING (true) WITH CHECK (true);

-- Atomic Wallet Credit / Debit RPC with Row-Level FOR UPDATE Lock & Idempotency
CREATE OR REPLACE FUNCTION fn_adjust_wallet_atomic(
  p_user_uid TEXT,
  p_balance_type TEXT,
  p_direction TEXT,
  p_amount_paise BIGINT,
  p_reason TEXT,
  p_actor TEXT,
  p_idempotency_key TEXT
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_user_id UUID;
  v_wallet RECORD;
  v_existing_tx RECORD;
  v_signed_paise BIGINT;
  v_next_cash BIGINT;
  v_next_promo BIGINT;
  v_tx_code TEXT;
BEGIN
  IF p_amount_paise <= 0 THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Amount in paise must be positive.');
  END IF;

  SELECT * INTO v_existing_tx FROM ledger_transactions WHERE idempotency_key = p_idempotency_key LIMIT 1;
  IF FOUND THEN
    SELECT * INTO v_wallet FROM wallets WHERE user_id = v_existing_tx.user_id;
    RETURN jsonb_build_object(
      'ok', true,
      'idempotentReplay', true,
      'txCode', v_existing_tx.tx_code,
      'cashBalancePaise', COALESCE(v_wallet.cash_balance_paise, 0),
      'promoBalancePaise', COALESCE(v_wallet.promo_balance_paise, 0)
    );
  END IF;

  SELECT id INTO v_user_id FROM users WHERE uid_code = p_user_uid LIMIT 1;
  IF v_user_id IS NULL THEN
    RETURN jsonb_build_object('ok', false, 'error', 'User not found.');
  END IF;

  SELECT * INTO v_wallet FROM wallets WHERE user_id = v_user_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Wallet not found.');
  END IF;

  v_signed_paise := CASE WHEN UPPER(p_direction) = 'CREDIT' THEN p_amount_paise ELSE -p_amount_paise END;
  v_next_cash := v_wallet.cash_balance_paise;
  v_next_promo := v_wallet.promo_balance_paise;

  IF UPPER(p_balance_type) = 'PROMO' THEN
    IF v_next_promo + v_signed_paise < 0 THEN
      RETURN jsonb_build_object('ok', false, 'error', 'Insufficient Promo Balance.');
    END IF;
    v_next_promo := v_next_promo + v_signed_paise;
  ELSE
    IF v_next_cash + v_signed_paise < 0 THEN
      RETURN jsonb_build_object('ok', false, 'error', 'Insufficient Cash Balance.');
    END IF;
    v_next_cash := v_next_cash + v_signed_paise;
  END IF;

  UPDATE wallets
  SET cash_balance_paise = v_next_cash,
      cash_balance_inr = ROUND(v_next_cash::NUMERIC / 100.0, 2),
      promo_balance_paise = v_next_promo,
      promo_bonus_balance_inr = ROUND(v_next_promo::NUMERIC / 100.0, 2),
      updated_at = NOW()
  WHERE id = v_wallet.id;

  v_tx_code := 'LDG-' || EXTRACT(EPOCH FROM NOW())::BIGINT || '-' || SUBSTRING(md5(random()::text) FROM 1 FOR 6);

  INSERT INTO ledger_transactions (
    tx_code, user_id, wallet_id, tx_type, amount_inr, amount_paise,
    currency, balance_type, related_reference_id, idempotency_key,
    status, authorized_actor, notes
  ) VALUES (
    v_tx_code, v_user_id, v_wallet.id, 'ATOMIC_ADJUSTMENT',
    ROUND(v_signed_paise::NUMERIC / 100.0, 2), v_signed_paise,
    'INR', UPPER(p_balance_type), 'DIRECT_WALLET_ADJ', p_idempotency_key,
    'COMPLETED', p_actor, p_reason
  );

  RETURN jsonb_build_object(
    'ok', true,
    'idempotentReplay', false,
    'txCode', v_tx_code,
    'cashBalancePaise', v_next_cash,
    'promoBalancePaise', v_next_promo
  );
END;
$$;
