CREATE TABLE IF NOT EXISTS mcp_tokens (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  label TEXT NOT NULL,
  organization_id TEXT NOT NULL REFERENCES organizations(id),
  project_id TEXT REFERENCES projects(id),
  owner_uid TEXT NOT NULL REFERENCES users(uid),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
  expires_at TEXT NOT NULL,
  last_used_at TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_mcp_tokens_org_status ON mcp_tokens(organization_id,status,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mcp_tokens_expiry ON mcp_tokens(status,expires_at);
CREATE TABLE IF NOT EXISTS retention_runs (
  id TEXT PRIMARY KEY,
  started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  finished_at TEXT,
  deleted_metrics INTEGER NOT NULL DEFAULT 0,
  deleted_sales INTEGER NOT NULL DEFAULT 0,
  deleted_costs INTEGER NOT NULL DEFAULT 0,
  deleted_reports INTEGER NOT NULL DEFAULT 0,
  deleted_drafts INTEGER NOT NULL DEFAULT 0,
  deleted_scheduled_posts INTEGER NOT NULL DEFAULT 0,
  deleted_audit_events INTEGER NOT NULL DEFAULT 0,
  deleted_expired_mcp_tokens INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running','complete','partial')),
  error_code TEXT
);
ALTER TABLE org_members ADD COLUMN revoked_at TEXT;
CREATE INDEX IF NOT EXISTS idx_metrics_retention ON metrics(date);
CREATE INDEX IF NOT EXISTS idx_sales_retention ON sales_observations(date);
CREATE INDEX IF NOT EXISTS idx_costs_retention ON business_costs(date);
CREATE INDEX IF NOT EXISTS idx_reports_retention ON reports(generated_at);
CREATE INDEX IF NOT EXISTS idx_drafts_retention ON content_drafts(updated_at);
CREATE INDEX IF NOT EXISTS idx_schedule_retention ON scheduled_posts(status,updated_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_integrations_provider_no_account
  ON integration_connections(organization_id,project_id,provider)
  WHERE account_id IS NULL;
