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
CREATE INDEX IF NOT EXISTS idx_mcp_tokens_owner ON mcp_tokens(owner_uid,status);
CREATE INDEX IF NOT EXISTS idx_mcp_tokens_org ON mcp_tokens(organization_id,status);

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
  status TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running','complete','partial','failed')),
  error_code TEXT
);
CREATE INDEX IF NOT EXISTS idx_retention_runs_started ON retention_runs(started_at DESC);
