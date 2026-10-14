-- OAuth 2.1 / MCP authorization server tables.
-- This migration is append-only once deployed.
CREATE TABLE IF NOT EXISTS oauth_clients (
  client_id TEXT PRIMARY KEY,
  client_name TEXT NOT NULL,
  redirect_uris_json TEXT NOT NULL,
  token_endpoint_auth_method TEXT NOT NULL CHECK (token_endpoint_auth_method IN ('none','client_secret_post','client_secret_basic')),
  client_secret_hash TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at TEXT,
  revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_oauth_clients_status ON oauth_clients(status,created_at DESC);

CREATE TABLE IF NOT EXISTS oauth_requests (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id),
  state TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL CHECK (code_challenge_method='S256'),
  scope TEXT NOT NULL CHECK (scope IN ('mcp:read','mcp:read offline_access')),
  resource TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  user_uid TEXT
);
CREATE INDEX IF NOT EXISTS idx_oauth_requests_expiry ON oauth_requests(expires_at);

CREATE TABLE IF NOT EXISTS oauth_sessions (
  session_hash TEXT PRIMARY KEY,
  user_uid TEXT NOT NULL REFERENCES users(uid),
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_oauth_sessions_expiry ON oauth_sessions(expires_at);

CREATE TABLE IF NOT EXISTS oauth_codes (
  id TEXT PRIMARY KEY,
  code_hash TEXT NOT NULL UNIQUE,
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id),
  user_uid TEXT NOT NULL REFERENCES users(uid),
  organization_id TEXT NOT NULL REFERENCES organizations(id),
  project_id TEXT REFERENCES projects(id),
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  scope TEXT NOT NULL CHECK (scope IN ('mcp:read','mcp:read offline_access')),
  resource TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_oauth_codes_expiry ON oauth_codes(expires_at,used_at);

CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id),
  family_id TEXT NOT NULL REFERENCES mcp_tokens(id),
  user_uid TEXT NOT NULL REFERENCES users(uid),
  organization_id TEXT NOT NULL REFERENCES organizations(id),
  project_id TEXT REFERENCES projects(id),
  scope TEXT NOT NULL CHECK (scope IN ('mcp:read','mcp:read offline_access')),
  resource TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_expiry ON oauth_refresh_tokens(status,expires_at);
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_family ON oauth_refresh_tokens(family_id,status);

-- Index the actual timestamp fields used by the scheduled retention worker.
CREATE INDEX IF NOT EXISTS idx_metrics_imported_retention ON metrics(imported_at);
CREATE INDEX IF NOT EXISTS idx_sales_imported_retention ON sales_observations(imported_at);
CREATE INDEX IF NOT EXISTS idx_costs_created_retention ON business_costs(created_at);
CREATE INDEX IF NOT EXISTS idx_drafts_created_retention ON content_drafts(created_at);
CREATE INDEX IF NOT EXISTS idx_schedule_created_retention ON scheduled_posts(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_created_retention ON audit_events(created_at);
CREATE INDEX IF NOT EXISTS idx_runs_started_retention ON retention_runs(started_at);
CREATE INDEX IF NOT EXISTS idx_connections_updated_retention ON integration_connections(status,updated_at);
