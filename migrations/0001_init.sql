CREATE TABLE IF NOT EXISTS users (
  uid TEXT PRIMARY KEY,
  email TEXT,
  email_verified INTEGER NOT NULL DEFAULT 0 CHECK (email_verified IN (0,1)),
  display_name TEXT,
  photo_url TEXT,
  last_seen_at TEXT
);

CREATE TABLE IF NOT EXISTS organizations (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  owner_uid TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','archived')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  schema_version INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_org_owner_status ON organizations(owner_uid,status);

CREATE TABLE IF NOT EXISTS org_members (
  organization_id TEXT NOT NULL REFERENCES organizations(id),
  user_uid TEXT NOT NULL REFERENCES users(uid),
  role TEXT NOT NULL CHECK (role IN ('owner','admin','operator','analyst','client_viewer')),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (organization_id,user_uid)
);
CREATE INDEX IF NOT EXISTS idx_members_user_status ON org_members(user_uid,status);

CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id),
  name TEXT NOT NULL,
  name_lower TEXT NOT NULL,
  type TEXT NOT NULL DEFAULT 'Other',
  location TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','archived','suspended')),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  schema_version INTEGER NOT NULL DEFAULT 1,
  UNIQUE(organization_id,name_lower)
);
CREATE INDEX IF NOT EXISTS idx_projects_org_status ON projects(organization_id,status);

CREATE TABLE IF NOT EXISTS metrics (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id),
  project_id TEXT NOT NULL REFERENCES projects(id),
  date TEXT NOT NULL,
  platform TEXT NOT NULL,
  platform_key TEXT NOT NULL,
  metric TEXT NOT NULL,
  metric_key TEXT NOT NULL,
  value REAL NOT NULL CHECK (value >= 0),
  source TEXT NOT NULL DEFAULT 'User import',
  source_verified INTEGER NOT NULL DEFAULT 0 CHECK (source_verified IN (0,1)),
  imported_by TEXT NOT NULL,
  imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(project_id,date,platform_key,metric_key)
);
CREATE INDEX IF NOT EXISTS idx_metrics_project_date ON metrics(project_id,date DESC);
CREATE INDEX IF NOT EXISTS idx_metrics_org_date ON metrics(organization_id,date DESC);
CREATE INDEX IF NOT EXISTS idx_metrics_project_series ON metrics(project_id,platform_key,metric_key,date);

CREATE TABLE IF NOT EXISTS platform_admins (
  uid TEXT PRIMARY KEY REFERENCES users(uid),
  admin_id TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL,
  display_name TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_admin_status_created ON platform_admins(status,created_at DESC);

CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  organization_id TEXT REFERENCES organizations(id),
  actor_uid TEXT NOT NULL,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL DEFAULT '',
  record_count INTEGER,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_audit_org_created ON audit_events(organization_id,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor_created ON audit_events(actor_uid,created_at DESC);

CREATE TABLE IF NOT EXISTS content_drafts (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id),
  project_id TEXT NOT NULL REFERENCES projects(id),
  title TEXT NOT NULL,
  copy_text TEXT NOT NULL DEFAULT '',
  platforms_json TEXT NOT NULL DEFAULT '[]',
  media_refs_json TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','ready','archived')),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_drafts_project_updated ON content_drafts(project_id,updated_at DESC);

CREATE TABLE IF NOT EXISTS scheduled_posts (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id),
  project_id TEXT NOT NULL REFERENCES projects(id),
  draft_id TEXT REFERENCES content_drafts(id),
  platform TEXT NOT NULL,
  scheduled_at TEXT,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','scheduled','needs_connection','publishing','published','failed','cancelled')),
  provider_post_id TEXT,
  last_error_code TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  published_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_schedule_due ON scheduled_posts(status,scheduled_at);

CREATE TABLE IF NOT EXISTS integration_connections (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id),
  project_id TEXT NOT NULL REFERENCES projects(id),
  provider TEXT NOT NULL,
  account_id TEXT,
  account_name TEXT,
  status TEXT NOT NULL DEFAULT 'not_connected' CHECK (status IN ('not_connected','pending_authorization','connected','import_required','error','revoked')),
  scopes_json TEXT NOT NULL DEFAULT '[]',
  last_verified_at TEXT,
  last_sync_at TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(project_id,provider,account_id)
);
CREATE INDEX IF NOT EXISTS idx_integrations_project_provider ON integration_connections(project_id,provider,status);

CREATE TABLE IF NOT EXISTS sales_observations (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id),
  project_id TEXT NOT NULL REFERENCES projects(id),
  date TEXT NOT NULL,
  source TEXT NOT NULL,
  metric TEXT NOT NULL,
  value REAL NOT NULL CHECK (value >= 0),
  currency TEXT NOT NULL DEFAULT 'INR',
  source_verified INTEGER NOT NULL DEFAULT 0 CHECK (source_verified IN (0,1)),
  imported_by TEXT NOT NULL,
  imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_sales_project_date ON sales_observations(project_id,date DESC);

CREATE TABLE IF NOT EXISTS business_costs (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id),
  project_id TEXT NOT NULL REFERENCES projects(id),
  date TEXT NOT NULL,
  category TEXT NOT NULL,
  amount REAL NOT NULL CHECK (amount >= 0),
  currency TEXT NOT NULL DEFAULT 'INR',
  description TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT 'User entry',
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_costs_project_date ON business_costs(project_id,date DESC);

CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id),
  project_id TEXT NOT NULL REFERENCES projects(id),
  report_type TEXT NOT NULL,
  period_start TEXT,
  period_end TEXT,
  content_json TEXT NOT NULL,
  source_verified INTEGER NOT NULL DEFAULT 0 CHECK (source_verified IN (0,1)),
  generated_by TEXT NOT NULL,
  generated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_reports_project_generated ON reports(project_id,generated_at DESC);
