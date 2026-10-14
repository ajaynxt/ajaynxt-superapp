-- OAuth abuse-control event log and retention run statistic.
CREATE TABLE IF NOT EXISTS oauth_registration_events (
  id TEXT PRIMARY KEY,
  ip_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_oauth_registration_ip_created ON oauth_registration_events(ip_hash,created_at);
CREATE INDEX IF NOT EXISTS idx_oauth_registration_created ON oauth_registration_events(created_at);

ALTER TABLE retention_runs ADD COLUMN deleted_oauth_records INTEGER NOT NULL DEFAULT 0;
