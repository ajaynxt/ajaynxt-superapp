CREATE TABLE IF NOT EXISTS oauth_registration_events (
  id TEXT PRIMARY KEY,
  ip_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_oauth_registration_ip_time ON oauth_registration_events(ip_hash,created_at DESC);
