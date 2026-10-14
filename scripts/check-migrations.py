#!/usr/bin/env python3
"""Validate all D1 SQL migrations against SQLite in dependency order."""
from pathlib import Path
import sqlite3
import sys

root = Path(__file__).resolve().parents[1]
migration_dir = root / "migrations"
files = sorted(migration_dir.glob("*.sql"))
if not files:
    raise SystemExit("No migration files found.")

connection = sqlite3.connect(":memory:")
connection.execute("PRAGMA foreign_keys = ON")

for path in files:
    try:
        connection.executescript(path.read_text(encoding="utf-8"))
    except sqlite3.Error as exc:
        raise SystemExit(f"Migration failed: {path.name}: {exc}") from exc

tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
required = {
    "users", "organizations", "org_members", "projects", "metrics",
    "platform_admins", "audit_events", "content_drafts", "scheduled_posts",
    "integration_connections", "sales_observations", "business_costs", "reports",
    "mcp_tokens", "retention_runs", "oauth_clients", "oauth_requests",
    "oauth_sessions", "oauth_codes", "oauth_refresh_tokens",
    "oauth_registration_events",
}
missing = required - tables
if missing:
    raise SystemExit("Missing tables after migrations: " + ", ".join(sorted(missing)))

foreign_key_errors = list(connection.execute("PRAGMA foreign_key_check"))
if foreign_key_errors:
    raise SystemExit("Foreign-key issues after migrations: " + repr(foreign_key_errors))

print(f"Validated {len(files)} D1 migrations and {len(required)} required tables.")
