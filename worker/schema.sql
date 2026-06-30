CREATE TABLE IF NOT EXISTS visitors (
  visitor_id TEXT PRIMARY KEY,
  country TEXT NOT NULL DEFAULT 'XX', region TEXT NOT NULL DEFAULT '', city TEXT NOT NULL DEFAULT '',
  latitude REAL, longitude REAL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, visit_count INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS threat_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, visitor_id TEXT NOT NULL, event_id TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL, attack TEXT NOT NULL, family TEXT NOT NULL, risk REAL NOT NULL,
  action TEXT NOT NULL, outcome TEXT NOT NULL, source_label TEXT NOT NULL DEFAULT '', target_label TEXT NOT NULL DEFAULT '',
  FOREIGN KEY(visitor_id) REFERENCES visitors(visitor_id)
);
CREATE INDEX IF NOT EXISTS idx_events_visitor ON threat_events(visitor_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_created ON threat_events(created_at DESC);
CREATE TABLE IF NOT EXISTS admin_attempts (
  visitor_id TEXT PRIMARY KEY, failures INTEGER NOT NULL DEFAULT 0, last_attempt TEXT NOT NULL
);
