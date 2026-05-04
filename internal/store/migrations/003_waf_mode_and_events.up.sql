-- Add mode column to WAF rules: 'block' or 'log_only'
ALTER TABLE waf_rules ADD COLUMN mode TEXT NOT NULL DEFAULT 'block' CHECK(mode IN ('block', 'log_only'));

-- Add WAF mode column to routes: 'block' or 'detect'
ALTER TABLE routes ADD COLUMN waf_mode TEXT NOT NULL DEFAULT 'block' CHECK(waf_mode IN ('block', 'detect'));

-- Create security events table for WAF block/detect logs
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    client_ip TEXT NOT NULL,
    host TEXT NOT NULL DEFAULT '',
    uri TEXT NOT NULL DEFAULT '',
    method TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    rule_name TEXT NOT NULL DEFAULT '',
    rule_id INTEGER,
    route_id INTEGER,
    action TEXT NOT NULL CHECK(action IN ('blocked', 'detected')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_security_events_created_at ON security_events(created_at);
CREATE INDEX IF NOT EXISTS idx_security_events_route_id ON security_events(route_id);
CREATE INDEX IF NOT EXISTS idx_security_events_action ON security_events(action);