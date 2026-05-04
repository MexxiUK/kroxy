-- Add route_id to waf_rules for per-route WAF rules
-- NULL route_id = global rule (applies to all routes)
-- Non-null route_id = rule specific to that route
ALTER TABLE waf_rules ADD COLUMN route_id INTEGER REFERENCES routes(id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS idx_waf_rules_route_id ON waf_rules(route_id);