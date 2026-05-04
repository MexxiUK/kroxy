-- Add WAF paranoia level to routes (0 = use global default, 1-3 = PL1/PL2/PL3)
ALTER TABLE routes ADD COLUMN waf_paranoia_level INTEGER NOT NULL DEFAULT 0 CHECK(waf_paranoia_level BETWEEN 0 AND 3);

-- Add exclusions column to WAF rules (comma-separated CRS rule IDs to exclude)
ALTER TABLE waf_rules ADD COLUMN exclusions TEXT NOT NULL DEFAULT '';