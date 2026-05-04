-- Settings table for global configuration key-value pairs
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default WAF paranoia level
INSERT INTO settings (key, value) VALUES ('waf_paranoia_level', '1');