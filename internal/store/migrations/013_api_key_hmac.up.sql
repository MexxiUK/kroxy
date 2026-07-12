-- Add HMAC pre-check column for API key secrets to mitigate bcrypt DoS (CRIT-004).
-- Existing keys with an empty HMAC fall back to bcrypt verification.
ALTER TABLE api_keys ADD COLUMN key_secret_hmac TEXT DEFAULT '';
