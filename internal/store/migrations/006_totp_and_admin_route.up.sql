-- Add TOTP fields to users table
ALTER TABLE users ADD COLUMN totp_secret TEXT DEFAULT '';
ALTER TABLE users ADD COLUMN totp_enabled BOOLEAN DEFAULT 0;

-- Add admin route flag to routes table
ALTER TABLE routes ADD COLUMN is_admin_route BOOLEAN DEFAULT 0;