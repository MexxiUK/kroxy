-- Remove the obsolete admin_tokens table. The global admin-token bypass
-- was removed in the previous security pass; this schema is now unused.
DROP TABLE IF EXISTS admin_tokens;
