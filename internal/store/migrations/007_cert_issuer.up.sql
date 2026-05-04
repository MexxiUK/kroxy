ALTER TABLE certificates ADD COLUMN issuer TEXT DEFAULT '';
ALTER TABLE certificates ADD COLUMN type TEXT DEFAULT 'custom';