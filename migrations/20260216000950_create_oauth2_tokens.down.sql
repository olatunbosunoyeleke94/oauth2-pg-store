-- Add down migration script here
DROP INDEX IF EXISTS idx_oauth2_access_hash;
DROP INDEX IF EXISTS idx_oauth2_refresh_hash;
DROP TABLE IF EXISTS oauth2_tokens;
