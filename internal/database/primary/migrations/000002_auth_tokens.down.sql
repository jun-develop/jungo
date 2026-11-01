DROP FUNCTION IF EXISTS f_auth_refresh_session;
DROP FUNCTION IF EXISTS f_auth_login_session;
DROP TRIGGER IF EXISTS trg_auth_tokens_updated_at ON auth_tokens;
DROP FUNCTION IF EXISTS f_set_auth_tokens_updated_at;
DROP INDEX IF EXISTS idx_auth_tokens_revoked_at;
DROP INDEX IF EXISTS idx_auth_tokens_expires_at;
DROP INDEX IF EXISTS idx_auth_tokens_user_device_active;
DROP INDEX IF EXISTS idx_auth_tokens_family;
DROP TABLE IF EXISTS auth_tokens;
