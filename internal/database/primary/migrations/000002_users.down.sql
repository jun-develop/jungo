-- Their role grants go with them (ON DELETE CASCADE).
DELETE FROM permissions WHERE code IN ('users:read', 'users:create', 'users:update', 'users:delete');
DROP FUNCTION IF EXISTS f_user_permissions;
DROP TABLE IF EXISTS user_roles;
DROP TRIGGER IF EXISTS trg_users_updated_at ON users;
DROP INDEX IF EXISTS idx_users_last_name_trgm;
DROP INDEX IF EXISTS idx_users_first_name_trgm;
DROP INDEX IF EXISTS idx_users_email_trgm;
DROP INDEX IF EXISTS uq_users_email;
DROP INDEX IF EXISTS idx_users_active_created_at;
DROP TABLE IF EXISTS users;
