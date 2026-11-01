DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS role_permissions;
DROP TRIGGER IF EXISTS trg_roles_updated_at ON roles;
DROP FUNCTION IF EXISTS f_set_roles_updated_at;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS permissions;
