-- =============================================================================
-- ACCESS SEEDER (development only)
-- Demo roles and the demo accounts' roles. Permissions and super_admin's grants come from the
-- migrations, never from here.
-- Idempotent: existing rows are skipped, so it is safe to re-run.
-- =============================================================================

-- Demo roles; super_admin is created by migration 000001_access.
INSERT INTO roles (code, name) VALUES
    ('manager', 'Manager'),
    ('member',  'Member')
ON CONFLICT (code) DO NOTHING;

-- manager: manages users (no delete) and views roles; member: views users.
INSERT INTO role_permissions (role_id, permission_code)
SELECT r.id, grants.permission_code
FROM (VALUES
    ('manager', 'users:read'),
    ('manager', 'users:create'),
    ('manager', 'users:update'),
    ('manager', 'roles:read'),
    ('member',  'users:read')
) AS grants(role_code, permission_code)
JOIN roles r ON r.code = grants.role_code
ON CONFLICT DO NOTHING;

-- Demo accounts (001_users.sql); user@jungo.com keeps no role.
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM (VALUES
    ('admin@jungo.com',   'super_admin'),
    ('manager@jungo.com', 'manager'),
    ('member@jungo.com',  'member')
) AS seed(email, role_code)
JOIN users u ON u.email = seed.email AND u.deleted_at IS NULL
JOIN roles r ON r.code = seed.role_code
ON CONFLICT DO NOTHING;
