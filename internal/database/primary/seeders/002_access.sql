-- =============================================================================
-- ACCESS SEEDER
-- The built-in permissions (the app never writes them, it only refuses to start when one a feature
-- declares in its domain/permission.go is missing), super_admin's grants, then the demo roles and
-- the demo accounts' roles. Generated features' permissions are not added here: each one's own
-- migration inserts them.
-- Idempotent: existing rows are skipped, so it is safe to re-run.
-- =============================================================================

-- Permissions: user feature (users:*) and access feature (roles:*).
INSERT INTO permissions (code, group_code) VALUES
    ('users:read',   'users'),
    ('users:create', 'users'),
    ('users:update', 'users'),
    ('users:delete', 'users'),
    ('roles:read',   'access'),
    ('roles:create', 'access'),
    ('roles:update', 'access'),
    ('roles:delete', 'access'),
    ('roles:assign', 'access')
ON CONFLICT (code) DO NOTHING;

-- super_admin holds every permission.
INSERT INTO role_permissions (role_id, permission_code)
SELECT r.id, p.code
FROM roles r
CROSS JOIN permissions p
WHERE r.code = 'super_admin'
ON CONFLICT DO NOTHING;

-- Demo roles; super_admin is created by migration 000003.
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
