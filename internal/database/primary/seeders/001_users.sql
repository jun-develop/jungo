-- =============================================================================
-- USERS SEEDER (development only)
-- Demo accounts, all with password: Password@123
-- Idempotent: existing emails are skipped, so it is safe to re-run.
-- bf 10 matches AUTH_PASSWORD_COST, so demo logins take as long as real ones.
-- =============================================================================

INSERT INTO users (email, password_hash, first_name, last_name)
SELECT email, crypt('Password@123', gen_salt('bf', 10)), first_name, 'Jungo'
FROM (VALUES
    ('admin@jungo.com',   'Admin'),
    ('manager@jungo.com', 'Manager'),
    ('member@jungo.com',  'Member'),
    ('user@jungo.com',    'User')
) AS seed(email, first_name)
WHERE NOT EXISTS (
    SELECT 1 FROM users u WHERE u.email = seed.email AND u.deleted_at IS NULL
);
