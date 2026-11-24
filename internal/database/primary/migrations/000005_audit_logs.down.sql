-- Its role grants go with it (ON DELETE CASCADE).
DELETE FROM permissions WHERE code = 'audit_logs:read';

DROP TABLE IF EXISTS audit_logs;
