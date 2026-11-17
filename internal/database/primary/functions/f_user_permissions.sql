-- =============================================================================
-- FUNCTION: f_user_permissions
-- =============================================================================
-- The permission codes a user holds through their roles, sorted and without
-- duplicates. Every query that needs a user's permissions calls this one.
-- =============================================================================

CREATE OR REPLACE FUNCTION f_user_permissions(p_user_id BIGINT)
RETURNS TEXT[]
LANGUAGE sql
STABLE
AS $$
    SELECT ARRAY(
        SELECT DISTINCT rp.permission_code
        FROM user_roles ur
        JOIN role_permissions rp ON rp.role_id = ur.role_id
        WHERE ur.user_id = p_user_id
        ORDER BY rp.permission_code
    );
$$;
