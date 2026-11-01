-- =============================================================================
-- FUNCTION: f_auth_refresh_session
-- =============================================================================
-- Exchanges a refresh token for a new token pair in the same session. Returns
-- status, family_uuid, user_uuid; status is one of:
--   rotated       the new pair was issued
--   not_found     no token has that hash, or its user was deleted
--   invalid_type  the token is an access token
--   user_inactive the user is not active
--   reused        the token was already exchanged: the whole session is revoked
--   revoked       the token was revoked for another reason
--   expired       the token has expired
-- The status names and revoked reasons match the Go constants in
-- internal/features/auth/domain/auth.go.
-- =============================================================================

CREATE OR REPLACE FUNCTION f_auth_refresh_session(
    p_hash               TEXT,
    p_device_id          TEXT,
    p_ip_address         INET,
    p_user_agent         TEXT,
    p_access_hash        TEXT,
    p_access_expires_at  TIMESTAMPTZ,
    p_refresh_hash       TEXT,
    p_refresh_expires_at TIMESTAMPTZ
)
RETURNS TABLE (
    status      TEXT,
    family_uuid UUID,
    user_uuid   UUID
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_user_id        BIGINT;
    v_family_uuid    UUID;
    v_type           SMALLINT;
    v_device_id      TEXT;
    v_expires_at     TIMESTAMPTZ;
    v_revoked_at     TIMESTAMPTZ;
    v_revoked_reason TEXT;
    v_user_uuid      UUID;
    v_user_active    BOOLEAN;
BEGIN
    -- Lock the token so two concurrent refreshes with it run one after the other: the second
    -- sees it already exchanged and is treated as reuse.
    SELECT t.user_id, t.family_uuid, t.type, t.device_id, t.expires_at, t.revoked_at, t.revoked_reason,
           u.uuid, u.status = 1
    INTO v_user_id, v_family_uuid, v_type, v_device_id, v_expires_at, v_revoked_at, v_revoked_reason,
         v_user_uuid, v_user_active
    FROM auth_tokens t
    JOIN users u ON u.id = t.user_id AND u.deleted_at IS NULL
    WHERE t.hash = p_hash
    FOR UPDATE OF t;

    IF NOT FOUND THEN
        RETURN QUERY SELECT 'not_found'::TEXT, NULL::UUID, NULL::UUID;
        RETURN;
    END IF;

    IF v_type <> 2 THEN
        RETURN QUERY SELECT 'invalid_type'::TEXT, v_family_uuid, v_user_uuid;
        RETURN;
    END IF;

    IF NOT v_user_active THEN
        RETURN QUERY SELECT 'user_inactive'::TEXT, v_family_uuid, v_user_uuid;
        RETURN;
    END IF;

    -- An already exchanged token used again means it may be stolen: end the whole session.
    IF v_revoked_reason = 'refresh' THEN
        UPDATE auth_tokens t
        SET revoked_at = now(), revoked_reason = 'reuse'
        WHERE t.family_uuid = v_family_uuid
          AND t.revoked_at IS NULL;

        RETURN QUERY SELECT 'reused'::TEXT, v_family_uuid, v_user_uuid;
        RETURN;
    END IF;

    IF v_revoked_at IS NOT NULL THEN
        RETURN QUERY SELECT 'revoked'::TEXT, v_family_uuid, v_user_uuid;
        RETURN;
    END IF;

    IF v_expires_at <= now() THEN
        RETURN QUERY SELECT 'expired'::TEXT, v_family_uuid, v_user_uuid;
        RETURN;
    END IF;

    -- Retire the current pair (the refresh token and its access token), then issue the new one.
    UPDATE auth_tokens t
    SET revoked_at = now(), revoked_reason = 'refresh'
    WHERE t.family_uuid = v_family_uuid
      AND t.revoked_at IS NULL;

    INSERT INTO auth_tokens (user_id, family_uuid, type, hash, expires_at, ip_address, user_agent, device_id)
    VALUES
        (v_user_id, v_family_uuid, 1, p_access_hash,  p_access_expires_at,  p_ip_address, p_user_agent, COALESCE(p_device_id, v_device_id)),
        (v_user_id, v_family_uuid, 2, p_refresh_hash, p_refresh_expires_at, p_ip_address, p_user_agent, COALESCE(p_device_id, v_device_id));

    RETURN QUERY SELECT 'rotated'::TEXT, v_family_uuid, v_user_uuid;
END;
$$;
