-- =============================================================================
-- FUNCTION: f_auth_login_session
-- =============================================================================
-- Rotates the user's session on the same device (or IP + User-Agent when no
-- device id) or creates a new one. Returns action, family_uuid, old_family_uuid.
-- An IPv6 client is matched by its /64, which it usually holds whole while its
-- address rotates (as security.ClientKey does in Go).
-- =============================================================================

CREATE OR REPLACE FUNCTION f_auth_login_session(
    p_user_id            BIGINT,
    p_device_id          TEXT,
    p_ip_address         INET,
    p_user_agent         TEXT,
    p_access_hash        TEXT,
    p_access_expires_at  TIMESTAMPTZ,
    p_refresh_hash       TEXT,
    p_refresh_expires_at TIMESTAMPTZ,
    p_new_family_uuid    UUID
)
RETURNS TABLE (
    action          TEXT,
    family_uuid     UUID,
    old_family_uuid UUID
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_client          CIDR := CASE WHEN family(p_ip_address) = 6
                                   THEN network(set_masklen(p_ip_address, 64))
                                   ELSE network(p_ip_address) END;
    v_existing_family UUID;
    v_updated_count   INT := 0;
BEGIN
    -- Lock the existing session so concurrent logins cannot rotate it twice.
    SELECT t.family_uuid INTO v_existing_family
    FROM auth_tokens t
    WHERE t.user_id = p_user_id
      AND t.revoked_at IS NULL
      AND t.expires_at > now()
      AND (
            (p_device_id IS NOT NULL AND t.device_id = p_device_id)
         OR (p_device_id IS NULL
             AND t.device_id IS NULL
             AND (t.ip_address <<= v_client OR (v_client IS NULL AND t.ip_address IS NULL))
             AND t.user_agent IS NOT DISTINCT FROM p_user_agent)
      )
    ORDER BY t.id DESC
    LIMIT 1
    FOR UPDATE;

    -- Rotate both tokens in one UPDATE.
    IF v_existing_family IS NOT NULL THEN
        UPDATE auth_tokens t
        SET uuid       = gen_random_uuid(),
            hash       = CASE WHEN t.type = 1 THEN p_access_hash       ELSE p_refresh_hash       END,
            expires_at = CASE WHEN t.type = 1 THEN p_access_expires_at ELSE p_refresh_expires_at END,
            ip_address = p_ip_address,
            user_agent = p_user_agent
        WHERE t.family_uuid = v_existing_family
          AND t.revoked_at IS NULL;

        GET DIAGNOSTICS v_updated_count = ROW_COUNT;

        IF v_updated_count = 2 THEN
            RETURN QUERY SELECT 'rotated'::TEXT, v_existing_family, v_existing_family;
            RETURN;
        END IF;

        -- Partial rotation: end that session and create a fresh one.
        UPDATE auth_tokens t
        SET revoked_at = now(), revoked_reason = 'rotated'
        WHERE t.family_uuid = v_existing_family
          AND t.revoked_at IS NULL;
    END IF;

    -- Create a fresh session.
    INSERT INTO auth_tokens (user_id, family_uuid, type, hash, expires_at, ip_address, user_agent, device_id)
    VALUES
        (p_user_id, p_new_family_uuid, 1, p_access_hash,  p_access_expires_at,  p_ip_address, p_user_agent, p_device_id),
        (p_user_id, p_new_family_uuid, 2, p_refresh_hash, p_refresh_expires_at, p_ip_address, p_user_agent, p_device_id);

    RETURN QUERY SELECT 'created'::TEXT, p_new_family_uuid, v_existing_family;
END;
$$;
