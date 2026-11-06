-- name: CreateLoginSession :one
-- old_family_uuid is uuid.Nil when no session existed.
SELECT s.action::text                                                               AS action,
       s.family_uuid::uuid                                                          AS family_uuid,
       COALESCE(s.old_family_uuid, '00000000-0000-0000-0000-000000000000')::uuid    AS old_family_uuid
FROM f_auth_login_session(
    sqlc.arg(user_id)::bigint,
    sqlc.narg(device_id)::text,
    sqlc.narg(ip_address)::inet,
    sqlc.narg(user_agent)::text,
    sqlc.arg(access_hash)::text,
    sqlc.arg(access_expires_at)::timestamptz,
    sqlc.arg(refresh_hash)::text,
    sqlc.arg(refresh_expires_at)::timestamptz,
    sqlc.arg(new_family_uuid)::uuid
) AS s(action, family_uuid, old_family_uuid);

-- name: RefreshSession :one
SELECT s.status::text                                                         AS status,
       COALESCE(s.family_uuid, '00000000-0000-0000-0000-000000000000')::uuid  AS family_uuid,
       COALESCE(s.user_uuid, '00000000-0000-0000-0000-000000000000')::uuid    AS user_uuid
FROM f_auth_refresh_session(
    sqlc.arg(hash)::text,
    sqlc.narg(device_id)::text,
    sqlc.narg(ip_address)::inet,
    sqlc.narg(user_agent)::text,
    sqlc.arg(access_hash)::text,
    sqlc.arg(access_expires_at)::timestamptz,
    sqlc.arg(refresh_hash)::text,
    sqlc.arg(refresh_expires_at)::timestamptz
) AS s(status, family_uuid, user_uuid);

-- name: GetSessionByHash :one
-- Any token hash of a family -> its user, their permission codes and latest token pair. The codes
-- come with the session so an authenticated request needs one query, not two.
WITH token AS (
    SELECT t.family_uuid, t.user_id FROM auth_tokens t WHERE t.hash = sqlc.arg(hash)
),
access_token AS (
    SELECT a.* FROM auth_tokens a
    WHERE a.family_uuid = (SELECT family_uuid FROM token) AND a.type = 1
    ORDER BY a.id DESC LIMIT 1
),
refresh_token AS (
    SELECT r.* FROM auth_tokens r
    WHERE r.family_uuid = (SELECT family_uuid FROM token) AND r.type = 2
    ORDER BY r.id DESC LIMIT 1
)
SELECT
    u.id                 AS user_id,
    u.uuid               AS user_uuid,
    u.email,
    u.first_name,
    u.last_name,
    u.avatar_url,
    u.status             AS user_status,
    tk.family_uuid,
    r.ip_address,
    r.user_agent,
    r.device_id,
    (SELECT min(f.created_at) FROM auth_tokens f WHERE f.family_uuid = tk.family_uuid)::timestamptz AS session_created_at,
    a.uuid               AS access_uuid,
    a.hash               AS access_hash,
    a.expires_at         AS access_expires_at,
    a.revoked_at         AS access_revoked_at,
    r.uuid               AS refresh_uuid,
    r.hash               AS refresh_hash,
    r.expires_at         AS refresh_expires_at,
    r.revoked_at         AS refresh_revoked_at,
    ARRAY(
        SELECT DISTINCT rp.permission_code
        FROM user_roles ur
        JOIN role_permissions rp ON rp.role_id = ur.role_id
        WHERE ur.user_id = u.id
        ORDER BY rp.permission_code
    )::text[]            AS permissions
FROM token tk
JOIN users u ON u.id = tk.user_id AND u.deleted_at IS NULL
JOIN access_token a ON true
JOIN refresh_token r ON true;

-- name: GetTokenByHash :one
SELECT t.uuid, t.user_id, u.uuid AS user_uuid, u.status AS user_status, t.family_uuid, t.type,
       t.device_id, t.expires_at, t.revoked_at, t.revoked_reason
FROM auth_tokens t
JOIN users u ON u.id = t.user_id AND u.deleted_at IS NULL
WHERE t.hash = $1;

-- name: RevokeFamily :execrows
UPDATE auth_tokens
SET revoked_at = now(), revoked_reason = sqlc.arg(reason)
WHERE family_uuid = sqlc.arg(family_uuid) AND revoked_at IS NULL;

-- name: RevokeFamilyByHash :one
-- No row means the token does not exist or its user was deleted.
WITH token AS (
    SELECT t.family_uuid FROM auth_tokens t
    JOIN users u ON u.id = t.user_id AND u.deleted_at IS NULL
    WHERE t.hash = sqlc.arg(hash)
),
revoked AS (
    UPDATE auth_tokens a
    SET revoked_at = now(), revoked_reason = sqlc.arg(reason)
    WHERE a.family_uuid = (SELECT family_uuid FROM token) AND a.revoked_at IS NULL
)
SELECT family_uuid FROM token;

-- name: RevokeAllByHash :one
-- Revokes every session of the token's owner. No row means the token does not exist or its user
-- was deleted.
WITH token AS (
    SELECT t.user_id FROM auth_tokens t
    JOIN users u ON u.id = t.user_id AND u.deleted_at IS NULL
    WHERE t.hash = sqlc.arg(hash)
),
revoked AS (
    UPDATE auth_tokens a
    SET revoked_at = now(), revoked_reason = sqlc.arg(reason)
    WHERE a.user_id = (SELECT user_id FROM token) AND a.revoked_at IS NULL
    RETURNING a.family_uuid
)
SELECT ARRAY(SELECT DISTINCT family_uuid FROM revoked)::uuid[] AS families FROM token;

-- name: RevokeAllForUser :many
UPDATE auth_tokens t
SET revoked_at = now(), revoked_reason = sqlc.arg(reason)
FROM users u
WHERE u.id = t.user_id AND u.uuid = sqlc.arg(user_uuid) AND t.revoked_at IS NULL
RETURNING t.family_uuid;

-- name: ListActiveSessions :many
SELECT family_uuid, ip_address, user_agent, device_id, created_at, updated_at, expires_at
FROM auth_tokens
WHERE user_id = $1 AND type = 2 AND revoked_at IS NULL AND expires_at > now()
ORDER BY created_at DESC;

-- name: CleanupTokens :execrows
-- A live session (a family with an unexpired, unrevoked token) keeps its first row, which
-- GetSessionByHash reads the session start from, and its latest access token, which
-- GetSessionByHash joins.
DELETE FROM auth_tokens t
WHERE (t.expires_at < sqlc.arg(before) OR (t.revoked_at IS NOT NULL AND t.revoked_at < sqlc.arg(before)))
  AND NOT (
      t.id IN (
          (SELECT min(f.id) FROM auth_tokens f WHERE f.family_uuid = t.family_uuid),
          (SELECT max(f.id) FROM auth_tokens f WHERE f.family_uuid = t.family_uuid AND f.type = 1)
      )
      AND EXISTS (
          SELECT 1 FROM auth_tokens l
          WHERE l.family_uuid = t.family_uuid AND l.revoked_at IS NULL AND l.expires_at > now()
      )
  );

-- name: CreatePasswordResetToken :exec
-- Supersedes the user's earlier unused tokens, so only the latest emailed link works.
WITH superseded AS (
    UPDATE password_reset_tokens SET used_at = now()
    WHERE user_id = sqlc.arg(user_id) AND used_at IS NULL
)
INSERT INTO password_reset_tokens (user_id, hash, expires_at)
VALUES (sqlc.arg(user_id), sqlc.arg(hash), sqlc.arg(expires_at));

-- name: ConsumePasswordResetToken :one
-- Marks a valid token used and returns its active user; no row means invalid, used or expired.
UPDATE password_reset_tokens t
SET used_at = now()
FROM users u
WHERE t.hash = sqlc.arg(hash) AND t.used_at IS NULL AND t.expires_at > now()
  AND u.id = t.user_id AND u.deleted_at IS NULL AND u.status = 1
RETURNING t.user_id, u.uuid AS user_uuid;

-- name: CleanupPasswordResetTokens :execrows
DELETE FROM password_reset_tokens
WHERE expires_at < sqlc.arg(before) OR (used_at IS NOT NULL AND used_at < sqlc.arg(before));
