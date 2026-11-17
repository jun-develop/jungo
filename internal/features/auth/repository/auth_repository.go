package repository

import (
	"context"
	"net/netip"
	"time"

	"github.com/google/uuid"

	"github.com/jun-develop/junkit/database"

	"jungo/internal/database/primary"
	"jungo/internal/database/primary/sqlc"
	"jungo/internal/features/auth/domain"
)

// cleanupBatchSize caps the rows one CleanupTokens statement deletes, so a cleanup never holds a
// long transaction on auth_tokens, which every request reads.
const cleanupBatchSize = 5000

// AuthRepository implements domain.AuthRepository.
type AuthRepository struct {
	db *primary.DB
}

// NewAuthRepository creates an AuthRepository backed by db.
func NewAuthRepository(db *primary.DB) *AuthRepository {
	return &AuthRepository{db: db}
}

// WithTransaction implements domain.AuthRepository.
func (r *AuthRepository) WithTransaction(ctx context.Context, fn func(ctx context.Context) error) error {
	return r.db.WithTransaction(ctx, fn)
}

// CreateLoginSession implements domain.AuthRepository; it rotates the device's session
// or creates a new one (f_auth_login_session).
func (r *AuthRepository) CreateLoginSession(ctx context.Context, params domain.NewSessionParams) (*domain.LoginSessionResult, error) {
	row, err := r.db.Queries(ctx).CreateLoginSession(ctx, sqlc.CreateLoginSessionParams{
		UserID:           params.UserID,
		DeviceID:         params.DeviceID,
		IPAddress:        parseIP(params.IPAddress),
		UserAgent:        params.UserAgent,
		AccessHash:       params.AccessHash,
		AccessExpiresAt:  params.AccessExpiresAt,
		RefreshHash:      params.RefreshHash,
		RefreshExpiresAt: params.RefreshExpiresAt,
		NewFamilyUUID:    params.FamilyUUID,
	})
	if err != nil {
		return nil, wrap("create login session", err)
	}

	return &domain.LoginSessionResult{FamilyUUID: row.FamilyUUID, StaleFamilyUUID: row.OldFamilyUUID}, nil
}

// RefreshSession implements domain.AuthRepository; it exchanges the refresh token for the new
// pair in params, or reports why not (f_auth_refresh_session).
func (r *AuthRepository) RefreshSession(ctx context.Context, hash string, params domain.NewSessionParams) (*domain.RefreshResult, error) {
	row, err := r.db.Queries(ctx).RefreshSession(ctx, sqlc.RefreshSessionParams{
		Hash:             hash,
		DeviceID:         params.DeviceID,
		IPAddress:        parseIP(params.IPAddress),
		UserAgent:        params.UserAgent,
		AccessHash:       params.AccessHash,
		AccessExpiresAt:  params.AccessExpiresAt,
		RefreshHash:      params.RefreshHash,
		RefreshExpiresAt: params.RefreshExpiresAt,
	})
	if err != nil {
		return nil, wrap("refresh session", err)
	}

	return &domain.RefreshResult{Status: row.Status, FamilyUUID: row.FamilyUUID, UserUUID: row.UserUUID}, nil
}

// GetSessionByHash implements domain.AuthRepository.
func (r *AuthRepository) GetSessionByHash(ctx context.Context, hash string) (*domain.Session, error) {
	row, err := r.db.Queries(ctx).GetSessionByHash(ctx, hash)
	if err != nil {
		return nil, wrap("get session", database.MatchNotFound(err, domain.ErrTokenNotFound))
	}

	return mapSession(row), nil
}

// GetTokenTypeByHash implements domain.AuthRepository.
func (r *AuthRepository) GetTokenTypeByHash(ctx context.Context, hash string) (domain.TokenType, error) {
	t, err := r.db.Queries(ctx).GetTokenTypeByHash(ctx, hash)
	if err != nil {
		return 0, wrap("get token type", database.MatchNotFound(err, domain.ErrTokenNotFound))
	}

	return domain.TokenType(t), nil
}

// RevokeFamily implements domain.AuthRepository.
func (r *AuthRepository) RevokeFamily(ctx context.Context, familyUUID uuid.UUID, reason string) error {
	_, err := r.db.Queries(ctx).RevokeFamily(ctx, sqlc.RevokeFamilyParams{
		FamilyUUID: familyUUID,
		Reason:     &reason,
	})
	if err != nil {
		return wrap("revoke family", err)
	}

	return nil
}

// RevokeFamilyByHash implements domain.AuthRepository; it revokes the session the token belongs to
// and returns its family.
func (r *AuthRepository) RevokeFamilyByHash(ctx context.Context, hash, reason string) (uuid.UUID, error) {
	family, err := r.db.Queries(ctx).RevokeFamilyByHash(ctx, sqlc.RevokeFamilyByHashParams{
		Hash:   hash,
		Reason: &reason,
	})
	if err != nil {
		return uuid.Nil, wrap("revoke family by hash", database.MatchNotFound(err, domain.ErrTokenNotFound))
	}

	return family, nil
}

// RevokeAllByHash implements domain.AuthRepository; it revokes every session of the token's owner
// and returns the affected families.
func (r *AuthRepository) RevokeAllByHash(ctx context.Context, hash, reason string) ([]uuid.UUID, error) {
	families, err := r.db.Queries(ctx).RevokeAllByHash(ctx, sqlc.RevokeAllByHashParams{
		Hash:   hash,
		Reason: &reason,
	})
	if err != nil {
		return nil, wrap("revoke all by hash", database.MatchNotFound(err, domain.ErrTokenNotFound))
	}

	return families, nil
}

// RevokeAllForUser implements domain.AuthRepository; it returns each affected family once.
func (r *AuthRepository) RevokeAllForUser(ctx context.Context, userUUID uuid.UUID, reason string) ([]uuid.UUID, error) {
	families, err := r.db.Queries(ctx).RevokeAllForUser(ctx, sqlc.RevokeAllForUserParams{
		UserUUID: userUUID,
		Reason:   &reason,
	})
	if err != nil {
		return nil, wrap("revoke all for user", err)
	}

	return families, nil
}

// ListActiveSessions implements domain.AuthRepository.
func (r *AuthRepository) ListActiveSessions(ctx context.Context, userID int64) ([]*domain.SessionSummary, error) {
	rows, err := r.db.Queries(ctx).ListActiveSessions(ctx, userID)
	if err != nil {
		return nil, wrap("list active sessions", err)
	}

	items := make([]*domain.SessionSummary, len(rows))
	for i, row := range rows {
		items[i] = &domain.SessionSummary{
			FamilyUUID: row.FamilyUUID,
			IPAddress:  formatIP(row.IPAddress),
			UserAgent:  row.UserAgent,
			DeviceID:   row.DeviceID,
			CreatedAt:  row.CreatedAt,
			ExpiresAt:  row.ExpiresAt,
		}
	}

	return items, nil
}

// CleanupTokens implements domain.AuthRepository; it deletes in batches of cleanupBatchSize.
func (r *AuthRepository) CleanupTokens(ctx context.Context, before time.Time) (int64, error) {
	queries := r.db.Queries(ctx)

	var deleted int64
	for {
		n, err := queries.CleanupTokens(ctx, sqlc.CleanupTokensParams{Before: before, BatchSize: cleanupBatchSize})
		if err != nil {
			return deleted, wrap("cleanup tokens", err)
		}

		deleted += n
		if n < cleanupBatchSize {
			break
		}
	}

	resets, err := queries.CleanupPasswordResetTokens(ctx, before)
	if err != nil {
		return deleted, wrap("cleanup password reset tokens", err)
	}

	return deleted + resets, nil
}

// CreatePasswordResetToken implements domain.AuthRepository; it supersedes the user's earlier
// unused tokens.
func (r *AuthRepository) CreatePasswordResetToken(ctx context.Context, userID int64, hash string, expiresAt time.Time) error {
	err := r.db.Queries(ctx).CreatePasswordResetToken(ctx, sqlc.CreatePasswordResetTokenParams{
		UserID:    userID,
		Hash:      hash,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return wrap("create password reset token", err)
	}

	return nil
}

// ConsumePasswordResetToken implements domain.AuthRepository; it returns ErrInvalidResetToken for
// an unknown, used or expired token, or one whose user is no longer active.
func (r *AuthRepository) ConsumePasswordResetToken(ctx context.Context, hash string) (*domain.PasswordResetOwner, error) {
	row, err := r.db.Queries(ctx).ConsumePasswordResetToken(ctx, hash)
	if err != nil {
		return nil, wrap("consume password reset token", database.MatchNotFound(err, domain.ErrInvalidResetToken))
	}

	return &domain.PasswordResetOwner{UserID: row.UserID, UserUUID: row.UserUUID}, nil
}

// mapSession converts a generated sqlc.GetSessionByHashRow to the domain model.
func mapSession(row sqlc.GetSessionByHashRow) *domain.Session {
	return &domain.Session{
		UserID:     row.UserID,
		UserUUID:   row.UserUUID,
		Email:      row.Email,
		FirstName:  row.FirstName,
		LastName:   row.LastName,
		AvatarURL:  row.AvatarURL,
		UserActive: row.UserActive,
		FamilyUUID: row.FamilyUUID,
		IPAddress:  formatIP(row.IPAddress),
		UserAgent:  row.UserAgent,
		DeviceID:   row.DeviceID,
		CreatedAt:  row.SessionCreatedAt,
		Access: domain.TokenState{
			UUID:      row.AccessUUID,
			Hash:      row.AccessHash,
			ExpiresAt: row.AccessExpiresAt,
			RevokedAt: row.AccessRevokedAt,
		},
		Refresh: domain.TokenState{
			UUID:      row.RefreshUUID,
			Hash:      row.RefreshHash,
			ExpiresAt: row.RefreshExpiresAt,
			RevokedAt: row.RefreshRevokedAt,
		},
		Permissions: append([]string{}, row.Permissions...),
	}
}

// parseIP converts a client IP string to the INET column type; unparsable input is stored as NULL.
func parseIP(ip *string) *netip.Addr {
	if ip == nil {
		return nil
	}

	addr, err := netip.ParseAddr(*ip)
	if err != nil {
		return nil
	}

	// Stored as IPv4 so f_auth_login_session matches it with plain IPv4 addresses.
	addr = addr.Unmap()

	return &addr
}

// wrap adds the failed operation to err; domain errors stay matchable with errors.Is/As.
var wrap = database.Wrapper("auth repository")

// formatIP converts an INET column value back to a string.
func formatIP(addr *netip.Addr) *string {
	if addr == nil {
		return nil
	}

	s := addr.String()

	return &s
}
