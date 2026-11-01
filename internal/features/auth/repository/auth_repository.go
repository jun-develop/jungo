package repository

import (
	"context"
	"net/netip"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/jun-develop/junkit/database"

	"jungo/internal/database/primary"
	"jungo/internal/database/primary/sqlc"
	"jungo/internal/features/auth/domain"
	userdomain "jungo/internal/features/user/domain"
)

// AuthRepository implements domain.AuthRepository.
type AuthRepository struct {
	db *primary.DB
}

// NewAuthRepository creates an AuthRepository backed by db.
func NewAuthRepository(db *primary.DB) *AuthRepository {
	return &AuthRepository{db: db}
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
		return nil, err
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
		return nil, err
	}

	return &domain.RefreshResult{Status: row.Status, FamilyUUID: row.FamilyUUID, UserUUID: row.UserUUID}, nil
}

// GetSessionByHash implements domain.AuthRepository.
func (r *AuthRepository) GetSessionByHash(ctx context.Context, hash string) (*domain.Session, error) {
	row, err := r.db.Queries(ctx).GetSessionByHash(ctx, hash)
	if err != nil {
		return nil, database.MatchNotFound(err, domain.ErrTokenNotFound)
	}

	return mapSession(row), nil
}

// GetTokenByHash implements domain.AuthRepository.
func (r *AuthRepository) GetTokenByHash(ctx context.Context, hash string) (*domain.StoredToken, error) {
	row, err := r.db.Queries(ctx).GetTokenByHash(ctx, hash)
	if err != nil {
		return nil, database.MatchNotFound(err, domain.ErrTokenNotFound)
	}

	return &domain.StoredToken{
		UUID:          row.UUID,
		UserID:        row.UserID,
		UserUUID:      row.UserUUID,
		UserActive:    row.UserStatus == userdomain.UserStatusActive,
		FamilyUUID:    row.FamilyUUID,
		Type:          domain.TokenType(row.Type),
		DeviceID:      row.DeviceID,
		ExpiresAt:     row.ExpiresAt,
		RevokedAt:     row.RevokedAt,
		RevokedReason: row.RevokedReason,
	}, nil
}

// RevokeFamily implements domain.AuthRepository.
func (r *AuthRepository) RevokeFamily(ctx context.Context, familyUUID uuid.UUID, reason string) error {
	_, err := r.db.Queries(ctx).RevokeFamily(ctx, sqlc.RevokeFamilyParams{
		FamilyUUID: familyUUID,
		Reason:     &reason,
	})
	return err
}

// RevokeFamilyByHash implements domain.AuthRepository; it revokes the session the token belongs to
// and returns its family.
func (r *AuthRepository) RevokeFamilyByHash(ctx context.Context, hash, reason string) (uuid.UUID, error) {
	family, err := r.db.Queries(ctx).RevokeFamilyByHash(ctx, sqlc.RevokeFamilyByHashParams{
		Hash:   hash,
		Reason: &reason,
	})
	if err != nil {
		return uuid.Nil, database.MatchNotFound(err, domain.ErrTokenNotFound)
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
		return nil, database.MatchNotFound(err, domain.ErrTokenNotFound)
	}

	return families, nil
}

// RevokeAllForUser implements domain.AuthRepository; it returns the affected families.
func (r *AuthRepository) RevokeAllForUser(ctx context.Context, userUUID uuid.UUID, reason string) ([]uuid.UUID, error) {
	families, err := r.db.Queries(ctx).RevokeAllForUser(ctx, sqlc.RevokeAllForUserParams{
		UserUUID: userUUID,
		Reason:   &reason,
	})
	if err != nil {
		return nil, err
	}

	slices.SortFunc(families, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })

	return slices.Compact(families), nil
}

// ListActiveSessions implements domain.AuthRepository.
func (r *AuthRepository) ListActiveSessions(ctx context.Context, userID int64) ([]*domain.SessionSummary, error) {
	rows, err := r.db.Queries(ctx).ListActiveSessions(ctx, userID)
	if err != nil {
		return nil, err
	}

	items := make([]*domain.SessionSummary, len(rows))
	for i, row := range rows {
		items[i] = &domain.SessionSummary{
			FamilyUUID: row.FamilyUUID,
			IPAddress:  formatIP(row.IPAddress),
			UserAgent:  row.UserAgent,
			DeviceID:   row.DeviceID,
			CreatedAt:  row.CreatedAt,
			UpdatedAt:  row.UpdatedAt,
			ExpiresAt:  row.ExpiresAt,
		}
	}

	return items, nil
}

// CleanupTokens implements domain.AuthRepository.
func (r *AuthRepository) CleanupTokens(ctx context.Context, before time.Time) (int64, error) {
	return r.db.Queries(ctx).CleanupTokens(ctx, before)
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
		UserActive: row.UserStatus == userdomain.UserStatusActive,
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

// formatIP converts an INET column value back to a string.
func formatIP(addr *netip.Addr) *string {
	if addr == nil {
		return nil
	}

	s := addr.String()

	return &s
}
