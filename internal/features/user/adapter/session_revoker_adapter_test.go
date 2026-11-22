package adapter

// =============================================================================
// TEST CASE OVERVIEW
// =============================================================================
//
// File: session_revoker_adapter_test.go
// Purpose: Verify that the user feature revokes and invalidates sessions through auth correctly.
// Type: Unit (Func-field fakes)
//
// Test functions: 2
// Total scenarios: 3
//
// #  Test Case                                                    Scenario        Expected Result
// 1  TestSessionRevokerAdapter_RevokeUserSessions_RevokesAll      User disabled   Every session of the user revoked as user_disabled
// 2  TestSessionRevokerAdapter_RevokeUserSessions_RevokesAll      Database fails  Returns the database error
// 3  TestSessionRevokerAdapter_InvalidateUserSessions_DropsCache  Any user        The user's cached sessions are dropped
//
// =============================================================================

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/google/uuid"

	authdomain "jungo/internal/features/auth/domain"
)

// errDB stands in for a failing database.
var errDB = errors.New("fake database: connection lost")

// fakeAuthRepository is an authdomain.AuthRepository that answers RevokeAllForUser through
// RevokeAllForUserFunc. Its other methods are the nil embedded interface, so calling one panics.
type fakeAuthRepository struct {
	authdomain.AuthRepository

	RevokeAllForUserFunc func(ctx context.Context, userUUID uuid.UUID, reason string) ([]uuid.UUID, error)
}

// RevokeAllForUser answers through RevokeAllForUserFunc.
func (f *fakeAuthRepository) RevokeAllForUser(
	ctx context.Context,
	userUUID uuid.UUID,
	reason string,
) ([]uuid.UUID, error) {
	return f.RevokeAllForUserFunc(ctx, userUUID, reason)
}

// fakeSessionCache is an authdomain.SessionCache that records the users it invalidates. Its other
// methods are the nil embedded interface, so calling one panics.
type fakeSessionCache struct {
	authdomain.SessionCache

	invalidatedUsers []uuid.UUID
}

// InvalidateUser records userUUID.
func (c *fakeSessionCache) InvalidateUser(_ context.Context, userUUID uuid.UUID) {
	c.invalidatedUsers = append(c.invalidatedUsers, userUUID)
}

func TestSessionRevokerAdapter_RevokeUserSessions_RevokesAll(t *testing.T) {
	userUUID := uuid.New()

	t.Run("user disabled", func(t *testing.T) {
		var gotUser uuid.UUID
		var gotReason string
		repo := &fakeAuthRepository{
			RevokeAllForUserFunc: func(_ context.Context, uid uuid.UUID, reason string) ([]uuid.UUID, error) {
				gotUser, gotReason = uid, reason
				return nil, nil
			},
		}

		err := NewSessionRevokerAdapter(repo, &fakeSessionCache{}).RevokeUserSessions(context.Background(), userUUID)

		if err != nil {
			t.Fatalf("RevokeUserSessions() error = %v", err)
		}

		if gotUser != userUUID {
			t.Errorf("revoked sessions of user %s, want %s", gotUser, userUUID)
		}

		if gotReason != authdomain.RevokedReasonUserDisabled {
			t.Errorf("revoke reason = %q, want %q", gotReason, authdomain.RevokedReasonUserDisabled)
		}
	})

	t.Run("database fails", func(t *testing.T) {
		repo := &fakeAuthRepository{
			RevokeAllForUserFunc: func(context.Context, uuid.UUID, string) ([]uuid.UUID, error) {
				return nil, errDB
			},
		}

		err := NewSessionRevokerAdapter(repo, &fakeSessionCache{}).RevokeUserSessions(context.Background(), userUUID)

		if !errors.Is(err, errDB) {
			t.Errorf("RevokeUserSessions() error = %v, want %v", err, errDB)
		}
	})
}

func TestSessionRevokerAdapter_InvalidateUserSessions_DropsCache(t *testing.T) {
	userUUID := uuid.New()
	cache := &fakeSessionCache{}

	NewSessionRevokerAdapter(&fakeAuthRepository{}, cache).InvalidateUserSessions(context.Background(), userUUID)

	if !slices.Equal(cache.invalidatedUsers, []uuid.UUID{userUUID}) {
		t.Errorf("invalidated users = %v, want [%s]", cache.invalidatedUsers, userUUID)
	}
}
