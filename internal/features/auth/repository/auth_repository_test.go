package repository

// =============================================================================
// TEST CASE OVERVIEW
// =============================================================================
//
// File: auth_repository_test.go
// Purpose: Verify on a real database which sessions the per-user revoke queries end, and the user
//          a session is read with.
// Type: Integration (PostgreSQL at TEST_DATABASE_URL; skipped when unset; every test rolls back)
//
// Test functions: 3
// Total scenarios: 7
//
// #  Test Case                                                Scenario                           Expected Result
// 1  TestAuthRepository_RevokeUserSession_EndsOnlyOwnActive    Another of the user's sessions     Its tokens revoked with the reason; the others untouched
// 2  TestAuthRepository_RevokeUserSession_EndsOnlyOwnActive    Another user's session             ErrSessionNotFound; nothing revoked
// 3  TestAuthRepository_RevokeUserSession_EndsOnlyOwnActive    A session already revoked          ErrSessionNotFound
// 4  TestAuthRepository_RevokeUserSession_EndsOnlyOwnActive    An expired session                 ErrSessionNotFound; nothing revoked
// 5  TestAuthRepository_RevokeUserSession_EndsOnlyOwnActive    An unknown family                  ErrSessionNotFound
// 6  TestAuthRepository_RevokeOtherSessions_KeepsOne           Three sessions, keep one           The two others revoked and returned; kept and other user's untouched
// 7  TestAuthRepository_GetSessionByHash_ReadsTheUser          User with a phone number           Session carries the user's name and phone number
//
// =============================================================================

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"jungo/internal/database/primary"
	"jungo/internal/database/primary/dbtest"
	"jungo/internal/database/primary/sqlc"
	"jungo/internal/features/auth/domain"
)

// newUser creates a user and returns their id.
func newUser(t *testing.T, ctx context.Context, db *primary.DB, email string) int64 {
	t.Helper()

	u, err := db.Queries(ctx).CreateUser(ctx, sqlc.CreateUserParams{Email: email, PasswordHash: "x", FirstName: "A", LastName: "B", Status: 1})
	if err != nil {
		t.Fatalf("CreateUser(%s) error = %v", email, err)
	}

	return u.ID
}

// newSession stores an access and a refresh token of a new session of userID, valid until expires.
func newSession(t *testing.T, ctx context.Context, db *primary.DB, userID int64, expires time.Time) uuid.UUID {
	t.Helper()

	family := uuid.New()
	for _, tokenType := range []int16{1, 2} {
		_, err := db.Executor(ctx).Exec(ctx,
			`INSERT INTO auth_tokens (user_id, family_uuid, type, hash, expires_at) VALUES ($1, $2, $3, $4, $5)`,
			userID, family, tokenType, uuid.NewString()+uuid.NewString()[:28], expires,
		)
		if err != nil {
			t.Fatalf("insert token: %v", err)
		}
	}

	return family
}

// revokedReasons returns the revoked_reason of each token of family (nil for one still live).
func revokedReasons(t *testing.T, ctx context.Context, db *primary.DB, family uuid.UUID) []*string {
	t.Helper()

	rows, err := db.Executor(ctx).Query(ctx, `SELECT revoked_reason FROM auth_tokens WHERE family_uuid = $1 ORDER BY id`, family)
	if err != nil {
		t.Fatalf("read tokens: %v", err)
	}
	defer rows.Close()

	var reasons []*string
	for rows.Next() {
		var r *string
		if err := rows.Scan(&r); err != nil {
			t.Fatalf("scan token: %v", err)
		}

		reasons = append(reasons, r)
	}

	return reasons
}

// live reports whether no token of family is revoked.
func live(t *testing.T, ctx context.Context, db *primary.DB, family uuid.UUID) bool {
	t.Helper()

	return !slices.ContainsFunc(revokedReasons(t, ctx, db, family), func(r *string) bool { return r != nil })
}

func TestAuthRepository_RevokeUserSession_EndsOnlyOwnActive(t *testing.T) {
	db := dbtest.Open(t)
	repo := NewAuthRepository(db)

	dbtest.InRollback(t, db, func(ctx context.Context) {
		later := time.Now().Add(time.Hour)
		owner := newUser(t, ctx, db, "owner@auth-repo.test")
		other := newUser(t, ctx, db, "other@auth-repo.test")
		current := newSession(t, ctx, db, owner, later)
		second := newSession(t, ctx, db, owner, later)
		revoked := newSession(t, ctx, db, owner, later)
		expired := newSession(t, ctx, db, owner, time.Now().Add(-time.Hour))
		othersSession := newSession(t, ctx, db, other, later)
		if err := repo.RevokeFamily(ctx, revoked, domain.RevokedReasonLogout); err != nil {
			t.Fatalf("RevokeFamily() error = %v", err)
		}

		t.Run("another of the user's sessions", func(t *testing.T) {
			if err := repo.RevokeUserSession(ctx, owner, second, domain.RevokedReasonLogout); err != nil {
				t.Fatalf("RevokeUserSession() error = %v", err)
			}

			for _, r := range revokedReasons(t, ctx, db, second) {
				if r == nil || *r != domain.RevokedReasonLogout {
					t.Errorf("token of the revoked session has reason %v, want %q", r, domain.RevokedReasonLogout)
				}
			}

			if !live(t, ctx, db, current) {
				t.Error("current session revoked, want it untouched")
			}
		})

		tests := []struct {
			name   string
			family uuid.UUID
		}{
			{"another user's session", othersSession},
			{"a session already revoked", revoked},
			{"an expired session", expired},
			{"an unknown family", uuid.New()},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := repo.RevokeUserSession(ctx, owner, tt.family, domain.RevokedReasonLogout)

				if !errors.Is(err, domain.ErrSessionNotFound) {
					t.Fatalf("RevokeUserSession() error = %v, want %v", err, domain.ErrSessionNotFound)
				}
			})
		}

		if !live(t, ctx, db, othersSession) || !live(t, ctx, db, expired) {
			t.Error("another user's or an expired session was revoked, want both untouched")
		}
	})
}

func TestAuthRepository_RevokeOtherSessions_KeepsOne(t *testing.T) {
	db := dbtest.Open(t)
	repo := NewAuthRepository(db)

	dbtest.InRollback(t, db, func(ctx context.Context) {
		later := time.Now().Add(time.Hour)
		owner := newUser(t, ctx, db, "owner.others@auth-repo.test")
		other := newUser(t, ctx, db, "other.others@auth-repo.test")
		kept := newSession(t, ctx, db, owner, later)
		first := newSession(t, ctx, db, owner, later)
		second := newSession(t, ctx, db, owner, later)
		othersSession := newSession(t, ctx, db, other, later)

		families, err := repo.RevokeOtherSessions(ctx, owner, kept, domain.RevokedReasonPasswordChange)
		if err != nil {
			t.Fatalf("RevokeOtherSessions() error = %v", err)
		}

		cmp := func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) }
		want := []uuid.UUID{first, second}
		slices.SortFunc(want, cmp)
		slices.SortFunc(families, cmp)
		if !slices.Equal(families, want) {
			t.Errorf("revoked families = %v, want %v", families, want)
		}

		if live(t, ctx, db, first) || live(t, ctx, db, second) {
			t.Error("another session of the user is still live, want it revoked")
		}

		if !live(t, ctx, db, kept) || !live(t, ctx, db, othersSession) {
			t.Error("kept session or another user's session revoked, want both untouched")
		}
	})
}

func TestAuthRepository_GetSessionByHash_ReadsTheUser(t *testing.T) {
	db := dbtest.Open(t)
	repo := NewAuthRepository(db)

	dbtest.InRollback(t, db, func(ctx context.Context) {
		phone := "+84901234567"
		u, err := db.Queries(ctx).CreateUser(ctx, sqlc.CreateUserParams{
			Email: "phone@auth-repo.test", PasswordHash: "x", FirstName: "Ann", LastName: "Lee", PhoneNumber: &phone, Status: 1,
		})
		if err != nil {
			t.Fatalf("CreateUser() error = %v", err)
		}

		newSession(t, ctx, db, u.ID, time.Now().Add(time.Hour))
		var hash string
		if err := db.Executor(ctx).QueryRow(ctx, `SELECT hash FROM auth_tokens WHERE user_id = $1 AND type = 1`, u.ID).Scan(&hash); err != nil {
			t.Fatalf("read token hash: %v", err)
		}

		session, err := repo.GetSessionByHash(ctx, hash)
		if err != nil {
			t.Fatalf("GetSessionByHash() error = %v", err)
		}

		if session.FirstName != "Ann" || session.PhoneNumber == nil || *session.PhoneNumber != phone {
			t.Errorf("session user = %s, phone %v; want Ann, phone %s", session.FirstName, session.PhoneNumber, phone)
		}
	})
}
