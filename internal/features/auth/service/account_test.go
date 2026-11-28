package service

// =============================================================================
// TEST CASE OVERVIEW
// =============================================================================
//
// File: account_test.go
// Purpose: Verify what AuthService decides when a logged-in user manages their own account: ending
//          their other sessions or one session, and changing their password.
// Type: Unit (Func-field repository; real sealer, hasher, session cache and login guard)
//
// Test functions: 8
// Total scenarios: 13
//
// #   Test Case                                                         Scenario                                Expected Result
// 1   TestAuthService_LogoutOthers_KeepsCurrentSession                  Two sessions, logged in on the first    Repository keeps the first; the second leaves the cache
// 2   TestAuthService_LogoutOthers_ReturnsRepositoryError               Revoke fails                            Returns the database error
// 3   TestAuthService_RevokeSession_RevokesOwnSession                   Another of the user's sessions          Revoked as a logout of that user; it leaves the cache
// 4   TestAuthService_RevokeSession_RevokesOwnSession                   The session of the request              Revoked as a logout; it leaves the cache
// 5   TestAuthService_RevokeSession_ReturnsNotFound                     Not one of the user's active sessions   ErrSessionNotFound
// 6   TestAuthService_ChangePassword_SavesHashAndKeepsCurrentSession    Right current password                  New hash saved; other sessions revoked; one change_password entry
// 7   TestAuthService_ChangePassword_RejectsInvalidRequests             Wrong current password                  ErrInvalidCurrentPassword; nothing saved
// 8   TestAuthService_ChangePassword_RejectsInvalidRequests             New password equals the current one     ErrNewPasswordSameAsCurrent; nothing saved
// 9   TestAuthService_ChangePassword_RejectsInvalidRequests             New password over 72 bytes              ErrPasswordTooLong; nothing saved
// 10  TestAuthService_ChangePassword_ThrottlesWrongPasswords            5 wrong passwords, then the right one   5 ErrInvalidCurrentPassword, then ErrTooManyAttempts
// 11  TestAuthService_ChangePassword_ReturnsTransactionErrors           Saving the hash fails                   Returns the database error
// 12  TestAuthService_ChangePassword_ReturnsTransactionErrors           Revoking the other sessions fails       Returns the database error
// 13  TestAuthService_ChangePassword_ReturnsTransactionErrors           The audit log fails                     Returns the database error
//
// =============================================================================

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"jungo/internal/common/auditlog"
	"jungo/internal/features/auth/domain"
)

// newPassword is the password ChangePassword sets in these tests.
const newPassword = "Another-Horse-42"

// fakeRecorder is an auditlog.Recorder that keeps every entry, or fails with err.
type fakeRecorder struct {
	entries []auditlog.Entry
	err     error
}

// Record keeps e, or returns f.err.
func (f *fakeRecorder) Record(_ context.Context, e auditlog.Entry) error {
	if f.err != nil {
		return f.err
	}

	f.entries = append(f.entries, e)

	return nil
}

// identityOf returns the identity of creds' user in session family.
func identityOf(creds *domain.Credentials, family uuid.UUID) *domain.Identity {
	return &domain.Identity{UserID: creds.UserID, UserUUID: creds.UserUUID, Email: creds.Email, FamilyUUID: family}
}

func TestAuthService_LogoutOthers_KeepsCurrentSession(t *testing.T) {
	repo := &fakeAuthRepository{}
	svc := newTestService(t, AuthServiceParams{Repo: repo})
	sessions := newCachedSessions(t, svc, repo, 2)
	current, other := sessions[0], sessions[1]
	identity := cacheSession(t, svc, current.token)
	cacheSession(t, svc, other.token)
	var gotUser int64
	var gotKeep uuid.UUID
	var gotReason string
	repo.RevokeOtherSessionsFunc = func(_ context.Context, userID int64, keep uuid.UUID, reason string) ([]uuid.UUID, error) {
		gotUser, gotKeep, gotReason = userID, keep, reason
		return []uuid.UUID{other.session.FamilyUUID}, nil
	}

	if err := svc.LogoutOthers(context.Background(), identity); err != nil {
		t.Fatalf("LogoutOthers() error = %v", err)
	}

	if gotUser != identity.UserID || gotKeep != identity.FamilyUUID || gotReason != domain.RevokedReasonLogout {
		t.Errorf("revoked others of user %d keeping %v (%q), want user %d keeping %v (%q)",
			gotUser, gotKeep, gotReason, identity.UserID, identity.FamilyUUID, domain.RevokedReasonLogout)
	}

	if !other.reloaded(t, svc) {
		t.Error("other session still served from the cache, want it invalidated")
	}

	if current.reloaded(t, svc) {
		t.Error("current session reloaded, want it to stay cached")
	}
}

func TestAuthService_LogoutOthers_ReturnsRepositoryError(t *testing.T) {
	repo := &fakeAuthRepository{
		RevokeOtherSessionsFunc: func(context.Context, int64, uuid.UUID, string) ([]uuid.UUID, error) { return nil, errDB },
	}
	svc := newTestService(t, AuthServiceParams{Repo: repo})

	err := svc.LogoutOthers(context.Background(), &domain.Identity{UserID: 1, FamilyUUID: uuid.New()})

	wantErr(t, err, errDB)
}

func TestAuthService_RevokeSession_RevokesOwnSession(t *testing.T) {
	tests := []struct {
		name    string
		current bool
	}{
		{"another of the user's sessions", false},
		{"the session of the request", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fakeAuthRepository{}
			svc := newTestService(t, AuthServiceParams{Repo: repo})
			sessions := newCachedSessions(t, svc, repo, 2)
			identity := cacheSession(t, svc, sessions[0].token)
			target := sessions[1]
			if tt.current {
				target = sessions[0]
			}

			cacheSession(t, svc, target.token)
			var gotUser int64
			var gotFamily uuid.UUID
			var gotReason string
			repo.RevokeUserSessionFunc = func(_ context.Context, userID int64, family uuid.UUID, reason string) error {
				gotUser, gotFamily, gotReason = userID, family, reason
				return nil
			}

			if err := svc.RevokeSession(context.Background(), identity, target.session.FamilyUUID); err != nil {
				t.Fatalf("RevokeSession() error = %v", err)
			}

			if gotUser != identity.UserID || gotFamily != target.session.FamilyUUID || gotReason != domain.RevokedReasonLogout {
				t.Errorf("revoked %v of user %d (%q), want %v of user %d (%q)",
					gotFamily, gotUser, gotReason, target.session.FamilyUUID, identity.UserID, domain.RevokedReasonLogout)
			}

			if !target.reloaded(t, svc) {
				t.Error("revoked session still served from the cache, want it invalidated")
			}
		})
	}
}

func TestAuthService_RevokeSession_ReturnsNotFound(t *testing.T) {
	repo := &fakeAuthRepository{
		RevokeUserSessionFunc: func(context.Context, int64, uuid.UUID, string) error { return domain.ErrSessionNotFound },
	}
	svc := newTestService(t, AuthServiceParams{Repo: repo})

	err := svc.RevokeSession(context.Background(), &domain.Identity{UserID: 1, FamilyUUID: uuid.New()}, uuid.New())

	wantErr(t, err, domain.ErrSessionNotFound)
}

func TestAuthService_ChangePassword_SavesHashAndKeepsCurrentSession(t *testing.T) {
	creds := testCredentials(t)
	identity := identityOf(creds, uuid.New())
	users := usersWith(creds)
	var gotUser int64
	var gotHash string
	users.SetPasswordHashFunc = func(_ context.Context, userID int64, hash string) error {
		gotUser, gotHash = userID, hash
		return nil
	}

	var gotKeep uuid.UUID
	var gotReason string
	repo := &fakeAuthRepository{
		RevokeOtherSessionsFunc: func(_ context.Context, _ int64, keep uuid.UUID, reason string) ([]uuid.UUID, error) {
			gotKeep, gotReason = keep, reason
			return nil, nil
		},
	}
	audit := &fakeRecorder{}
	svc := newTestService(t, AuthServiceParams{Repo: repo, Users: users, Audit: audit})

	err := svc.ChangePassword(context.Background(), identity, domain.ChangePasswordInput{
		CurrentPassword: testPassword, NewPassword: newPassword, Metadata: browser,
	})

	if err != nil {
		t.Fatalf("ChangePassword() error = %v", err)
	}

	if gotUser != creds.UserID {
		t.Errorf("saved hash of user %d, want %d", gotUser, creds.UserID)
	}

	if bcrypt.CompareHashAndPassword([]byte(gotHash), []byte(newPassword)) != nil {
		t.Error("saved hash is not a bcrypt hash of the new password")
	}

	if gotKeep != identity.FamilyUUID || gotReason != domain.RevokedReasonPasswordChange {
		t.Errorf("revoked other sessions keeping %v (%q), want keeping %v (%q)", gotKeep, gotReason, identity.FamilyUUID, domain.RevokedReasonPasswordChange)
	}

	if len(audit.entries) != 1 {
		t.Fatalf("audit entries = %+v, want one", audit.entries)
	}

	if e := audit.entries[0]; e.Action != "change_password" || e.EntityType != "users" || e.EntityID != creds.UserUUID.String() || e.Before != nil || e.After != nil {
		t.Errorf("audit entry = %+v, want a change_password of user %v without values", e, creds.UserUUID)
	}
}

func TestAuthService_ChangePassword_RejectsInvalidRequests(t *testing.T) {
	tests := []struct {
		name    string
		current string
		next    string
		want    error
	}{
		{"wrong current password", "wrong-password", newPassword, domain.ErrInvalidCurrentPassword},
		{"new password equals the current one", testPassword, testPassword, domain.ErrNewPasswordSameAsCurrent},
		{"new password over 72 bytes", testPassword, strings.Repeat("é", 37), domain.ErrPasswordTooLong},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds := testCredentials(t)
			// SetPasswordHashFunc and the repository's Funcs are nil: saving anything would panic.
			svc := newTestService(t, AuthServiceParams{Repo: &fakeAuthRepository{}, Users: usersWith(creds)})

			err := svc.ChangePassword(context.Background(), identityOf(creds, uuid.New()), domain.ChangePasswordInput{
				CurrentPassword: tt.current, NewPassword: tt.next, Metadata: browser,
			})

			wantErr(t, err, tt.want)
		})
	}
}

func TestAuthService_ChangePassword_ThrottlesWrongPasswords(t *testing.T) {
	creds := testCredentials(t)
	svc := newTestService(t, AuthServiceParams{Repo: &fakeAuthRepository{}, Users: usersWith(creds)})
	identity := identityOf(creds, uuid.New())
	change := func(current string) error {
		return svc.ChangePassword(context.Background(), identity, domain.ChangePasswordInput{
			CurrentPassword: current, NewPassword: newPassword, Metadata: browser,
		})
	}

	for i := range 5 {
		if err := change("wrong-password"); !errors.Is(err, domain.ErrInvalidCurrentPassword) {
			t.Fatalf("attempt %d: error = %v, want %v", i+1, err, domain.ErrInvalidCurrentPassword)
		}
	}

	wantErr(t, change(testPassword), domain.ErrTooManyAttempts)
}

func TestAuthService_ChangePassword_ReturnsTransactionErrors(t *testing.T) {
	tests := []struct {
		name      string
		saveErr   error
		revokeErr error
		auditErr  error
	}{
		{name: "saving the hash fails", saveErr: errDB},
		{name: "revoking the other sessions fails", revokeErr: errDB},
		{name: "the audit log fails", auditErr: errDB},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds := testCredentials(t)
			users := usersWith(creds)
			users.SetPasswordHashFunc = func(context.Context, int64, string) error { return tt.saveErr }
			repo := &fakeAuthRepository{
				RevokeOtherSessionsFunc: func(context.Context, int64, uuid.UUID, string) ([]uuid.UUID, error) { return nil, tt.revokeErr },
			}
			svc := newTestService(t, AuthServiceParams{Repo: repo, Users: users, Audit: &fakeRecorder{err: tt.auditErr}})

			err := svc.ChangePassword(context.Background(), identityOf(creds, uuid.New()), domain.ChangePasswordInput{
				CurrentPassword: testPassword, NewPassword: newPassword, Metadata: browser,
			})

			wantErr(t, err, errDB)
		})
	}
}
