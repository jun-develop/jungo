package service

// =============================================================================
// TEST HELPERS (no test scenarios)
// =============================================================================
//
// File: fakes_test.go
// Purpose: Func-field fakes of AuthRepository and UserProvider, shared fixtures, and
//          newTestService, which builds an AuthService around them with a real sealer, hasher,
//          session cache and login guard.
// Used by: auth_service_test.go, password_reset_test.go
//
// =============================================================================

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/fx/fxtest"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/jun-develop/junkit/cache"
	"github.com/jun-develop/junkit/security"

	"jungo/internal/config"
	"jungo/internal/features/auth/domain"
	"jungo/internal/features/auth/infrastructure"
)

// testPassword is the password of the user testCredentials returns.
const testPassword = "correct-horse-battery"

// testNow is the time the service clock reads in every test.
var testNow = time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)

// browser is the client metadata of an ordinary browser request.
var browser = domain.Metadata{IPAddress: "203.0.113.10", UserAgent: "Firefox"}

// errDB stands in for a database failure.
var errDB = errors.New("database unavailable")

// fakeAuthRepository is a test double for domain.AuthRepository. Calling a method whose Func is
// nil panics, so a test sets exactly the calls it expects. WithTransaction runs fn directly.
type fakeAuthRepository struct {
	CreateLoginSessionFunc        func(context.Context, domain.NewSessionParams) (*domain.LoginSessionResult, error)
	RefreshSessionFunc            func(context.Context, string, domain.NewSessionParams) (*domain.RefreshResult, error)
	GetSessionByHashFunc          func(ctx context.Context, hash string) (*domain.Session, error)
	GetTokenTypeByHashFunc        func(ctx context.Context, hash string) (domain.TokenType, error)
	RevokeFamilyFunc              func(ctx context.Context, familyUUID uuid.UUID, reason string) error
	RevokeFamilyByHashFunc        func(ctx context.Context, hash, reason string) (uuid.UUID, error)
	RevokeAllByHashFunc           func(ctx context.Context, hash, reason string) ([]uuid.UUID, error)
	RevokeAllForUserFunc          func(ctx context.Context, userUUID uuid.UUID, reason string) ([]uuid.UUID, error)
	ListActiveSessionsFunc        func(ctx context.Context, userID int64) ([]*domain.SessionSummary, error)
	CleanupTokensFunc             func(ctx context.Context, before time.Time) (int64, error)
	CreatePasswordResetTokenFunc  func(ctx context.Context, userID int64, hash string, expiresAt time.Time) error
	ConsumePasswordResetTokenFunc func(ctx context.Context, hash string) (*domain.PasswordResetOwner, error)
}

// WithTransaction runs fn directly: the fake has nothing to roll back.
func (f *fakeAuthRepository) WithTransaction(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

// CreateLoginSession calls CreateLoginSessionFunc.
func (f *fakeAuthRepository) CreateLoginSession(
	ctx context.Context, p domain.NewSessionParams,
) (*domain.LoginSessionResult, error) {
	return f.CreateLoginSessionFunc(ctx, p)
}

// RefreshSession calls RefreshSessionFunc.
func (f *fakeAuthRepository) RefreshSession(
	ctx context.Context, hash string, p domain.NewSessionParams,
) (*domain.RefreshResult, error) {
	return f.RefreshSessionFunc(ctx, hash, p)
}

// GetSessionByHash calls GetSessionByHashFunc.
func (f *fakeAuthRepository) GetSessionByHash(ctx context.Context, hash string) (*domain.Session, error) {
	return f.GetSessionByHashFunc(ctx, hash)
}

// GetTokenTypeByHash calls GetTokenTypeByHashFunc.
func (f *fakeAuthRepository) GetTokenTypeByHash(ctx context.Context, hash string) (domain.TokenType, error) {
	return f.GetTokenTypeByHashFunc(ctx, hash)
}

// RevokeFamily calls RevokeFamilyFunc.
func (f *fakeAuthRepository) RevokeFamily(ctx context.Context, familyUUID uuid.UUID, reason string) error {
	return f.RevokeFamilyFunc(ctx, familyUUID, reason)
}

// RevokeFamilyByHash calls RevokeFamilyByHashFunc.
func (f *fakeAuthRepository) RevokeFamilyByHash(ctx context.Context, hash, reason string) (uuid.UUID, error) {
	return f.RevokeFamilyByHashFunc(ctx, hash, reason)
}

// RevokeAllByHash calls RevokeAllByHashFunc.
func (f *fakeAuthRepository) RevokeAllByHash(ctx context.Context, hash, reason string) ([]uuid.UUID, error) {
	return f.RevokeAllByHashFunc(ctx, hash, reason)
}

// RevokeAllForUser calls RevokeAllForUserFunc.
func (f *fakeAuthRepository) RevokeAllForUser(
	ctx context.Context, userUUID uuid.UUID, reason string,
) ([]uuid.UUID, error) {
	return f.RevokeAllForUserFunc(ctx, userUUID, reason)
}

// ListActiveSessions calls ListActiveSessionsFunc.
func (f *fakeAuthRepository) ListActiveSessions(ctx context.Context, userID int64) ([]*domain.SessionSummary, error) {
	return f.ListActiveSessionsFunc(ctx, userID)
}

// CleanupTokens calls CleanupTokensFunc.
func (f *fakeAuthRepository) CleanupTokens(ctx context.Context, before time.Time) (int64, error) {
	return f.CleanupTokensFunc(ctx, before)
}

// CreatePasswordResetToken calls CreatePasswordResetTokenFunc.
func (f *fakeAuthRepository) CreatePasswordResetToken(
	ctx context.Context, userID int64, hash string, expiresAt time.Time,
) error {
	return f.CreatePasswordResetTokenFunc(ctx, userID, hash, expiresAt)
}

// ConsumePasswordResetToken calls ConsumePasswordResetTokenFunc.
func (f *fakeAuthRepository) ConsumePasswordResetToken(
	ctx context.Context, hash string,
) (*domain.PasswordResetOwner, error) {
	return f.ConsumePasswordResetTokenFunc(ctx, hash)
}

// fakeUserProvider is a test double for domain.UserProvider. Calling a method whose Func is nil
// panics.
type fakeUserProvider struct {
	GetCredentialsByEmailFunc func(ctx context.Context, email string) (*domain.Credentials, error)
	SetPasswordHashFunc       func(ctx context.Context, userID int64, passwordHash string) error
}

// GetCredentialsByEmail calls GetCredentialsByEmailFunc.
func (f *fakeUserProvider) GetCredentialsByEmail(ctx context.Context, email string) (*domain.Credentials, error) {
	return f.GetCredentialsByEmailFunc(ctx, email)
}

// SetPasswordHash calls SetPasswordHashFunc.
func (f *fakeUserProvider) SetPasswordHash(ctx context.Context, userID int64, passwordHash string) error {
	return f.SetPasswordHashFunc(ctx, userID, passwordHash)
}

// usersWith returns a UserProvider that knows only creds: any other email is ErrUserNotFound.
func usersWith(creds *domain.Credentials) *fakeUserProvider {
	return &fakeUserProvider{
		GetCredentialsByEmailFunc: func(_ context.Context, email string) (*domain.Credentials, error) {
			if email != creds.Email {
				return nil, domain.ErrUserNotFound
			}

			return creds, nil
		},
	}
}

// testCredentials returns an active user whose password is testPassword.
func testCredentials(t *testing.T) *domain.Credentials {
	t.Helper()

	hash, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword() error = %v", err)
	}

	return &domain.Credentials{
		UserID:       1,
		UserUUID:     uuid.New(),
		Email:        "jane@example.com",
		FirstName:    "Jane",
		LastName:     "Doe",
		PasswordHash: string(hash),
		Active:       true,
	}
}

// testConfig returns the auth settings every test service starts from.
func testConfig() *config.Config {
	return &config.Config{
		Environment: "test",
		Auth: config.AuthConfig{
			AccessTokenTTL:         15 * time.Minute,
			RefreshTokenTTL:        24 * time.Hour,
			SessionCacheTTL:        time.Minute,
			LoginMaxAttempts:       5,
			LoginBlockWindow:       15 * time.Minute,
			LoginBlacklistAttempts: 8,
			LoginBlacklistWindow:   24 * time.Hour,
		},
	}
}

// newTestService builds an AuthService from p. Dependencies p leaves nil get test defaults:
// testConfig(), a no-op logger, a real token sealer, a bcrypt hasher at the minimum cost, and a
// memory-backed session cache and login guard. The service clock reads testNow.
func newTestService(t *testing.T, p AuthServiceParams) *AuthService {
	t.Helper()

	if p.Config == nil {
		p.Config = testConfig()
	}

	if p.Logger == nil {
		p.Logger = zap.NewNop()
	}

	sealer, err := security.NewTokenSealer(security.Options{
		TokenHMACSecret:    []byte(strings.Repeat("h", security.MinHMACSecretSize)),
		TokenEncryptionKey: []byte(strings.Repeat("e", security.EncryptionKeySize)),
	})
	if err != nil {
		t.Fatalf("NewTokenSealer() error = %v", err)
	}

	hasher, err := security.NewPasswordHasher(security.Options{
		Password: security.PasswordOptions{Cost: bcrypt.MinCost},
	})
	if err != nil {
		t.Fatalf("NewPasswordHasher() error = %v", err)
	}

	store := cache.NewStore(cache.Options{Driver: cache.DriverMemory})
	p.Lifecycle = fxtest.NewLifecycle(t)
	p.Sealer = sealer
	p.Hasher = hasher
	p.Cache = infrastructure.NewSessionCache(store, p.Config, zap.NewNop())
	p.Guard = infrastructure.NewLoginGuard(infrastructure.LoginGuardParams{
		Lifecycle: p.Lifecycle,
		Cache:     store,
		Config:    p.Config,
		Logger:    zap.NewNop(),
	})

	svc := NewAuthService(p)
	svc.now = func() time.Time { return testNow }

	return svc
}

// sealedToken returns a token sealed by svc and the hash the repository stores for it.
func sealedToken(t *testing.T, svc *AuthService) (token, hash string) {
	t.Helper()

	raw := security.GenerateToken()
	token, err := svc.sealer.Seal(raw)
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}

	return token, security.HashToken(raw)
}

// liveSession returns the session of an active user whose access and refresh tokens are valid at
// testNow and stored under accessHash and refreshHash.
func liveSession(accessHash, refreshHash string) *domain.Session {
	return &domain.Session{
		UserID:     1,
		UserUUID:   uuid.New(),
		Email:      "jane@example.com",
		UserActive: true,
		FamilyUUID: uuid.New(),
		Access: domain.TokenState{
			UUID:      uuid.New(),
			Hash:      accessHash,
			ExpiresAt: testNow.Add(15 * time.Minute),
		},
		Refresh: domain.TokenState{
			UUID:      uuid.New(),
			Hash:      refreshHash,
			ExpiresAt: testNow.Add(24 * time.Hour),
		},
	}
}

// wantErr fails the test unless got matches want with errors.Is.
func wantErr(t *testing.T, got, want error) {
	t.Helper()

	if !errors.Is(got, want) {
		t.Fatalf("error = %v, want %v", got, want)
	}
}
