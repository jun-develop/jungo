package service

// =============================================================================
// TEST HELPERS (no test scenarios)
// =============================================================================
//
// File: fakes_test.go
// Purpose: The test environment for AuthService: an in-memory repository that mirrors the SQL
//          functions (f_auth_login_session, f_auth_refresh_session, ...), a controllable clock,
//          and newTestEnv, which wires a real sealer, hasher, session cache and login guard
//          around them. Only the database is faked.
// Used by: auth_service_test.go, password_reset_test.go
//
// =============================================================================

import (
	"context"
	"errors"
	"strings"
	"sync"
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

const testPassword = "correct-horse-battery"

// =============================================================================
// Fake repository
// =============================================================================

// fakeUser is a row of the fake users table.
type fakeUser struct {
	id           int64
	uuid         uuid.UUID
	email        string
	passwordHash string
	active       bool
	deleted      bool
}

// fakeToken is a row of the fake auth_tokens table.
type fakeToken struct {
	id        int64
	uuid      uuid.UUID
	userID    int64
	family    uuid.UUID
	typ       domain.TokenType
	hash      string
	expiresAt time.Time
	revokedAt *time.Time
	reason    *string
	ip, ua    *string
	deviceID  *string
	createdAt time.Time
	updatedAt *time.Time
}

// fakeRepository is an in-memory AuthRepository and UserProvider mirroring the SQL.
type fakeRepository struct {
	mu     sync.Mutex
	now    func() time.Time
	users  map[int64]*fakeUser
	tokens []*fakeToken
	resets []*fakeReset
	nextID int64
}

// fakeReset is a row of the fake password_reset_tokens table.
type fakeReset struct {
	userID    int64
	hash      string
	expiresAt time.Time
	used      bool
}

func newFakeRepository(now func() time.Time) *fakeRepository {
	return &fakeRepository{now: now, users: map[int64]*fakeUser{}}
}

func (r *fakeRepository) addUser(u *fakeUser) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.users[u.id] = u
}

// GetCredentialsByEmail implements domain.UserProvider.
func (r *fakeRepository) GetCredentialsByEmail(_ context.Context, email string) (*domain.Credentials, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, u := range r.users {
		if u.email == email && !u.deleted {
			return &domain.Credentials{UserID: u.id, UserUUID: u.uuid, Email: u.email, FirstName: "Jane", LastName: "Doe", PasswordHash: u.passwordHash, Active: u.active}, nil
		}
	}

	return nil, domain.ErrUserNotFound
}

// SetPasswordHash implements domain.UserProvider.
func (r *fakeRepository) SetPasswordHash(_ context.Context, userID int64, passwordHash string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok || u.deleted {
		return domain.ErrUserNotFound
	}

	u.passwordHash = passwordHash

	return nil
}

// WithTransaction runs fn directly: the fake has no rollback.
func (r *fakeRepository) WithTransaction(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

func (r *fakeRepository) CreatePasswordResetToken(_ context.Context, userID int64, hash string, expiresAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rt := range r.resets {
		if rt.userID == userID {
			rt.used = true
		}
	}

	r.resets = append(r.resets, &fakeReset{userID: userID, hash: hash, expiresAt: expiresAt})

	return nil
}

func (r *fakeRepository) ConsumePasswordResetToken(_ context.Context, hash string) (*domain.PasswordResetOwner, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rt := range r.resets {
		u := r.users[rt.userID]
		if rt.hash == hash && !rt.used && r.now().Before(rt.expiresAt) && u.active && !u.deleted {
			rt.used = true
			return &domain.PasswordResetOwner{UserID: u.id, UserUUID: u.uuid}, nil
		}
	}

	return nil, domain.ErrInvalidResetToken
}

func (r *fakeRepository) CreateLoginSession(_ context.Context, p domain.NewSessionParams) (*domain.LoginSessionResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()

	var existing uuid.UUID
	for i := len(r.tokens) - 1; i >= 0; i-- {
		t := r.tokens[i]
		if t.userID != p.UserID || t.revokedAt != nil || !now.Before(t.expiresAt) {
			continue
		}

		byDevice := p.DeviceID != nil && t.deviceID != nil && *t.deviceID == *p.DeviceID
		byClient := p.DeviceID == nil && t.deviceID == nil && sameClient(t.ip, p.IPAddress) && eqPtr(t.ua, p.UserAgent)
		if byDevice || byClient {
			existing = t.family
			break
		}
	}

	if existing != uuid.Nil {
		r.revokeFamilyLocked(existing, "rotated")
		p.FamilyUUID = existing
		r.insertPairLocked(p)

		return &domain.LoginSessionResult{FamilyUUID: existing, StaleFamilyUUID: existing}, nil
	}

	r.insertPairLocked(p)

	return &domain.LoginSessionResult{FamilyUUID: p.FamilyUUID}, nil
}

// RefreshSession mirrors f_auth_refresh_session.
func (r *fakeRepository) RefreshSession(_ context.Context, hash string, p domain.NewSessionParams) (*domain.RefreshResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	t := r.byHash(hash)
	if t == nil || r.users[t.userID] == nil || r.users[t.userID].deleted {
		return &domain.RefreshResult{Status: domain.RefreshNotFound}, nil
	}

	u := r.users[t.userID]
	result := &domain.RefreshResult{FamilyUUID: t.family, UserUUID: u.uuid}

	switch {
	case t.typ != domain.TokenTypeRefresh:
		result.Status = domain.RefreshInvalidType
	case !u.active:
		result.Status = domain.RefreshUserInactive
	case exchanged(t) && t.revokedAt.After(r.now().Add(-reuseGrace)):
		result.Status = domain.RefreshRevoked
	case exchanged(t):
		r.revokeFamilyLocked(t.family, domain.RevokedReasonReuse)
		result.Status = domain.RefreshReused
	case t.revokedAt != nil:
		result.Status = domain.RefreshRevoked
	case !r.now().Before(t.expiresAt):
		result.Status = domain.RefreshExpired
	default:
		r.revokeFamilyLocked(t.family, domain.RevokedReasonRefresh)

		p.UserID, p.FamilyUUID = t.userID, t.family
		if p.DeviceID == nil {
			p.DeviceID = t.deviceID
		}

		r.insertPairLocked(p)
		result.Status = domain.RefreshRotated
	}

	return result, nil
}

func (r *fakeRepository) GetSessionByHash(_ context.Context, hash string) (*domain.Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	tok := r.byHash(hash)
	if tok == nil {
		return nil, domain.ErrTokenNotFound
	}

	u := r.users[tok.userID]
	if u == nil || u.deleted {
		return nil, domain.ErrTokenNotFound
	}

	var access, refresh *fakeToken
	created := tok.createdAt
	for _, t := range r.tokens {
		if t.family != tok.family {
			continue
		}

		if t.createdAt.Before(created) {
			created = t.createdAt
		}

		if t.typ == domain.TokenTypeAccess {
			access = t
		} else {
			refresh = t
		}
	}

	return &domain.Session{
		UserID: u.id, UserUUID: u.uuid, Email: u.email, UserActive: u.active,
		FamilyUUID: tok.family, IPAddress: refresh.ip, UserAgent: refresh.ua, DeviceID: refresh.deviceID,
		CreatedAt: created,
		Access:    domain.TokenState{UUID: access.uuid, Hash: access.hash, ExpiresAt: access.expiresAt, RevokedAt: access.revokedAt},
		Refresh:   domain.TokenState{UUID: refresh.uuid, Hash: refresh.hash, ExpiresAt: refresh.expiresAt, RevokedAt: refresh.revokedAt},
	}, nil
}

func (r *fakeRepository) GetTokenTypeByHash(_ context.Context, hash string) (domain.TokenType, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	t := r.byHash(hash)
	if t == nil || r.users[t.userID] == nil || r.users[t.userID].deleted {
		return 0, domain.ErrTokenNotFound
	}

	return t.typ, nil
}

func (r *fakeRepository) RevokeFamily(_ context.Context, family uuid.UUID, reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revokeFamilyLocked(family, reason)

	return nil
}

func (r *fakeRepository) RevokeFamilyByHash(_ context.Context, hash, reason string) (uuid.UUID, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	t := r.byHash(hash)
	if t == nil || r.users[t.userID] == nil || r.users[t.userID].deleted {
		return uuid.Nil, domain.ErrTokenNotFound
	}

	r.revokeFamilyLocked(t.family, reason)

	return t.family, nil
}

func (r *fakeRepository) RevokeAllByHash(ctx context.Context, hash, reason string) ([]uuid.UUID, error) {
	r.mu.Lock()
	t := r.byHash(hash)
	if t == nil || r.users[t.userID] == nil || r.users[t.userID].deleted {
		r.mu.Unlock()
		return nil, domain.ErrTokenNotFound
	}

	userUUID := r.users[t.userID].uuid
	r.mu.Unlock()

	return r.RevokeAllForUser(ctx, userUUID, reason)
}

func (r *fakeRepository) RevokeAllForUser(_ context.Context, userUUID uuid.UUID, reason string) ([]uuid.UUID, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	seen := map[uuid.UUID]bool{}
	var families []uuid.UUID
	for _, t := range r.tokens {
		if u := r.users[t.userID]; u != nil && u.uuid == userUUID && t.revokedAt == nil {
			if !seen[t.family] {
				seen[t.family] = true
				families = append(families, t.family)
			}
		}
	}

	for _, f := range families {
		r.revokeFamilyLocked(f, reason)
	}

	return families, nil
}

func (r *fakeRepository) ListActiveSessions(_ context.Context, userID int64) ([]*domain.SessionSummary, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var items []*domain.SessionSummary
	for _, t := range r.tokens {
		if t.userID == userID && t.typ == domain.TokenTypeRefresh && t.revokedAt == nil && r.now().Before(t.expiresAt) {
			items = append(items, &domain.SessionSummary{FamilyUUID: t.family, IPAddress: t.ip, UserAgent: t.ua, DeviceID: t.deviceID, CreatedAt: t.createdAt, ExpiresAt: t.expiresAt})
		}
	}

	return items, nil
}

func (r *fakeRepository) CleanupTokens(_ context.Context, before time.Time) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// A live family keeps its first row and its latest access token.
	now := r.now()
	live, first, lastAccess := map[uuid.UUID]bool{}, map[uuid.UUID]*fakeToken{}, map[uuid.UUID]*fakeToken{}
	for _, t := range r.tokens {
		if t.revokedAt == nil && now.Before(t.expiresAt) {
			live[t.family] = true
		}

		if first[t.family] == nil {
			first[t.family] = t
		}

		if t.typ == domain.TokenTypeAccess {
			lastAccess[t.family] = t
		}
	}

	kept := r.tokens[:0]
	var deleted int64
	for _, t := range r.tokens {
		// An exchanged refresh token stays until it would have expired, so its reuse is detected.
		protected := live[t.family] && (t == first[t.family] || t == lastAccess[t.family]) ||
			t.typ == domain.TokenTypeRefresh && exchanged(t) && now.Before(t.expiresAt)
		if !protected && (t.expiresAt.Before(before) || (t.revokedAt != nil && t.revokedAt.Before(before))) {
			deleted++
			continue
		}

		kept = append(kept, t)
	}

	r.tokens = kept

	return deleted, nil
}

// activeFamilyCount returns how many non-revoked tokens the family has.
func (r *fakeRepository) activeFamilyCount(family uuid.UUID) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	return len(r.activeInFamily(family))
}

func (r *fakeRepository) activeInFamily(family uuid.UUID) []*fakeToken {
	var active []*fakeToken
	for _, t := range r.tokens {
		if t.family == family && t.revokedAt == nil {
			active = append(active, t)
		}
	}

	return active
}

func (r *fakeRepository) revokeFamilyLocked(family uuid.UUID, reason string) {
	now := r.now()
	for _, t := range r.tokens {
		if t.family == family && t.revokedAt == nil {
			t.revokedAt, t.reason = &now, &reason
		}
	}
}

func (r *fakeRepository) insertPairLocked(p domain.NewSessionParams) {
	now := r.now()
	for _, tt := range []struct {
		typ     domain.TokenType
		hash    string
		expires time.Time
	}{
		{domain.TokenTypeAccess, p.AccessHash, p.AccessExpiresAt},
		{domain.TokenTypeRefresh, p.RefreshHash, p.RefreshExpiresAt},
	} {
		r.nextID++
		r.tokens = append(r.tokens, &fakeToken{
			id: r.nextID, uuid: uuid.New(), userID: p.UserID, family: p.FamilyUUID, typ: tt.typ,
			hash: tt.hash, expiresAt: tt.expires, ip: p.IPAddress, ua: p.UserAgent, deviceID: p.DeviceID, createdAt: now,
		})
	}
}

func (r *fakeRepository) byHash(hash string) *fakeToken {
	for _, t := range r.tokens {
		if t.hash == hash {
			return t
		}
	}

	return nil
}

// reuseGrace mirrors f_auth_refresh_session's v_reuse_grace.
const reuseGrace = 10 * time.Second

// exchanged reports whether t was retired by a refresh or a re-login (its reuse is suspicious).
func exchanged(t *fakeToken) bool {
	return t.reason != nil && (*t.reason == domain.RevokedReasonRefresh || *t.reason == "rotated")
}

// sameClient mirrors f_auth_login_session's IP match: an IPv6 address by its /64.
func sameClient(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}

	return security.ClientKey(*a) == security.ClientKey(*b)
}

func eqPtr(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}

	return *a == *b
}

// =============================================================================
// Test environment
// =============================================================================

// testClock is a controllable clock shared by the service and the fake repository.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// testEnv is an AuthService with real crypto, cache and guard; only the database is faked.
type testEnv struct {
	svc    *AuthService
	repo   *fakeRepository
	cache  *infrastructure.SessionCache
	clock  *testClock
	sealer security.TokenSealer
	user   *fakeUser
}

type envOption func(*config.Config, *AuthServiceParams)

func newTestEnv(t *testing.T, opts ...envOption) *testEnv {
	t.Helper()

	cfg := &config.Config{Environment: "test", Auth: config.AuthConfig{
		AccessTokenTTL:         15 * time.Minute,
		RefreshTokenTTL:        24 * time.Hour,
		SessionCacheTTL:        time.Minute,
		LoginMaxAttempts:       5,
		LoginBlockWindow:       15 * time.Minute,
		LoginBlacklistAttempts: 8,
		LoginBlacklistWindow:   24 * time.Hour,
	}}

	sealer, err := security.NewTokenSealer(security.Options{
		TokenHMACSecret:    []byte(strings.Repeat("h", security.MinHMACSecretSize)),
		TokenEncryptionKey: []byte(strings.Repeat("e", security.EncryptionKeySize)),
	})
	if err != nil {
		t.Fatalf("NewTokenSealer() error = %v", err)
	}

	hasher, err := security.NewPasswordHasher(security.Options{Password: security.PasswordOptions{Cost: bcrypt.MinCost}})
	if err != nil {
		t.Fatalf("NewPasswordHasher() error = %v", err)
	}

	hash, err := hasher.Hash(context.Background(), testPassword)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	clock := &testClock{now: time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)}
	repo := newFakeRepository(clock.Now)
	user := &fakeUser{id: 1, uuid: uuid.New(), email: "jane@example.com", passwordHash: hash, active: true}
	repo.addUser(user)

	lc := fxtest.NewLifecycle(t)
	p := AuthServiceParams{
		Lifecycle: lc,
		Config:    cfg,
		Repo:      repo,
		Users:     repo,
		Sealer:    sealer,
		Hasher:    hasher,
		Logger:    zap.NewNop(),
	}
	for _, opt := range opts {
		opt(cfg, &p)
	}

	s := cache.NewStore(cache.Options{Driver: cache.DriverMemory})
	sessionCache := infrastructure.NewSessionCache(s, cfg, zap.NewNop())
	p.Cache = sessionCache
	p.Guard = infrastructure.NewLoginGuard(infrastructure.LoginGuardParams{
		Lifecycle: lc,
		Cache:     s,
		Config:    cfg,
		Logger:    zap.NewNop(),
	})

	svc := NewAuthService(p)
	svc.now = clock.Now

	return &testEnv{svc: svc, repo: repo, cache: sessionCache, clock: clock, sealer: sealer, user: user}
}

func (e *testEnv) login(t *testing.T, meta domain.Metadata) *domain.TokenPair {
	t.Helper()
	pair, err := e.svc.Login(context.Background(), domain.LoginInput{Email: e.user.email, Password: testPassword, Metadata: meta})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	return pair
}

func (e *testEnv) authenticate(t *testing.T, token string) (*domain.Identity, error) {
	t.Helper()
	return e.svc.AuthenticateAccess(context.Background(), token)
}

func mustAuthenticate(t *testing.T, e *testEnv, token string) *domain.Identity {
	t.Helper()
	id, err := e.authenticate(t, token)
	if err != nil {
		t.Fatalf("AuthenticateAccess() error = %v, want nil", err)
	}

	return id
}

func wantErr(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("error = %v, want %v", got, want)
	}
}

var browser = domain.Metadata{IPAddress: "203.0.113.10", UserAgent: "Firefox"}

// errDB stands in for a database failure.
var errDB = errors.New("database unavailable")

// failingRepo wraps the fake repository; once err is set, the overridden repository calls return
// it, and once usersErr is set, GetCredentialsByEmail returns it.
type failingRepo struct {
	*fakeRepository
	err      error
	usersErr error
}

// withFailingRepo makes the service use a failingRepo as its repository and user provider, stored
// in *f so the test can arm it.
func withFailingRepo(f **failingRepo) envOption {
	return func(_ *config.Config, p *AuthServiceParams) {
		*f = &failingRepo{fakeRepository: p.Repo.(*fakeRepository)}
		p.Repo = *f
		p.Users = *f
	}
}

func (f *failingRepo) GetCredentialsByEmail(ctx context.Context, email string) (*domain.Credentials, error) {
	if f.usersErr != nil {
		return nil, f.usersErr
	}

	return f.fakeRepository.GetCredentialsByEmail(ctx, email)
}

func (f *failingRepo) RefreshSession(ctx context.Context, hash string, p domain.NewSessionParams) (*domain.RefreshResult, error) {
	if f.err != nil {
		return nil, f.err
	}

	return f.fakeRepository.RefreshSession(ctx, hash, p)
}

func (f *failingRepo) GetSessionByHash(ctx context.Context, hash string) (*domain.Session, error) {
	if f.err != nil {
		return nil, f.err
	}

	return f.fakeRepository.GetSessionByHash(ctx, hash)
}

func (f *failingRepo) RevokeFamily(ctx context.Context, family uuid.UUID, reason string) error {
	if f.err != nil {
		return f.err
	}

	return f.fakeRepository.RevokeFamily(ctx, family, reason)
}

func (f *failingRepo) RevokeFamilyByHash(ctx context.Context, hash, reason string) (uuid.UUID, error) {
	if f.err != nil {
		return uuid.Nil, f.err
	}

	return f.fakeRepository.RevokeFamilyByHash(ctx, hash, reason)
}

func (f *failingRepo) RevokeAllByHash(ctx context.Context, hash, reason string) ([]uuid.UUID, error) {
	if f.err != nil {
		return nil, f.err
	}

	return f.fakeRepository.RevokeAllByHash(ctx, hash, reason)
}

func (f *failingRepo) RevokeAllForUser(ctx context.Context, userUUID uuid.UUID, reason string) ([]uuid.UUID, error) {
	if f.err != nil {
		return nil, f.err
	}

	return f.fakeRepository.RevokeAllForUser(ctx, userUUID, reason)
}

func (f *failingRepo) ListActiveSessions(ctx context.Context, userID int64) ([]*domain.SessionSummary, error) {
	if f.err != nil {
		return nil, f.err
	}

	return f.fakeRepository.ListActiveSessions(ctx, userID)
}

func (f *failingRepo) CreatePasswordResetToken(ctx context.Context, userID int64, hash string, expiresAt time.Time) error {
	if f.err != nil {
		return f.err
	}

	return f.fakeRepository.CreatePasswordResetToken(ctx, userID, hash, expiresAt)
}
