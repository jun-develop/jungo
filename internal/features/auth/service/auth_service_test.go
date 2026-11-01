package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/jun-develop/junkit/cache"
	"github.com/jun-develop/junkit/security"

	"jungo/internal/config"
	"jungo/internal/features/auth/adapter"
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
	nextID int64
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
			return &domain.Credentials{UserID: u.id, UserUUID: u.uuid, PasswordHash: u.passwordHash, Active: u.active}, nil
		}
	}

	return nil, domain.ErrUserNotFound
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
		active := r.activeInFamily(existing)
		if len(active) == 2 {
			for _, t := range active {
				t.uuid = uuid.New()
				t.hash, t.expiresAt = p.AccessHash, p.AccessExpiresAt
				if t.typ == domain.TokenTypeRefresh {
					t.hash, t.expiresAt = p.RefreshHash, p.RefreshExpiresAt
				}

				t.ip, t.ua, t.updatedAt = p.IPAddress, p.UserAgent, &now
			}

			return &domain.LoginSessionResult{FamilyUUID: existing, StaleFamilyUUID: existing}, nil
		}

		r.revokeFamilyLocked(existing, "rotated")
	}

	r.insertPairLocked(p)

	return &domain.LoginSessionResult{FamilyUUID: p.FamilyUUID, StaleFamilyUUID: existing}, nil
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
	case t.reason != nil && *t.reason == domain.RevokedReasonRefresh:
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

func (r *fakeRepository) GetTokenByHash(_ context.Context, hash string) (*domain.StoredToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	t := r.byHash(hash)
	if t == nil || r.users[t.userID] == nil || r.users[t.userID].deleted {
		return nil, domain.ErrTokenNotFound
	}

	u := r.users[t.userID]

	return &domain.StoredToken{
		UUID: t.uuid, UserID: t.userID, UserUUID: u.uuid, UserActive: u.active, FamilyUUID: t.family,
		Type: t.typ, DeviceID: t.deviceID, ExpiresAt: t.expiresAt, RevokedAt: t.revokedAt, RevokedReason: t.reason,
	}, nil
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
		protected := live[t.family] && (t == first[t.family] || t == lastAccess[t.family])
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

type envOption func(*config.Config, *Params)

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
		LoginEmailMaxAttempts:  10,
	}}

	sealer, err := security.NewTokenSealer(security.Options{
		TokenHMACSecret:    []byte(strings.Repeat("h", security.MinHMACSecretSize)),
		TokenEncryptionKey: []byte(strings.Repeat("e", security.EncryptionKeySize)),
	})
	if err != nil {
		t.Fatal(err)
	}

	hasher, err := security.NewPasswordHasher(security.Options{Password: security.PasswordOptions{Cost: bcrypt.MinCost}})
	if err != nil {
		t.Fatal(err)
	}

	hash, _ := hasher.Hash(testPassword)

	clock := &testClock{now: time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)}
	repo := newFakeRepository(clock.Now)
	user := &fakeUser{id: 1, uuid: uuid.New(), email: "jane@example.com", passwordHash: hash, active: true}
	repo.addUser(user)

	p := Params{
		Config: cfg,
		Repo:   repo,
		Users:  repo,
		Sealer: sealer,
		Hasher: hasher,
		Logger: zap.NewNop(),
	}
	for _, opt := range opts {
		opt(cfg, &p)
	}

	sessionCache := infrastructure.NewSessionCache(cache.Options{Driver: cache.DriverMemory}, cfg, zap.NewNop())
	p.Cache = sessionCache
	p.Guard = infrastructure.NewLoginGuard(infrastructure.LoginGuardParams{
		CacheOptions: cache.Options{Driver: cache.DriverMemory},
		Config:       cfg,
		Logger:       zap.NewNop(),
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

// =============================================================================
// Login
// =============================================================================

func TestLogin_IssuesSealedTokensAndStoresOnlyHashes(t *testing.T) {
	e := newTestEnv(t)
	pair := e.login(t, browser)

	for _, tok := range []string{pair.AccessToken, pair.RefreshToken} {
		raw, err := e.sealer.Open(tok)
		if err != nil {
			t.Fatalf("issued token does not open: %v", err)
		}

		stored := e.repo.byHash(security.HashToken(raw))
		if stored == nil {
			t.Fatal("hash of issued token not stored")
		}

		if stored.hash == raw || strings.Contains(tok, raw) {
			t.Error("raw token leaked into storage or sealed token")
		}
	}

	id := mustAuthenticate(t, e, pair.AccessToken)
	if id.UserUUID != e.user.uuid || id.Session == nil {
		t.Errorf("identity = %+v, want user %v with session", id, e.user.uuid)
	}
}

func TestLogin_InvalidCredentialsLookTheSame(t *testing.T) {
	e := newTestEnv(t)

	_, errWrongPassword := e.svc.Login(context.Background(), domain.LoginInput{Email: e.user.email, Password: "nope", Metadata: browser})
	_, errUnknownEmail := e.svc.Login(context.Background(), domain.LoginInput{Email: "ghost@example.com", Password: "nope", Metadata: domain.Metadata{IPAddress: "198.51.100.1"}})

	wantErr(t, errWrongPassword, domain.ErrInvalidCredentials)
	wantErr(t, errUnknownEmail, domain.ErrInvalidCredentials)
}

func TestLogin_InactiveUserOnlyAfterCorrectPassword(t *testing.T) {
	e := newTestEnv(t)
	e.user.active = false

	_, err := e.svc.Login(context.Background(), domain.LoginInput{Email: e.user.email, Password: "nope", Metadata: browser})
	wantErr(t, err, domain.ErrInvalidCredentials)

	_, err = e.svc.Login(context.Background(), domain.LoginInput{Email: e.user.email, Password: testPassword, Metadata: browser})
	wantErr(t, err, domain.ErrUserInactive)
}

func TestLogin_SameDeviceDifferentIPRotatesSession(t *testing.T) {
	e := newTestEnv(t)
	first := e.login(t, domain.Metadata{IPAddress: "203.0.113.10", UserAgent: "App", DeviceID: "phone-1"})
	firstID := mustAuthenticate(t, e, first.AccessToken) // cached

	second := e.login(t, domain.Metadata{IPAddress: "198.51.100.7", UserAgent: "App", DeviceID: "phone-1"})
	secondID := mustAuthenticate(t, e, second.AccessToken)

	if secondID.FamilyUUID != firstID.FamilyUUID {
		t.Error("login from the same device created a new session instead of rotating")
	}

	if _, err := e.authenticate(t, first.AccessToken); err == nil {
		t.Error("access token from before the rotation still authenticates")
	}
}

func TestLogin_WithoutDeviceMatchesByIPAndUserAgent(t *testing.T) {
	e := newTestEnv(t)
	first := e.login(t, browser)
	firstID := mustAuthenticate(t, e, first.AccessToken)

	t.Run("same IP and User-Agent rotates", func(t *testing.T) {
		again := e.login(t, browser)
		if id := mustAuthenticate(t, e, again.AccessToken); id.FamilyUUID != firstID.FamilyUUID {
			t.Error("expected the same session family")
		}
	})

	t.Run("same IP, different User-Agent creates a separate session", func(t *testing.T) {
		chromeMeta := domain.Metadata{IPAddress: browser.IPAddress, UserAgent: "Chrome"}
		chrome := e.login(t, chromeMeta)
		chromeID := mustAuthenticate(t, e, chrome.AccessToken)
		if chromeID.FamilyUUID == firstID.FamilyUUID {
			t.Error("a different browser behind the same IP rotated the other browser's session")
		}

		if e.repo.activeFamilyCount(firstID.FamilyUUID) != 2 {
			t.Error("the Firefox session was revoked by the Chrome login")
		}
	})
}

func TestLogin_WithoutDeviceMatchesIPv6BySlash64(t *testing.T) {
	e := newTestEnv(t)
	meta := func(ip string) domain.Metadata { return domain.Metadata{IPAddress: ip, UserAgent: "Firefox"} }
	first := mustAuthenticate(t, e, e.login(t, meta("2001:db8:1:2::1")).AccessToken)

	if id := mustAuthenticate(t, e, e.login(t, meta("2001:db8:1:2::99")).AccessToken); id.FamilyUUID != first.FamilyUUID {
		t.Error("a new address in the same /64 created a new session, want the same one rotated")
	}

	if id := mustAuthenticate(t, e, e.login(t, meta("2001:db8:1:3::1")).AccessToken); id.FamilyUUID == first.FamilyUUID {
		t.Error("an address in another /64 rotated the session, want a new one")
	}
}

func TestLogin_DifferentDeviceCreatesNewSession(t *testing.T) {
	e := newTestEnv(t)
	a := mustAuthenticate(t, e, e.login(t, domain.Metadata{IPAddress: "203.0.113.10", DeviceID: "phone-1"}).AccessToken)
	b := mustAuthenticate(t, e, e.login(t, domain.Metadata{IPAddress: "203.0.113.10", DeviceID: "laptop-1"}).AccessToken)
	if a.FamilyUUID == b.FamilyUUID {
		t.Error("two devices share one session")
	}
}

// =============================================================================
// Brute-force protection
// =============================================================================

func TestLogin_BruteForceWarnsThenBlocks(t *testing.T) {
	e := newTestEnv(t)
	bad := domain.LoginInput{Email: e.user.email, Password: "wrong", Metadata: browser}

	var errs []error
	for range 5 {
		_, err := e.svc.Login(context.Background(), bad)
		errs = append(errs, err)
	}

	wantErr(t, errs[0], domain.ErrInvalidCredentials)
	wantErr(t, errs[2], domain.ErrInvalidCredentialsWarning) // 2 attempts left
	wantErr(t, errs[4], domain.ErrInvalidCredentialsWarning)

	// Blocked now, even with the right password.
	_, err := e.svc.Login(context.Background(), domain.LoginInput{Email: e.user.email, Password: testPassword, Metadata: browser})
	wantErr(t, err, domain.ErrTooManyAttempts)
}

func TestLogin_ConcurrentAttemptsCannotExceedLimit(t *testing.T) {
	e := newTestEnv(t)
	bad := domain.LoginInput{Email: e.user.email, Password: "wrong", Metadata: browser}

	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		passed int
	)
	for range 20 {
		wg.Go(func() {
			_, err := e.svc.Login(context.Background(), bad)
			if !errors.Is(err, domain.ErrTooManyAttempts) {
				mu.Lock()
				passed++
				mu.Unlock()
			}
		})
	}

	wg.Wait()

	if passed != 5 {
		t.Errorf("%d concurrent attempts reached the password check, want exactly LoginMaxAttempts (5)", passed)
	}
}

func TestLogin_SuccessClearsShortWindow(t *testing.T) {
	e := newTestEnv(t)
	bad := domain.LoginInput{Email: e.user.email, Password: "wrong", Metadata: browser}
	for range 4 {
		_, _ = e.svc.Login(context.Background(), bad)
	}

	e.login(t, browser)

	_, err := e.svc.Login(context.Background(), bad)
	wantErr(t, err, domain.ErrInvalidCredentials) // counter restarted: no warning yet
}

func TestLogin_PerEmailLimitAcrossIPs(t *testing.T) {
	e := newTestEnv(t)
	for i := range 10 {
		ip := "198.51.100." + string(rune('0'+i))
		_, _ = e.svc.Login(context.Background(), domain.LoginInput{Email: e.user.email, Password: "wrong", Metadata: domain.Metadata{IPAddress: ip}})
	}

	_, err := e.svc.Login(context.Background(), domain.LoginInput{Email: e.user.email, Password: testPassword, Metadata: domain.Metadata{IPAddress: "192.0.2.99"}})
	wantErr(t, err, domain.ErrTooManyAttempts)
}

// =============================================================================
// Recaptcha (optional dependency)
// =============================================================================

type fakeVerifier struct{ err error }

func (f fakeVerifier) Verify(context.Context, string, string) error { return f.err }

func TestLogin_RecaptchaIsOptional(t *testing.T) {
	enable := func(cfg *config.Config, _ *Params) { cfg.Auth.RecaptchaOnLogin = true }

	t.Run("enabled but no verifier wired: login works", func(t *testing.T) {
		e := newTestEnv(t, enable)
		e.login(t, browser)
	})

	t.Run("enabled with a failing verifier: rejected", func(t *testing.T) {
		e := newTestEnv(t, enable, func(_ *config.Config, p *Params) { p.Recaptcha = fakeVerifier{err: errors.New("bad")} })
		_, err := e.svc.Login(context.Background(), domain.LoginInput{Email: e.user.email, Password: testPassword, Metadata: browser})
		wantErr(t, err, domain.ErrRecaptchaFailed)
	})

	t.Run("disabled: verifier not called", func(t *testing.T) {
		e := newTestEnv(t, func(_ *config.Config, p *Params) { p.Recaptcha = fakeVerifier{err: errors.New("bad")} })
		e.login(t, browser)
	})
}

// =============================================================================
// AuthenticateAccess
// =============================================================================

func TestAuthenticate_RejectsRefreshTokenRawTokenAndHash(t *testing.T) {
	e := newTestEnv(t)
	pair := e.login(t, browser)
	raw, _ := e.sealer.Open(pair.AccessToken)

	_, err := e.authenticate(t, pair.RefreshToken)
	wantErr(t, err, domain.ErrInvalidTokenType)

	_, err = e.authenticate(t, raw)
	wantErr(t, err, domain.ErrInvalidToken)

	_, err = e.authenticate(t, security.HashToken(raw))
	wantErr(t, err, domain.ErrInvalidToken)
}

func TestAuthenticate_ExpiredAccessToken(t *testing.T) {
	e := newTestEnv(t)
	pair := e.login(t, browser)
	mustAuthenticate(t, e, pair.AccessToken)

	e.clock.Advance(16 * time.Minute) // expiry is checked even on cache hits
	_, err := e.authenticate(t, pair.AccessToken)
	wantErr(t, err, domain.ErrTokenExpired)
}

func TestAuthenticate_DeactivatedUserRejectedDespiteCache(t *testing.T) {
	e := newTestEnv(t)
	pair := e.login(t, browser)
	mustAuthenticate(t, e, pair.AccessToken) // cached

	e.user.active = false
	if err := adapter.NewSessionRevokerAdapter(e.repo, e.cache).RevokeUserSessions(context.Background(), e.user.uuid); err != nil {
		t.Fatal(err)
	}

	_, err := e.authenticate(t, pair.AccessToken)
	wantErr(t, err, domain.ErrUserInactive)

	_, err = e.svc.Refresh(context.Background(), pair.RefreshToken, browser)
	wantErr(t, err, domain.ErrUserInactive)
}

func TestAuthenticate_InactiveUserWithoutRevocation(t *testing.T) {
	e := newTestEnv(t)
	pair := e.login(t, browser)

	// Status changed outside the user service, so no session was revoked.
	e.user.active = false

	_, err := e.authenticate(t, pair.AccessToken)
	wantErr(t, err, domain.ErrUserInactive)

	_, err = e.svc.Refresh(context.Background(), pair.RefreshToken, browser)
	wantErr(t, err, domain.ErrUserInactive)
}

// =============================================================================
// Logout
// =============================================================================

func TestLogout_RevokesFamilyDespiteCache(t *testing.T) {
	e := newTestEnv(t)
	pair := e.login(t, browser)
	id := mustAuthenticate(t, e, pair.AccessToken) // cached

	if err := e.svc.Logout(context.Background(), id); err != nil {
		t.Fatal(err)
	}

	_, err := e.authenticate(t, pair.AccessToken)
	wantErr(t, err, domain.ErrTokenRevoked)
	_, err = e.svc.Refresh(context.Background(), pair.RefreshToken, browser)
	wantErr(t, err, domain.ErrTokenRevoked)
}

func TestLogoutAll_RevokesEverySession(t *testing.T) {
	e := newTestEnv(t)
	phone := e.login(t, domain.Metadata{DeviceID: "phone"})
	laptop := e.login(t, domain.Metadata{DeviceID: "laptop"})
	id := mustAuthenticate(t, e, phone.AccessToken)
	mustAuthenticate(t, e, laptop.AccessToken)

	if err := e.svc.LogoutAll(context.Background(), id); err != nil {
		t.Fatal(err)
	}

	for _, tok := range []string{phone.AccessToken, laptop.AccessToken} {
		_, err := e.authenticate(t, tok)
		wantErr(t, err, domain.ErrTokenRevoked)
	}
}

// =============================================================================
// Refresh
// =============================================================================

func TestRefresh_RotatesPairInSameSession(t *testing.T) {
	e := newTestEnv(t)
	old := e.login(t, browser)
	oldID := mustAuthenticate(t, e, old.AccessToken) // cached

	fresh, err := e.svc.Refresh(context.Background(), old.RefreshToken, browser)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}

	newID := mustAuthenticate(t, e, fresh.AccessToken)
	if newID.FamilyUUID != oldID.FamilyUUID {
		t.Error("refresh changed the session family")
	}

	_, err = e.authenticate(t, old.AccessToken)
	wantErr(t, err, domain.ErrTokenRevoked)
}

func TestRefresh_ReuseRevokesWholeSession(t *testing.T) {
	e := newTestEnv(t)
	old := e.login(t, browser)
	fresh, err := e.svc.Refresh(context.Background(), old.RefreshToken, browser)
	if err != nil {
		t.Fatal(err)
	}

	mustAuthenticate(t, e, fresh.AccessToken) // cached

	_, err = e.svc.Refresh(context.Background(), old.RefreshToken, browser)
	wantErr(t, err, domain.ErrTokenReused)

	_, err = e.authenticate(t, fresh.AccessToken)
	wantErr(t, err, domain.ErrTokenRevoked)
	_, err = e.svc.Refresh(context.Background(), fresh.RefreshToken, browser)
	wantErr(t, err, domain.ErrTokenRevoked)
}

func TestRefresh_RejectsAccessTokenExpiredAndGarbage(t *testing.T) {
	e := newTestEnv(t)
	pair := e.login(t, browser)

	_, err := e.svc.Refresh(context.Background(), pair.AccessToken, browser)
	wantErr(t, err, domain.ErrInvalidTokenType)

	_, err = e.svc.Refresh(context.Background(), "garbage", browser)
	wantErr(t, err, domain.ErrInvalidToken)

	e.clock.Advance(25 * time.Hour)
	_, err = e.svc.Refresh(context.Background(), pair.RefreshToken, browser)
	wantErr(t, err, domain.ErrTokenExpired)
}

func TestRefresh_KeepsDeviceWhenHeaderMissing(t *testing.T) {
	e := newTestEnv(t)
	pair := e.login(t, domain.Metadata{DeviceID: "phone-1"})

	fresh, err := e.svc.Refresh(context.Background(), pair.RefreshToken, domain.Metadata{})
	if err != nil {
		t.Fatal(err)
	}

	id := mustAuthenticate(t, e, fresh.AccessToken)
	if id.Session.DeviceID == nil || *id.Session.DeviceID != "phone-1" {
		t.Errorf("device after refresh = %v, want phone-1", id.Session.DeviceID)
	}
}

// =============================================================================
// Sessions, internal endpoints, cleanup
// =============================================================================

func TestListSessions_FlagsCurrent(t *testing.T) {
	e := newTestEnv(t)
	phone := e.login(t, domain.Metadata{DeviceID: "phone"})
	e.login(t, domain.Metadata{DeviceID: "laptop"})
	id := mustAuthenticate(t, e, phone.AccessToken)

	sessions, err := e.svc.ListSessions(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}

	if len(sessions) != 2 {
		t.Fatalf("got %d sessions, want 2", len(sessions))
	}

	current := 0
	for _, s := range sessions {
		if s.Current {
			current++
			if s.FamilyUUID != id.FamilyUUID {
				t.Error("wrong session flagged as current")
			}
		}
	}

	if current != 1 {
		t.Errorf("%d sessions flagged current, want 1", current)
	}
}

func TestGetTokenDetails(t *testing.T) {
	e := newTestEnv(t)
	pair := e.login(t, browser)

	details, err := e.svc.GetTokenDetails(context.Background(), pair.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}

	if details.TokenType != domain.TokenTypeRefresh || details.Status != domain.TokenStatusActive {
		t.Errorf("details = %s/%s, want refresh_token/active", details.TokenType, details.Status)
	}

	_, err = e.svc.GetTokenDetails(context.Background(), "garbage")
	wantErr(t, err, domain.ErrInvalidToken)
}

func TestRevokeToken(t *testing.T) {
	e := newTestEnv(t)
	pair := e.login(t, browser)
	mustAuthenticate(t, e, pair.AccessToken)

	if err := e.svc.RevokeToken(context.Background(), pair.RefreshToken); err != nil {
		t.Fatal(err)
	}

	_, err := e.authenticate(t, pair.AccessToken)
	wantErr(t, err, domain.ErrTokenRevoked)
}

func TestRevokeAllTokens_RevokesEveryDevice(t *testing.T) {
	e := newTestEnv(t)
	phone := e.login(t, domain.Metadata{DeviceID: "phone"})
	laptop := e.login(t, domain.Metadata{DeviceID: "laptop"})
	mustAuthenticate(t, e, phone.AccessToken)
	mustAuthenticate(t, e, laptop.AccessToken)

	if err := e.svc.RevokeAllTokens(context.Background(), phone.RefreshToken); err != nil {
		t.Fatal(err)
	}

	for _, tok := range []string{phone.AccessToken, laptop.AccessToken} {
		_, err := e.authenticate(t, tok)
		wantErr(t, err, domain.ErrTokenRevoked)
	}
}

func TestCleanupTokens(t *testing.T) {
	e := newTestEnv(t)
	pair := e.login(t, browser)
	id := mustAuthenticate(t, e, pair.AccessToken)
	if err := e.svc.Logout(context.Background(), id); err != nil {
		t.Fatal(err)
	}

	e.clock.Advance(8 * 24 * time.Hour)
	fresh := e.login(t, browser)

	deleted, err := e.svc.CleanupTokens(context.Background(), 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	if deleted != 2 {
		t.Errorf("deleted = %d, want 2 (the pair revoked 8 days ago)", deleted)
	}

	mustAuthenticate(t, e, fresh.AccessToken)
}

func TestCleanupTokens_KeepsLiveSessionStartAndLatestAccess(t *testing.T) {
	e := newTestEnv(t)
	started := e.clock.Now()
	pair := e.login(t, browser)

	// Refresh daily for 9 days: the first pair is revoked well past the 7-day retention.
	for range 9 {
		e.clock.Advance(23 * time.Hour)
		next, err := e.svc.Refresh(context.Background(), pair.RefreshToken, browser)
		if err != nil {
			t.Fatal(err)
		}

		pair = next
	}

	if _, err := e.svc.CleanupTokens(context.Background(), 7*24*time.Hour); err != nil {
		t.Fatal(err)
	}

	details, err := e.svc.GetTokenDetails(context.Background(), pair.RefreshToken)
	if err != nil {
		t.Fatalf("GetTokenDetails() error = %v, want the live session to survive cleanup", err)
	}

	if !details.Session.CreatedAt.Equal(started) {
		t.Errorf("session CreatedAt = %v, want %v (the login time)", details.Session.CreatedAt, started)
	}
}
