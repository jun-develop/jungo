package service

// =============================================================================
// TEST CASE OVERVIEW
// =============================================================================
//
// File: auth_service_test.go
// Purpose: Verify what AuthService decides for login, token authentication, refresh, logout,
//          session listing, the internal token endpoints and token cleanup.
// Type: Unit (Func-field repository; real sealer, hasher, session cache and login guard)
//
// Test functions: 37
// Total scenarios: 67
//
// #   Test Case                                                               Scenario                                   Expected Result
// 1   TestAuthService_Login_IssuesSealedTokensAndStoresOnlyHashes             Successful login                           Sealed tokens returned; only their hashes and expiries stored
// 2   TestAuthService_Login_TrimsClientMetadata                               Values with spaces                         Stored trimmed
// 3   TestAuthService_Login_TrimsClientMetadata                               Long user agent and device ID              Truncated to 512 and 100 characters
// 4   TestAuthService_Login_TrimsClientMetadata                               Empty values                               Stored as nil
// 5   TestAuthService_Login_InvalidatesReplacedSession                        Repository reports a replaced session      That session leaves the cache; others stay
// 6   TestAuthService_Login_RejectsInvalidCredentialsTheSameWay               Wrong password                             ErrInvalidCredentials
// 7   TestAuthService_Login_RejectsInvalidCredentialsTheSameWay               Unknown email                              ErrInvalidCredentials
// 8   TestAuthService_Login_ChecksStatusOnlyAfterPassword                     Inactive user, wrong password              ErrInvalidCredentials
// 9   TestAuthService_Login_ChecksStatusOnlyAfterPassword                     Inactive user, right password              ErrUserInactive
// 10  TestAuthService_Login_ReturnsRepositoryError                            User lookup fails                          Returns the database error
// 11  TestAuthService_Login_ReturnsRepositoryError                            Session cannot be stored                   Returns the database error
// 12  TestAuthService_Login_BruteForceWarnsThenBlocks                         5 wrong passwords, then the right one      Warning from the 3rd failure; then ErrTooManyAttempts
// 13  TestAuthService_Login_ConcurrentAttemptsCannotExceedLimit               20 concurrent wrong passwords              Exactly 5 reach the password check
// 14  TestAuthService_Login_SuccessClearsShortWindow                          4 failures, success, then a failure        Plain ErrInvalidCredentials (counter restarted)
// 15  TestAuthService_Login_FailuresElsewhereCannotLockTheOwnerOut            20 failures from other IPs                 Owner still logs in from their own IP
// 16  TestAuthService_Login_RecaptchaIsOptional                               Enabled, no verifier wired                 Login works
// 17  TestAuthService_Login_RecaptchaIsOptional                               Enabled, verifier fails                    ErrRecaptchaFailed
// 18  TestAuthService_Login_RecaptchaIsOptional                               Disabled, failing verifier wired           Login works (verifier not called)
// 19  TestAuthService_AuthenticateAccess_ReturnsIdentityOfSession             Access token of a live session             Identity built from the session
// 20  TestAuthService_AuthenticateAccess_ChecksSessionState                   Refresh token instead of access token      ErrInvalidTokenType
// 21  TestAuthService_AuthenticateAccess_ChecksSessionState                   User inactive                              ErrUserInactive
// 22  TestAuthService_AuthenticateAccess_ChecksSessionState                   User inactive and token revoked            ErrUserInactive (status checked first)
// 23  TestAuthService_AuthenticateAccess_ChecksSessionState                   Access token superseded                    ErrTokenRevoked
// 24  TestAuthService_AuthenticateAccess_ChecksSessionState                   Access token revoked                       ErrTokenRevoked
// 25  TestAuthService_AuthenticateAccess_ChecksSessionState                   Access token expired                       ErrTokenExpired
// 26  TestAuthService_AuthenticateAccess_RejectsUnknownTokens                 Raw unsealed token                         ErrInvalidToken
// 27  TestAuthService_AuthenticateAccess_RejectsUnknownTokens                 Stored token hash                          ErrInvalidToken
// 28  TestAuthService_AuthenticateAccess_RejectsUnknownTokens                 Sealed token the repository does not know  ErrInvalidToken
// 29  TestAuthService_AuthenticateAccess_ReturnsRepositoryError               Database fails                             The database error, not ErrInvalidToken
// 30  TestAuthService_AuthenticateAccess_ChecksExpiryOnCacheHit               Cached session, 16 minutes later           ErrTokenExpired without reloading
// 31  TestAuthService_AuthenticateAccess_ReloadsSessionAfterUserInvalidation  User's cache entries invalidated           Session reloaded; ErrUserInactive
// 32  TestAuthService_Logout_RevokesFamilyAndInvalidatesCache                 Logout of a cached session                 Family revoked as logout; session leaves the cache
// 33  TestAuthService_Logout_ReturnsRepositoryError                           Database fails                             Returns the database error
// 34  TestAuthService_LogoutAll_RevokesEverySessionOfUser                     Two cached sessions                        User's sessions revoked as logout; both leave the cache
// 35  TestAuthService_LogoutAll_ReturnsRepositoryError                        Database fails                             Returns the database error
// 36  TestAuthService_Refresh_ExchangesRefreshTokenForNewPair                 Valid refresh token                        New pair's hashes, metadata, expiries and nil device ID sent
// 37  TestAuthService_Refresh_MapsRefreshStatus                               Status rotated                             New pair; session leaves the cache
// 38  TestAuthService_Refresh_MapsRefreshStatus                               Status reused                              ErrTokenReused; session leaves the cache
// 39  TestAuthService_Refresh_MapsRefreshStatus                               Status not_found                           ErrInvalidToken
// 40  TestAuthService_Refresh_MapsRefreshStatus                               Status invalid_type                        ErrInvalidTokenType
// 41  TestAuthService_Refresh_MapsRefreshStatus                               Status user_inactive                       ErrUserInactive
// 42  TestAuthService_Refresh_MapsRefreshStatus                               Status revoked                             ErrTokenRevoked
// 43  TestAuthService_Refresh_MapsRefreshStatus                               Status expired                             ErrTokenExpired
// 44  TestAuthService_Refresh_LogsReuse                                       Status reused                              Warning logged with family_uuid and user_uuid
// 45  TestAuthService_Refresh_RejectsUnknownStatus                            Status the service does not know           Returns an unknown refresh status error
// 46  TestAuthService_Refresh_RejectsUnsealedToken                            Not a sealed token                         ErrInvalidToken
// 47  TestAuthService_Refresh_ReturnsRepositoryError                          Database fails                             Returns the database error
// 48  TestAuthService_ListSessions_FlagsCurrent                               Two sessions of the user                   Only the caller's session is flagged current
// 49  TestAuthService_ListSessions_ReturnsRepositoryError                     Database fails                             Returns the database error
// 50  TestAuthService_GetTokenDetails_ReportsTypeAndStatus                    Refresh token of a live session            refresh_token, active
// 51  TestAuthService_GetTokenDetails_ReportsTypeAndStatus                    Access token of a live session             access_token, active
// 52  TestAuthService_GetTokenDetails_ReportsTypeAndStatus                    Access token superseded                    access_token, revoked
// 53  TestAuthService_GetTokenDetails_ReportsTypeAndStatus                    Expired access token                       access_token, expired
// 54  TestAuthService_GetTokenDetails_RejectsInvalidTokens                    Not a sealed token                         ErrInvalidToken
// 55  TestAuthService_GetTokenDetails_RejectsInvalidTokens                    Sealed token the repository does not know  ErrTokenNotFound
// 56  TestAuthService_GetTokenDetails_RejectsInvalidTokens                    Database fails                             Returns the database error
// 57  TestAuthService_RevokeToken_RevokesTheTokensSession                     Valid sealed token                         Its family revoked as admin; session leaves the cache
// 58  TestAuthService_RevokeToken_RejectsInvalidTokens                        Not a sealed token                         ErrInvalidToken
// 59  TestAuthService_RevokeToken_RejectsInvalidTokens                        Sealed token the repository does not know  ErrTokenNotFound
// 60  TestAuthService_RevokeToken_RejectsInvalidTokens                        Database fails                             Returns the database error
// 61  TestAuthService_RevokeAllTokens_RevokesEverySessionOfUser               Valid sealed token                         User's sessions revoked as admin; all leave the cache
// 62  TestAuthService_RevokeAllTokens_RejectsInvalidTokens                    Not a sealed token                         ErrInvalidToken
// 63  TestAuthService_RevokeAllTokens_RejectsInvalidTokens                    Sealed token the repository does not know  ErrTokenNotFound
// 64  TestAuthService_RevokeAllTokens_RejectsInvalidTokens                    Database fails                             Returns the database error
// 65  TestAuthService_CleanupTokens_PassesRetentionCutoff                     7-day retention                            Repository gets now minus 7 days; its count returned
// 66  TestWaitOrTimeout_WaitsForBackgroundWork                                Background work finishes                   Returns nil
// 67  TestWaitOrTimeout_WaitsForBackgroundWork                                Stop deadline ends first                   Returns context.Canceled
//
// =============================================================================

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/jun-develop/junkit/security"

	"jungo/internal/features/auth/domain"
)

// fakeVerifier is a recaptcha.Verifier that always returns err.
type fakeVerifier struct{ err error }

// Verify returns f.err.
func (f fakeVerifier) Verify(context.Context, string, string) error { return f.err }

// loginRepository returns a repository that accepts every new login session.
func loginRepository() *fakeAuthRepository {
	return recordingLoginRepository(&domain.NewSessionParams{})
}

// recordingLoginRepository returns a repository that accepts every new login session and stores
// the params of the last one in got.
func recordingLoginRepository(got *domain.NewSessionParams) *fakeAuthRepository {
	return &fakeAuthRepository{
		CreateLoginSessionFunc: func(_ context.Context, p domain.NewSessionParams) (*domain.LoginSessionResult, error) {
			*got = p
			return &domain.LoginSessionResult{FamilyUUID: p.FamilyUUID}, nil
		},
	}
}

// refreshAnswers returns a RefreshSessionFunc that always answers result and err.
func refreshAnswers(
	result *domain.RefreshResult,
	err error,
) func(context.Context, string, domain.NewSessionParams) (*domain.RefreshResult, error) {
	return func(context.Context, string, domain.NewSessionParams) (*domain.RefreshResult, error) {
		return result, err
	}
}

// deref returns *p, or "<nil>" when p is nil, so optional strings compare and print alike.
func deref(p *string) string {
	if p == nil {
		return "<nil>"
	}

	return *p
}

// invalidTokenCase is a token the internal token endpoints must reject, and what the repository
// answers if the service asks it.
type invalidTokenCase struct {
	name    string
	token   func(t *testing.T, svc *AuthService) string
	repoErr error
	want    error
}

// invalidTokenCases are the tokens GetTokenDetails, RevokeToken and RevokeAllTokens reject.
func invalidTokenCases() []invalidTokenCase {
	sealed := func(t *testing.T, svc *AuthService) string {
		token, _ := sealedToken(t, svc)
		return token
	}

	return []invalidTokenCase{
		{
			name:  "not a sealed token",
			token: func(*testing.T, *AuthService) string { return "garbage" },
			want:  domain.ErrInvalidToken,
		},
		{
			name:    "sealed token the repository does not know",
			token:   sealed,
			repoErr: domain.ErrTokenNotFound,
			want:    domain.ErrTokenNotFound,
		},
		{
			name:    "repository fails",
			token:   sealed,
			repoErr: errDB,
			want:    errDB,
		},
	}
}

// login logs in as creds and fails the test on error.
func login(t *testing.T, svc *AuthService, creds *domain.Credentials, meta domain.Metadata) *domain.TokenPair {
	t.Helper()

	input := domain.LoginInput{Email: creds.Email, Password: testPassword, Metadata: meta}
	pair, err := svc.Login(context.Background(), input)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	return pair
}

// authenticate calls AuthenticateAccess with a background context.
func authenticate(svc *AuthService, token string) (*domain.Identity, error) {
	return svc.AuthenticateAccess(context.Background(), token)
}

// cacheSession authenticates token once, so its session is in the session cache.
func cacheSession(t *testing.T, svc *AuthService, token string) *domain.Identity {
	t.Helper()

	identity, err := authenticate(svc, token)
	if err != nil {
		t.Fatalf("AuthenticateAccess() error = %v", err)
	}

	return identity
}

// openHash unseals token and returns the hash the repository stores for it.
func openHash(t *testing.T, svc *AuthService, token string) string {
	t.Helper()

	raw, err := svc.sealer.Open(token)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	return security.HashToken(raw)
}

// cachedSession is one session the session cache holds, with a counter of its loads from the
// repository.
type cachedSession struct {
	token   string
	session *domain.Session
	loads   int
}

// newCachedSessions puts one live session per family in the session cache of svc and makes
// repo.GetSessionByHashFunc serve them, so a test can tell which ones the service invalidates.
func newCachedSessions(t *testing.T, svc *AuthService, repo *fakeAuthRepository, families int) []*cachedSession {
	t.Helper()

	byHash := map[string]*cachedSession{}
	var sessions []*cachedSession
	for range families {
		token, hash := sealedToken(t, svc)
		_, refreshHash := sealedToken(t, svc)
		cached := &cachedSession{token: token, session: liveSession(hash, refreshHash)}
		byHash[hash] = cached
		sessions = append(sessions, cached)
	}

	repo.GetSessionByHashFunc = func(_ context.Context, hash string) (*domain.Session, error) {
		cached := byHash[hash]
		cached.loads++

		return cached.session, nil
	}

	for _, cached := range sessions {
		cacheSession(t, svc, cached.token)
	}

	return sessions
}

// reloaded reports whether authenticating the session again had to load it from the repository,
// that is whether the service invalidated it.
func (c *cachedSession) reloaded(t *testing.T, svc *AuthService) bool {
	t.Helper()

	before := c.loads
	if _, err := authenticate(svc, c.token); err != nil {
		t.Fatalf("AuthenticateAccess() error = %v", err)
	}

	return c.loads > before
}

func TestAuthService_Login_IssuesSealedTokensAndStoresOnlyHashes(t *testing.T) {
	creds := testCredentials(t)
	var got domain.NewSessionParams
	svc := newTestService(t, AuthServiceParams{Repo: recordingLoginRepository(&got), Users: usersWith(creds)})

	pair := login(t, svc, creds, browser)

	if hash := openHash(t, svc, pair.AccessToken); got.AccessHash != hash {
		t.Errorf("stored access hash = %q, want the hash of the issued access token %q", got.AccessHash, hash)
	}

	if hash := openHash(t, svc, pair.RefreshToken); got.RefreshHash != hash {
		t.Errorf("stored refresh hash = %q, want the hash of the issued refresh token %q", got.RefreshHash, hash)
	}

	for _, token := range []string{pair.AccessToken, pair.RefreshToken} {
		raw, err := svc.sealer.Open(token)
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}

		if strings.Contains(token, raw) {
			t.Error("sealed token contains the raw token")
		}
	}

	if got.UserID != creds.UserID {
		t.Errorf("session user ID = %d, want %d", got.UserID, creds.UserID)
	}

	if got.FamilyUUID == uuid.Nil {
		t.Error("session family UUID = uuid.Nil, want a new family")
	}

	if want := testNow.Add(15 * time.Minute); !got.AccessExpiresAt.Equal(want) {
		t.Errorf("access expiry = %v, want %v", got.AccessExpiresAt, want)
	}

	if want := testNow.Add(24 * time.Hour); !got.RefreshExpiresAt.Equal(want) {
		t.Errorf("refresh expiry = %v, want %v", got.RefreshExpiresAt, want)
	}
}

func TestAuthService_Login_TrimsClientMetadata(t *testing.T) {
	longDevice := strings.Repeat("d", 150)
	longAgent := strings.Repeat("a", 600)
	tests := []struct {
		name       string
		meta       domain.Metadata
		wantIP     *string
		wantAgent  *string
		wantDevice *string
	}{
		{
			name:       "values with spaces are trimmed",
			meta:       domain.Metadata{IPAddress: " 203.0.113.10 ", UserAgent: " Firefox ", DeviceID: " phone "},
			wantIP:     new("203.0.113.10"),
			wantAgent:  new("Firefox"),
			wantDevice: new("phone"),
		},
		{
			name:       "long user agent and device ID are truncated",
			meta:       domain.Metadata{IPAddress: "203.0.113.10", UserAgent: longAgent, DeviceID: longDevice},
			wantIP:     new("203.0.113.10"),
			wantAgent:  new(longAgent[:maxUserAgentLength]),
			wantDevice: new(longDevice[:maxDeviceIDLength]),
		},
		{
			name:   "empty values are stored as nil",
			meta:   domain.Metadata{IPAddress: "203.0.113.10", UserAgent: "  "},
			wantIP: new("203.0.113.10"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds := testCredentials(t)
			var got domain.NewSessionParams
			svc := newTestService(t, AuthServiceParams{Repo: recordingLoginRepository(&got), Users: usersWith(creds)})

			login(t, svc, creds, tt.meta)

			if deref(got.IPAddress) != deref(tt.wantIP) {
				t.Errorf("IP address = %v, want %v", deref(got.IPAddress), deref(tt.wantIP))
			}

			if deref(got.UserAgent) != deref(tt.wantAgent) {
				t.Errorf("user agent = %v, want %v", deref(got.UserAgent), deref(tt.wantAgent))
			}

			if deref(got.DeviceID) != deref(tt.wantDevice) {
				t.Errorf("device ID = %v, want %v", deref(got.DeviceID), deref(tt.wantDevice))
			}
		})
	}
}

func TestAuthService_Login_InvalidatesReplacedSession(t *testing.T) {
	creds := testCredentials(t)
	repo := &fakeAuthRepository{}
	svc := newTestService(t, AuthServiceParams{Repo: repo, Users: usersWith(creds)})
	sessions := newCachedSessions(t, svc, repo, 2)
	replaced, other := sessions[0], sessions[1]
	repo.CreateLoginSessionFunc = func(
		_ context.Context, p domain.NewSessionParams,
	) (*domain.LoginSessionResult, error) {
		return &domain.LoginSessionResult{FamilyUUID: p.FamilyUUID, StaleFamilyUUID: replaced.session.FamilyUUID}, nil
	}

	login(t, svc, creds, browser)

	if !replaced.reloaded(t, svc) {
		t.Error("replaced session still served from the cache, want it invalidated")
	}

	if other.reloaded(t, svc) {
		t.Error("unrelated session reloaded, want it to stay cached")
	}
}

func TestAuthService_Login_RejectsInvalidCredentialsTheSameWay(t *testing.T) {
	tests := []struct {
		name  string
		email string
	}{
		{"wrong password", "jane@example.com"},
		{"unknown email", "ghost@example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestService(t, AuthServiceParams{Repo: loginRepository(), Users: usersWith(testCredentials(t))})
			input := domain.LoginInput{Email: tt.email, Password: "nope", Metadata: browser}

			_, err := svc.Login(context.Background(), input)

			wantErr(t, err, domain.ErrInvalidCredentials)
		})
	}
}

func TestAuthService_Login_ChecksStatusOnlyAfterPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		want     error
	}{
		{"inactive user, wrong password", "nope", domain.ErrInvalidCredentials},
		{"inactive user, right password", testPassword, domain.ErrUserInactive},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds := testCredentials(t)
			creds.Active = false
			svc := newTestService(t, AuthServiceParams{Repo: loginRepository(), Users: usersWith(creds)})
			input := domain.LoginInput{Email: creds.Email, Password: tt.password, Metadata: browser}

			_, err := svc.Login(context.Background(), input)

			wantErr(t, err, tt.want)
		})
	}
}

func TestAuthService_Login_ReturnsRepositoryError(t *testing.T) {
	t.Run("user lookup fails", func(t *testing.T) {
		users := &fakeUserProvider{
			GetCredentialsByEmailFunc: func(context.Context, string) (*domain.Credentials, error) {
				return nil, errDB
			},
		}
		svc := newTestService(t, AuthServiceParams{Repo: &fakeAuthRepository{}, Users: users})
		input := domain.LoginInput{Email: "jane@example.com", Password: testPassword, Metadata: browser}

		_, err := svc.Login(context.Background(), input)

		wantErr(t, err, errDB)
	})

	t.Run("session cannot be stored", func(t *testing.T) {
		creds := testCredentials(t)
		repo := &fakeAuthRepository{
			CreateLoginSessionFunc: func(context.Context, domain.NewSessionParams) (*domain.LoginSessionResult, error) {
				return nil, errDB
			},
		}
		svc := newTestService(t, AuthServiceParams{Repo: repo, Users: usersWith(creds)})
		input := domain.LoginInput{Email: creds.Email, Password: testPassword, Metadata: browser}

		_, err := svc.Login(context.Background(), input)

		wantErr(t, err, errDB)
	})
}

func TestAuthService_Login_BruteForceWarnsThenBlocks(t *testing.T) {
	creds := testCredentials(t)
	svc := newTestService(t, AuthServiceParams{Repo: loginRepository(), Users: usersWith(creds)})
	bad := domain.LoginInput{Email: creds.Email, Password: "wrong", Metadata: browser}

	var errs []error
	for range 5 {
		_, err := svc.Login(context.Background(), bad)
		errs = append(errs, err)
	}

	wantErr(t, errs[0], domain.ErrInvalidCredentials)
	wantErr(t, errs[1], domain.ErrInvalidCredentials)
	// From the 3rd failure on, 2 or fewer attempts are left.
	wantErr(t, errs[2], domain.ErrInvalidCredentialsWarning)
	wantErr(t, errs[3], domain.ErrInvalidCredentialsWarning)
	wantErr(t, errs[4], domain.ErrInvalidCredentialsWarning)

	// Blocked now, even with the right password.
	good := domain.LoginInput{Email: creds.Email, Password: testPassword, Metadata: browser}
	_, err := svc.Login(context.Background(), good)
	wantErr(t, err, domain.ErrTooManyAttempts)
}

func TestAuthService_Login_ConcurrentAttemptsCannotExceedLimit(t *testing.T) {
	creds := testCredentials(t)
	svc := newTestService(t, AuthServiceParams{Repo: loginRepository(), Users: usersWith(creds)})
	bad := domain.LoginInput{Email: creds.Email, Password: "wrong", Metadata: browser}

	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		passed int
	)
	for range 20 {
		wg.Go(func() {
			_, err := svc.Login(context.Background(), bad)
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

func TestAuthService_Login_SuccessClearsShortWindow(t *testing.T) {
	creds := testCredentials(t)
	svc := newTestService(t, AuthServiceParams{Repo: loginRepository(), Users: usersWith(creds)})
	bad := domain.LoginInput{Email: creds.Email, Password: "wrong", Metadata: browser}
	for i := range 4 {
		if _, err := svc.Login(context.Background(), bad); err == nil {
			t.Fatalf("failed attempt %d: Login() error = nil, want a rejection", i+1)
		}
	}

	login(t, svc, creds, browser)

	_, err := svc.Login(context.Background(), bad)
	// The counter restarted: no warning yet.
	wantErr(t, err, domain.ErrInvalidCredentials)
}

func TestAuthService_Login_FailuresElsewhereCannotLockTheOwnerOut(t *testing.T) {
	creds := testCredentials(t)
	svc := newTestService(t, AuthServiceParams{Repo: loginRepository(), Users: usersWith(creds)})
	for i := range 20 {
		ip := "198.51.100." + strconv.Itoa(i)
		input := domain.LoginInput{Email: creds.Email, Password: "wrong", Metadata: domain.Metadata{IPAddress: ip}}
		if _, err := svc.Login(context.Background(), input); err == nil {
			t.Fatalf("attempt from %s: Login() error = nil, want a rejection", ip)
		}
	}

	login(t, svc, creds, domain.Metadata{IPAddress: "192.0.2.99"})
}

func TestAuthService_Login_RecaptchaIsOptional(t *testing.T) {
	failing := fakeVerifier{err: errors.New("bad")}

	t.Run("enabled but no verifier wired: login works", func(t *testing.T) {
		creds := testCredentials(t)
		cfg := testConfig()
		cfg.Auth.RecaptchaOnLogin = true
		svc := newTestService(t, AuthServiceParams{Config: cfg, Repo: loginRepository(), Users: usersWith(creds)})

		login(t, svc, creds, browser)
	})

	t.Run("enabled with a failing verifier: rejected", func(t *testing.T) {
		creds := testCredentials(t)
		cfg := testConfig()
		cfg.Auth.RecaptchaOnLogin = true
		svc := newTestService(t, AuthServiceParams{
			Config:    cfg,
			Repo:      loginRepository(),
			Users:     usersWith(creds),
			Recaptcha: failing,
		})
		input := domain.LoginInput{Email: creds.Email, Password: testPassword, Metadata: browser}

		_, err := svc.Login(context.Background(), input)

		wantErr(t, err, domain.ErrRecaptchaFailed)
	})

	t.Run("disabled: verifier not called", func(t *testing.T) {
		creds := testCredentials(t)
		svc := newTestService(t, AuthServiceParams{
			Repo:      loginRepository(),
			Users:     usersWith(creds),
			Recaptcha: failing,
		})

		login(t, svc, creds, browser)
	})
}

func TestAuthService_AuthenticateAccess_ReturnsIdentityOfSession(t *testing.T) {
	repo := &fakeAuthRepository{}
	svc := newTestService(t, AuthServiceParams{Repo: repo})
	token, hash := sealedToken(t, svc)
	session := liveSession(hash, "refresh-hash")
	repo.GetSessionByHashFunc = func(context.Context, string) (*domain.Session, error) { return session, nil }

	identity, err := authenticate(svc, token)

	if err != nil {
		t.Fatalf("AuthenticateAccess() error = %v", err)
	}

	want := &domain.Identity{
		UserID:     session.UserID,
		UserUUID:   session.UserUUID,
		Email:      session.Email,
		FamilyUUID: session.FamilyUUID,
		TokenUUID:  session.Access.UUID,
		ExpiresAt:  session.Access.ExpiresAt,
		Session:    session,
	}
	if *identity != *want {
		t.Errorf("AuthenticateAccess() = %+v, want %+v", identity, want)
	}
}

func TestAuthService_AuthenticateAccess_ChecksSessionState(t *testing.T) {
	revokedAt := testNow.Add(-time.Minute)
	tests := []struct {
		name         string
		useRefresh   bool
		modify       func(s *domain.Session)
		want         error
		wantIdentity bool
	}{
		{
			name:       "refresh token instead of an access token",
			useRefresh: true,
			want:       domain.ErrInvalidTokenType,
		},
		{
			name:   "user inactive",
			modify: func(s *domain.Session) { s.UserActive = false },
			want:   domain.ErrUserInactive,
		},
		{
			name: "user inactive and access token revoked",
			modify: func(s *domain.Session) {
				s.UserActive = false
				s.Access.RevokedAt = &revokedAt
			},
			want: domain.ErrUserInactive,
		},
		{
			name:   "access token superseded by a newer one",
			modify: func(s *domain.Session) { s.Access.Hash = "newer-access-hash" },
			want:   domain.ErrTokenRevoked,
		},
		{
			name:   "access token revoked",
			modify: func(s *domain.Session) { s.Access.RevokedAt = &revokedAt },
			want:   domain.ErrTokenRevoked,
		},
		{
			name:   "access token expired",
			modify: func(s *domain.Session) { s.Access.ExpiresAt = testNow },
			want:   domain.ErrTokenExpired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fakeAuthRepository{}
			svc := newTestService(t, AuthServiceParams{Repo: repo})
			accessToken, accessHash := sealedToken(t, svc)
			refreshToken, refreshHash := sealedToken(t, svc)
			session := liveSession(accessHash, refreshHash)
			if tt.modify != nil {
				tt.modify(session)
			}

			repo.GetSessionByHashFunc = func(context.Context, string) (*domain.Session, error) { return session, nil }

			token := accessToken
			if tt.useRefresh {
				token = refreshToken
			}

			_, err := authenticate(svc, token)

			wantErr(t, err, tt.want)
		})
	}
}

func TestAuthService_AuthenticateAccess_RejectsUnknownTokens(t *testing.T) {
	tests := []struct {
		name  string
		token func(t *testing.T, svc *AuthService) string
	}{
		{
			name: "raw unsealed token",
			token: func(*testing.T, *AuthService) string {
				return security.GenerateToken()
			},
		},
		{
			name: "stored token hash",
			token: func(t *testing.T, svc *AuthService) string {
				_, hash := sealedToken(t, svc)
				return hash
			},
		},
		{
			name: "sealed token the repository does not know",
			token: func(t *testing.T, svc *AuthService) string {
				token, _ := sealedToken(t, svc)
				return token
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fakeAuthRepository{
				GetSessionByHashFunc: func(context.Context, string) (*domain.Session, error) {
					return nil, domain.ErrTokenNotFound
				},
			}
			svc := newTestService(t, AuthServiceParams{Repo: repo})

			_, err := authenticate(svc, tt.token(t, svc))

			wantErr(t, err, domain.ErrInvalidToken)
		})
	}
}

func TestAuthService_AuthenticateAccess_ReturnsRepositoryError(t *testing.T) {
	repo := &fakeAuthRepository{
		GetSessionByHashFunc: func(context.Context, string) (*domain.Session, error) { return nil, errDB },
	}
	svc := newTestService(t, AuthServiceParams{Repo: repo})
	token, _ := sealedToken(t, svc)

	_, err := authenticate(svc, token)

	// A database outage must not be reported as a bad token.
	wantErr(t, err, errDB)
}

func TestAuthService_AuthenticateAccess_ChecksExpiryOnCacheHit(t *testing.T) {
	repo := &fakeAuthRepository{}
	svc := newTestService(t, AuthServiceParams{Repo: repo})
	session := newCachedSessions(t, svc, repo, 1)[0]
	// AuthServiceParams has no clock: moving the service clock is the only way to age the session.
	svc.now = func() time.Time { return testNow.Add(16 * time.Minute) }

	_, err := authenticate(svc, session.token)

	wantErr(t, err, domain.ErrTokenExpired)
	if session.loads != 1 {
		t.Errorf("session loads = %d, want 1 (expiry checked on the cached session)", session.loads)
	}
}

func TestAuthService_AuthenticateAccess_ReloadsSessionAfterUserInvalidation(t *testing.T) {
	repo := &fakeAuthRepository{}
	svc := newTestService(t, AuthServiceParams{Repo: repo})
	session := newCachedSessions(t, svc, repo, 1)[0]
	inactive := *session.session
	inactive.UserActive = false
	session.session = &inactive

	// What the user feature does after deactivating a user.
	svc.cache.InvalidateUser(context.Background(), inactive.UserUUID)
	_, err := authenticate(svc, session.token)

	wantErr(t, err, domain.ErrUserInactive)
}

func TestAuthService_Logout_RevokesFamilyAndInvalidatesCache(t *testing.T) {
	repo := &fakeAuthRepository{}
	svc := newTestService(t, AuthServiceParams{Repo: repo})
	session := newCachedSessions(t, svc, repo, 1)[0]
	identity := cacheSession(t, svc, session.token)
	var gotFamily uuid.UUID
	var gotReason string
	repo.RevokeFamilyFunc = func(_ context.Context, family uuid.UUID, reason string) error {
		gotFamily, gotReason = family, reason
		return nil
	}

	if err := svc.Logout(context.Background(), identity); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}

	if gotFamily != identity.FamilyUUID {
		t.Errorf("revoked family = %v, want %v", gotFamily, identity.FamilyUUID)
	}

	if gotReason != domain.RevokedReasonLogout {
		t.Errorf("revoke reason = %q, want %q", gotReason, domain.RevokedReasonLogout)
	}

	if !session.reloaded(t, svc) {
		t.Error("session still served from the cache after logout, want it invalidated")
	}
}

func TestAuthService_Logout_ReturnsRepositoryError(t *testing.T) {
	repo := &fakeAuthRepository{
		RevokeFamilyFunc: func(context.Context, uuid.UUID, string) error { return errDB },
	}
	svc := newTestService(t, AuthServiceParams{Repo: repo})

	err := svc.Logout(context.Background(), &domain.Identity{FamilyUUID: uuid.New()})

	wantErr(t, err, errDB)
}

func TestAuthService_LogoutAll_RevokesEverySessionOfUser(t *testing.T) {
	repo := &fakeAuthRepository{}
	svc := newTestService(t, AuthServiceParams{Repo: repo})
	sessions := newCachedSessions(t, svc, repo, 2)
	identity := &domain.Identity{UserUUID: uuid.New()}
	var gotUser uuid.UUID
	var gotReason string
	repo.RevokeAllForUserFunc = func(_ context.Context, user uuid.UUID, reason string) ([]uuid.UUID, error) {
		gotUser, gotReason = user, reason
		return []uuid.UUID{sessions[0].session.FamilyUUID, sessions[1].session.FamilyUUID}, nil
	}

	if err := svc.LogoutAll(context.Background(), identity); err != nil {
		t.Fatalf("LogoutAll() error = %v", err)
	}

	if gotUser != identity.UserUUID {
		t.Errorf("revoked user = %v, want %v", gotUser, identity.UserUUID)
	}

	if gotReason != domain.RevokedReasonLogout {
		t.Errorf("revoke reason = %q, want %q", gotReason, domain.RevokedReasonLogout)
	}

	for i, session := range sessions {
		if !session.reloaded(t, svc) {
			t.Errorf("session %d still served from the cache, want every revoked family invalidated", i)
		}
	}
}

func TestAuthService_LogoutAll_ReturnsRepositoryError(t *testing.T) {
	repo := &fakeAuthRepository{
		RevokeAllForUserFunc: func(context.Context, uuid.UUID, string) ([]uuid.UUID, error) { return nil, errDB },
	}
	svc := newTestService(t, AuthServiceParams{Repo: repo})

	err := svc.LogoutAll(context.Background(), &domain.Identity{UserUUID: uuid.New()})

	wantErr(t, err, errDB)
}

func TestAuthService_Refresh_ExchangesRefreshTokenForNewPair(t *testing.T) {
	repo := &fakeAuthRepository{}
	svc := newTestService(t, AuthServiceParams{Repo: repo})
	refreshToken, refreshHash := sealedToken(t, svc)
	var gotHash string
	var gotParams domain.NewSessionParams
	repo.RefreshSessionFunc = func(
		_ context.Context, hash string, p domain.NewSessionParams,
	) (*domain.RefreshResult, error) {
		gotHash, gotParams = hash, p
		return &domain.RefreshResult{Status: domain.RefreshRotated, FamilyUUID: uuid.New()}, nil
	}

	pair, err := svc.Refresh(context.Background(), refreshToken, browser)

	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}

	if gotHash != refreshHash {
		t.Errorf("refreshed hash = %q, want the hash of the presented refresh token %q", gotHash, refreshHash)
	}

	if hash := openHash(t, svc, pair.AccessToken); gotParams.AccessHash != hash {
		t.Errorf("stored access hash = %q, want the hash of the new access token %q", gotParams.AccessHash, hash)
	}

	if hash := openHash(t, svc, pair.RefreshToken); gotParams.RefreshHash != hash {
		t.Errorf("stored refresh hash = %q, want the hash of the new refresh token %q", gotParams.RefreshHash, hash)
	}

	// browser sends no device ID: nil lets the database keep the session's device.
	if gotParams.DeviceID != nil {
		t.Errorf("device ID = %q, want nil", *gotParams.DeviceID)
	}

	if deref(gotParams.IPAddress) != browser.IPAddress {
		t.Errorf("IP address = %v, want %v", deref(gotParams.IPAddress), browser.IPAddress)
	}

	if deref(gotParams.UserAgent) != browser.UserAgent {
		t.Errorf("user agent = %v, want %v", deref(gotParams.UserAgent), browser.UserAgent)
	}

	if want := testNow.Add(15 * time.Minute); !gotParams.AccessExpiresAt.Equal(want) {
		t.Errorf("access expiry = %v, want %v", gotParams.AccessExpiresAt, want)
	}

	if want := testNow.Add(24 * time.Hour); !gotParams.RefreshExpiresAt.Equal(want) {
		t.Errorf("refresh expiry = %v, want %v", gotParams.RefreshExpiresAt, want)
	}
}

func TestAuthService_Refresh_MapsRefreshStatus(t *testing.T) {
	tests := []struct {
		status          string
		want            error
		wantInvalidated bool
	}{
		{domain.RefreshRotated, nil, true},
		{domain.RefreshReused, domain.ErrTokenReused, true},
		{domain.RefreshNotFound, domain.ErrInvalidToken, false},
		{domain.RefreshInvalidType, domain.ErrInvalidTokenType, false},
		{domain.RefreshUserInactive, domain.ErrUserInactive, false},
		{domain.RefreshRevoked, domain.ErrTokenRevoked, false},
		{domain.RefreshExpired, domain.ErrTokenExpired, false},
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			repo := &fakeAuthRepository{}
			svc := newTestService(t, AuthServiceParams{Repo: repo})
			session := newCachedSessions(t, svc, repo, 1)[0]
			refreshToken, _ := sealedToken(t, svc)
			repo.RefreshSessionFunc = refreshAnswers(
				&domain.RefreshResult{Status: tt.status, FamilyUUID: session.session.FamilyUUID},
				nil,
			)

			pair, err := svc.Refresh(context.Background(), refreshToken, browser)

			if !errors.Is(err, tt.want) {
				t.Fatalf("Refresh() error = %v, want %v", err, tt.want)
			}

			if gotPair := pair != nil; gotPair != (tt.want == nil) {
				t.Errorf("Refresh() returned a pair = %v, want %v", gotPair, tt.want == nil)
			}

			if got := session.reloaded(t, svc); got != tt.wantInvalidated {
				t.Errorf("session invalidated = %v, want %v", got, tt.wantInvalidated)
			}
		})
	}
}

func TestAuthService_Refresh_LogsReuse(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	family, user := uuid.New(), uuid.New()
	repo := &fakeAuthRepository{
		RefreshSessionFunc: refreshAnswers(
			&domain.RefreshResult{Status: domain.RefreshReused, FamilyUUID: family, UserUUID: user},
			nil,
		),
	}
	svc := newTestService(t, AuthServiceParams{Repo: repo, Logger: zap.New(core)})
	refreshToken, _ := sealedToken(t, svc)

	_, err := svc.Refresh(context.Background(), refreshToken, browser)

	wantErr(t, err, domain.ErrTokenReused)
	entries := logs.FilterMessage("auth: refresh token reuse detected, session revoked").All()
	if len(entries) != 1 {
		t.Fatalf("reuse log entries = %d, want 1", len(entries))
	}

	fields := entries[0].ContextMap()
	if fields["family_uuid"] != family.String() {
		t.Errorf("logged family_uuid = %v, want %s", fields["family_uuid"], family)
	}

	if fields["user_uuid"] != user.String() {
		t.Errorf("logged user_uuid = %v, want %s", fields["user_uuid"], user)
	}
}

func TestAuthService_Refresh_RejectsUnknownStatus(t *testing.T) {
	repo := &fakeAuthRepository{RefreshSessionFunc: refreshAnswers(&domain.RefreshResult{Status: "teleported"}, nil)}
	svc := newTestService(t, AuthServiceParams{Repo: repo})
	refreshToken, _ := sealedToken(t, svc)

	_, err := svc.Refresh(context.Background(), refreshToken, browser)

	if err == nil {
		t.Fatal("Refresh() error = nil, want an unknown refresh status error")
	}

	if !strings.Contains(err.Error(), `unknown refresh status "teleported"`) {
		t.Errorf("Refresh() error = %q, want it to name the unknown status", err)
	}
}

func TestAuthService_Refresh_RejectsUnsealedToken(t *testing.T) {
	svc := newTestService(t, AuthServiceParams{Repo: &fakeAuthRepository{}})

	_, err := svc.Refresh(context.Background(), "garbage", browser)

	wantErr(t, err, domain.ErrInvalidToken)
}

func TestAuthService_Refresh_ReturnsRepositoryError(t *testing.T) {
	repo := &fakeAuthRepository{RefreshSessionFunc: refreshAnswers(nil, errDB)}
	svc := newTestService(t, AuthServiceParams{Repo: repo})
	refreshToken, _ := sealedToken(t, svc)

	_, err := svc.Refresh(context.Background(), refreshToken, browser)

	wantErr(t, err, errDB)
}

func TestAuthService_ListSessions_FlagsCurrent(t *testing.T) {
	identity := &domain.Identity{UserID: 7, FamilyUUID: uuid.New()}
	other := uuid.New()
	var gotUserID int64
	repo := &fakeAuthRepository{
		ListActiveSessionsFunc: func(_ context.Context, userID int64) ([]*domain.SessionSummary, error) {
			gotUserID = userID
			return []*domain.SessionSummary{{FamilyUUID: other}, {FamilyUUID: identity.FamilyUUID}}, nil
		},
	}
	svc := newTestService(t, AuthServiceParams{Repo: repo})

	sessions, err := svc.ListSessions(context.Background(), identity)

	if err != nil {
		t.Fatalf("ListSessions() error = %v", err)
	}

	if gotUserID != identity.UserID {
		t.Errorf("listed user ID = %d, want %d", gotUserID, identity.UserID)
	}

	if len(sessions) != 2 {
		t.Fatalf("ListSessions() returned %d sessions, want 2", len(sessions))
	}

	if sessions[0].Current {
		t.Error("another session flagged current, want only the caller's")
	}

	if !sessions[1].Current {
		t.Error("the caller's session is not flagged current")
	}
}

func TestAuthService_ListSessions_ReturnsRepositoryError(t *testing.T) {
	repo := &fakeAuthRepository{
		ListActiveSessionsFunc: func(context.Context, int64) ([]*domain.SessionSummary, error) { return nil, errDB },
	}
	svc := newTestService(t, AuthServiceParams{Repo: repo})

	_, err := svc.ListSessions(context.Background(), &domain.Identity{UserID: 7})

	wantErr(t, err, errDB)
}

func TestAuthService_GetTokenDetails_ReportsTypeAndStatus(t *testing.T) {
	tests := []struct {
		name       string
		useRefresh bool
		modify     func(s *domain.Session)
		wantType   domain.TokenType
		wantStatus string
	}{
		{
			name:       "refresh token of a live session",
			useRefresh: true,
			wantType:   domain.TokenTypeRefresh,
			wantStatus: domain.TokenStatusActive,
		},
		{
			name:       "access token of a live session",
			wantType:   domain.TokenTypeAccess,
			wantStatus: domain.TokenStatusActive,
		},
		{
			name:       "access token superseded by a newer one",
			modify:     func(s *domain.Session) { s.Access.Hash = "newer-access-hash" },
			wantType:   domain.TokenTypeAccess,
			wantStatus: domain.TokenStatusRevoked,
		},
		{
			name:       "expired access token",
			modify:     func(s *domain.Session) { s.Access.ExpiresAt = testNow },
			wantType:   domain.TokenTypeAccess,
			wantStatus: domain.TokenStatusExpired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fakeAuthRepository{
				GetTokenTypeByHashFunc: func(context.Context, string) (domain.TokenType, error) {
					return domain.TokenTypeAccess, nil
				},
			}
			svc := newTestService(t, AuthServiceParams{Repo: repo})
			accessToken, accessHash := sealedToken(t, svc)
			refreshToken, refreshHash := sealedToken(t, svc)
			session := liveSession(accessHash, refreshHash)
			if tt.modify != nil {
				tt.modify(session)
			}

			repo.GetSessionByHashFunc = func(context.Context, string) (*domain.Session, error) { return session, nil }

			token := accessToken
			if tt.useRefresh {
				token = refreshToken
			}

			details, err := svc.GetTokenDetails(context.Background(), token)

			if err != nil {
				t.Fatalf("GetTokenDetails() error = %v", err)
			}

			if details.TokenType != tt.wantType {
				t.Errorf("token type = %s, want %s", details.TokenType, tt.wantType)
			}

			if details.Status != tt.wantStatus {
				t.Errorf("status = %s, want %s", details.Status, tt.wantStatus)
			}
		})
	}
}

func TestAuthService_GetTokenDetails_RejectsInvalidTokens(t *testing.T) {
	for _, tt := range invalidTokenCases() {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fakeAuthRepository{
				GetSessionByHashFunc: func(context.Context, string) (*domain.Session, error) { return nil, tt.repoErr },
			}
			svc := newTestService(t, AuthServiceParams{Repo: repo})

			_, err := svc.GetTokenDetails(context.Background(), tt.token(t, svc))

			wantErr(t, err, tt.want)
		})
	}
}

func TestAuthService_RevokeToken_RevokesTheTokensSession(t *testing.T) {
	repo := &fakeAuthRepository{}
	svc := newTestService(t, AuthServiceParams{Repo: repo})
	session := newCachedSessions(t, svc, repo, 1)[0]
	token, hash := sealedToken(t, svc)
	var gotHash, gotReason string
	repo.RevokeFamilyByHashFunc = func(_ context.Context, h, reason string) (uuid.UUID, error) {
		gotHash, gotReason = h, reason
		return session.session.FamilyUUID, nil
	}

	if err := svc.RevokeToken(context.Background(), token); err != nil {
		t.Fatalf("RevokeToken() error = %v", err)
	}

	if gotHash != hash {
		t.Errorf("revoked hash = %q, want %q", gotHash, hash)
	}

	if gotReason != domain.RevokedReasonAdmin {
		t.Errorf("revoke reason = %q, want %q", gotReason, domain.RevokedReasonAdmin)
	}

	if !session.reloaded(t, svc) {
		t.Error("session still served from the cache, want it invalidated")
	}
}

func TestAuthService_RevokeToken_RejectsInvalidTokens(t *testing.T) {
	for _, tt := range invalidTokenCases() {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fakeAuthRepository{
				RevokeFamilyByHashFunc: func(context.Context, string, string) (uuid.UUID, error) {
					return uuid.Nil, tt.repoErr
				},
			}
			svc := newTestService(t, AuthServiceParams{Repo: repo})

			err := svc.RevokeToken(context.Background(), tt.token(t, svc))

			wantErr(t, err, tt.want)
		})
	}
}

func TestAuthService_RevokeAllTokens_RevokesEverySessionOfUser(t *testing.T) {
	repo := &fakeAuthRepository{}
	svc := newTestService(t, AuthServiceParams{Repo: repo})
	sessions := newCachedSessions(t, svc, repo, 2)
	token, hash := sealedToken(t, svc)
	var gotHash, gotReason string
	repo.RevokeAllByHashFunc = func(_ context.Context, h, reason string) ([]uuid.UUID, error) {
		gotHash, gotReason = h, reason
		return []uuid.UUID{sessions[0].session.FamilyUUID, sessions[1].session.FamilyUUID}, nil
	}

	if err := svc.RevokeAllTokens(context.Background(), token); err != nil {
		t.Fatalf("RevokeAllTokens() error = %v", err)
	}

	if gotHash != hash {
		t.Errorf("revoked hash = %q, want %q", gotHash, hash)
	}

	if gotReason != domain.RevokedReasonAdmin {
		t.Errorf("revoke reason = %q, want %q", gotReason, domain.RevokedReasonAdmin)
	}

	for i, session := range sessions {
		if !session.reloaded(t, svc) {
			t.Errorf("session %d still served from the cache, want every revoked family invalidated", i)
		}
	}
}

func TestAuthService_RevokeAllTokens_RejectsInvalidTokens(t *testing.T) {
	for _, tt := range invalidTokenCases() {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fakeAuthRepository{
				RevokeAllByHashFunc: func(context.Context, string, string) ([]uuid.UUID, error) {
					return nil, tt.repoErr
				},
			}
			svc := newTestService(t, AuthServiceParams{Repo: repo})

			err := svc.RevokeAllTokens(context.Background(), tt.token(t, svc))

			wantErr(t, err, tt.want)
		})
	}
}

func TestAuthService_CleanupTokens_PassesRetentionCutoff(t *testing.T) {
	var gotBefore time.Time
	repo := &fakeAuthRepository{
		CleanupTokensFunc: func(_ context.Context, before time.Time) (int64, error) {
			gotBefore = before
			return 2, nil
		},
	}
	svc := newTestService(t, AuthServiceParams{Repo: repo})

	deleted, err := svc.CleanupTokens(context.Background(), 7*24*time.Hour)

	if err != nil {
		t.Fatalf("CleanupTokens() error = %v", err)
	}

	if want := testNow.Add(-7 * 24 * time.Hour); !gotBefore.Equal(want) {
		t.Errorf("cleanup cutoff = %v, want %v (now minus retention)", gotBefore, want)
	}

	if deleted != 2 {
		t.Errorf("CleanupTokens() = %d, want 2 (the repository's count)", deleted)
	}
}

func TestWaitOrTimeout_WaitsForBackgroundWork(t *testing.T) {
	t.Run("background work finishes", func(t *testing.T) {
		var wg sync.WaitGroup
		wg.Go(func() {})

		if err := waitOrTimeout(context.Background(), &wg); err != nil {
			t.Errorf("waitOrTimeout() error = %v, want nil", err)
		}
	})

	t.Run("stop deadline ends first", func(t *testing.T) {
		var wg sync.WaitGroup
		wg.Add(1)
		t.Cleanup(wg.Done)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		if err := waitOrTimeout(ctx, &wg); !errors.Is(err, context.Canceled) {
			t.Errorf("waitOrTimeout() error = %v, want context.Canceled", err)
		}
	})
}
