package service

// =============================================================================
// TEST CASE OVERVIEW
// =============================================================================
//
// File: auth_service_test.go
// Purpose: Verify login, token authentication, refresh rotation, logout, session listing,
//          internal token endpoints and token cleanup of AuthService.
// Type: Unit (in-memory repository, real sealer, hasher, cache and login guard)
//
// Test functions: 37
// Total scenarios: 59
//
// #   Test Case                                                                Scenario                                          Expected Result
// 1   TestAuthService_Login_IssuesSealedTokensAndStoresOnlyHashes              Successful login                                  Tokens are sealed; only their hashes are stored; access token authenticates
// 2   TestAuthService_Login_InvalidCredentialsLookTheSame                      Wrong password vs. unknown email                  Both return ErrInvalidCredentials
// 3   TestAuthService_Login_InactiveUserOnlyAfterCorrectPassword               Inactive user, wrong then right password          ErrInvalidCredentials, then ErrUserInactive
// 4   TestAuthService_Login_SameDeviceDifferentIPRotatesSession                Same device ID from a new IP                      Same session rotated; old access token rejected
// 5   TestAuthService_Login_WithoutDeviceMatchesByIPAndUserAgent               Same IP and User-Agent                            Same session rotated
// 6   TestAuthService_Login_WithoutDeviceMatchesByIPAndUserAgent               Same IP, different User-Agent                     Separate session; the other one untouched
// 7   TestAuthService_Login_WithoutDeviceMatchesIPv6BySlash64                  IPv6 in the same /64, then another /64            Same /64 rotates; another /64 gets a new session
// 8   TestAuthService_Login_DifferentDeviceCreatesNewSession                   Two device IDs                                    Two separate sessions
// 9   TestAuthService_Login_BruteForceWarnsThenBlocks                          5 wrong passwords, then the right one             Warning from the 3rd failure; then ErrTooManyAttempts
// 10  TestAuthService_Login_ConcurrentAttemptsCannotExceedLimit                20 concurrent wrong passwords                     Exactly 5 reach the password check
// 11  TestAuthService_Login_SuccessClearsShortWindow                           4 failures, success, then a failure               Plain ErrInvalidCredentials (counter restarted)
// 12  TestAuthService_Login_FailuresElsewhereCannotLockTheOwnerOut             20 failures from other IPs                        Owner still logs in from their own IP
// 13  TestAuthService_Login_RecaptchaIsOptional                                Enabled, no verifier wired                        Login works
// 14  TestAuthService_Login_RecaptchaIsOptional                                Enabled, verifier fails                           ErrRecaptchaFailed
// 15  TestAuthService_Login_RecaptchaIsOptional                                Disabled, failing verifier wired                  Login works (verifier not called)
// 16  TestAuthService_AuthenticateAccess_RejectsNonAccessTokens                Refresh token                                     ErrInvalidTokenType
// 17  TestAuthService_AuthenticateAccess_RejectsNonAccessTokens                Raw unsealed token                                ErrInvalidToken
// 18  TestAuthService_AuthenticateAccess_RejectsNonAccessTokens                Stored token hash                                 ErrInvalidToken
// 19  TestAuthService_AuthenticateAccess_RejectsNonAccessTokens                Sealed token not in the database                  ErrInvalidToken
// 20  TestAuthService_AuthenticateAccess_RejectsExpiredTokenDespiteCache       Cached token after 16 minutes                     ErrTokenExpired
// 21  TestAuthService_AuthenticateAccess_RejectsDeactivatedUserDespiteCache    User deactivated and sessions revoked             Access and refresh return ErrUserInactive
// 22  TestAuthService_AuthenticateAccess_RejectsInactiveUserWithoutRevocation  User inactive, sessions not revoked               Access and refresh return ErrUserInactive
// 23  TestAuthService_AuthenticateAccess_ReturnsRepositoryError                Database fails                                    The database error, not ErrInvalidToken
// 24  TestAuthService_Logout_RevokesFamilyDespiteCache                         Logout of a cached session                        Access and refresh return ErrTokenRevoked
// 25  TestAuthService_LogoutAll_RevokesEverySession                            Two devices, LogoutAll                            Both access tokens return ErrTokenRevoked
// 26  TestAuthService_LogoutAndLogoutAll_ReturnRepositoryError                 Logout, database fails                            Returns the database error
// 27  TestAuthService_LogoutAndLogoutAll_ReturnRepositoryError                 LogoutAll, database fails                         Returns the database error
// 28  TestAuthService_Refresh_RotatesPairInSameSession                         Valid refresh token                               New pair in the same session; old access token revoked
// 29  TestAuthService_Refresh_ReuseRevokesWholeSession                         Old refresh token reused after the grace period   ErrTokenReused; the whole session revoked
// 30  TestAuthService_Refresh_RetryWithinGraceOnlyFails                        Old refresh token reused within the grace period  ErrTokenRevoked; the new pair still works
// 31  TestAuthService_Refresh_ReuseAfterReloginRevokesSession                  Refresh token from before a re-login              ErrTokenReused; the new session revoked
// 32  TestAuthService_Refresh_RejectsInvalidTokens                             Access token instead of refresh token             ErrInvalidTokenType
// 33  TestAuthService_Refresh_RejectsInvalidTokens                             Not a sealed token                                ErrInvalidToken
// 34  TestAuthService_Refresh_RejectsInvalidTokens                             Refresh token after 25 hours                      ErrTokenExpired
// 35  TestAuthService_Refresh_RejectsInvalidTokens                             Sealed token not in the database                  ErrInvalidToken
// 36  TestAuthService_Refresh_KeepsDeviceWhenHeaderMissing                     Refresh without a device ID                       Session keeps device phone-1
// 37  TestAuthService_Refresh_ReturnsRepositoryError                           Database fails                                    Returns the database error
// 38  TestAuthService_ListSessions_FlagsCurrent                                Two devices                                       Two sessions; only the caller's is flagged current
// 39  TestAuthService_ListSessions_ReturnsRepositoryError                      Database fails                                    Returns the database error
// 40  TestAuthService_GetTokenDetails_ReportsTypeAndStatus                     Refresh token of a live session                   refresh_token, active
// 41  TestAuthService_GetTokenDetails_ReportsTypeAndStatus                     Access token of a live session                    access_token, active
// 42  TestAuthService_GetTokenDetails_ReportsTypeAndStatus                     Access token superseded by a refresh              access_token, revoked
// 43  TestAuthService_GetTokenDetails_ReportsTypeAndStatus                     Access token after 16 minutes                     access_token, expired
// 44  TestAuthService_RevokeToken_RevokesTheTokensSession                      Revoke by refresh token                           Access token returns ErrTokenRevoked
// 45  TestAuthService_RevokeAllTokens_RevokesEveryDevice                       Revoke all by the phone's refresh token           Both devices return ErrTokenRevoked
// 46  TestAuthService_InternalTokenEndpoints_RejectInvalidTokens               GetTokenDetails, not a sealed token               ErrInvalidToken
// 47  TestAuthService_InternalTokenEndpoints_RejectInvalidTokens               GetTokenDetails, unknown sealed token             ErrTokenNotFound
// 48  TestAuthService_InternalTokenEndpoints_RejectInvalidTokens               GetTokenDetails, database fails                   Returns the database error
// 49  TestAuthService_InternalTokenEndpoints_RejectInvalidTokens               RevokeToken, not a sealed token                   ErrInvalidToken
// 50  TestAuthService_InternalTokenEndpoints_RejectInvalidTokens               RevokeToken, unknown sealed token                 ErrTokenNotFound
// 51  TestAuthService_InternalTokenEndpoints_RejectInvalidTokens               RevokeToken, database fails                       Returns the database error
// 52  TestAuthService_InternalTokenEndpoints_RejectInvalidTokens               RevokeAllTokens, not a sealed token               ErrInvalidToken
// 53  TestAuthService_InternalTokenEndpoints_RejectInvalidTokens               RevokeAllTokens, unknown sealed token             ErrTokenNotFound
// 54  TestAuthService_InternalTokenEndpoints_RejectInvalidTokens               RevokeAllTokens, database fails                   Returns the database error
// 55  TestAuthService_CleanupTokens_DeletesTokensRevokedBeforeRetention        Pair revoked 8 days ago, 7-day retention          2 tokens deleted; the live session survives
// 56  TestAuthService_CleanupTokens_KeepsLiveSessionStartAndLatestAccess       Session refreshed daily for 9 days                Session survives with its original start time
// 57  TestAuthService_CleanupTokens_KeepsExchangedRefreshTokenUntilItExpires   Exchanged token past retention, not expired       Kept, so its reuse is still detected
// 58  TestWaitOrTimeout_WaitsForBackgroundWork                                 Background work finishes                          Returns nil
// 59  TestWaitOrTimeout_WaitsForBackgroundWork                                 Stop deadline ends first                          Returns context.Canceled
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

	"github.com/jun-develop/junkit/security"

	"jungo/internal/config"
	"jungo/internal/features/auth/domain"
	useradapter "jungo/internal/features/user/adapter"
)

// fakeVerifier is a recaptcha.Verifier that always returns err.
type fakeVerifier struct{ err error }

func (f fakeVerifier) Verify(context.Context, string, string) error { return f.err }

// sealedUnknownToken returns a correctly sealed token whose hash is not in the database.
func sealedUnknownToken(t *testing.T, e *testEnv) string {
	t.Helper()
	token, err := e.sealer.Seal(security.GenerateToken())
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}

	return token
}

// =============================================================================
// Login
// =============================================================================

func TestAuthService_Login_IssuesSealedTokensAndStoresOnlyHashes(t *testing.T) {
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

		if stored.hash == raw {
			t.Error("stored value is the raw token, want only its hash")
		}

		if strings.Contains(tok, raw) {
			t.Error("sealed token contains the raw token")
		}
	}

	id := mustAuthenticate(t, e, pair.AccessToken)
	if id.UserUUID != e.user.uuid {
		t.Errorf("identity user = %v, want %v", id.UserUUID, e.user.uuid)
	}

	if id.Session == nil {
		t.Error("identity session = nil, want the loaded session")
	}
}

func TestAuthService_Login_InvalidCredentialsLookTheSame(t *testing.T) {
	e := newTestEnv(t)

	_, errWrongPassword := e.svc.Login(context.Background(), domain.LoginInput{Email: e.user.email, Password: "nope", Metadata: browser})
	_, errUnknownEmail := e.svc.Login(context.Background(), domain.LoginInput{Email: "ghost@example.com", Password: "nope", Metadata: domain.Metadata{IPAddress: "198.51.100.1"}})

	wantErr(t, errWrongPassword, domain.ErrInvalidCredentials)
	wantErr(t, errUnknownEmail, domain.ErrInvalidCredentials)
}

func TestAuthService_Login_InactiveUserOnlyAfterCorrectPassword(t *testing.T) {
	e := newTestEnv(t)
	e.user.active = false

	_, err := e.svc.Login(context.Background(), domain.LoginInput{Email: e.user.email, Password: "nope", Metadata: browser})
	wantErr(t, err, domain.ErrInvalidCredentials)

	_, err = e.svc.Login(context.Background(), domain.LoginInput{Email: e.user.email, Password: testPassword, Metadata: browser})
	wantErr(t, err, domain.ErrUserInactive)
}

func TestAuthService_Login_SameDeviceDifferentIPRotatesSession(t *testing.T) {
	e := newTestEnv(t)
	first := e.login(t, domain.Metadata{IPAddress: "203.0.113.10", UserAgent: "App", DeviceID: "phone-1"})
	// Cached, so a later change must invalidate it.
	firstID := mustAuthenticate(t, e, first.AccessToken)

	second := e.login(t, domain.Metadata{IPAddress: "198.51.100.7", UserAgent: "App", DeviceID: "phone-1"})
	secondID := mustAuthenticate(t, e, second.AccessToken)

	if secondID.FamilyUUID != firstID.FamilyUUID {
		t.Error("login from the same device created a new session instead of rotating")
	}

	if _, err := e.authenticate(t, first.AccessToken); err == nil {
		t.Error("access token from before the rotation still authenticates")
	}
}

func TestAuthService_Login_WithoutDeviceMatchesByIPAndUserAgent(t *testing.T) {
	e := newTestEnv(t)
	first := e.login(t, browser)
	firstID := mustAuthenticate(t, e, first.AccessToken)

	// The subtests run in order on the same environment.
	t.Run("same IP and User-Agent rotates", func(t *testing.T) {
		again := e.login(t, browser)
		if id := mustAuthenticate(t, e, again.AccessToken); id.FamilyUUID != firstID.FamilyUUID {
			t.Error("login with the same IP and User-Agent created a new session, want the same one rotated")
		}
	})

	t.Run("same IP, different User-Agent creates a separate session", func(t *testing.T) {
		chromeMeta := domain.Metadata{IPAddress: browser.IPAddress, UserAgent: "Chrome"}
		chrome := e.login(t, chromeMeta)
		chromeID := mustAuthenticate(t, e, chrome.AccessToken)
		if chromeID.FamilyUUID == firstID.FamilyUUID {
			t.Error("a different browser behind the same IP rotated the other browser's session")
		}

		if got := e.repo.activeFamilyCount(firstID.FamilyUUID); got != 2 {
			t.Errorf("active tokens in the Firefox session = %d, want 2 (not revoked by the Chrome login)", got)
		}
	})
}

func TestAuthService_Login_WithoutDeviceMatchesIPv6BySlash64(t *testing.T) {
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

func TestAuthService_Login_DifferentDeviceCreatesNewSession(t *testing.T) {
	e := newTestEnv(t)
	phone := mustAuthenticate(t, e, e.login(t, domain.Metadata{IPAddress: "203.0.113.10", DeviceID: "phone-1"}).AccessToken)
	laptop := mustAuthenticate(t, e, e.login(t, domain.Metadata{IPAddress: "203.0.113.10", DeviceID: "laptop-1"}).AccessToken)

	if phone.FamilyUUID == laptop.FamilyUUID {
		t.Error("two devices share one session, want one session per device")
	}
}

// =============================================================================
// Brute-force protection
// =============================================================================

func TestAuthService_Login_BruteForceWarnsThenBlocks(t *testing.T) {
	e := newTestEnv(t)
	bad := domain.LoginInput{Email: e.user.email, Password: "wrong", Metadata: browser}

	var errs []error
	for range 5 {
		_, err := e.svc.Login(context.Background(), bad)
		errs = append(errs, err)
	}

	wantErr(t, errs[0], domain.ErrInvalidCredentials)
	wantErr(t, errs[1], domain.ErrInvalidCredentials)
	// From the 3rd failure on, 2 or fewer attempts are left.
	wantErr(t, errs[2], domain.ErrInvalidCredentialsWarning)
	wantErr(t, errs[3], domain.ErrInvalidCredentialsWarning)
	wantErr(t, errs[4], domain.ErrInvalidCredentialsWarning)

	// Blocked now, even with the right password.
	_, err := e.svc.Login(context.Background(), domain.LoginInput{Email: e.user.email, Password: testPassword, Metadata: browser})
	wantErr(t, err, domain.ErrTooManyAttempts)
}

func TestAuthService_Login_ConcurrentAttemptsCannotExceedLimit(t *testing.T) {
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

func TestAuthService_Login_SuccessClearsShortWindow(t *testing.T) {
	e := newTestEnv(t)
	bad := domain.LoginInput{Email: e.user.email, Password: "wrong", Metadata: browser}
	for i := range 4 {
		if _, err := e.svc.Login(context.Background(), bad); err == nil {
			t.Fatalf("failed attempt %d: Login() error = nil, want a rejection", i+1)
		}
	}

	e.login(t, browser)

	_, err := e.svc.Login(context.Background(), bad)
	// The counter restarted: no warning yet.
	wantErr(t, err, domain.ErrInvalidCredentials)
}

func TestAuthService_Login_FailuresElsewhereCannotLockTheOwnerOut(t *testing.T) {
	e := newTestEnv(t)
	for i := range 20 {
		ip := "198.51.100." + strconv.Itoa(i)
		if _, err := e.svc.Login(context.Background(), domain.LoginInput{Email: e.user.email, Password: "wrong", Metadata: domain.Metadata{IPAddress: ip}}); err == nil {
			t.Fatalf("attempt from %s: Login() error = nil, want a rejection", ip)
		}
	}

	e.login(t, domain.Metadata{IPAddress: "192.0.2.99"})
}

func TestAuthService_Login_RecaptchaIsOptional(t *testing.T) {
	enable := func(cfg *config.Config, _ *AuthServiceParams) { cfg.Auth.RecaptchaOnLogin = true }

	t.Run("enabled but no verifier wired: login works", func(t *testing.T) {
		e := newTestEnv(t, enable)
		e.login(t, browser)
	})

	t.Run("enabled with a failing verifier: rejected", func(t *testing.T) {
		e := newTestEnv(t, enable, func(_ *config.Config, p *AuthServiceParams) { p.Recaptcha = fakeVerifier{err: errors.New("bad")} })
		_, err := e.svc.Login(context.Background(), domain.LoginInput{Email: e.user.email, Password: testPassword, Metadata: browser})
		wantErr(t, err, domain.ErrRecaptchaFailed)
	})

	t.Run("disabled: verifier not called", func(t *testing.T) {
		e := newTestEnv(t, func(_ *config.Config, p *AuthServiceParams) { p.Recaptcha = fakeVerifier{err: errors.New("bad")} })
		e.login(t, browser)
	})
}

// =============================================================================
// AuthenticateAccess
// =============================================================================

func TestAuthService_AuthenticateAccess_RejectsNonAccessTokens(t *testing.T) {
	e := newTestEnv(t)
	pair := e.login(t, browser)
	raw, err := e.sealer.Open(pair.AccessToken)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	tests := []struct {
		name  string
		token string
		want  error
	}{
		{"refresh token", pair.RefreshToken, domain.ErrInvalidTokenType},
		{"raw unsealed token", raw, domain.ErrInvalidToken},
		{"stored token hash", security.HashToken(raw), domain.ErrInvalidToken},
		{"sealed token not in the database", sealedUnknownToken(t, e), domain.ErrInvalidToken},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := e.authenticate(t, tt.token)
			wantErr(t, err, tt.want)
		})
	}
}

func TestAuthService_AuthenticateAccess_RejectsExpiredTokenDespiteCache(t *testing.T) {
	e := newTestEnv(t)
	pair := e.login(t, browser)
	mustAuthenticate(t, e, pair.AccessToken)

	// Expiry is checked even on cache hits.
	e.clock.Advance(16 * time.Minute)
	_, err := e.authenticate(t, pair.AccessToken)
	wantErr(t, err, domain.ErrTokenExpired)
}

func TestAuthService_AuthenticateAccess_RejectsDeactivatedUserDespiteCache(t *testing.T) {
	e := newTestEnv(t)
	pair := e.login(t, browser)
	// Cached, so a later change must invalidate it.
	mustAuthenticate(t, e, pair.AccessToken)

	// What UserService does on deactivation: revoke in its transaction, then drop the cache.
	e.user.active = false
	revoker := useradapter.NewSessionRevokerAdapter(e.repo, e.cache)
	if err := revoker.RevokeUserSessions(context.Background(), e.user.uuid); err != nil {
		t.Fatalf("RevokeUserSessions() error = %v", err)
	}

	revoker.InvalidateUserSessions(context.Background(), e.user.uuid)

	_, err := e.authenticate(t, pair.AccessToken)
	wantErr(t, err, domain.ErrUserInactive)

	_, err = e.svc.Refresh(context.Background(), pair.RefreshToken, browser)
	wantErr(t, err, domain.ErrUserInactive)
}

func TestAuthService_AuthenticateAccess_RejectsInactiveUserWithoutRevocation(t *testing.T) {
	e := newTestEnv(t)
	pair := e.login(t, browser)

	// Status changed outside the user service, so no session was revoked.
	e.user.active = false

	_, err := e.authenticate(t, pair.AccessToken)
	wantErr(t, err, domain.ErrUserInactive)

	_, err = e.svc.Refresh(context.Background(), pair.RefreshToken, browser)
	wantErr(t, err, domain.ErrUserInactive)
}

func TestAuthService_AuthenticateAccess_ReturnsRepositoryError(t *testing.T) {
	var repo *failingRepo
	e := newTestEnv(t, withFailingRepo(&repo))
	pair := e.login(t, browser)
	repo.err = errDB

	_, err := e.authenticate(t, pair.AccessToken)

	// A database outage must not be reported as a bad token.
	wantErr(t, err, errDB)
}

// =============================================================================
// Logout
// =============================================================================

func TestAuthService_Logout_RevokesFamilyDespiteCache(t *testing.T) {
	e := newTestEnv(t)
	pair := e.login(t, browser)
	// Cached, so a later change must invalidate it.
	id := mustAuthenticate(t, e, pair.AccessToken)

	if err := e.svc.Logout(context.Background(), id); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}

	_, err := e.authenticate(t, pair.AccessToken)
	wantErr(t, err, domain.ErrTokenRevoked)
	_, err = e.svc.Refresh(context.Background(), pair.RefreshToken, browser)
	wantErr(t, err, domain.ErrTokenRevoked)
}

func TestAuthService_LogoutAll_RevokesEverySession(t *testing.T) {
	e := newTestEnv(t)
	phone := e.login(t, domain.Metadata{DeviceID: "phone"})
	laptop := e.login(t, domain.Metadata{DeviceID: "laptop"})
	id := mustAuthenticate(t, e, phone.AccessToken)
	mustAuthenticate(t, e, laptop.AccessToken)

	if err := e.svc.LogoutAll(context.Background(), id); err != nil {
		t.Fatalf("LogoutAll() error = %v", err)
	}

	for _, tok := range []string{phone.AccessToken, laptop.AccessToken} {
		_, err := e.authenticate(t, tok)
		wantErr(t, err, domain.ErrTokenRevoked)
	}
}

func TestAuthService_LogoutAndLogoutAll_ReturnRepositoryError(t *testing.T) {
	tests := []struct {
		name   string
		logout func(s *AuthService, id *domain.Identity) error
	}{
		{"Logout", func(s *AuthService, id *domain.Identity) error { return s.Logout(context.Background(), id) }},
		{"LogoutAll", func(s *AuthService, id *domain.Identity) error { return s.LogoutAll(context.Background(), id) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var repo *failingRepo
			e := newTestEnv(t, withFailingRepo(&repo))
			id := mustAuthenticate(t, e, e.login(t, browser).AccessToken)
			repo.err = errDB

			wantErr(t, tt.logout(e.svc, id), errDB)
		})
	}
}

// =============================================================================
// Refresh
// =============================================================================

func TestAuthService_Refresh_RotatesPairInSameSession(t *testing.T) {
	e := newTestEnv(t)
	old := e.login(t, browser)
	// Cached, so a later change must invalidate it.
	oldID := mustAuthenticate(t, e, old.AccessToken)

	fresh, err := e.svc.Refresh(context.Background(), old.RefreshToken, browser)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}

	newID := mustAuthenticate(t, e, fresh.AccessToken)
	if newID.FamilyUUID != oldID.FamilyUUID {
		t.Error("refresh changed the session family, want the same session")
	}

	_, err = e.authenticate(t, old.AccessToken)
	wantErr(t, err, domain.ErrTokenRevoked)
}

func TestAuthService_Refresh_ReuseRevokesWholeSession(t *testing.T) {
	e := newTestEnv(t)
	old := e.login(t, browser)
	fresh, err := e.svc.Refresh(context.Background(), old.RefreshToken, browser)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}

	// Cached, so the revocation below must invalidate it.
	mustAuthenticate(t, e, fresh.AccessToken)

	e.clock.Advance(reuseGrace + time.Second)
	_, err = e.svc.Refresh(context.Background(), old.RefreshToken, browser)
	wantErr(t, err, domain.ErrTokenReused)

	_, err = e.authenticate(t, fresh.AccessToken)
	wantErr(t, err, domain.ErrTokenRevoked)
	_, err = e.svc.Refresh(context.Background(), fresh.RefreshToken, browser)
	wantErr(t, err, domain.ErrTokenRevoked)
}

func TestAuthService_Refresh_RetryWithinGraceOnlyFails(t *testing.T) {
	e := newTestEnv(t)
	old := e.login(t, browser)
	fresh, err := e.svc.Refresh(context.Background(), old.RefreshToken, browser)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}

	// A second tab refreshing with the same token at once must not log the user out.
	_, err = e.svc.Refresh(context.Background(), old.RefreshToken, browser)
	wantErr(t, err, domain.ErrTokenRevoked)
	mustAuthenticate(t, e, fresh.AccessToken)
}

func TestAuthService_Refresh_ReuseAfterReloginRevokesSession(t *testing.T) {
	e := newTestEnv(t)
	old := e.login(t, browser)
	again := e.login(t, browser)

	e.clock.Advance(reuseGrace + time.Second)
	_, err := e.svc.Refresh(context.Background(), old.RefreshToken, browser)
	wantErr(t, err, domain.ErrTokenReused)

	_, err = e.authenticate(t, again.AccessToken)
	wantErr(t, err, domain.ErrTokenRevoked)
}

func TestAuthService_Refresh_RejectsInvalidTokens(t *testing.T) {
	tests := []struct {
		name  string
		token func(t *testing.T, e *testEnv, pair *domain.TokenPair) string
		want  error
	}{
		{
			name:  "access token instead of refresh token",
			token: func(_ *testing.T, _ *testEnv, pair *domain.TokenPair) string { return pair.AccessToken },
			want:  domain.ErrInvalidTokenType,
		},
		{
			name:  "not a sealed token",
			token: func(*testing.T, *testEnv, *domain.TokenPair) string { return "garbage" },
			want:  domain.ErrInvalidToken,
		},
		{
			name: "expired refresh token",
			token: func(_ *testing.T, e *testEnv, pair *domain.TokenPair) string {
				e.clock.Advance(25 * time.Hour)
				return pair.RefreshToken
			},
			want: domain.ErrTokenExpired,
		},
		{
			name:  "sealed token not in the database",
			token: func(t *testing.T, e *testEnv, _ *domain.TokenPair) string { return sealedUnknownToken(t, e) },
			want:  domain.ErrInvalidToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newTestEnv(t)
			pair := e.login(t, browser)

			_, err := e.svc.Refresh(context.Background(), tt.token(t, e, pair), browser)

			wantErr(t, err, tt.want)
		})
	}
}

func TestAuthService_Refresh_KeepsDeviceWhenHeaderMissing(t *testing.T) {
	e := newTestEnv(t)
	pair := e.login(t, domain.Metadata{DeviceID: "phone-1"})

	fresh, err := e.svc.Refresh(context.Background(), pair.RefreshToken, domain.Metadata{})
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}

	id := mustAuthenticate(t, e, fresh.AccessToken)
	if id.Session.DeviceID == nil {
		t.Fatal("device after refresh = nil, want phone-1")
	}

	if *id.Session.DeviceID != "phone-1" {
		t.Errorf("device after refresh = %q, want phone-1", *id.Session.DeviceID)
	}
}

func TestAuthService_Refresh_ReturnsRepositoryError(t *testing.T) {
	var repo *failingRepo
	e := newTestEnv(t, withFailingRepo(&repo))
	pair := e.login(t, browser)
	repo.err = errDB

	_, err := e.svc.Refresh(context.Background(), pair.RefreshToken, browser)

	wantErr(t, err, errDB)
}

// =============================================================================
// Sessions
// =============================================================================

func TestAuthService_ListSessions_FlagsCurrent(t *testing.T) {
	e := newTestEnv(t)
	phone := e.login(t, domain.Metadata{DeviceID: "phone"})
	e.login(t, domain.Metadata{DeviceID: "laptop"})
	id := mustAuthenticate(t, e, phone.AccessToken)

	sessions, err := e.svc.ListSessions(context.Background(), id)
	if err != nil {
		t.Fatalf("ListSessions() error = %v", err)
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

func TestAuthService_ListSessions_ReturnsRepositoryError(t *testing.T) {
	var repo *failingRepo
	e := newTestEnv(t, withFailingRepo(&repo))
	id := mustAuthenticate(t, e, e.login(t, browser).AccessToken)
	repo.err = errDB

	_, err := e.svc.ListSessions(context.Background(), id)

	wantErr(t, err, errDB)
}

// =============================================================================
// Internal token endpoints
// =============================================================================

func TestAuthService_GetTokenDetails_ReportsTypeAndStatus(t *testing.T) {
	tests := []struct {
		name       string
		token      func(t *testing.T, e *testEnv, pair *domain.TokenPair) string
		wantType   domain.TokenType
		wantStatus string
	}{
		{
			name:       "refresh token of a live session",
			token:      func(_ *testing.T, _ *testEnv, pair *domain.TokenPair) string { return pair.RefreshToken },
			wantType:   domain.TokenTypeRefresh,
			wantStatus: domain.TokenStatusActive,
		},
		{
			name:       "access token of a live session",
			token:      func(_ *testing.T, _ *testEnv, pair *domain.TokenPair) string { return pair.AccessToken },
			wantType:   domain.TokenTypeAccess,
			wantStatus: domain.TokenStatusActive,
		},
		{
			name: "access token superseded by a refresh",
			token: func(t *testing.T, e *testEnv, pair *domain.TokenPair) string {
				if _, err := e.svc.Refresh(context.Background(), pair.RefreshToken, browser); err != nil {
					t.Fatalf("Refresh() error = %v", err)
				}

				return pair.AccessToken
			},
			wantType:   domain.TokenTypeAccess,
			wantStatus: domain.TokenStatusRevoked,
		},
		{
			name: "expired access token",
			token: func(_ *testing.T, e *testEnv, pair *domain.TokenPair) string {
				e.clock.Advance(16 * time.Minute)
				return pair.AccessToken
			},
			wantType:   domain.TokenTypeAccess,
			wantStatus: domain.TokenStatusExpired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newTestEnv(t)
			pair := e.login(t, browser)

			details, err := e.svc.GetTokenDetails(context.Background(), tt.token(t, e, pair))

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

func TestAuthService_RevokeToken_RevokesTheTokensSession(t *testing.T) {
	e := newTestEnv(t)
	pair := e.login(t, browser)
	mustAuthenticate(t, e, pair.AccessToken)

	if err := e.svc.RevokeToken(context.Background(), pair.RefreshToken); err != nil {
		t.Fatalf("RevokeToken() error = %v", err)
	}

	_, err := e.authenticate(t, pair.AccessToken)
	wantErr(t, err, domain.ErrTokenRevoked)
}

func TestAuthService_RevokeAllTokens_RevokesEveryDevice(t *testing.T) {
	e := newTestEnv(t)
	phone := e.login(t, domain.Metadata{DeviceID: "phone"})
	laptop := e.login(t, domain.Metadata{DeviceID: "laptop"})
	mustAuthenticate(t, e, phone.AccessToken)
	mustAuthenticate(t, e, laptop.AccessToken)

	if err := e.svc.RevokeAllTokens(context.Background(), phone.RefreshToken); err != nil {
		t.Fatalf("RevokeAllTokens() error = %v", err)
	}

	for _, tok := range []string{phone.AccessToken, laptop.AccessToken} {
		_, err := e.authenticate(t, tok)
		wantErr(t, err, domain.ErrTokenRevoked)
	}
}

func TestAuthService_InternalTokenEndpoints_RejectInvalidTokens(t *testing.T) {
	endpoints := []struct {
		name string
		call func(s *AuthService, token string) error
	}{
		{"GetTokenDetails", func(s *AuthService, token string) error {
			_, err := s.GetTokenDetails(context.Background(), token)
			return err
		}},
		{"RevokeToken", func(s *AuthService, token string) error { return s.RevokeToken(context.Background(), token) }},
		{"RevokeAllTokens", func(s *AuthService, token string) error { return s.RevokeAllTokens(context.Background(), token) }},
	}

	tests := []struct {
		name string
		want error
	}{
		{"not a sealed token", domain.ErrInvalidToken},
		{"sealed token not in the database", domain.ErrTokenNotFound},
		{"repository fails", errDB},
	}

	for _, ep := range endpoints {
		for _, tt := range tests {
			t.Run(ep.name+": "+tt.name, func(t *testing.T) {
				var repo *failingRepo
				e := newTestEnv(t, withFailingRepo(&repo))
				token := "garbage"
				switch tt.want {
				case domain.ErrTokenNotFound:
					token = sealedUnknownToken(t, e)
				case errDB:
					token = e.login(t, browser).RefreshToken
					repo.err = errDB
				}

				wantErr(t, ep.call(e.svc, token), tt.want)
			})
		}
	}
}

// =============================================================================
// Cleanup
// =============================================================================

func TestAuthService_CleanupTokens_DeletesTokensRevokedBeforeRetention(t *testing.T) {
	e := newTestEnv(t)
	pair := e.login(t, browser)
	id := mustAuthenticate(t, e, pair.AccessToken)
	if err := e.svc.Logout(context.Background(), id); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}

	e.clock.Advance(8 * 24 * time.Hour)
	fresh := e.login(t, browser)

	deleted, err := e.svc.CleanupTokens(context.Background(), 7*24*time.Hour)
	if err != nil {
		t.Fatalf("CleanupTokens() error = %v", err)
	}

	if deleted != 2 {
		t.Errorf("deleted = %d, want 2 (the pair revoked 8 days ago)", deleted)
	}

	mustAuthenticate(t, e, fresh.AccessToken)
}

func TestAuthService_CleanupTokens_KeepsLiveSessionStartAndLatestAccess(t *testing.T) {
	e := newTestEnv(t)
	started := e.clock.Now()
	pair := e.login(t, browser)

	// Refresh daily for 9 days: the first pair is revoked well past the 7-day retention.
	for range 9 {
		e.clock.Advance(23 * time.Hour)
		next, err := e.svc.Refresh(context.Background(), pair.RefreshToken, browser)
		if err != nil {
			t.Fatalf("Refresh() error = %v", err)
		}

		pair = next
	}

	if _, err := e.svc.CleanupTokens(context.Background(), 7*24*time.Hour); err != nil {
		t.Fatalf("CleanupTokens() error = %v", err)
	}

	details, err := e.svc.GetTokenDetails(context.Background(), pair.RefreshToken)
	if err != nil {
		t.Fatalf("GetTokenDetails() error = %v, want the live session to survive cleanup", err)
	}

	if !details.Session.CreatedAt.Equal(started) {
		t.Errorf("session CreatedAt = %v, want %v (the login time)", details.Session.CreatedAt, started)
	}
}

func TestAuthService_CleanupTokens_KeepsExchangedRefreshTokenUntilItExpires(t *testing.T) {
	e := newTestEnv(t)
	old := e.login(t, browser)
	if _, err := e.svc.Refresh(context.Background(), old.RefreshToken, browser); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}

	// Revoked 2h ago, past a 1h retention, but valid for 22h more had it not been exchanged.
	e.clock.Advance(2 * time.Hour)
	if _, err := e.svc.CleanupTokens(context.Background(), time.Hour); err != nil {
		t.Fatalf("CleanupTokens() error = %v", err)
	}

	_, err := e.svc.Refresh(context.Background(), old.RefreshToken, browser)
	wantErr(t, err, domain.ErrTokenReused)
}

// =============================================================================
// Shutdown
// =============================================================================

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
