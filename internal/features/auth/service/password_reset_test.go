package service

// =============================================================================
// TEST CASE OVERVIEW
// =============================================================================
//
// File: password_reset_test.go
// Purpose: Verify the forgot/reset password flow: emailed single-use links, throttling, setup
//          checks, background send failures and the rendered email.
// Type: Unit (in-memory repository, fake mailer)
//
// Test functions: 11
// Total scenarios: 16
//
// #   Test Case                                                           Scenario                                     Expected Result
// 1   TestAuthService_ResetPassword_ReplacesPasswordAndEndsSessions       Emailed link used with a new password        Sessions revoked; old password fails, new works; link single-use
// 2   TestAuthService_ForgotPassword_UnknownAndInactiveEmailsLookTheSame  Unknown email, then inactive user            Both return nil; no email sent
// 3   TestAuthService_ForgotPassword_NewerLinkReplacesOlder               Two requests                                 First link rejected; latest link works
// 4   TestAuthService_ResetPassword_RejectsInvalidTokens                  Not a reset token                            ErrInvalidResetToken
// 5   TestAuthService_ResetPassword_RejectsInvalidTokens                  Token past its 30-minute lifetime            ErrInvalidResetToken
// 6   TestAuthService_ResetPassword_TooLongPasswordKeepsToken             80-byte password, then a valid one           ErrPasswordTooLong; the token still works
// 7   TestAuthService_ForgotPassword_ThrottlesPerEmailAndPerIP            4 requests for one email from different IPs  4th returns ErrTooManyResetRequests
// 8   TestAuthService_ForgotPassword_ThrottlesPerEmailAndPerIP            6 requests from one IP for different emails  6th returns ErrTooManyResetRequests
// 9   TestAuthService_ForgotPassword_UnavailableWithoutEmailSetup         No reset URL                                 ErrPasswordResetUnavailable
// 10  TestAuthService_ForgotPassword_UnavailableWithoutEmailSetup         No mailer wired                              ErrPasswordResetUnavailable
// 11  TestAuthService_ForgotPassword_UnavailableWithoutEmailSetup         Log mail driver outside development          ErrPasswordResetUnavailable
// 12  TestAuthService_ForgotPassword_LogDriverAllowedInDevelopment        Log mail driver in development               Email handed to the mailer
// 13  TestAuthService_ForgotPassword_ReturnsUserLookupError               User lookup fails                            Returns the lookup error
// 14  TestAuthService_ForgotPassword_LogsBackgroundSendFailures           Reset token cannot be stored                 Returns nil; no email; failure logged
// 15  TestAuthService_ForgotPassword_LogsBackgroundSendFailures           Mailer fails                                 Returns nil; failure logged
// 16  TestResetEmail_RendersAndEscapes                                    Name with HTML, link with a query            HTML escapes name and link; text keeps the raw link and signature
//
// =============================================================================

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/jun-develop/junkit/mailer"

	"jungo/internal/config"
	"jungo/internal/features/auth/domain"
)

// fakeMailer records sent messages on a channel (ForgotPassword sends in the background) and
// returns err from every Send.
type fakeMailer struct {
	sent chan mailer.Message
	err  error
}

func (f *fakeMailer) Send(_ context.Context, msg mailer.Message) error {
	f.sent <- msg
	return f.err
}

func newMailer() *fakeMailer { return &fakeMailer{sent: make(chan mailer.Message, 10)} }

// withPasswordReset configures password reset with a real mail driver and the given mailer.
func withPasswordReset(m *fakeMailer) envOption {
	return func(cfg *config.Config, p *AuthServiceParams) {
		cfg.Auth.PasswordResetURL = "https://app.example.com/reset-password?lang=vi"
		cfg.Auth.PasswordResetTTL = 30 * time.Minute
		cfg.Auth.PasswordResetWindow = time.Hour
		cfg.Auth.PasswordResetIPMax = 5
		cfg.Auth.PasswordResetEmailMax = 3
		cfg.Mail.Driver = string(mailer.DriverSMTP)
		p.Mailer = m
	}
}

// withObservedLogs makes the service log into the returned recorder.
func withObservedLogs(logs **observer.ObservedLogs) envOption {
	return func(_ *config.Config, p *AuthServiceParams) {
		core, recorded := observer.New(zap.InfoLevel)
		*logs = recorded
		p.Logger = zap.New(core)
	}
}

// waitMail returns the next sent message, failing after a second.
func waitMail(t *testing.T, m *fakeMailer) mailer.Message {
	t.Helper()
	select {
	case msg := <-m.sent:
		return msg
	case <-time.After(time.Second):
		t.Fatal("no email sent within 1s, want one")
		return mailer.Message{}
	}
}

// noMail fails if a message is sent shortly.
func noMail(t *testing.T, m *fakeMailer) {
	t.Helper()
	select {
	case msg := <-m.sent:
		t.Fatalf("email sent to %v, want none", msg.To)
	case <-time.After(50 * time.Millisecond):
	}
}

var linkToken = regexp.MustCompile(`https://\S+`)

// tokenFrom extracts the reset token from the email's text link.
func tokenFrom(t *testing.T, msg mailer.Message) string {
	t.Helper()
	u, err := url.Parse(linkToken.FindString(msg.Text))
	if err != nil {
		t.Fatalf("parse reset link: %v", err)
	}

	if u.Query().Get("lang") != "vi" {
		t.Fatalf("link lost the configured query: %s", u)
	}

	return u.Query().Get("token")
}

// requestResetToken asks for a reset link for the test user and returns the emailed token.
func requestResetToken(t *testing.T, e *testEnv, m *fakeMailer) string {
	t.Helper()
	if err := e.svc.ForgotPassword(context.Background(), e.user.email, browser); err != nil {
		t.Fatalf("ForgotPassword() error = %v", err)
	}

	return tokenFrom(t, waitMail(t, m))
}

// =============================================================================
// ForgotPassword + ResetPassword
// =============================================================================

func TestAuthService_ResetPassword_ReplacesPasswordAndEndsSessions(t *testing.T) {
	m := newMailer()
	e := newTestEnv(t, withPasswordReset(m))
	ctx := context.Background()
	old := e.login(t, browser)

	if err := e.svc.ForgotPassword(ctx, e.user.email, browser); err != nil {
		t.Fatalf("ForgotPassword() error = %v", err)
	}

	msg := waitMail(t, m)
	if len(msg.To) != 1 || msg.To[0] != e.user.email {
		t.Fatalf("email To = %v, want [%s]", msg.To, e.user.email)
	}

	if !strings.Contains(msg.HTML, "Hi Jane Doe") {
		t.Fatalf("email HTML does not greet the user by name:\n%s", msg.HTML)
	}

	token := tokenFrom(t, msg)
	if err := e.svc.ResetPassword(ctx, token, "New-passw0rd!"); err != nil {
		t.Fatalf("ResetPassword() error = %v", err)
	}

	// Old sessions end, the old password stops working, the new one works.
	_, err := e.authenticate(t, old.AccessToken)
	wantErr(t, err, domain.ErrTokenRevoked)

	_, err = e.svc.Login(ctx, domain.LoginInput{Email: e.user.email, Password: testPassword, Metadata: browser})
	wantErr(t, err, domain.ErrInvalidCredentials)

	if _, err := e.svc.Login(ctx, domain.LoginInput{Email: e.user.email, Password: "New-passw0rd!", Metadata: browser}); err != nil {
		t.Fatalf("Login() with the new password error = %v", err)
	}

	// The token works once.
	wantErr(t, e.svc.ResetPassword(ctx, token, "Another-passw0rd!"), domain.ErrInvalidResetToken)
}

func TestAuthService_ForgotPassword_UnknownAndInactiveEmailsLookTheSame(t *testing.T) {
	m := newMailer()
	e := newTestEnv(t, withPasswordReset(m))

	if err := e.svc.ForgotPassword(context.Background(), "nobody@example.com", browser); err != nil {
		t.Fatalf("ForgotPassword(unknown email) error = %v, want nil", err)
	}

	e.user.active = false
	if err := e.svc.ForgotPassword(context.Background(), e.user.email, browser); err != nil {
		t.Fatalf("ForgotPassword(inactive user) error = %v, want nil", err)
	}

	noMail(t, m)
}

func TestAuthService_ForgotPassword_NewerLinkReplacesOlder(t *testing.T) {
	m := newMailer()
	e := newTestEnv(t, withPasswordReset(m))
	ctx := context.Background()

	first := requestResetToken(t, e, m)
	second := requestResetToken(t, e, m)

	wantErr(t, e.svc.ResetPassword(ctx, first, "New-passw0rd!"), domain.ErrInvalidResetToken)
	if err := e.svc.ResetPassword(ctx, second, "New-passw0rd!"); err != nil {
		t.Fatalf("ResetPassword(latest token) error = %v", err)
	}
}

func TestAuthService_ResetPassword_RejectsInvalidTokens(t *testing.T) {
	t.Run("not a reset token", func(t *testing.T) {
		e := newTestEnv(t, withPasswordReset(newMailer()))

		wantErr(t, e.svc.ResetPassword(context.Background(), "garbage", "New-passw0rd!"), domain.ErrInvalidResetToken)
	})

	t.Run("token past its 30-minute lifetime", func(t *testing.T) {
		m := newMailer()
		e := newTestEnv(t, withPasswordReset(m))
		token := requestResetToken(t, e, m)

		e.clock.Advance(31 * time.Minute)

		wantErr(t, e.svc.ResetPassword(context.Background(), token, "New-passw0rd!"), domain.ErrInvalidResetToken)
	})
}

func TestAuthService_ResetPassword_TooLongPasswordKeepsToken(t *testing.T) {
	m := newMailer()
	e := newTestEnv(t, withPasswordReset(m))
	ctx := context.Background()
	token := requestResetToken(t, e, m)

	wantErr(t, e.svc.ResetPassword(ctx, token, strings.Repeat("é", 40)), domain.ErrPasswordTooLong)
	if err := e.svc.ResetPassword(ctx, token, "New-passw0rd!"); err != nil {
		t.Fatalf("ResetPassword() after a rejected password error = %v, want the token to still work", err)
	}
}

func TestAuthService_ForgotPassword_ThrottlesPerEmailAndPerIP(t *testing.T) {
	ctx := context.Background()

	t.Run("per email, across IPs: 3 allowed", func(t *testing.T) {
		e := newTestEnv(t, withPasswordReset(newMailer()))
		for i := range 3 {
			ip := domain.Metadata{IPAddress: "198.51.100." + string(rune('1'+i))}
			if err := e.svc.ForgotPassword(ctx, e.user.email, ip); err != nil {
				t.Fatalf("request %d: ForgotPassword() error = %v", i+1, err)
			}
		}

		wantErr(t, e.svc.ForgotPassword(ctx, e.user.email, domain.Metadata{IPAddress: "198.51.100.9"}), domain.ErrTooManyResetRequests)
	})

	t.Run("per IP, across emails registered or not: 5 allowed", func(t *testing.T) {
		e := newTestEnv(t, withPasswordReset(newMailer()))
		for i := range 5 {
			if err := e.svc.ForgotPassword(ctx, "user"+string(rune('a'+i))+"@example.com", browser); err != nil {
				t.Fatalf("request %d: ForgotPassword() error = %v", i+1, err)
			}
		}

		wantErr(t, e.svc.ForgotPassword(ctx, "other@example.com", browser), domain.ErrTooManyResetRequests)
	})
}

func TestAuthService_ForgotPassword_UnavailableWithoutEmailSetup(t *testing.T) {
	tests := []struct {
		name string
		opt  envOption
	}{
		{"no reset url", func(cfg *config.Config, _ *AuthServiceParams) { cfg.Auth.PasswordResetURL = "" }},
		{"no mailer", func(_ *config.Config, p *AuthServiceParams) { p.Mailer = nil }},
		{"log driver outside development", func(cfg *config.Config, _ *AuthServiceParams) {
			cfg.Mail.Driver = string(mailer.DriverLog)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newTestEnv(t, withPasswordReset(newMailer()), tt.opt)
			wantErr(t, e.svc.ForgotPassword(context.Background(), e.user.email, browser), domain.ErrPasswordResetUnavailable)
		})
	}
}

func TestAuthService_ForgotPassword_LogDriverAllowedInDevelopment(t *testing.T) {
	m := newMailer()
	e := newTestEnv(t, withPasswordReset(m), func(cfg *config.Config, _ *AuthServiceParams) {
		cfg.Mail.Driver = string(mailer.DriverLog)
		cfg.Environment = "development"
	})

	if err := e.svc.ForgotPassword(context.Background(), e.user.email, browser); err != nil {
		t.Fatalf("ForgotPassword() error = %v", err)
	}

	waitMail(t, m)
}

func TestAuthService_ForgotPassword_ReturnsUserLookupError(t *testing.T) {
	var repo *failingRepo
	e := newTestEnv(t, withPasswordReset(newMailer()), withFailingRepo(&repo))
	repo.usersErr = errDB

	err := e.svc.ForgotPassword(context.Background(), e.user.email, browser)

	wantErr(t, err, errDB)
}

func TestAuthService_ForgotPassword_LogsBackgroundSendFailures(t *testing.T) {
	tests := []struct {
		name     string
		mailErr  error
		storeErr error
		wantMail bool
	}{
		{name: "reset token cannot be stored", storeErr: errDB, wantMail: false},
		{name: "mailer fails", mailErr: errors.New("smtp down"), wantMail: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				repo *failingRepo
				logs *observer.ObservedLogs
			)
			m := newMailer()
			m.err = tt.mailErr
			e := newTestEnv(t, withPasswordReset(m), withFailingRepo(&repo), withObservedLogs(&logs))
			repo.err = tt.storeErr

			// The caller gets the same answer either way: the send runs in the background.
			if err := e.svc.ForgotPassword(context.Background(), e.user.email, browser); err != nil {
				t.Fatalf("ForgotPassword() error = %v, want nil", err)
			}

			e.svc.background.Wait()

			if got := len(m.sent) == 1; got != tt.wantMail {
				t.Errorf("email handed to the mailer = %v, want %v", got, tt.wantMail)
			}

			failures := logs.FilterMessage("auth: send password reset email failed").All()
			if len(failures) != 1 {
				t.Fatalf("failure log entries = %d, want 1", len(failures))
			}

			cause := tt.storeErr
			if cause == nil {
				cause = tt.mailErr
			}

			if got := failures[0].ContextMap()["error"]; got != cause.Error() {
				t.Errorf("logged error = %v, want %q", got, cause)
			}
		})
	}
}

// =============================================================================
// Email rendering
// =============================================================================

func TestResetEmail_RendersAndEscapes(t *testing.T) {
	creds := &domain.Credentials{Email: "a@example.com", FirstName: "<b>Eve</b>", LastName: "Lý"}
	msg, err := resetEmail(creds, senderName("Jungo <no-reply@example.com>"), "https://x.com/reset?lang=vi&token=abc", 30*time.Minute)
	if err != nil {
		t.Fatalf("resetEmail() error = %v", err)
	}

	for _, want := range []string{"Jungo", "Hi &lt;b&gt;Eve&lt;/b&gt; Lý,", `href="https://x.com/reset?lang=vi&amp;token=abc"`, "30 minutes"} {
		if !strings.Contains(msg.HTML, want) {
			t.Errorf("HTML missing %q", want)
		}
	}

	if strings.Contains(msg.HTML, "<b>Eve") {
		t.Error("HTML contains the raw name, want it escaped")
	}

	if !strings.Contains(msg.Text, "https://x.com/reset?lang=vi&token=abc") {
		t.Errorf("text body missing the unescaped link:\n%s", msg.Text)
	}

	if !strings.Contains(msg.Text, "— Jungo") {
		t.Errorf("text body missing the sender signature:\n%s", msg.Text)
	}
}
