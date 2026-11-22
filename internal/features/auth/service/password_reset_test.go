package service

// =============================================================================
// TEST CASE OVERVIEW
// =============================================================================
//
// File: password_reset_test.go
// Purpose: Verify what AuthService decides in the forgot/reset password flow: the emailed link,
//          throttling, setup checks, background send failures and the rendered email.
// Type: Unit (Func-field repository, fake mailer)
//
// Test functions: 11
// Total scenarios: 16
//
// #   Test Case                                                             Scenario                                     Expected Result
// 1   TestAuthService_ForgotPassword_EmailsResetLink                        Active user                                  Link keeps its query; token hash, user and 30-min expiry stored
// 2   TestAuthService_ForgotPassword_UnknownAndInactiveEmailsLookTheSame    Unknown email                                Returns nil; no email sent
// 3   TestAuthService_ForgotPassword_UnknownAndInactiveEmailsLookTheSame    Inactive user                                Returns nil; no email sent
// 4   TestAuthService_ForgotPassword_ThrottlesPerEmailAndPerIP              4 requests for one email from different IPs  4th returns ErrTooManyResetRequests
// 5   TestAuthService_ForgotPassword_ThrottlesPerEmailAndPerIP              6 requests from one IP for different emails  6th returns ErrTooManyResetRequests
// 6   TestAuthService_ForgotPassword_UnavailableWithoutEmailSetup           No reset URL                                 ErrPasswordResetUnavailable
// 7   TestAuthService_ForgotPassword_UnavailableWithoutEmailSetup           No mailer wired                              ErrPasswordResetUnavailable
// 8   TestAuthService_ForgotPassword_UnavailableWithoutEmailSetup           Log mail driver outside development          ErrPasswordResetUnavailable
// 9   TestAuthService_ForgotPassword_LogDriverAllowedInDevelopment          Log mail driver in development               Email handed to the mailer
// 10  TestAuthService_ForgotPassword_ReturnsUserLookupError                 User lookup fails                            Returns the lookup error
// 11  TestAuthService_ForgotPassword_LogsBackgroundSendFailures             Reset token cannot be stored                 Returns nil; no email; the error is logged
// 12  TestAuthService_ForgotPassword_LogsBackgroundSendFailures             Mailer fails                                 Returns nil; the error is logged
// 13  TestAuthService_ResetPassword_ReplacesPasswordAndEndsSessions         Valid reset token                            Token hash consumed; new hash saved; sessions revoked and uncached
// 14  TestAuthService_ResetPassword_ReturnsConsumeError                     Repository rejects the token                 ErrInvalidResetToken; password untouched
// 15  TestAuthService_ResetPassword_RejectsTooLongPasswordBeforeUsingToken  80-byte password                             ErrPasswordTooLong; token not spent
// 16  TestResetEmail_RendersAndEscapes                                      Name with HTML, link with a query            HTML escapes name and link; text keeps the raw link and signature
//
// =============================================================================

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/crypto/bcrypt"

	"github.com/jun-develop/junkit/mailer"
	"github.com/jun-develop/junkit/security"

	"jungo/internal/config"
	"jungo/internal/features/auth/domain"
)

// fakeMailer records sent messages on a channel, because ForgotPassword sends in the background,
// and returns err from every Send.
type fakeMailer struct {
	sent chan mailer.Message
	err  error
}

// newMailer returns a fakeMailer that accepts every message.
func newMailer() *fakeMailer {
	return &fakeMailer{sent: make(chan mailer.Message, 10)}
}

// Send records msg and returns f.err.
func (f *fakeMailer) Send(_ context.Context, msg mailer.Message) error {
	f.sent <- msg
	return f.err
}

// resetConfig returns testConfig with password reset set up to send through a real mail driver.
func resetConfig() *config.Config {
	cfg := testConfig()
	cfg.Auth.PasswordResetURL = "https://app.example.com/reset-password?lang=vi"
	cfg.Auth.PasswordResetTTL = 30 * time.Minute
	cfg.Auth.PasswordResetWindow = time.Hour
	cfg.Auth.PasswordResetIPMax = 5
	cfg.Auth.PasswordResetEmailMax = 3
	cfg.Mail.Driver = string(mailer.DriverSMTP)

	return cfg
}

// storingResetTokens returns a repository that accepts every new password reset token.
func storingResetTokens() *fakeAuthRepository {
	return &fakeAuthRepository{
		CreatePasswordResetTokenFunc: func(context.Context, int64, string, time.Time) error { return nil },
	}
}

// unknownUsers returns a UserProvider that knows no email.
func unknownUsers() *fakeUserProvider {
	return &fakeUserProvider{
		GetCredentialsByEmailFunc: func(context.Context, string) (*domain.Credentials, error) {
			return nil, domain.ErrUserNotFound
		},
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

// noMail fails if a message is sent within 50ms.
func noMail(t *testing.T, m *fakeMailer) {
	t.Helper()

	select {
	case msg := <-m.sent:
		t.Fatalf("email sent to %v, want none", msg.To)
	case <-time.After(50 * time.Millisecond):
	}
}

// resetLink matches the reset link in the text body of the email.
var resetLink = regexp.MustCompile(`https://\S+`)

// linkFrom parses the reset link out of the email's text body.
func linkFrom(t *testing.T, msg mailer.Message) *url.URL {
	t.Helper()

	link, err := url.Parse(resetLink.FindString(msg.Text))
	if err != nil {
		t.Fatalf("parse reset link: %v", err)
	}

	return link
}

func TestAuthService_ForgotPassword_EmailsResetLink(t *testing.T) {
	creds := testCredentials(t)
	m := newMailer()
	var (
		gotUserID    int64
		gotHash      string
		gotExpiresAt time.Time
	)
	repo := &fakeAuthRepository{
		CreatePasswordResetTokenFunc: func(_ context.Context, userID int64, hash string, expiresAt time.Time) error {
			gotUserID, gotHash, gotExpiresAt = userID, hash, expiresAt
			return nil
		},
	}
	svc := newTestService(t, AuthServiceParams{Config: resetConfig(), Repo: repo, Users: usersWith(creds), Mailer: m})

	if err := svc.ForgotPassword(context.Background(), creds.Email, browser); err != nil {
		t.Fatalf("ForgotPassword() error = %v", err)
	}

	msg := waitMail(t, m)
	if !slices.Equal(msg.To, []string{creds.Email}) {
		t.Errorf("email To = %v, want [%s]", msg.To, creds.Email)
	}

	link := linkFrom(t, msg)
	if got := link.Query().Get("lang"); got != "vi" {
		t.Errorf("link query lang = %q, want vi (the configured query is kept)", got)
	}

	if want := security.HashToken(link.Query().Get("token")); gotHash != want {
		t.Errorf("stored token hash = %q, want the hash of the emailed token %q", gotHash, want)
	}

	if gotUserID != creds.UserID {
		t.Errorf("token user ID = %d, want %d", gotUserID, creds.UserID)
	}

	if want := testNow.Add(30 * time.Minute); !gotExpiresAt.Equal(want) {
		t.Errorf("token expiry = %v, want %v", gotExpiresAt, want)
	}
}

func TestAuthService_ForgotPassword_UnknownAndInactiveEmailsLookTheSame(t *testing.T) {
	inactive := testCredentials(t)
	inactive.Active = false
	tests := []struct {
		name  string
		users *fakeUserProvider
	}{
		{"unknown email", unknownUsers()},
		{"inactive user", usersWith(inactive)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newMailer()
			svc := newTestService(t, AuthServiceParams{
				Config: resetConfig(),
				Repo:   storingResetTokens(),
				Users:  tt.users,
				Mailer: m,
			})

			if err := svc.ForgotPassword(context.Background(), inactive.Email, browser); err != nil {
				t.Fatalf("ForgotPassword() error = %v, want nil", err)
			}

			noMail(t, m)
		})
	}
}

func TestAuthService_ForgotPassword_ThrottlesPerEmailAndPerIP(t *testing.T) {
	ctx := context.Background()

	t.Run("per email, across IPs: 3 allowed", func(t *testing.T) {
		svc := newTestService(t, AuthServiceParams{Config: resetConfig(), Users: unknownUsers(), Mailer: newMailer()})
		for i := range 3 {
			meta := domain.Metadata{IPAddress: "198.51.100." + strconv.Itoa(i+1)}
			if err := svc.ForgotPassword(ctx, "jane@example.com", meta); err != nil {
				t.Fatalf("request %d: ForgotPassword() error = %v", i+1, err)
			}
		}

		err := svc.ForgotPassword(ctx, "jane@example.com", domain.Metadata{IPAddress: "198.51.100.9"})

		wantErr(t, err, domain.ErrTooManyResetRequests)
	})

	t.Run("per IP, across emails: 5 allowed", func(t *testing.T) {
		svc := newTestService(t, AuthServiceParams{Config: resetConfig(), Users: unknownUsers(), Mailer: newMailer()})
		for i := range 5 {
			if err := svc.ForgotPassword(ctx, "user"+strconv.Itoa(i)+"@example.com", browser); err != nil {
				t.Fatalf("request %d: ForgotPassword() error = %v", i+1, err)
			}
		}

		err := svc.ForgotPassword(ctx, "other@example.com", browser)

		wantErr(t, err, domain.ErrTooManyResetRequests)
	})
}

func TestAuthService_ForgotPassword_UnavailableWithoutEmailSetup(t *testing.T) {
	tests := []struct {
		name   string
		modify func(cfg *config.Config, p *AuthServiceParams)
	}{
		{
			name:   "no reset url",
			modify: func(cfg *config.Config, _ *AuthServiceParams) { cfg.Auth.PasswordResetURL = "" },
		},
		{
			name:   "no mailer",
			modify: func(_ *config.Config, p *AuthServiceParams) { p.Mailer = nil },
		},
		{
			name:   "log driver outside development",
			modify: func(cfg *config.Config, _ *AuthServiceParams) { cfg.Mail.Driver = string(mailer.DriverLog) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := AuthServiceParams{Config: resetConfig(), Users: unknownUsers(), Mailer: newMailer()}
			tt.modify(p.Config, &p)
			svc := newTestService(t, p)

			err := svc.ForgotPassword(context.Background(), "jane@example.com", browser)

			wantErr(t, err, domain.ErrPasswordResetUnavailable)
		})
	}
}

func TestAuthService_ForgotPassword_LogDriverAllowedInDevelopment(t *testing.T) {
	creds := testCredentials(t)
	cfg := resetConfig()
	cfg.Mail.Driver = string(mailer.DriverLog)
	cfg.Environment = "development"
	m := newMailer()
	svc := newTestService(t, AuthServiceParams{
		Config: cfg,
		Repo:   storingResetTokens(),
		Users:  usersWith(creds),
		Mailer: m,
	})

	if err := svc.ForgotPassword(context.Background(), creds.Email, browser); err != nil {
		t.Fatalf("ForgotPassword() error = %v", err)
	}

	waitMail(t, m)
}

func TestAuthService_ForgotPassword_ReturnsUserLookupError(t *testing.T) {
	users := &fakeUserProvider{
		GetCredentialsByEmailFunc: func(context.Context, string) (*domain.Credentials, error) { return nil, errDB },
	}
	svc := newTestService(t, AuthServiceParams{Config: resetConfig(), Users: users, Mailer: newMailer()})

	err := svc.ForgotPassword(context.Background(), "jane@example.com", browser)

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
			creds := testCredentials(t)
			core, logs := observer.New(zap.InfoLevel)
			m := newMailer()
			m.err = tt.mailErr
			repo := &fakeAuthRepository{
				CreatePasswordResetTokenFunc: func(context.Context, int64, string, time.Time) error {
					return tt.storeErr
				},
			}
			svc := newTestService(t, AuthServiceParams{
				Config: resetConfig(),
				Repo:   repo,
				Users:  usersWith(creds),
				Mailer: m,
				Logger: zap.New(core),
			})

			// The caller gets the same answer either way: the send runs in the background.
			if err := svc.ForgotPassword(context.Background(), creds.Email, browser); err != nil {
				t.Fatalf("ForgotPassword() error = %v, want nil", err)
			}

			svc.background.Wait()

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

func TestAuthService_ResetPassword_ReplacesPasswordAndEndsSessions(t *testing.T) {
	const newPassword = "New-passw0rd!"
	owner := &domain.PasswordResetOwner{UserID: 1, UserUUID: uuid.New()}
	repo := &fakeAuthRepository{}
	var (
		gotConsumed string
		gotUserID   int64
		gotHash     string
		gotRevoked  uuid.UUID
		gotReason   string
	)
	users := &fakeUserProvider{
		SetPasswordHashFunc: func(_ context.Context, userID int64, passwordHash string) error {
			gotUserID, gotHash = userID, passwordHash
			return nil
		},
	}
	svc := newTestService(t, AuthServiceParams{Repo: repo, Users: users})
	sessions := newCachedSessions(t, svc, repo, 2)
	repo.ConsumePasswordResetTokenFunc = func(_ context.Context, hash string) (*domain.PasswordResetOwner, error) {
		gotConsumed = hash
		return owner, nil
	}
	repo.RevokeAllForUserFunc = func(_ context.Context, user uuid.UUID, reason string) ([]uuid.UUID, error) {
		gotRevoked, gotReason = user, reason
		return []uuid.UUID{sessions[0].session.FamilyUUID, sessions[1].session.FamilyUUID}, nil
	}

	if err := svc.ResetPassword(context.Background(), "reset-token", newPassword); err != nil {
		t.Fatalf("ResetPassword() error = %v", err)
	}

	if want := security.HashToken("reset-token"); gotConsumed != want {
		t.Errorf("consumed hash = %q, want the hash of the reset token %q", gotConsumed, want)
	}

	if gotUserID != owner.UserID {
		t.Errorf("password set for user %d, want %d", gotUserID, owner.UserID)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(gotHash), []byte(newPassword)); err != nil {
		t.Errorf("stored hash does not match the new password: %v", err)
	}

	if gotRevoked != owner.UserUUID {
		t.Errorf("sessions revoked for %v, want %v", gotRevoked, owner.UserUUID)
	}

	if gotReason != domain.RevokedReasonPasswordReset {
		t.Errorf("revoke reason = %q, want %q", gotReason, domain.RevokedReasonPasswordReset)
	}

	for i, session := range sessions {
		if !session.reloaded(t, svc) {
			t.Errorf("session %d still served from the cache, want every revoked family invalidated", i)
		}
	}
}

func TestAuthService_ResetPassword_ReturnsConsumeError(t *testing.T) {
	repo := &fakeAuthRepository{
		ConsumePasswordResetTokenFunc: func(context.Context, string) (*domain.PasswordResetOwner, error) {
			return nil, domain.ErrInvalidResetToken
		},
	}
	svc := newTestService(t, AuthServiceParams{Repo: repo, Users: &fakeUserProvider{}})

	err := svc.ResetPassword(context.Background(), "garbage", "New-passw0rd!")

	// SetPasswordHashFunc is nil: reaching it would panic.
	wantErr(t, err, domain.ErrInvalidResetToken)
}

func TestAuthService_ResetPassword_RejectsTooLongPasswordBeforeUsingToken(t *testing.T) {
	svc := newTestService(t, AuthServiceParams{Repo: &fakeAuthRepository{}, Users: &fakeUserProvider{}})

	err := svc.ResetPassword(context.Background(), "reset-token", strings.Repeat("é", 40))

	// ConsumePasswordResetTokenFunc is nil: spending the token would panic.
	wantErr(t, err, domain.ErrPasswordTooLong)
}

func TestResetEmail_RendersAndEscapes(t *testing.T) {
	creds := &domain.Credentials{Email: "a@example.com", FirstName: "<b>Eve</b>", LastName: "Lý"}
	link := "https://x.com/reset?lang=vi&token=abc"

	msg, err := resetEmail(creds, senderName("Jungo <no-reply@example.com>"), link, 30*time.Minute)

	if err != nil {
		t.Fatalf("resetEmail() error = %v", err)
	}

	wantHTML := []string{
		"Jungo",
		"Hi &lt;b&gt;Eve&lt;/b&gt; Lý,",
		`href="https://x.com/reset?lang=vi&amp;token=abc"`,
		"30 minutes",
	}
	for _, want := range wantHTML {
		if !strings.Contains(msg.HTML, want) {
			t.Errorf("HTML missing %q", want)
		}
	}

	if strings.Contains(msg.HTML, "<b>Eve") {
		t.Error("HTML contains the raw name, want it escaped")
	}

	if !strings.Contains(msg.Text, link) {
		t.Errorf("text body missing the unescaped link:\n%s", msg.Text)
	}

	if !strings.Contains(msg.Text, "— Jungo") {
		t.Errorf("text body missing the sender signature:\n%s", msg.Text)
	}
}
