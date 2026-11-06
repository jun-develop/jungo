package service

import (
	"context"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jun-develop/junkit/mailer"

	"jungo/internal/config"
	"jungo/internal/features/auth/domain"
)

// fakeMailer records sent messages on a channel (ForgotPassword sends in the background).
type fakeMailer struct{ sent chan mailer.Message }

func (f *fakeMailer) Send(_ context.Context, msg mailer.Message) error {
	f.sent <- msg
	return nil
}

// withPasswordReset configures password reset with a real mail driver and the given mailer.
func withPasswordReset(m *fakeMailer) envOption {
	return func(cfg *config.Config, p *Params) {
		cfg.Auth.PasswordResetURL = "https://app.example.com/reset-password?lang=vi"
		cfg.Auth.PasswordResetTTL = 30 * time.Minute
		cfg.Auth.PasswordResetWindow = time.Hour
		cfg.Auth.PasswordResetIPMax = 5
		cfg.Auth.PasswordResetEmailMax = 3
		cfg.Mail.Driver = string(mailer.DriverSMTP)
		p.Mailer = m
	}
}

func newMailer() *fakeMailer { return &fakeMailer{sent: make(chan mailer.Message, 10)} }

// waitMail returns the next sent message, failing after a second.
func waitMail(t *testing.T, m *fakeMailer) mailer.Message {
	t.Helper()
	select {
	case msg := <-m.sent:
		return msg
	case <-time.After(time.Second):
		t.Fatal("no email sent")
		return mailer.Message{}
	}
}

// noMail fails if a message is sent shortly.
func noMail(t *testing.T, m *fakeMailer) {
	t.Helper()
	select {
	case msg := <-m.sent:
		t.Fatalf("unexpected email to %v", msg.To)
	case <-time.After(50 * time.Millisecond):
	}
}

var linkToken = regexp.MustCompile(`https://\S+`)

// tokenFrom extracts the reset token from the email's text link.
func tokenFrom(t *testing.T, msg mailer.Message) string {
	t.Helper()
	u, err := url.Parse(linkToken.FindString(msg.Text))
	if err != nil {
		t.Fatal(err)
	}

	if u.Query().Get("lang") != "vi" {
		t.Fatalf("link lost the configured query: %s", u)
	}

	return u.Query().Get("token")
}

func TestPasswordReset_FullFlow(t *testing.T) {
	m := newMailer()
	e := newTestEnv(t, withPasswordReset(m))
	ctx := context.Background()
	old := e.login(t, browser)

	if err := e.svc.ForgotPassword(ctx, e.user.email, browser); err != nil {
		t.Fatalf("ForgotPassword() error = %v", err)
	}

	msg := waitMail(t, m)
	if msg.To[0] != e.user.email || !strings.Contains(msg.HTML, "Hi Jane Doe") {
		t.Fatalf("unexpected email: %+v", msg)
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
		t.Fatalf("login with new password: %v", err)
	}

	// The token works once.
	wantErr(t, e.svc.ResetPassword(ctx, token, "Another-passw0rd!"), domain.ErrInvalidResetToken)
}

func TestForgotPassword_UnknownAndInactiveEmailsLookTheSame(t *testing.T) {
	m := newMailer()
	e := newTestEnv(t, withPasswordReset(m))

	if err := e.svc.ForgotPassword(context.Background(), "nobody@example.com", browser); err != nil {
		t.Fatalf("unknown email: error = %v, want nil", err)
	}

	e.user.active = false
	if err := e.svc.ForgotPassword(context.Background(), e.user.email, browser); err != nil {
		t.Fatalf("inactive user: error = %v, want nil", err)
	}

	noMail(t, m)
}

func TestForgotPassword_NewerLinkReplacesOlder(t *testing.T) {
	m := newMailer()
	e := newTestEnv(t, withPasswordReset(m))
	ctx := context.Background()

	_ = e.svc.ForgotPassword(ctx, e.user.email, browser)
	first := tokenFrom(t, waitMail(t, m))
	_ = e.svc.ForgotPassword(ctx, e.user.email, browser)
	second := tokenFrom(t, waitMail(t, m))

	wantErr(t, e.svc.ResetPassword(ctx, first, "New-passw0rd!"), domain.ErrInvalidResetToken)
	if err := e.svc.ResetPassword(ctx, second, "New-passw0rd!"); err != nil {
		t.Fatalf("latest token: %v", err)
	}
}

func TestResetPassword_ExpiredAndGarbageTokens(t *testing.T) {
	m := newMailer()
	e := newTestEnv(t, withPasswordReset(m))
	ctx := context.Background()

	_ = e.svc.ForgotPassword(ctx, e.user.email, browser)
	token := tokenFrom(t, waitMail(t, m))

	wantErr(t, e.svc.ResetPassword(ctx, "garbage", "New-passw0rd!"), domain.ErrInvalidResetToken)

	e.clock.Advance(31 * time.Minute)
	wantErr(t, e.svc.ResetPassword(ctx, token, "New-passw0rd!"), domain.ErrInvalidResetToken)
}

func TestResetPassword_TooLongPasswordKeepsToken(t *testing.T) {
	m := newMailer()
	e := newTestEnv(t, withPasswordReset(m))
	ctx := context.Background()

	_ = e.svc.ForgotPassword(ctx, e.user.email, browser)
	token := tokenFrom(t, waitMail(t, m))

	wantErr(t, e.svc.ResetPassword(ctx, token, strings.Repeat("é", 40)), domain.ErrPasswordTooLong)
	if err := e.svc.ResetPassword(ctx, token, "New-passw0rd!"); err != nil {
		t.Fatalf("token must survive a rejected password: %v", err)
	}
}

func TestForgotPassword_ThrottlesPerEmailAndPerIP(t *testing.T) {
	m := newMailer()
	e := newTestEnv(t, withPasswordReset(m))
	ctx := context.Background()

	// Per email, across IPs: 3 allowed.
	for i := range 3 {
		ip := domain.Metadata{IPAddress: "198.51.100." + string(rune('1'+i))}
		if err := e.svc.ForgotPassword(ctx, e.user.email, ip); err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
	}

	wantErr(t, e.svc.ForgotPassword(ctx, e.user.email, domain.Metadata{IPAddress: "198.51.100.9"}), domain.ErrTooManyResetRequests)

	// Per IP, across emails (registered or not): 5 allowed.
	for i := range 5 {
		if err := e.svc.ForgotPassword(ctx, "user"+string(rune('a'+i))+"@example.com", browser); err != nil {
			t.Fatalf("ip request %d: %v", i+1, err)
		}
	}

	wantErr(t, e.svc.ForgotPassword(ctx, "other@example.com", browser), domain.ErrTooManyResetRequests)
}

func TestForgotPassword_UnavailableWithoutEmailSetup(t *testing.T) {
	cases := map[string]envOption{
		"no reset url": func(cfg *config.Config, _ *Params) { cfg.Auth.PasswordResetURL = "" },
		"no mailer":    func(_ *config.Config, p *Params) { p.Mailer = nil },
		"log driver outside development": func(cfg *config.Config, _ *Params) {
			cfg.Mail.Driver = string(mailer.DriverLog)
		},
	}

	for name, opt := range cases {
		t.Run(name, func(t *testing.T) {
			e := newTestEnv(t, withPasswordReset(newMailer()), opt)
			wantErr(t, e.svc.ForgotPassword(context.Background(), e.user.email, browser), domain.ErrPasswordResetUnavailable)
		})
	}
}

func TestForgotPassword_LogDriverAllowedInDevelopment(t *testing.T) {
	m := newMailer()
	e := newTestEnv(t, withPasswordReset(m), func(cfg *config.Config, _ *Params) {
		cfg.Mail.Driver = string(mailer.DriverLog)
		cfg.Environment = "development"
	})

	if err := e.svc.ForgotPassword(context.Background(), e.user.email, browser); err != nil {
		t.Fatalf("ForgotPassword() error = %v", err)
	}

	waitMail(t, m)
}

func TestResetEmail_RendersAndEscapes(t *testing.T) {
	creds := &domain.Credentials{Email: "a@example.com", FirstName: "<b>Eve</b>", LastName: "Lý"}
	msg, err := resetEmail(creds, senderName("Jungo <no-reply@example.com>"), "https://x.com/reset?lang=vi&token=abc", 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{"Jungo", "Hi &lt;b&gt;Eve&lt;/b&gt; Lý,", `href="https://x.com/reset?lang=vi&amp;token=abc"`, "30 minutes"} {
		if !strings.Contains(msg.HTML, want) {
			t.Errorf("HTML missing %q", want)
		}
	}

	if strings.Contains(msg.HTML, "<b>Eve") {
		t.Error("name must be escaped in HTML")
	}

	if !strings.Contains(msg.Text, "https://x.com/reset?lang=vi&token=abc") || !strings.Contains(msg.Text, "— Jungo") {
		t.Errorf("unexpected text body:\n%s", msg.Text)
	}
}
