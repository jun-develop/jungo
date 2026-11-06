package service

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"net/mail"
	"net/url"
	"strings"
	texttemplate "text/template"
	"time"

	"go.uber.org/zap"

	"github.com/jun-develop/junkit/mailer"
	"github.com/jun-develop/junkit/security"
	"github.com/jun-develop/junkit/tracer"

	"jungo/internal/features/auth/domain"
)

// mailTimeout bounds sending one password reset email.
const mailTimeout = 30 * time.Second

// maxPasswordBytes is bcrypt's input limit, checked before a reset token is spent.
const maxPasswordBytes = 72

//go:embed templates/password_reset.html templates/password_reset.txt
var templateFS embed.FS

// Password reset email templates; html/template escapes the user's name and the link.
var (
	resetHTML = htmltemplate.Must(htmltemplate.ParseFS(templateFS, "templates/password_reset.html"))
	resetText = texttemplate.Must(texttemplate.ParseFS(templateFS, "templates/password_reset.txt"))
)

// resetEmailData is what the password reset templates render.
type resetEmailData struct {
	AppName string
	Name    string
	Link    string
	Minutes int
}

// ForgotPassword emails a single-use reset link when email belongs to an active user. Unknown and
// inactive emails also return nil, and the email is sent in the background, so neither the response
// nor its timing reveals which emails are registered.
//
// Flow: check email setup -> throttle IP + email -> look up user -> store token hash -> send email
func (s *AuthService) ForgotPassword(ctx context.Context, email string, meta domain.Metadata) error {
	if err := s.passwordResetReady(); err != nil {
		return err
	}

	if err := s.guard.AttemptPasswordReset(ctx, meta.IPAddress, email); err != nil {
		return err
	}

	creds, err := s.users.GetCredentialsByEmail(ctx, email)
	if errors.Is(err, domain.ErrUserNotFound) {
		return nil
	}

	if err != nil {
		return err
	}

	if !creds.Active {
		return nil
	}

	link, err := url.Parse(s.cfg.PasswordResetURL)
	if err != nil {
		return fmt.Errorf("AUTH_PASSWORD_RESET_URL: %w", err)
	}

	token := security.GenerateToken()
	if err := s.repo.CreatePasswordResetToken(ctx, creds.UserID, security.HashToken(token), s.now().Add(s.cfg.PasswordResetTTL)); err != nil {
		return err
	}

	q := link.Query()
	q.Set("token", token)
	link.RawQuery = q.Encode()

	msg, err := resetEmail(creds, s.appName, link.String(), s.cfg.PasswordResetTTL)
	if err != nil {
		return err
	}

	s.sendResetEmail(ctx, msg)

	return nil
}

// ResetPassword sets a new password with a token from ForgotPassword, then ends every session of
// the user. The token works once, whether or not the rest succeeds.
//
// Flow: check length -> consume token -> hash password -> save hash -> revoke every session
func (s *AuthService) ResetPassword(ctx context.Context, token, password string) error {
	if len(password) > maxPasswordBytes {
		return domain.ErrPasswordTooLong
	}

	owner, err := s.repo.ConsumePasswordResetToken(ctx, security.HashToken(token))
	if err != nil {
		return err
	}

	stop := tracer.Span(ctx, "Bcrypt Hashing")
	hash, err := s.hasher.Hash(password)
	stop()
	if err != nil {
		return err
	}

	if err := s.users.SetPasswordHash(ctx, owner.UserID, hash); err != nil {
		return err
	}

	families, err := s.repo.RevokeAllForUser(ctx, owner.UserUUID, domain.RevokedReasonPasswordReset)
	if err != nil {
		return err
	}

	s.cache.InvalidateFamilies(ctx, families...)

	return nil
}

// passwordResetReady returns ErrPasswordResetUnavailable, logging what the developer must
// configure, when reset emails cannot reach users. In development MAIL_DRIVER=log is allowed: the
// email, link included, is written to the log.
func (s *AuthService) passwordResetReady() error {
	switch {
	case s.cfg.PasswordResetURL == "":
		s.logger.Error("auth: password reset is disabled: set AUTH_PASSWORD_RESET_URL to the frontend page that reads ?token= (see .env.example)")
	case s.mailer == nil:
		s.logger.Error("auth: password reset is disabled: no mailer.Sender is wired (add mailer.Module)")
	case s.mailLog && !s.dev:
		s.logger.Error("auth: password reset needs email: set MAIL_DRIVER=smtp or brevo and the MAIL_* settings (see .env.example); MAIL_DRIVER=log only writes emails to the log")
	default:
		return nil
	}

	return domain.ErrPasswordResetUnavailable
}

// sendResetEmail sends msg in the background; a failure is logged, never returned to the client.
func (s *AuthService) sendResetEmail(ctx context.Context, msg mailer.Message) {
	go func() {
		sendCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mailTimeout)
		defer cancel()

		if err := s.mailer.Send(sendCtx, msg); err != nil {
			s.logger.Error("auth: send password reset email failed", zap.Error(err))
			return
		}

		if s.mailLog {
			s.logger.Warn("auth: password reset email was NOT sent, only logged above (MAIL_DRIVER=log); set MAIL_DRIVER=smtp or brevo to deliver it")
		}
	}()
}

// resetEmail renders the password reset email from the embedded templates.
func resetEmail(creds *domain.Credentials, appName, link string, ttl time.Duration) (mailer.Message, error) {
	data := resetEmailData{
		AppName: appName,
		Name:    strings.TrimSpace(creds.FirstName + " " + creds.LastName),
		Link:    link,
		Minutes: int(ttl.Minutes()),
	}

	var htmlBody, textBody bytes.Buffer
	if err := resetHTML.Execute(&htmlBody, data); err != nil {
		return mailer.Message{}, fmt.Errorf("render password reset email: %w", err)
	}

	if err := resetText.Execute(&textBody, data); err != nil {
		return mailer.Message{}, fmt.Errorf("render password reset email: %w", err)
	}

	return mailer.Message{
		To:      []string{creds.Email},
		Subject: "Reset your password",
		HTML:    htmlBody.String(),
		Text:    textBody.String(),
	}, nil
}

// senderName returns the display name of a MAIL_FROM address ("Jungo <a@x.com>" → "Jungo").
func senderName(from string) string {
	if a, err := mail.ParseAddress(from); err == nil {
		return a.Name
	}

	return ""
}
