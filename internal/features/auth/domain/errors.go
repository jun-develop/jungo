package domain

import "github.com/jun-develop/junkit/response"

// Domain errors for the auth feature.
var (
	ErrUserNotFound    = response.New(response.NotFound, "user_not_found")
	ErrPasswordTooLong = response.New(response.UnprocessableEntity, "password_too_long")

	ErrInvalidCredentials        = response.New(response.Unauthorized, "invalid_credentials")
	ErrInvalidCredentialsWarning = response.New(response.Unauthorized, "invalid_credentials_warning")
	ErrUserInactive              = response.New(response.Forbidden, "user_account_is_not_active")
	ErrTooManyAttempts           = response.New(response.TooManyRequests, "too_many_login_attempts")
	ErrIPBlocked                 = response.New(response.TooManyRequests, "ip_temporarily_blocked")
	ErrRecaptchaFailed           = response.New(response.Forbidden, "recaptcha_verification_failed")

	ErrInvalidToken     = response.New(response.Unauthorized, "invalid_token")
	ErrInvalidTokenType = response.New(response.Unauthorized, "invalid_token_type")
	ErrTokenExpired     = response.New(response.Unauthorized, "token_expired")
	ErrTokenRevoked     = response.New(response.Unauthorized, "token_revoked")
	ErrTokenReused      = response.New(response.Unauthorized, "token_reused")
	ErrTokenNotFound    = response.New(response.NotFound, "token_not_found")

	ErrInvalidCurrentPassword   = response.New(response.BadRequest, "invalid_current_password")
	ErrNewPasswordSameAsCurrent = response.New(response.UnprocessableEntity, "new_password_same_as_current")
	ErrSessionNotFound          = response.New(response.NotFound, "session_not_found")

	ErrInvalidResetToken        = response.New(response.BadRequest, "invalid_reset_token")
	ErrTooManyResetRequests     = response.New(response.TooManyRequests, "too_many_password_reset_requests")
	ErrPasswordResetUnavailable = response.New(response.Internal, "password_reset_unavailable")
)
