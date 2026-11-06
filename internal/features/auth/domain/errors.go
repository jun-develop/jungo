package domain

import "github.com/jun-develop/junkit/response"

// Domain errors for the auth feature.
var (
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

	ErrUserNotFound = response.New(response.NotFound, "user_not_found")

	ErrInvalidResetToken        = response.New(response.BadRequest, "invalid_reset_token")
	ErrTooManyResetRequests     = response.New(response.TooManyRequests, "too_many_password_reset_requests")
	ErrPasswordResetUnavailable = response.New(response.Internal, "password_reset_unavailable")
	ErrPasswordTooLong          = response.New(response.UnprocessableEntity, "password_too_long")
)
