package domain

import "github.com/jun-develop/junkit/response"

// Domain errors for the user feature.
var (
	ErrUserNotFound          = response.New(response.NotFound, "user_not_found")
	ErrPasswordTooLong       = response.New(response.UnprocessableEntity, "password_too_long")
	ErrEmailAlreadyExists    = response.New(response.Conflict, "email_already_exists")
	ErrInvalidAvatarFile     = response.New(response.BadRequest, "invalid_avatar_file")
	ErrCannotChangeOwnStatus = response.New(response.Forbidden, "cannot_change_own_status")
	ErrCannotDeleteSelf      = response.New(response.Forbidden, "cannot_delete_self")
)
