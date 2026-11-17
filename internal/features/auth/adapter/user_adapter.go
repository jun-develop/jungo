package adapter

import (
	"context"
	"errors"

	authdomain "jungo/internal/features/auth/domain"
	userdomain "jungo/internal/features/user/domain"
)

// UserAdapter implements authdomain.UserProvider over the user feature's CredentialStore; it turns
// userdomain.ErrUserNotFound into authdomain.ErrUserNotFound.
type UserAdapter struct {
	credentials userdomain.CredentialStore
}

// NewUserAdapter creates a UserAdapter.
func NewUserAdapter(credentials userdomain.CredentialStore) *UserAdapter {
	return &UserAdapter{credentials: credentials}
}

// GetCredentialsByEmail implements authdomain.UserProvider.
func (a *UserAdapter) GetCredentialsByEmail(ctx context.Context, email string) (*authdomain.Credentials, error) {
	creds, err := a.credentials.GetCredentialsByEmail(ctx, email)
	if err != nil {
		return nil, mapErr(err)
	}

	return &authdomain.Credentials{
		UserID:       creds.ID,
		UserUUID:     creds.UUID,
		Email:        creds.Email,
		FirstName:    creds.FirstName,
		LastName:     creds.LastName,
		PasswordHash: creds.PasswordHash,
		Active:       creds.Status == userdomain.UserStatusActive,
	}, nil
}

// SetPasswordHash implements authdomain.UserProvider.
func (a *UserAdapter) SetPasswordHash(ctx context.Context, userID int64, passwordHash string) error {
	return mapErr(a.credentials.SetPasswordHash(ctx, userID, passwordHash))
}

// mapErr turns the user feature's not-found error into the auth feature's; others pass through.
func mapErr(err error) error {
	if errors.Is(err, userdomain.ErrUserNotFound) {
		return authdomain.ErrUserNotFound
	}

	return err
}
