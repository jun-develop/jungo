package adapter

import (
	"context"
	"errors"

	"github.com/google/uuid"

	accessdomain "jungo/internal/features/access/domain"
	userdomain "jungo/internal/features/user/domain"
)

// UserAdapter implements accessdomain.UserLookup over the user feature's repository: UserService
// has no ID lookup or row lock, which the access feature needs inside its own transactions.
// It turns userdomain.ErrUserNotFound into accessdomain.ErrUserNotFound.
type UserAdapter struct {
	repo userdomain.UserRepository
}

// NewUserAdapter creates a UserAdapter.
func NewUserAdapter(repo userdomain.UserRepository) *UserAdapter {
	return &UserAdapter{repo: repo}
}

// GetUserID implements accessdomain.UserLookup.
func (a *UserAdapter) GetUserID(ctx context.Context, userUUID uuid.UUID) (int64, error) {
	id, err := a.repo.GetIDByUUID(ctx, userUUID)
	return id, mapErr(err)
}

// LockUser implements accessdomain.UserLookup; the user's row stays locked until the transaction
// in ctx ends.
func (a *UserAdapter) LockUser(ctx context.Context, userUUID uuid.UUID) (int64, error) {
	id, err := a.repo.LockByUUID(ctx, userUUID)
	return id, mapErr(err)
}

// mapErr turns the user feature's not-found error into the access feature's; others pass through.
func mapErr(err error) error {
	if errors.Is(err, userdomain.ErrUserNotFound) {
		return accessdomain.ErrUserNotFound
	}

	return err
}
