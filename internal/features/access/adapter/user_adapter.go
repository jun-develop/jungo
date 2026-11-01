package adapter

import (
	"context"
	"errors"

	"github.com/google/uuid"

	accessdomain "jungo/internal/features/access/domain"
	userdomain "jungo/internal/features/user/domain"
)

// UserAdapter implements accessdomain.UserLookup. It uses the user repository, not UserService,
// to avoid a dependency cycle: UserService reads permissions from the access feature.
type UserAdapter struct {
	repo userdomain.UserRepository
}

// NewUserAdapter creates a UserAdapter.
func NewUserAdapter(repo userdomain.UserRepository) *UserAdapter {
	return &UserAdapter{repo: repo}
}

// GetUserID implements accessdomain.UserLookup.
func (a *UserAdapter) GetUserID(ctx context.Context, uid uuid.UUID) (int64, error) {
	return mapUserErr(a.repo.GetIDByUUID(ctx, uid))
}

// LockUser implements accessdomain.UserLookup; the user's row stays locked until the transaction
// in ctx ends.
func (a *UserAdapter) LockUser(ctx context.Context, uid uuid.UUID) (int64, error) {
	return mapUserErr(a.repo.LockByUUID(ctx, uid))
}

// mapUserErr converts userdomain.ErrUserNotFound to accessdomain.ErrUserNotFound.
func mapUserErr(id int64, err error) (int64, error) {
	if errors.Is(err, userdomain.ErrUserNotFound) {
		return 0, accessdomain.ErrUserNotFound
	}

	return id, err
}
