package service

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"go.uber.org/fx"
	"go.uber.org/zap"

	"github.com/jun-develop/junkit/security"
	"github.com/jun-develop/junkit/storage"
	"github.com/jun-develop/junkit/tracer"

	"jungo/internal/common/actor"
	"jungo/internal/features/user/domain"
)

// UserServiceParams defines dependencies for UserService.
type UserServiceParams struct {
	fx.In

	Repo        domain.UserRepository
	Permissions actor.TargetPermissionReader
	Storage     storage.Service
	Hasher      security.PasswordHasher
	Sessions    domain.SessionRevoker
	Logger      *zap.Logger
}

// UserService implements domain.UserService and domain.CredentialStore.
type UserService struct {
	repo        domain.UserRepository
	permissions actor.TargetPermissionReader
	storage     storage.Service
	hasher      security.PasswordHasher
	sessions    domain.SessionRevoker
	logger      *zap.Logger
}

// NewUserService creates a UserService.
func NewUserService(p UserServiceParams) *UserService {
	return &UserService{
		repo:        p.Repo,
		permissions: p.Permissions,
		storage:     p.Storage,
		hasher:      p.Hasher,
		sessions:    p.Sessions,
		logger:      p.Logger,
	}
}

// CreateUser creates a new user with a hashed password; the route requires users:create.
func (s *UserService) CreateUser(ctx context.Context, input domain.CreateUserInput) (*domain.User, error) {
	input.Email = domain.NormalizeEmail(input.Email)

	stop := tracer.Span(ctx, "Bcrypt Hashing")
	passwordHash, err := s.hasher.Hash(ctx, input.Password)
	stop()
	if err != nil {
		if errors.Is(err, security.ErrPasswordTooLong) {
			return nil, domain.ErrPasswordTooLong
		}

		return nil, err
	}

	return s.repo.Create(ctx, input, passwordHash)
}

// GetUser returns a user by UUID to the user themself or a holder of users:read; anyone else
// gets ErrUserNotFound, so the endpoint does not reveal which users exist.
func (s *UserService) GetUser(ctx context.Context, uid uuid.UUID) (*domain.User, error) {
	if err := actor.RequireSelfOrPermission(ctx, uid, domain.UsersRead); err != nil {
		return nil, domain.ErrUserNotFound
	}

	return s.repo.GetByUUID(ctx, uid)
}

// GetCredentialsByEmail implements domain.CredentialStore.
func (s *UserService) GetCredentialsByEmail(ctx context.Context, email string) (*domain.Credentials, error) {
	return s.repo.GetCredentialsByEmail(ctx, domain.NormalizeEmail(email))
}

// SetPasswordHash implements domain.CredentialStore; the caller (the auth feature's password reset)
// has verified the request itself.
func (s *UserService) SetPasswordHash(ctx context.Context, userID int64, passwordHash string) error {
	return s.repo.UpdatePassword(ctx, userID, passwordHash)
}

// ListUsers returns a page of users; the route requires users:read.
func (s *UserService) ListUsers(ctx context.Context, filter domain.UserListFilter) ([]*domain.User, int64, error) {
	return s.repo.List(ctx, filter)
}

// UpdateUser updates a user. The user themself may change everything but their status; anyone
// else is checked by authorize with users:update. A user made inactive loses their sessions in the
// same transaction, so the change and the logout cannot half happen.
//
// Flow: authorize + update + revoke sessions if inactive (tx) -> drop cached sessions
func (s *UserService) UpdateUser(ctx context.Context, uid uuid.UUID, input domain.UpdateUserInput) (*domain.User, error) {
	var user *domain.User
	err := s.repo.WithTransaction(ctx, func(ctx context.Context) error {
		self, err := s.authorize(ctx, uid, domain.UsersUpdate)
		if err != nil {
			return err
		}

		if self && input.Status != nil {
			return domain.ErrCannotChangeOwnStatus
		}

		if user, err = s.repo.Update(ctx, uid, input); err != nil {
			return err
		}

		if user.IsActive() {
			return nil
		}

		return s.sessions.RevokeUserSessions(ctx, uid)
	})
	if err != nil {
		return nil, err
	}

	s.sessions.InvalidateUserSessions(ctx, uid)

	return user, nil
}

// DeleteUser deletes another user, checked by authorize with users:delete, ends their sessions and
// removes their avatar file. No one deletes themself, so the last super_admin always stays.
//
// Flow: authorize + get user + soft-delete + revoke sessions (tx) -> drop cached sessions -> delete avatar file
func (s *UserService) DeleteUser(ctx context.Context, uid uuid.UUID) error {
	var user *domain.User
	err := s.repo.WithTransaction(ctx, func(ctx context.Context) error {
		self, err := s.authorize(ctx, uid, domain.UsersDelete)
		if err != nil {
			return err
		}

		if self {
			return domain.ErrCannotDeleteSelf
		}

		if user, err = s.repo.GetByUUID(ctx, uid); err != nil {
			return err
		}

		if err := s.repo.Delete(ctx, uid); err != nil {
			return err
		}

		return s.sessions.RevokeUserSessions(ctx, uid)
	})
	if err != nil {
		return err
	}

	s.sessions.InvalidateUserSessions(ctx, uid)

	if hasAvatar(user) {
		s.deleteFile(ctx, *user.AvatarURL)
	}

	return nil
}

// UploadAvatar uploads a new avatar and updates the user record, for the user themself or anyone
// authorize allows with users:update. The upload runs outside the transaction so the row is not
// kept locked during it; inside, authorize runs again (the user's roles may have changed) and the
// old avatar is read under the row lock, so two uploads at once cannot orphan a file.
//
// Flow: authorize -> upload file -> authorize + lock + read old avatar + update (tx) -> drop cached sessions -> delete old file
func (s *UserService) UploadAvatar(ctx context.Context, uid uuid.UUID, file domain.AvatarFile) (*domain.User, error) {
	if _, err := s.authorize(ctx, uid, domain.UsersUpdate); err != nil {
		return nil, err
	}

	stop := tracer.Span(ctx, "Upload Avatar to Storage")
	newURL, err := s.storage.UploadFile(ctx, file.Reader, file.Filename)
	stop()
	if err != nil {
		return nil, domain.ErrInvalidAvatarFile
	}

	var previous, updated *domain.User
	err = s.repo.WithTransaction(ctx, func(ctx context.Context) error {
		var err error
		if previous, err = s.lockForUpdate(ctx, uid); err != nil {
			return err
		}

		updated, err = s.repo.Update(ctx, uid, domain.UpdateUserInput{AvatarURL: &newURL})

		return err
	})
	if err != nil {
		s.deleteFile(ctx, newURL)
		return nil, err
	}

	s.sessions.InvalidateUserSessions(ctx, uid)

	if hasAvatar(previous) {
		s.deleteFile(ctx, *previous.AvatarURL)
	}

	return updated, nil
}

// DeleteAvatar clears the avatar URL, then removes the file, for the user themself or anyone
// authorize allows with users:update.
//
// Flow: authorize + lock + read avatar + clear it (tx) -> drop cached sessions -> delete file
func (s *UserService) DeleteAvatar(ctx context.Context, uid uuid.UUID) (*domain.User, error) {
	var previous, updated *domain.User
	err := s.repo.WithTransaction(ctx, func(ctx context.Context) error {
		var err error
		if previous, err = s.lockForUpdate(ctx, uid); err != nil {
			return err
		}

		if !hasAvatar(previous) {
			return nil
		}

		empty := ""
		updated, err = s.repo.Update(ctx, uid, domain.UpdateUserInput{AvatarURL: &empty})

		return err
	})
	if err != nil {
		return nil, err
	}

	if !hasAvatar(previous) {
		return previous, nil
	}

	s.sessions.InvalidateUserSessions(ctx, uid)
	s.deleteFile(ctx, *previous.AvatarURL)

	return updated, nil
}

// lockForUpdate authorizes a change to user uid with users:update, locks their row until the
// transaction in ctx ends and returns them as they are now.
func (s *UserService) lockForUpdate(ctx context.Context, uid uuid.UUID) (*domain.User, error) {
	if _, err := s.authorize(ctx, uid, domain.UsersUpdate); err != nil {
		return nil, err
	}

	if _, err := s.repo.LockByUUID(ctx, uid); err != nil {
		return nil, err
	}

	return s.repo.GetByUUID(ctx, uid)
}

// authorize checks the actor may act on user uid and reports whether uid is the actor. Acting on
// someone else needs permission plus every permission uid holds (never on a stronger user); without
// permission the answer is ErrUserNotFound, so it does not reveal which users exist.
func (s *UserService) authorize(ctx context.Context, uid uuid.UUID, permission string) (bool, error) {
	a, ok := actor.From(ctx)
	if !ok {
		return false, domain.ErrUserNotFound
	}

	if a.Is(uid) {
		return true, nil
	}

	if !a.Has(permission) {
		return false, domain.ErrUserNotFound
	}

	// The lock is its own statement: a statement reading the permissions after it then sees role
	// changes committed while it waited, which one combined statement's snapshot would miss.
	targetID, err := s.repo.LockByUUID(ctx, uid)
	if err != nil {
		return false, err
	}

	if _, err := actor.RequireManage(ctx, s.permissions, targetID, permission); err != nil {
		return false, err
	}

	return false, nil
}

// hasAvatar checks if the user has an avatar URL.
func hasAvatar(user *domain.User) bool {
	return user.AvatarURL != nil && *user.AvatarURL != ""
}

// deleteFile removes a stored file best-effort; a failure only leaves an orphaned file, so it is
// logged rather than returned.
func (s *UserService) deleteFile(ctx context.Context, fileURL string) {
	if err := s.storage.DeleteFile(ctx, fileURL); err != nil {
		s.logger.Error("user: delete stored file failed", zap.String("file_url", fileURL), zap.Error(err))
	}
}
