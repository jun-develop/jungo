package service

import (
	"context"
	"errors"
	"slices"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/jun-develop/junkit/security"
	"github.com/jun-develop/junkit/storage"
	"github.com/jun-develop/junkit/tracer"

	"jungo/internal/common/actor"
	"jungo/internal/features/user/domain"
)

// UserService implements domain.UserService.
type UserService struct {
	repo        domain.UserRepository
	permissions domain.PermissionReader
	storage     storage.Service
	hasher      security.PasswordHasher
	sessions    domain.SessionRevoker
	logger      *zap.Logger
}

// NewUserService creates a UserService.
func NewUserService(repo domain.UserRepository, permissions domain.PermissionReader, storageService storage.Service, hasher security.PasswordHasher, sessions domain.SessionRevoker, logger *zap.Logger) *UserService {
	return &UserService{repo: repo, permissions: permissions, storage: storageService, hasher: hasher, sessions: sessions, logger: logger}
}

// CreateUser creates a new user with hashed password.
//
// Flow: normalize email -> hash password -> persist user
func (s *UserService) CreateUser(ctx context.Context, input domain.CreateUserInput) (*domain.User, error) {
	input.Email = domain.NormalizeEmail(input.Email)

	stop := tracer.Span(ctx, "Bcrypt Hashing")
	passwordHash, err := s.hasher.Hash(input.Password)
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

// GetCredentialsByEmail returns the login credentials of the user with email.
func (s *UserService) GetCredentialsByEmail(ctx context.Context, email string) (*domain.Credentials, error) {
	return s.repo.GetCredentialsByEmail(ctx, domain.NormalizeEmail(email))
}

// GetUsers returns a paginated list of users.
func (s *UserService) GetUsers(ctx context.Context, filter domain.UserListFilter) ([]*domain.User, int64, error) {
	return s.repo.List(ctx, filter)
}

// UpdateUser updates a user. The user themself may change everything but their status; anyone
// else is checked by authorize with users:update.
//
// Flow: authorize + update (tx) -> revoke sessions if no longer active
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

		user, err = s.repo.Update(ctx, uid, input)

		return err
	})
	if err != nil {
		return nil, err
	}

	if !user.IsActive() {
		if err := s.revokeSessions(ctx, uid); err != nil {
			return nil, err
		}
	}

	return user, nil
}

// DeleteUser deletes another user, checked by authorize with users:delete, and removes their
// avatar file. No one deletes themself, so the last super_admin always stays.
//
// Flow: authorize + get user + soft-delete (tx) -> revoke sessions -> delete avatar file
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

		return s.repo.Delete(ctx, uid)
	})
	if err != nil {
		return err
	}

	if err := s.revokeSessions(ctx, uid); err != nil {
		return err
	}

	if hasAvatar(user) {
		s.deleteFile(ctx, *user.AvatarURL)
	}

	return nil
}

// UploadAvatar uploads a new avatar and updates the user record, for the user themself or anyone
// authorize allows with users:update. The upload runs outside the transaction so the row is not
// kept locked during it; authorize runs again inside, in case the user's roles changed meanwhile.
//
// Flow: authorize -> get user -> upload file -> authorize + update avatar URL (tx) -> delete old file
func (s *UserService) UploadAvatar(ctx context.Context, uid uuid.UUID, file domain.AvatarFile) (*domain.User, error) {
	if _, err := s.authorize(ctx, uid, domain.UsersUpdate); err != nil {
		return nil, err
	}

	user, err := s.repo.GetByUUID(ctx, uid)
	if err != nil {
		return nil, err
	}

	stop := tracer.Span(ctx, "Upload Avatar to Storage")
	newURL, err := s.storage.UploadFile(ctx, file.Reader, file.Filename)
	stop()
	if err != nil {
		return nil, domain.ErrInvalidAvatarFile
	}

	var updated *domain.User
	err = s.repo.WithTransaction(ctx, func(ctx context.Context) error {
		if _, err := s.authorize(ctx, uid, domain.UsersUpdate); err != nil {
			return err
		}

		updated, err = s.repo.Update(ctx, uid, domain.UpdateUserInput{AvatarURL: &newURL})

		return err
	})
	if err != nil {
		s.deleteFile(ctx, newURL)
		return nil, err
	}

	if hasAvatar(user) {
		s.deleteFile(ctx, *user.AvatarURL)
	}

	return updated, nil
}

// DeleteAvatar clears the avatar URL, then removes the file, for the user themself or anyone
// authorize allows with users:update.
//
// Flow: authorize + get user + clear avatar URL (tx) -> delete file
func (s *UserService) DeleteAvatar(ctx context.Context, uid uuid.UUID) (*domain.User, error) {
	var user, updated *domain.User
	err := s.repo.WithTransaction(ctx, func(ctx context.Context) error {
		if _, err := s.authorize(ctx, uid, domain.UsersUpdate); err != nil {
			return err
		}

		var err error
		if user, err = s.repo.GetByUUID(ctx, uid); err != nil || !hasAvatar(user) {
			return err
		}

		empty := ""
		updated, err = s.repo.Update(ctx, uid, domain.UpdateUserInput{AvatarURL: &empty})

		return err
	})
	if err != nil {
		return nil, err
	}

	if !hasAvatar(user) {
		return user, nil
	}

	s.deleteFile(ctx, *user.AvatarURL)

	return updated, nil
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

	held, target, err := s.permissions.GetActorAndTargetPermissions(ctx, a.UserID, targetID)
	if err != nil {
		return false, err
	}

	if !slices.Contains(held, permission) {
		return false, actor.ErrForbidden
	}

	if !actor.Covers(held, target) {
		return false, domain.ErrCannotManageStrongerUser
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

// revokeSessions ends the user's sessions. Its error is returned: until revoked, a cached session
// keeps the user's old active status for up to AUTH_SESSION_CACHE_TTL.
func (s *UserService) revokeSessions(ctx context.Context, uid uuid.UUID) error {
	if s.sessions == nil {
		return nil
	}

	return s.sessions.RevokeUserSessions(ctx, uid)
}
