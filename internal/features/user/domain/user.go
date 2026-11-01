package domain

import (
	"context"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
)

// User status constants.
const (
	UserStatusActive   int16 = 1
	UserStatusInactive int16 = 2
)

// User status names exposed by the API.
const (
	UserStatusNameActive   = "active"
	UserStatusNameInactive = "inactive"
)

var userStatusNames = map[int16]string{
	UserStatusActive:   UserStatusNameActive,
	UserStatusInactive: UserStatusNameInactive,
}

// UserStatusName returns the API name of a status code ("unknown" if unmapped).
func UserStatusName(status int16) string {
	if name, ok := userStatusNames[status]; ok {
		return name
	}

	return "unknown"
}

// ParseUserStatus returns the status code for an API name.
func ParseUserStatus(name string) (int16, bool) {
	for status, n := range userStatusNames {
		if n == name {
			return status, true
		}
	}

	return 0, false
}

// User represents the user entity.
type User struct {
	UUID        uuid.UUID
	Email       string
	FirstName   string
	LastName    string
	PhoneNumber *string
	AvatarURL   *string
	Status      int16
	CreatedAt   time.Time
	UpdatedAt   *time.Time
}

// IsActive checks if the user is active.
func (u *User) IsActive() bool {
	return u.Status == UserStatusActive
}

// NormalizeEmail trims and lowercases email; users are stored and looked up this way.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// Credentials is the login view of a user, kept apart from User so the hash never reaches responses.
type Credentials struct {
	ID           int64
	UUID         uuid.UUID
	PasswordHash string
	Status       int16
}

// SessionRevoker ends a user's login sessions; implemented by the auth feature.
type SessionRevoker interface {
	RevokeUserSessions(ctx context.Context, uid uuid.UUID) error
}

// PermissionReader reads permission codes from the database, never a cache; implemented by the
// access feature.
type PermissionReader interface {
	GetActorAndTargetPermissions(ctx context.Context, actorID, targetID int64) (actor, target []string, err error)
}

// CreateUserInput holds data for creating a user.
type CreateUserInput struct {
	FirstName   string
	LastName    string
	Email       string
	Password    string
	PhoneNumber *string
}

// UpdateUserInput holds data for updating a user. A nil field is left unchanged; an empty
// PhoneNumber or AvatarURL clears it.
type UpdateUserInput struct {
	FirstName   *string
	LastName    *string
	PhoneNumber *string
	AvatarURL   *string
	Status      *int16
}

// UserListFilter holds parameters for filtering and paginating users.
type UserListFilter struct {
	Search    string
	Limit     int32
	Offset    int32
	SortOrder string
}

// UserRepository defines database operations for users.
type UserRepository interface {
	WithTransaction(ctx context.Context, fn func(ctx context.Context) error) error
	Create(ctx context.Context, input CreateUserInput, passwordHash string) (*User, error)
	GetByUUID(ctx context.Context, uid uuid.UUID) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	GetCredentialsByEmail(ctx context.Context, email string) (*Credentials, error)
	List(ctx context.Context, filter UserListFilter) ([]*User, int64, error)
	Update(ctx context.Context, uid uuid.UUID, input UpdateUserInput) (*User, error)
	Delete(ctx context.Context, uid uuid.UUID) error
	GetIDByUUID(ctx context.Context, uid uuid.UUID) (int64, error)
	LockByUUID(ctx context.Context, uid uuid.UUID) (int64, error)
}

// UserService defines business logic for users.
type UserService interface {
	CreateUser(ctx context.Context, input CreateUserInput) (*User, error)
	GetUser(ctx context.Context, uid uuid.UUID) (*User, error)
	GetCredentialsByEmail(ctx context.Context, email string) (*Credentials, error)
	GetUsers(ctx context.Context, filter UserListFilter) ([]*User, int64, error)
	UpdateUser(ctx context.Context, uid uuid.UUID, input UpdateUserInput) (*User, error)
	DeleteUser(ctx context.Context, uid uuid.UUID) error
	UploadAvatar(ctx context.Context, uid uuid.UUID, file AvatarFile) (*User, error)
	DeleteAvatar(ctx context.Context, uid uuid.UUID) (*User, error)
}

// AvatarFile represents an uploaded avatar file.
type AvatarFile struct {
	Reader   io.Reader
	Filename string
}
