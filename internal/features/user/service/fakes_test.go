package service

// =============================================================================
// TEST HELPERS (no test scenarios)
// =============================================================================
//
// File: fakes_test.go
// Purpose: In-memory fakes for the UserService's dependencies (repository, permission reader,
//          storage, session revoker, password hasher) and helpers that build a service and an
//          actor context.
// Used by: user_service_test.go
//
// =============================================================================

import (
	"context"
	"io"
	"testing"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/jun-develop/junkit/security"

	"jungo/internal/common/actor"
	"jungo/internal/features/user/domain"
)

// fakeUserRepository is a test double for domain.UserRepository; calling an unset Func panics,
// except LockFunc, which defaults to lockTarget.
type fakeUserRepository struct {
	CreateFunc         func(ctx context.Context, input domain.CreateUserInput, passwordHash string) (*domain.User, error)
	GetByUUIDFunc      func(ctx context.Context, uid uuid.UUID) (*domain.User, error)
	GetCredsFunc       func(ctx context.Context, email string) (*domain.Credentials, error)
	ListFunc           func(ctx context.Context, filter domain.UserListFilter) ([]*domain.User, int64, error)
	UpdateFunc         func(ctx context.Context, uid uuid.UUID, input domain.UpdateUserInput) (*domain.User, error)
	DeleteFunc         func(ctx context.Context, uid uuid.UUID) error
	LockFunc           func(ctx context.Context, uid uuid.UUID) (int64, error)
	UpdatePasswordFunc func(ctx context.Context, userID int64, passwordHash string) error
}

func (f *fakeUserRepository) WithTransaction(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

func (f *fakeUserRepository) Create(ctx context.Context, input domain.CreateUserInput, passwordHash string) (*domain.User, error) {
	return f.CreateFunc(ctx, input, passwordHash)
}

func (f *fakeUserRepository) GetByUUID(ctx context.Context, uid uuid.UUID) (*domain.User, error) {
	return f.GetByUUIDFunc(ctx, uid)
}

func (f *fakeUserRepository) GetCredentialsByEmail(ctx context.Context, email string) (*domain.Credentials, error) {
	return f.GetCredsFunc(ctx, email)
}

func (f *fakeUserRepository) List(ctx context.Context, filter domain.UserListFilter) ([]*domain.User, int64, error) {
	return f.ListFunc(ctx, filter)
}

func (f *fakeUserRepository) Update(ctx context.Context, uid uuid.UUID, input domain.UpdateUserInput) (*domain.User, error) {
	return f.UpdateFunc(ctx, uid, input)
}

func (f *fakeUserRepository) Delete(ctx context.Context, uid uuid.UUID) error {
	return f.DeleteFunc(ctx, uid)
}

func (f *fakeUserRepository) UpdatePassword(ctx context.Context, userID int64, passwordHash string) error {
	return f.UpdatePasswordFunc(ctx, userID, passwordHash)
}

func (f *fakeUserRepository) GetIDByUUID(ctx context.Context, uid uuid.UUID) (int64, error) {
	return f.LockByUUID(ctx, uid)
}

func (f *fakeUserRepository) LockByUUID(ctx context.Context, uid uuid.UUID) (int64, error) {
	if f.LockFunc == nil {
		return lockTarget(ctx, uid)
	}

	return f.LockFunc(ctx, uid)
}

// IDs of the users the tests act as and on.
const (
	actorUserID  int64 = 1
	targetUserID int64 = 2
)

// lockTarget is a LockFunc resolving any UUID to targetUserID.
func lockTarget(context.Context, uuid.UUID) (int64, error) { return targetUserID, nil }

// fakePermissions is an actor.TargetPermissionReader over a user ID -> codes map.
type fakePermissions map[int64][]string

func (f fakePermissions) GetActorAndTargetPermissions(_ context.Context, actorID, targetID int64) (actor, target []string, err error) {
	return f[actorID], f[targetID], nil
}

// managerPermissions are what withManager's actor holds, in the context and in the database.
var managerPermissions = []string{domain.UsersRead, domain.UsersUpdate, domain.UsersDelete}

// fakeStorage is a test double for storage.Service that records UploadFile/DeleteFile calls.
type fakeStorage struct {
	UploadFileFunc func(ctx context.Context, filename string) (string, error)
	DeleteFileFunc func(ctx context.Context, fileURL string) error

	uploadCalls []string
	deleteCalls []string
}

func (f *fakeStorage) UploadFile(ctx context.Context, file io.Reader, originalFilename string) (string, error) {
	f.uploadCalls = append(f.uploadCalls, originalFilename)
	if f.UploadFileFunc != nil {
		return f.UploadFileFunc(ctx, originalFilename)
	}

	return "", nil
}

func (f *fakeStorage) DeleteFile(ctx context.Context, fileURL string) error {
	f.deleteCalls = append(f.deleteCalls, fileURL)
	if f.DeleteFileFunc != nil {
		return f.DeleteFileFunc(ctx, fileURL)
	}

	return nil
}

// fakeSessionRevoker records which users had their sessions revoked and their cache dropped.
type fakeSessionRevoker struct {
	revoked     []uuid.UUID
	invalidated []uuid.UUID
	err         error
}

func (f *fakeSessionRevoker) RevokeUserSessions(_ context.Context, uid uuid.UUID) error {
	f.revoked = append(f.revoked, uid)
	return f.err
}

func (f *fakeSessionRevoker) InvalidateUserSessions(_ context.Context, uid uuid.UUID) {
	f.invalidated = append(f.invalidated, uid)
}

// failingHasher is a security.PasswordHasher whose every call fails with err.
type failingHasher struct{ err error }

func (h failingHasher) Hash(context.Context, string) (string, error) { return "", h.err }

func (h failingHasher) Compare(context.Context, string, string) (bool, error) { return false, h.err }

func (h failingHasher) CompareDummy(context.Context, string) error { return h.err }

// noAvatar is a GetByUUIDFunc returning a user without an avatar.
func noAvatar(_ context.Context, uid uuid.UUID) (*domain.User, error) {
	return &domain.User{UUID: uid}, nil
}

// withActor returns a context whose actor is the user with uid and no permissions.
func withActor(uid uuid.UUID) context.Context {
	return actor.With(context.Background(), &actor.Actor{UserUUID: uid})
}

// withManager returns a context whose actor (actorUserID) holds managerPermissions.
func withManager() context.Context {
	return actor.With(context.Background(), &actor.Actor{UserID: actorUserID, UserUUID: uuid.New(), Permissions: managerPermissions})
}

// newTestUserService builds a UserService with a fast bcrypt hasher and a recording session revoker.
func newTestUserService(t *testing.T, repo domain.UserRepository, storage *fakeStorage) *UserService {
	t.Helper()
	svc, _ := newTestUserServiceWithRevoker(t, repo, storage)

	return svc
}

// newTestUserServiceWithRevoker is newTestUserService that also returns the revoker for assertions.
// In the database the actor holds managerPermissions and the target none.
func newTestUserServiceWithRevoker(t *testing.T, repo domain.UserRepository, storage *fakeStorage) (*UserService, *fakeSessionRevoker) {
	t.Helper()

	return newTestUserServiceWith(t, repo, storage, fakePermissions{actorUserID: managerPermissions})
}

// newTestUserServiceWith is newTestUserServiceWithRevoker with the database's permissions.
func newTestUserServiceWith(t *testing.T, repo domain.UserRepository, storage *fakeStorage, perms fakePermissions) (*UserService, *fakeSessionRevoker) {
	t.Helper()
	hasher, err := security.NewPasswordHasher(security.Options{Password: security.PasswordOptions{Cost: bcrypt.MinCost}})
	if err != nil {
		t.Fatalf("NewPasswordHasher() error = %v", err)
	}

	revoker := &fakeSessionRevoker{}

	svc := NewUserService(UserServiceParams{
		Repo:        repo,
		Permissions: perms,
		Storage:     storage,
		Hasher:      hasher,
		Sessions:    revoker,
		Logger:      zap.NewNop(),
	})

	return svc, revoker
}

func strPtr(s string) *string { return &s }
