package service

// =============================================================================
// TEST HELPERS (no test scenarios)
// =============================================================================
//
// File: fakes_test.go
// Purpose: Func-field fakes for UserService's dependencies (repository, permission reader,
//          storage, session revoker, password hasher), answer builders, and a constructor for the
//          service.
// Used by: user_service_test.go
//
// =============================================================================

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/jun-develop/junkit/security"

	"jungo/internal/common/actor"
	"jungo/internal/features/user/domain"
)

// IDs of the users the tests act as and on.
const (
	actorUserID  int64 = 1
	targetUserID int64 = 2
)

// actorUUID is the acting user's UUID when a test does not act on itself.
var actorUUID = uuid.MustParse("00000000-0000-0000-0000-000000000001")

// managerPermissions are what a manager actor holds, in the context and in the database.
var managerPermissions = []string{domain.UsersRead, domain.UsersUpdate, domain.UsersDelete}

// errDB stands in for a failing database.
var errDB = errors.New("fake database: connection lost")

// fakeUserRepository is a domain.UserRepository whose answers each test sets through the Func
// fields. Calling a method whose Func is nil panics, except LockByUUID, which resolves any UUID to
// targetUserID: the lock decides nothing a test checks unless the test makes it fail.
type fakeUserRepository struct {
	CreateFunc                func(ctx context.Context, in domain.CreateUserInput, hash string) (*domain.User, error)
	GetByUUIDFunc             func(ctx context.Context, uid uuid.UUID) (*domain.User, error)
	GetCredentialsByEmailFunc func(ctx context.Context, email string) (*domain.Credentials, error)
	UpdatePasswordFunc        func(ctx context.Context, userID int64, passwordHash string) error
	ListFunc                  func(ctx context.Context, filter domain.UserListFilter) ([]*domain.User, int64, error)
	UpdateFunc                func(ctx context.Context, uid uuid.UUID, in domain.UpdateUserInput) (*domain.User, error)
	DeleteFunc                func(ctx context.Context, uid uuid.UUID) error
	GetIDByUUIDFunc           func(ctx context.Context, uid uuid.UUID) (int64, error)
	LockByUUIDFunc            func(ctx context.Context, uid uuid.UUID) (int64, error)
}

// WithTransaction runs fn directly: the fake has nothing to commit or roll back.
func (f *fakeUserRepository) WithTransaction(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

// Create answers through CreateFunc.
func (f *fakeUserRepository) Create(
	ctx context.Context,
	input domain.CreateUserInput,
	passwordHash string,
) (*domain.User, error) {
	return f.CreateFunc(ctx, input, passwordHash)
}

// GetByUUID answers through GetByUUIDFunc.
func (f *fakeUserRepository) GetByUUID(ctx context.Context, uid uuid.UUID) (*domain.User, error) {
	return f.GetByUUIDFunc(ctx, uid)
}

// GetCredentialsByEmail answers through GetCredentialsByEmailFunc.
func (f *fakeUserRepository) GetCredentialsByEmail(ctx context.Context, email string) (*domain.Credentials, error) {
	return f.GetCredentialsByEmailFunc(ctx, email)
}

// UpdatePassword answers through UpdatePasswordFunc.
func (f *fakeUserRepository) UpdatePassword(ctx context.Context, userID int64, passwordHash string) error {
	return f.UpdatePasswordFunc(ctx, userID, passwordHash)
}

// List answers through ListFunc.
func (f *fakeUserRepository) List(ctx context.Context, filter domain.UserListFilter) ([]*domain.User, int64, error) {
	return f.ListFunc(ctx, filter)
}

// Update answers through UpdateFunc.
func (f *fakeUserRepository) Update(
	ctx context.Context,
	uid uuid.UUID,
	input domain.UpdateUserInput,
) (*domain.User, error) {
	return f.UpdateFunc(ctx, uid, input)
}

// Delete answers through DeleteFunc.
func (f *fakeUserRepository) Delete(ctx context.Context, uid uuid.UUID) error {
	return f.DeleteFunc(ctx, uid)
}

// GetIDByUUID answers through GetIDByUUIDFunc.
func (f *fakeUserRepository) GetIDByUUID(ctx context.Context, uid uuid.UUID) (int64, error) {
	return f.GetIDByUUIDFunc(ctx, uid)
}

// LockByUUID answers through LockByUUIDFunc, or returns targetUserID when it is nil.
func (f *fakeUserRepository) LockByUUID(ctx context.Context, uid uuid.UUID) (int64, error) {
	if f.LockByUUIDFunc == nil {
		return targetUserID, nil
	}

	return f.LockByUUIDFunc(ctx, uid)
}

// fakePermissionReader is an actor.TargetPermissionReader answering through its Func field.
type fakePermissionReader struct {
	GetActorAndTargetPermissionsFunc func(ctx context.Context, actorID, targetID int64) ([]string, []string, error)
}

// GetActorAndTargetPermissions answers through GetActorAndTargetPermissionsFunc.
func (f *fakePermissionReader) GetActorAndTargetPermissions(
	ctx context.Context,
	actorID, targetID int64,
) (actor, target []string, err error) {
	return f.GetActorAndTargetPermissionsFunc(ctx, actorID, targetID)
}

// dbHolds returns a permission reader answering from db, user ID -> permission codes: what the
// database holds when the service asks. A test may change db to simulate a concurrent change.
func dbHolds(db map[int64][]string) *fakePermissionReader {
	return &fakePermissionReader{
		GetActorAndTargetPermissionsFunc: func(_ context.Context, actorID, targetID int64) ([]string, []string, error) {
			return db[actorID], db[targetID], nil
		},
	}
}

// fakeStorage is a storage.Service answering through its Func fields; calling a method whose Func
// is nil panics.
type fakeStorage struct {
	UploadFileFunc func(ctx context.Context, file io.Reader, originalFilename string) (string, error)
	DeleteFileFunc func(ctx context.Context, fileURL string) error
}

// UploadFile answers through UploadFileFunc.
func (f *fakeStorage) UploadFile(ctx context.Context, file io.Reader, originalFilename string) (string, error) {
	return f.UploadFileFunc(ctx, file, originalFilename)
}

// DeleteFile answers through DeleteFileFunc.
func (f *fakeStorage) DeleteFile(ctx context.Context, fileURL string) error {
	return f.DeleteFileFunc(ctx, fileURL)
}

// uploadsAs is an UploadFileFunc that stores every file under url.
func uploadsAs(url string) func(context.Context, io.Reader, string) (string, error) {
	return func(context.Context, io.Reader, string) (string, error) {
		return url, nil
	}
}

// recordDeletes is a DeleteFileFunc that appends every deleted URL to got.
func recordDeletes(got *[]string) func(context.Context, string) error {
	return func(_ context.Context, fileURL string) error {
		*got = append(*got, fileURL)
		return nil
	}
}

// fakeSessionRevoker is a domain.SessionRevoker. RevokeUserSessions answers through its Func and
// panics when it is nil; InvalidateUserSessions only records the user, like a cache would drop it.
type fakeSessionRevoker struct {
	RevokeUserSessionsFunc func(ctx context.Context, uid uuid.UUID) error

	invalidated []uuid.UUID
}

// RevokeUserSessions answers through RevokeUserSessionsFunc.
func (f *fakeSessionRevoker) RevokeUserSessions(ctx context.Context, uid uuid.UUID) error {
	return f.RevokeUserSessionsFunc(ctx, uid)
}

// InvalidateUserSessions records uid.
func (f *fakeSessionRevoker) InvalidateUserSessions(_ context.Context, uid uuid.UUID) {
	f.invalidated = append(f.invalidated, uid)
}

// recordRevokes is a RevokeUserSessionsFunc that appends every user whose sessions are revoked
// to got.
func recordRevokes(got *[]uuid.UUID) func(context.Context, uuid.UUID) error {
	return func(_ context.Context, uid uuid.UUID) error {
		*got = append(*got, uid)
		return nil
	}
}

// failingHasher is a security.PasswordHasher whose every call fails with err.
type failingHasher struct {
	err error
}

// Hash returns err.
func (h failingHasher) Hash(context.Context, string) (string, error) {
	return "", h.err
}

// Compare returns err.
func (h failingHasher) Compare(context.Context, string, string) (bool, error) {
	return false, h.err
}

// CompareDummy returns err.
func (h failingHasher) CompareDummy(context.Context, string) error {
	return h.err
}

// noAvatar is a GetByUUIDFunc returning the user without an avatar.
func noAvatar(_ context.Context, uid uuid.UUID) (*domain.User, error) {
	return &domain.User{UUID: uid}, nil
}

// withAvatar returns a GetByUUIDFunc returning the user with avatar URL url.
func withAvatar(url string) func(context.Context, uuid.UUID) (*domain.User, error) {
	return func(_ context.Context, uid uuid.UUID) (*domain.User, error) {
		return &domain.User{UUID: uid, AvatarURL: new(url)}, nil
	}
}

// asActor returns a context whose actor (actorUserID) is the user uid and holds perms in its
// cached copy, as middleware.Guard sets it.
func asActor(uid uuid.UUID, perms ...string) context.Context {
	return actor.With(context.Background(), &actor.Actor{UserID: actorUserID, UserUUID: uid, Permissions: perms})
}

// asManager returns a context whose actor is actorUUID holding managerPermissions.
func asManager() context.Context {
	return asActor(actorUUID, managerPermissions...)
}

// newTestService returns a UserService built from p. Fields p leaves nil get defaults: the
// database grants the actor managerPermissions and the target nothing, storage and the session
// revoker are fakes that panic when called, a bcrypt hasher at the minimum cost, a no-op logger.
func newTestService(t *testing.T, p UserServiceParams) *UserService {
	t.Helper()

	if p.Permissions == nil {
		p.Permissions = dbHolds(map[int64][]string{actorUserID: managerPermissions})
	}

	if p.Storage == nil {
		p.Storage = &fakeStorage{}
	}

	if p.Sessions == nil {
		p.Sessions = &fakeSessionRevoker{}
	}

	if p.Hasher == nil {
		hasher, err := security.NewPasswordHasher(security.Options{
			Password: security.PasswordOptions{Cost: bcrypt.MinCost},
		})
		if err != nil {
			t.Fatalf("NewPasswordHasher() error = %v", err)
		}

		p.Hasher = hasher
	}

	if p.Logger == nil {
		p.Logger = zap.NewNop()
	}

	return NewUserService(p)
}

// wantErr fails the test unless errors.Is(got, want).
func wantErr(t *testing.T, got, want error) {
	t.Helper()

	if !errors.Is(got, want) {
		t.Fatalf("error = %v, want %v", got, want)
	}
}
