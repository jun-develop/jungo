package service

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/jun-develop/junkit/security"

	"jungo/internal/common/actor"
	"jungo/internal/features/user/domain"
)

// fakeUserRepository is a test double for domain.UserRepository; calling an unset Func panics.
type fakeUserRepository struct {
	CreateFunc     func(ctx context.Context, input domain.CreateUserInput, passwordHash string) (*domain.User, error)
	GetByUUIDFunc  func(ctx context.Context, uid uuid.UUID) (*domain.User, error)
	GetByEmailFunc func(ctx context.Context, email string) (*domain.User, error)
	GetCredsFunc   func(ctx context.Context, email string) (*domain.Credentials, error)
	ListFunc       func(ctx context.Context, filter domain.UserListFilter) ([]*domain.User, int64, error)
	UpdateFunc     func(ctx context.Context, uid uuid.UUID, input domain.UpdateUserInput) (*domain.User, error)
	DeleteFunc     func(ctx context.Context, uid uuid.UUID) error
	LockFunc       func(ctx context.Context, uid uuid.UUID) (int64, error)
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

func (f *fakeUserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	return f.GetByEmailFunc(ctx, email)
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

func (f *fakeUserRepository) GetIDByUUID(ctx context.Context, uid uuid.UUID) (int64, error) {
	return f.LockFunc(ctx, uid)
}

func (f *fakeUserRepository) LockByUUID(ctx context.Context, uid uuid.UUID) (int64, error) {
	return f.LockFunc(ctx, uid)
}

// IDs of the users the tests act as and on.
const (
	actorUserID  int64 = 1
	targetUserID int64 = 2
)

// lockTarget is a LockFunc resolving any UUID to targetUserID.
func lockTarget(context.Context, uuid.UUID) (int64, error) { return targetUserID, nil }

// fakePermissions is a domain.PermissionReader over a user ID -> codes map.
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

// fakeSessionRevoker records which users had their sessions revoked.
type fakeSessionRevoker struct {
	revoked []uuid.UUID
	err     error
}

func (f *fakeSessionRevoker) RevokeUserSessions(_ context.Context, uid uuid.UUID) error {
	f.revoked = append(f.revoked, uid)
	return f.err
}

// newTestUserService builds a UserService with a fast bcrypt hasher and a no-op session revoker.
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
		t.Fatalf("NewPasswordHasher: %v", err)
	}

	revoker := &fakeSessionRevoker{}

	return NewUserService(repo, perms, storage, hasher, revoker, zap.NewNop()), revoker
}

func strPtr(s string) *string { return &s }

func TestUserService_CreateUser(t *testing.T) {
	t.Run("hashes the password and persists it, not the plaintext", func(t *testing.T) {
		var gotHash string
		var gotInput domain.CreateUserInput
		repo := &fakeUserRepository{
			CreateFunc: func(_ context.Context, input domain.CreateUserInput, passwordHash string) (*domain.User, error) {
				gotInput = input
				gotHash = passwordHash

				return &domain.User{Email: input.Email}, nil
			},
		}
		svc := newTestUserService(t, repo, &fakeStorage{})

		input := domain.CreateUserInput{FirstName: "Jane", LastName: "Doe", Email: "jane@example.com", Password: "s3cret-pw"}
		user, err := svc.CreateUser(context.Background(), input)
		if err != nil {
			t.Fatalf("CreateUser() error = %v, want nil", err)
		}

		if user.Email != input.Email {
			t.Errorf("repo received email %q, want %q", gotInput.Email, input.Email)
		}

		if gotHash == "" || gotHash == input.Password {
			t.Fatalf("repo received passwordHash %q, want a bcrypt hash distinct from the plaintext", gotHash)
		}

		if err := bcrypt.CompareHashAndPassword([]byte(gotHash), []byte(input.Password)); err != nil {
			t.Errorf("stored hash does not match the original password: %v", err)
		}
	})

	t.Run("propagates a repository error without wrapping", func(t *testing.T) {
		wantErr := errors.New("unique violation")
		repo := &fakeUserRepository{
			CreateFunc: func(context.Context, domain.CreateUserInput, string) (*domain.User, error) {
				return nil, wantErr
			},
		}
		svc := newTestUserService(t, repo, &fakeStorage{})

		_, err := svc.CreateUser(context.Background(), domain.CreateUserInput{Password: "whatever"})
		if !errors.Is(err, wantErr) {
			t.Fatalf("CreateUser() error = %v, want %v", err, wantErr)
		}
	})

	t.Run("rejects a password under 72 characters but over 72 bytes as a client error", func(t *testing.T) {
		repo := &fakeUserRepository{
			CreateFunc: func(context.Context, domain.CreateUserInput, string) (*domain.User, error) {
				t.Fatal("Create should not be called when hashing fails")
				return nil, nil
			},
		}
		svc := newTestUserService(t, repo, &fakeStorage{})

		password := strings.Repeat("ệ", 30) // 30 characters, 90 bytes
		_, err := svc.CreateUser(context.Background(), domain.CreateUserInput{Password: password})
		if !errors.Is(err, domain.ErrPasswordTooLong) {
			t.Fatalf("CreateUser() error = %v, want %v", err, domain.ErrPasswordTooLong)
		}
	})
}

func TestUserService_UploadAvatar(t *testing.T) {
	userID := uuid.New()

	t.Run("uploads the new file, updates the record, then deletes the old avatar", func(t *testing.T) {
		var deletedBeforeUpdate bool
		repo := &fakeUserRepository{
			GetByUUIDFunc: func(context.Context, uuid.UUID) (*domain.User, error) {
				return &domain.User{UUID: userID, AvatarURL: strPtr("old/avatar.png")}, nil
			},
			UpdateFunc: func(_ context.Context, _ uuid.UUID, input domain.UpdateUserInput) (*domain.User, error) {
				if input.AvatarURL == nil || *input.AvatarURL != "new/avatar.png" {
					t.Errorf("Update() got AvatarURL %v, want \"new/avatar.png\"", input.AvatarURL)
				}

				return &domain.User{UUID: userID, AvatarURL: input.AvatarURL}, nil
			},
		}
		storage := &fakeStorage{
			UploadFileFunc: func(context.Context, string) (string, error) { return "new/avatar.png", nil },
			DeleteFileFunc: func(_ context.Context, fileURL string) error {
				deletedBeforeUpdate = true
				if fileURL != "old/avatar.png" {
					t.Errorf("DeleteFile() got %q, want \"old/avatar.png\"", fileURL)
				}

				return nil
			},
		}
		svc := newTestUserService(t, repo, storage)

		user, err := svc.UploadAvatar(withActor(userID), userID, domain.AvatarFile{Filename: "me.png"})
		if err != nil {
			t.Fatalf("UploadAvatar() error = %v, want nil", err)
		}

		if !deletedBeforeUpdate {
			t.Error("old avatar was never deleted")
		}

		if *user.AvatarURL != "new/avatar.png" {
			t.Errorf("returned user AvatarURL = %q, want \"new/avatar.png\"", *user.AvatarURL)
		}
	})

	t.Run("does not attempt to delete anything when the user had no avatar", func(t *testing.T) {
		repo := &fakeUserRepository{
			GetByUUIDFunc: func(context.Context, uuid.UUID) (*domain.User, error) {
				return &domain.User{UUID: userID, AvatarURL: nil}, nil
			},
			UpdateFunc: func(_ context.Context, _ uuid.UUID, input domain.UpdateUserInput) (*domain.User, error) {
				return &domain.User{UUID: userID, AvatarURL: input.AvatarURL}, nil
			},
		}
		storage := &fakeStorage{
			UploadFileFunc: func(context.Context, string) (string, error) { return "new/avatar.png", nil },
		}
		svc := newTestUserService(t, repo, storage)

		if _, err := svc.UploadAvatar(withActor(userID), userID, domain.AvatarFile{Filename: "me.png"}); err != nil {
			t.Fatalf("UploadAvatar() error = %v, want nil", err)
		}

		if len(storage.deleteCalls) != 0 {
			t.Errorf("DeleteFile called %d times, want 0", len(storage.deleteCalls))
		}
	})

	t.Run("returns ErrInvalidAvatarFile and does not touch the record when upload fails", func(t *testing.T) {
		repo := &fakeUserRepository{
			GetByUUIDFunc: func(context.Context, uuid.UUID) (*domain.User, error) {
				return &domain.User{UUID: userID}, nil
			},
			UpdateFunc: func(context.Context, uuid.UUID, domain.UpdateUserInput) (*domain.User, error) {
				t.Fatal("Update should not be called when upload fails")
				return nil, nil
			},
		}
		storage := &fakeStorage{
			UploadFileFunc: func(context.Context, string) (string, error) { return "", errors.New("disk full") },
		}
		svc := newTestUserService(t, repo, storage)

		_, err := svc.UploadAvatar(withActor(userID), userID, domain.AvatarFile{Filename: "me.png"})
		if !errors.Is(err, domain.ErrInvalidAvatarFile) {
			t.Fatalf("UploadAvatar() error = %v, want %v", err, domain.ErrInvalidAvatarFile)
		}
	})

	t.Run("cleans up the newly uploaded file when Update fails, leaving the old avatar untouched", func(t *testing.T) {
		wantErr := errors.New("db unavailable")
		repo := &fakeUserRepository{
			GetByUUIDFunc: func(context.Context, uuid.UUID) (*domain.User, error) {
				return &domain.User{UUID: userID, AvatarURL: strPtr("old/avatar.png")}, nil
			},
			UpdateFunc: func(context.Context, uuid.UUID, domain.UpdateUserInput) (*domain.User, error) {
				return nil, wantErr
			},
		}
		storage := &fakeStorage{
			UploadFileFunc: func(context.Context, string) (string, error) { return "new/avatar.png", nil },
		}
		svc := newTestUserService(t, repo, storage)

		_, err := svc.UploadAvatar(withActor(userID), userID, domain.AvatarFile{Filename: "me.png"})
		if !errors.Is(err, wantErr) {
			t.Fatalf("UploadAvatar() error = %v, want %v", err, wantErr)
		}

		if len(storage.deleteCalls) != 1 || storage.deleteCalls[0] != "new/avatar.png" {
			t.Errorf("DeleteFile calls = %v, want exactly [\"new/avatar.png\"] (the orphaned upload must be cleaned up, the old avatar left alone)", storage.deleteCalls)
		}
	})

	t.Run("propagates a GetByUUID error before touching storage", func(t *testing.T) {
		wantErr := errors.New("user not found")
		repo := &fakeUserRepository{
			GetByUUIDFunc: func(context.Context, uuid.UUID) (*domain.User, error) { return nil, wantErr },
		}
		storage := &fakeStorage{}
		svc := newTestUserService(t, repo, storage)

		_, err := svc.UploadAvatar(withActor(userID), userID, domain.AvatarFile{Filename: "me.png"})
		if !errors.Is(err, wantErr) {
			t.Fatalf("UploadAvatar() error = %v, want %v", err, wantErr)
		}

		if len(storage.uploadCalls) != 0 {
			t.Errorf("UploadFile called %d times, want 0", len(storage.uploadCalls))
		}
	})
}

func TestUserService_DeleteAvatar(t *testing.T) {
	userID := uuid.New()

	t.Run("deletes the file and clears the avatar URL", func(t *testing.T) {
		var gotClearedTo *string
		repo := &fakeUserRepository{
			GetByUUIDFunc: func(context.Context, uuid.UUID) (*domain.User, error) {
				return &domain.User{UUID: userID, AvatarURL: strPtr("avatar.png")}, nil
			},
			UpdateFunc: func(_ context.Context, _ uuid.UUID, input domain.UpdateUserInput) (*domain.User, error) {
				gotClearedTo = input.AvatarURL
				return &domain.User{UUID: userID, AvatarURL: input.AvatarURL}, nil
			},
		}
		storage := &fakeStorage{}
		svc := newTestUserService(t, repo, storage)

		if _, err := svc.DeleteAvatar(withActor(userID), userID); err != nil {
			t.Fatalf("DeleteAvatar() error = %v, want nil", err)
		}

		if len(storage.deleteCalls) != 1 || storage.deleteCalls[0] != "avatar.png" {
			t.Errorf("DeleteFile calls = %v, want exactly [\"avatar.png\"]", storage.deleteCalls)
		}

		if gotClearedTo == nil || *gotClearedTo != "" {
			t.Errorf("Update() got AvatarURL %v, want a pointer to an empty string", gotClearedTo)
		}
	})

	t.Run("keeps the file when clearing the avatar URL fails", func(t *testing.T) {
		wantErr := errors.New("db unavailable")
		repo := &fakeUserRepository{
			GetByUUIDFunc: func(context.Context, uuid.UUID) (*domain.User, error) {
				return &domain.User{UUID: userID, AvatarURL: strPtr("avatar.png")}, nil
			},
			UpdateFunc: func(context.Context, uuid.UUID, domain.UpdateUserInput) (*domain.User, error) {
				return nil, wantErr
			},
		}
		storage := &fakeStorage{}
		svc := newTestUserService(t, repo, storage)

		_, err := svc.DeleteAvatar(withActor(userID), userID)
		if !errors.Is(err, wantErr) {
			t.Fatalf("DeleteAvatar() error = %v, want %v", err, wantErr)
		}

		if len(storage.deleteCalls) != 0 {
			t.Errorf("DeleteFile calls = %v, want none (the record still points at the file)", storage.deleteCalls)
		}
	})

	t.Run("is a no-op when the user has no avatar", func(t *testing.T) {
		repo := &fakeUserRepository{
			GetByUUIDFunc: func(context.Context, uuid.UUID) (*domain.User, error) {
				return &domain.User{UUID: userID, AvatarURL: nil}, nil
			},
			UpdateFunc: func(context.Context, uuid.UUID, domain.UpdateUserInput) (*domain.User, error) {
				t.Fatal("Update should not be called when there is no avatar to clear")
				return nil, nil
			},
		}
		storage := &fakeStorage{}
		svc := newTestUserService(t, repo, storage)

		if _, err := svc.DeleteAvatar(withActor(userID), userID); err != nil {
			t.Fatalf("DeleteAvatar() error = %v, want nil", err)
		}

		if len(storage.deleteCalls) != 0 {
			t.Errorf("DeleteFile called %d times, want 0", len(storage.deleteCalls))
		}
	})

	t.Run("treats an already-empty avatar URL as no avatar", func(t *testing.T) {
		repo := &fakeUserRepository{
			GetByUUIDFunc: func(context.Context, uuid.UUID) (*domain.User, error) {
				return &domain.User{UUID: userID, AvatarURL: strPtr("")}, nil
			},
		}
		storage := &fakeStorage{}
		svc := newTestUserService(t, repo, storage)

		if _, err := svc.DeleteAvatar(withActor(userID), userID); err != nil {
			t.Fatalf("DeleteAvatar() error = %v, want nil", err)
		}

		if len(storage.deleteCalls) != 0 {
			t.Errorf("DeleteFile called %d times, want 0", len(storage.deleteCalls))
		}
	})

	t.Run("propagates a GetByUUID error", func(t *testing.T) {
		wantErr := errors.New("user not found")
		repo := &fakeUserRepository{
			GetByUUIDFunc: func(context.Context, uuid.UUID) (*domain.User, error) { return nil, wantErr },
		}
		svc := newTestUserService(t, repo, &fakeStorage{})

		_, err := svc.DeleteAvatar(withActor(userID), userID)
		if !errors.Is(err, wantErr) {
			t.Fatalf("DeleteAvatar() error = %v, want %v", err, wantErr)
		}
	})
}

func TestUserService_GetUser(t *testing.T) {
	userID := uuid.New()
	want := &domain.User{UUID: userID, Email: "jane@example.com"}
	repo := &fakeUserRepository{
		GetByUUIDFunc: func(_ context.Context, uid uuid.UUID) (*domain.User, error) {
			if uid != userID {
				t.Errorf("GetByUUID called with %v, want %v", uid, userID)
			}

			return want, nil
		},
	}
	svc := newTestUserService(t, repo, &fakeStorage{})

	got, err := svc.GetUser(withActor(userID), userID)
	if err != nil {
		t.Fatalf("GetUser() error = %v, want nil", err)
	}

	if got != want {
		t.Errorf("GetUser() = %v, want %v", got, want)
	}
}

func TestUserService_GetUsers(t *testing.T) {
	filter := domain.UserListFilter{Search: "jane", Limit: 10, Offset: 0, SortOrder: "asc"}
	wantUsers := []*domain.User{{Email: "jane@example.com"}}
	repo := &fakeUserRepository{
		ListFunc: func(_ context.Context, f domain.UserListFilter) ([]*domain.User, int64, error) {
			if f != filter {
				t.Errorf("List called with %+v, want %+v", f, filter)
			}

			return wantUsers, 1, nil
		},
	}
	svc := newTestUserService(t, repo, &fakeStorage{})

	users, total, err := svc.GetUsers(context.Background(), filter)
	if err != nil {
		t.Fatalf("GetUsers() error = %v, want nil", err)
	}

	if total != 1 || len(users) != 1 {
		t.Errorf("GetUsers() = (%v, %d), want ([1 user], 1)", users, total)
	}
}

func TestUserService_NormalizesEmail(t *testing.T) {
	t.Run("CreateUser stores the email lowercase and trimmed", func(t *testing.T) {
		var got string
		repo := &fakeUserRepository{
			CreateFunc: func(_ context.Context, input domain.CreateUserInput, _ string) (*domain.User, error) {
				got = input.Email
				return &domain.User{Email: input.Email}, nil
			},
		}
		svc := newTestUserService(t, repo, &fakeStorage{})

		if _, err := svc.CreateUser(context.Background(), domain.CreateUserInput{Email: "  Jane.Doe@Example.COM ", Password: "s3cret-pw"}); err != nil {
			t.Fatal(err)
		}

		if got != "jane.doe@example.com" {
			t.Errorf("stored email = %q, want jane.doe@example.com", got)
		}
	})

	t.Run("GetCredentialsByEmail looks up the normalized email", func(t *testing.T) {
		var got string
		repo := &fakeUserRepository{
			GetCredsFunc: func(_ context.Context, email string) (*domain.Credentials, error) {
				got = email
				return &domain.Credentials{}, nil
			},
		}
		svc := newTestUserService(t, repo, &fakeStorage{})

		if _, err := svc.GetCredentialsByEmail(context.Background(), "Jane.Doe@Example.COM"); err != nil {
			t.Fatal(err)
		}

		if got != "jane.doe@example.com" {
			t.Errorf("looked up %q, want jane.doe@example.com", got)
		}
	})
}

func TestUserService_UpdateUser(t *testing.T) {
	userID := uuid.New()
	input := domain.UpdateUserInput{FirstName: strPtr("New")}
	want := &domain.User{UUID: userID, FirstName: "New", Status: domain.UserStatusActive}
	repo := &fakeUserRepository{
		LockFunc: lockTarget,
		UpdateFunc: func(_ context.Context, uid uuid.UUID, in domain.UpdateUserInput) (*domain.User, error) {
			if uid != userID || in.FirstName == nil || *in.FirstName != "New" {
				t.Errorf("Update called with (%v, %+v), want (%v, %+v)", uid, in, userID, input)
			}

			return want, nil
		},
	}
	svc, revoker := newTestUserServiceWithRevoker(t, repo, &fakeStorage{})

	got, err := svc.UpdateUser(withManager(), userID, input)
	if err != nil {
		t.Fatalf("UpdateUser() error = %v, want nil", err)
	}

	if got != want {
		t.Errorf("UpdateUser() = %v, want %v", got, want)
	}

	if len(revoker.revoked) != 0 {
		t.Errorf("sessions revoked for an active user: %v", revoker.revoked)
	}
}

func TestUserService_UpdateUser_DeactivationRevokesSessions(t *testing.T) {
	userID := uuid.New()
	inactive := domain.UserStatusInactive
	repo := &fakeUserRepository{
		LockFunc: lockTarget,
		UpdateFunc: func(context.Context, uuid.UUID, domain.UpdateUserInput) (*domain.User, error) {
			return &domain.User{UUID: userID, Status: domain.UserStatusInactive}, nil
		},
	}
	svc, revoker := newTestUserServiceWithRevoker(t, repo, &fakeStorage{})

	if _, err := svc.UpdateUser(withManager(), userID, domain.UpdateUserInput{Status: &inactive}); err != nil {
		t.Fatalf("UpdateUser() error = %v, want nil", err)
	}

	if len(revoker.revoked) != 1 || revoker.revoked[0] != userID {
		t.Errorf("revoked = %v, want [%v]", revoker.revoked, userID)
	}
}

func TestUserService_UpdateUser_DeactivationPropagatesRevokeError(t *testing.T) {
	wantErr := errors.New("revoke failed")
	inactive := domain.UserStatusInactive
	repo := &fakeUserRepository{
		LockFunc: lockTarget,
		UpdateFunc: func(_ context.Context, uid uuid.UUID, _ domain.UpdateUserInput) (*domain.User, error) {
			return &domain.User{UUID: uid, Status: domain.UserStatusInactive}, nil
		},
	}
	svc, revoker := newTestUserServiceWithRevoker(t, repo, &fakeStorage{})
	revoker.err = wantErr

	if _, err := svc.UpdateUser(withManager(), uuid.New(), domain.UpdateUserInput{Status: &inactive}); !errors.Is(err, wantErr) {
		t.Fatalf("UpdateUser() error = %v, want %v", err, wantErr)
	}
}

func TestUserService_DeleteUser(t *testing.T) {
	t.Run("delegates to the repository and revokes the user's sessions", func(t *testing.T) {
		userID := uuid.New()
		var gotID uuid.UUID
		repo := &fakeUserRepository{
			LockFunc:      lockTarget,
			GetByUUIDFunc: noAvatar,
			DeleteFunc: func(_ context.Context, uid uuid.UUID) error {
				gotID = uid
				return nil
			},
		}
		svc, revoker := newTestUserServiceWithRevoker(t, repo, &fakeStorage{})

		if err := svc.DeleteUser(withManager(), userID); err != nil {
			t.Fatalf("DeleteUser() error = %v, want nil", err)
		}

		if gotID != userID {
			t.Errorf("Delete called with %v, want %v", gotID, userID)
		}

		if len(revoker.revoked) != 1 || revoker.revoked[0] != userID {
			t.Errorf("revoked = %v, want [%v]", revoker.revoked, userID)
		}
	})

	t.Run("propagates a repository error", func(t *testing.T) {
		wantErr := errors.New("not found")
		repo := &fakeUserRepository{
			LockFunc:      lockTarget,
			GetByUUIDFunc: noAvatar,
			DeleteFunc:    func(context.Context, uuid.UUID) error { return wantErr },
		}
		svc := newTestUserService(t, repo, &fakeStorage{})

		if err := svc.DeleteUser(withManager(), uuid.New()); !errors.Is(err, wantErr) {
			t.Fatalf("DeleteUser() error = %v, want %v", err, wantErr)
		}
	})
}

func TestUserService_DeleteUser_RemovesAvatarFile(t *testing.T) {
	repo := &fakeUserRepository{
		LockFunc: lockTarget,
		GetByUUIDFunc: func(_ context.Context, uid uuid.UUID) (*domain.User, error) {
			return &domain.User{UUID: uid, AvatarURL: strPtr("avatar.png")}, nil
		},
		DeleteFunc: func(context.Context, uuid.UUID) error { return nil },
	}
	storage := &fakeStorage{}
	svc := newTestUserService(t, repo, storage)

	if err := svc.DeleteUser(withManager(), uuid.New()); err != nil {
		t.Fatalf("DeleteUser() error = %v, want nil", err)
	}

	if len(storage.deleteCalls) != 1 || storage.deleteCalls[0] != "avatar.png" {
		t.Errorf("deleted files = %v, want [avatar.png]", storage.deleteCalls)
	}
}

func TestUserService_UploadAvatar_ReauthorizesAfterUpload(t *testing.T) {
	db := fakePermissions{actorUserID: managerPermissions, targetUserID: {domain.UsersRead}}
	var wrote bool
	repo := &fakeUserRepository{
		LockFunc:      lockTarget,
		GetByUUIDFunc: noAvatar,
		UpdateFunc: func(context.Context, uuid.UUID, domain.UpdateUserInput) (*domain.User, error) {
			wrote = true
			return &domain.User{}, nil
		},
	}
	storage := &fakeStorage{
		// The target is promoted while the file uploads.
		UploadFileFunc: func(context.Context, string) (string, error) {
			db[targetUserID] = []string{domain.UsersRead, "roles:assign"}
			return "new.png", nil
		},
	}
	svc, _ := newTestUserServiceWith(t, repo, storage, db)

	_, err := svc.UploadAvatar(withManager(), uuid.New(), domain.AvatarFile{Filename: "a.png"})
	if !errors.Is(err, domain.ErrCannotManageStrongerUser) {
		t.Fatalf("UploadAvatar() error = %v, want %v", err, domain.ErrCannotManageStrongerUser)
	}

	if wrote {
		t.Error("avatar URL was written for a user who became stronger during the upload")
	}

	if len(storage.deleteCalls) != 1 || storage.deleteCalls[0] != "new.png" {
		t.Errorf("deleted files = %v, want the new upload [new.png]", storage.deleteCalls)
	}
}

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

func TestUserService_ActingOnUsers(t *testing.T) {
	self := uuid.New()
	inactive := domain.UserStatusInactive
	deactivate := domain.UpdateUserInput{Status: &inactive}
	asSelf := actor.With(context.Background(), &actor.Actor{UserID: actorUserID, UserUUID: self, Permissions: managerPermissions})
	noPermission := actor.With(context.Background(), &actor.Actor{UserID: actorUserID, UserUUID: uuid.New()})

	cases := []struct {
		name   string
		ctx    context.Context
		target uuid.UUID
		db     fakePermissions // actorUserID's and targetUserID's permissions in the database
		delete bool            // DeleteUser instead of UpdateUser(deactivate)
		want   error
	}{
		{"weaker target", withManager(), uuid.New(), fakePermissions{actorUserID: managerPermissions, targetUserID: {domain.UsersRead}}, false, nil},
		{"equal target", withManager(), uuid.New(), fakePermissions{actorUserID: managerPermissions, targetUserID: managerPermissions}, true, nil},
		{"stronger target", withManager(), uuid.New(), fakePermissions{actorUserID: managerPermissions, targetUserID: {domain.UsersRead, "roles:assign"}}, false, domain.ErrCannotManageStrongerUser},
		{"stronger target, delete", withManager(), uuid.New(), fakePermissions{actorUserID: managerPermissions, targetUserID: {"roles:assign"}}, true, domain.ErrCannotManageStrongerUser},
		{"permission removed since the request's cache", withManager(), uuid.New(), fakePermissions{actorUserID: {domain.UsersRead}}, false, actor.ErrForbidden},
		{"no permission hides the user", noPermission, uuid.New(), nil, false, domain.ErrUserNotFound},
		{"no actor hides the user", context.Background(), uuid.New(), nil, true, domain.ErrUserNotFound},
		{"own status", asSelf, self, nil, false, domain.ErrCannotChangeOwnStatus},
		{"own account", asSelf, self, nil, true, domain.ErrCannotDeleteSelf},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var wrote bool
			repo := &fakeUserRepository{
				LockFunc:      lockTarget,
				GetByUUIDFunc: noAvatar,
				UpdateFunc: func(_ context.Context, uid uuid.UUID, _ domain.UpdateUserInput) (*domain.User, error) {
					wrote = true
					return &domain.User{UUID: uid, Status: domain.UserStatusInactive}, nil
				},
				DeleteFunc: func(context.Context, uuid.UUID) error {
					wrote = true
					return nil
				},
			}
			svc, _ := newTestUserServiceWith(t, repo, &fakeStorage{}, tc.db)

			var err error
			if tc.delete {
				err = svc.DeleteUser(tc.ctx, tc.target)
			} else {
				_, err = svc.UpdateUser(tc.ctx, tc.target, deactivate)
			}

			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}

			if wrote != (tc.want == nil) {
				t.Errorf("wrote = %v, want %v", wrote, tc.want == nil)
			}
		})
	}
}
