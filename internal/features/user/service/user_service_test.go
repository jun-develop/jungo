package service

// =============================================================================
// TEST CASE OVERVIEW
// =============================================================================
//
// File: user_service_test.go
// Purpose: Verify UserService: user creation, lookup, updates, deletion, avatars and who may act on which user.
// Type: Unit (in-memory fakes from fakes_test.go)
//
// Test functions: 21
// Total scenarios: 46
//
// #   Test Case                                                             Scenario                                    Expected Result
// 1   TestUserService_CreateUser_HashesPasswordAndMapsErrors                Valid input                                 Repository receives a bcrypt hash, never the plaintext
// 2   TestUserService_CreateUser_HashesPasswordAndMapsErrors                Repository fails                            Repository error returned unchanged
// 3   TestUserService_CreateUser_HashesPasswordAndMapsErrors                30 characters but 90 bytes                  ErrPasswordTooLong; nothing stored
// 4   TestUserService_CreateUser_HashesPasswordAndMapsErrors                Hasher fails for another reason             Hasher error returned unchanged; nothing stored
// 5   TestUserService_UploadAvatar_ReplacesStoredFile                       User had an avatar                          New file uploaded, record updated, old file deleted
// 6   TestUserService_UploadAvatar_ReplacesStoredFile                       User had no avatar                          Nothing deleted
// 7   TestUserService_UploadAvatar_ReplacesStoredFile                       Upload fails                                ErrInvalidAvatarFile; record untouched
// 8   TestUserService_UploadAvatar_ReplacesStoredFile                       Record update fails                         Error returned; new upload deleted, old avatar kept
// 9   TestUserService_UploadAvatar_ReplacesStoredFile                       User lookup fails                           Error returned; new upload deleted
// 10  TestUserService_UploadAvatar_RejectsUnauthorizedActorBeforeUploading  No actor in the request                     ErrUserNotFound; nothing uploaded
// 11  TestUserService_UploadAvatar_ReauthorizesAfterUpload                  Target promoted during the upload           ErrCannotManageStrongerUser; nothing written, upload deleted
// 12  TestUserService_DeleteAvatar_ClearsURLThenDeletesFile                 User has an avatar                          URL cleared, then the file deleted
// 13  TestUserService_DeleteAvatar_ClearsURLThenDeletesFile                 Clearing the URL fails                      Error returned; file kept
// 14  TestUserService_DeleteAvatar_ClearsURLThenDeletesFile                 No avatar                                   No-op
// 15  TestUserService_DeleteAvatar_ClearsURLThenDeletesFile                 Avatar URL is an empty string               Treated as no avatar
// 16  TestUserService_DeleteAvatar_ClearsURLThenDeletesFile                 User lookup fails                           Error returned
// 17  TestUserService_DeleteAvatar_PropagatesLockError                      Row lock fails                              Error returned; nothing updated or deleted
// 18  TestUserService_GetUser_ReturnsUserToSelfOrReader                     User reads themself                         Returns the user
// 19  TestUserService_GetUser_ReturnsUserToSelfOrReader                     Holder of users:read reads another user     Returns the user
// 20  TestUserService_GetUser_HidesUserFromUnauthorizedActors               No actor in the request                     ErrUserNotFound; repository not queried
// 21  TestUserService_GetUser_HidesUserFromUnauthorizedActors               Other user without users:read               ErrUserNotFound; repository not queried
// 22  TestUserService_GetUser_PropagatesRepositoryError                     Repository fails                            Repository error returned
// 23  TestUserService_SetPasswordHash_UpdatesStoredHash                     Valid user ID and hash                      Repository stores that hash for that user
// 24  TestUserService_SetPasswordHash_UpdatesStoredHash                     Repository fails                            Repository error returned
// 25  TestUserService_ListUsers_PassesFilterToRepository                    Search filter                               Repository receives the same filter; its page returned
// 26  TestUserService_NormalizesEmailOnCreateAndLookup                      CreateUser with mixed case and spaces       Email stored lowercase and trimmed
// 27  TestUserService_NormalizesEmailOnCreateAndLookup                      GetCredentialsByEmail with mixed case       Normalized email looked up
// 28  TestUserService_UpdateUser_UpdatesActiveUserWithoutRevoking           Manager renames an active user              Updated user returned; no session revoked
// 29  TestUserService_UpdateUser_DeactivationRevokesSessions                Manager deactivates a user                  Sessions revoked and cached sessions dropped
// 30  TestUserService_UpdateUser_DeactivationPropagatesRevokeError          Session revocation fails                    Revocation error returned
// 31  TestUserService_UpdateUser_PropagatesRepositoryErrors                 Update fails                                Error returned; cached sessions kept
// 32  TestUserService_UpdateUser_PropagatesRepositoryErrors                 Target row lock fails during authorization  Error returned; nothing updated
// 33  TestUserService_DeleteUser_DeletesAndRevokesSessions                  Manager deletes a user                      Repository deletes that user; sessions revoked
// 34  TestUserService_DeleteUser_DeletesAndRevokesSessions                  Repository delete fails                     Repository error returned
// 35  TestUserService_DeleteUser_StopsWhenLookupFails                       User lookup fails                           Error returned; nothing deleted, no session revoked
// 36  TestUserService_DeleteUser_RemovesAvatarFile                          Deleted user had an avatar                  Avatar file deleted
// 37  TestUserService_DeleteUser_LogsAvatarDeleteFailure                    Avatar file deletion fails                  DeleteUser still succeeds; failure logged
// 38  TestUserService_UpdateAndDeleteUser_EnforceAuthorization              Deactivate a weaker user                    Allowed
// 39  TestUserService_UpdateAndDeleteUser_EnforceAuthorization              Delete a user with equal permissions        Allowed
// 40  TestUserService_UpdateAndDeleteUser_EnforceAuthorization              Deactivate a stronger user                  ErrCannotManageStrongerUser; nothing written
// 41  TestUserService_UpdateAndDeleteUser_EnforceAuthorization              Delete a stronger user                      ErrCannotManageStrongerUser; nothing written
// 42  TestUserService_UpdateAndDeleteUser_EnforceAuthorization              Permission removed since the cache          ErrForbidden; nothing written
// 43  TestUserService_UpdateAndDeleteUser_EnforceAuthorization              Actor without the permission                ErrUserNotFound (user hidden)
// 44  TestUserService_UpdateAndDeleteUser_EnforceAuthorization              No actor in the request                     ErrUserNotFound (user hidden)
// 45  TestUserService_UpdateAndDeleteUser_EnforceAuthorization              User changes their own status               ErrCannotChangeOwnStatus
// 46  TestUserService_UpdateAndDeleteUser_EnforceAuthorization              User deletes their own account              ErrCannotDeleteSelf
//
// =============================================================================

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/crypto/bcrypt"

	"jungo/internal/common/actor"
	"jungo/internal/features/user/domain"
)

func TestUserService_CreateUser_HashesPasswordAndMapsErrors(t *testing.T) {
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

		if gotInput.Email != input.Email {
			t.Errorf("repo received email %q, want %q", gotInput.Email, input.Email)
		}

		if user.Email != input.Email {
			t.Errorf("CreateUser().Email = %q, want %q", user.Email, input.Email)
		}

		if gotHash == "" {
			t.Fatal("repo received an empty passwordHash, want a bcrypt hash")
		}

		if gotHash == input.Password {
			t.Fatal("repo received the plaintext password, want a bcrypt hash")
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
		if err != wantErr {
			t.Fatalf("CreateUser() error = %v, want exactly %v", err, wantErr)
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

		// 30 characters, 90 bytes.
		password := strings.Repeat("ệ", 30)
		_, err := svc.CreateUser(context.Background(), domain.CreateUserInput{Password: password})
		if !errors.Is(err, domain.ErrPasswordTooLong) {
			t.Fatalf("CreateUser() error = %v, want %v", err, domain.ErrPasswordTooLong)
		}
	})

	t.Run("propagates any other hashing error unchanged", func(t *testing.T) {
		wantErr := context.DeadlineExceeded
		repo := &fakeUserRepository{
			CreateFunc: func(context.Context, domain.CreateUserInput, string) (*domain.User, error) {
				t.Fatal("Create should not be called when hashing fails")
				return nil, nil
			},
		}
		svc := newTestUserService(t, repo, &fakeStorage{})
		svc.hasher = failingHasher{err: wantErr}

		_, err := svc.CreateUser(context.Background(), domain.CreateUserInput{Password: "s3cret-pw"})
		if err != wantErr {
			t.Fatalf("CreateUser() error = %v, want exactly %v", err, wantErr)
		}
	})
}

func TestUserService_UploadAvatar_ReplacesStoredFile(t *testing.T) {
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

		if user.AvatarURL == nil {
			t.Fatal("returned user AvatarURL = nil, want \"new/avatar.png\"")
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

		if len(storage.deleteCalls) != 1 {
			t.Fatalf("DeleteFile calls = %v, want exactly [\"new/avatar.png\"] (the orphaned upload must be cleaned up, the old avatar left alone)", storage.deleteCalls)
		}

		if storage.deleteCalls[0] != "new/avatar.png" {
			t.Errorf("DeleteFile called with %q, want \"new/avatar.png\" (the old avatar must be left alone)", storage.deleteCalls[0])
		}
	})

	t.Run("propagates a GetByUUID error and removes the new upload", func(t *testing.T) {
		wantErr := errors.New("user not found")
		repo := &fakeUserRepository{
			GetByUUIDFunc: func(context.Context, uuid.UUID) (*domain.User, error) { return nil, wantErr },
		}
		storage := &fakeStorage{
			UploadFileFunc: func(context.Context, string) (string, error) { return "new/avatar.png", nil },
		}
		svc := newTestUserService(t, repo, storage)

		_, err := svc.UploadAvatar(withActor(userID), userID, domain.AvatarFile{Filename: "me.png"})
		if !errors.Is(err, wantErr) {
			t.Fatalf("UploadAvatar() error = %v, want %v", err, wantErr)
		}

		if len(storage.deleteCalls) != 1 {
			t.Fatalf("DeleteFile calls = %v, want exactly [\"new/avatar.png\"]", storage.deleteCalls)
		}

		if storage.deleteCalls[0] != "new/avatar.png" {
			t.Errorf("DeleteFile called with %q, want \"new/avatar.png\"", storage.deleteCalls[0])
		}
	})
}

func TestUserService_UploadAvatar_RejectsUnauthorizedActorBeforeUploading(t *testing.T) {
	storage := &fakeStorage{}
	svc := newTestUserService(t, &fakeUserRepository{}, storage)

	_, err := svc.UploadAvatar(context.Background(), uuid.New(), domain.AvatarFile{Filename: "me.png"})

	if !errors.Is(err, domain.ErrUserNotFound) {
		t.Fatalf("UploadAvatar() error = %v, want %v", err, domain.ErrUserNotFound)
	}

	if len(storage.uploadCalls) != 0 {
		t.Errorf("UploadFile calls = %v, want none for an unauthorized actor", storage.uploadCalls)
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
	if !errors.Is(err, actor.ErrCannotManageStrongerUser) {
		t.Fatalf("UploadAvatar() error = %v, want %v", err, actor.ErrCannotManageStrongerUser)
	}

	if wrote {
		t.Error("avatar URL was written for a user who became stronger during the upload")
	}

	if len(storage.deleteCalls) != 1 {
		t.Fatalf("deleted files = %v, want the new upload [new.png]", storage.deleteCalls)
	}

	if storage.deleteCalls[0] != "new.png" {
		t.Errorf("deleted file = %q, want the new upload new.png", storage.deleteCalls[0])
	}
}

func TestUserService_DeleteAvatar_ClearsURLThenDeletesFile(t *testing.T) {
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

		if len(storage.deleteCalls) != 1 {
			t.Fatalf("DeleteFile calls = %v, want exactly [\"avatar.png\"]", storage.deleteCalls)
		}

		if storage.deleteCalls[0] != "avatar.png" {
			t.Errorf("DeleteFile called with %q, want \"avatar.png\"", storage.deleteCalls[0])
		}

		if gotClearedTo == nil {
			t.Fatal("Update() got AvatarURL nil, want a pointer to an empty string")
		}

		if *gotClearedTo != "" {
			t.Errorf("Update() got AvatarURL %q, want an empty string", *gotClearedTo)
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

func TestUserService_DeleteAvatar_PropagatesLockError(t *testing.T) {
	userID := uuid.New()
	wantErr := errors.New("lock timeout")
	repo := &fakeUserRepository{
		LockFunc: func(context.Context, uuid.UUID) (int64, error) { return 0, wantErr },
		GetByUUIDFunc: func(context.Context, uuid.UUID) (*domain.User, error) {
			t.Fatal("GetByUUID should not be called when the row lock fails")
			return nil, nil
		},
		UpdateFunc: func(context.Context, uuid.UUID, domain.UpdateUserInput) (*domain.User, error) {
			t.Fatal("Update should not be called when the row lock fails")
			return nil, nil
		},
	}
	storage := &fakeStorage{}
	svc := newTestUserService(t, repo, storage)

	_, err := svc.DeleteAvatar(withActor(userID), userID)

	if !errors.Is(err, wantErr) {
		t.Fatalf("DeleteAvatar() error = %v, want %v", err, wantErr)
	}

	if len(storage.deleteCalls) != 0 {
		t.Errorf("DeleteFile calls = %v, want none", storage.deleteCalls)
	}
}

func TestUserService_GetUser_ReturnsUserToSelfOrReader(t *testing.T) {
	userID := uuid.New()
	reader := actor.With(context.Background(), &actor.Actor{UserUUID: uuid.New(), Permissions: []string{domain.UsersRead}})
	tests := []struct {
		name string
		ctx  context.Context
	}{
		{"user reads themself", withActor(userID)},
		{"holder of users:read reads another user", reader},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

			got, err := svc.GetUser(tt.ctx, userID)
			if err != nil {
				t.Fatalf("GetUser() error = %v, want nil", err)
			}

			if got != want {
				t.Errorf("GetUser() = %v, want %v", got, want)
			}
		})
	}
}

func TestUserService_GetUser_HidesUserFromUnauthorizedActors(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
	}{
		{"no actor in the request", context.Background()},
		{"other user without users:read", withActor(uuid.New())},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fakeUserRepository{
				GetByUUIDFunc: func(context.Context, uuid.UUID) (*domain.User, error) {
					t.Fatal("GetByUUID should not be called for an unauthorized actor")
					return nil, nil
				},
			}
			svc := newTestUserService(t, repo, &fakeStorage{})

			_, err := svc.GetUser(tt.ctx, uuid.New())

			if !errors.Is(err, domain.ErrUserNotFound) {
				t.Errorf("GetUser() error = %v, want %v (the user's existence must stay hidden)", err, domain.ErrUserNotFound)
			}
		})
	}
}

func TestUserService_GetUser_PropagatesRepositoryError(t *testing.T) {
	userID := uuid.New()
	wantErr := errors.New("db unavailable")
	repo := &fakeUserRepository{
		GetByUUIDFunc: func(context.Context, uuid.UUID) (*domain.User, error) { return nil, wantErr },
	}
	svc := newTestUserService(t, repo, &fakeStorage{})

	_, err := svc.GetUser(withActor(userID), userID)

	if !errors.Is(err, wantErr) {
		t.Errorf("GetUser() error = %v, want %v", err, wantErr)
	}
}

func TestUserService_SetPasswordHash_UpdatesStoredHash(t *testing.T) {
	t.Run("stores the hash for the given user id", func(t *testing.T) {
		var gotID int64
		var gotHash string
		repo := &fakeUserRepository{
			UpdatePasswordFunc: func(_ context.Context, userID int64, passwordHash string) error {
				gotID = userID
				gotHash = passwordHash

				return nil
			},
		}
		svc := newTestUserService(t, repo, &fakeStorage{})

		if err := svc.SetPasswordHash(context.Background(), targetUserID, "new-hash"); err != nil {
			t.Fatalf("SetPasswordHash() error = %v, want nil", err)
		}

		if gotID != targetUserID {
			t.Errorf("UpdatePassword called for user %d, want %d", gotID, targetUserID)
		}

		if gotHash != "new-hash" {
			t.Errorf("UpdatePassword called with hash %q, want %q", gotHash, "new-hash")
		}
	})

	t.Run("propagates a repository error", func(t *testing.T) {
		wantErr := errors.New("db unavailable")
		repo := &fakeUserRepository{
			UpdatePasswordFunc: func(context.Context, int64, string) error { return wantErr },
		}
		svc := newTestUserService(t, repo, &fakeStorage{})

		if err := svc.SetPasswordHash(context.Background(), targetUserID, "new-hash"); !errors.Is(err, wantErr) {
			t.Errorf("SetPasswordHash() error = %v, want %v", err, wantErr)
		}
	})
}

func TestUserService_ListUsers_PassesFilterToRepository(t *testing.T) {
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

	users, total, err := svc.ListUsers(context.Background(), filter)
	if err != nil {
		t.Fatalf("ListUsers() error = %v, want nil", err)
	}

	if total != 1 {
		t.Errorf("ListUsers() total = %d, want 1", total)
	}

	if len(users) != 1 {
		t.Errorf("ListUsers() returned %d users, want 1", len(users))
	}
}

func TestUserService_NormalizesEmailOnCreateAndLookup(t *testing.T) {
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
			t.Fatalf("CreateUser() error = %v, want nil", err)
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
			t.Fatalf("GetCredentialsByEmail() error = %v, want nil", err)
		}

		if got != "jane.doe@example.com" {
			t.Errorf("looked up %q, want jane.doe@example.com", got)
		}
	})
}

func TestUserService_UpdateUser_UpdatesActiveUserWithoutRevoking(t *testing.T) {
	userID := uuid.New()
	input := domain.UpdateUserInput{FirstName: strPtr("New")}
	want := &domain.User{UUID: userID, FirstName: "New", Status: domain.UserStatusActive}
	repo := &fakeUserRepository{
		LockFunc: lockTarget,
		UpdateFunc: func(_ context.Context, uid uuid.UUID, in domain.UpdateUserInput) (*domain.User, error) {
			if uid != userID {
				t.Errorf("Update called for %v, want %v", uid, userID)
			}

			if in.FirstName == nil || *in.FirstName != "New" {
				t.Errorf("Update called with %+v, want %+v", in, input)
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

	if len(revoker.revoked) != 1 {
		t.Fatalf("revoked = %v, want [%v]", revoker.revoked, userID)
	}

	if revoker.revoked[0] != userID {
		t.Errorf("revoked user = %v, want %v", revoker.revoked[0], userID)
	}

	if len(revoker.invalidated) != 1 {
		t.Fatalf("invalidated = %v, want [%v] (cached sessions dropped after the commit)", revoker.invalidated, userID)
	}

	if revoker.invalidated[0] != userID {
		t.Errorf("invalidated user = %v, want %v", revoker.invalidated[0], userID)
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

func TestUserService_UpdateUser_PropagatesRepositoryErrors(t *testing.T) {
	t.Run("update fails", func(t *testing.T) {
		wantErr := errors.New("db unavailable")
		repo := &fakeUserRepository{
			LockFunc:   lockTarget,
			UpdateFunc: func(context.Context, uuid.UUID, domain.UpdateUserInput) (*domain.User, error) { return nil, wantErr },
		}
		svc, revoker := newTestUserServiceWithRevoker(t, repo, &fakeStorage{})

		_, err := svc.UpdateUser(withManager(), uuid.New(), domain.UpdateUserInput{FirstName: strPtr("New")})

		if !errors.Is(err, wantErr) {
			t.Fatalf("UpdateUser() error = %v, want %v", err, wantErr)
		}

		if len(revoker.invalidated) != 0 {
			t.Errorf("invalidated = %v, want none when the update failed", revoker.invalidated)
		}
	})

	t.Run("target row lock fails during authorization", func(t *testing.T) {
		wantErr := errors.New("lock timeout")
		repo := &fakeUserRepository{
			LockFunc: func(context.Context, uuid.UUID) (int64, error) { return 0, wantErr },
			UpdateFunc: func(context.Context, uuid.UUID, domain.UpdateUserInput) (*domain.User, error) {
				t.Fatal("Update should not be called when the target cannot be locked")
				return nil, nil
			},
		}
		svc := newTestUserService(t, repo, &fakeStorage{})

		_, err := svc.UpdateUser(withManager(), uuid.New(), domain.UpdateUserInput{FirstName: strPtr("New")})

		if !errors.Is(err, wantErr) {
			t.Errorf("UpdateUser() error = %v, want %v", err, wantErr)
		}
	})
}

func TestUserService_DeleteUser_DeletesAndRevokesSessions(t *testing.T) {
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

		if len(revoker.revoked) != 1 {
			t.Fatalf("revoked = %v, want [%v]", revoker.revoked, userID)
		}

		if revoker.revoked[0] != userID {
			t.Errorf("revoked user = %v, want %v", revoker.revoked[0], userID)
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

func TestUserService_DeleteUser_StopsWhenLookupFails(t *testing.T) {
	wantErr := errors.New("db unavailable")
	repo := &fakeUserRepository{
		LockFunc:      lockTarget,
		GetByUUIDFunc: func(context.Context, uuid.UUID) (*domain.User, error) { return nil, wantErr },
		DeleteFunc: func(context.Context, uuid.UUID) error {
			t.Fatal("Delete should not be called when the user lookup fails")
			return nil
		},
	}
	svc, revoker := newTestUserServiceWithRevoker(t, repo, &fakeStorage{})

	err := svc.DeleteUser(withManager(), uuid.New())

	if !errors.Is(err, wantErr) {
		t.Fatalf("DeleteUser() error = %v, want %v", err, wantErr)
	}

	if len(revoker.revoked) != 0 {
		t.Errorf("revoked = %v, want none when nothing was deleted", revoker.revoked)
	}
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

	if len(storage.deleteCalls) != 1 {
		t.Fatalf("deleted files = %v, want [avatar.png]", storage.deleteCalls)
	}

	if storage.deleteCalls[0] != "avatar.png" {
		t.Errorf("deleted file = %q, want avatar.png", storage.deleteCalls[0])
	}
}

func TestUserService_DeleteUser_LogsAvatarDeleteFailure(t *testing.T) {
	repo := &fakeUserRepository{
		LockFunc: lockTarget,
		GetByUUIDFunc: func(_ context.Context, uid uuid.UUID) (*domain.User, error) {
			return &domain.User{UUID: uid, AvatarURL: strPtr("avatar.png")}, nil
		},
		DeleteFunc: func(context.Context, uuid.UUID) error { return nil },
	}
	storage := &fakeStorage{
		DeleteFileFunc: func(context.Context, string) error { return errors.New("disk unavailable") },
	}
	svc := newTestUserService(t, repo, storage)
	core, logs := observer.New(zap.ErrorLevel)
	svc.logger = zap.New(core)

	err := svc.DeleteUser(withManager(), uuid.New())

	if err != nil {
		t.Fatalf("DeleteUser() error = %v, want nil (a leftover avatar file must not fail the deletion)", err)
	}

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("got %d error log entries, want 1", len(entries))
	}

	if got := entries[0].ContextMap()["file_url"]; got != "avatar.png" {
		t.Errorf("logged file_url = %v, want avatar.png", got)
	}
}

func TestUserService_UpdateAndDeleteUser_EnforceAuthorization(t *testing.T) {
	self := uuid.New()
	inactive := domain.UserStatusInactive
	deactivate := domain.UpdateUserInput{Status: &inactive}
	asSelf := actor.With(context.Background(), &actor.Actor{UserID: actorUserID, UserUUID: self, Permissions: managerPermissions})
	noPermission := actor.With(context.Background(), &actor.Actor{UserID: actorUserID, UserUUID: uuid.New()})

	tests := []struct {
		name   string
		ctx    context.Context
		target uuid.UUID
		// db holds actorUserID's and targetUserID's permissions in the database; delete calls
		// DeleteUser instead of UpdateUser(deactivate).
		db     fakePermissions
		delete bool
		want   error
	}{
		{"weaker target", withManager(), uuid.New(), fakePermissions{actorUserID: managerPermissions, targetUserID: {domain.UsersRead}}, false, nil},
		{"equal target", withManager(), uuid.New(), fakePermissions{actorUserID: managerPermissions, targetUserID: managerPermissions}, true, nil},
		{"stronger target", withManager(), uuid.New(), fakePermissions{actorUserID: managerPermissions, targetUserID: {domain.UsersRead, "roles:assign"}}, false, actor.ErrCannotManageStrongerUser},
		{"stronger target, delete", withManager(), uuid.New(), fakePermissions{actorUserID: managerPermissions, targetUserID: {"roles:assign"}}, true, actor.ErrCannotManageStrongerUser},
		{"permission removed since the request's cache", withManager(), uuid.New(), fakePermissions{actorUserID: {domain.UsersRead}}, false, actor.ErrForbidden},
		{"no permission hides the user", noPermission, uuid.New(), nil, false, domain.ErrUserNotFound},
		{"no actor hides the user", context.Background(), uuid.New(), nil, true, domain.ErrUserNotFound},
		{"own status", asSelf, self, nil, false, domain.ErrCannotChangeOwnStatus},
		{"own account", asSelf, self, nil, true, domain.ErrCannotDeleteSelf},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
			svc, _ := newTestUserServiceWith(t, repo, &fakeStorage{}, tt.db)

			var err error
			if tt.delete {
				err = svc.DeleteUser(tt.ctx, tt.target)
			} else {
				_, err = svc.UpdateUser(tt.ctx, tt.target, deactivate)
			}

			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}

			if wrote != (tt.want == nil) {
				t.Errorf("wrote = %v, want %v", wrote, tt.want == nil)
			}
		})
	}
}
