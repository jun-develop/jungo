package service

// =============================================================================
// TEST CASE OVERVIEW
// =============================================================================
//
// File: user_service_test.go
// Purpose: Verify what UserService decides: user creation, lookup, updates, deletion, avatars and
//          who may act on which user.
// Type: Unit (Func-field fakes)
//
// Test functions: 24
// Total scenarios: 48
//
// #   Test Case                                                             Scenario                                 Expected Result
// 1   TestUserService_CreateUser_HashesPasswordAndMapsErrors                Valid input                              Repository receives a bcrypt hash; one create entry without the password
// 2   TestUserService_CreateUser_HashesPasswordAndMapsErrors                Repository fails                         Repository error returned unchanged
// 3   TestUserService_CreateUser_HashesPasswordAndMapsErrors                30 characters but 90 bytes               ErrPasswordTooLong; nothing stored
// 4   TestUserService_CreateUser_HashesPasswordAndMapsErrors                Hasher fails for another reason          Hasher error returned unchanged; nothing stored
// 5   TestUserService_CreateUser_NormalizesEmail                            Email with mixed case and spaces         Email stored lowercase and trimmed
// 6   TestUserService_GetUser_ReturnsUserToSelfOrReader                     User reads themself                      Returns the user
// 7   TestUserService_GetUser_ReturnsUserToSelfOrReader                     Holder of users:read reads another user  Returns the user
// 8   TestUserService_GetUser_HidesUserFromUnauthorizedActors               No actor in the request                  ErrUserNotFound; repository not queried
// 9   TestUserService_GetUser_HidesUserFromUnauthorizedActors               Other user without users:read            ErrUserNotFound; repository not queried
// 10  TestUserService_GetUser_PropagatesRepositoryError                     Repository fails                         Database error
// 11  TestUserService_GetCredentialsByEmail_NormalizesEmail                 Email with mixed case                    Normalized email looked up
// 12  TestUserService_SetPasswordHash_UpdatesStoredHash                     Valid user ID and hash                   Repository stores that hash for that user
// 13  TestUserService_SetPasswordHash_UpdatesStoredHash                     Repository fails                         Database error
// 14  TestUserService_ListUsers_PassesFilterToRepository                    Search filter                            Repository receives the same filter; its total returned
// 15  TestUserService_UpdateUser_UpdatesActiveUserWithoutRevoking           Manager renames an active user           Updated user returned; no session revoked; cache dropped; one update entry
// 16  TestUserService_UpdateUser_FailsWhenTheAuditLogFails                  Audit log write fails                    Its error returned; cache not dropped
// 17  TestUserService_UpdateUser_DeactivationRevokesSessions                Manager deactivates a user               Sessions revoked and cached sessions dropped
// 18  TestUserService_UpdateUser_DeactivationPropagatesRevokeError          Session revocation fails                 Revocation error returned
// 19  TestUserService_UpdateUser_PropagatesRepositoryErrors                 Update fails                             Error returned; cached sessions kept
// 20  TestUserService_UpdateUser_PropagatesRepositoryErrors                 Current values unreadable                Error returned; nothing updated
// 21  TestUserService_UpdateUser_PropagatesRepositoryErrors                 Target row lock fails                    Error returned; nothing updated
// 22  TestUserService_UpdateUser_EnforcesAuthorization                      Deactivate a weaker user                 Allowed
// 23  TestUserService_UpdateUser_EnforcesAuthorization                      Deactivate a stronger user               ErrCannotManageStrongerUser; nothing written
// 24  TestUserService_UpdateUser_EnforcesAuthorization                      Permission removed since the cache       ErrForbidden; nothing written
// 25  TestUserService_UpdateUser_EnforcesAuthorization                      Actor without the permission             ErrUserNotFound (user hidden)
// 26  TestUserService_UpdateUser_EnforcesAuthorization                      User changes their own status            ErrCannotChangeOwnStatus
// 27  TestUserService_DeleteUser_DeletesAndRevokesSessions                  Manager deletes a user                   That user deleted; sessions revoked; cache dropped; one delete entry
// 28  TestUserService_DeleteUser_DeletesAndRevokesSessions                  Repository delete fails                  Database error; no session revoked
// 29  TestUserService_DeleteUser_StopsWhenLookupFails                       User lookup fails                        Error returned; nothing deleted, no session revoked
// 30  TestUserService_DeleteUser_RemovesAvatarFile                          Deleted user had an avatar               Avatar file deleted
// 31  TestUserService_DeleteUser_LogsAvatarDeleteFailure                    Avatar file deletion fails               DeleteUser still succeeds; failure logged
// 32  TestUserService_DeleteUser_EnforcesAuthorization                      Delete a user with equal permissions     Allowed
// 33  TestUserService_DeleteUser_EnforcesAuthorization                      Delete a stronger user                   ErrCannotManageStrongerUser; nothing written
// 34  TestUserService_DeleteUser_EnforcesAuthorization                      No actor in the request                  ErrUserNotFound (user hidden)
// 35  TestUserService_DeleteUser_EnforcesAuthorization                      User deletes their own account           ErrCannotDeleteSelf
// 36  TestUserService_UploadAvatar_ReplacesStoredFile                       User had an avatar                       Record updated before the old file is deleted; cache dropped
// 37  TestUserService_UploadAvatar_ReplacesStoredFile                       User had no avatar                       Nothing deleted
// 38  TestUserService_UploadAvatar_ReplacesStoredFile                       Upload fails                             ErrInvalidAvatarFile; record untouched
// 39  TestUserService_UploadAvatar_ReplacesStoredFile                       Record update fails                      Error returned; new upload deleted, old avatar kept
// 40  TestUserService_UploadAvatar_ReplacesStoredFile                       User lookup fails                        Error returned; new upload deleted
// 41  TestUserService_UploadAvatar_RejectsUnauthorizedActorBeforeUploading  No actor in the request                  ErrUserNotFound; nothing uploaded
// 42  TestUserService_UploadAvatar_ReauthorizesAfterUpload                  Target promoted during the upload        ErrCannotManageStrongerUser; nothing written, upload deleted
// 43  TestUserService_DeleteAvatar_ClearsURLThenDeletesFile                 User has an avatar                       URL cleared, file deleted, cache dropped
// 44  TestUserService_DeleteAvatar_ClearsURLThenDeletesFile                 Clearing the URL fails                   Error returned; file kept
// 45  TestUserService_DeleteAvatar_ClearsURLThenDeletesFile                 No avatar                                No-op
// 46  TestUserService_DeleteAvatar_ClearsURLThenDeletesFile                 Avatar URL is an empty string            Treated as no avatar
// 47  TestUserService_DeleteAvatar_ClearsURLThenDeletesFile                 User lookup fails                        Error returned
// 48  TestUserService_DeleteAvatar_PropagatesLockError                      Row lock fails                           Error returned; nothing updated or deleted
//
// =============================================================================

import (
	"context"
	"errors"
	"io"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/crypto/bcrypt"

	"jungo/internal/common/actor"
	"jungo/internal/features/user/domain"
)

// revokesNothing is a session revoker that accepts every revocation.
func revokesNothing() *fakeSessionRevoker {
	return &fakeSessionRevoker{RevokeUserSessionsFunc: func(context.Context, uuid.UUID) error { return nil }}
}

func TestUserService_CreateUser_HashesPasswordAndMapsErrors(t *testing.T) {
	t.Run("valid input", func(t *testing.T) {
		var gotHash string
		var gotInput domain.CreateUserInput
		repo := &fakeUserRepository{
			CreateFunc: func(_ context.Context, in domain.CreateUserInput, hash string) (*domain.User, error) {
				gotInput, gotHash = in, hash
				return &domain.User{Email: in.Email, FirstName: in.FirstName, LastName: in.LastName}, nil
			},
		}
		input := domain.CreateUserInput{
			FirstName: "Jane",
			LastName:  "Doe",
			Email:     "jane@example.com",
			Password:  "s3cret-pw",
		}
		audit := &fakeRecorder{}

		user, err := newTestService(t, UserServiceParams{Repo: repo, Audit: audit}).CreateUser(context.Background(), input)

		if err != nil {
			t.Fatalf("CreateUser() error = %v", err)
		}

		if gotInput.Email != input.Email {
			t.Errorf("repository received email %q, want %q", gotInput.Email, input.Email)
		}

		if user.Email != input.Email {
			t.Errorf("CreateUser().Email = %q, want %q", user.Email, input.Email)
		}

		if err := bcrypt.CompareHashAndPassword([]byte(gotHash), []byte(input.Password)); err != nil {
			t.Errorf("stored hash is not a bcrypt hash of the password: %v", err)
		}

		if len(audit.entries) != 1 {
			t.Fatalf("audit entries = %+v, want one", audit.entries)
		}

		e := audit.entries[0]
		if e.Action != "create" || e.Before != nil || e.After["email"] != "jane@example.com" || e.After["password"] != nil {
			t.Errorf("audit entry = %+v, want a create with the user's values after and no password", e)
		}
	})

	t.Run("repository fails", func(t *testing.T) {
		repo := &fakeUserRepository{
			CreateFunc: func(context.Context, domain.CreateUserInput, string) (*domain.User, error) {
				return nil, errDB
			},
		}

		_, err := newTestService(t, UserServiceParams{Repo: repo}).
			CreateUser(context.Background(), domain.CreateUserInput{Password: "whatever"})

		if err != errDB {
			t.Fatalf("CreateUser() error = %v, want exactly %v", err, errDB)
		}
	})

	t.Run("30 characters but 90 bytes", func(t *testing.T) {
		// CreateFunc is nil: storing anything would panic.
		svc := newTestService(t, UserServiceParams{Repo: &fakeUserRepository{}})

		_, err := svc.CreateUser(context.Background(), domain.CreateUserInput{Password: strings.Repeat("ệ", 30)})

		wantErr(t, err, domain.ErrPasswordTooLong)
	})

	t.Run("hasher fails for another reason", func(t *testing.T) {
		hashErr := context.DeadlineExceeded
		svc := newTestService(t, UserServiceParams{Repo: &fakeUserRepository{}, Hasher: failingHasher{err: hashErr}})

		_, err := svc.CreateUser(context.Background(), domain.CreateUserInput{Password: "s3cret-pw"})

		if err != hashErr {
			t.Fatalf("CreateUser() error = %v, want exactly %v", err, hashErr)
		}
	})
}

func TestUserService_CreateUser_NormalizesEmail(t *testing.T) {
	var got string
	repo := &fakeUserRepository{
		CreateFunc: func(_ context.Context, input domain.CreateUserInput, _ string) (*domain.User, error) {
			got = input.Email
			return &domain.User{Email: input.Email}, nil
		},
	}
	input := domain.CreateUserInput{Email: "  Jane.Doe@Example.COM ", Password: "s3cret-pw"}

	_, err := newTestService(t, UserServiceParams{Repo: repo}).CreateUser(context.Background(), input)

	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	if got != "jane.doe@example.com" {
		t.Errorf("stored email = %q, want jane.doe@example.com", got)
	}
}

func TestUserService_GetUser_ReturnsUserToSelfOrReader(t *testing.T) {
	userID := uuid.New()
	tests := []struct {
		name string
		ctx  context.Context
	}{
		{"user reads themself", asActor(userID)},
		{"holder of users:read reads another user", asActor(actorUUID, domain.UsersRead)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var askedFor uuid.UUID
			want := &domain.User{UUID: userID, Email: "jane@example.com"}
			repo := &fakeUserRepository{
				GetByUUIDFunc: func(_ context.Context, uid uuid.UUID) (*domain.User, error) {
					askedFor = uid
					return want, nil
				},
			}

			got, err := newTestService(t, UserServiceParams{Repo: repo}).GetUser(tt.ctx, userID)

			if err != nil {
				t.Fatalf("GetUser() error = %v", err)
			}

			if askedFor != userID {
				t.Errorf("repository asked for %v, want %v", askedFor, userID)
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
		{"other user without users:read", asActor(actorUUID)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// GetByUUIDFunc is nil: querying the repository would panic.
			svc := newTestService(t, UserServiceParams{Repo: &fakeUserRepository{}})

			_, err := svc.GetUser(tt.ctx, uuid.New())

			// The user's existence must stay hidden.
			wantErr(t, err, domain.ErrUserNotFound)
		})
	}
}

func TestUserService_GetUser_PropagatesRepositoryError(t *testing.T) {
	userID := uuid.New()
	repo := &fakeUserRepository{
		GetByUUIDFunc: func(context.Context, uuid.UUID) (*domain.User, error) { return nil, errDB },
	}

	_, err := newTestService(t, UserServiceParams{Repo: repo}).GetUser(asActor(userID), userID)

	wantErr(t, err, errDB)
}

func TestUserService_GetCredentialsByEmail_NormalizesEmail(t *testing.T) {
	var got string
	repo := &fakeUserRepository{
		GetCredentialsByEmailFunc: func(_ context.Context, email string) (*domain.Credentials, error) {
			got = email
			return &domain.Credentials{}, nil
		},
	}

	_, err := newTestService(t, UserServiceParams{Repo: repo}).
		GetCredentialsByEmail(context.Background(), "Jane.Doe@Example.COM")

	if err != nil {
		t.Fatalf("GetCredentialsByEmail() error = %v", err)
	}

	if got != "jane.doe@example.com" {
		t.Errorf("looked up %q, want jane.doe@example.com", got)
	}
}

func TestUserService_SetPasswordHash_UpdatesStoredHash(t *testing.T) {
	t.Run("valid user id and hash", func(t *testing.T) {
		var gotID int64
		var gotHash string
		repo := &fakeUserRepository{
			UpdatePasswordFunc: func(_ context.Context, userID int64, passwordHash string) error {
				gotID, gotHash = userID, passwordHash
				return nil
			},
		}

		err := newTestService(t, UserServiceParams{Repo: repo}).
			SetPasswordHash(context.Background(), targetUserID, "new-hash")

		if err != nil {
			t.Fatalf("SetPasswordHash() error = %v", err)
		}

		if gotID != targetUserID {
			t.Errorf("password updated for user %d, want %d", gotID, targetUserID)
		}

		if gotHash != "new-hash" {
			t.Errorf("stored hash = %q, want %q", gotHash, "new-hash")
		}
	})

	t.Run("repository fails", func(t *testing.T) {
		repo := &fakeUserRepository{
			UpdatePasswordFunc: func(context.Context, int64, string) error { return errDB },
		}

		err := newTestService(t, UserServiceParams{Repo: repo}).
			SetPasswordHash(context.Background(), targetUserID, "new-hash")

		wantErr(t, err, errDB)
	})
}

func TestUserService_ListUsers_PassesFilterToRepository(t *testing.T) {
	filter := domain.UserListFilter{Search: "jane", Limit: 10, Offset: 0, SortOrder: "asc"}
	var got domain.UserListFilter
	repo := &fakeUserRepository{
		ListFunc: func(_ context.Context, f domain.UserListFilter) ([]*domain.User, int64, error) {
			got = f
			return []*domain.User{{Email: "jane@example.com"}}, 1, nil
		},
	}

	_, total, err := newTestService(t, UserServiceParams{Repo: repo}).ListUsers(context.Background(), filter)

	if err != nil {
		t.Fatalf("ListUsers() error = %v", err)
	}

	if got != filter {
		t.Errorf("repository received filter %+v, want %+v", got, filter)
	}

	if total != 1 {
		t.Errorf("ListUsers() total = %d, want 1", total)
	}
}

func TestUserService_UpdateUser_UpdatesActiveUserWithoutRevoking(t *testing.T) {
	userID := uuid.New()
	var gotID uuid.UUID
	var gotInput domain.UpdateUserInput
	want := &domain.User{UUID: userID, FirstName: "New", Status: domain.UserStatusActive}
	repo := &fakeUserRepository{
		GetByUUIDFunc: func(_ context.Context, uid uuid.UUID) (*domain.User, error) {
			return &domain.User{UUID: uid, FirstName: "Old", Status: domain.UserStatusActive}, nil
		},
		UpdateFunc: func(_ context.Context, uid uuid.UUID, in domain.UpdateUserInput) (*domain.User, error) {
			gotID, gotInput = uid, in
			return want, nil
		},
	}
	// RevokeUserSessionsFunc is nil: revoking an active user's sessions would panic.
	sessions := &fakeSessionRevoker{}
	audit := &fakeRecorder{}
	svc := newTestService(t, UserServiceParams{Repo: repo, Sessions: sessions, Audit: audit})

	got, err := svc.UpdateUser(asManager(), userID, domain.UpdateUserInput{FirstName: new("New")})

	if err != nil {
		t.Fatalf("UpdateUser() error = %v", err)
	}

	if gotID != userID {
		t.Errorf("updated user = %v, want %v", gotID, userID)
	}

	if deref(gotInput.FirstName) != "New" {
		t.Errorf("updated first name = %q, want %q", deref(gotInput.FirstName), "New")
	}

	if got != want {
		t.Errorf("UpdateUser() = %v, want %v", got, want)
	}

	// Cached sessions carry the profile, so they are dropped even when no session is revoked.
	if !slices.Equal(sessions.invalidated, []uuid.UUID{userID}) {
		t.Errorf("invalidated users = %v, want [%v]", sessions.invalidated, userID)
	}

	if len(audit.entries) != 1 {
		t.Fatalf("audit entries = %+v, want one", audit.entries)
	}

	e := audit.entries[0]
	if e.Action != "update" || e.EntityID != userID.String() || e.Before["first_name"] != "Old" ||
		!reflect.DeepEqual(e.After, map[string]any{"first_name": "New"}) {
		t.Errorf("audit entry = %+v, want an update of first_name from Old to New", e)
	}
}

func TestUserService_UpdateUser_FailsWhenTheAuditLogFails(t *testing.T) {
	repo := &fakeUserRepository{
		GetByUUIDFunc: noAvatar,
		UpdateFunc: func(_ context.Context, uid uuid.UUID, _ domain.UpdateUserInput) (*domain.User, error) {
			return &domain.User{UUID: uid, Status: domain.UserStatusActive}, nil
		},
	}
	sessions := &fakeSessionRevoker{}
	svc := newTestService(t, UserServiceParams{Repo: repo, Sessions: sessions, Audit: &fakeRecorder{err: errDB}})

	_, err := svc.UpdateUser(asManager(), uuid.New(), domain.UpdateUserInput{FirstName: new("New")})

	wantErr(t, err, errDB)
	if len(sessions.invalidated) != 0 {
		t.Errorf("invalidated users = %v, want none (the transaction rolled back)", sessions.invalidated)
	}
}

func TestUserService_UpdateUser_DeactivationRevokesSessions(t *testing.T) {
	userID := uuid.New()
	repo := &fakeUserRepository{
		GetByUUIDFunc: noAvatar,
		UpdateFunc: func(context.Context, uuid.UUID, domain.UpdateUserInput) (*domain.User, error) {
			return &domain.User{UUID: userID, Status: domain.UserStatusInactive}, nil
		},
	}
	var revoked []uuid.UUID
	sessions := &fakeSessionRevoker{RevokeUserSessionsFunc: recordRevokes(&revoked)}
	svc := newTestService(t, UserServiceParams{Repo: repo, Sessions: sessions})

	_, err := svc.UpdateUser(asManager(), userID, domain.UpdateUserInput{Status: new(domain.UserStatusInactive)})

	if err != nil {
		t.Fatalf("UpdateUser() error = %v", err)
	}

	if !slices.Equal(revoked, []uuid.UUID{userID}) {
		t.Errorf("revoked users = %v, want [%v]", revoked, userID)
	}

	if !slices.Equal(sessions.invalidated, []uuid.UUID{userID}) {
		t.Errorf("invalidated users = %v, want [%v]", sessions.invalidated, userID)
	}
}

func TestUserService_UpdateUser_DeactivationPropagatesRevokeError(t *testing.T) {
	repo := &fakeUserRepository{
		GetByUUIDFunc: noAvatar,
		UpdateFunc: func(_ context.Context, uid uuid.UUID, _ domain.UpdateUserInput) (*domain.User, error) {
			return &domain.User{UUID: uid, Status: domain.UserStatusInactive}, nil
		},
	}
	sessions := &fakeSessionRevoker{RevokeUserSessionsFunc: func(context.Context, uuid.UUID) error { return errDB }}
	svc := newTestService(t, UserServiceParams{Repo: repo, Sessions: sessions})

	_, err := svc.UpdateUser(asManager(), uuid.New(), domain.UpdateUserInput{Status: new(domain.UserStatusInactive)})

	wantErr(t, err, errDB)
}

func TestUserService_UpdateUser_PropagatesRepositoryErrors(t *testing.T) {
	t.Run("update fails", func(t *testing.T) {
		repo := &fakeUserRepository{
			GetByUUIDFunc: noAvatar,
			UpdateFunc: func(context.Context, uuid.UUID, domain.UpdateUserInput) (*domain.User, error) {
				return nil, errDB
			},
		}
		sessions := &fakeSessionRevoker{}
		svc := newTestService(t, UserServiceParams{Repo: repo, Sessions: sessions})

		_, err := svc.UpdateUser(asManager(), uuid.New(), domain.UpdateUserInput{FirstName: new("New")})

		wantErr(t, err, errDB)

		if len(sessions.invalidated) != 0 {
			t.Errorf("invalidated users = %v, want none when the update failed", sessions.invalidated)
		}
	})

	t.Run("current values unreadable", func(t *testing.T) {
		// UpdateFunc is nil: updating without the values it replaces would panic.
		repo := &fakeUserRepository{
			GetByUUIDFunc: func(context.Context, uuid.UUID) (*domain.User, error) { return nil, errDB },
		}

		_, err := newTestService(t, UserServiceParams{Repo: repo}).
			UpdateUser(asManager(), uuid.New(), domain.UpdateUserInput{FirstName: new("New")})

		wantErr(t, err, errDB)
	})

	t.Run("target row lock fails", func(t *testing.T) {
		// UpdateFunc is nil: updating after a failed lock would panic.
		repo := &fakeUserRepository{
			LockByUUIDFunc: func(context.Context, uuid.UUID) (int64, error) { return 0, errDB },
		}

		_, err := newTestService(t, UserServiceParams{Repo: repo}).
			UpdateUser(asManager(), uuid.New(), domain.UpdateUserInput{FirstName: new("New")})

		wantErr(t, err, errDB)
	})
}

func TestUserService_UpdateUser_EnforcesAuthorization(t *testing.T) {
	self := uuid.New()
	tests := []struct {
		name   string
		ctx    context.Context
		target uuid.UUID
		db     map[int64][]string
		want   error
	}{
		{
			name:   "deactivate a weaker user",
			ctx:    asManager(),
			target: uuid.New(),
			db:     map[int64][]string{actorUserID: managerPermissions, targetUserID: {domain.UsersRead}},
		},
		{
			name:   "deactivate a stronger user",
			ctx:    asManager(),
			target: uuid.New(),
			db: map[int64][]string{
				actorUserID:  managerPermissions,
				targetUserID: {domain.UsersRead, "roles:assign"},
			},
			want: actor.ErrCannotManageStrongerUser,
		},
		{
			name:   "permission removed since the cache",
			ctx:    asManager(),
			target: uuid.New(),
			db:     map[int64][]string{actorUserID: {domain.UsersRead}},
			want:   actor.ErrForbidden,
		},
		{
			name:   "actor without the permission",
			ctx:    asActor(actorUUID),
			target: uuid.New(),
			want:   domain.ErrUserNotFound,
		},
		{
			name:   "user changes their own status",
			ctx:    asActor(self, managerPermissions...),
			target: self,
			want:   domain.ErrCannotChangeOwnStatus,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var wrote bool
			repo := &fakeUserRepository{
				GetByUUIDFunc: noAvatar,
				UpdateFunc: func(_ context.Context, uid uuid.UUID, _ domain.UpdateUserInput) (*domain.User, error) {
					wrote = true
					return &domain.User{UUID: uid, Status: domain.UserStatusInactive}, nil
				},
			}
			svc := newTestService(t, UserServiceParams{
				Repo:        repo,
				Permissions: dbHolds(tt.db),
				Sessions:    revokesNothing(),
			})

			_, err := svc.UpdateUser(tt.ctx, tt.target, domain.UpdateUserInput{Status: new(domain.UserStatusInactive)})

			wantErr(t, err, tt.want)

			if wrote != (tt.want == nil) {
				t.Errorf("user updated = %v, want %v", wrote, tt.want == nil)
			}
		})
	}
}

func TestUserService_DeleteUser_DeletesAndRevokesSessions(t *testing.T) {
	t.Run("manager deletes a user", func(t *testing.T) {
		userID := uuid.New()
		var deleted uuid.UUID
		repo := &fakeUserRepository{
			GetByUUIDFunc: noAvatar,
			DeleteFunc: func(_ context.Context, uid uuid.UUID) error {
				deleted = uid
				return nil
			},
		}
		var revoked []uuid.UUID
		sessions := &fakeSessionRevoker{RevokeUserSessionsFunc: recordRevokes(&revoked)}
		audit := &fakeRecorder{}

		err := newTestService(t, UserServiceParams{Repo: repo, Sessions: sessions, Audit: audit}).DeleteUser(asManager(), userID)

		if err != nil {
			t.Fatalf("DeleteUser() error = %v", err)
		}

		if deleted != userID {
			t.Errorf("deleted user = %v, want %v", deleted, userID)
		}

		if !slices.Equal(revoked, []uuid.UUID{userID}) {
			t.Errorf("revoked users = %v, want [%v]", revoked, userID)
		}

		if !slices.Equal(sessions.invalidated, []uuid.UUID{userID}) {
			t.Errorf("invalidated users = %v, want [%v]", sessions.invalidated, userID)
		}

		if len(audit.entries) != 1 || audit.entries[0].Action != "delete" || audit.entries[0].EntityID != userID.String() {
			t.Errorf("audit entries = %+v, want one delete of %v", audit.entries, userID)
		}
	})

	t.Run("repository delete fails", func(t *testing.T) {
		// The session revoker's Func is nil: revoking after a failed delete would panic.
		repo := &fakeUserRepository{
			GetByUUIDFunc: noAvatar,
			DeleteFunc:    func(context.Context, uuid.UUID) error { return errDB },
		}

		err := newTestService(t, UserServiceParams{Repo: repo}).DeleteUser(asManager(), uuid.New())

		wantErr(t, err, errDB)
	})
}

func TestUserService_DeleteUser_StopsWhenLookupFails(t *testing.T) {
	// DeleteFunc and the session revoker's Func are nil: deleting or revoking would panic.
	repo := &fakeUserRepository{
		GetByUUIDFunc: func(context.Context, uuid.UUID) (*domain.User, error) { return nil, errDB },
	}

	err := newTestService(t, UserServiceParams{Repo: repo}).DeleteUser(asManager(), uuid.New())

	wantErr(t, err, errDB)
}

func TestUserService_DeleteUser_RemovesAvatarFile(t *testing.T) {
	repo := &fakeUserRepository{
		GetByUUIDFunc: withAvatar("avatar.png"),
		DeleteFunc:    func(context.Context, uuid.UUID) error { return nil },
	}
	var deletedFiles []string
	svc := newTestService(t, UserServiceParams{
		Repo:     repo,
		Storage:  &fakeStorage{DeleteFileFunc: recordDeletes(&deletedFiles)},
		Sessions: revokesNothing(),
	})

	if err := svc.DeleteUser(asManager(), uuid.New()); err != nil {
		t.Fatalf("DeleteUser() error = %v", err)
	}

	if !slices.Equal(deletedFiles, []string{"avatar.png"}) {
		t.Errorf("deleted files = %v, want [avatar.png]", deletedFiles)
	}
}

func TestUserService_DeleteUser_LogsAvatarDeleteFailure(t *testing.T) {
	core, logs := observer.New(zap.ErrorLevel)
	repo := &fakeUserRepository{
		GetByUUIDFunc: withAvatar("avatar.png"),
		DeleteFunc:    func(context.Context, uuid.UUID) error { return nil },
	}
	storage := &fakeStorage{
		DeleteFileFunc: func(context.Context, string) error { return errors.New("disk unavailable") },
	}
	svc := newTestService(t, UserServiceParams{
		Repo:     repo,
		Storage:  storage,
		Sessions: revokesNothing(),
		Logger:   zap.New(core),
	})

	err := svc.DeleteUser(asManager(), uuid.New())

	// A leftover avatar file must not fail the deletion.
	if err != nil {
		t.Fatalf("DeleteUser() error = %v, want nil", err)
	}

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("error log entries = %d, want 1", len(entries))
	}

	if got := entries[0].ContextMap()["file_url"]; got != "avatar.png" {
		t.Errorf("logged file_url = %v, want avatar.png", got)
	}
}

func TestUserService_DeleteUser_EnforcesAuthorization(t *testing.T) {
	self := uuid.New()
	tests := []struct {
		name   string
		ctx    context.Context
		target uuid.UUID
		db     map[int64][]string
		want   error
	}{
		{
			name:   "delete a user with equal permissions",
			ctx:    asManager(),
			target: uuid.New(),
			db:     map[int64][]string{actorUserID: managerPermissions, targetUserID: managerPermissions},
		},
		{
			name:   "delete a stronger user",
			ctx:    asManager(),
			target: uuid.New(),
			db:     map[int64][]string{actorUserID: managerPermissions, targetUserID: {"roles:assign"}},
			want:   actor.ErrCannotManageStrongerUser,
		},
		{
			name:   "no actor in the request",
			ctx:    context.Background(),
			target: uuid.New(),
			want:   domain.ErrUserNotFound,
		},
		{
			name:   "user deletes their own account",
			ctx:    asActor(self, managerPermissions...),
			target: self,
			want:   domain.ErrCannotDeleteSelf,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var wrote bool
			repo := &fakeUserRepository{
				GetByUUIDFunc: noAvatar,
				DeleteFunc: func(context.Context, uuid.UUID) error {
					wrote = true
					return nil
				},
			}
			svc := newTestService(t, UserServiceParams{
				Repo:        repo,
				Permissions: dbHolds(tt.db),
				Sessions:    revokesNothing(),
			})

			err := svc.DeleteUser(tt.ctx, tt.target)

			wantErr(t, err, tt.want)

			if wrote != (tt.want == nil) {
				t.Errorf("user deleted = %v, want %v", wrote, tt.want == nil)
			}
		})
	}
}

func TestUserService_UploadAvatar_ReplacesStoredFile(t *testing.T) {
	userID := uuid.New()
	file := domain.AvatarFile{Filename: "me.png"}

	t.Run("user had an avatar", func(t *testing.T) {
		var calls []string
		var storedURL string
		repo := &fakeUserRepository{
			GetByUUIDFunc: withAvatar("old/avatar.png"),
			UpdateFunc: func(_ context.Context, _ uuid.UUID, in domain.UpdateUserInput) (*domain.User, error) {
				calls = append(calls, "update")
				storedURL = deref(in.AvatarURL)
				return &domain.User{UUID: userID, AvatarURL: in.AvatarURL}, nil
			},
		}
		storage := &fakeStorage{
			UploadFileFunc: uploadsAs("new/avatar.png"),
			DeleteFileFunc: func(_ context.Context, fileURL string) error {
				calls = append(calls, "delete "+fileURL)
				return nil
			},
		}
		sessions := &fakeSessionRevoker{}
		svc := newTestService(t, UserServiceParams{Repo: repo, Storage: storage, Sessions: sessions})

		user, err := svc.UploadAvatar(asActor(userID), userID, file)

		if err != nil {
			t.Fatalf("UploadAvatar() error = %v", err)
		}

		if storedURL != "new/avatar.png" {
			t.Errorf("stored avatar URL = %q, want new/avatar.png", storedURL)
		}

		// The old file is deleted only once the record points at the new one.
		if want := []string{"update", "delete old/avatar.png"}; !slices.Equal(calls, want) {
			t.Errorf("calls = %v, want %v", calls, want)
		}

		if deref(user.AvatarURL) != "new/avatar.png" {
			t.Errorf("UploadAvatar().AvatarURL = %q, want new/avatar.png", deref(user.AvatarURL))
		}

		if !slices.Equal(sessions.invalidated, []uuid.UUID{userID}) {
			t.Errorf("invalidated users = %v, want [%v]", sessions.invalidated, userID)
		}
	})

	t.Run("user had no avatar", func(t *testing.T) {
		// DeleteFileFunc is nil: deleting a file would panic.
		repo := &fakeUserRepository{
			GetByUUIDFunc: noAvatar,
			UpdateFunc: func(_ context.Context, _ uuid.UUID, in domain.UpdateUserInput) (*domain.User, error) {
				return &domain.User{UUID: userID, AvatarURL: in.AvatarURL}, nil
			},
		}
		storage := &fakeStorage{UploadFileFunc: uploadsAs("new/avatar.png")}
		svc := newTestService(t, UserServiceParams{Repo: repo, Storage: storage})

		_, err := svc.UploadAvatar(asActor(userID), userID, file)

		wantErr(t, err, nil)
	})

	t.Run("upload fails", func(t *testing.T) {
		// The repository's Funcs are nil: touching the record would panic.
		storage := &fakeStorage{
			UploadFileFunc: func(context.Context, io.Reader, string) (string, error) {
				return "", errors.New("disk full")
			},
		}
		svc := newTestService(t, UserServiceParams{Repo: &fakeUserRepository{}, Storage: storage})

		_, err := svc.UploadAvatar(asActor(userID), userID, file)

		wantErr(t, err, domain.ErrInvalidAvatarFile)
	})

	t.Run("record update fails", func(t *testing.T) {
		repo := &fakeUserRepository{
			GetByUUIDFunc: withAvatar("old/avatar.png"),
			UpdateFunc: func(context.Context, uuid.UUID, domain.UpdateUserInput) (*domain.User, error) {
				return nil, errDB
			},
		}
		var deletedFiles []string
		storage := &fakeStorage{
			UploadFileFunc: uploadsAs("new/avatar.png"),
			DeleteFileFunc: recordDeletes(&deletedFiles),
		}
		svc := newTestService(t, UserServiceParams{Repo: repo, Storage: storage})

		_, err := svc.UploadAvatar(asActor(userID), userID, file)

		wantErr(t, err, errDB)

		// The orphaned upload is cleaned up; the old avatar is left alone.
		if !slices.Equal(deletedFiles, []string{"new/avatar.png"}) {
			t.Errorf("deleted files = %v, want [new/avatar.png]", deletedFiles)
		}
	})

	t.Run("user lookup fails", func(t *testing.T) {
		repo := &fakeUserRepository{
			GetByUUIDFunc: func(context.Context, uuid.UUID) (*domain.User, error) { return nil, errDB },
		}
		var deletedFiles []string
		storage := &fakeStorage{
			UploadFileFunc: uploadsAs("new/avatar.png"),
			DeleteFileFunc: recordDeletes(&deletedFiles),
		}
		svc := newTestService(t, UserServiceParams{Repo: repo, Storage: storage})

		_, err := svc.UploadAvatar(asActor(userID), userID, file)

		wantErr(t, err, errDB)

		if !slices.Equal(deletedFiles, []string{"new/avatar.png"}) {
			t.Errorf("deleted files = %v, want [new/avatar.png]", deletedFiles)
		}
	})
}

func TestUserService_UploadAvatar_RejectsUnauthorizedActorBeforeUploading(t *testing.T) {
	// UploadFileFunc is nil: uploading would panic.
	svc := newTestService(t, UserServiceParams{Repo: &fakeUserRepository{}})

	_, err := svc.UploadAvatar(context.Background(), uuid.New(), domain.AvatarFile{Filename: "me.png"})

	wantErr(t, err, domain.ErrUserNotFound)
}

func TestUserService_UploadAvatar_ReauthorizesAfterUpload(t *testing.T) {
	db := map[int64][]string{actorUserID: managerPermissions, targetUserID: {domain.UsersRead}}
	var deletedFiles []string
	storage := &fakeStorage{
		// The target is promoted while the file uploads.
		UploadFileFunc: func(context.Context, io.Reader, string) (string, error) {
			db[targetUserID] = []string{domain.UsersRead, "roles:assign"}
			return "new.png", nil
		},
		DeleteFileFunc: recordDeletes(&deletedFiles),
	}
	// UpdateFunc is nil: writing the avatar URL would panic.
	svc := newTestService(t, UserServiceParams{Repo: &fakeUserRepository{}, Permissions: dbHolds(db), Storage: storage})

	_, err := svc.UploadAvatar(asManager(), uuid.New(), domain.AvatarFile{Filename: "a.png"})

	wantErr(t, err, actor.ErrCannotManageStrongerUser)

	if !slices.Equal(deletedFiles, []string{"new.png"}) {
		t.Errorf("deleted files = %v, want the new upload [new.png]", deletedFiles)
	}
}

func TestUserService_DeleteAvatar_ClearsURLThenDeletesFile(t *testing.T) {
	userID := uuid.New()

	t.Run("user has an avatar", func(t *testing.T) {
		var clearedTo *string
		repo := &fakeUserRepository{
			GetByUUIDFunc: withAvatar("avatar.png"),
			UpdateFunc: func(_ context.Context, _ uuid.UUID, in domain.UpdateUserInput) (*domain.User, error) {
				clearedTo = in.AvatarURL
				return &domain.User{UUID: userID, AvatarURL: in.AvatarURL}, nil
			},
		}
		var deletedFiles []string
		sessions := &fakeSessionRevoker{}
		svc := newTestService(t, UserServiceParams{
			Repo:     repo,
			Storage:  &fakeStorage{DeleteFileFunc: recordDeletes(&deletedFiles)},
			Sessions: sessions,
		})

		if _, err := svc.DeleteAvatar(asActor(userID), userID); err != nil {
			t.Fatalf("DeleteAvatar() error = %v", err)
		}

		// An empty string, not nil: nil would mean "leave the avatar unchanged".
		if clearedTo == nil {
			t.Fatal("avatar URL set to nil, want a pointer to an empty string")
		}

		if *clearedTo != "" {
			t.Errorf("avatar URL set to %q, want an empty string", *clearedTo)
		}

		if !slices.Equal(deletedFiles, []string{"avatar.png"}) {
			t.Errorf("deleted files = %v, want [avatar.png]", deletedFiles)
		}

		if !slices.Equal(sessions.invalidated, []uuid.UUID{userID}) {
			t.Errorf("invalidated users = %v, want [%v]", sessions.invalidated, userID)
		}
	})

	t.Run("clearing the url fails", func(t *testing.T) {
		// DeleteFileFunc is nil: the record still points at the file, so deleting it would panic.
		repo := &fakeUserRepository{
			GetByUUIDFunc: withAvatar("avatar.png"),
			UpdateFunc: func(context.Context, uuid.UUID, domain.UpdateUserInput) (*domain.User, error) {
				return nil, errDB
			},
		}

		_, err := newTestService(t, UserServiceParams{Repo: repo}).DeleteAvatar(asActor(userID), userID)

		wantErr(t, err, errDB)
	})

	// UpdateFunc and DeleteFileFunc are nil in the two no-op cases: either call would panic.
	t.Run("no avatar", func(t *testing.T) {
		repo := &fakeUserRepository{GetByUUIDFunc: noAvatar}

		_, err := newTestService(t, UserServiceParams{Repo: repo}).DeleteAvatar(asActor(userID), userID)

		wantErr(t, err, nil)
	})

	t.Run("avatar url is an empty string", func(t *testing.T) {
		repo := &fakeUserRepository{GetByUUIDFunc: withAvatar("")}

		_, err := newTestService(t, UserServiceParams{Repo: repo}).DeleteAvatar(asActor(userID), userID)

		wantErr(t, err, nil)
	})

	t.Run("user lookup fails", func(t *testing.T) {
		repo := &fakeUserRepository{
			GetByUUIDFunc: func(context.Context, uuid.UUID) (*domain.User, error) { return nil, errDB },
		}

		_, err := newTestService(t, UserServiceParams{Repo: repo}).DeleteAvatar(asActor(userID), userID)

		wantErr(t, err, errDB)
	})
}

func TestUserService_DeleteAvatar_PropagatesLockError(t *testing.T) {
	userID := uuid.New()
	// GetByUUIDFunc, UpdateFunc and DeleteFileFunc are nil: any of them after the lock would panic.
	repo := &fakeUserRepository{
		LockByUUIDFunc: func(context.Context, uuid.UUID) (int64, error) { return 0, errDB },
	}

	_, err := newTestService(t, UserServiceParams{Repo: repo}).DeleteAvatar(asActor(userID), userID)

	wantErr(t, err, errDB)
}

// deref returns *p, or "<nil>" when p is nil, so optional strings compare and print alike.
func deref(p *string) string {
	if p == nil {
		return "<nil>"
	}

	return *p
}
