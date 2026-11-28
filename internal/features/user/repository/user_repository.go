package repository

import (
	"context"

	"github.com/google/uuid"

	"github.com/jun-develop/junkit/database"
	"github.com/jun-develop/junkit/slicex"

	"jungo/internal/database/primary"
	"jungo/internal/database/primary/sqlc"
	"jungo/internal/features/user/domain"
)

// UserRepository implements domain.UserRepository.
type UserRepository struct {
	db *primary.DB
}

// NewUserRepository creates a UserRepository backed by db.
func NewUserRepository(db *primary.DB) *UserRepository {
	return &UserRepository{db: db}
}

// WithTransaction implements domain.UserRepository.
func (r *UserRepository) WithTransaction(ctx context.Context, fn func(ctx context.Context) error) error {
	return r.db.WithTransaction(ctx, fn)
}

// Create implements domain.UserRepository; new users are active.
func (r *UserRepository) Create(ctx context.Context, input domain.CreateUserInput, passwordHash string) (*domain.User, error) {
	row, err := r.db.Queries(ctx).CreateUser(ctx, sqlc.CreateUserParams{
		Email:        input.Email,
		PasswordHash: passwordHash,
		FirstName:    input.FirstName,
		LastName:     input.LastName,
		PhoneNumber:  input.PhoneNumber,
		Status:       domain.UserStatusActive,
	})
	if err != nil {
		return nil, wrap("create", database.Match(err, map[database.ErrorType]error{
			database.ErrorUniqueViolation: domain.ErrEmailAlreadyExists,
		}))
	}

	// A new user holds no role yet.
	user := mapUser(row)
	user.Roles = []domain.UserRole{}

	return user, nil
}

// GetByUUID implements domain.UserRepository.
func (r *UserRepository) GetByUUID(ctx context.Context, uid uuid.UUID) (*domain.User, error) {
	row, err := r.db.Queries(ctx).GetUserByUUID(ctx, uid)
	if err != nil {
		return nil, wrap("get by uuid", database.MatchNotFound(err, domain.ErrUserNotFound))
	}

	return r.withRoles(ctx, mapUser(row))
}

// GetCredentialsByEmail implements domain.UserRepository.
func (r *UserRepository) GetCredentialsByEmail(ctx context.Context, email string) (*domain.Credentials, error) {
	row, err := r.db.Queries(ctx).GetUserByEmail(ctx, email)
	if err != nil {
		return nil, wrap("get credentials", database.MatchNotFound(err, domain.ErrUserNotFound))
	}

	return &domain.Credentials{
		ID:           row.ID,
		UUID:         row.UUID,
		Email:        row.Email,
		FirstName:    row.FirstName,
		LastName:     row.LastName,
		PasswordHash: row.PasswordHash,
		Status:       row.Status,
	}, nil
}

// UpdatePassword implements domain.UserRepository.
func (r *UserRepository) UpdatePassword(ctx context.Context, id int64, passwordHash string) error {
	n, err := r.db.Queries(ctx).UpdateUserPassword(ctx, sqlc.UpdateUserPasswordParams{ID: id, PasswordHash: passwordHash})
	if err != nil {
		return wrap("update password", err)
	}

	if n == 0 {
		return domain.ErrUserNotFound
	}

	return nil
}

// List implements domain.UserRepository; it also returns the total count for pagination.
func (r *UserRepository) List(ctx context.Context, filter domain.UserListFilter) ([]*domain.User, int64, error) {
	queries := r.db.Queries(ctx)
	search := database.EscapeLike(filter.Search)

	// nil, not an empty array, is what the queries read as "any role".
	var roleUUIDs []uuid.UUID
	if len(filter.RoleUUIDs) > 0 {
		roleUUIDs = filter.RoleUUIDs
	}

	var rows []sqlc.User
	var err error
	switch {
	case filter.SortBy != "" && filter.SortBy != "created_at":
		rows, err = queries.ListUsersSorted(ctx, sqlc.ListUsersSortedParams{
			Search: search, Status: filter.Status, RoleUuids: roleUUIDs,
			SortBy: filter.SortBy, Descending: filter.SortOrder != "asc", Limit: filter.Limit, Offset: filter.Offset,
		})
	case filter.SortOrder == "asc":
		rows, err = queries.ListUsersOldest(ctx, sqlc.ListUsersOldestParams{
			Search: search, Status: filter.Status, RoleUuids: roleUUIDs, Limit: filter.Limit, Offset: filter.Offset,
		})
	default:
		rows, err = queries.ListUsersNewest(ctx, sqlc.ListUsersNewestParams{
			Search: search, Status: filter.Status, RoleUuids: roleUUIDs, Limit: filter.Limit, Offset: filter.Offset,
		})
	}

	if err != nil {
		return nil, 0, wrap("list", err)
	}

	users := slicex.Map(rows, mapUser)
	if err := r.fillRoles(ctx, users); err != nil {
		return nil, 0, err
	}

	// A short page that is not past the end is the last one, so it already gives the total.
	if len(rows) < int(filter.Limit) && (len(rows) > 0 || filter.Offset == 0) {
		return users, int64(filter.Offset) + int64(len(rows)), nil
	}

	total, err := queries.CountUsers(ctx, sqlc.CountUsersParams{Search: search, Status: filter.Status, RoleUuids: roleUUIDs})
	if err != nil {
		return nil, 0, wrap("count", err)
	}

	return users, total, nil
}

// Update implements domain.UserRepository.
func (r *UserRepository) Update(ctx context.Context, uid uuid.UUID, input domain.UpdateUserInput) (*domain.User, error) {
	row, err := r.db.Queries(ctx).UpdateUser(ctx, sqlc.UpdateUserParams{
		UUID:        uid,
		FirstName:   input.FirstName,
		LastName:    input.LastName,
		PhoneNumber: input.PhoneNumber,
		AvatarURL:   input.AvatarURL,
		Status:      input.Status,
	})
	if err != nil {
		return nil, wrap("update", database.MatchNotFound(err, domain.ErrUserNotFound))
	}

	return r.withRoles(ctx, mapUser(row))
}

// Delete implements domain.UserRepository; it soft-deletes via deleted_at.
func (r *UserRepository) Delete(ctx context.Context, uid uuid.UUID) error {
	n, err := r.db.Queries(ctx).DeleteUser(ctx, uid)
	if err != nil {
		return wrap("delete", err)
	}

	if n == 0 {
		return domain.ErrUserNotFound
	}

	return nil
}

// GetIDByUUID implements domain.UserRepository.
func (r *UserRepository) GetIDByUUID(ctx context.Context, uid uuid.UUID) (int64, error) {
	id, err := r.db.Queries(ctx).GetUserIDByUUID(ctx, uid)
	if err != nil {
		return 0, wrap("get id", database.MatchNotFound(err, domain.ErrUserNotFound))
	}

	return id, nil
}

// LockByUUID implements domain.UserRepository; it returns the user's ID and locks their row until
// the transaction in ctx ends.
func (r *UserRepository) LockByUUID(ctx context.Context, uid uuid.UUID) (int64, error) {
	id, err := r.db.Queries(ctx).LockUserByUUID(ctx, uid)
	if err != nil {
		return 0, wrap("lock", database.MatchNotFound(err, domain.ErrUserNotFound))
	}

	return id, nil
}

// withRoles fills user's roles and returns it.
func (r *UserRepository) withRoles(ctx context.Context, user *domain.User) (*domain.User, error) {
	if err := r.fillRoles(ctx, []*domain.User{user}); err != nil {
		return nil, err
	}

	return user, nil
}

// fillRoles fills the roles of users, by name, with one query; a user without roles gets an empty list.
func (r *UserRepository) fillRoles(ctx context.Context, users []*domain.User) error {
	if len(users) == 0 {
		return nil
	}

	byUUID := make(map[uuid.UUID]*domain.User, len(users))
	uids := make([]uuid.UUID, len(users))
	for i, u := range users {
		u.Roles = []domain.UserRole{}
		byUUID[u.UUID] = u
		uids[i] = u.UUID
	}

	rows, err := r.db.Queries(ctx).ListRolesOfUsers(ctx, uids)
	if err != nil {
		return wrap("list roles", err)
	}

	for _, row := range rows {
		u := byUUID[row.UserUUID]
		u.Roles = append(u.Roles, domain.UserRole{UUID: row.UUID, Code: row.Code, Name: row.Name, IsSystem: row.IsSystem})
	}

	return nil
}

// mapUser converts a generated sqlc.User row to the domain model.
func mapUser(row sqlc.User) *domain.User {
	return &domain.User{
		UUID:        row.UUID,
		Email:       row.Email,
		FirstName:   row.FirstName,
		LastName:    row.LastName,
		PhoneNumber: row.PhoneNumber,
		AvatarURL:   row.AvatarURL,
		Status:      row.Status,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
	}
}

// wrap adds the failed operation to err; domain errors stay matchable with errors.Is/As.
var wrap = database.ErrorPrefixer("user repository")
