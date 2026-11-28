package v1

import (
	"time"

	"github.com/google/uuid"

	"github.com/jun-develop/junkit/pagination"
	"github.com/jun-develop/junkit/slicex"

	"jungo/internal/features/user/domain"
)

// CreateUserRequest is the request body for POST /users.
type CreateUserRequest struct {
	FirstName   string  `json:"first_name" binding:"required,min=2,max=50"`
	LastName    string  `json:"last_name" binding:"required,min=2,max=50"`
	Email       string  `json:"email" binding:"required,max=150,email,email_advanced"`
	Password    string  `json:"password" binding:"required,min=8,max=72,password_strong"`
	PhoneNumber *string `json:"phone_number" binding:"omitempty,phone_advanced"`
}

// ToCreateUserInput converts CreateUserRequest to domain input.
func ToCreateUserInput(req CreateUserRequest) domain.CreateUserInput {
	return domain.CreateUserInput{
		FirstName:   req.FirstName,
		LastName:    req.LastName,
		Email:       req.Email,
		Password:    req.Password,
		PhoneNumber: req.PhoneNumber,
	}
}

// UpdateUserRequest is the request body for PATCH /users/:uuid; a field left out (or null) is kept, and
// "phone_number": "" clears the phone.
type UpdateUserRequest struct {
	FirstName   *string `json:"first_name" binding:"omitempty,min=2,max=50"`
	LastName    *string `json:"last_name" binding:"omitempty,min=2,max=50"`
	PhoneNumber *string `json:"phone_number" binding:"omitzero,phone_advanced"`
	Status      *string `json:"status" binding:"omitempty,oneof=active inactive"`
}

// ToUpdateUserInput converts UpdateUserRequest to domain input.
func ToUpdateUserInput(req UpdateUserRequest) domain.UpdateUserInput {
	var status *int16
	if req.Status != nil {
		// The binding tag guarantees a known name.
		if s, ok := domain.ParseUserStatus(*req.Status); ok {
			status = &s
		}
	}

	return domain.UpdateUserInput{
		FirstName:   req.FirstName,
		LastName:    req.LastName,
		PhoneNumber: req.PhoneNumber,
		Status:      status,
	}
}

// UpdateMeRequest is the request body for PATCH /auth/me: the fields and rules of UpdateUserRequest a
// user may change on themself. A field left out (or null) is kept; "phone_number": "" clears the phone.
type UpdateMeRequest struct {
	FirstName   *string `json:"first_name" binding:"omitempty,min=2,max=50"`
	LastName    *string `json:"last_name" binding:"omitempty,min=2,max=50"`
	PhoneNumber *string `json:"phone_number" binding:"omitzero,phone_advanced"`
}

// ToUpdateMeInput converts UpdateMeRequest to domain input.
func ToUpdateMeInput(req UpdateMeRequest) domain.UpdateUserInput {
	return domain.UpdateUserInput{FirstName: req.FirstName, LastName: req.LastName, PhoneNumber: req.PhoneNumber}
}

// ListUsersRequest binds query parameters for listing users. role_uuid may repeat: a user holding any
// of the roles matches, and an unknown UUID matches no one.
type ListUsersRequest struct {
	pagination.PageRequest
	Search string `form:"search" binding:"omitempty" example:"John"`
	Status string `form:"status" binding:"omitempty,oneof=active inactive" example:"active"`
	// RoleUUID is singular, as its parameter, so validation errors name it "role_uuid[0]".
	RoleUUID  []string `form:"role_uuid" binding:"omitempty,dive,uuid"`
	SortBy    string   `form:"sort_by" binding:"omitempty,oneof=created_at email first_name last_name status" example:"created_at"`
	SortOrder string   `form:"sort_order" binding:"omitempty,oneof=asc desc" example:"desc"`
}

// ToUserListFilter converts ListUsersRequest to domain filter, newest first unless asked otherwise.
func ToUserListFilter(req ListUsersRequest) domain.UserListFilter {
	filter := domain.UserListFilter{
		Search:    req.Search,
		Limit:     req.GetLimit(),
		Offset:    req.GetOffset(),
		SortBy:    req.SortBy,
		SortOrder: req.SortOrder,
		// The binding tag guarantees UUIDs.
		RoleUUIDs: slicex.Map(req.RoleUUID, uuid.MustParse),
	}

	// The binding tag guarantees a known name.
	if s, ok := domain.ParseUserStatus(req.Status); ok {
		filter.Status = &s
	}

	if filter.SortBy == "" {
		filter.SortBy = "created_at"
	}

	if filter.SortOrder == "" {
		filter.SortOrder = "desc"
	}

	return filter
}

// UserResponse represents the JSON response for a user.
type UserResponse struct {
	UUID        uuid.UUID  `json:"uuid"`
	Email       string     `json:"email"`
	FirstName   string     `json:"first_name"`
	LastName    string     `json:"last_name"`
	PhoneNumber *string    `json:"phone_number"`
	AvatarURL   *string    `json:"avatar_url"`
	Status      string     `json:"status" enum:"active inactive"`
	Active      bool       `json:"active"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   *time.Time `json:"updated_at"`
	// Roles are the user's roles by name.
	Roles []UserRoleResponse `json:"roles"`
}

// UserRoleResponse is a role in UserResponse.
type UserRoleResponse struct {
	UUID     uuid.UUID `json:"uuid"`
	Code     string    `json:"code"`
	Name     string    `json:"name"`
	IsSystem bool      `json:"is_system"`
}

// NewUserResponse converts domain.User to UserResponse.
func NewUserResponse(u *domain.User) UserResponse {
	return UserResponse{
		UUID:        u.UUID,
		Email:       u.Email,
		FirstName:   u.FirstName,
		LastName:    u.LastName,
		PhoneNumber: u.PhoneNumber,
		AvatarURL:   u.AvatarURL,
		Status:      domain.UserStatusName(u.Status),
		Active:      u.IsActive(),
		CreatedAt:   u.CreatedAt,
		UpdatedAt:   u.UpdatedAt,
		Roles: slicex.Map(u.Roles, func(r domain.UserRole) UserRoleResponse {
			return UserRoleResponse{UUID: r.UUID, Code: r.Code, Name: r.Name, IsSystem: r.IsSystem}
		}),
	}
}

// NewUserResponseList converts a slice of domain.User to UserResponse list.
func NewUserResponseList(users []*domain.User) []UserResponse {
	return slicex.Map(users, NewUserResponse)
}
